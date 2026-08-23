//! Black-box acceptance for the no-dependency minimal service.

#![cfg(unix)]

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn child_mut(&mut self) -> &mut Child {
        let Some(child) = self.0.as_mut() else {
            unreachable!("child process already consumed");
        };
        child
    }

    fn finish(mut self) -> Result<(std::process::ExitStatus, String), Box<dyn std::error::Error>> {
        let Some(mut child) = self.0.take() else {
            unreachable!("child process already consumed");
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill()?;
                return Err("service did not exit under its shutdown deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .ok_or("stderr was not captured")?
            .read_to_string(&mut stderr)?;
        Ok((status, stderr))
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn minimal_profile_serves_contract_and_drains_without_dependencies()
-> Result<(), Box<dyn std::error::Error>> {
    let address = available_address()?;
    let mut service = spawn_service(address)?;

    wait_until_ready(service.child_mut(), address)?;
    assert_response(address, "/live", "200 OK", "\"status\":\"live\"")?;
    assert_response(address, "/ready", "200 OK", "\"status\":\"ready\"")?;
    assert_response(address, "/startup", "200 OK", "\"status\":\"started\"")?;
    assert_response(address, "/version", "200 OK", "\"profile\":\"minimal\"")?;
    assert_response(address, "/version", "200 OK", "\"test-support\"")?;
    assert_response(
        address,
        "/example",
        "200 OK",
        "hello from minimal-reference",
    )?;

    let missing = request(address, "/missing")?;
    assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
    assert!(
        missing
            .to_ascii_lowercase()
            .contains("content-type: application/problem+json")
    );
    assert!(missing.to_ascii_lowercase().contains("x-request-id:"));
    assert!(missing.contains("\"status\":404"));

    assert!(send_signal(service.child_mut(), "-TERM")?);
    let (status, stderr) = service.finish()?;
    assert!(status.success(), "service stderr:\n{stderr}");
    assert!(stderr.contains("startup complete listen_address="));
    assert!(!stderr.to_ascii_lowercase().contains("authorization"));
    Ok(())
}
#[test]
fn second_termination_signal_forces_a_blocked_listener_drain()
-> Result<(), Box<dyn std::error::Error>> {
    let address = available_address()?;
    let mut service = spawn_service(address)?;
    wait_until_ready(service.child_mut(), address)?;

    let mut incomplete_request = TcpStream::connect(address)?;
    write!(
        incomplete_request,
        "GET /example HTTP/1.1\r\nHost: {address}\r\nX-Incomplete:"
    )?;
    incomplete_request.flush()?;

    assert!(send_signal(service.child_mut(), "-TERM")?);
    thread::sleep(Duration::from_millis(100));
    assert!(
        service.child_mut().try_wait()?.is_none(),
        "first signal must allow an in-flight connection to drain"
    );
    assert!(send_signal(service.child_mut(), "-TERM")?);

    let (status, stderr) = service.finish()?;
    assert_eq!(status.code(), Some(130), "service stderr:\n{stderr}");
    Ok(())
}
#[test]
fn configured_header_deadline_closes_an_incomplete_request()
-> Result<(), Box<dyn std::error::Error>> {
    let address = available_address()?;
    let mut service = spawn_service(address)?;
    wait_until_ready(service.child_mut(), address)?;

    let mut incomplete_request = TcpStream::connect(address)?;
    incomplete_request.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        incomplete_request,
        "GET /example HTTP/1.1\r\nHost: {address}\r\nX-Incomplete:"
    )?;
    incomplete_request.flush()?;
    let mut byte = [0_u8; 1];
    assert_eq!(incomplete_request.read(&mut byte)?, 0);

    assert!(send_signal(service.child_mut(), "-TERM")?);
    let (status, stderr) = service.finish()?;
    assert!(status.success(), "service stderr:\n{stderr}");
    Ok(())
}

#[test]
fn invalid_config_fails_with_a_stable_code_without_leaking_source_detail()
-> Result<(), Box<dyn std::error::Error>> {
    const SECRET_MARKER: &str = "secret-value-must-not-leak";
    let missing = format!("/tmp/rsk-{SECRET_MARKER}-missing.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_rsk-server"))
        .args(["server", "--config", &missing, "--environment", "test"])
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;

    assert!(!output.status.success());
    assert!(stderr.contains("code=STARTUP_CONFIG"));
    assert!(!stderr.contains(SECRET_MARKER));
    Ok(())
}

fn spawn_service(address: SocketAddr) -> Result<ChildGuard, Box<dyn std::error::Error>> {
    let config = workspace_root()?.join("config/minimal.toml");
    let child = Command::new(env!("CARGO_BIN_EXE_rsk-server"))
        .args([
            "server",
            "--config",
            config.to_str().ok_or("config path is not UTF-8")?,
            "--environment",
            "test",
            "--listen-address",
            &address.to_string(),
        ])
        .env("RSK__TELEMETRY__ENVIRONMENT", "test")
        .env("RSK__HTTP__HEADER_READ_TIMEOUT", "200ms")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    Ok(ChildGuard(Some(child)))
}

fn send_signal(child: &mut Child, signal: &str) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(Command::new("/bin/kill")
        .args([signal, &child.id().to_string()])
        .status()?
        .success())
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "server package must be under apps/server".into())
}

fn available_address() -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn wait_until_ready(
    child: &mut Child,
    address: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("service exited before readiness with {status}").into());
        }
        if request(address, "/ready").is_ok_and(|response| response.starts_with("HTTP/1.1 200 OK"))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("service did not become ready".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_response(
    address: SocketAddr,
    path: &str,
    status: &str,
    body_fragment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = request(address, path)?;
    assert!(
        response.starts_with(&format!("HTTP/1.1 {status}")),
        "unexpected response: {response}"
    );
    assert!(
        response.contains(body_fragment),
        "unexpected response: {response}"
    );
    Ok(())
}

fn request(address: SocketAddr, path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}
