//! Process-level acceptance for the PostgreSQL-backed API profile.

#![cfg(unix)]

use std::{
    error::Error,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use rsk_config::ExposeSecret as _;
use rsk_test_support::PostgresFixture;
use serde_json::Value;

const CURSOR_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_START_TIMEOUT: Duration = Duration::from_secs(10);
const READINESS_DEGRADE_TIMEOUT: Duration = Duration::from_secs(5);
const SERVICE_STOP_TIMEOUT: Duration = Duration::from_secs(15);

const _: () = assert!(CURSOR_SIGNING_KEY.len() == 32);

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(command: &mut Command) -> Result<Self, Box<dyn Error>> {
        command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map(|child| Self(Some(child)))
            .map_err(Into::into)
    }

    fn child_mut(&mut self) -> &mut Child {
        let Some(child) = self.0.as_mut() else {
            unreachable!("child process already consumed");
        };
        child
    }

    fn finish(mut self, timeout: Duration) -> Result<Output, Box<dyn Error>> {
        let Some(mut child) = self.0.take() else {
            unreachable!("child process already consumed");
        };
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait()?.is_some() {
                return child.wait_with_output().map_err(Into::into);
            }
            if Instant::now() >= deadline {
                let kill = child.kill();
                let wait = child.wait();
                kill?;
                wait?;
                return Err("child process did not exit before its deadline".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
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

#[derive(Debug)]
struct HttpResponse {
    status: String,
    content_type: String,
    body: String,
}

#[tokio::test(flavor = "multi_thread")]
async fn migrated_api_profile_serves_contract_degrades_readiness_and_shuts_down_cleanly()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let database_url = fixture.database_url().expose_secret().to_owned();

    let migration = run_command(api_command("migrate", &database_url)?, COMMAND_TIMEOUT)?;
    assert_safe_output(&migration, &database_url);
    let migration_stderr = String::from_utf8(migration.stderr)?;
    assert!(
        migration.status.success(),
        "migration command failed: {migration_stderr}"
    );
    let migration_status: Value = serde_json::from_slice(&migration.stdout)?;
    assert_migration_completed(&migration_status);

    let address = available_address()?;
    let mut server_command = api_command("server", &database_url)?;
    server_command.args(["--listen-address", &address.to_string()]);
    let mut service = ChildGuard::spawn(&mut server_command)?;

    let ready = wait_for_status(
        service.child_mut(),
        address,
        "/ready",
        "200 OK",
        SERVICE_START_TIMEOUT,
    )?;
    assert_response(&ready, "200 OK", "application/json", "\"status\":\"ready\"");
    assert_route(
        address,
        "/live",
        "200 OK",
        "application/json",
        "\"status\":\"live\"",
    )?;
    assert_route(
        address,
        "/startup",
        "200 OK",
        "application/json",
        "\"status\":\"started\"",
    )?;
    assert_route(
        address,
        "/version",
        "200 OK",
        "application/json",
        "\"profile\":\"api\"",
    )?;
    assert_route(
        address,
        "/openapi.json",
        "200 OK",
        "application/json",
        "\"openapi\":",
    )?;
    assert_route(
        address,
        "/docs/swagger-ui.css",
        "200 OK",
        "text/css",
        ".swagger-ui",
    )?;

    fixture.cleanup().await?;

    let unavailable = wait_for_status(
        service.child_mut(),
        address,
        "/ready",
        "503 Service Unavailable",
        READINESS_DEGRADE_TIMEOUT,
    )?;
    assert_response(
        &unavailable,
        "503 Service Unavailable",
        "application/problem+json",
        "\"code\":\"SERVICE_UNAVAILABLE\"",
    );
    assert_route(
        address,
        "/live",
        "200 OK",
        "application/json",
        "\"status\":\"live\"",
    )?;

    assert!(send_signal(service.child_mut(), "-TERM")?);
    let output = service.finish(SERVICE_STOP_TIMEOUT)?;
    assert_safe_output(&output, &database_url);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "service failed to stop: {stderr}");
    assert!(stderr.contains("startup complete listen_address="));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_database_is_not_auto_migrated_by_server_startup() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let database_url = fixture.database_url().expose_secret().to_owned();
    let address = available_address()?;
    let mut server_command = api_command("server", &database_url)?;
    server_command.args(["--listen-address", &address.to_string()]);

    let output = ChildGuard::spawn(&mut server_command)?.finish(SERVICE_START_TIMEOUT)?;
    assert_safe_output(&output, &database_url);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        !output.status.success(),
        "unmigrated server unexpectedly started"
    );
    assert!(stderr.contains("code=MIGRATION_OPERATION"));
    assert!(stderr.contains("database schema is not initialized"));

    let status = run_command(
        api_command("migration-status", &database_url)?,
        COMMAND_TIMEOUT,
    )?;
    assert_safe_output(&status, &database_url);
    let status_stderr = String::from_utf8(status.stderr)?;
    assert!(
        status.status.success(),
        "migration status command failed: {status_stderr}"
    );
    let status: Value = serde_json::from_slice(&status.stdout)?;
    assert!(status["current_version"].is_null());
    assert_eq!(status["applied_count"].as_u64(), Some(0));
    assert!(
        status["pending_versions"]
            .as_array()
            .is_some_and(|versions| !versions.is_empty())
    );

    fixture.cleanup().await?;
    Ok(())
}

fn api_command(subcommand: &str, database_url: &str) -> Result<Command, Box<dyn Error>> {
    let config = workspace_root()?.join("config/reference.toml");
    let config = config.to_str().ok_or("config path is not UTF-8")?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_rsk-api-server"));
    command
        .args([subcommand, "--config", config, "--environment", "test"])
        .env("POSTGRES_URL", database_url)
        .env("CURSOR_SIGNING_KEY", CURSOR_SIGNING_KEY)
        .env("RSK__POSTGRES__URL", database_url)
        .env("RSK__PAGINATION__CURSOR_SIGNING_KEY", CURSOR_SIGNING_KEY)
        .env("RSK__POSTGRES__TLS_MODE", "disable")
        .env("RSK__POSTGRES__CONNECT_TIMEOUT", "500ms")
        .env("RSK__POSTGRES__ACQUIRE_TIMEOUT", "250ms")
        .env("RSK__POSTGRES__HEALTH_TIMEOUT", "500ms")
        .env("RSK__POSTGRES__SHUTDOWN_TIMEOUT", "1s")
        .env("RSK__HEALTH__REFRESH_INTERVAL", "50ms")
        .env("RSK__HEALTH__STALE_AFTER", "750ms")
        .env("RSK__HEALTH__SHUTDOWN_TIMEOUT", "500ms")
        .env("RSK__TELEMETRY__ENVIRONMENT", "test");
    Ok(command)
}

fn run_command(mut command: Command, timeout: Duration) -> Result<Output, Box<dyn Error>> {
    ChildGuard::spawn(&mut command)?.finish(timeout)
}

fn assert_migration_completed(status: &Value) {
    assert_eq!(status["current_version"], status["target_version"]);
    assert!(
        status["applied_count"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(
        status["pending_versions"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert!(status["dirty_version"].is_null());
}

fn assert_safe_output(output: &Output, database_url: &str) {
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !contains_bytes(bytes, database_url.as_bytes()),
            "child output leaked POSTGRES_URL"
        );
        assert!(
            !contains_bytes(bytes, CURSOR_SIGNING_KEY.as_bytes()),
            "child output leaked CURSOR_SIGNING_KEY"
        );
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "api-server package must be under apps/api-server".into())
}

fn available_address() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn wait_for_status(
    child: &mut Child,
    address: SocketAddr,
    path: &str,
    expected_status: &str,
    timeout: Duration,
) -> Result<HttpResponse, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!(
                "service exited before {path} reached {expected_status}: {status}"
            )
            .into());
        }
        if let Ok(response) = request(address, path)
            && response.status == expected_status
        {
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(format!("{path} did not reach {expected_status}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_route(
    address: SocketAddr,
    path: &str,
    status: &str,
    content_type: &str,
    body_fragment: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request(address, path)?;
    assert_response(&response, status, content_type, body_fragment);
    Ok(())
}

fn assert_response(response: &HttpResponse, status: &str, content_type: &str, body_fragment: &str) {
    assert_eq!(response.status, status, "unexpected response: {response:?}");
    assert!(
        response.content_type.starts_with(content_type),
        "unexpected response: {response:?}"
    );
    assert!(
        response.body.contains(body_fragment),
        "unexpected response: {response:?}"
    );
}

fn request(address: SocketAddr, path: &str) -> Result<HttpResponse, Box<dyn Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("HTTP response did not contain a header terminator")?;
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .ok_or("HTTP response did not contain an HTTP/1.1 status line")?
        .to_owned();
    let content_type = lines
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-type")
                .then(|| value.trim().to_owned())
        })
        .ok_or("HTTP response did not contain Content-Type")?;
    Ok(HttpResponse {
        status,
        content_type,
        body: body.to_owned(),
    })
}

fn send_signal(child: &mut Child, signal: &str) -> Result<bool, Box<dyn Error>> {
    Ok(Command::new("/bin/kill")
        .args([signal, &child.id().to_string()])
        .status()?
        .success())
}
