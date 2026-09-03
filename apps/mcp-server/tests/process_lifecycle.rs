//! Process-level readiness and bounded SIGTERM coverage for the dedicated MCP binary.

#![cfg(unix)]

use std::{
    error::Error,
    fs,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{AlgorithmParameters, Jwk},
};
use omnius_config::ExposeSecret as _;
use omnius_test_support::PostgresFixture;
use uuid::Uuid;

const CURSOR_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef";
const JWT_ISSUER: &str = "https://issuer.example.test";
const PASSWORD_PEPPER: &str = "test-password-pepper";
const REGISTRATION_INVITATION_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const API_KEY_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OAUTH_ISSUER: &str = "http://127.0.0.1:49271";
const OAUTH_MCP_RESOURCE: &str = "http://127.0.0.1:49271/mcp";
const OAUTH_TOKEN_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const RSA_SIGNING_KEY: &[u8] = include_bytes!("../../../crates/auth-jwt/tests/test_rsa_key.pem");
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const START_TIMEOUT: Duration = Duration::from_secs(10);
const STOP_TIMEOUT: Duration = Duration::from_secs(20);

const _: () = assert!(CURSOR_SIGNING_KEY.len() == 32);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn(command: &mut Command) -> TestResult<Self> {
        Ok(Self(Some(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        )))
    }

    fn child_mut(&mut self) -> TestResult<&mut Child> {
        self.0
            .as_mut()
            .ok_or_else(|| Box::<dyn Error>::from("child process already consumed"))
    }

    fn finish(mut self, timeout: Duration) -> TestResult<Output> {
        let mut child = self
            .0
            .take()
            .ok_or_else(|| Box::<dyn Error>::from("child process already consumed"))?;
        let deadline = Instant::now() + timeout;
        loop {
            if child.try_wait()?.is_some() {
                return Ok(child.wait_with_output()?);
            }
            if Instant::now() >= deadline {
                child.kill()?;
                child.wait()?;
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

struct McpConfigOverride {
    path: PathBuf,
    mcp_resource: String,
}

impl McpConfigOverride {
    fn new() -> TestResult<Self> {
        let path =
            std::env::temp_dir().join(format!("omnius-mcp-process-config-{}.toml", Uuid::now_v7()));
        let mcp_resource = format!("{OAUTH_ISSUER}/mcp");
        assert_eq!(mcp_resource, OAUTH_MCP_RESOURCE);
        let private_key = std::str::from_utf8(RSA_SIGNING_KEY)?;
        let modulus = oauth_signing_modulus()?;
        fs::write(
            &path,
            format!(
                r#"[telemetry]
service = "mcp-reference"
version = "0.3.0"
environment = "test"

[server]
listen_address = "127.0.0.1:8090"
listener_shutdown_timeout = "15s"
telemetry_flush_timeout = "5s"

[postgres]
application_name = "mcp-reference"

[outbound_http]
user_agent = "mcp-reference/0.3.0"

[outbound_http.url_policy]
allow_development_loopback_http = true

[mcp_http]
allowed_hosts = ["localhost", "127.0.0.1", "::1"]
max_json_response_bytes = 2097152
max_response_frame_bytes = 2097152
drain_timeout = "10s"

[auth.jwt]
enabled = false

[auth.authorization_server]
issuer = "{OAUTH_ISSUER}"
token_pepper = "{OAUTH_TOKEN_PEPPER}"

[[auth.authorization_server.resources]]
uri = "{OAUTH_ISSUER}"
name = "Omnius API"
description = "The first-party Omnius HTTP API."
minimum_assurance = "aal1"

[[auth.authorization_server.resources.scopes]]
name = "api:read"
description = "Read authenticated API resources."

[[auth.authorization_server.resources]]
uri = "{mcp_resource}"
name = "Omnius MCP"
description = "The dedicated reference-record MCP resource."
minimum_assurance = "aal1"

[[auth.authorization_server.resources.scopes]]
name = "reference-records:read"
description = "Read reference records through MCP."

[[auth.authorization_server.signing_keys]]
kid = "reference-active"
algorithm = "RS256"
state = "active"
public_jwk = {{ kty = "RSA", kid = "reference-active", alg = "RS256", use = "sig", key_ops = ["verify"], n = "{modulus}", e = "AQAB" }}
private_key_pkcs8_pem = '''{private_key}'''
"#,
            ),
        )?;
        Ok(Self { path, mcp_resource })
    }

    fn path(&self) -> TestResult<&str> {
        self.path
            .to_str()
            .ok_or_else(|| "environment config path is not valid UTF-8".into())
    }

    fn mcp_resource(&self) -> &str {
        &self.mcp_resource
    }
}

impl Drop for McpConfigOverride {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
#[tokio::test]
async fn process_becomes_ready_and_sigterm_drains_cleanly() -> TestResult {
    let fixture = PostgresFixture::start().await?;
    let database_url = fixture.database_url().expose_secret().to_owned();
    let environment_config = McpConfigOverride::new()?;
    assert_eq!(
        environment_config.mcp_resource(),
        format!("{OAUTH_ISSUER}/mcp")
    );

    let migrate = run_command(
        mcp_command("migrate", &database_url, &environment_config)?,
        COMMAND_TIMEOUT,
    )?;
    if !migrate.status.success() {
        return Err(format!(
            "MCP migration command failed: {}",
            String::from_utf8_lossy(&migrate.stderr)
        )
        .into());
    }

    let address = reserve_address()?;
    let mut command = mcp_command("server", &database_url, &environment_config)?;
    command.args(["--listen-address", &address.to_string()]);
    let mut child = ChildGuard::spawn(&mut command)?;
    wait_ready(child.child_mut()?, address)?;
    assert!(send_signal(child.child_mut()?, "-TERM")?);
    let output = child.finish(STOP_TIMEOUT)?;
    assert!(
        output.status.success(),
        "MCP process did not drain cleanly: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fixture.cleanup().await?;
    Ok(())
}

fn mcp_command(
    subcommand: &str,
    database_url: &str,
    environment_config: &McpConfigOverride,
) -> TestResult<Command> {
    let root = workspace_root()?;
    let config = root.join("config/reference.toml");
    let template_dir = root.join("apps/api-server/email-templates");
    let mut command = Command::new(env!("CARGO_BIN_EXE_omnius-mcp-server"));
    command
        .args([
            subcommand,
            "--config",
            config.to_str().ok_or("config path is not UTF-8")?,
            "--environment",
            "test",
            "--environment-config",
            environment_config.path()?,
        ])
        .env("POSTGRES_URL", database_url)
        .env("CURSOR_SIGNING_KEY", CURSOR_SIGNING_KEY)
        .env("JWT_ISSUER", JWT_ISSUER)
        .env("PUBLIC_APP_URL", OAUTH_ISSUER)
        .env("OMNIUS__AUTH__REGISTRATION__PUBLIC_APP_URL", OAUTH_ISSUER)
        .env("PASSWORD_PEPPER", PASSWORD_PEPPER)
        .env(
            "REGISTRATION_INVITATION_PEPPER",
            REGISTRATION_INVITATION_PEPPER,
        )
        .env(
            "OMNIUS__AUTH__REGISTRATION__INVITATION_TOKEN_PEPPER",
            REGISTRATION_INVITATION_PEPPER,
        )
        .env("API_KEY_PEPPER", API_KEY_PEPPER)
        .env("OMNIUS__AUTH__API_KEY__PEPPER", API_KEY_PEPPER)
        .env(
            "EMAIL_TEMPLATE_DIR",
            template_dir
                .to_str()
                .ok_or("email template path is not UTF-8")?,
        )
        .env(
            "OMNIUS__EMAIL__TEMPLATES__DIRECTORY",
            template_dir
                .to_str()
                .ok_or("email template path is not UTF-8")?,
        )
        .env("OMNIUS__EMAIL__PROVIDER__RELAY", "smtp.example.test")
        .env("OMNIUS__EMAIL__PROVIDER__USERNAME", "test-user")
        .env("OMNIUS__EMAIL__PROVIDER__PASSWORD", "test-password")
        .env("SMTP_RELAY", "smtp.example.test")
        .env("SMTP_USERNAME", "test-user")
        .env("SMTP_PASSWORD", "test-password")
        .env("OMNIUS__POSTGRES__URL", database_url)
        .env("OMNIUS__PAGINATION__CURSOR_SIGNING_KEY", CURSOR_SIGNING_KEY)
        .env("OMNIUS__POSTGRES__TLS_MODE", "disable")
        .env("OMNIUS__POSTGRES__CONNECT_TIMEOUT", "500ms")
        .env("OMNIUS__POSTGRES__ACQUIRE_TIMEOUT", "250ms")
        .env("OMNIUS__POSTGRES__HEALTH_TIMEOUT", "500ms")
        .env("OMNIUS__POSTGRES__SHUTDOWN_TIMEOUT", "1s")
        .env("OMNIUS__HEALTH__REFRESH_INTERVAL", "50ms")
        .env("OMNIUS__HEALTH__STALE_AFTER", "750ms")
        .env("OMNIUS__HEALTH__SHUTDOWN_TIMEOUT", "500ms")
        .env("OMNIUS__TELEMETRY__ENVIRONMENT", "test");
    Ok(command)
}

fn oauth_signing_modulus() -> TestResult<String> {
    let encoding = EncodingKey::from_rsa_pem(RSA_SIGNING_KEY)?;
    let derived = Jwk::from_encoding_key(&encoding, Algorithm::RS256)?;
    let AlgorithmParameters::RSA(parameters) = derived.algorithm else {
        return Err("test key did not produce an RSA JWK".into());
    };
    Ok(parameters.n)
}

fn reserve_address() -> TestResult<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

fn wait_ready(child: &mut Child, address: SocketAddr) -> TestResult {
    let deadline = Instant::now() + START_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(format!("MCP process exited before readiness: {status}").into());
        }
        if request_ready(address).is_ok_and(|status| status == 200) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("MCP process did not become ready before its deadline".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn request_ready(address: SocketAddr) -> TestResult<u16> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    stream.write_all(
        format!("GET /ready HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes(),
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .ok_or_else(|| "readiness response omitted an HTTP status".into())
}

fn send_signal(child: &mut Child, signal: &str) -> TestResult<bool> {
    Ok(Command::new("/bin/kill")
        .args([signal, &child.id().to_string()])
        .status()?
        .success())
}

fn run_command(mut command: Command, timeout: Duration) -> TestResult<Output> {
    ChildGuard::spawn(&mut command)?.finish(timeout)
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("MCP package must remain under apps/")?
        .to_path_buf())
}
