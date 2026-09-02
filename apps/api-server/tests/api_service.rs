//! Process-level acceptance for the PostgreSQL-backed authenticated API profile.

#![cfg(unix)]

use std::{
    error::Error,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use jsonwebtoken::{
    Algorithm, EncodingKey,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use omnius_config::ExposeSecret as _;
use omnius_test_support::{
    PostgresFixture, ProviderFake, ProviderMock, ProviderResponse, provider_matchers,
};
use serde_json::Value;
use uuid::Uuid;

const CURSOR_SIGNING_KEY: &str = "0123456789abcdef0123456789abcdef";
const JWT_ISSUER: &str = "https://issuer.example.test";
const PASSWORD_PEPPER: &str = "test-password-pepper";
const REGISTRATION_INVITATION_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const API_KEY_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OAUTH_ISSUER: &str = "http://127.0.0.1:8080";
const OAUTH_TOKEN_PEPPER: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const JWT_SIGNING_KEY: &[u8] = include_bytes!("../../../crates/auth-jwt/tests/test_rsa_key.pem");
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

struct JwtConfigOverride(PathBuf);

impl JwtConfigOverride {
    fn new(jwks_url: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let path = std::env::temp_dir().join(format!(
            "omnius-authenticated-profile-runtime-{}.toml",
            Uuid::now_v7()
        ));
        let jwt = jwks_url.map_or_else(
            || "[auth.jwt]\nenabled = false\n".to_owned(),
            |jwks_url| {
                format!(
                    "[auth.jwt]\nenabled = true\nissuers = [{{ issuer = \"{JWT_ISSUER}\", jwks_url = \"{jwks_url}\" }}]\n"
                )
            },
        );
        let private_key = std::str::from_utf8(JWT_SIGNING_KEY)?;
        let modulus = oauth_signing_modulus()?;
        fs::write(
            &path,
            format!(
                "{jwt}\
                 [auth.authorization_server]\nissuer = \"{OAUTH_ISSUER}\"\ntoken_pepper = \"{OAUTH_TOKEN_PEPPER}\"\n\
                 [[auth.authorization_server.resources]]\nuri = \"{OAUTH_ISSUER}\"\nname = \"Omnius API\"\ndescription = \"The first-party Omnius HTTP API.\"\nminimum_assurance = \"aal1\"\n\
                 [[auth.authorization_server.resources.scopes]]\nname = \"api:read\"\ndescription = \"Read authenticated API resources.\"\n\
                 [[auth.authorization_server.resources]]\nuri = \"{OAUTH_ISSUER}/mcp\"\nname = \"Omnius MCP\"\ndescription = \"The dedicated reference-record MCP resource.\"\nminimum_assurance = \"aal1\"\n\
                 [[auth.authorization_server.resources.scopes]]\nname = \"reference-records:read\"\ndescription = \"Read reference records through MCP.\"\n\
                 [[auth.authorization_server.signing_keys]]\nkid = \"reference-active\"\nalgorithm = \"RS256\"\nstate = \"active\"\n\
                 public_jwk = {{ kty = \"RSA\", use = \"sig\", key_ops = [\"verify\"], alg = \"RS256\", kid = \"reference-active\", n = \"{modulus}\", e = \"AQAB\" }}\n\
                 private_key_pkcs8_pem = '''{private_key}'''\n\
                 [outbound_http.url_policy]\nallow_development_loopback_http = true\n"
            ),
        )?;
        Ok(Self(path))
    }

    fn path(&self) -> Result<&str, Box<dyn Error>> {
        self.0
            .to_str()
            .ok_or_else(|| "JWT override path is not UTF-8".into())
    }
}

impl Drop for JwtConfigOverride {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: String,
    content_type: String,
    body: String,
}

fn jwks_body() -> Result<String, Box<dyn Error>> {
    let encoding_key = EncodingKey::from_rsa_pem(JWT_SIGNING_KEY)?;
    let mut key = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256)?;
    key.common.key_id = Some("profile-key".to_owned());
    key.common.public_key_use = Some(PublicKeyUse::Signature);
    key.common.key_operations = Some(vec![KeyOperations::Verify]);
    Ok(serde_json::to_string(&JwkSet { keys: vec![key] })?)
}

async fn mount_jwks(
    fake: &ProviderFake,
) -> Result<omnius_test_support::ProviderMockGuard, Box<dyn Error>> {
    Ok(fake
        .mount_scoped(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/jwks"))
                .respond_with(
                    ProviderResponse::new(200).set_body_raw(jwks_body()?, "application/json"),
                )
                .expect(1),
        )
        .await)
}

fn migrate_database(database_url: &str) -> Result<(), Box<dyn Error>> {
    let migration = run_command(api_command("migrate", database_url)?, COMMAND_TIMEOUT)?;
    assert_safe_output(&migration, database_url);
    let migration_stderr = String::from_utf8(migration.stderr)?;
    assert!(
        migration.status.success(),
        "migration command failed: {migration_stderr}"
    );
    let migration_status: Value = serde_json::from_slice(&migration.stdout).map_err(|error| {
        format!(
            "migration stdout is not one JSON document: {error}; stdout={}",
            String::from_utf8_lossy(&migration.stdout)
        )
    })?;
    assert_migration_completed(&migration_status);
    Ok(())
}

fn assert_service_contract(
    service: &mut ChildGuard,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
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
        "\"profile\":\"oauth-provider\"",
    )?;
    assert_route(
        address,
        "/openapi.json",
        "200 OK",
        "application/json",
        "\"openapi\":",
    )
}

fn assert_oauth_contract(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    assert_route(
        address,
        "/.well-known/oauth-authorization-server",
        "200 OK",
        "application/json",
        "\"issuer\":\"http://127.0.0.1:8080\"",
    )?;
    assert_route(
        address,
        "/.well-known/openid-configuration",
        "200 OK",
        "application/json",
        "\"response_modes_supported\":[\"query\"]",
    )?;
    assert_route(
        address,
        "/.well-known/oauth-protected-resource",
        "200 OK",
        "application/json",
        "\"resource\":\"http://127.0.0.1:8080\"",
    )?;
    assert_route(
        address,
        "/oauth/jwks.json",
        "200 OK",
        "application/json",
        "\"kid\":\"reference-active\"",
    )?;
    assert_ne!(
        request_method(address, "POST", "/oauth/register")?.status,
        "201 Created"
    );
    Ok(())
}

fn assert_unselected_routes_absent(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    for (method, absent) in [
        ("POST", "/uploads"),
        (
            "PUT",
            "/uploads/01890f2a-0000-7000-8000-000000000001/content",
        ),
        (
            "POST",
            "/uploads/01890f2a-0000-7000-8000-000000000001/complete",
        ),
        (
            "POST",
            "/uploads/01890f2a-0000-7000-8000-000000000001/status",
        ),
        (
            "POST",
            "/uploads/01890f2a-0000-7000-8000-000000000001/abandon",
        ),
        (
            "GET",
            "/uploads/01890f2a-0000-7000-8000-000000000001/download",
        ),
        ("GET", "/events"),
        ("GET", "/realtime/ws"),
        ("POST", "/webhooks/inbound/provider"),
        ("POST", "/mcp"),
        ("GET", "/mcp"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
    ] {
        assert_route_absent(address, method, absent)?;
    }
    Ok(())
}

fn assert_protected_route_and_docs(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    assert_route(
        address,
        "/whoami",
        "401 Unauthorized",
        "application/problem+json",
        "\"code\":\"AUTHENTICATION_REQUIRED\"",
    )?;
    assert_route(
        address,
        "/docs/swagger-ui.css",
        "200 OK",
        "text/css",
        ".swagger-ui",
    )
}

fn assert_readiness_degrades(
    service: &mut ChildGuard,
    address: SocketAddr,
) -> Result<(), Box<dyn Error>> {
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
    )
}

fn stop_service_cleanly(
    mut service: ChildGuard,
    address: SocketAddr,
    database_url: &str,
) -> Result<(), Box<dyn Error>> {
    assert_cookie_liveness(address)?;
    assert!(send_signal(service.child_mut(), "-TERM")?);
    wait_until_intake_closed(service.child_mut(), address)?;
    let output = service.finish(SERVICE_STOP_TIMEOUT)?;
    assert_safe_output(&output, database_url);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "service failed to stop: {stderr}");
    assert!(stderr.contains("startup complete listen_address="));
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn migrated_authenticated_profile_serves_contract_degrades_readiness_and_shuts_down_cleanly()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let database_url = fixture.database_url().expose_secret().to_owned();
    migrate_database(&database_url)?;

    let jwt_provider = ProviderFake::start().await?;
    let jwt_guard = mount_jwks(&jwt_provider).await?;
    let jwt_config = JwtConfigOverride::new(Some(jwt_provider.endpoint("/jwks")?.as_str()))?;
    let address = available_address()?;
    let mut server_command = configured_server_command(&database_url, address, &jwt_config)?;
    let mut service = ChildGuard::spawn(&mut server_command)?;

    assert_service_contract(&mut service, address)?;
    assert_oauth_contract(address)?;
    assert_unselected_routes_absent(address)?;
    assert_protected_route_and_docs(address)?;

    fixture.cleanup().await?;
    assert_readiness_degrades(&mut service, address)?;
    stop_service_cleanly(service, address, &database_url)?;
    drop(jwt_guard);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_database_is_not_auto_migrated_by_server_startup() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let database_url = fixture.database_url().expose_secret().to_owned();
    let runtime_config = JwtConfigOverride::new(None)?;
    let address = available_address()?;
    let mut server_command = api_command("server", &database_url)?;
    server_command.args([
        "--environment-config",
        runtime_config.path()?,
        "--listen-address",
        &address.to_string(),
    ]);

    let output = ChildGuard::spawn(&mut server_command)?.finish(SERVICE_START_TIMEOUT)?;
    assert_safe_output(&output, &database_url);
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        !output.status.success(),
        "unmigrated server unexpectedly started"
    );
    assert!(stderr.contains("code=MIGRATION_OPERATION"), "{stderr}");
    assert!(
        stderr.contains("database schema is not initialized"),
        "{stderr}"
    );

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

#[test]
fn local_issuer_does_not_require_external_jwt_configuration() -> Result<(), Box<dyn Error>> {
    let database_url = "postgres://test:test@127.0.0.1:1/test";
    let mut command = api_command("migration-status", database_url)?;
    command.env("OMNIUS__AUTH__JWT__ENABLED", "false");
    let output = run_command(command, COMMAND_TIMEOUT)?;
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!stderr.contains("code=STARTUP_JWT"));
    Ok(())
}

fn configured_server_command(
    database_url: &str,
    address: SocketAddr,
    jwt_config: &JwtConfigOverride,
) -> Result<Command, Box<dyn Error>> {
    let mut command = api_command("server", database_url)?;
    command.args([
        "--environment-config",
        jwt_config.path()?,
        "--listen-address",
        &address.to_string(),
    ]);
    Ok(command)
}

fn api_command(subcommand: &str, database_url: &str) -> Result<Command, Box<dyn Error>> {
    let root = workspace_root()?;
    let config = root.join("config/reference.toml");
    let template_dir = root.join("apps/api-server/email-templates");
    let config = config.to_str().ok_or("config path is not UTF-8")?;
    let template_dir = template_dir
        .to_str()
        .ok_or("email template path is not UTF-8")?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_omnius-api-server"));
    command
        .args([subcommand, "--config", config, "--environment", "test"])
        .env("POSTGRES_URL", database_url)
        .env("CURSOR_SIGNING_KEY", CURSOR_SIGNING_KEY)
        .env("JWT_ISSUER", JWT_ISSUER)
        .env("PUBLIC_APP_URL", OAUTH_ISSUER)
        .env("OAUTH_ISSUER", OAUTH_ISSUER)
        .env("OMNIUS__AUTH__REGISTRATION__PUBLIC_APP_URL", OAUTH_ISSUER)
        .env("OMNIUS__AUTH__AUTHORIZATION_SERVER__ISSUER", OAUTH_ISSUER)
        .env(
            "OMNIUS__AUTH__AUTHORIZATION_SERVER__TOKEN_PEPPER",
            OAUTH_TOKEN_PEPPER,
        )
        .env("OAUTH_TOKEN_PEPPER", OAUTH_TOKEN_PEPPER)
        .env("OAUTH_SIGNING_JWK_N", oauth_signing_modulus()?)
        .env(
            "OAUTH_SIGNING_PRIVATE_KEY_PKCS8_PEM",
            std::str::from_utf8(JWT_SIGNING_KEY)?,
        )
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
        .env("EMAIL_TEMPLATE_DIR", template_dir)
        .env("OMNIUS__EMAIL__TEMPLATES__DIRECTORY", template_dir)
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

fn oauth_signing_modulus() -> Result<String, Box<dyn Error>> {
    fn find_modulus(value: &Value) -> Option<&str> {
        match value {
            Value::Object(object) => object
                .get("n")
                .and_then(Value::as_str)
                .or_else(|| object.values().find_map(find_modulus)),
            Value::Array(values) => values.iter().find_map(find_modulus),
            _ => None,
        }
    }
    let jwks: Value = serde_json::from_str(&jwks_body()?)?;
    find_modulus(&jwks)
        .map(str::to_owned)
        .ok_or_else(|| "generated RSA JWK omitted its modulus".into())
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
        assert!(
            !contains_bytes(bytes, PASSWORD_PEPPER.as_bytes()),
            "child output leaked PASSWORD_PEPPER"
        );
        assert!(
            !contains_bytes(bytes, REGISTRATION_INVITATION_PEPPER.as_bytes()),
            "child output leaked REGISTRATION_INVITATION_PEPPER"
        );
        assert!(
            !contains_bytes(bytes, API_KEY_PEPPER.as_bytes()),
            "child output leaked API_KEY_PEPPER"
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
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                pipe.read_to_string(&mut stderr)?;
            }
            return Err(format!(
                "service exited before {path} reached {expected_status}: {status}: {stderr}"
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

fn assert_route_absent(
    address: SocketAddr,
    method: &str,
    path: &str,
) -> Result<(), Box<dyn Error>> {
    let response = request_method(address, method, path)?;
    assert_eq!(
        response.status, "404 Not Found",
        "unselected route resolved: {method} {path}: {response:?}"
    );
    Ok(())
}

fn assert_cookie_liveness(address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let response = request_with_cookie(
        address,
        "/live",
        Some("__Host-omnius_session=AAAAAAAAAAAAAAAAAAAAAA"),
    )?;
    assert_response(
        &response,
        "200 OK",
        "application/json",
        "\"status\":\"live\"",
    );
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
    request_method_with_cookie(address, "GET", path, None)
}

fn request_method(
    address: SocketAddr,
    method: &str,
    path: &str,
) -> Result<HttpResponse, Box<dyn Error>> {
    request_method_with_cookie(address, method, path, None)
}

fn request_with_cookie(
    address: SocketAddr,
    path: &str,
    cookie: Option<&str>,
) -> Result<HttpResponse, Box<dyn Error>> {
    request_method_with_cookie(address, "GET", path, cookie)
}

fn request_method_with_cookie(
    address: SocketAddr,
    method: &str,
    path: &str,
    cookie: Option<&str>,
) -> Result<HttpResponse, Box<dyn Error>> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(100))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let cookie_header = cookie.map_or_else(String::new, |value| format!("Cookie: {value}\r\n"));
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\n{cookie_header}Content-Length: 0\r\nConnection: close\r\n\r\n"
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

fn wait_until_intake_closed(child: &mut Child, address: SocketAddr) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if child.try_wait()?.is_some()
            || TcpStream::connect_timeout(&address, Duration::from_millis(20)).is_err()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("HTTP listener continued accepting after the first signal".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn send_signal(child: &mut Child, signal: &str) -> Result<bool, Box<dyn Error>> {
    Ok(Command::new("/bin/kill")
        .args([signal, &child.id().to_string()])
        .status()?
        .success())
}
