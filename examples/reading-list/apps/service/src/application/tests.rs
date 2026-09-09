use std::{error::Error, io, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    Router,
    body::Body,
    http::{
        Method, Request, Response, StatusCode,
        header::{CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE},
    },
};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use service_kit::{
    auth_http::{AuthenticatedHttpInput, build_authenticated_http},
    config::{DeploymentEnvironment, SecretString},
    outbound_http::{OutboundHttpClients, OutboundHttpConfig},
    postgres::{
        PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
    },
    test_support::PostgresFixture,
};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::TcpListener,
    task::JoinHandle,
};
use tower::ServiceExt as _;

use super::*;

const TRUSTED_ORIGIN: &str = "http://localhost:3002";
const TEST_PASSWORD: &str = "correct horse battery staple";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn merged_application_contract_matches_fixed_auth_policy() {
    let document = application_contract();
    assert!(document["paths"]["/api/reading-items"].is_object());
    assert!(document["paths"]["/auth/register"].is_object());
    assert!(document["paths"]["/auth/registration-invitations"].is_null());
    assert_eq!(
        document["components"]["securitySchemes"]["session_cookie"]["name"],
        CONTRACT_SESSION_COOKIE_NAME
    );
}

#[tokio::test]
async fn real_registration_verification_session_and_protected_router_lifecycle() -> TestResult {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    crate::prepared_migrations()
        .await?
        .as_migrator()
        .run(&pool.sqlx_pool())
        .await?;
    let (smtp_port, smtp) = spawn_smtp().await?;
    let config = auth_config(smtp_port)?;
    let outbound = Arc::new(OutboundHttpClients::new(&OutboundHttpConfig::default())?);
    let authenticated = build_authenticated_http(AuthenticatedHttpInput {
        pool: pool.clone(),
        config: config.auth,
        account_email: config.email,
        trusted_origins: config.trusted_origins,
        outbound_http: outbound,
        deployment: DeploymentEnvironment::Test,
    })
    .await?;
    let protected =
        authenticated.protect_application_router(reading_items::router(pool.clone()))?;
    let router = authenticated.router().merge(protected);

    register_and_verify(&router, smtp).await?;
    let logged_in = login(&router, Some(TRUSTED_ORIGIN)).await?;
    assert_eq!(logged_in.status(), StatusCode::OK);
    let cookie = session_cookie(&logged_in)?;
    let session = json_body(logged_in).await?;
    assert_eq!(session["kind"], "user");
    assert_eq!(session["auth_method"], "session");
    assert!(session["subject_id"].is_string());
    assert!(session["expires_at"].is_string());
    assert!(!session.to_string().contains(&cookie));
    assert_authenticated_session_and_logout(&router, &cookie).await?;

    authenticated.email().shutdown().await;
    fixture.cleanup().await?;
    Ok(())
}

async fn register_and_verify(router: &Router, smtp: JoinHandle<io::Result<String>>) -> TestResult {
    let registration = json_request(
        Method::POST,
        "/auth/register",
        &json!({"email": "reader@example.test", "password": TEST_PASSWORD}),
        None,
        None,
    )?;
    let registered = router.clone().oneshot(registration).await?;
    assert_eq!(registered.status(), StatusCode::ACCEPTED);
    assert_eq!(json_body(registered).await?["status"], "accepted");

    let pending = login(router, Some(TRUSTED_ORIGIN)).await?;
    assert_problem(pending, StatusCode::UNAUTHORIZED, "LOGIN_REJECTED").await?;
    let missing_origin = login(router, None).await?;
    assert_problem(missing_origin, StatusCode::FORBIDDEN, "CSRF_ORIGIN_DENIED").await?;
    let wrong_origin = login(router, Some("http://localhost:3003")).await?;
    assert_problem(wrong_origin, StatusCode::FORBIDDEN, "CSRF_ORIGIN_DENIED").await?;

    let transcript = smtp.await??;
    assert!(transcript.contains("RCPT TO:<reader@example.test>"));
    assert!(transcript.contains("verify-email"));
    let verification_token = verification_token(&transcript)?;
    let verified = router
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/email/verification/complete",
            &json!({"token": verification_token}),
            None,
            None,
        )?)
        .await?;
    assert_eq!(verified.status(), StatusCode::NO_CONTENT);
    Ok(())
}

async fn assert_authenticated_session_and_logout(router: &Router, cookie: &str) -> TestResult {
    let session = router
        .clone()
        .oneshot(empty_request(
            Method::GET,
            "/auth/session",
            Some(cookie),
            None,
        )?)
        .await?;
    assert_eq!(session.status(), StatusCode::OK);
    let session_body = json_body(session).await?;
    assert_eq!(session_body["kind"], "user");

    let created = router
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/api/reading-items",
            &json!({"title": "Authenticated item", "url": "https://example.com/authenticated"}),
            Some(cookie),
            Some(TRUSTED_ORIGIN),
        )?)
        .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    assert_eq!(json_body(created).await?["title"], "Authenticated item");

    let logout = router
        .clone()
        .oneshot(empty_request(
            Method::POST,
            "/auth/logout",
            Some(cookie),
            Some(TRUSTED_ORIGIN),
        )?)
        .await?;
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let after_logout = router
        .clone()
        .oneshot(empty_request(
            Method::GET,
            "/auth/session",
            Some(cookie),
            None,
        )?)
        .await?;
    assert_problem(
        after_logout,
        StatusCode::UNAUTHORIZED,
        "SESSION_REVOKED_OR_EXPIRED",
    )
    .await
}

fn auth_config(smtp_port: u16) -> TestResult<ApplicationConfig> {
    let template_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/email-templates");
    Ok(serde_json::from_value(json!({
        "trusted_origins": [TRUSTED_ORIGIN],
        "auth": {
            "session": {
                "enabled": true,
                "store": "postgres",
                "cookie_name": "reading_list_session",
                "secure": false,
                "http_only": true,
                "same_site": "lax",
                "idle_timeout": "12h",
                "absolute_timeout": "30d"
            },
            "password": {
                "login_provider": "email",
                "max_concurrency": 2,
                "policy": {
                    "memory_kib": 19456,
                    "iterations": 2,
                    "parallelism": 1,
                    "min_password_bytes": 12,
                    "max_password_bytes": 1024,
                    "recovery_ttl": "15m",
                    "verification_ttl": "24h"
                },
                "pepper": {"version": 1, "secret": "test-password-pepper"}
            },
            "registration": {
                "mode": "self_service",
                "local_identity_provider": "email",
                "invitation_ttl": "7d",
                "public_app_url": "http://localhost:3002/",
                "invitation_token_pepper": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "response_floor": "500ms"
            }
        },
        "email": {
            "from": {"address": "accounts@example.test", "display_name": "Reading List"},
            "provider": {
                "provider": "development-smtp",
                "relay": "127.0.0.1",
                "port": smtp_port
            },
            "templates": {
                "directory": template_root,
                "allowed_templates": [
                    "account-email-verification",
                    "account-password-recovery",
                    "account-registration-invitation"
                ]
            }
        }
    }))?)
}

async fn spawn_smtp() -> io::Result<(u16, JoinHandle<io::Result<String>>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        let (reader, mut writer) = stream.into_split();
        writer.write_all(b"220 loopback ESMTP ready\r\n").await?;
        let mut lines = BufReader::new(reader).lines();
        let mut transcript = String::new();
        let mut reading_data = false;
        while let Some(line) = lines.next_line().await? {
            transcript.push_str(&line);
            transcript.push('\n');
            if reading_data {
                if line == "." {
                    writer
                        .write_all(b"250 2.0.0 queued id=reading-list-test\r\n")
                        .await?;
                    break;
                }
                continue;
            }
            let command = line
                .split_ascii_whitespace()
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            match command.as_str() {
                "EHLO" | "HELO" => writer.write_all(b"250-loopback\r\n250 OK\r\n").await?,
                "MAIL" | "RCPT" | "RSET" | "NOOP" => {
                    writer.write_all(b"250 OK\r\n").await?;
                }
                "DATA" => {
                    writer
                        .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                        .await?;
                    reading_data = true;
                }
                "QUIT" => {
                    writer.write_all(b"221 Bye\r\n").await?;
                    break;
                }
                _ => writer.write_all(b"500 Unsupported\r\n").await?,
            }
        }
        Ok(transcript)
    });
    Ok((port, task))
}

fn verification_token(transcript: &str) -> TestResult<String> {
    let decoded = transcript
        .replace("=\r\n", "")
        .replace("=\n", "")
        .replace("=3D", "=");
    let marker = "#token=";
    let start = decoded
        .find(marker)
        .ok_or("verification email did not contain a fragment token")?
        + marker.len();
    let token = decoded[start..]
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();
    if token.is_empty() {
        return Err("verification fragment token was empty".into());
    }
    Ok(token)
}

async fn login(router: &Router, origin: Option<&str>) -> TestResult<Response<Body>> {
    Ok(router
        .clone()
        .oneshot(json_request(
            Method::POST,
            "/auth/login",
            &json!({"identifier": "reader@example.test", "password": TEST_PASSWORD}),
            None,
            origin,
        )?)
        .await?)
}

fn json_request(
    method: Method,
    uri: &str,
    value: &Value,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> TestResult<Request<Body>> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    Ok(builder.body(Body::from(serde_json::to_vec(&value)?))?)
}

fn empty_request(
    method: Method,
    uri: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> TestResult<Request<Body>> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header(COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(ORIGIN, origin);
    }
    Ok(builder.body(Body::empty())?)
}

fn session_cookie(response: &Response<Body>) -> TestResult<String> {
    for value in response.headers().get_all(SET_COOKIE) {
        let value = value.to_str()?;
        if let Some(pair) = value.split(';').next()
            && pair.starts_with("reading_list_session=")
        {
            return Ok(pair.to_owned());
        }
    }
    Err("login response did not set the browser session cookie".into())
}

async fn json_body(response: Response<Body>) -> TestResult<Value> {
    Ok(serde_json::from_slice(
        &response.into_body().collect().await?.to_bytes(),
    )?)
}

async fn assert_problem(response: Response<Body>, status: StatusCode, code: &str) -> TestResult {
    assert_eq!(response.status(), status);
    let body = json_body(response).await?;
    assert_eq!(body["code"], code);
    assert_eq!(body["status"], u64::from(status.as_u16()));
    Ok(())
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "reading-list-auth-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(10),
        lock_timeout: Duration::from_secs(2),
        health_timeout: Duration::from_secs(3),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}
