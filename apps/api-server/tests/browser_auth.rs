//! Browser authentication integration against real PostgreSQL password and session providers.

use std::{error::Error, num::NonZeroUsize, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::Path,
    http::{Method, Request, StatusCode, header},
    routing::post,
};
use omnius_api_server::browser_auth::{
    BROWSER_LOGIN_PATH, BROWSER_LOGOUT_ALL_PATH, BROWSER_LOGOUT_PATH, BROWSER_PRIVILEGED_PATH,
    BROWSER_SESSION_PATH, BrowserAuthSession, BrowserAuthState, BrowserAuthorization,
    BrowserSessionRevalidation, PasswordLoginProvider, bind_browser_session_tenant,
    browser_auth_router, protected_browser_router,
};
use omnius_auth_core::{Scope, SessionConfig, SubjectId, TenantId};
use omnius_auth_password::{
    PasswordEngine, PasswordInput, PasswordPolicy, PasswordWorker, PostgresPasswordStore,
};
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, Grant, PolicyMatrix, PolicyRule, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_http::{HttpShell, HttpShellConfig};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::Connection as _;
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const TRUSTED_ORIGIN: &str = "https://browser.example.test";
const LOGIN_IDENTIFIER: &str = "person@example.test";
const LOGIN_PASSWORD: &str = "correct horse battery staple";

struct TestContext {
    fixture: PostgresFixture,
    pool: PostgresPool,
    app: Router,
    state: BrowserAuthState,
    subject_id: SubjectId,
}

fn postgres_config(fixture: &PostgresFixture) -> PostgresConfig {
    PostgresConfig {
        url: fixture.database_url().clone(),
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-browser-auth-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
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

fn password(value: &str) -> Result<PasswordInput, Box<dyn Error>> {
    Ok(PasswordInput::new(SecretString::from(value.to_owned()))?)
}

fn denied_browser_authorization() -> Result<BrowserAuthorization, Box<dyn Error>> {
    let action = Action::new("browser:privileged")?;
    let resource_kind = ResourceKind::new("browser_session")?;
    let rule = PolicyRule::new(action.clone(), resource_kind.clone(), vec![Grant::Owner])?
        .with_required_scopes(vec![Scope::new("browser:privileged")?])?;
    let authorizer = AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
    Ok(BrowserAuthorization::new(authorizer, action, resource_kind))
}

async fn setup() -> Result<TestContext, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool =
        PostgresPool::connect(&postgres_config(&fixture), DeploymentEnvironment::Test).await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;

    let subject_id = SubjectId::new();
    let created_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(subject_id.as_uuid())
        .bind(created_at)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) \
         VALUES ($1, $2, 'email', $3, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(LOGIN_IDENTIFIER)
    .bind(created_at)
    .execute(&mut *connection)
    .await?;

    let worker = PasswordWorker::new(
        PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?,
        NonZeroUsize::new(2).ok_or("password worker concurrency must be nonzero")?,
    );
    let credential = worker.hash_password(password(LOGIN_PASSWORD)?).await?;
    let mut transaction = connection.begin().await?;
    PostgresPasswordStore
        .replace_password_with(&mut transaction, subject_id, &credential, created_at)
        .await?;
    transaction.commit().await?;
    drop(connection);

    let session_config = SessionConfig::default();
    let state = BrowserAuthState::new(
        pool.clone(),
        session_config,
        worker,
        PasswordLoginProvider::new("email")?,
        denied_browser_authorization()?,
        vec![TRUSTED_ORIGIN.to_owned()],
    );
    let tenant_binding = protected_browser_router(
        &state,
        DeploymentEnvironment::Test,
        Router::new().route("/test/tenant/{tenant_id}", post(bind_test_tenant)),
    )?;
    let routes =
        browser_auth_router(state.clone(), DeploymentEnvironment::Test)?.merge(tenant_binding);
    let shell = HttpShell::new(HttpShellConfig {
        trusted_origins: vec![TRUSTED_ORIGIN.to_owned()],
        ..HttpShellConfig::default()
    })?;
    let app = shell.apply(routes)?;
    Ok(TestContext {
        fixture,
        pool,
        app,
        state,
        subject_id,
    })
}

async fn bind_test_tenant(
    Path(tenant_id): Path<String>,
    auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let tenant_id = tenant_id
        .parse::<TenantId>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    bind_browser_session_tenant(&auth, tenant_id)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request(
    app: &Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    body: Option<Value>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    let body = if let Some(body) = body {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&body)?)
    } else {
        Body::empty()
    };
    Ok(app.clone().oneshot(builder.body(body)?).await?)
}

async fn login(
    app: &Router,
    origin: Option<&str>,
) -> Result<axum::response::Response, Box<dyn Error>> {
    request(
        app,
        Method::POST,
        BROWSER_LOGIN_PATH,
        None,
        origin,
        Some(json!({
            "identifier": LOGIN_IDENTIFIER,
            "password": LOGIN_PASSWORD,
        })),
    )
    .await
}

fn session_cookie(response: &axum::response::Response) -> Result<String, Box<dyn Error>> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|value| {
            let pair = value.split(';').next()?;
            pair.starts_with("__Host-omnius_session=")
                .then(|| pair.to_owned())
        })
        .ok_or_else(|| "response did not set the browser session cookie".into())
}

fn set_cookie_values(response: &axum::response::Response) -> Vec<&str> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect()
}

async fn response_json<T: DeserializeOwned>(
    response: axum::response::Response,
) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024).await?,
    )?)
}

#[tokio::test]
async fn login_bootstrap_and_logout_expose_a_real_server_session_lifecycle()
-> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let login_response = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    assert_eq!(login_response.status(), StatusCode::NO_CONTENT);
    let cookie = session_cookie(&login_response)?;
    let cookie_headers = set_cookie_values(&login_response);
    assert!(cookie_headers.iter().any(|value| {
        value.contains("Secure")
            && value.contains("HttpOnly")
            && value.contains("SameSite=Lax")
            && value.contains("Path=/")
    }));

    let bootstrap = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(bootstrap.status(), StatusCode::OK);
    let payload: Value = response_json(bootstrap).await?;
    assert_eq!(payload["subject_id"], context.subject_id.to_string());
    assert_eq!(payload["auth_method"], "session");
    assert!(payload["expires_at"].is_string());
    assert!(!payload.to_string().contains(&cookie));

    let logout_response = request(
        &context.app,
        Method::POST,
        BROWSER_LOGOUT_PATH,
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(logout_response.status(), StatusCode::NO_CONTENT);
    assert!(
        set_cookie_values(&logout_response)
            .iter()
            .any(|value| value.contains("Max-Age=0"))
    );

    let rejected = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let problem: Value = response_json(rejected).await?;
    assert_eq!(problem["code"], "SESSION_REVOKED_OR_EXPIRED");
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn logout_all_invalidates_a_sibling_session_cookie() -> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let first = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let first_cookie = session_cookie(&first)?;
    let sibling = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let sibling_cookie = session_cookie(&sibling)?;
    assert_ne!(first_cookie, sibling_cookie);

    let logout_all = request(
        &context.app,
        Method::POST,
        BROWSER_LOGOUT_ALL_PATH,
        Some(&first_cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(logout_all.status(), StatusCode::NO_CONTENT);

    let rejected = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&sibling_cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    let problem: Value = response_json(rejected).await?;
    assert_eq!(problem["code"], "SESSION_REVOKED_OR_EXPIRED");
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn expired_metadata_rejects_and_clears_an_old_cookie() -> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let login_response = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let cookie = session_cookie(&login_response)?;
    let now = OffsetDateTime::now_utc();
    sqlx::query(
        "UPDATE sessions SET created_at = $2, last_seen_at = $2, absolute_expires_at = $3 \
         WHERE user_id = $1",
    )
    .bind(context.subject_id.as_uuid())
    .bind(now - time::Duration::hours(2))
    .bind(now - time::Duration::hours(1))
    .execute(&context.pool.sqlx_pool())
    .await?;

    let rejected = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
    assert!(
        set_cookie_values(&rejected)
            .iter()
            .any(|value| value.contains("Max-Age=0"))
    );
    let problem: Value = response_json(rejected).await?;
    assert_eq!(problem["code"], "SESSION_REVOKED_OR_EXPIRED");
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn direct_privileged_request_is_denied_by_backend_authorization() -> Result<(), Box<dyn Error>>
{
    let context = setup().await?;
    let login_response = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let cookie = session_cookie(&login_response)?;

    let denied = request(
        &context.app,
        Method::POST,
        BROWSER_PRIVILEGED_PATH,
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let problem: Value = response_json(denied).await?;
    assert_eq!(problem["code"], "PERMISSION_DENIED");

    let bootstrap = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&cookie),
        None,
        None,
    )
    .await?;
    let payload: Value = response_json(bootstrap).await?;
    assert_eq!(payload["presentation_permissions"], json!([]));
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn canonical_origin_csrf_layer_rejects_untrusted_password_login() -> Result<(), Box<dyn Error>>
{
    let context = setup().await?;
    let missing_origin = login(&context.app, None).await?;
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);
    let cross_origin = login(&context.app, Some("https://attacker.example.test")).await?;
    assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);
    let session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
        .fetch_one(&context.pool.sqlx_pool())
        .await?;
    assert_eq!(session_count, 0);
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn tenant_binding_is_authoritative_and_exact_session_scoped() -> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let first_cookie = session_cookie(&login(&context.app, Some(TRUSTED_ORIGIN)).await?)?;
    let second_cookie = session_cookie(&login(&context.app, Some(TRUSTED_ORIGIN)).await?)?;
    let tenant_id = TenantId::new();
    let binding_response = request(
        &context.app,
        Method::POST,
        &format!("/test/tenant/{tenant_id}"),
        Some(&first_cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(binding_response.status(), StatusCode::NO_CONTENT);

    let first_bootstrap: Value = response_json(
        request(
            &context.app,
            Method::GET,
            BROWSER_SESSION_PATH,
            Some(&first_cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    let second_bootstrap: Value = response_json(
        request(
            &context.app,
            Method::GET,
            BROWSER_SESSION_PATH,
            Some(&second_cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    assert_eq!(first_bootstrap["tenant_id"], tenant_id.to_string());
    assert!(second_bootstrap["tenant_id"].is_null());

    let identity = context.state.cookie_identity();
    let mut first_headers = axum::http::HeaderMap::new();
    first_headers.insert(header::COOKIE, first_cookie.parse()?);
    let mut second_headers = axum::http::HeaderMap::new();
    second_headers.insert(header::COOKIE, second_cookie.parse()?);
    assert_eq!(
        identity
            .authenticate_headers(&first_headers)
            .await?
            .principal
            .tenant_id,
        Some(tenant_id)
    );
    assert_eq!(
        identity
            .authenticate_headers(&second_headers)
            .await?
            .principal
            .tenant_id,
        None
    );
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn bound_cookie_identity_revalidates_the_exact_session() -> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let login_response = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let cookie = session_cookie(&login_response)?;
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(header::COOKIE, cookie.parse()?);
    let identity = context.state.cookie_identity();
    let (active, binding) = identity.authenticate_bound_headers(&headers).await?;
    assert_eq!(active.principal.subject_id, context.subject_id);
    assert_eq!(
        identity
            .revalidate_bound_session(&active.principal, &binding)
            .await,
        BrowserSessionRevalidation::Active
    );

    sqlx::query("UPDATE sessions SET revoked_at = now() WHERE user_id = $1")
        .bind(context.subject_id.as_uuid())
        .execute(&context.pool.sqlx_pool())
        .await?;
    assert_eq!(
        identity
            .revalidate_bound_session(&active.principal, &binding)
            .await,
        BrowserSessionRevalidation::Revoked
    );
    context.fixture.cleanup().await?;
    Ok(())
}
