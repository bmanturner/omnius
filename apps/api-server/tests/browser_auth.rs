//! Browser authentication integration against real PostgreSQL password and session providers.

use std::{error::Error, num::NonZeroUsize, time::Duration};

use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    extract::Path,
    http::{Method, Request, StatusCode, header},
    routing::{get, post},
};
use omnius_api_server::{
    account_auth::{
        AccountAuthState, AccountMailPresentation, INVITATIONS_PATH, PASSWORD_CHANGE_PATH,
        PASSWORD_RESET_COMPLETE_PATH, PASSWORD_RESET_REQUEST_PATH, REGISTER_PATH,
        SESSION_DEVICE_PATH, SESSIONS_PATH, VERIFICATION_COMPLETE_PATH, account_auth_router,
        account_invitation_router,
    },
    api_key_auth::{
        API_KEY_PATH, API_KEY_ROTATE_PATH, ApiKeyManagementState, CanonicalPrincipalState,
        SERVICE_ACCOUNT_API_KEYS_PATH, SERVICE_ACCOUNT_PATH, SERVICE_ACCOUNTS_PATH,
        api_key_management_router, canonical_identity_route, protected_principal_router,
    },
    browser_auth::{
        BROWSER_LOGIN_PATH, BROWSER_LOGOUT_ALL_PATH, BROWSER_LOGOUT_PATH, BROWSER_PRIVILEGED_PATH,
        BROWSER_SESSION_PATH, BrowserAuthSession, BrowserAuthState, BrowserAuthorization,
        BrowserSessionRevalidation, PasswordLoginProvider, bind_browser_session_tenant,
        browser_auth_router, protected_browser_router,
    },
};
use omnius_auth_api_key::{ApiKeyConfig, ApiKeyStore};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SessionConfig, SubjectId, TenantId,
};
use omnius_auth_password::{
    InvitationTokenPepper, PasswordEngine, PasswordInput, PasswordPolicy, PasswordWorker,
    PostgresPasswordStore, RegistrationMode, RegistrationPolicyConfig,
};
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, Grant, PolicyMatrix, PolicyRule, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_email::{
    CapturingMailSink, CustomHeaderPolicy, EmailAddress, EmailConfig, EmailLimits,
    EmailProviderConfig, EmailService, MailboxAddress, TemplateConfig, TemplateName,
};
use omnius_http::{HttpShell, HttpShellConfig};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_pagination::{CursorCodec, CursorSigningKey};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_tenancy::{OrganizationName, TenancyConfig, TenancyStore};
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
    api_key_store: ApiKeyStore,
    account_state: AccountAuthState,
    tenancy_store: TenancyStore,
    state: BrowserAuthState,
    subject_id: SubjectId,
    capture: CapturingMailSink,
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
    setup_with_registration_mode(RegistrationMode::SelfService).await
}

async fn setup_with_registration_mode(
    registration_mode: RegistrationMode,
) -> Result<TestContext, Box<dyn Error>> {
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
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(subject_id.as_uuid())
        .bind(created_at)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, 'email', $3, $4, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(LOGIN_IDENTIFIER)
    .bind(created_at)
    .execute(&mut *connection)
    .await?;

    let password_policy = PasswordPolicy::default_unpeppered()?;
    let worker = PasswordWorker::new(
        PasswordEngine::new(password_policy.clone())?,
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
        session_config.clone(),
        worker.clone(),
        PasswordLoginProvider::new("email")?,
        denied_browser_authorization()?,
        vec![TRUSTED_ORIGIN.to_owned()],
    );
    let template_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("email-templates");
    let email = EmailService::build(
        EmailConfig {
            provider: EmailProviderConfig::Capturing { capacity: 16 },
            templates: TemplateConfig {
                directory: template_dir,
                allowed_templates: [
                    "account-email-verification",
                    "account-password-recovery",
                    "account-registration-invitation",
                ]
                .into_iter()
                .map(TemplateName::try_from)
                .collect::<Result<Vec<_>, _>>()?,
            },
            custom_headers: CustomHeaderPolicy::default(),
            limits: EmailLimits::default(),
        },
        DeploymentEnvironment::Test,
    )?;
    let capture = email
        .capturing_sink()
        .ok_or("capturing email provider must expose its test sink")?;
    let registration = RegistrationPolicyConfig {
        mode: Some(registration_mode),
        local_identity_provider: "email".to_owned(),
        invitation_ttl: Duration::from_secs(7 * 24 * 60 * 60),
        public_app_url: Some("https://browser.example.test/app".parse()?),
    }
    .validate_for(DeploymentEnvironment::Test, &password_policy)?;
    let account_state = AccountAuthState::new(
        pool.clone(),
        session_config.clone(),
        worker,
        registration,
        InvitationTokenPepper::parse(SecretString::from(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        ))?,
        Duration::from_millis(500),
        email,
        AccountMailPresentation::new(MailboxAddress::new(
            EmailAddress::try_from("accounts@example.test")?,
            None,
        ))?,
    )?;
    let invitation_routes = account_invitation_router(account_state.clone());
    let api_key_store = ApiKeyStore::new(
        pool.clone(),
        &ApiKeyConfig {
            enabled: true,
            pepper: SecretString::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned()),
            ..ApiKeyConfig::default()
        },
    )?;
    let tenancy_store = TenancyStore::new(pool.clone(), &TenancyConfig::default())?;
    let management_state = ApiKeyManagementState::new(
        api_key_store.clone(),
        tenancy_store.clone(),
        CursorCodec::new(CursorSigningKey::from([9_u8; 32])),
    )?;
    let common_routes = protected_principal_router(
        CanonicalPrincipalState::new(
            pool.clone(),
            session_config,
            None,
            Some(api_key_store.clone()),
        )
        .with_trusted_origins(vec![TRUSTED_ORIGIN.to_owned()]),
        DeploymentEnvironment::Test,
        canonical_identity_route()
            .merge(Router::new().route("/test/protected", get(common_protected_resource)))
            .merge(invitation_routes)
            .merge(api_key_management_router(management_state)),
    )?;
    let tenant_binding = protected_browser_router(
        &state,
        DeploymentEnvironment::Test,
        Router::new().route("/test/tenant/{tenant_id}", post(bind_test_tenant)),
    )?;
    let routes = browser_auth_router(state.clone(), DeploymentEnvironment::Test)?
        .merge(account_auth_router(
            account_state.clone(),
            &state,
            DeploymentEnvironment::Test,
        )?)
        .merge(tenant_binding)
        .merge(common_routes);
    let shell = HttpShell::new(HttpShellConfig {
        trusted_origins: vec![TRUSTED_ORIGIN.to_owned()],
        ..HttpShellConfig::default()
    })?;
    let app = shell.apply(routes)?;
    Ok(TestContext {
        account_state,
        fixture,
        pool,
        api_key_store,
        tenancy_store,
        app,
        state,
        capture,
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
async fn common_protected_resource(Extension(principal): Extension<Principal>) -> Json<Value> {
    Json(json!({
        "subject_id": principal.subject_id.to_string(),
        "auth_method": match principal.auth_method {
            AuthMethod::Session => "session",
            AuthMethod::ApiKey => "api_key",
            AuthMethod::Jwt => "jwt",
            _ => "other",
        }
    }))
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
async fn wait_for_captured_mail(
    capture: &CapturingMailSink,
    expected: usize,
) -> Result<(), Box<dyn Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while capture.len()? < expected {
        if tokio::time::Instant::now() >= deadline {
            return Err("account mail was not captured before the bounded deadline".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
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
async fn request_with_authorizations(
    app: &Router,
    path: &str,
    cookie: Option<&str>,
    values: &[String],
) -> Result<axum::response::Response, Box<dyn Error>> {
    let mut builder = Request::builder().method(Method::GET).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    for value in values {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    Ok(app.clone().oneshot(builder.body(Body::empty())?).await?)
}

fn captured_fragment_token(message: &str) -> Result<String, Box<dyn Error>> {
    let decoded = message.replace("=\r\n", "").replace("=3D", "=");
    let token = decoded
        .split("#token=")
        .nth(1)
        .and_then(|suffix| suffix.get(..43))
        .ok_or("captured account message did not contain a fragment token")?;
    if !token
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("captured account token was not canonical base64url".into());
    }
    Ok(token.to_owned())
}

async fn login_as(
    app: &Router,
    identifier: &str,
    password: &str,
) -> Result<axum::response::Response, Box<dyn Error>> {
    request(
        app,
        Method::POST,
        BROWSER_LOGIN_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "identifier": identifier, "password": password })),
    )
    .await
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

#[tokio::test]
async fn account_discovery_has_one_accepted_shape_and_only_committed_known_mail()
-> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let known_started = std::time::Instant::now();
    let known = request(
        &context.app,
        Method::POST,
        PASSWORD_RESET_REQUEST_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": LOGIN_IDENTIFIER })),
    )
    .await?;
    let known_elapsed = known_started.elapsed();
    let unknown_started = std::time::Instant::now();
    let unknown = request(
        &context.app,
        Method::POST,
        PASSWORD_RESET_REQUEST_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": "missing@example.test" })),
    )
    .await?;
    let unknown_elapsed = unknown_started.elapsed();
    assert_eq!(known.status(), StatusCode::ACCEPTED);
    assert_eq!(unknown.status(), StatusCode::ACCEPTED);
    let known_body: Value = response_json(known).await?;
    let unknown_body: Value = response_json(unknown).await?;
    assert_eq!(known_body, json!({ "status": "accepted" }));
    assert_eq!(known_body, unknown_body);
    assert!(known_elapsed >= Duration::from_millis(400));
    assert!(unknown_elapsed >= Duration::from_millis(400));
    wait_for_captured_mail(&context.capture, 1).await?;
    assert_eq!(context.capture.len()?, 1);

    context.fixture.cleanup().await?;
    Ok(())
}
#[tokio::test]
async fn invite_only_management_requires_aal2_scope_and_accepts_canonical_bearer_authority()
-> Result<(), Box<dyn Error>> {
    let context = setup_with_registration_mode(RegistrationMode::InviteOnly).await?;
    let cookie = session_cookie(&login(&context.app, Some(TRUSTED_ORIGIN)).await?)?;
    let aal1 = request(
        &context.app,
        Method::POST,
        INVITATIONS_PATH,
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": "invitee-aal1@example.test" })),
    )
    .await?;
    assert_eq!(aal1.status(), StatusCode::FORBIDDEN);

    let principal = Principal::new(
        context.subject_id,
        PrincipalKind::User,
        None,
        AuthMethod::Jwt,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal2,
        vec![Scope::new("auth.registration-invitations.manage")?],
    )?;
    let invitation_routes =
        account_invitation_router(context.account_state.clone()).layer(Extension(principal));
    let app = HttpShell::new(HttpShellConfig {
        trusted_origins: vec![TRUSTED_ORIGIN.to_owned()],
        ..HttpShellConfig::default()
    })?
    .apply(invitation_routes)?;
    let accepted = request(
        &app,
        Method::POST,
        INVITATIONS_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": "invitee-aal2@example.test" })),
    )
    .await?;
    assert_eq!(accepted.status(), StatusCode::CREATED);
    wait_for_captured_mail(&context.capture, 1).await?;

    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn registration_mail_uses_a_fragment_and_activation_enables_login()
-> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let registered_email = "new.person@example.test";
    let registered_password = "registration correct horse battery staple";
    let registration_started = std::time::Instant::now();
    let response = request(
        &context.app,
        Method::POST,
        REGISTER_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({
            "email": registered_email,
            "password": registered_password,
        })),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let registration_elapsed = registration_started.elapsed();
    let response_body: Value = response_json(response).await?;
    assert_eq!(response_body, json!({ "status": "accepted" }));
    assert!(registration_elapsed >= Duration::from_millis(400));
    wait_for_captured_mail(&context.capture, 1).await?;
    let captured = context.capture.snapshot()?;
    assert_eq!(captured.len(), 1);
    let formatted = captured[0].formatted_utf8()?;
    let decoded = formatted.replace("=\\r\\n", "").replace("=3D", "=");
    assert!(decoded.contains("/app/verify-email#token="));
    assert!(!decoded.contains("?token="));
    let token = captured_fragment_token(&formatted)?;
    assert!(!format!("{:?}", captured[0]).contains(&token));
    assert!(!response_body.to_string().contains(&token));
    let status: String = sqlx::query_scalar(
        "SELECT u.status FROM users u JOIN identities i ON i.user_id = u.id \
         WHERE i.provider = 'email' AND i.provider_subject = $1",
    )
    .bind(registered_email)
    .fetch_one(&context.pool.sqlx_pool())
    .await?;
    assert_eq!(status, "pending_verification");

    let completion = request(
        &context.app,
        Method::POST,
        VERIFICATION_COMPLETE_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "token": token })),
    )
    .await?;
    assert_eq!(completion.status(), StatusCode::NO_CONTENT);
    let login = login_as(&context.app, registered_email, registered_password).await?;
    assert_eq!(login.status(), StatusCode::NO_CONTENT);
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn password_and_session_routes_apply_rotation_revocation_and_invitation_mode_guards()
-> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let first_cookie = session_cookie(&login(&context.app, Some(TRUSTED_ORIGIN)).await?)?;
    let sibling_cookie = session_cookie(&login(&context.app, Some(TRUSTED_ORIGIN)).await?)?;
    let changed_password = "changed correct horse battery staple";
    let change = request(
        &context.app,
        Method::POST,
        PASSWORD_CHANGE_PATH,
        Some(&first_cookie),
        Some(TRUSTED_ORIGIN),
        Some(json!({
            "current_password": LOGIN_PASSWORD,
            "new_password": changed_password,
        })),
    )
    .await?;
    assert_eq!(change.status(), StatusCode::NO_CONTENT);
    let rotated_cookie = session_cookie(&change)?;
    assert_ne!(rotated_cookie, first_cookie);
    let sibling = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&sibling_cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(sibling.status(), StatusCode::UNAUTHORIZED);

    let sessions = request(
        &context.app,
        Method::GET,
        SESSIONS_PATH,
        Some(&rotated_cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(sessions.status(), StatusCode::OK);
    let session_body: Value = response_json(sessions).await?;
    let listed = session_body["sessions"]
        .as_array()
        .ok_or("session list response must contain an array")?;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["current"], true);

    let invitation = request(
        &context.app,
        Method::POST,
        INVITATIONS_PATH,
        Some(&rotated_cookie),
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": "invitee@example.test" })),
    )
    .await?;
    assert_eq!(invitation.status(), StatusCode::NOT_FOUND);

    let reset_request = request(
        &context.app,
        Method::POST,
        PASSWORD_RESET_REQUEST_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({ "email": LOGIN_IDENTIFIER })),
    )
    .await?;
    assert_eq!(reset_request.status(), StatusCode::ACCEPTED);
    wait_for_captured_mail(&context.capture, 1).await?;
    let recovery_message = context
        .capture
        .snapshot()?
        .into_iter()
        .next()
        .ok_or("password recovery must be captured after commit")?;
    let recovery_token = captured_fragment_token(&recovery_message.formatted_utf8()?)?;
    let recovered_password = "recovered correct horse battery staple";
    let recovered = request(
        &context.app,
        Method::POST,
        PASSWORD_RESET_COMPLETE_PATH,
        None,
        Some(TRUSTED_ORIGIN),
        Some(json!({
            "token": recovery_token,
            "new_password": recovered_password,
        })),
    )
    .await?;
    assert_eq!(recovered.status(), StatusCode::NO_CONTENT);
    let revoked_current = request(
        &context.app,
        Method::GET,
        BROWSER_SESSION_PATH,
        Some(&rotated_cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(revoked_current.status(), StatusCode::UNAUTHORIZED);

    let relogin = login_as(&context.app, LOGIN_IDENTIFIER, recovered_password).await?;
    let current_cookie = session_cookie(&relogin)?;
    let sessions: Value = response_json(
        request(
            &context.app,
            Method::GET,
            SESSIONS_PATH,
            Some(&current_cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    let device_id = sessions["sessions"][0]["device_id"]
        .as_str()
        .ok_or("current device id must be serialized")?;
    let revoke = request(
        &context.app,
        Method::DELETE,
        &SESSION_DEVICE_PATH.replace("{device_id}", device_id),
        Some(&current_cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);
    assert!(set_cookie_values(&revoke).iter().any(|value| {
        value.starts_with("__Host-omnius_session=")
            && (value.contains("Max-Age=0") || value.contains("Expires="))
    }));
    context.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn common_principal_and_api_key_lifecycle_are_deterministic_and_policy_bounded()
-> Result<(), Box<dyn Error>> {
    let context = setup().await?;
    let login_response = login(&context.app, Some(TRUSTED_ORIGIN)).await?;
    let cookie = session_cookie(&login_response)?;

    let missing_origin = request(
        &context.app,
        Method::POST,
        SERVICE_ACCOUNTS_PATH,
        Some(&cookie),
        None,
        Some(json!({ "name": "origin-blocked", "tenant_id": null })),
    )
    .await?;
    assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);

    let created = response_json::<Value>(
        request(
            &context.app,
            Method::POST,
            SERVICE_ACCOUNTS_PATH,
            Some(&cookie),
            Some(TRUSTED_ORIGIN),
            Some(json!({ "name": "browser-owned", "tenant_id": null })),
        )
        .await?,
    )
    .await?;
    let account_id = created["id"]
        .as_str()
        .ok_or("created service account must expose its safe identifier")?
        .to_owned();

    let escalation = request(
        &context.app,
        Method::POST,
        &SERVICE_ACCOUNT_API_KEYS_PATH.replace("{service_account_id}", &account_id),
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        Some(json!({
            "name": "escalated",
            "scopes": ["reference-records:write"],
            "expires_at": null
        })),
    )
    .await?;
    assert_eq!(escalation.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response_json::<Value>(escalation).await?["code"],
        "API_KEY_SCOPE_ESCALATION"
    );

    let issued = response_json::<Value>(
        request(
            &context.app,
            Method::POST,
            &SERVICE_ACCOUNT_API_KEYS_PATH.replace("{service_account_id}", &account_id),
            Some(&cookie),
            Some(TRUSTED_ORIGIN),
            Some(json!({
                "name": "browser-key",
                "scopes": [],
                "expires_at": null
            })),
        )
        .await?,
    )
    .await?;
    let old_secret = issued["api_key"]
        .as_str()
        .ok_or("creation must reveal one API-key presentation")?
        .to_owned();
    let old_key_id = issued["metadata"]["id"]
        .as_str()
        .ok_or("creation must return safe key metadata")?
        .to_owned();
    assert!(old_secret.starts_with("omnius_"));

    let listed_keys = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            &format!(
                "{}?limit=1",
                SERVICE_ACCOUNT_API_KEYS_PATH.replace("{service_account_id}", &account_id)
            ),
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    assert_eq!(listed_keys["items"].as_array().map(Vec::len), Some(1));
    assert!(!listed_keys.to_string().contains(&old_secret));

    let api_authorization = format!("ApiKey {old_secret}");
    let api_identity = response_json::<Value>(
        request_with_authorizations(
            &context.app,
            "/whoami",
            Some(&cookie),
            std::slice::from_ref(&api_authorization),
        )
        .await?,
    )
    .await?;
    assert_eq!(api_identity["kind"], "service_account");
    assert_eq!(api_identity["auth_method"], "api_key");
    assert_eq!(api_identity["subject_id"], account_id);
    let api_protected = response_json::<Value>(
        request_with_authorizations(
            &context.app,
            "/test/protected",
            Some(&cookie),
            std::slice::from_ref(&api_authorization),
        )
        .await?,
    )
    .await?;
    assert_eq!(api_protected["auth_method"], "api_key");
    assert_eq!(api_protected["subject_id"], account_id);
    let session_protected = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            "/test/protected",
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    assert_eq!(session_protected["auth_method"], "session");
    assert_eq!(
        session_protected["subject_id"],
        context.subject_id.to_string()
    );

    let malformed = request_with_authorizations(
        &context.app,
        "/whoami",
        Some(&cookie),
        &["Basic ignored".to_owned()],
    )
    .await?;
    assert_eq!(malformed.status(), StatusCode::UNAUTHORIZED);
    let duplicated = request_with_authorizations(
        &context.app,
        "/whoami",
        Some(&cookie),
        &[api_authorization.clone(), api_authorization.clone()],
    )
    .await?;
    assert_eq!(duplicated.status(), StatusCode::UNAUTHORIZED);
    let mixed = request_with_authorizations(
        &context.app,
        "/whoami",
        Some(&cookie),
        &[format!("{api_authorization}, Bearer ignored")],
    )
    .await?;
    assert_eq!(mixed.status(), StatusCode::UNAUTHORIZED);

    for name in ["pagination-two", "pagination-three"] {
        let response = request(
            &context.app,
            Method::POST,
            SERVICE_ACCOUNTS_PATH,
            Some(&cookie),
            Some(TRUSTED_ORIGIN),
            Some(json!({ "name": name, "tenant_id": null })),
        )
        .await?;
        assert_eq!(response.status(), StatusCode::CREATED);
    }
    let first_page = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            &format!("{SERVICE_ACCOUNTS_PATH}?limit=1"),
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    let cursor = first_page["next_cursor"]
        .as_str()
        .ok_or("bounded account page must expose a continuation cursor")?;
    let second_page = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            &format!("{SERVICE_ACCOUNTS_PATH}?limit=1&cursor={cursor}"),
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    assert_ne!(first_page["items"][0]["id"], second_page["items"][0]["id"]);

    let other_user = SubjectId::new();
    let mut connection = context.pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(other_user.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
    drop(connection);
    let other_account = context
        .api_key_store
        .create_service_account("other-tenantless", None, other_user)
        .await?;
    let owner_only = request(
        &context.app,
        Method::GET,
        &SERVICE_ACCOUNT_PATH.replace("{service_account_id}", &other_account.id.to_string()),
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(owner_only.status(), StatusCode::FORBIDDEN);

    let organization = context
        .tenancy_store
        .create_organization(context.subject_id, OrganizationName::new("managed tenant")?)
        .await?;
    let mut connection = context.pool.acquire().await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 1, $3, $3)",
    )
    .bind(organization.organization.id.as_uuid())
    .bind(other_user.as_uuid())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let tenant_account = context
        .api_key_store
        .create_service_account(
            "tenant-policy-managed",
            Some(organization.organization.id),
            other_user,
        )
        .await?;
    let tenant_policy = request(
        &context.app,
        Method::GET,
        &SERVICE_ACCOUNT_PATH.replace("{service_account_id}", &tenant_account.id.to_string()),
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(tenant_policy.status(), StatusCode::OK);
    let mut connection = context.pool.acquire().await?;
    sqlx::query("UPDATE organizations SET status = 'suspended', updated_at = $2 WHERE id = $1")
        .bind(organization.organization.id.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
    drop(connection);
    let stale_membership = request(
        &context.app,
        Method::GET,
        &SERVICE_ACCOUNT_PATH.replace("{service_account_id}", &tenant_account.id.to_string()),
        Some(&cookie),
        None,
        None,
    )
    .await?;
    assert_eq!(stale_membership.status(), StatusCode::FORBIDDEN);

    let rotated = response_json::<Value>(
        request(
            &context.app,
            Method::POST,
            &API_KEY_ROTATE_PATH.replace("{api_key_id}", &old_key_id),
            Some(&cookie),
            Some(TRUSTED_ORIGIN),
            Some(json!({ "expires_at": null })),
        )
        .await?,
    )
    .await?;
    let new_secret = rotated["api_key"]
        .as_str()
        .ok_or("rotation must reveal one replacement presentation")?
        .to_owned();
    assert_ne!(old_secret, new_secret);
    assert_eq!(rotated["metadata"]["rotated_from_id"], old_key_id);
    let overlap = request_with_authorizations(
        &context.app,
        "/whoami",
        None,
        std::slice::from_ref(&api_authorization),
    )
    .await?;
    assert_eq!(overlap.status(), StatusCode::OK);
    let rotated_page = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            &format!(
                "{}?limit=1",
                SERVICE_ACCOUNT_API_KEYS_PATH.replace("{service_account_id}", &account_id)
            ),
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    let key_cursor = rotated_page["next_cursor"]
        .as_str()
        .ok_or("rotated key inventory must expose a continuation cursor")?;
    let older_key_page = response_json::<Value>(
        request(
            &context.app,
            Method::GET,
            &format!(
                "{}?limit=1&cursor={key_cursor}",
                SERVICE_ACCOUNT_API_KEYS_PATH.replace("{service_account_id}", &account_id)
            ),
            Some(&cookie),
            None,
            None,
        )
        .await?,
    )
    .await?;
    assert_ne!(
        rotated_page["items"][0]["id"],
        older_key_page["items"][0]["id"]
    );

    let revoked = request(
        &context.app,
        Method::DELETE,
        &API_KEY_PATH.replace("{api_key_id}", &old_key_id),
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    let revoked_again = request(
        &context.app,
        Method::DELETE,
        &API_KEY_PATH.replace("{api_key_id}", &old_key_id),
        Some(&cookie),
        Some(TRUSTED_ORIGIN),
        None,
    )
    .await?;
    assert_eq!(revoked_again.status(), StatusCode::NO_CONTENT);
    let rejected_old =
        request_with_authorizations(&context.app, "/whoami", None, &[api_authorization]).await?;
    assert_eq!(rejected_old.status(), StatusCode::UNAUTHORIZED);

    let new_authorization = format!("ApiKey {new_secret}");
    let replacement_active = request_with_authorizations(
        &context.app,
        "/whoami",
        None,
        std::slice::from_ref(&new_authorization),
    )
    .await?;
    assert_eq!(replacement_active.status(), StatusCode::OK);
    for _ in 0..2 {
        let disabled = request(
            &context.app,
            Method::DELETE,
            &SERVICE_ACCOUNT_PATH.replace("{service_account_id}", &account_id),
            Some(&cookie),
            Some(TRUSTED_ORIGIN),
            None,
        )
        .await?;
        assert_eq!(disabled.status(), StatusCode::NO_CONTENT);
    }
    let rejected_replacement =
        request_with_authorizations(&context.app, "/whoami", None, &[new_authorization]).await?;
    assert_eq!(rejected_replacement.status(), StatusCode::UNAUTHORIZED);

    context.fixture.cleanup().await?;
    Ok(())
}
