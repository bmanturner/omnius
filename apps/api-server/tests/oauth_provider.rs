//! Real PostgreSQL acceptance coverage for the hosted OAuth/OIDC HTTP flow.

use std::{collections::BTreeSet, error::Error, num::NonZeroUsize, sync::Arc, time::Duration};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode, header},
    routing::get,
};
use axum_login::{AuthManagerLayerBuilder, AuthSession, AuthnBackend as _};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
};
use omnius_auth_core::{AssuranceLevel, Scope, SessionConfig, SessionRegistration, SubjectId};
use omnius_auth_oauth_server::{
    AuthorizationServerConfig, IdTokenClaims, KeyAlgorithm, KeyState, ResourceConfig,
    ResourceScopeConfig, RsaPublicJwk, SigningKeyConfig, TokenPepper,
    ValidatedAuthorizationServerConfig,
};
use omnius_auth_password::{PasswordEngine, PasswordPolicy, PasswordWorker};
use omnius_auth_session_postgres::{
    PostgresSessionLifecycle, SessionBackend, session_manager_layer,
};
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, Grant, PolicyMatrix, PolicyRule, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_outbound_http::{OutboundHttpClients, OutboundHttpConfig, OutboundUrlPolicyConfig};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_rate_limit_local::{
    LocalRateLimitPolicy, LocalRateLimiter, RateLimitIdentityKind, RateLimitOperation,
};
use omnius_reference_api::{
    api_key_auth::{CanonicalPrincipalState, canonical_identity_route, protected_principal_router},
    browser_auth::{BrowserAuthState, BrowserAuthorization, PasswordLoginProvider},
    oauth_provider::{
        AUTHORIZATION_SERVER_METADATA_PATH, OAUTH_AUTHORIZE_PATH, OAUTH_DECISION_PATH,
        OAUTH_INTERACTION_PATH, OAUTH_JWKS_PATH, OAUTH_REGISTER_PATH, OAUTH_REVOKE_PATH,
        OAUTH_TOKEN_PATH, OAUTH_USERINFO_PATH, OAuthAdapter, OAuthProviderBuildInput,
        OAuthRateLimiters, OPENID_CONFIGURATION_PATH, PROTECTED_RESOURCE_METADATA_PATH,
        build_oauth_provider,
    },
};
use omnius_test_support::PostgresFixture;
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use url::Url;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const ISSUER: &str = "http://127.0.0.1:49251";
const CLIENT_ID: &str = "oauth-http-acceptance-client";
const CLIENT_REDIRECT: &str = "https://client.example.test/callback";
const KEY_ID: &str = "oauth-http-acceptance-key";
const VERIFIED_EMAIL: &str = "oauth-user@example.test";
const CODE_VERIFIER: &str = "oauth-acceptance-code-verifier-000000000000";
const PRIVATE_KEY: &str = include_str!("../../../crates/auth-jwt/tests/test_rsa_key.pem");

type BrowserAuthSession = AuthSession<SessionBackend>;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Clone)]
struct LoginState {
    pool: PostgresPool,
    session_config: SessionConfig,
    subject_id: SubjectId,
    authenticated_at: OffsetDateTime,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
}

struct OAuthTestRuntime {
    pool: PostgresPool,
    app: Router,
    admin_adapter: Arc<OAuthAdapter>,
    subject_id: SubjectId,
    session_cookie: String,
}

async fn establish_session(
    State(state): State<LoginState>,
    mut auth: BrowserAuthSession,
) -> Result<StatusCode, StatusCode> {
    let user = auth
        .backend
        .get_user(&state.subject_id)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    auth.login(&user)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    PostgresSessionLifecycle
        .register_after_login(
            &state.pool,
            &auth.session,
            &SessionRegistration {
                subject_id: state.subject_id,
                device_id: Uuid::now_v7(),
                created_at: state.authenticated_at,
                user_agent_hash: None,
                ip_prefix: None,
            },
            &state.session_config,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

fn postgres_config(fixture: &PostgresFixture) -> PostgresConfig {
    PostgresConfig {
        url: fixture.database_url().clone(),
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 6,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-oauth-http-acceptance-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
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

fn denied_browser_authorization() -> TestResult<BrowserAuthorization> {
    let action = Action::new("browser:privileged")?;
    let resource_kind = ResourceKind::new("browser_session")?;
    let rule = PolicyRule::new(action.clone(), resource_kind.clone(), vec![Grant::Owner])?
        .with_required_scopes(vec![Scope::new("browser:privileged")?])?;
    let authorizer = AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
    Ok(BrowserAuthorization::new(authorizer, action, resource_kind))
}

fn browser_auth_state(
    pool: PostgresPool,
    session_config: SessionConfig,
) -> TestResult<BrowserAuthState> {
    let password_worker = PasswordWorker::new(
        PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?,
        NonZeroUsize::new(2).ok_or("password worker concurrency must be nonzero")?,
    );
    Ok(BrowserAuthState::new(
        pool,
        session_config,
        password_worker,
        PasswordLoginProvider::new("email")?,
        denied_browser_authorization()?,
        vec![ISSUER.to_owned()],
    ))
}

fn public_jwk() -> TestResult<RsaPublicJwk> {
    let encoding = EncodingKey::from_rsa_pem(PRIVATE_KEY.as_bytes())?;
    let derived = Jwk::from_encoding_key(&encoding, Algorithm::RS256)?;
    let AlgorithmParameters::RSA(parameters) = derived.algorithm else {
        return Err("test signing key did not produce an RSA JWK".into());
    };
    Ok(RsaPublicJwk {
        kty: "RSA".to_owned(),
        public_key_use: "sig".to_owned(),
        key_ops: vec!["verify".to_owned()],
        alg: "RS256".to_owned(),
        kid: KEY_ID.to_owned(),
        n: parameters.n,
        e: parameters.e,
    })
}

fn authorization_server_config(
    now: OffsetDateTime,
) -> TestResult<ValidatedAuthorizationServerConfig> {
    let config = AuthorizationServerConfig {
        enabled: true,
        issuer: ISSUER.to_owned(),
        token_pepper: Some(TokenPepper::parse(&URL_SAFE_NO_PAD.encode([7_u8; 32]))?),
        dynamic_client_registration: false,
        resources: vec![ResourceConfig {
            uri: ISSUER.to_owned(),
            name: "Loopback acceptance API".to_owned(),
            description: "Root API protected by the test issuer".to_owned(),
            minimum_assurance: AssuranceLevel::Aal1,
            scopes: vec![ResourceScopeConfig {
                name: Scope::new("api:read")?,
                description: "Read the root API".to_owned(),
            }],
        }],
        signing_keys: vec![SigningKeyConfig {
            kid: KEY_ID.to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk: public_jwk()?,
            private_key_pkcs8_pem: Some(SecretString::from(PRIVATE_KEY.to_owned())),
            verification_until: None,
        }],
        ..AuthorizationServerConfig::default()
    };
    config
        .build_for(DeploymentEnvironment::Test, now)?
        .ok_or_else(|| "enabled authorization server did not produce validated config".into())
}

fn rate_limiter(operation: RateLimitOperation) -> TestResult<LocalRateLimiter> {
    Ok(LocalRateLimiter::new(
        operation,
        RateLimitIdentityKind::OAuthClientIp,
        LocalRateLimitPolicy {
            replenish_every: Duration::from_millis(1),
            burst_size: 100,
            identity_buckets: 64,
        },
    )?)
}

fn oauth_rate_limiters() -> TestResult<OAuthRateLimiters> {
    Ok(OAuthRateLimiters {
        authorize: rate_limiter(RateLimitOperation::OAuthAuthorize)?,
        token: rate_limiter(RateLimitOperation::OAuthToken)?,
        register: rate_limiter(RateLimitOperation::OAuthClientRegistration)?,
        revoke: rate_limiter(RateLimitOperation::OAuthRevoke)?,
    })
}

fn encode_form(pairs: &[(&str, &str)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

async fn request(
    app: &Router,
    method: Method,
    path: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
    content_type: Option<&str>,
    body: Option<String>,
) -> TestResult<axum::response::Response> {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        builder = builder.header(header::ORIGIN, origin);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    Ok(app
        .clone()
        .oneshot(builder.body(Body::from(body.unwrap_or_default()))?)
        .await?)
}

async fn bearer_request(
    app: &Router,
    path: &str,
    token: &str,
    cookie: Option<&str>,
) -> TestResult<axum::response::Response> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"));
    if let Some(cookie) = cookie {
        builder = builder.header(header::COOKIE, cookie);
    }
    Ok(app.clone().oneshot(builder.body(Body::empty())?).await?)
}

async fn response_json<T: DeserializeOwned>(response: axum::response::Response) -> TestResult<T> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024).await?,
    )?)
}

fn cookie_pair(response: &axum::response::Response) -> TestResult<String> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("session establishment did not set a cookie")?
        .to_str()?
        .split(';')
        .next()
        .ok_or("session cookie was empty")?
        .to_owned())
}

fn location(response: &axum::response::Response) -> TestResult<Url> {
    Ok(Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .ok_or("redirect omitted Location")?
            .to_str()?,
    )?)
}

fn unique_query_value(url: &Url, name: &str) -> TestResult<String> {
    let mut values = url
        .query_pairs()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.into_owned());
    let value = values.next().ok_or("redirect query value was missing")?;
    if values.next().is_some() {
        return Err("redirect query value was duplicated".into());
    }
    Ok(value)
}

fn assert_cache_header(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("public, max-age=300, immutable")
    );
}

fn assert_cache_no_store(headers: &HeaderMap) {
    assert_eq!(
        headers
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

fn assert_oauth_no_store(headers: &HeaderMap) {
    assert_cache_no_store(headers);
    assert_eq!(
        headers
            .get(header::PRAGMA)
            .and_then(|value| value.to_str().ok()),
        Some("no-cache")
    );
}

fn scope_set(value: &str) -> BTreeSet<String> {
    value.split_ascii_whitespace().map(str::to_owned).collect()
}

fn interaction_scope_names(interaction: &Value) -> TestResult<BTreeSet<String>> {
    let scopes = interaction["scopes"]
        .as_array()
        .ok_or("interaction scopes were not an array")?;
    Ok(scopes
        .iter()
        .map(|scope| {
            scope["name"]
                .as_str()
                .map(str::to_owned)
                .ok_or("interaction scope omitted its name")
        })
        .collect::<Result<_, _>>()?)
}

fn verify_openid_id_token(encoded: &str, jwks: &Value, expected_nonce: &str) -> TestResult<String> {
    let header = decode_header(encoded)?;
    assert_eq!(header.alg, Algorithm::RS256);
    let key_id = header.kid.as_deref().ok_or("ID Token omitted its key ID")?;
    let key_set = serde_json::from_value::<JwkSet>(jwks.clone())?;
    let jwk = key_set
        .keys
        .iter()
        .find(|jwk| jwk.common.key_id.as_deref() == Some(key_id))
        .ok_or("ID Token key ID was absent from the provider JWKS")?;
    let decoding_key = DecodingKey::from_jwk(jwk)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.algorithms = vec![Algorithm::RS256];
    validation.set_required_spec_claims(&["aud", "exp", "iat", "iss", "nonce", "sub"]);
    validation.set_issuer(&[ISSUER]);
    validation.set_audience(&[CLIENT_ID]);
    let claims = decode::<IdTokenClaims>(encoded, &decoding_key, &validation)?.claims;
    assert_eq!(claims.issuer(), ISSUER);
    assert_eq!(claims.audience(), CLIENT_ID);
    assert_eq!(claims.nonce(), Some(expected_nonce));
    assert!(!claims.subject().is_empty());
    Ok(claims.subject().to_owned())
}

async fn authorize_and_approve(
    app: &Router,
    session_cookie: &str,
    scopes: &str,
    resource: Option<&str>,
    expected_resource: &str,
    state: &str,
    nonce: &str,
) -> TestResult<String> {
    assert_eq!(CODE_VERIFIER.len(), 43);
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(CODE_VERIFIER.as_bytes()));
    let mut fields = vec![
        ("client_id", CLIENT_ID),
        ("redirect_uri", CLIENT_REDIRECT),
        ("response_type", "code"),
        ("response_mode", "query"),
        ("scope", scopes),
        ("state", state),
        ("nonce", nonce),
        ("prompt", "consent"),
        ("code_challenge", code_challenge.as_str()),
        ("code_challenge_method", "S256"),
        ("iss", ISSUER),
    ];
    if let Some(resource) = resource {
        fields.push(("resource", resource));
    }
    let authorize_response = request(
        app,
        Method::GET,
        &format!("{OAUTH_AUTHORIZE_PATH}?{}", encode_form(&fields)),
        Some(session_cookie),
        None,
        None,
        None,
    )
    .await?;
    if authorize_response.status() != StatusCode::SEE_OTHER {
        let status = authorize_response.status();
        let body = to_bytes(authorize_response.into_body(), 64 * 1024).await?;
        return Err(format!(
            "authorization returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    assert_oauth_no_store(authorize_response.headers());
    let interaction_redirect = location(&authorize_response)?;
    assert_eq!(interaction_redirect.origin().ascii_serialization(), ISSUER);
    assert_eq!(interaction_redirect.path(), "/authorize");
    assert_eq!(interaction_redirect.query_pairs().count(), 1);
    let request_handle = unique_query_value(&interaction_redirect, "request")?;

    let interaction_response = request(
        app,
        Method::GET,
        &format!(
            "{OAUTH_INTERACTION_PATH}?{}",
            encode_form(&[("request", &request_handle)])
        ),
        None,
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(interaction_response.status(), StatusCode::OK);
    assert_oauth_no_store(interaction_response.headers());
    let interaction: Value = response_json(interaction_response).await?;
    assert_eq!(interaction["client_name"], "OAuth HTTP acceptance client");
    assert_eq!(interaction["resource"], expected_resource);
    assert_eq!(interaction["minimum_assurance"], "aal1");
    assert_eq!(interaction["requirement"], "Consent");
    let interaction_scopes = interaction_scope_names(&interaction)?;
    assert_eq!(interaction_scopes, scope_set(scopes));

    let decision_response = request(
        app,
        Method::POST,
        OAUTH_DECISION_PATH,
        Some(session_cookie),
        Some(ISSUER),
        Some("application/x-www-form-urlencoded"),
        Some(encode_form(&[
            ("request", &request_handle),
            ("decision", "approve"),
        ])),
    )
    .await?;
    assert_eq!(decision_response.status(), StatusCode::SEE_OTHER);
    assert_oauth_no_store(decision_response.headers());
    let client_redirect = location(&decision_response)?;
    assert_eq!(
        &client_redirect[..url::Position::AfterPath],
        CLIENT_REDIRECT
    );
    assert_eq!(client_redirect.query_pairs().count(), 3);
    assert_eq!(unique_query_value(&client_redirect, "state")?, state);
    assert_eq!(unique_query_value(&client_redirect, "iss")?, ISSUER);
    unique_query_value(&client_redirect, "code")
}

async fn exchange_code(
    app: &Router,
    code: &str,
    resource: Option<&str>,
) -> TestResult<TokenResponse> {
    let mut fields = vec![
        ("grant_type", "authorization_code"),
        ("client_id", CLIENT_ID),
        ("code", code),
        ("redirect_uri", CLIENT_REDIRECT),
        ("code_verifier", CODE_VERIFIER),
    ];
    if let Some(resource) = resource {
        fields.push(("resource", resource));
    }
    let response = request(
        app,
        Method::POST,
        OAUTH_TOKEN_PATH,
        None,
        None,
        Some("application/x-www-form-urlencoded"),
        Some(encode_form(&fields)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_oauth_no_store(response.headers());
    response_json(response).await
}

async fn migrated_pool(fixture: &PostgresFixture) -> TestResult<PostgresPool> {
    let pool =
        PostgresPool::connect(&postgres_config(fixture), DeploymentEnvironment::Test).await?;
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
    Ok(pool)
}

async fn seed_verified_user(pool: &PostgresPool, now: OffsetDateTime) -> TestResult<SubjectId> {
    let subject_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(subject_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, 'email', $3, $4, $4)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(VERIFIED_EMAIL)
    .bind(now)
    .execute(&mut *connection)
    .await?;
    Ok(subject_id)
}

async fn establish_test_session(
    pool: &PostgresPool,
    session_config: &SessionConfig,
    subject_id: SubjectId,
    now: OffsetDateTime,
) -> TestResult<String> {
    let login_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(pool.clone()),
        session_manager_layer(pool, session_config, DeploymentEnvironment::Test)?,
    )
    .build();
    let login_app = Router::new()
        .route("/test/session", get(establish_session))
        .with_state(LoginState {
            pool: pool.clone(),
            session_config: session_config.clone(),
            subject_id,
            authenticated_at: now,
        })
        .layer(login_layer);
    let login_response = request(
        &login_app,
        Method::GET,
        "/test/session",
        None,
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(login_response.status(), StatusCode::NO_CONTENT);
    cookie_pair(&login_response)
}

async fn oauth_test_runtime(fixture: &PostgresFixture) -> TestResult<OAuthTestRuntime> {
    let pool = migrated_pool(fixture).await?;
    let now = OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())?;
    let subject_id = seed_verified_user(&pool, now).await?;
    let session_config = SessionConfig::default();
    let session_cookie = establish_test_session(&pool, &session_config, subject_id, now).await?;
    let outbound_http = Arc::new(OutboundHttpClients::new(&OutboundHttpConfig {
        url_policy: OutboundUrlPolicyConfig {
            allow_development_loopback_http: true,
            ..OutboundUrlPolicyConfig::default()
        },
        ..OutboundHttpConfig::default()
    })?);
    let runtime = build_oauth_provider(OAuthProviderBuildInput {
        config: authorization_server_config(now)?,
        pool: pool.clone(),
        outbound_http,
        session_config: session_config.clone(),
        browser_auth: browser_auth_state(pool.clone(), session_config.clone())?,
        local_identity_provider: "email".to_owned(),
        authorization_ui: Url::parse(ISSUER)?,
        deployment: DeploymentEnvironment::Test,
        rate_limits: oauth_rate_limiters()?,
    })?;
    let admin_adapter = Arc::clone(&runtime.adapter);
    let protected = protected_principal_router(
        CanonicalPrincipalState::new(pool.clone(), session_config, None, None)
            .with_oauth_resource_verifier(runtime.resource_verifier),
        DeploymentEnvironment::Test,
        canonical_identity_route(),
    )?;
    Ok(OAuthTestRuntime {
        pool,
        app: runtime.routes.merge(protected),
        admin_adapter,
        subject_id,
        session_cookie,
    })
}

async fn assert_public_metadata(app: &Router) -> TestResult<Value> {
    let discovery_response = request(
        app,
        Method::GET,
        AUTHORIZATION_SERVER_METADATA_PATH,
        None,
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(discovery_response.status(), StatusCode::OK);
    assert_cache_header(discovery_response.headers());
    let discovery: Value = response_json(discovery_response).await?;
    assert_eq!(discovery["issuer"], ISSUER);
    assert_eq!(
        discovery["authorization_endpoint"],
        format!("{ISSUER}{OAUTH_AUTHORIZE_PATH}")
    );
    assert_eq!(
        discovery["token_endpoint"],
        format!("{ISSUER}{OAUTH_TOKEN_PATH}")
    );
    assert!(discovery.get("registration_endpoint").is_none());

    let oidc_response = request(
        app,
        Method::GET,
        OPENID_CONFIGURATION_PATH,
        None,
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(oidc_response.status(), StatusCode::OK);
    assert_cache_header(oidc_response.headers());
    let oidc: Value = response_json(oidc_response).await?;
    assert_eq!(oidc["issuer"], ISSUER);
    assert_eq!(oidc["jwks_uri"], format!("{ISSUER}{OAUTH_JWKS_PATH}"));
    assert!(oidc.get("registration_endpoint").is_none());

    let resource_response = request(
        app,
        Method::GET,
        PROTECTED_RESOURCE_METADATA_PATH,
        None,
        None,
        None,
        None,
    )
    .await?;
    assert_eq!(resource_response.status(), StatusCode::OK);
    assert_cache_header(resource_response.headers());
    let resource_metadata: Value = response_json(resource_response).await?;
    assert_eq!(resource_metadata["resource"], ISSUER);
    assert_eq!(resource_metadata["authorization_servers"], json!([ISSUER]));

    let jwks_response = request(app, Method::GET, OAUTH_JWKS_PATH, None, None, None, None).await?;
    assert_eq!(jwks_response.status(), StatusCode::OK);
    assert_cache_header(jwks_response.headers());
    let jwks: Value = response_json(jwks_response).await?;
    assert_eq!(jwks["keys"].as_array().map(Vec::len), Some(1));
    assert_eq!(jwks["keys"][0]["kid"], KEY_ID);
    assert_eq!(jwks["keys"][0]["alg"], "RS256");
    assert!(jwks["keys"][0].get("d").is_none());
    Ok(jwks)
}

async fn register_test_client(admin_adapter: &OAuthAdapter) -> TestResult {
    admin_adapter
        .register_pre_registered_json(
            serde_json::to_string(&json!({
                "client_id": CLIENT_ID,
                "client_name": "OAuth HTTP acceptance client",
                "redirect_uris": [CLIENT_REDIRECT],
                "application_type": "web",
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": ["openid", "offline_access", "api:read"]
            }))?
            .as_bytes(),
            16 * 1024,
        )
        .await?;
    Ok(())
}

async fn assert_root_resource_authorization(
    runtime: &OAuthTestRuntime,
) -> TestResult<TokenResponse> {
    let root_code = authorize_and_approve(
        &runtime.app,
        &runtime.session_cookie,
        "openid offline_access api:read",
        Some(ISSUER),
        ISSUER,
        "root-resource-state",
        "root-resource-nonce",
    )
    .await?;
    let root_tokens = exchange_code(&runtime.app, &root_code, Some(ISSUER)).await?;
    assert_eq!(root_tokens.token_type, "Bearer");
    assert_eq!(
        scope_set(&root_tokens.scope),
        scope_set("openid offline_access api:read")
    );
    assert!(root_tokens.id_token.as_deref().is_some());
    let _refresh_token = root_tokens
        .refresh_token
        .as_deref()
        .ok_or("offline access omitted refresh token")?;

    let bearer_whoami = bearer_request(
        &runtime.app,
        "/whoami",
        &root_tokens.access_token,
        Some(&runtime.session_cookie),
    )
    .await?;
    assert_eq!(bearer_whoami.status(), StatusCode::OK);
    assert_cache_no_store(bearer_whoami.headers());
    let principal: Value = response_json(bearer_whoami).await?;
    assert_eq!(principal["subject_id"], runtime.subject_id.to_string());
    assert_eq!(principal["auth_method"], "jwt");
    Ok(root_tokens)
}

async fn assert_oidc_userinfo_authorization(
    runtime: &OAuthTestRuntime,
    jwks: &Value,
) -> TestResult {
    let oidc_code = authorize_and_approve(
        &runtime.app,
        &runtime.session_cookie,
        "openid offline_access",
        None,
        &format!("{ISSUER}{OAUTH_USERINFO_PATH}"),
        "userinfo-state",
        "userinfo-nonce",
    )
    .await?;
    let oidc_tokens = exchange_code(&runtime.app, &oidc_code, None).await?;
    assert_eq!(
        scope_set(&oidc_tokens.scope),
        scope_set("openid offline_access")
    );
    assert!(oidc_tokens.refresh_token.is_some());
    let id_token_subject = verify_openid_id_token(
        oidc_tokens
            .id_token
            .as_deref()
            .ok_or("OIDC exchange omitted its ID Token")?,
        jwks,
        "userinfo-nonce",
    )?;
    assert_ne!(id_token_subject, runtime.subject_id.to_string());
    let userinfo_response = bearer_request(
        &runtime.app,
        OAUTH_USERINFO_PATH,
        &oidc_tokens.access_token,
        None,
    )
    .await?;
    assert_eq!(userinfo_response.status(), StatusCode::OK);
    assert_oauth_no_store(userinfo_response.headers());
    let userinfo: Value = response_json(userinfo_response).await?;
    assert_eq!(userinfo["sub"], id_token_subject);
    assert!(userinfo.get("email").is_none());
    Ok(())
}

async fn refresh_and_revoke_root_token(
    runtime: &OAuthTestRuntime,
    root_tokens: &TokenResponse,
) -> TestResult {
    let refresh_token = root_tokens
        .refresh_token
        .as_deref()
        .ok_or("offline access omitted refresh token")?;
    let refresh_response = request(
        &runtime.app,
        Method::POST,
        OAUTH_TOKEN_PATH,
        None,
        None,
        Some("application/x-www-form-urlencoded"),
        Some(encode_form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token),
            ("resource", ISSUER),
        ])),
    )
    .await?;
    assert_eq!(refresh_response.status(), StatusCode::OK);
    assert_oauth_no_store(refresh_response.headers());
    let refreshed: TokenResponse = response_json(refresh_response).await?;
    let refreshed_refresh = refreshed
        .refresh_token
        .as_deref()
        .ok_or("refresh omitted rotated refresh token")?;
    assert_ne!(refreshed.access_token, root_tokens.access_token);
    assert_ne!(refreshed_refresh, refresh_token);

    let refreshed_whoami = bearer_request(
        &runtime.app,
        "/whoami",
        &refreshed.access_token,
        Some(&runtime.session_cookie),
    )
    .await?;
    assert_eq!(refreshed_whoami.status(), StatusCode::OK);

    let revoke_response = request(
        &runtime.app,
        Method::POST,
        OAUTH_REVOKE_PATH,
        None,
        None,
        Some("application/x-www-form-urlencoded"),
        Some(encode_form(&[
            ("client_id", CLIENT_ID),
            ("token", &refreshed.access_token),
            ("token_type_hint", "access_token"),
        ])),
    )
    .await?;
    assert_eq!(revoke_response.status(), StatusCode::OK);
    assert_oauth_no_store(revoke_response.headers());

    let revoked_whoami = bearer_request(
        &runtime.app,
        "/whoami",
        &refreshed.access_token,
        Some(&runtime.session_cookie),
    )
    .await?;
    assert_eq!(revoked_whoami.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

async fn assert_disabled_surfaces(runtime: &OAuthTestRuntime) -> TestResult {
    let dcr_response = request(
        &runtime.app,
        Method::POST,
        OAUTH_REGISTER_PATH,
        None,
        None,
        Some("application/json"),
        Some("{}".to_owned()),
    )
    .await?;
    assert_eq!(dcr_response.status(), StatusCode::NOT_FOUND);
    let client_count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_clients")
        .fetch_one(&runtime.pool.sqlx_pool())
        .await?;
    assert_eq!(client_count, 1);

    for path in ["/mcp", "/.well-known/oauth-protected-resource/mcp"] {
        let response = request(&runtime.app, Method::GET, path, None, None, None, None).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    Ok(())
}

#[tokio::test]
async fn oauth_provider_http_flow_issues_refreshes_and_revokes_a_root_resource_token() -> TestResult
{
    let fixture = PostgresFixture::start().await?;
    let runtime = oauth_test_runtime(&fixture).await?;
    let jwks = assert_public_metadata(&runtime.app).await?;
    register_test_client(&runtime.admin_adapter).await?;
    let root_tokens = assert_root_resource_authorization(&runtime).await?;
    assert_oidc_userinfo_authorization(&runtime, &jwks).await?;
    refresh_and_revoke_root_token(&runtime, &root_tokens).await?;
    assert_disabled_surfaces(&runtime).await?;
    fixture.cleanup().await?;
    Ok(())
}
