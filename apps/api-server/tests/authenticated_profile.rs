//! Authenticated-profile contract proving real session and JWT adapters converge on `Principal`.

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header},
    routing::get,
};
use std::{error::Error, time::Duration};

use axum_login::{AuthManagerLayerBuilder, AuthSession, AuthnBackend as _};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use rsk_api_server::{AuthenticatedIdentityState, authenticated_identity_router};
use rsk_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, SessionConfig,
    testing::{TestPrincipalFactory, ensure_principal_matches},
};
use rsk_auth_jwt::{JwtAlgorithm, JwtConfig, JwtIssuerConfig, JwtVerifier};
use rsk_auth_session_postgres::{
    PostgresSessionLifecycle, SessionBackend, SessionRegistration, session_manager_layer,
};
use rsk_config::DeploymentEnvironment;
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_outbound_http::{OutboundHttpClients, OutboundHttpConfig};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{
    PostgresFixture, ProviderFake, ProviderMock, ProviderResponse, provider_matchers,
};
use serde::{Serialize, de::DeserializeOwned};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const AUTH_HEAD: i64 = 2_026_082_312;
const ISSUER: &str = "https://issuer.example.test";
const AUDIENCE: &str = "authenticated-profile";
const KEY_ID: &str = "profile-key";
const SIGNING_KEY: &[u8] = include_bytes!("../../../crates/auth-jwt/tests/test_rsa_key.pem");

#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    exp: i64,
    nbf: i64,
    iat: i64,
    kind: PrincipalKind,
    assurance: AssuranceLevel,
}

type BrowserAuthSession = AuthSession<SessionBackend>;

#[derive(Clone)]
struct LoginState {
    pool: PostgresPool,
    subject_id: rsk_auth_core::SubjectId,
    authenticated_at: OffsetDateTime,
}

async fn login(
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
            &SessionConfig::default(),
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

fn cookie_pair(response: &axum::response::Response) -> Result<String, Box<dyn Error>> {
    Ok(response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or("login did not set a session cookie")?
        .to_str()?
        .split(';')
        .next()
        .ok_or("session cookie was empty")?
        .to_owned())
}

async fn response_json<T: DeserializeOwned>(
    response: axum::response::Response,
) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 64 * 1024).await?,
    )?)
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
        application_name: "rsk-authenticated-profile-test".to_owned(),
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

fn signing_key() -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    EncodingKey::from_rsa_pem(SIGNING_KEY)
}

fn jwks() -> Result<String, Box<dyn Error>> {
    let mut key = Jwk::from_encoding_key(&signing_key()?, Algorithm::RS256)?;
    key.common.key_id = Some(KEY_ID.to_owned());
    key.common.public_key_use = Some(PublicKeyUse::Signature);
    key.common.key_operations = Some(vec![KeyOperations::Verify]);
    Ok(serde_json::to_string(&JwkSet { keys: vec![key] })?)
}

fn token(claims: &Claims) -> Result<String, jsonwebtoken::errors::Error> {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KEY_ID.to_owned());
    header.typ = Some("at+jwt".to_owned());
    encode(&header, claims, &signing_key()?)
}

fn jwt_config(fake: &ProviderFake) -> Result<JwtConfig, Box<dyn Error>> {
    Ok(JwtConfig {
        enabled: true,
        issuers: vec![JwtIssuerConfig {
            issuer: ISSUER.to_owned(),
            jwks_url: fake.endpoint("/jwks")?.to_string(),
        }],
        audiences: vec![AUDIENCE.to_owned()],
        algorithms: vec![JwtAlgorithm::RS256],
        token_types: vec!["at+jwt".to_owned()],
        min_refresh_interval: Duration::from_secs(30),
        ..JwtConfig::default()
    })
}

fn assert_same_identity(session: &Principal, jwt: &Principal) {
    assert_eq!(session.subject_id, jwt.subject_id);
    assert_eq!(session.kind, jwt.kind);
    assert_eq!(session.tenant_id, jwt.tenant_id);
    assert_eq!(session.authenticated_at, jwt.authenticated_at);
    assert_eq!(session.assurance, jwt.assurance);
    assert_eq!(session.scopes, jwt.scopes);
    assert_eq!(session.auth_method, AuthMethod::Session);
    assert_eq!(jwt.auth_method, AuthMethod::Jwt);
}

async fn assert_endpoint_mapping(
    fixture: PostgresFixture,
    pool: PostgresPool,
    subject_id: rsk_auth_core::SubjectId,
    authenticated_at: OffsetDateTime,
    verifier: JwtVerifier,
    bearer_token: &str,
) -> Result<(), Box<dyn Error>> {
    let session_config = SessionConfig::default();
    let login_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(pool.clone()),
        session_manager_layer(&pool, &session_config, DeploymentEnvironment::Test)?,
    )
    .build();
    let login_app = Router::new()
        .route("/test-login", get(login))
        .with_state(LoginState {
            pool: pool.clone(),
            subject_id,
            authenticated_at,
        })
        .layer(login_layer);
    let login_response = login_app
        .oneshot(Request::builder().uri("/test-login").body(Body::empty())?)
        .await?;
    assert_eq!(login_response.status(), StatusCode::NO_CONTENT);
    let session_cookie = cookie_pair(&login_response)?;

    let identity_app = authenticated_identity_router(
        AuthenticatedIdentityState::new(pool, session_config, Some(verifier)),
        DeploymentEnvironment::Test,
    )?;
    let session_response = identity_app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(session_response.status(), StatusCode::OK);
    assert_eq!(
        session_response.headers().get(header::CACHE_CONTROL),
        Some(&"no-store".parse()?)
    );
    let session_json: serde_json::Value = response_json(session_response).await?;
    fixture.cleanup().await?;
    let bearer_response = identity_app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {bearer_token}"))
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(bearer_response.status(), StatusCode::OK);
    assert_eq!(
        bearer_response.headers().get(header::CACHE_CONTROL),
        Some(&"no-store".parse()?)
    );
    let bearer_json: serde_json::Value = response_json(bearer_response).await?;

    assert_eq!(session_json["auth_method"], "session");
    assert_eq!(bearer_json["auth_method"], "jwt");
    for field in [
        "subject_id",
        "kind",
        "tenant_id",
        "authenticated_at",
        "assurance",
        "scopes",
    ] {
        assert_eq!(session_json[field], bearer_json[field], "{field}");
    }
    Ok(())
}

#[tokio::test]
async fn real_session_and_jwt_adapters_satisfy_the_canonical_principal_contract()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool =
        PostgresPool::connect(&postgres_config(&fixture), DeploymentEnvironment::Test).await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, AUTH_HEAD)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;

    let template = TestPrincipalFactory::default()
        .with_tenant_id(None)
        .with_assurance(AssuranceLevel::Aal1)
        .build()?;
    let subject_id = template.subject_id;
    let authenticated_at =
        OffsetDateTime::from_unix_timestamp(OffsetDateTime::now_utc().unix_timestamp())?;
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(subject_id.as_uuid())
        .bind(authenticated_at)
        .execute(&mut *connection)
        .await?;
    drop(connection);

    let session_user = SessionBackend::new(pool.clone())
        .get_user(&subject_id)
        .await?
        .ok_or("session adapter did not restore the user")?;
    let session_principal = session_user.principal(authenticated_at);
    let expected_session = TestPrincipalFactory::new(subject_id, authenticated_at)
        .with_auth_method(AuthMethod::Session)
        .with_assurance(AssuranceLevel::Aal1)
        .build()?;
    ensure_principal_matches(&session_principal, &expected_session)?;

    let fake = ProviderFake::start().await?;
    let jwks_guard = fake
        .mount_scoped(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/jwks"))
                .respond_with(ProviderResponse::new(200).set_body_raw(jwks()?, "application/json"))
                .expect(1),
        )
        .await;
    let verifier = JwtVerifier::initialize(
        &jwt_config(&fake)?,
        DeploymentEnvironment::Test,
        OutboundHttpClients::new(&OutboundHttpConfig::default())?,
    )
    .await?;
    drop(jwks_guard);
    let issued_at = authenticated_at.unix_timestamp();
    let claims = Claims {
        sub: subject_id.to_string(),
        iss: ISSUER.to_owned(),
        aud: vec![AUDIENCE.to_owned()],
        exp: issued_at + 300,
        nbf: issued_at - 1,
        iat: issued_at,
        kind: PrincipalKind::User,
        assurance: AssuranceLevel::Aal1,
    };
    let bearer_token = token(&claims)?;
    let jwt_principal = verifier.verify(&bearer_token).await?;
    let expected_jwt = TestPrincipalFactory::new(subject_id, authenticated_at)
        .with_auth_method(AuthMethod::Jwt)
        .with_assurance(AssuranceLevel::Aal1)
        .build()?;
    ensure_principal_matches(&jwt_principal, &expected_jwt)?;
    assert_same_identity(&session_principal, &jwt_principal);

    assert_endpoint_mapping(
        fixture,
        pool,
        subject_id,
        authenticated_at,
        verifier,
        &bearer_token,
    )
    .await?;
    Ok(())
}
