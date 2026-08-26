//! End-to-end OIDC identity linking and recovery invariants against PostgreSQL.

use std::{error::Error, time::Duration};

use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_auth_oidc::{
    AccountOutcome, CompletedAuthorization, IdentityLinkOutcome, OidcConfig, OidcFlow,
    OidcIdentityStore, OidcPendingStore, OidcProviderConfig, OidcStoreError, UnlinkOutcome,
};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_outbound_http::{
    BuildError, OutboundHttpClients, OutboundHttpConfig, OutboundUrlPolicyConfig,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{ProviderFake, ProviderMock, ProviderResponse, provider_matchers};
use serde::Serialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const CLIENT_ID: &str = "oidc-identity-store-test";
const SIGNING_KEY: &[u8] = include_bytes!("../../auth-jwt/tests/test_rsa_key.pem");
const SIGNING_KEY_ID: &str = "identity-store-key";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Serialize)]
struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-auth-oidc-identity-store-test".to_owned(),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

fn outbound_clients() -> Result<OutboundHttpClients, BuildError> {
    let config = OutboundHttpConfig {
        url_policy: OutboundUrlPolicyConfig {
            allow_development_loopback_http: true,
            ..OutboundUrlPolicyConfig::default()
        },
        ..OutboundHttpConfig::default()
    };
    OutboundHttpClients::new(&config)
}

fn redirect_uri(provider_id: &str) -> String {
    format!("https://service.example.test/oidc/callback/{provider_id}")
}

fn provider_config(provider_id: &str, fake: &ProviderFake) -> OidcProviderConfig {
    OidcProviderConfig {
        provider_id: provider_id.to_owned(),
        issuer: fake.base_url().as_str().to_owned(),
        client_id: CLIENT_ID.to_owned(),
        client_secret: SecretString::from("test-client-secret".to_owned()),
        redirect_uri: redirect_uri(provider_id),
        scopes: vec!["openid".to_owned(), "email".to_owned()],
    }
}

fn oidc_config(provider_a: &ProviderFake, provider_b: &ProviderFake) -> OidcConfig {
    OidcConfig {
        enabled: true,
        providers: vec![
            provider_config("provider-a", provider_a),
            provider_config("provider-b", provider_b),
        ],
        ..OidcConfig::default()
    }
}

fn signing_key() -> Result<EncodingKey, jsonwebtoken::errors::Error> {
    EncodingKey::from_rsa_pem(SIGNING_KEY)
}

fn jwks_body() -> TestResult<String> {
    let mut key = Jwk::from_encoding_key(&signing_key()?, Algorithm::RS256)?;
    key.common.key_id = Some(SIGNING_KEY_ID.to_owned());
    key.common.public_key_use = Some(PublicKeyUse::Signature);
    key.common.key_operations = Some(vec![KeyOperations::Verify]);
    Ok(serde_json::to_string(&JwkSet { keys: vec![key] })?)
}

async fn mount_provider(fake: &ProviderFake) -> TestResult {
    let issuer = fake.base_url().as_str();
    let discovery = json!({
        "issuer": issuer,
        "authorization_endpoint": fake.endpoint("/authorize")?,
        "token_endpoint": fake.endpoint("/token")?,
        "jwks_uri": fake.endpoint("/jwks")?,
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"]
    });
    fake.mount(
        ProviderMock::given(provider_matchers::method("GET"))
            .and(provider_matchers::path("/.well-known/openid-configuration"))
            .respond_with(ProviderResponse::new(200).set_body_json(discovery))
            .expect(1),
    )
    .await;
    fake.mount(
        ProviderMock::given(provider_matchers::method("GET"))
            .and(provider_matchers::path("/jwks"))
            .respond_with(ProviderResponse::new(200).set_body_raw(jwks_body()?, "application/json"))
            .expect(1),
    )
    .await;
    Ok(())
}

fn user_principal_at(
    subject_id: SubjectId,
    authenticated_at: OffsetDateTime,
) -> TestResult<Principal> {
    Ok(Principal::new(
        subject_id,
        PrincipalKind::User,
        None,
        AuthMethod::Password,
        authenticated_at,
        AssuranceLevel::Aal2,
        Vec::new(),
    )?)
}

fn id_token(
    fake: &ProviderFake,
    provider_subject: &str,
    nonce: String,
    email: Option<&str>,
) -> TestResult<String> {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = IdTokenClaims {
        iss: fake.base_url().as_str().to_owned(),
        sub: provider_subject.to_owned(),
        aud: CLIENT_ID.to_owned(),
        exp: now + 300,
        iat: now,
        nonce,
        email: email.map(str::to_owned),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(SIGNING_KEY_ID.to_owned());
    Ok(encode(&header, &claims, &signing_key()?)?)
}

#[expect(
    clippy::too_many_arguments,
    reason = "provider protocol fixtures keep each security input explicit"
)]
async fn verified_authorization(
    flow: &OidcFlow,
    pending_store: &OidcPendingStore,
    fake: &ProviderFake,
    provider_id: &str,
    provider_subject: &str,
    email: Option<&str>,
    link_subject: Option<SubjectId>,
    link_authenticated_at: Option<OffsetDateTime>,
) -> TestResult<CompletedAuthorization> {
    let start = if let Some(subject_id) = link_subject {
        let principal = user_principal_at(
            subject_id,
            link_authenticated_at.unwrap_or_else(OffsetDateTime::now_utc),
        )?;
        flow.start_link(provider_id, &principal)?
    } else {
        flow.start_login(provider_id)?
    };
    let issued = pending_store.issue(start).await?;
    let (authorization_url, pending_id) = issued.into_parts();
    let query = authorization_url
        .query_pairs()
        .into_owned()
        .collect::<std::collections::HashMap<String, String>>();
    let state = query
        .get("state")
        .cloned()
        .ok_or("authorization URL omitted state")?;
    let nonce = query
        .get("nonce")
        .cloned()
        .ok_or("authorization URL omitted nonce")?;
    let code = format!("code-{}", Uuid::now_v7());
    let signed_id_token = id_token(fake, provider_subject, nonce, email)?;
    let token_guard = fake
        .mount_scoped(
            ProviderMock::given(provider_matchers::method("POST"))
                .and(provider_matchers::path("/token"))
                .and(provider_matchers::body_string_contains(format!(
                    "code={code}"
                )))
                .respond_with(ProviderResponse::new(200).set_body_json(json!({
                    "access_token": "opaque-test-access-token",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "id_token": signed_id_token
                })))
                .expect(1),
        )
        .await;
    let taken = pending_store.take(pending_id).await?;
    let result = flow
        .complete(
            taken,
            provider_id,
            &redirect_uri(provider_id),
            &code,
            &state,
        )
        .await?;
    drop(token_guard);
    Ok(result)
}

fn expect_link(outcome: AccountOutcome, expected: IdentityLinkOutcome) -> TestResult<Principal> {
    match outcome {
        AccountOutcome::Link { principal, outcome } if outcome == expected => Ok(principal),
        other => Err(format!("unexpected link outcome: {other:?}").into()),
    }
}

fn expect_login(outcome: AccountOutcome) -> TestResult<Principal> {
    match outcome {
        AccountOutcome::Login(principal) => Ok(principal),
        other @ AccountOutcome::Link { .. } => {
            Err(format!("unexpected login outcome: {other:?}").into())
        }
    }
}

async fn insert_user(
    pool: &PostgresPool,
    subject_id: SubjectId,
    created_at: OffsetDateTime,
) -> TestResult {
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(subject_id.as_uuid())
        .bind(created_at)
        .execute(&mut *connection)
        .await?;
    Ok(())
}

async fn insert_identity(
    pool: &PostgresPool,
    subject_id: SubjectId,
    provider: &str,
    provider_subject: &str,
    created_at: OffsetDateTime,
) -> TestResult {
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(provider)
    .bind(provider_subject)
    .bind(created_at)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn insert_password_credential(
    pool: &PostgresPool,
    subject_id: SubjectId,
    created_at: OffsetDateTime,
) -> TestResult {
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO password_credentials \
         (user_id, password_hash, pepper_version, created_at, changed_at, updated_at) \
         VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 0, $2, $2, $2)",
    )
    .bind(subject_id.as_uuid())
    .bind(created_at)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn database_shape(pool: &PostgresPool) -> TestResult<(i64, i64)> {
    let mut connection = pool.acquire().await?;
    Ok(
        sqlx::query_as("SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM identities)")
            .fetch_one(&mut *connection)
            .await?,
    )
}

async fn identity_owner(
    pool: &PostgresPool,
    provider: &str,
    provider_subject: &str,
) -> TestResult<Option<Uuid>> {
    let mut connection = pool.acquire().await?;
    Ok(sqlx::query_scalar(
        "SELECT user_id FROM identities WHERE provider = $1 AND provider_subject = $2",
    )
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(&mut *connection)
    .await?)
}

async fn user_identity_count(pool: &PostgresPool, subject_id: SubjectId) -> TestResult<i64> {
    let mut connection = pool.acquire().await?;
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE user_id = $1")
            .bind(subject_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?,
    )
}

async fn recovery_state(
    pool: &PostgresPool,
    subject_id: SubjectId,
    provider: &str,
    provider_subject: &str,
) -> TestResult<(i64, bool)> {
    let mut connection = pool.acquire().await?;
    Ok(sqlx::query_as(
        "SELECT u.authentication_version, EXISTS( \
             SELECT 1 FROM identities i \
             WHERE i.user_id = u.id AND i.provider = $2 AND i.provider_subject = $3 \
         ) \
         FROM users u WHERE u.id = $1",
    )
    .bind(subject_id.as_uuid())
    .bind(provider)
    .bind(provider_subject)
    .fetch_one(&mut *connection)
    .await?)
}

async fn password_credential_count(pool: &PostgresPool, subject_id: SubjectId) -> TestResult<i64> {
    let mut connection = pool.acquire().await?;
    Ok(
        sqlx::query_scalar("SELECT COUNT(*) FROM password_credentials WHERE user_id = $1")
            .bind(subject_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?,
    )
}

#[expect(
    clippy::too_many_lines,
    reason = "one real provider and database lifecycle proves the cross-operation transaction contract"
)]
#[tokio::test]
async fn identity_store_enforces_explicit_linking_collisions_and_atomic_recovery() -> TestResult {
    let fixture = rsk_test_support::PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;

    let provider_a = ProviderFake::start().await?;
    let provider_b = ProviderFake::start().await?;
    mount_provider(&provider_a).await?;
    mount_provider(&provider_b).await?;
    let config = oidc_config(&provider_a, &provider_b);
    let flow =
        OidcFlow::initialize(&config, DeploymentEnvironment::Test, outbound_clients()?).await?;
    let store = OidcIdentityStore::new(pool.clone(), &config);
    let pending_store = OidcPendingStore::new(pool.clone());
    let issuer_a = provider_a.base_url().as_str().to_owned();
    let issuer_b = provider_b.base_url().as_str().to_owned();

    let created_at = OffsetDateTime::now_utc() - time::Duration::minutes(1);
    let linked_user = SubjectId::new();
    let other_user = SubjectId::new();
    let password_user = SubjectId::new();
    insert_user(&pool, linked_user, created_at).await?;
    insert_user(&pool, other_user, created_at).await?;
    insert_user(&pool, password_user, created_at).await?;
    insert_identity(
        &pool,
        other_user,
        "email",
        "person@example.test",
        created_at,
    )
    .await?;

    let before_unknown_login = database_shape(&pool).await?;
    let unknown_login = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "unknown-subject",
        Some("person@example.test"),
        None,
        None,
    )
    .await?;
    assert_eq!(
        store.complete(unknown_login).await,
        Err(OidcStoreError::IdentityNotLinked)
    );
    assert_eq!(database_shape(&pool).await?, before_unknown_login);
    assert_eq!(
        identity_owner(&pool, &issuer_a, "unknown-subject").await?,
        None
    );

    let first_link = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "linked-subject",
        Some("person@example.test"),
        Some(linked_user),
        None,
    )
    .await?;
    let first_principal = expect_link(
        store.complete(first_link).await?,
        IdentityLinkOutcome::Linked,
    )?;
    assert_eq!(
        (
            first_principal.subject_id,
            first_principal.kind,
            first_principal.auth_method,
            first_principal.assurance,
            first_principal.tenant_id,
            first_principal.scopes.is_empty(),
        ),
        (
            linked_user,
            PrincipalKind::User,
            AuthMethod::Oidc,
            AssuranceLevel::Aal1,
            None,
            true,
        )
    );
    assert_eq!(
        identity_owner(&pool, &issuer_a, "linked-subject").await?,
        Some(linked_user.as_uuid())
    );

    let expiring_provider = ProviderFake::start().await?;
    mount_provider(&expiring_provider).await?;
    let mut short_config = config.clone();
    short_config.providers = vec![provider_config("provider-expiring", &expiring_provider)];
    short_config.link_proof_max_age = Duration::from_secs(30);
    let short_flow = OidcFlow::initialize(
        &short_config,
        DeploymentEnvironment::Test,
        outbound_clients()?,
    )
    .await?;
    let expiring_link = verified_authorization(
        &short_flow,
        &pending_store,
        &expiring_provider,
        "provider-expiring",
        "expired-proof-subject",
        None,
        Some(linked_user),
        Some(OffsetDateTime::now_utc() - time::Duration::seconds(28)),
    )
    .await?;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        store.complete(expiring_link).await,
        Err(OidcStoreError::RecentAuthenticationRequired)
    );
    assert_eq!(
        identity_owner(
            &pool,
            expiring_provider.base_url().as_str(),
            "expired-proof-subject"
        )
        .await?,
        None
    );

    let repeated_link = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "linked-subject",
        None,
        Some(linked_user),
        None,
    )
    .await?;
    expect_link(
        store.complete(repeated_link).await?,
        IdentityLinkOutcome::AlreadyLinked,
    )?;
    assert_eq!(user_identity_count(&pool, linked_user).await?, 1);

    let conflicting_link = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "linked-subject",
        None,
        Some(other_user),
        None,
    )
    .await?;
    assert_eq!(
        store.complete(conflicting_link).await,
        Err(OidcStoreError::IdentityConflict)
    );
    assert_eq!(
        identity_owner(&pool, &issuer_a, "linked-subject").await?,
        Some(linked_user.as_uuid())
    );

    let existing_login = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "linked-subject",
        None,
        None,
        None,
    )
    .await?;
    let login_principal = expect_login(store.complete(existing_login).await?)?;
    assert_eq!(
        (
            login_principal.subject_id,
            login_principal.kind,
            login_principal.auth_method,
        ),
        (linked_user, PrincipalKind::User, AuthMethod::Oidc)
    );

    let second_provider_link = verified_authorization(
        &flow,
        &pending_store,
        &provider_b,
        "provider-b",
        "second-provider-subject",
        None,
        Some(linked_user),
        None,
    )
    .await?;
    let unlink_proof = expect_link(
        store.complete(second_provider_link).await?,
        IdentityLinkOutcome::Linked,
    )?;
    assert_eq!(user_identity_count(&pool, linked_user).await?, 2);
    assert_eq!(
        identity_owner(&pool, &issuer_b, "second-provider-subject").await?,
        Some(linked_user.as_uuid())
    );

    let before_concurrent_unlink =
        recovery_state(&pool, linked_user, &issuer_a, "linked-subject").await?;
    let first_store = store.clone();
    let second_store = store.clone();
    let first_proof = unlink_proof.clone();
    let second_proof = unlink_proof.clone();
    let (first_unlink, second_unlink) = tokio::join!(
        first_store.unlink(&first_proof, &issuer_a, "linked-subject"),
        second_store.unlink(&second_proof, &issuer_a, "linked-subject"),
    );
    let unlink_outcomes = [first_unlink?, second_unlink?];
    assert_eq!(
        (
            unlink_outcomes
                .iter()
                .filter(|outcome| **outcome == UnlinkOutcome::Unlinked)
                .count(),
            unlink_outcomes
                .iter()
                .filter(|outcome| **outcome == UnlinkOutcome::NotLinked)
                .count(),
        ),
        (1, 1)
    );
    assert_eq!(before_concurrent_unlink, (1, true));
    assert_eq!(
        recovery_state(&pool, linked_user, &issuer_a, "linked-subject").await?,
        (2, false)
    );
    assert_eq!(user_identity_count(&pool, linked_user).await?, 1);

    let mut stale_proof = unlink_proof.clone();
    stale_proof.authenticated_at = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let mut non_user_proof = unlink_proof.clone();
    non_user_proof.kind = PrincipalKind::ServiceAccount;
    assert_eq!(
        store
            .unlink(&stale_proof, &issuer_b, "second-provider-subject")
            .await,
        Err(OidcStoreError::RecentAuthenticationRequired)
    );
    assert_eq!(
        store
            .unlink(&non_user_proof, &issuer_b, "second-provider-subject")
            .await,
        Err(OidcStoreError::RecentAuthenticationRequired)
    );
    assert_eq!(
        recovery_state(&pool, linked_user, &issuer_b, "second-provider-subject").await?,
        (2, true)
    );

    assert_eq!(
        store
            .unlink(&unlink_proof, &issuer_b, "second-provider-subject")
            .await,
        Err(OidcStoreError::LastRecoveryMethod)
    );
    assert_eq!(
        recovery_state(&pool, linked_user, &issuer_b, "second-provider-subject").await?,
        (2, true)
    );

    let password_backed_link = verified_authorization(
        &flow,
        &pending_store,
        &provider_a,
        "provider-a",
        "password-backed-subject",
        None,
        Some(password_user),
        None,
    )
    .await?;
    let password_unlink_proof = expect_link(
        store.complete(password_backed_link).await?,
        IdentityLinkOutcome::Linked,
    )?;
    insert_password_credential(&pool, password_user, created_at).await?;
    assert_eq!(
        recovery_state(&pool, password_user, &issuer_a, "password-backed-subject").await?,
        (1, true)
    );
    assert_eq!(
        store
            .unlink(&password_unlink_proof, &issuer_a, "password-backed-subject")
            .await?,
        UnlinkOutcome::Unlinked
    );
    assert_eq!(
        recovery_state(&pool, password_user, &issuer_a, "password-backed-subject").await?,
        (2, false)
    );
    assert_eq!(password_credential_count(&pool, password_user).await?, 1);

    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
