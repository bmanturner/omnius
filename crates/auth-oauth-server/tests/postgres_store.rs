//! Disposable PostgreSQL coverage for OAuth one-use, revocation, and cleanup invariants.

use std::{error::Error, time::Duration as StdDuration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Scope, SubjectId};
use omnius_auth_oauth_server::{
    cleanup::{OAuthCleanup, OAuthCleanupError},
    crypto::BearerDigest,
    store::{
        AccessRevocationReason, AccessTokenLiveCheck, AccessTokenRevocation,
        AuthorizationCodeBinding, AuthorizationCodeCreate, AuthorizationCodeExchange,
        AuthorizationCodeRejection, AuthorizationDecision, AuthorizationInteractionRequirement,
        AuthorizationInteractionScope, AuthorizationRequestCreate, AuthorizationRequestLoad,
        AuthorizationTransition, ClientAssertionRecord, ClientMetadataCache, ClientSource,
        ClientStatus, ClientUpsert, GrantCreate, OAuthPostgresStore, OAuthStoreError,
        PublicSubject, RefreshFamilyIssue, RefreshRotation,
    },
    types::{
        ApplicationType, ClientId, GrantType, IssuerUri, JwtId, PkceVerifier, RedirectUri,
        ResourceUri, ResponseMode, ResponseType, TokenEndpointAuthMethod,
    },
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use serde_json::json;
use sqlx::Row as _;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

impl TestDatabase {
    async fn start() -> TestResult<Self> {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &postgres_config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        let runner = MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
            migration_config(),
            DeploymentEnvironment::Test,
        )?;
        runner.run().await?;
        Ok(Self {
            pool,
            _fixture: fixture,
        })
    }
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 8,
        connect_timeout: StdDuration::from_secs(5),
        acquire_timeout: StdDuration::from_secs(2),
        idle_timeout: StdDuration::from_secs(30),
        max_lifetime: StdDuration::from_secs(60),
        max_lifetime_jitter: StdDuration::from_secs(10),
        application_name: "omnius-oauth-postgres-store-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: StdDuration::from_secs(5),
        lock_timeout: StdDuration::from_secs(2),
        health_timeout: StdDuration::from_secs(2),
        shutdown_timeout: StdDuration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: StdDuration::from_millis(5),
            max_delay: StdDuration::from_millis(50),
            max_jitter: StdDuration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: StdDuration::from_secs(10),
    }
}

async fn seed_active_user(
    pool: &PostgresPool,
    now: OffsetDateTime,
    with_email: bool,
) -> TestResult<SubjectId> {
    let user_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(user_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    if with_email {
        sqlx::query(
            "INSERT INTO identities \
             (id, user_id, provider, provider_subject, created_at, verified_at) \
             VALUES ($1, $2, 'email', 'verified@example.test', $3, $3)",
        )
        .bind(Uuid::now_v7())
        .bind(user_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    }
    Ok(user_id)
}

fn client_registration(
    client_id: &str,
    redirects: &[&str],
    now: OffsetDateTime,
    secret_byte: Option<u8>,
) -> TestResult<ClientUpsert> {
    Ok(ClientUpsert {
        client_id: ClientId::parse(client_id)?,
        source: ClientSource::PreRegistered,
        display_name: "Example Client".to_owned(),
        client_uri: Some("https://client.example.test".to_owned()),
        logo_uri: None,
        application_type: ApplicationType::Web,
        token_endpoint_auth_method: if secret_byte.is_some() {
            TokenEndpointAuthMethod::ClientSecretBasic
        } else {
            TokenEndpointAuthMethod::None
        },
        client_secret_digest: secret_byte.map(|byte| BearerDigest::from_bytes([byte; 32])),
        response_types: vec![ResponseType::Code],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        allowed_scopes: scopes()?,
        public_jwks: None,
        redirect_uris: redirects
            .iter()
            .map(|value| RedirectUri::parse((*value).to_owned()))
            .collect::<Result<Vec<_>, _>>()?,
        post_logout_redirect_uris: vec![RedirectUri::parse(
            "https://client.example.test/logout/callback".to_owned(),
        )?],
        metadata_document_uri: None,
        metadata_cache: None,
        now,
    })
}

fn public_subject(byte: u8) -> TestResult<PublicSubject> {
    Ok(PublicSubject::parse(URL_SAFE_NO_PAD.encode([byte; 32]))?)
}

fn resource() -> TestResult<ResourceUri> {
    Ok(ResourceUri::parse(
        "https://api.example.test".to_owned(),
        true,
    )?)
}

fn scopes() -> TestResult<Vec<Scope>> {
    Ok(vec![Scope::new("openid")?, Scope::new("records:read")?])
}

fn grant_input(
    user_id: SubjectId,
    client_id: &str,
    authenticated_at: OffsetDateTime,
    consented_at: OffsetDateTime,
) -> TestResult<GrantCreate> {
    Ok(GrantCreate {
        user_id,
        tenant_id: None,
        client_id: ClientId::parse(client_id)?,
        resources: vec![resource()?],
        granted_scopes: scopes()?,
        authenticated_at,
        assurance_level: AssuranceLevel::Aal2,
        authentication_methods: vec![AuthMethod::Password, AuthMethod::Session],
        consented_at,
    })
}

fn authorization_request(
    client_id: &str,
    redirect_uri: &str,
    digest_byte: u8,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
) -> TestResult<AuthorizationRequestCreate> {
    let verifier = PkceVerifier::parse("a".repeat(43))?;
    Ok(AuthorizationRequestCreate {
        handle_digest: BearerDigest::from_bytes([digest_byte; 32]),
        client_id: ClientId::parse(client_id)?,
        redirect_uri: RedirectUri::parse(redirect_uri.to_owned())?,
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        client_state: Some("opaque-state".to_owned()),
        requested_scopes: scopes()?,
        resource_uris: vec![resource()?],
        pkce_code_challenge: verifier.challenge(),
        nonce: Some("nonce-value".to_owned()),
        prompt_values: Vec::new(),
        max_age_seconds: None,
        expected_issuer: IssuerUri::parse("https://issuer.example.test".to_owned(), true)?,
        interaction_resource_name: "Configured API".to_owned(),
        interaction_resource_description: "Configured API resource".to_owned(),
        interaction_minimum_assurance: AssuranceLevel::Aal2,
        interaction_scopes: vec![
            AuthorizationInteractionScope {
                name: Scope::new("openid")?,
                description: "Identify your account".to_owned(),
                newly_requested: false,
            },
            AuthorizationInteractionScope {
                name: Scope::new("records:read")?,
                description: "Read configured records".to_owned(),
                newly_requested: true,
            },
        ],
        interaction_requirement: AuthorizationInteractionRequirement::Login,
        created_at,
        expires_at,
    })
}

#[tokio::test]
async fn client_redirect_assertion_and_subject_state_is_exact_and_stable() -> TestResult {
    let database = TestDatabase::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000)?;
    let user_id = seed_active_user(&database.pool, now, true).await?;
    let store = OAuthPostgresStore::new(database.pool.clone());

    assert_client_redirect_and_assertion_state(&store, now).await?;
    assert_authorization_request_state(&store, now).await?;
    assert_subject_and_verified_email_state(&store, user_id, now).await
}

async fn assert_client_redirect_and_assertion_state(
    store: &OAuthPostgresStore,
    now: OffsetDateTime,
) -> TestResult {
    let initial = client_registration(
        "client-a",
        &[
            "https://client.example.test/callback",
            "https://client.example.test/other",
        ],
        now,
        Some(91),
    )?;
    store.upsert_client(&initial).await?;
    let replacement = client_registration(
        "client-a",
        &["https://client.example.test/callback"],
        now + Duration::seconds(1),
        Some(92),
    )?;
    let persisted = store.upsert_client(&replacement).await?;
    assert_eq!(persisted.redirect_uris, replacement.redirect_uris);
    assert_eq!(persisted.status, ClientStatus::Active);

    let authentication = store
        .load_client_authentication(&ClientId::parse("client-a")?)
        .await?
        .ok_or("missing client authentication")?;
    let debug = format!("{authentication:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("92, 92"));

    assert_eq!(
        store
            .record_client_assertion(
                &ClientId::parse("client-a")?,
                "assertion-jti",
                now,
                now + Duration::minutes(5),
            )
            .await?,
        ClientAssertionRecord::Accepted
    );
    assert_eq!(
        store
            .record_client_assertion(
                &ClientId::parse("client-a")?,
                "assertion-jti",
                now,
                now + Duration::minutes(5),
            )
            .await?,
        ClientAssertionRecord::Replay
    );
    Ok(())
}

async fn assert_authorization_request_state(
    store: &OAuthPostgresStore,
    now: OffsetDateTime,
) -> TestResult {
    let request = authorization_request(
        "client-a",
        "https://client.example.test/callback",
        9,
        now,
        now + Duration::minutes(10),
    )?;
    store.create_authorization_request(&request).await?;
    let AuthorizationRequestLoad::Pending(loaded_request) = store
        .load_authorization_request(&BearerDigest::from_bytes([9; 32]), now)
        .await?
    else {
        return Err("pending authorization request missing".into());
    };
    assert_eq!(
        loaded_request.interaction_resource_name,
        request.interaction_resource_name
    );
    assert_eq!(
        loaded_request.interaction_resource_description,
        request.interaction_resource_description
    );
    assert_eq!(
        loaded_request.interaction_minimum_assurance,
        request.interaction_minimum_assurance
    );
    assert_eq!(
        loaded_request.interaction_scopes,
        request.interaction_scopes
    );
    assert_eq!(
        loaded_request.interaction_requirement,
        AuthorizationInteractionRequirement::Login
    );
    assert!(matches!(
        store
            .transition_authorization_request(
                &BearerDigest::from_bytes([9; 32]),
                AuthorizationDecision::Approve,
                now + Duration::seconds(1),
            )
            .await?,
        AuthorizationTransition::Completed(_)
    ));
    assert!(matches!(
        store
            .transition_authorization_request(
                &BearerDigest::from_bytes([9; 32]),
                AuthorizationDecision::Deny,
                now + Duration::seconds(2),
            )
            .await?,
        AuthorizationTransition::Unavailable
    ));
    Ok(())
}

async fn assert_subject_and_verified_email_state(
    store: &OAuthPostgresStore,
    user_id: SubjectId,
    now: OffsetDateTime,
) -> TestResult {
    let left_store = store.clone();
    let right_store = store.clone();
    let left = public_subject(7)?;
    let right = public_subject(8)?;
    let (left_result, right_result) = tokio::join!(
        left_store.allocate_subject(user_id, left, now),
        right_store.allocate_subject(user_id, right, now)
    );
    let left_result = left_result?;
    let right_result = right_result?;
    assert_eq!(left_result.id, right_result.id);
    assert_eq!(left_result.public_subject, right_result.public_subject);

    let email = store
        .verified_email(user_id, "email")
        .await?
        .ok_or("missing verified email")?;
    assert_eq!(email.as_str(), "verified@example.test");
    Ok(())
}

#[tokio::test]
async fn authorization_codes_are_consumed_once_even_when_binding_validation_fails() -> TestResult {
    let database = TestDatabase::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_100_000)?;
    let user_id = seed_active_user(&database.pool, now, false).await?;
    let store = OAuthPostgresStore::new(database.pool.clone());
    let code = seed_authorization_code(&store, user_id, now).await?;

    assert_concurrent_authorization_code_consumption(&store, now).await?;
    assert_overbroad_authorization_code_is_rejected(&store, &code).await?;
    assert_binding_mismatch_consumes_authorization_code(&store, &code, now).await?;
    assert_stored_binding_violation_consumes_authorization_code(&store, &database.pool, code, now)
        .await
}

async fn seed_authorization_code(
    store: &OAuthPostgresStore,
    user_id: SubjectId,
    now: OffsetDateTime,
) -> TestResult<AuthorizationCodeCreate> {
    let client = client_registration(
        "client-code",
        &["https://client.example.test/callback"],
        now,
        None,
    )?;
    store.upsert_client(&client).await?;
    store
        .allocate_subject(user_id, public_subject(11)?, now)
        .await?;
    let grant = store
        .create_grant(&grant_input(
            user_id,
            "client-code",
            now,
            now + Duration::seconds(1),
        )?)
        .await?;
    let verifier = PkceVerifier::parse("v".repeat(43))?;
    let code = AuthorizationCodeCreate {
        code_digest: BearerDigest::from_bytes([21; 32]),
        grant_id: grant.id,
        client_id: ClientId::parse("client-code")?,
        redirect_uri: RedirectUri::parse("https://client.example.test/callback".to_owned())?,
        resource_uris: vec![resource()?],
        granted_scopes: scopes()?,
        pkce_code_challenge: verifier.challenge(),
        nonce: Some("nonce".to_owned()),
        issued_at: now + Duration::seconds(2),
        expires_at: now + Duration::minutes(2),
    };
    store.persist_authorization_code(&code).await?;
    Ok(code)
}

async fn assert_concurrent_authorization_code_consumption(
    store: &OAuthPostgresStore,
    now: OffsetDateTime,
) -> TestResult {
    let left_store = store.clone();
    let right_store = store.clone();
    let left_binding = AuthorizationCodeBinding {
        client_id: ClientId::parse("client-code")?,
        redirect_uri: RedirectUri::parse("https://client.example.test/callback".to_owned())?,
        resource_uris: vec![resource()?],
        pkce_verifier: PkceVerifier::parse("v".repeat(43))?,
    };
    let right_binding = AuthorizationCodeBinding {
        client_id: ClientId::parse("client-code")?,
        redirect_uri: RedirectUri::parse("https://client.example.test/callback".to_owned())?,
        resource_uris: vec![resource()?],
        pkce_verifier: PkceVerifier::parse("v".repeat(43))?,
    };
    let digest = BearerDigest::from_bytes([21; 32]);
    let (left, right) = tokio::join!(
        left_store.consume_authorization_code(&digest, &left_binding, now + Duration::seconds(3),),
        right_store
            .consume_authorization_code(&digest, &right_binding, now + Duration::seconds(3),)
    );
    let left = left?;
    let right = right?;
    assert!(matches!(
        (&left, &right),
        (
            AuthorizationCodeExchange::Issued(_),
            AuthorizationCodeExchange::Unavailable
        ) | (
            AuthorizationCodeExchange::Unavailable,
            AuthorizationCodeExchange::Issued(_)
        )
    ));
    Ok(())
}

async fn assert_overbroad_authorization_code_is_rejected(
    store: &OAuthPostgresStore,
    code: &AuthorizationCodeCreate,
) -> TestResult {
    let mut overbroad_scopes = scopes()?;
    overbroad_scopes.push(Scope::new("records:write")?);
    let overbroad_code = AuthorizationCodeCreate {
        code_digest: BearerDigest::from_bytes([22; 32]),
        granted_scopes: overbroad_scopes,
        ..code.clone()
    };
    assert_eq!(
        store.persist_authorization_code(&overbroad_code).await,
        Err(OAuthStoreError::Inactive)
    );
    Ok(())
}

async fn assert_binding_mismatch_consumes_authorization_code(
    store: &OAuthPostgresStore,
    code: &AuthorizationCodeCreate,
    now: OffsetDateTime,
) -> TestResult {
    let rejected_code = AuthorizationCodeCreate {
        code_digest: BearerDigest::from_bytes([23; 32]),
        ..code.clone()
    };
    store.persist_authorization_code(&rejected_code).await?;
    let bad_binding = AuthorizationCodeBinding {
        client_id: ClientId::parse("client-code")?,
        redirect_uri: RedirectUri::parse("https://client.example.test/callback".to_owned())?,
        resource_uris: vec![resource()?],
        pkce_verifier: PkceVerifier::parse("x".repeat(43))?,
    };
    assert!(matches!(
        store
            .consume_authorization_code(
                &BearerDigest::from_bytes([23; 32]),
                &bad_binding,
                now + Duration::seconds(4),
            )
            .await?,
        AuthorizationCodeExchange::Rejected(AuthorizationCodeRejection::BindingMismatch)
    ));
    assert!(matches!(
        store
            .consume_authorization_code(
                &BearerDigest::from_bytes([23; 32]),
                &bad_binding,
                now + Duration::seconds(5),
            )
            .await?,
        AuthorizationCodeExchange::Unavailable
    ));
    Ok(())
}

async fn assert_stored_binding_violation_consumes_authorization_code(
    store: &OAuthPostgresStore,
    pool: &PostgresPool,
    code: AuthorizationCodeCreate,
    now: OffsetDateTime,
) -> TestResult {
    let corrupt_code = AuthorizationCodeCreate {
        code_digest: BearerDigest::from_bytes([24; 32]),
        ..code
    };
    store.persist_authorization_code(&corrupt_code).await?;
    let mut connection = pool.acquire().await?;
    sqlx::query("UPDATE oauth_authorization_codes SET granted_scopes = $2 WHERE code_digest = $1")
        .bind(BearerDigest::from_bytes([24; 32]).as_bytes().as_slice())
        .bind(vec![
            "openid".to_owned(),
            "records:read".to_owned(),
            "records:write".to_owned(),
        ])
        .execute(&mut *connection)
        .await?;
    drop(connection);
    let good_binding = AuthorizationCodeBinding {
        client_id: ClientId::parse("client-code")?,
        redirect_uri: RedirectUri::parse("https://client.example.test/callback".to_owned())?,
        resource_uris: vec![resource()?],
        pkce_verifier: PkceVerifier::parse("v".repeat(43))?,
    };
    assert!(matches!(
        store
            .consume_authorization_code(
                &BearerDigest::from_bytes([24; 32]),
                &good_binding,
                now + Duration::seconds(6),
            )
            .await?,
        AuthorizationCodeExchange::Rejected(AuthorizationCodeRejection::StoredBindingViolation)
    ));
    assert!(matches!(
        store
            .consume_authorization_code(
                &BearerDigest::from_bytes([24; 32]),
                &good_binding,
                now + Duration::seconds(7),
            )
            .await?,
        AuthorizationCodeExchange::Unavailable
    ));
    Ok(())
}

#[tokio::test]
async fn refresh_reuse_access_revocation_and_client_disable_close_live_grants() -> TestResult {
    let database = TestDatabase::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_200_000)?;
    let user_id = seed_active_user(&database.pool, now, true).await?;
    let store = OAuthPostgresStore::new(database.pool.clone());

    let subject = assert_refresh_rotation_and_reuse(&store, user_id, now).await?;
    let access_check =
        seed_connected_grants_and_revoke_owner(&store, user_id, &subject, now).await?;
    let revoked_check = assert_access_token_revocation(&store, access_check, now).await?;
    assert_client_disable_closes_live_grant(&store, revoked_check, now).await
}

async fn assert_refresh_rotation_and_reuse(
    store: &OAuthPostgresStore,
    user_id: SubjectId,
    now: OffsetDateTime,
) -> TestResult<PublicSubject> {
    store
        .upsert_client(&client_registration(
            "client-live",
            &["https://client.example.test/callback"],
            now,
            None,
        )?)
        .await?;
    let subject = store
        .allocate_subject(user_id, public_subject(31)?, now)
        .await?;
    let grant = store
        .create_grant(&grant_input(
            user_id,
            "client-live",
            now,
            now + Duration::seconds(1),
        )?)
        .await?;
    let reusable = store
        .find_reusable_grant(
            user_id,
            None,
            &ClientId::parse("client-live")?,
            &[resource()?],
            &scopes()?,
        )
        .await?
        .ok_or("missing reusable grant")?;
    assert_eq!(reusable.id, grant.id);
    let first = BearerDigest::from_bytes([32; 32]);
    let refresh_scopes = vec![Scope::new("openid")?];
    store
        .issue_refresh_family(&RefreshFamilyIssue {
            grant_id: grant.id,
            client_id: ClientId::parse("client-live")?,
            resource: resource()?,
            granted_scopes: refresh_scopes.clone(),
            token_digest: first.clone(),
            issued_at: now + Duration::seconds(2),
            expires_at: now + Duration::days(30),
        })
        .await?;
    let RefreshRotation::Rotated(rotated) = store
        .rotate_refresh_token(
            &first,
            &ClientId::parse("client-live")?,
            &BearerDigest::from_bytes([33; 32]),
            now + Duration::seconds(3),
            now + Duration::days(29),
        )
        .await?
    else {
        return Err("expected successful refresh rotation".into());
    };
    assert_eq!(rotated.resource, resource()?);
    assert_eq!(rotated.granted_scopes, refresh_scopes);

    let access_check = AccessTokenLiveCheck {
        jti: JwtId::new(),
        grant_id: grant.id,
        public_subject: subject.public_subject.clone(),
        client_id: ClientId::parse("client-live")?,
        tenant_id: None,
        resource: resource()?,
        scopes: scopes()?,
    };
    assert!(
        store
            .verify_access_token_live(&access_check, now + Duration::seconds(4))
            .await?
            .is_some()
    );
    assert!(matches!(
        store
            .rotate_refresh_token(
                &first,
                &ClientId::parse("client-live")?,
                &BearerDigest::from_bytes([34; 32]),
                now + Duration::seconds(5),
                now + Duration::days(28),
            )
            .await?,
        RefreshRotation::ReuseDetected { .. }
    ));
    assert!(
        store
            .verify_access_token_live(&access_check, now + Duration::seconds(6))
            .await?
            .is_none()
    );
    Ok(subject.public_subject)
}

async fn seed_connected_grants_and_revoke_owner(
    store: &OAuthPostgresStore,
    user_id: SubjectId,
    subject: &PublicSubject,
    now: OffsetDateTime,
) -> TestResult<AccessTokenLiveCheck> {
    let live_grant = store
        .create_grant(&grant_input(
            user_id,
            "client-live",
            now + Duration::seconds(7),
            now + Duration::seconds(8),
        )?)
        .await?;
    store
        .issue_refresh_family(&RefreshFamilyIssue {
            grant_id: live_grant.id,
            client_id: ClientId::parse("client-live")?,
            resource: resource()?,
            granted_scopes: scopes()?,
            token_digest: BearerDigest::from_bytes([35; 32]),
            issued_at: now + Duration::seconds(8),
            expires_at: now + Duration::days(30),
        })
        .await?;
    let owner_revoked_grant = store
        .create_grant(&grant_input(
            user_id,
            "client-live",
            now + Duration::seconds(8),
            now + Duration::seconds(9),
        )?)
        .await?;
    let connected = store.list_connected_grants(user_id, None, 10).await?;
    assert_eq!(connected.grants.len(), 2);
    assert!(
        connected
            .grants
            .iter()
            .any(|item| item.grant_id == live_grant.id)
    );
    assert!(
        connected
            .grants
            .iter()
            .any(|item| item.grant_id == owner_revoked_grant.id)
    );
    assert!(
        connected
            .grants
            .iter()
            .all(|item| item.client_name == "Example Client")
    );
    let owner_check = AccessTokenLiveCheck {
        jti: JwtId::new(),
        grant_id: owner_revoked_grant.id,
        public_subject: subject.clone(),
        client_id: ClientId::parse("client-live")?,
        tenant_id: None,
        resource: resource()?,
        scopes: scopes()?,
    };
    assert!(
        store
            .verify_access_token_live(&owner_check, now + Duration::seconds(9))
            .await?
            .is_some()
    );
    assert!(
        store
            .revoke_grant(user_id, owner_revoked_grant.id, now + Duration::seconds(10))
            .await?
    );
    assert!(
        store
            .verify_access_token_live(&owner_check, now + Duration::seconds(10))
            .await?
            .is_none()
    );
    Ok(AccessTokenLiveCheck {
        jti: JwtId::new(),
        grant_id: live_grant.id,
        public_subject: subject.clone(),
        client_id: ClientId::parse("client-live")?,
        tenant_id: None,
        resource: resource()?,
        scopes: scopes()?,
    })
}

async fn assert_access_token_revocation(
    store: &OAuthPostgresStore,
    revoked_check: AccessTokenLiveCheck,
    now: OffsetDateTime,
) -> TestResult<AccessTokenLiveCheck> {
    assert!(
        store
            .verify_access_token_live(&revoked_check, now + Duration::seconds(9))
            .await?
            .is_some()
    );
    assert!(
        store
            .revoke_access_token(&AccessTokenRevocation {
                jti: revoked_check.jti,
                grant_id: revoked_check.grant_id,
                client_id: ClientId::parse("client-live")?,
                issued_at: now + Duration::seconds(8),
                expires_at: now + Duration::minutes(10),
                revoked_at: now + Duration::seconds(9),
                reason: AccessRevocationReason::TokenRevoked,
            })
            .await?
    );
    assert!(
        store
            .verify_access_token_live(&revoked_check, now + Duration::seconds(10))
            .await?
            .is_none()
    );
    Ok(revoked_check)
}

async fn assert_client_disable_closes_live_grant(
    store: &OAuthPostgresStore,
    revoked_check: AccessTokenLiveCheck,
    now: OffsetDateTime,
) -> TestResult {
    let disable_check = AccessTokenLiveCheck {
        jti: JwtId::new(),
        ..revoked_check
    };
    assert!(
        store
            .verify_access_token_live(&disable_check, now + Duration::seconds(10))
            .await?
            .is_some()
    );
    let disabled = store
        .disable_client(
            &ClientId::parse("client-live")?,
            now + Duration::seconds(11),
        )
        .await?
        .ok_or("client missing during disable")?;
    assert!(disabled.newly_disabled);
    assert_eq!(disabled.grants_revoked, 1);
    assert_eq!(disabled.refresh_families_revoked, 1);
    assert!(
        store
            .verify_access_token_live(&disable_check, now + Duration::seconds(12))
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn cleanup_passes_are_bounded_and_remove_only_expired_state() -> TestResult {
    let database = TestDatabase::start().await?;
    let created_at = OffsetDateTime::from_unix_timestamp(1_788_300_000)?;
    let cleanup_at = created_at + Duration::days(2);
    let user_id = seed_active_user(&database.pool, created_at, false).await?;
    let store = OAuthPostgresStore::new(database.pool.clone());

    seed_expired_cleanup_state(&store, user_id, created_at).await?;
    seed_expired_metadata_cache(&store, created_at).await?;
    assert_bounded_cleanup(&database.pool, cleanup_at).await
}

async fn seed_expired_cleanup_state(
    store: &OAuthPostgresStore,
    user_id: SubjectId,
    created_at: OffsetDateTime,
) -> TestResult {
    store
        .upsert_client(&client_registration(
            "client-cleanup",
            &["https://client.example.test/callback"],
            created_at,
            None,
        )?)
        .await?;
    store
        .allocate_subject(user_id, public_subject(41)?, created_at)
        .await?;
    let grant = store
        .create_grant(&grant_input(
            user_id,
            "client-cleanup",
            created_at,
            created_at + Duration::seconds(1),
        )?)
        .await?;
    let verifier = PkceVerifier::parse("c".repeat(43))?;
    for offset in 0_u8..2 {
        store
            .create_authorization_request(&authorization_request(
                "client-cleanup",
                "https://client.example.test/callback",
                50 + offset,
                created_at,
                created_at + Duration::minutes(10),
            )?)
            .await?;
        store
            .persist_authorization_code(&AuthorizationCodeCreate {
                code_digest: BearerDigest::from_bytes([60 + offset; 32]),
                grant_id: grant.id,
                client_id: ClientId::parse("client-cleanup")?,
                redirect_uri: RedirectUri::parse(
                    "https://client.example.test/callback".to_owned(),
                )?,
                resource_uris: vec![resource()?],
                granted_scopes: scopes()?,
                pkce_code_challenge: verifier.challenge(),
                nonce: None,
                issued_at: created_at,
                expires_at: created_at + Duration::minutes(2),
            })
            .await?;
        store
            .record_client_assertion(
                &ClientId::parse("client-cleanup")?,
                &format!("cleanup-assertion-{offset}"),
                created_at,
                created_at + Duration::minutes(5),
            )
            .await?;
        store
            .issue_refresh_family(&RefreshFamilyIssue {
                grant_id: grant.id,
                client_id: ClientId::parse("client-cleanup")?,
                resource: resource()?,
                granted_scopes: scopes()?,
                token_digest: BearerDigest::from_bytes([70 + offset; 32]),
                issued_at: created_at,
                expires_at: created_at + Duration::days(1),
            })
            .await?;
        store
            .revoke_access_token(&AccessTokenRevocation {
                jti: JwtId::new(),
                grant_id: grant.id,
                client_id: ClientId::parse("client-cleanup")?,
                issued_at: created_at,
                expires_at: created_at + Duration::minutes(10),
                revoked_at: created_at + Duration::seconds(1),
                reason: AccessRevocationReason::Manual,
            })
            .await?;
    }
    Ok(())
}

async fn seed_expired_metadata_cache(
    store: &OAuthPostgresStore,
    created_at: OffsetDateTime,
) -> TestResult {
    let metadata_client = ClientUpsert {
        client_id: ClientId::parse("https://metadata.example.test/client.json")?,
        source: ClientSource::ClientIdMetadata,
        display_name: "Metadata Client".to_owned(),
        client_uri: None,
        logo_uri: None,
        application_type: ApplicationType::Web,
        token_endpoint_auth_method: TokenEndpointAuthMethod::None,
        client_secret_digest: None,
        response_types: vec![ResponseType::Code],
        grant_types: vec![GrantType::AuthorizationCode],
        allowed_scopes: scopes()?,
        public_jwks: None,
        redirect_uris: vec![RedirectUri::parse(
            "https://metadata.example.test/callback".to_owned(),
        )?],
        post_logout_redirect_uris: Vec::new(),
        metadata_document_uri: Some("https://metadata.example.test/client.json".to_owned()),
        metadata_cache: Some(ClientMetadataCache {
            body: json!({"client_id": "https://metadata.example.test/client.json"}),
            etag: Some("etag".to_owned()),
            last_modified: None,
            cached_at: created_at,
            expires_at: created_at + Duration::minutes(5),
        }),
        now: created_at,
    };
    store.upsert_client(&metadata_client).await?;
    Ok(())
}

async fn assert_bounded_cleanup(pool: &PostgresPool, cleanup_at: OffsetDateTime) -> TestResult {
    let cleanup = OAuthCleanup::new(pool.clone());
    assert_eq!(
        cleanup.cleanup_access_revocations(cleanup_at, 0).await,
        Err(OAuthCleanupError::InvalidBatch)
    );
    let report = cleanup.run_bounded(cleanup_at, 1).await?;
    assert_eq!(report.authorization_artifacts.requests, 1);
    assert_eq!(report.authorization_artifacts.codes, 1);
    assert_eq!(report.client_state.assertions, 1);
    assert_eq!(report.client_state.metadata_caches, 1);
    assert_eq!(report.refresh_tombstones, 1);
    assert_eq!(report.access_revocations, 1);

    let mut connection = pool.acquire().await?;
    let counts = sqlx::query(
        "SELECT \
           (SELECT COUNT(*) FROM oauth_authorization_requests) AS requests, \
           (SELECT COUNT(*) FROM oauth_authorization_codes) AS codes, \
           (SELECT COUNT(*) FROM oauth_client_assertions) AS assertions, \
           (SELECT COUNT(*) FROM oauth_refresh_tokens) AS refresh_tokens, \
           (SELECT COUNT(*) FROM oauth_access_token_revocations) AS access_revocations",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(counts.try_get::<i64, _>("requests")?, 1);
    assert_eq!(counts.try_get::<i64, _>("codes")?, 1);
    assert_eq!(counts.try_get::<i64, _>("assertions")?, 1);
    assert_eq!(counts.try_get::<i64, _>("refresh_tokens")?, 1);
    assert_eq!(counts.try_get::<i64, _>("access_revocations")?, 1);
    Ok(())
}
