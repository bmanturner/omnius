//! Focused production-adapter mapping, authentication, transaction, and liveness coverage.

use std::{
    error::Error,
    future::{Future, ready},
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration as StdDuration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId};
use omnius_auth_oauth_server::{
    Clock, EntropySource,
    client::{ClientMetadataResolverError, ResolvedClientMetadata},
    crypto::{BearerDigest, TokenPepper},
    postgres_adapter::{
        AuthorizedBrowserSession, OAuthAuditError, OAuthAuditEvent, OAuthAuditSink,
        OAuthClientMetadataResolver, OAuthSessionAuthority, PostgresOAuthAdapter,
        PostgresOAuthAdapterInput, SessionAuthorityError, map_connected_grant,
        map_registered_client, map_stored_authorization,
    },
    service::{
        AuthorizationInteraction, AuthorizationStore, AuthorizationSubject,
        CommitAuthorizationDecision, ConsentDecision, CreateAuthorization, InteractionRequirement,
        InteractionScope, LogoutSession, SessionCandidate, StoredAuthorization,
    },
    store::{
        AuthorizationInteractionRequirement as StoreInteractionRequirement,
        AuthorizationInteractionScope as StoreInteractionScope, AuthorizationRequestId,
        AuthorizationRequestRecord, AuthorizationRequestStatus, ClientSource, ClientStatus,
        ConnectedGrant as StoreGrant, GrantCreate, OAuthClientRecordId, OAuthPostgresStore,
        PublicSubject, RegisteredClient,
    },
    types::{
        ApplicationType, AuthorizationRequestInput, AuthorizationRequestParts, ClientId, GrantId,
        GrantType, IssuerUri, JwtId, PkceVerifier, Prompt, RedirectUri, ResourceUri, ResponseMode,
        ResponseType, TokenEndpointAuthMethod,
    },
    verifier::{AccessTokenLiveCheck, AccessTokenStateStore},
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const ISSUER: &str = "https://issuer.example.test";
const CLIENT: &str = "adapter-client";
const REDIRECT: &str = "https://client.example.test/callback";
const RESOURCE: &str = "https://api.example.test";
type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Database {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

impl Database {
    async fn start() -> TestResult<Self> {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &postgres_config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
            MigrationConfig {
                run_on_startup: false,
                operation_timeout: StdDuration::from_secs(10),
            },
            DeploymentEnvironment::Test,
        )?
        .run()
        .await?;
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
        application_name: "omnius-oauth-postgres-adapter-test".to_owned(),
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

#[derive(Clone, Copy)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Clone, Copy)]
struct FixedEntropy(u8);

impl EntropySource for FixedEntropy {
    fn try_fill(
        &self,
        output: &mut [u8],
    ) -> Result<(), omnius_auth_oauth_server::OAuthCryptoError> {
        output.fill(self.0);
        Ok(())
    }
}

#[derive(Default)]
struct Audit {
    fail: bool,
    events: Mutex<Vec<OAuthAuditEvent>>,
}

impl OAuthAuditSink for Audit {
    fn append<'a>(
        &'a self,
        _transaction: &'a mut Transaction<'_, Postgres>,
        event: OAuthAuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthAuditError>> + Send + 'a>> {
        Box::pin(async move {
            if self.fail {
                return Err(OAuthAuditError);
            }
            self.events.lock().map_err(|_| OAuthAuditError)?.push(event);
            Ok(())
        })
    }
}

#[derive(Clone)]
struct Sessions;

impl OAuthSessionAuthority for Sessions {
    fn authorize_session(
        &self,
        _candidate: SessionCandidate,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<AuthorizedBrowserSession>, SessionAuthorityError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(ready(Ok(None)))
    }

    fn validate_logout_binding(
        &self,
        _command: LogoutSession,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionAuthorityError>> + Send + '_>> {
        Box::pin(ready(Ok(true)))
    }
}

#[derive(Clone)]
struct NoMetadata;

impl OAuthClientMetadataResolver for NoMetadata {
    fn resolve<'a>(
        &'a self,
        _client_id: &'a ClientId,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResolvedClientMetadata, ClientMetadataResolverError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(ready(Err(
            ClientMetadataResolverError::InvalidClientIdentifier,
        )))
    }
}

fn issuer() -> TestResult<IssuerUri> {
    Ok(IssuerUri::parse(ISSUER.to_owned(), true)?)
}

fn resource() -> TestResult<ResourceUri> {
    Ok(ResourceUri::parse(RESOURCE.to_owned(), true)?)
}

fn scopes() -> TestResult<Vec<Scope>> {
    Ok(vec![Scope::new("openid")?, Scope::new("records:read")?])
}

fn interaction(requirement: InteractionRequirement) -> TestResult<AuthorizationInteraction> {
    Ok(AuthorizationInteraction {
        client_name: "Adapter Client".to_owned(),
        client_origin: "https://client.example.test".to_owned(),
        redirect_host: "client.example.test".to_owned(),
        resource: resource()?,
        resource_name: "Configured API".to_owned(),
        resource_description: "Configured API resource".to_owned(),
        minimum_assurance: AssuranceLevel::Aal2,
        scopes: vec![
            InteractionScope {
                name: Scope::new("openid")?,
                description: "Identify your account".to_owned(),
                newly_requested: false,
            },
            InteractionScope {
                name: Scope::new("records:read")?,
                description: "Read configured records".to_owned(),
                newly_requested: true,
            },
        ],
        requirement,
    })
}

fn request() -> TestResult<AuthorizationRequestInput> {
    Ok(AuthorizationRequestInput::new(AuthorizationRequestParts {
        client_id: ClientId::parse(CLIENT)?,
        redirect_uri: RedirectUri::parse(REDIRECT)?,
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        state: Some("state".to_owned()),
        scopes: scopes()?,
        resources: vec![resource()?],
        pkce_challenge: PkceVerifier::parse("a".repeat(43))?.challenge(),
        pkce_method: "S256".to_owned(),
        nonce: Some("nonce".to_owned()),
        prompt: Some(Prompt::Consent),
        max_age_seconds: None,
        expected_issuer: Some(issuer()?),
    })?)
}

fn client(now: OffsetDateTime) -> TestResult<RegisteredClient> {
    Ok(RegisteredClient {
        id: OAuthClientRecordId::new(),
        client_id: ClientId::parse(CLIENT)?,
        source: ClientSource::PreRegistered,
        status: ClientStatus::Active,
        display_name: "Adapter Client".to_owned(),
        client_uri: Some("https://client.example.test/application".to_owned()),
        logo_uri: None,
        application_type: ApplicationType::Web,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        response_types: vec![ResponseType::Code],
        grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
        allowed_scopes: scopes()?,
        public_jwks: None,
        redirect_uris: vec![RedirectUri::parse(REDIRECT)?],
        post_logout_redirect_uris: Vec::new(),
        metadata_cache_expires_at: None,
        created_at: now,
        updated_at: now,
        disabled_at: None,
    })
}

fn adapter(
    pool: PostgresPool,
    now: OffsetDateTime,
    fail_audit: bool,
) -> TestResult<PostgresOAuthAdapter<FixedClock, FixedEntropy, Audit, Sessions, NoMetadata>> {
    Ok(PostgresOAuthAdapter::new(PostgresOAuthAdapterInput {
        store: OAuthPostgresStore::new(pool),
        pepper: TokenPepper::parse(&URL_SAFE_NO_PAD.encode([9_u8; 32]))?,
        issuer: issuer()?,
        client_metadata: Arc::new(NoMetadata),
        dynamic_client_registration_enabled: true,
        local_identity_provider: "email".to_owned(),
        clock: Arc::new(FixedClock(now)),
        entropy: Arc::new(FixedEntropy(7)),
        audit: Arc::new(Audit {
            fail: fail_audit,
            events: Mutex::new(Vec::new()),
        }),
        sessions: Arc::new(Sessions),
    })?)
}

async fn seed_user(pool: &PostgresPool, now: OffsetDateTime) -> TestResult<SubjectId> {
    let user_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(user_id.as_uuid())
        .bind(now)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, 'email', 'verified@example.test', $3, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    Ok(user_id)
}

#[test]
fn mappings_preserve_safe_client_authorization_and_connected_grant_state() -> TestResult {
    let now = OffsetDateTime::UNIX_EPOCH;
    let registered = client(now)?;
    let resolved = map_registered_client(registered.clone())?;
    assert_eq!(resolved.display_origin, "https://client.example.test");
    assert_eq!(resolved.scopes, scopes()?);

    let input = request()?;
    let stored = map_stored_authorization(
        &issuer()?,
        AuthorizationRequestRecord {
            id: AuthorizationRequestId::new(),
            client: registered,
            redirect_uri: input.redirect_uri().clone(),
            response_type: ResponseType::Code,
            response_mode: ResponseMode::Query,
            client_state: input.state().map(str::to_owned),
            requested_scopes: input.scopes().to_vec(),
            resource_uris: input.resources().to_vec(),
            pkce_code_challenge: input.pkce_challenge().clone(),
            nonce: input.nonce().map(str::to_owned),
            prompt_values: vec![Prompt::Consent],
            max_age_seconds: None,
            expected_issuer: issuer()?,
            interaction_resource_name: "Configured API".to_owned(),
            interaction_resource_description: "Configured API resource".to_owned(),
            interaction_minimum_assurance: AssuranceLevel::Aal2,
            interaction_scopes: vec![
                StoreInteractionScope {
                    name: Scope::new("openid")?,
                    description: "Identify your account".to_owned(),
                    newly_requested: false,
                },
                StoreInteractionScope {
                    name: Scope::new("records:read")?,
                    description: "Read configured records".to_owned(),
                    newly_requested: true,
                },
            ],
            interaction_requirement: StoreInteractionRequirement::Login,
            status: AuthorizationRequestStatus::Pending,
            created_at: now,
            expires_at: now + Duration::minutes(5),
            completed_at: None,
        },
    )?;
    assert_eq!(stored.resource, resource()?);
    assert_eq!(
        stored.interaction,
        interaction(InteractionRequirement::Login)?
    );

    let connected = map_connected_grant(StoreGrant {
        grant_id: GrantId::new(),
        client_id: ClientId::parse(CLIENT)?,
        client_name: "Adapter Client".to_owned(),
        client_uri: None,
        logo_uri: None,
        tenant_id: None,
        resources: vec![resource()?],
        granted_scopes: scopes()?,
        consented_at: now,
        created_at: now,
    })?;
    assert_eq!(connected.resource, resource()?);
    Ok(())
}

#[tokio::test]
async fn persisted_login_interaction_round_trips_exact_safe_display_and_scope_delta() -> TestResult
{
    let database = Database::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000)?;
    let adapter = adapter(database.pool, now, false)?;
    let metadata = br#"{
        "client_id":"adapter-client","client_name":"Adapter Client",
        "redirect_uris":["https://client.example.test/callback"],
        "grant_types":["authorization_code","refresh_token"],"response_types":["code"]
    }"#;
    adapter
        .register_pre_registered_json(metadata, 16 * 1_024)
        .await
        .map_err(|_| "register interaction test client")?;
    let expected = interaction(InteractionRequirement::Login)?;
    let digest = BearerDigest::from_bytes([31_u8; 32]);
    adapter
        .create_authorization(CreateAuthorization {
            handle_digest: digest.clone(),
            authorization: StoredAuthorization {
                request: request()?,
                client: adapter
                    .resolve_client(&ClientId::parse(CLIENT)?)
                    .await
                    .map_err(|_| "resolve interaction test client")?
                    .ok_or("client missing")?,
                resource: resource()?,
                interaction: expected.clone(),
                authentication_time_before_login: None,
                expires_at: now + Duration::minutes(5),
            },
        })
        .await
        .map_err(|_| "persist authorization interaction")?;
    let loaded = adapter
        .load_authorization(digest, now)
        .await
        .map_err(|_| "reload authorization interaction")?
        .ok_or("persisted authorization missing")?;
    assert_eq!(loaded.interaction, expected);
    Ok(())
}

#[tokio::test]
async fn strict_admin_onboarding_generates_and_verifies_one_confidential_secret() -> TestResult {
    let database = Database::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000)?;
    let adapter = adapter(database.pool, now, false)?;
    let input = br#"{
        "client_id":"adapter-client",
        "client_name":"Adapter Client",
        "redirect_uris":["https://client.example.test/callback"],
        "token_endpoint_auth_method":"client_secret_basic",
        "grant_types":["authorization_code","refresh_token"],
        "response_types":["code"]
    }"#;
    let onboarded = adapter
        .register_pre_registered_json(input, 16 * 1_024)
        .await?;
    let secret = onboarded
        .client_secret
        .ok_or("secret missing")?
        .expose_once();
    assert!(
        adapter
            .authenticate_client_secret(&ClientId::parse(CLIENT)?, &secret)
            .await?
    );
    assert!(
        !adapter
            .authenticate_client_secret(
                &ClientId::parse(CLIENT)?,
                &URL_SAFE_NO_PAD.encode([2_u8; 32]),
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn audit_failure_rolls_back_request_and_terminal_decision_mutations() -> TestResult {
    let database = Database::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000)?;
    let passing = adapter(database.pool.clone(), now, false)?;
    let metadata = br#"{
        "client_id":"adapter-client","client_name":"Adapter Client",
        "redirect_uris":["https://client.example.test/callback"],
        "grant_types":["authorization_code","refresh_token"],"response_types":["code"]
    }"#;
    passing
        .register_pre_registered_json(metadata, 16 * 1_024)
        .await?;
    let failing = adapter(database.pool.clone(), now, true)?;
    let input = request()?;
    let create = CreateAuthorization {
        handle_digest: BearerDigest::from_bytes([3_u8; 32]),
        authorization: StoredAuthorization {
            request: input.clone(),
            client: passing
                .resolve_client(&ClientId::parse(CLIENT)?)
                .await?
                .ok_or("client missing")?,
            resource: resource()?,
            interaction: interaction(InteractionRequirement::Consent)?,
            authentication_time_before_login: None,
            expires_at: now + Duration::minutes(5),
        },
    };
    assert!(failing.create_authorization(create).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_authorization_requests")
        .fetch_one(&database.pool.sqlx_pool())
        .await?;
    assert_eq!(count, 0);

    let digest = BearerDigest::from_bytes([4_u8; 32]);
    passing
        .create_authorization(CreateAuthorization {
            handle_digest: digest.clone(),
            authorization: StoredAuthorization {
                request: input,
                client: passing
                    .resolve_client(&ClientId::parse(CLIENT)?)
                    .await?
                    .ok_or("client missing")?,
                resource: resource()?,
                interaction: interaction(InteractionRequirement::Consent)?,
                authentication_time_before_login: None,
                expires_at: now + Duration::minutes(5),
            },
        })
        .await?;
    let user_id = seed_user(&database.pool, now).await?;
    let subject = OAuthPostgresStore::new(database.pool.clone())
        .allocate_subject(
            user_id,
            PublicSubject::parse(URL_SAFE_NO_PAD.encode([8_u8; 32]))?,
            now,
        )
        .await?;
    let principal = Principal::new(
        user_id,
        PrincipalKind::User,
        None,
        AuthMethod::Session,
        now,
        AssuranceLevel::Aal2,
        Vec::new(),
    )?;
    assert!(
        failing
            .commit_authorization_decision(CommitAuthorizationDecision {
                handle_digest: digest.clone(),
                subject: AuthorizationSubject {
                    principal,
                    public_subject: subject.public_subject.as_str().to_owned(),
                    verified_email: Some("verified@example.test".to_owned()),
                    acr: "aal2".to_owned(),
                    amr: vec!["pwd".to_owned(), "session".to_owned()],
                },
                decision: ConsentDecision::Approve,
                code_digest: Some(BearerDigest::from_bytes([5_u8; 32])),
                code_expires_at: Some(now + Duration::minutes(2)),
                explicit_offline_consent: false,
                require_existing_grant: false,
            })
            .await
            .is_err()
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM oauth_authorization_requests WHERE request_handle_digest = $1",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_one(&database.pool.sqlx_pool())
    .await?;
    assert_eq!(status, "pending");
    let grants: i64 = sqlx::query_scalar("SELECT count(*) FROM oauth_grants")
        .fetch_one(&database.pool.sqlx_pool())
        .await?;
    assert_eq!(grants, 0);
    Ok(())
}

#[tokio::test]
async fn live_identity_is_immediately_inactive_after_connected_grant_revocation() -> TestResult {
    let database = Database::start().await?;
    let now = OffsetDateTime::from_unix_timestamp(1_788_000_000)?;
    let adapter = adapter(database.pool.clone(), now, false)?;
    let metadata = br#"{
        "client_id":"adapter-client","client_name":"Adapter Client",
        "redirect_uris":["https://client.example.test/callback"],
        "grant_types":["authorization_code","refresh_token"],"response_types":["code"]
    }"#;
    adapter
        .register_pre_registered_json(metadata, 16 * 1_024)
        .await?;
    let user_id = seed_user(&database.pool, now).await?;
    let store = OAuthPostgresStore::new(database.pool.clone());
    let subject = store
        .allocate_subject(
            user_id,
            PublicSubject::parse(URL_SAFE_NO_PAD.encode([7_u8; 32]))?,
            now,
        )
        .await?;
    let grant = store
        .create_grant(&GrantCreate {
            user_id,
            tenant_id: None,
            client_id: ClientId::parse(CLIENT)?,
            resources: vec![resource()?],
            granted_scopes: scopes()?,
            authenticated_at: now,
            assurance_level: AssuranceLevel::Aal2,
            authentication_methods: vec![AuthMethod::Password, AuthMethod::Session],
            consented_at: now,
        })
        .await?;
    let check = AccessTokenLiveCheck {
        public_subject: subject.public_subject.as_str().to_owned(),
        client_id: ClientId::parse(CLIENT)?,
        grant_id: grant.id,
        audience: resource()?,
        jwt_id: JwtId::new(),
        scopes: scopes()?,
    };
    let identity = adapter
        .authorize_access_token(check.clone())
        .await?
        .ok_or("identity missing")?;
    assert_eq!(
        identity.verified_email.as_deref(),
        Some("verified@example.test")
    );
    assert!(adapter.revoke_connected_grant(user_id, grant.id).await?);
    assert!(adapter.authorize_access_token(check).await?.is_none());
    Ok(())
}
