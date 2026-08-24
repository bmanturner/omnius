//! PostgreSQL proof for durable, one-use passkey registration and authentication lifecycle.

use std::{error::Error, time::Duration};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_auth_webauthn::{RegistrationStart, WebAuthnConfig, WebAuthnService, WebAuthnServiceError};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use time::{Duration as TimeDuration, OffsetDateTime};
use webauthn_authenticator_rs::{WebauthnAuthenticator, softpasskey::SoftPasskey};
use webauthn_rs::prelude::Url;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const AUTH_HEAD: i64 = 2_026_082_312;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
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
        application_name: "rsk-auth-webauthn-test".to_owned(),
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

fn webauthn_config() -> WebAuthnConfig {
    WebAuthnConfig {
        enabled: true,
        rp_id: "example.test".to_owned(),
        rp_name: "Example Test".to_owned(),
        origins: vec!["https://login.example.test".to_owned()],
        ceremony_ttl: Duration::from_mins(5),
        recent_auth_age: Duration::from_mins(15),
        max_credentials_per_user: 4,
        max_pending_ceremonies: 100,
        max_pending_discoverable_ceremonies: 25,
        max_pending_ceremonies_per_user: 4,
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, AUTH_HEAD)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

async fn seed_user(pool: &PostgresPool) -> Result<SubjectId, Box<dyn Error>> {
    let user_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(user_id.as_uuid())
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await?;
    Ok(user_id)
}

fn user_principal(
    user_id: SubjectId,
    authenticated_at: OffsetDateTime,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        user_id,
        PrincipalKind::User,
        None,
        AuthMethod::Password,
        authenticated_at,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

async fn register(
    service: &WebAuthnService,
    principal: &Principal,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    origin: &Url,
    credential_name: &str,
) -> Result<rsk_auth_webauthn::PasskeyMetadata, Box<dyn Error>> {
    let RegistrationStart {
        public_key,
        ceremony_handle,
    } = service
        .start_registration(principal, "user@example.test", "Test User", credential_name)
        .await?;
    let response = authenticator.do_registration(origin.clone(), public_key)?;
    Ok(service
        .finish_registration(&ceremony_handle, &response)
        .await?)
}

fn operation_error<T>(
    result: Result<T, WebAuthnServiceError>,
) -> Result<WebAuthnServiceError, Box<dyn Error>> {
    result
        .err()
        .ok_or_else(|| "operation unexpectedly succeeded".into())
}

#[expect(
    clippy::too_many_lines,
    reason = "one PostgreSQL fixture proves the complete passkey lifecycle and state transitions"
)]
#[tokio::test]
async fn passkey_lifecycle_is_official_durable_multi_credential_and_replay_safe()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let user_id = seed_user(&database.pool).await?;
    let principal = user_principal(user_id, OffsetDateTime::now_utc())?;
    let service = WebAuthnService::new(
        database.pool.clone(),
        &webauthn_config(),
        DeploymentEnvironment::Test,
    )?;
    let origin = Url::parse("https://login.example.test")?;

    let mut rejected_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let rejected = service
        .start_registration(
            &principal,
            "user@example.test",
            "Test User",
            "rejected origin",
        )
        .await?;
    let wrong_origin = Url::parse("https://other.example.test")?;
    let rejected_response =
        rejected_authenticator.do_registration(wrong_origin, rejected.public_key)?;
    assert_eq!(
        operation_error(
            service
                .finish_registration(&rejected.ceremony_handle, &rejected_response)
                .await
        )?,
        WebAuthnServiceError::VerificationFailed
    );
    assert_eq!(
        operation_error(
            service
                .finish_registration(&rejected.ceremony_handle, &rejected_response)
                .await
        )?,
        WebAuthnServiceError::CeremonyNotFound
    );

    let rp_rejected = service
        .start_registration(
            &principal,
            "user@example.test",
            "Test User",
            "rejected RP hash",
        )
        .await?;
    let mut rp_options = rp_rejected.public_key;
    rp_options.public_key.rp.id = "login.example.test".to_owned();
    let rp_response = rejected_authenticator.do_registration(origin.clone(), rp_options)?;
    assert_eq!(
        operation_error(
            service
                .finish_registration(&rp_rejected.ceremony_handle, &rp_response)
                .await
        )?,
        WebAuthnServiceError::VerificationFailed
    );

    let mut first_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut second_authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let first = register(
        &service,
        &principal,
        &mut first_authenticator,
        &origin,
        "laptop",
    )
    .await?;
    let first_state_count: i64 = {
        let mut connection = database.pool.acquire().await?;
        sqlx::query_scalar("SELECT count(*) FROM webauthn_ceremonies")
            .fetch_one(&mut *connection)
            .await?
    };
    assert_eq!(first_state_count, 0);
    let second = register(
        &service,
        &principal,
        &mut second_authenticator,
        &origin,
        "security key",
    )
    .await?;
    assert_ne!(first.id, second.id);

    let listed = service.list_credentials(user_id).await?;
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .all(|credential| credential.user_id == user_id)
    );
    assert!(
        listed
            .iter()
            .all(|credential| credential.disabled_at.is_none())
    );

    let first_start = service.start_authentication(user_id).await?;
    let first_response =
        first_authenticator.do_authentication(origin.clone(), first_start.public_key)?;
    let second_start = service.start_authentication(user_id).await?;
    let second_response =
        first_authenticator.do_authentication(origin.clone(), second_start.public_key)?;
    let authenticated = service
        .finish_authentication(&second_start.ceremony_handle, &second_response)
        .await?;
    assert_eq!(
        (
            authenticated.subject_id,
            authenticated.kind,
            authenticated.auth_method,
            authenticated.assurance,
        ),
        (
            user_id,
            PrincipalKind::User,
            AuthMethod::WebAuthn,
            AssuranceLevel::Aal2,
        )
    );
    assert_eq!(authenticated.tenant_id, None);
    assert!(authenticated.scopes.is_empty());
    assert_eq!(
        operation_error(
            service
                .finish_authentication(&first_start.ceremony_handle, &first_response)
                .await
        )?,
        WebAuthnServiceError::CounterReplay
    );

    let after_auth = service.list_credentials(user_id).await?;
    let used = after_auth
        .iter()
        .find(|credential| credential.id == first.id)
        .ok_or("first credential missing")?;
    assert_eq!(used.sign_count, 2);
    assert!(used.last_used_at.is_some());

    let stale = user_principal(user_id, OffsetDateTime::now_utc() - TimeDuration::hours(1))?;
    assert_eq!(
        operation_error(service.disable_credential(&stale, first.id).await)?,
        WebAuthnServiceError::RecentAuthenticationRequired
    );
    let disabled_first = service.disable_credential(&authenticated, first.id).await?;
    assert!(disabled_first.disabled_at.is_some());
    assert_eq!(
        service.disable_credential(&authenticated, first.id).await?,
        disabled_first
    );

    let remaining_start = service.start_authentication(user_id).await?;
    let remaining_response =
        second_authenticator.do_authentication(origin.clone(), remaining_start.public_key)?;
    let remaining_principal = service
        .finish_authentication(&remaining_start.ceremony_handle, &remaining_response)
        .await?;
    let disabled_second = service
        .disable_credential(&remaining_principal, second.id)
        .await?;
    assert!(disabled_second.disabled_at.is_some());
    let mut connection = database.pool.acquire().await?;
    let authentication_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(user_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(authentication_version, 5);
    assert_eq!(
        operation_error(service.start_authentication(user_id).await)?,
        WebAuthnServiceError::NoActiveCredentials
    );

    let discoverable = service.start_discoverable_authentication().await?;
    let discoverable_json = serde_json::to_value(&discoverable.public_key)?;
    assert_eq!(discoverable_json["mediation"], "conditional");
    Ok(())
}

#[tokio::test]
async fn discoverable_capacity_is_partitioned_reclaimed_and_cannot_block_registration()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let user_id = seed_user(&database.pool).await?;
    let principal = user_principal(user_id, OffsetDateTime::now_utc())?;
    let mut config = webauthn_config();
    config.max_pending_ceremonies = 2;
    config.max_pending_discoverable_ceremonies = 1;
    config.max_pending_ceremonies_per_user = 1;
    let service =
        WebAuthnService::new(database.pool.clone(), &config, DeploymentEnvironment::Test)?;

    let _first = service.start_discoverable_authentication().await?;
    assert_eq!(
        operation_error(service.start_discoverable_authentication().await)?,
        WebAuthnServiceError::CeremonyCapacityReached
    );
    let _registration = service
        .start_registration(
            &principal,
            "reserved@example.test",
            "Reserved User",
            "reserved credential",
        )
        .await?;

    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE webauthn_ceremonies \
         SET created_at = NOW() - INTERVAL '2 minutes', \
             expires_at = NOW() - INTERVAL '1 minute' \
         WHERE user_id IS NULL",
    )
    .execute(&mut *connection)
    .await?;
    drop(connection);

    let _replacement = service.start_discoverable_authentication().await?;
    let mut connection = database.pool.acquire().await?;
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM webauthn_ceremonies")
        .fetch_one(&mut *connection)
        .await?;
    let anonymous: i64 =
        sqlx::query_scalar("SELECT count(*) FROM webauthn_ceremonies WHERE user_id IS NULL")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(retained, 2);
    assert_eq!(anonymous, 1);
    Ok(())
}
