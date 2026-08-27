//! PostgreSQL proof for encrypted TOTP, replay, lock, recovery, and disable behavior.

use std::{error::Error, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_auth_totp::{TotpConfig, TotpStore, TotpStoreError};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use time::{Duration as TimeDuration, OffsetDateTime};
use totp_rs::{Algorithm, Builder, Secret, Totp};
use url::Url;

const FIRST_MIGRATION: i64 = 2_026_082_301;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-auth-totp-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(10),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(15),
    }
}

fn totp_config() -> TotpConfig {
    TotpConfig {
        enabled: true,
        encryption_key: Some(SecretString::from(URL_SAFE_NO_PAD.encode([61_u8; 32]))),
        issuer: "Omnius Integration".to_owned(),
        skew: 2,
        recent_auth_max_age: Duration::from_mins(10),
        verification_failure_window: Duration::from_mins(5),
        verification_failure_threshold: 3,
        verification_lock_duration: Duration::from_mins(15),
        recovery_code_count: 5,
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
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
    tenant_id: Option<TenantId>,
    authenticated_at: OffsetDateTime,
    scopes: Vec<Scope>,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        user_id,
        PrincipalKind::User,
        tenant_id,
        AuthMethod::Session,
        authenticated_at,
        AssuranceLevel::Aal1,
        scopes,
    )?)
}

fn totp_from_uri(uri: &SecretString) -> Result<(Totp, Vec<u8>), Box<dyn Error>> {
    let url = Url::parse(uri.expose_secret())?;
    let encoded = url
        .query_pairs()
        .find_map(|(name, value)| (name == "secret").then(|| value.into_owned()))
        .ok_or("otpauth URI did not contain a secret")?;
    let secret = Secret::try_from_base32(encoded).map_err(|_| "otpauth secret was invalid")?;
    let seed = secret.as_bytes().to_vec();
    let totp = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_secret(seed.as_slice())
        .with_skew(2)
        .with_step_duration(30)
        .build()
        .map_err(|_| "otpauth TOTP parameters were invalid")?;
    Ok((totp, seed))
}

fn token_at_offset(totp: &Totp, seconds: i64) -> Result<String, Box<dyn Error>> {
    let at = OffsetDateTime::now_utc()
        .checked_add(TimeDuration::seconds(seconds))
        .ok_or("test timestamp overflowed")?;
    let timestamp = u64::try_from(at.unix_timestamp())?;
    Ok(totp.generate(timestamp).to_string())
}

fn operation_error<T>(result: Result<T, TotpStoreError>) -> Result<TotpStoreError, Box<dyn Error>> {
    result
        .err()
        .ok_or_else(|| "operation unexpectedly succeeded".into())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves the complete TOTP security lifecycle and transitions"
)]
#[tokio::test]
async fn totp_lifecycle_is_encrypted_replay_safe_rate_limited_and_recoverable()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let config = totp_config();
    let store = TotpStore::new(database.pool.clone(), &config)?;
    let user_id = seed_user(&database.pool).await?;
    let tenant_id = TenantId::new();
    let scopes = vec![Scope::new("profile:read")?, Scope::new("profile:write")?];
    let principal = user_principal(
        user_id,
        Some(tenant_id),
        OffsetDateTime::now_utc(),
        scopes.clone(),
    )?;

    let pending = store.enroll(&principal, "person@example.test").await?;
    let credential_id = pending.metadata().id;
    let pending_debug = format!("{pending:?}");
    let uri = pending.expose_once();
    assert!(pending_debug.contains("[REDACTED]"));
    assert!(!pending_debug.contains(uri.expose_secret()));
    let (totp, raw_seed) = totp_from_uri(&uri)?;

    let mut connection = database.pool.acquire().await?;
    let (ciphertext, nonce, encryption_version, confirmed_at): (
        Vec<u8>,
        Vec<u8>,
        i16,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        "SELECT seed_ciphertext, seed_nonce, seed_encryption_version, confirmed_at \
         FROM totp_credentials WHERE id = $1",
    )
    .bind(credential_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        (ciphertext.len(), nonce.len(), encryption_version),
        (36, 12, 1)
    );
    assert_ne!(ciphertext.as_slice(), raw_seed.as_slice());
    assert!(
        !ciphertext
            .windows(raw_seed.len())
            .any(|window| window == raw_seed)
    );
    assert!(confirmed_at.is_none());
    drop(connection);

    let confirmation_token = token_at_offset(&totp, 0)?;
    assert_eq!(
        operation_error(store.verify(&principal, &confirmation_token).await)?,
        TotpStoreError::VerificationFailed
    );
    let confirmed = store.confirm(&principal, &confirmation_token).await?;
    assert!(confirmed.metadata().confirmed_at.is_some());
    let confirmed_debug = format!("{confirmed:?}");
    let mut recovery_codes = confirmed.expose_recovery_codes_once();
    assert!(confirmed_debug.contains("[REDACTED]"));
    assert_eq!(recovery_codes.len(), config.recovery_code_count);

    let mut connection = database.pool.acquire().await?;
    let hashes: Vec<String> = sqlx::query_scalar(
        "SELECT code_hash FROM recovery_codes WHERE credential_id = $1 ORDER BY lookup_id",
    )
    .bind(credential_id)
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(hashes.len(), config.recovery_code_count);
    assert!(
        hashes
            .iter()
            .all(|hash| hash.starts_with("$argon2id$v=19$"))
    );
    assert!(recovery_codes.iter().all(|code| {
        hashes
            .iter()
            .all(|hash| !hash.contains(code.expose_secret()))
    }));
    drop(connection);

    assert_eq!(
        operation_error(store.verify(&principal, &confirmation_token).await)?,
        TotpStoreError::VerificationFailed
    );
    let accepted_at_skew_limit = token_at_offset(&totp, 60)?;
    let stepped_up = store.verify(&principal, &accepted_at_skew_limit).await?;
    assert_eq!(
        (
            stepped_up.subject_id,
            stepped_up.kind,
            stepped_up.tenant_id,
            stepped_up.auth_method,
            stepped_up.assurance,
            stepped_up.scopes.as_slice(),
        ),
        (
            user_id,
            PrincipalKind::User,
            Some(tenant_id),
            AuthMethod::Totp,
            AssuranceLevel::Aal2,
            scopes.as_slice(),
        )
    );
    assert_eq!(
        operation_error(store.verify(&principal, &accepted_at_skew_limit).await)?,
        TotpStoreError::VerificationFailed
    );
    let outside_skew = token_at_offset(&totp, 90)?;
    assert_eq!(
        operation_error(store.verify(&principal, &outside_skew).await)?,
        TotpStoreError::VerificationFailed
    );

    let first_recovery = recovery_codes.remove(0);
    let first_replay = first_recovery.clone();
    let recovered = store.verify_recovery(&principal, first_recovery).await?;
    assert_eq!(
        (
            recovered.tenant_id,
            recovered.auth_method,
            recovered.assurance,
            recovered.scopes
        ),
        (
            Some(tenant_id),
            AuthMethod::Totp,
            AssuranceLevel::Aal2,
            scopes.clone()
        )
    );
    assert_eq!(
        operation_error(store.verify_recovery(&principal, first_replay).await)?,
        TotpStoreError::VerificationFailed
    );
    let second_recovery = recovery_codes.remove(0);
    let second_recovery_replay = second_recovery.clone();
    assert!(
        store
            .verify_recovery(&principal, second_recovery)
            .await
            .is_ok()
    );

    let stale_principal = user_principal(
        user_id,
        Some(tenant_id),
        OffsetDateTime::now_utc() - TimeDuration::minutes(11),
        scopes.clone(),
    )?;
    assert_eq!(
        operation_error(store.disable(&stale_principal).await)?,
        TotpStoreError::RecentAuthenticationRequired
    );
    let disabled = store.disable(&principal).await?;
    assert!(disabled.disabled_at.is_some());
    assert_eq!(store.disable(&principal).await?, disabled);
    assert_eq!(
        operation_error(
            store
                .verify_recovery(&principal, second_recovery_replay)
                .await
        )?,
        TotpStoreError::VerificationFailed
    );
    let metadata = store
        .credential_metadata(user_id)
        .await?
        .ok_or("disabled credential metadata was missing")?;
    assert_eq!(metadata, disabled);
    let mut connection = database.pool.acquire().await?;
    let authentication_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(user_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(authentication_version, 5);
    let (used_codes, invalidated_codes): (i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE used_at IS NOT NULL), \
                count(*) FILTER (WHERE invalidated_at IS NOT NULL) \
         FROM recovery_codes WHERE credential_id = $1",
    )
    .bind(credential_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        (used_codes, invalidated_codes),
        (2, i64::try_from(config.recovery_code_count)? - 2)
    );

    let locked_user_id = seed_user(&database.pool).await?;
    let locked_principal = user_principal(
        locked_user_id,
        None,
        OffsetDateTime::now_utc(),
        vec![Scope::new("profile:read")?],
    )?;
    let locked_pending = store
        .enroll(&locked_principal, "locked@example.test")
        .await?;
    let locked_uri = locked_pending.expose_once();
    let (locked_totp, _) = totp_from_uri(&locked_uri)?;
    let locked_confirmation = token_at_offset(&locked_totp, 0)?;
    let locked_confirmed = store
        .confirm(&locked_principal, &locked_confirmation)
        .await?;
    let _locked_recovery_codes = locked_confirmed.expose_recovery_codes_once();
    for expected in [
        TotpStoreError::VerificationFailed,
        TotpStoreError::VerificationFailed,
        TotpStoreError::Locked,
    ] {
        assert_eq!(
            operation_error(store.verify(&locked_principal, "invalid").await)?,
            expected
        );
    }
    let restarted_store = TotpStore::new(database.pool.clone(), &config)?;
    let valid_while_locked = token_at_offset(&locked_totp, 30)?;
    assert_eq!(
        operation_error(
            restarted_store
                .verify(&locked_principal, &valid_while_locked)
                .await
        )?,
        TotpStoreError::Locked
    );
    let (failure_count, locked_until): (i32, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT failure_count, locked_until FROM totp_credentials \
         WHERE user_id = $1 AND disabled_at IS NULL",
    )
    .bind(locked_user_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(failure_count, 3);
    assert!(locked_until.is_some());
    Ok(())
}
