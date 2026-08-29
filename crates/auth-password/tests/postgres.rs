//! End-to-end password, verification-token, and recovery persistence contract.

use std::{error::Error, num::NonZeroUsize, time::Duration};

use omnius_auth_core::SubjectId;
use omnius_auth_password::{
    IdentityTokenRequest, OsTokenGenerator, PasswordEngine, PasswordInput, PasswordPolicy,
    PasswordVerification, PasswordWorker, PostgresPasswordStore, TokenConsumption, TokenPurpose,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::Connection as _;
use time::OffsetDateTime;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-auth-password-test".to_owned(),
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

fn password(value: &str) -> Result<PasswordInput, Box<dyn Error>> {
    Ok(PasswordInput::new(SecretString::from(value.to_owned()))?)
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture verifies the complete atomic recovery lifecycle and cleanup"
)]
#[tokio::test]
async fn recovery_is_single_use_version_bound_and_enumeration_resistant()
-> Result<(), Box<dyn Error>> {
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

    let subject_id = SubjectId::from_uuid(Uuid::now_v7())?;
    let identity_id = Uuid::now_v7();
    let created_at = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, status, created_at) VALUES ($1, 'active', $2)")
        .bind(subject_id.as_uuid())
        .bind(created_at)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO identities \
         (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, 'email', 'person@example.test', $3, $3)",
    )
    .bind(identity_id)
    .bind(subject_id.as_uuid())
    .bind(created_at)
    .execute(&mut *connection)
    .await?;

    let engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
    let worker = PasswordWorker::new(
        engine,
        NonZeroUsize::new(2).ok_or("password worker concurrency must be nonzero")?,
    );
    let original_credential = worker
        .hash_password(password("correct horse battery staple")?)
        .await?;
    let store = PostgresPasswordStore;
    let mut transaction = connection.begin().await?;
    store
        .replace_password_with(
            &mut transaction,
            subject_id,
            &original_credential,
            created_at,
        )
        .await?;
    transaction.commit().await?;

    assert!(matches!(
        store
            .verify_password_with(
                &mut connection,
                subject_id,
                password("correct horse battery staple")?,
                &worker,
                created_at,
            )
            .await?,
        PasswordVerification::Verified { .. }
    ));

    let generator = OsTokenGenerator;
    let request_time = created_at + time::Duration::minutes(1);
    let known_started = tokio::time::Instant::now();
    let mut transaction = connection.begin().await?;
    let known = store
        .request_for_identity_with(
            &mut transaction,
            IdentityTokenRequest {
                provider: "email",
                provider_subject: "person@example.test",
                purpose: TokenPurpose::PasswordRecovery,
                now: request_time,
                ttl: Duration::from_mins(15),
                response_floor: Duration::from_millis(500),
            },
            &generator,
        )
        .await?;
    transaction.commit().await?;
    let known = known.complete_after_commit().await;
    assert!(known.accepted());
    assert!(known_started.elapsed() >= Duration::from_millis(500));
    let recovery = known
        .into_post_commit_dispatch()
        .ok_or("known identity did not produce a token dispatch")?;

    let unknown_started = tokio::time::Instant::now();
    let mut transaction = connection.begin().await?;
    let unknown = store
        .request_for_identity_with(
            &mut transaction,
            IdentityTokenRequest {
                provider: "email",
                provider_subject: "unknown@example.test",
                purpose: TokenPurpose::PasswordRecovery,
                now: request_time,
                ttl: Duration::from_mins(15),
                response_floor: Duration::from_millis(500),
            },
            &generator,
        )
        .await?;
    transaction.commit().await?;
    let unknown = unknown.complete_after_commit().await;
    assert!(unknown.accepted());
    assert!(unknown_started.elapsed() >= Duration::from_millis(500));
    assert!(unknown.into_post_commit_dispatch().is_none());

    let replacement_credential = worker
        .hash_password(password("new correct horse battery staple")?)
        .await?;
    let recovery_time = request_time + time::Duration::minutes(1);
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .recover_password_with(
                &mut transaction,
                &recovery.token,
                &replacement_credential,
                recovery_time,
            )
            .await?,
        TokenConsumption::Consumed(subject_id)
    );
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    let version_bound_recovery = store
        .issue_for_subject_with(
            &mut transaction,
            subject_id,
            TokenPurpose::PasswordRecovery,
            recovery_time,
            Duration::from_hours(1),
            &generator,
        )
        .await?;
    transaction.commit().await?;
    sqlx::query(
        "UPDATE users SET authentication_version = authentication_version + 1 WHERE id = $1",
    )
    .bind(subject_id.as_uuid())
    .execute(&mut *connection)
    .await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .recover_password_with(
                &mut transaction,
                &recovery.token,
                &replacement_credential,
                recovery_time,
            )
            .await?,
        TokenConsumption::Rejected
    );
    assert_eq!(
        store
            .consume_token_with(
                &mut transaction,
                &version_bound_recovery.token,
                TokenPurpose::PasswordRecovery,
                recovery_time,
            )
            .await?,
        TokenConsumption::Rejected
    );
    transaction.commit().await?;
    assert!(matches!(
        store
            .verify_password_with(
                &mut connection,
                subject_id,
                password("correct horse battery staple")?,
                &worker,
                recovery_time,
            )
            .await?,
        PasswordVerification::Rejected
    ));
    assert!(matches!(
        store
            .verify_password_with(
                &mut connection,
                subject_id,
                password("new correct horse battery staple")?,
                &worker,
                recovery_time,
            )
            .await?,
        PasswordVerification::Verified { .. }
    ));

    let persisted_hash: String =
        sqlx::query_scalar("SELECT password_hash FROM password_credentials WHERE user_id = $1")
            .bind(subject_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert!(persisted_hash.starts_with("$argon2id$v=19$"));
    assert!(!persisted_hash.contains("new correct horse"));

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
