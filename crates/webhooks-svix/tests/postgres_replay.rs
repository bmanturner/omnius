//! Durable PostgreSQL replay-admission lifecycle coverage.

use std::{error::Error, num::NonZeroU32, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use omnius_webhooks_svix::{
    ApplicationId, EndpointId, FailureClass, PostgresReplayAdmission, ReplayAdmission,
    ReplayAdmissionRequest, ReplayCompletion, ReplayFingerprint, ReplayMode, ReplayTaskId,
    ReplayTenantId, ReplayWindow,
};
use time::OffsetDateTime;

const FIRST_MIGRATION: i64 = 2_026_082_301;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-svix-replay-test".to_owned(),
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

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

fn replay_request(
    application: &str,
    endpoint: &str,
    fingerprint: &str,
    since: i64,
    until: i64,
) -> Result<ReplayAdmissionRequest, Box<dyn Error>> {
    Ok(ReplayAdmissionRequest::new(
        ApplicationId::new(application)?,
        EndpointId::new(endpoint)?,
        ReplayMode::All,
        ReplayWindow::new(
            OffsetDateTime::from_unix_timestamp(since)?,
            OffsetDateTime::from_unix_timestamp(until)?,
        )?,
        ReplayFingerprint::new(fingerprint)?,
    ))
}

async fn exercise_replay_admission(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;

    let admission = PostgresReplayAdmission::new(
        pool.clone(),
        ReplayTenantId::new("tenant-a")?,
        NonZeroU32::new(4).ok_or("active replay limit must be non-zero")?,
        Duration::from_secs(60),
    )?;
    let canonical = replay_request(
        "application-a",
        "endpoint-a",
        "fingerprint-canonical",
        1_788_134_400,
        1_788_138_000,
    )?;

    let first_admission = admission.clone();
    let second_admission = admission.clone();
    let first_request = canonical.clone();
    let second_request = canonical.clone();
    let (first, second) = tokio::join!(
        async move { first_admission.reserve(&first_request).await },
        async move { second_admission.reserve(&second_request).await },
    );
    let first = first?;
    let second = second?;
    assert_eq!(first.id(), second.id());

    let overlapping = replay_request(
        "application-a",
        "endpoint-a",
        "fingerprint-overlap",
        1_788_136_200,
        1_788_139_800,
    )?;
    let overlap_error = admission.reserve(&overlapping).await.unwrap_err();
    assert_eq!(overlap_error.class(), FailureClass::Conflict);

    let task_id = ReplayTaskId::new("provider-task-a")?;
    let binding = admission.bind_task(&first, &task_id).await?;
    let foreign_application = ApplicationId::new("application-foreign")?;
    let foreign_error = admission
        .authorize_task(&foreign_application, &task_id)
        .await
        .unwrap_err();
    assert_eq!(foreign_error.class(), FailureClass::NotFound);

    let releasable = replay_request(
        "application-a",
        "endpoint-release",
        "fingerprint-release",
        1_788_134_400,
        1_788_138_000,
    )?;
    let released_lease = admission.reserve(&releasable).await?;
    admission.release_rejected(&released_lease).await?;
    admission.release_rejected(&released_lease).await?;
    let retried_lease = admission.reserve(&releasable).await?;
    assert_ne!(released_lease.id(), retried_lease.id());

    admission
        .complete(&binding, ReplayCompletion::Finished)
        .await?;
    admission
        .complete(&binding, ReplayCompletion::Finished)
        .await?;
    let after_completion = replay_request(
        "application-a",
        "endpoint-a",
        "fingerprint-after-completion",
        1_788_220_800,
        1_788_224_400,
    )?;
    let cooldown_error = admission.reserve(&after_completion).await.unwrap_err();
    assert_eq!(cooldown_error.class(), FailureClass::RateLimited);
    Ok(())
}

#[tokio::test]
async fn postgres_replay_admission_enforces_durable_lifecycle() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_replay_admission(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
