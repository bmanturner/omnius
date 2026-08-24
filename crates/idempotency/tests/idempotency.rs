//! Real PostgreSQL idempotency replay, conflict, and transaction contracts.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_idempotency::{
    ClaimOutcome, IdempotencyConfig, IdempotencyKey, IdempotencyOperation, IdempotencyRequest,
    IdempotencyScope, IdempotencyScopeValue, IdempotencyStoreError, PostgresIdempotencyStore,
    RequestFingerprint, SafeResponse,
};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use sqlx::Connection as _;

const SCHEMA_VERSION: i64 = 2_026_082_307;

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
        application_name: "rsk-idempotency-test".to_owned(),
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

fn request(fingerprint: &[u8]) -> Result<IdempotencyRequest, Box<dyn Error>> {
    Ok(IdempotencyRequest::new(
        IdempotencyScope::new(Some(IdempotencyScopeValue::try_from("principal-1")?), None),
        IdempotencyOperation::new("reference.create")?,
        IdempotencyKey::try_from("request-1")?,
        RequestFingerprint::sha256(fingerprint),
    ))
}

#[tokio::test]
async fn replay_returns_original_response_and_changed_request_conflicts()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_VERSION, SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let store = PostgresIdempotencyStore::new(IdempotencyConfig::default())?;
    let original_request = request(br#"{"name":"first"}"#)?;
    let original_response = SafeResponse::new(
        201,
        Some("application/json".to_owned()),
        br#"{"result":"created"}"#.to_vec(),
    )?;
    let mut connection = pool.acquire().await?;
    sqlx::query("CREATE TABLE idempotency_effects (id integer PRIMARY KEY)")
        .execute(&mut *connection)
        .await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .claim_with(&mut transaction, &original_request)
            .await?,
        ClaimOutcome::Started
    );
    sqlx::query("INSERT INTO idempotency_effects (id) VALUES (1)")
        .execute(&mut *transaction)
        .await?;
    store
        .complete_with(&mut transaction, &original_request, &original_response)
        .await?;
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store
            .claim_with(&mut transaction, &original_request)
            .await?,
        ClaimOutcome::Replay(original_response)
    );
    transaction.commit().await?;
    let effect_count: i64 = sqlx::query_scalar("SELECT count(*) FROM idempotency_effects")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(effect_count, 1);

    let changed_request = request(br#"{"name":"changed"}"#)?;
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store.claim_with(&mut transaction, &changed_request).await,
        Err(IdempotencyStoreError::Conflict)
    );
    transaction.rollback().await?;

    sqlx::query(
        "UPDATE idempotency_records
         SET created_at = clock_timestamp() - INTERVAL '3 seconds',
             completed_at = clock_timestamp() - INTERVAL '2 seconds',
             expires_at = clock_timestamp() - INTERVAL '1 second'",
    )
    .execute(&mut *connection)
    .await?;
    let mut transaction = connection.begin().await?;
    assert_eq!(
        store.claim_with(&mut transaction, &changed_request).await?,
        ClaimOutcome::Started
    );
    transaction.rollback().await?;

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn rollback_releases_claim_and_committed_claim_remains_in_progress()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_VERSION, SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let store = PostgresIdempotencyStore::new(IdempotencyConfig::default())?;
    let request = request(br#"{"name":"rollback"}"#)?;
    let mut connection = pool.acquire().await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store.claim_with(&mut transaction, &request).await?,
        ClaimOutcome::Started
    );
    transaction.rollback().await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store.claim_with(&mut transaction, &request).await?,
        ClaimOutcome::Started
    );
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    assert_eq!(
        store.claim_with(&mut transaction, &request).await?,
        ClaimOutcome::InProgress
    );
    transaction.rollback().await?;

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
