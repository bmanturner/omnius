//! Real PostgreSQL inbox transaction, conflict, concurrency, and retention contracts.

use std::{error::Error, io, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_inbox::{
    ClaimOutcome, ClaimedInboxEvent, CleanupBatchSize, InboxEvent, InboxStoreError, PayloadSha256,
    PostgresInbox, Producer, Retention,
};
use rsk_jobs_core::{EventId, EventName, TenantId, Version};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use sqlx::{Connection as _, PgConnection};
use time::OffsetDateTime;
use uuid::Uuid;

const SCHEMA_VERSION: i64 = 2_026_082_314;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

struct TestDatabase {
    fixture: PostgresFixture,
    pool: PostgresPool,
}

impl TestDatabase {
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
            SchemaVersionRange::new(SCHEMA_VERSION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
            MigrationConfig {
                run_on_startup: false,
                operation_timeout: Duration::from_secs(10),
            },
            DeploymentEnvironment::Test,
        )?
        .run()
        .await?;
        Ok(Self { fixture, pool })
    }

    async fn shutdown(self) -> TestResult {
        self.pool.close().await?;
        self.fixture.cleanup().await?;
        Ok(())
    }
}

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
        application_name: "rsk-inbox-test".to_owned(),
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

struct Delivery {
    event: EventId,
    correlation: Uuid,
    causation: Uuid,
}

impl Delivery {
    fn new() -> Self {
        Self {
            event: EventId::new(),
            correlation: Uuid::now_v7(),
            causation: Uuid::now_v7(),
        }
    }

    fn event(&self, event_type: &str, payload: &[u8]) -> TestResult<InboxEvent> {
        self.event_with_tenant(event_type, payload, None)
    }

    fn event_with_tenant(
        &self,
        event_type: &str,
        payload: &[u8],
        tenant_id: Option<&TenantId>,
    ) -> TestResult<InboxEvent> {
        Ok(InboxEvent::new(
            Producer::try_from("orders.service")?,
            self.event,
            EventName::try_from(event_type)?,
            Version::new(1)?,
            tenant_id,
            self.correlation,
            Some(self.causation),
            payload,
            Retention::new(Duration::from_hours(24))?,
        )?)
    }
}

fn claimed(outcome: ClaimOutcome) -> TestResult<ClaimedInboxEvent> {
    match outcome {
        ClaimOutcome::Claimed(claim) => Ok(claim),
        other => Err(io::Error::other(format!("expected claimed outcome, got {other:?}")).into()),
    }
}

async fn database_now(connection: &mut PgConnection) -> TestResult<OffsetDateTime> {
    Ok(sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *connection)
        .await?)
}

#[tokio::test]
async fn rollback_allows_retry_and_completed_receipt_prevents_a_second_harmful_effect() -> TestResult
{
    let database = TestDatabase::start().await?;
    let inbox = PostgresInbox::new();
    let delivery = Delivery::new();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "CREATE TABLE inbox_harmful_effects (
             event_id uuid PRIMARY KEY,
             applications integer NOT NULL
         )",
    )
    .execute(&mut *connection)
    .await?;

    let mut transaction = connection.begin().await?;
    let claim = claimed(
        inbox
            .claim_with(
                &mut transaction,
                delivery.event("orders.debited.v1", br#"{"amount":100}"#)?,
            )
            .await?,
    )?;
    sqlx::query("INSERT INTO inbox_harmful_effects (event_id, applications) VALUES ($1, 1)")
        .bind(claim.event_id().as_uuid())
        .execute(&mut *transaction)
        .await?;
    let processed_at = database_now(&mut transaction).await?;
    inbox
        .complete_with(&mut transaction, claim, processed_at)
        .await?;
    transaction.rollback().await?;

    let effects_after_rollback: i64 =
        sqlx::query_scalar("SELECT count(*) FROM inbox_harmful_effects")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(effects_after_rollback, 0);

    let mut transaction = connection.begin().await?;
    let retry_claim = claimed(
        inbox
            .claim_with(
                &mut transaction,
                delivery.event("orders.debited.v1", br#"{"amount":100}"#)?,
            )
            .await?,
    )?;
    sqlx::query("INSERT INTO inbox_harmful_effects (event_id, applications) VALUES ($1, 1)")
        .bind(retry_claim.event_id().as_uuid())
        .execute(&mut *transaction)
        .await?;
    let processed_at = database_now(&mut transaction).await?;
    inbox
        .complete_with(&mut transaction, retry_claim, processed_at)
        .await?;
    transaction.commit().await?;

    let mut duplicate_transaction = connection.begin().await?;
    let duplicate = inbox
        .claim_with(
            &mut duplicate_transaction,
            delivery.event("orders.debited.v1", br#"{"amount":100}"#)?,
        )
        .await?;
    assert!(matches!(duplicate, ClaimOutcome::Duplicate));
    duplicate_transaction.commit().await?;

    let applications: i64 =
        sqlx::query_scalar("SELECT coalesce(sum(applications), 0) FROM inbox_harmful_effects")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(applications, 1);

    drop(connection);
    database.shutdown().await
}

#[tokio::test]
async fn concurrent_same_identity_claims_serialize_to_one_completed_receipt() -> TestResult {
    let database = TestDatabase::start().await?;
    let inbox = PostgresInbox::new();
    let delivery = Delivery::new();
    let second_event = delivery.event("orders.created.v1", br#"{"order_id":"one"}"#)?;
    let mut first_connection = database.pool.acquire().await?;
    let mut first_transaction = first_connection.begin().await?;
    let first_claim = claimed(
        inbox
            .claim_with(
                &mut first_transaction,
                delivery.event("orders.created.v1", br#"{"order_id":"one"}"#)?,
            )
            .await?,
    )?;

    let second_pool = database.pool.clone();
    let second = tokio::spawn(async move {
        let mut connection = second_pool
            .acquire()
            .await
            .map_err(|_| InboxStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| InboxStoreError::Unavailable)?;
        let outcome = inbox.claim_with(&mut transaction, second_event).await?;
        transaction
            .commit()
            .await
            .map_err(|_| InboxStoreError::Unavailable)?;
        Ok::<ClaimOutcome, InboxStoreError>(outcome)
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!second.is_finished());

    let processed_at = database_now(&mut first_transaction).await?;
    inbox
        .complete_with(&mut first_transaction, first_claim, processed_at)
        .await?;
    first_transaction.commit().await?;
    assert!(matches!(second.await??, ClaimOutcome::Duplicate));

    drop(first_connection);
    database.shutdown().await
}

#[tokio::test]
async fn changed_immutable_data_conflicts_and_committed_incomplete_receipt_is_in_progress()
-> TestResult {
    let database = TestDatabase::start().await?;
    let inbox = PostgresInbox::new();
    let completed_delivery = Delivery::new();
    let mut connection = database.pool.acquire().await?;

    let mut transaction = connection.begin().await?;
    let claim = claimed(
        inbox
            .claim_with(
                &mut transaction,
                completed_delivery.event("orders.created.v1", br#"{"order_id":"one"}"#)?,
            )
            .await?,
    )?;
    let processed_at = database_now(&mut transaction).await?;
    inbox
        .complete_with(&mut transaction, claim, processed_at)
        .await?;
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    let changed_payload = inbox
        .claim_with(
            &mut transaction,
            completed_delivery.event("orders.created.v1", br#"{"order_id":"changed"}"#)?,
        )
        .await?;
    assert!(matches!(changed_payload, ClaimOutcome::Conflict));
    transaction.rollback().await?;

    let mut transaction = connection.begin().await?;
    let changed_type = inbox
        .claim_with(
            &mut transaction,
            completed_delivery.event("orders.replaced.v1", br#"{"order_id":"one"}"#)?,
        )
        .await?;
    assert!(matches!(changed_type, ClaimOutcome::Conflict));
    transaction.rollback().await?;

    let tenant = TenantId::try_from(Uuid::now_v7().to_string())?;
    let mut transaction = connection.begin().await?;
    let changed_tenant = inbox
        .claim_with(
            &mut transaction,
            completed_delivery.event_with_tenant(
                "orders.created.v1",
                br#"{"order_id":"one"}"#,
                Some(&tenant),
            )?,
        )
        .await?;
    assert!(matches!(changed_tenant, ClaimOutcome::Conflict));
    transaction.rollback().await?;

    let incomplete_delivery = Delivery::new();
    let mut transaction = connection.begin().await?;
    let incomplete_claim = inbox
        .claim_with(
            &mut transaction,
            incomplete_delivery.event("orders.created.v1", br#"{"order_id":"two"}"#)?,
        )
        .await?;
    assert!(matches!(incomplete_claim, ClaimOutcome::Claimed(_)));
    transaction.commit().await?;

    let mut transaction = connection.begin().await?;
    let in_progress = inbox
        .claim_with(
            &mut transaction,
            incomplete_delivery.event("orders.created.v1", br#"{"order_id":"two"}"#)?,
        )
        .await?;
    assert!(matches!(in_progress, ClaimOutcome::InProgress));
    transaction.rollback().await?;

    drop(connection);
    database.shutdown().await
}

#[test]
fn exact_canonical_bytes_preserve_duplicate_member_differences() -> TestResult {
    let shadowed = PayloadSha256::from_canonical_payload(br#"{"role":"admin","role":"user"}"#)?;
    let unshadowed = PayloadSha256::from_canonical_payload(br#"{"role":"user"}"#)?;
    assert_ne!(shadowed, unshadowed);
    Ok(())
}

#[tokio::test]
async fn cleanup_skips_locked_receipts_and_never_removes_unprocessed_or_unexpired_rows()
-> TestResult {
    let database = TestDatabase::start().await?;
    let inbox = PostgresInbox::new();
    let locked_expired = Delivery::new();
    let removable_expired = Delivery::new();
    let unprocessed_expired = Delivery::new();
    let processed_active = Delivery::new();
    let mut connection = database.pool.acquire().await?;
    let mut transaction = connection.begin().await?;

    for delivery in [&locked_expired, &removable_expired, &processed_active] {
        let claim = claimed(
            inbox
                .claim_with(
                    &mut transaction,
                    delivery.event("orders.projected.v1", br#"{"projection":true}"#)?,
                )
                .await?,
        )?;
        let processed_at = database_now(&mut transaction).await?;
        inbox
            .complete_with(&mut transaction, claim, processed_at)
            .await?;
    }
    let unprocessed = inbox
        .claim_with(
            &mut transaction,
            unprocessed_expired.event("orders.projected.v1", br#"{"projection":true}"#)?,
        )
        .await?;
    assert!(matches!(unprocessed, ClaimOutcome::Claimed(_)));
    transaction.commit().await?;

    sqlx::query(
        "UPDATE inbox_receipts
         SET received_at = clock_timestamp() - INTERVAL '3 days',
             processed_at = CASE
                 WHEN processed_at IS NULL THEN NULL
                 ELSE clock_timestamp() - INTERVAL '2 days'
             END,
             expires_at = clock_timestamp() - INTERVAL '1 day'
         WHERE event_id IN ($1, $2, $3)",
    )
    .bind(locked_expired.event.as_uuid())
    .bind(removable_expired.event.as_uuid())
    .bind(unprocessed_expired.event.as_uuid())
    .execute(&mut *connection)
    .await?;

    let mut locker_connection = database.pool.acquire().await?;
    let mut locker = locker_connection.begin().await?;
    sqlx::query("SELECT event_id FROM inbox_receipts WHERE event_id = $1 FOR UPDATE")
        .bind(locked_expired.event.as_uuid())
        .fetch_one(&mut *locker)
        .await?;

    let mut cleaner_connection = database.pool.acquire().await?;
    let first_deleted = inbox
        .cleanup_expired_with(
            &mut cleaner_connection,
            CleanupBatchSize::new(MAX_TEST_BATCH)?,
        )
        .await?;
    assert_eq!(first_deleted, 1);

    locker.commit().await?;
    let second_deleted = inbox
        .cleanup_expired_with(
            &mut cleaner_connection,
            CleanupBatchSize::new(MAX_TEST_BATCH)?,
        )
        .await?;
    assert_eq!(second_deleted, 1);

    let unprocessed_remains: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM inbox_receipts WHERE event_id = $1 AND processed_at IS NULL)",
    )
    .bind(unprocessed_expired.event.as_uuid())
    .fetch_one(&mut *cleaner_connection)
    .await?;
    assert!(unprocessed_remains);
    let active_remains: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM inbox_receipts WHERE event_id = $1 AND processed_at IS NOT NULL)",
    )
    .bind(processed_active.event.as_uuid())
    .fetch_one(&mut *cleaner_connection)
    .await?;
    assert!(active_remains);

    drop(cleaner_connection);
    drop(locker_connection);
    drop(connection);
    database.shutdown().await
}

const MAX_TEST_BATCH: u16 = 10;
