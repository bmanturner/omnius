//! Real PostgreSQL transaction, lease-fencing, transition, and relay-drain contracts.

use std::{
    collections::BTreeSet,
    error::Error,
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::future::BoxFuture;
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_jobs_core::{
    Destination, DomainEvent, EventEnvelope, EventEnvelopeOptions, EventLimits, Source, Subject,
    TenantId, Traceparent,
};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_outbox::{
    FailureClass, LeasedOutboxEvent, OutboxConfig, OutboxError, OutboxPublisher, PostgresOutbox,
    PublishError,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_runtime::Supervisor;
use rsk_test_support::PostgresFixture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use tokio::sync::Notify;
use uuid::Uuid;

const SCHEMA_HEAD: i64 = 2_026_082_314;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AccountCreated {
    account_number: u32,
}

impl DomainEvent for AccountCreated {
    const NAME: &'static str = "account.created.v1";
    const VERSION: u16 = 1;
}

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
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
        application_name: "rsk-outbox-test".to_owned(),
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
        SchemaVersionRange::new(SCHEMA_HEAD, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase { pool, fixture })
}

async fn cleanup(database: TestDatabase) -> Result<(), Box<dyn Error>> {
    database.pool.close().await?;
    database.fixture.cleanup().await?;
    Ok(())
}

fn relay_config(claim_batch: usize) -> OutboxConfig {
    OutboxConfig {
        enabled: true,
        lease_owner: "test-relay-1".to_owned(),
        claim_batch,
        poll_interval: Duration::from_millis(10),
        lease_duration: Duration::from_secs(10),
        publication_timeout: Duration::from_millis(20),
        retry_delay: Duration::from_secs(5),
        shutdown_timeout: Duration::from_secs(2),
        max_attempts: 5,
        retention: Duration::from_hours(24),
        cleanup_batch: 20,
        restart: rsk_outbox::OutboxRestartConfig::default(),
    }
}

fn event(account_number: u32) -> Result<EventEnvelope<AccountCreated>, Box<dyn Error>> {
    let tenant = Uuid::now_v7();
    let correlation = Uuid::now_v7();
    let causation = Uuid::now_v7();
    let options = EventEnvelopeOptions::new(
        Source::try_from("reference-api")?,
        Subject::try_from(format!("account/{account_number}"))?,
        correlation,
    )?
    .with_tenant(TenantId::try_from(tenant.to_string())?)
    .with_causation(causation)?
    .with_traceparent(Traceparent::try_from(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )?);
    Ok(EventEnvelope::new(
        AccountCreated { account_number },
        options,
        EventLimits::default(),
    )?)
}

fn destination() -> Result<Destination, Box<dyn Error>> {
    Ok(Destination::try_from("nats:account-events")?)
}

async fn append_committed(
    outbox: &PostgresOutbox,
    pool: &PostgresPool,
    envelope: &EventEnvelope<AccountCreated>,
) -> Result<(), Box<dyn Error>> {
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    outbox
        .append(
            &mut transaction,
            envelope,
            "account",
            &format!("account-{}", envelope.data().account_number),
            &destination()?,
            OffsetDateTime::now_utc() - time::Duration::seconds(1),
            EventLimits::default(),
        )
        .await?;
    transaction.commit().await?;
    Ok(())
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one end-to-end transaction proves rollback, commit, and every persisted header"
)]
async fn business_state_and_outbox_intent_commit_and_rollback_atomically_with_exact_headers()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let outbox = PostgresOutbox::new(database.pool.clone(), relay_config(2))?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query("CREATE TABLE account_effects (id integer PRIMARY KEY)")
        .execute(&mut *connection)
        .await?;

    let rolled_back = event(1)?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO account_effects (id) VALUES (1)")
        .execute(&mut *transaction)
        .await?;
    outbox
        .append(
            &mut transaction,
            &rolled_back,
            "account",
            "account-1",
            &destination()?,
            OffsetDateTime::now_utc(),
            EventLimits::default(),
        )
        .await?;
    transaction.rollback().await?;

    let business_after_rollback: i64 = sqlx::query_scalar("SELECT count(*) FROM account_effects")
        .fetch_one(&mut *connection)
        .await?;
    let outbox_after_rollback: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_events")
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!((business_after_rollback, outbox_after_rollback), (0, 0));

    let committed = event(2)?;
    let available_at = OffsetDateTime::now_utc();
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO account_effects (id) VALUES (2)")
        .execute(&mut *transaction)
        .await?;
    outbox
        .append(
            &mut transaction,
            &committed,
            "account",
            "account-2",
            &destination()?,
            available_at,
            EventLimits::default(),
        )
        .await?;
    transaction.commit().await?;

    let stored = sqlx::query(
        "SELECT id, aggregate_type, aggregate_id, event_type, event_version, source, subject,
                tenant_id, occurred_at, correlation_id, causation_id, traceparent, payload,
                destination, available_at, attempt_count, lease_token, published_at
         FROM outbox_events WHERE id = $1",
    )
    .bind(committed.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let stored_payload: Value = stored.try_get("payload")?;
    let stored_occurred_at: OffsetDateTime = stored.try_get("occurred_at")?;
    let stored_available_at: OffsetDateTime = stored.try_get("available_at")?;
    let expected_tenant = Uuid::parse_str(
        committed
            .tenant_id()
            .ok_or_else(|| io::Error::other("test event has no tenant"))?
            .as_str(),
    )?;
    assert_eq!(stored.try_get::<Uuid, _>("id")?, committed.id().as_uuid());
    assert_eq!(stored.try_get::<String, _>("aggregate_type")?, "account");
    assert_eq!(stored.try_get::<String, _>("aggregate_id")?, "account-2");
    assert_eq!(
        stored.try_get::<String, _>("event_type")?,
        committed.event_name().as_str()
    );
    assert_eq!(stored.try_get::<i16, _>("event_version")?, 1);
    assert_eq!(
        stored.try_get::<String, _>("source")?,
        committed.source().as_str()
    );
    assert_eq!(
        stored.try_get::<String, _>("subject")?,
        committed.subject().as_str()
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("tenant_id")?,
        Some(expected_tenant)
    );
    assert_eq!(
        stored_occurred_at.unix_timestamp_nanos() / 1_000,
        committed.occurred_at().unix_timestamp_nanos() / 1_000,
    );
    assert_eq!(
        stored.try_get::<Uuid, _>("correlation_id")?,
        committed.correlation_id()
    );
    assert_eq!(
        stored.try_get::<Option<Uuid>, _>("causation_id")?,
        committed.causation_id()
    );
    assert_eq!(
        stored
            .try_get::<Option<String>, _>("traceparent")?
            .as_deref(),
        committed
            .traceparent()
            .map(rsk_jobs_core::Traceparent::as_str),
    );
    assert_eq!(stored_payload, serde_json::to_value(&committed)?);
    assert_eq!(
        stored.try_get::<String, _>("destination")?,
        destination()?.as_str()
    );
    assert_eq!(
        stored_available_at.unix_timestamp_nanos() / 1_000,
        available_at.unix_timestamp_nanos() / 1_000,
    );
    assert_eq!(stored.try_get::<i32, _>("attempt_count")?, 0);
    assert_eq!(stored.try_get::<Option<Uuid>, _>("lease_token")?, None);
    assert_eq!(
        stored.try_get::<Option<OffsetDateTime>, _>("published_at")?,
        None
    );

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one multi-worker scenario proves disjoint claims, reclaim, and token fencing"
)]
async fn concurrent_claims_reclaim_and_fenced_transitions_are_disjoint_and_restart_safe()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let outbox = PostgresOutbox::new(database.pool.clone(), relay_config(2))?;
    for account_number in 10..14 {
        append_committed(&outbox, &database.pool, &event(account_number)?).await?;
    }

    let (first, second) = tokio::join!(outbox.claim(), outbox.claim());
    let first = first?;
    let second = second?;
    assert_eq!((first.len(), second.len()), (2, 2));
    let first_ids = first
        .iter()
        .map(LeasedOutboxEvent::id)
        .collect::<BTreeSet<_>>();
    let second_ids = second
        .iter()
        .map(LeasedOutboxEvent::id)
        .collect::<BTreeSet<_>>();
    assert!(first_ids.is_disjoint(&second_ids));

    let reclaimable = event(20)?;
    append_committed(&outbox, &database.pool, &reclaimable).await?;
    let original_claim = outbox.claim().await?;
    assert_eq!(original_claim.len(), 1);
    let original_token = original_claim[0].lease_token();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE outbox_events
         SET lease_expires_at = clock_timestamp() - INTERVAL '1 second'
         WHERE id = $1",
    )
    .bind(reclaimable.id().as_uuid())
    .execute(&mut *connection)
    .await?;

    let reclaimed = outbox.claim().await?;
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].id(), reclaimable.id());
    assert_ne!(reclaimed[0].lease_token(), original_token);
    assert_eq!(
        outbox
            .mark_published(reclaimable.id(), original_token)
            .await,
        Err(OutboxError::LostLease),
    );

    let transient = FailureClass::try_from("provider_unavailable")?;
    outbox
        .mark_failed(
            reclaimed[0].id(),
            reclaimed[0].lease_token(),
            &transient,
            Duration::from_secs(5),
        )
        .await?;
    let failed = sqlx::query(
        "SELECT attempt_count, last_error_class, lease_token, lease_owner, lease_expires_at,
                available_at > clock_timestamp() AS delayed
         FROM outbox_events WHERE id = $1",
    )
    .bind(reclaimable.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(failed.try_get::<i32, _>("attempt_count")?, 2);
    assert_eq!(
        failed.try_get::<String, _>("last_error_class")?,
        transient.as_str()
    );
    assert_eq!(failed.try_get::<Option<Uuid>, _>("lease_token")?, None);
    assert_eq!(failed.try_get::<Option<String>, _>("lease_owner")?, None);
    assert_eq!(
        failed.try_get::<Option<OffsetDateTime>, _>("lease_expires_at")?,
        None
    );
    assert!(failed.try_get::<bool, _>("delayed")?);

    let publishable = event(21)?;
    append_committed(&outbox, &database.pool, &publishable).await?;
    let published_claim = outbox.claim().await?;
    assert_eq!(published_claim.len(), 1);
    assert_eq!(published_claim[0].id(), publishable.id());
    outbox
        .mark_published(published_claim[0].id(), published_claim[0].lease_token())
        .await?;
    let published = sqlx::query(
        "SELECT published_at, lease_token, lease_owner, lease_expires_at, last_error_class
         FROM outbox_events WHERE id = $1",
    )
    .bind(publishable.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert!(
        published
            .try_get::<Option<OffsetDateTime>, _>("published_at")?
            .is_some()
    );
    assert_eq!(published.try_get::<Option<Uuid>, _>("lease_token")?, None);
    assert_eq!(published.try_get::<Option<String>, _>("lease_owner")?, None);
    assert_eq!(
        published.try_get::<Option<OffsetDateTime>, _>("lease_expires_at")?,
        None
    );
    assert_eq!(
        published.try_get::<Option<String>, _>("last_error_class")?,
        None
    );

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
async fn cleanup_removes_an_exhausted_row_after_its_final_lease_expires()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let mut config = relay_config(1);
    config.max_attempts = 1;
    config.retention = Duration::from_hours(1);
    let outbox = PostgresOutbox::new(database.pool.clone(), config)?;
    let exhausted = event(30)?;
    append_committed(&outbox, &database.pool, &exhausted).await?;
    assert_eq!(outbox.claim().await?.len(), 1);

    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE outbox_events
         SET lease_expires_at = clock_timestamp() - INTERVAL '1 second',
             available_at = clock_timestamp() - INTERVAL '2 hours'
         WHERE id = $1",
    )
    .bind(exhausted.id().as_uuid())
    .execute(&mut *connection)
    .await?;

    assert_eq!(outbox.cleanup_retained().await?, 1);
    let remains: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM outbox_events WHERE id = $1)")
            .bind(exhausted.id().as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert!(!remains);

    drop(connection);
    cleanup(database).await
}

#[tokio::test]
async fn backlog_status_classifies_every_unpublished_state_and_reports_oldest_age()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let mut config = relay_config(1);
    config.max_attempts = 2;
    let outbox = PostgresOutbox::new(database.pool.clone(), config)?;

    let leased = event(40)?;
    append_committed(&outbox, &database.pool, &leased).await?;
    let leased_claim = outbox.claim().await?;
    assert_eq!(leased_claim.len(), 1);

    let ready = event(41)?;
    let delayed = event(42)?;
    let exhausted = event(43)?;
    let published = event(44)?;
    for envelope in [&ready, &delayed, &exhausted, &published] {
        append_committed(&outbox, &database.pool, envelope).await?;
    }

    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE outbox_events
         SET lease_expires_at = clock_timestamp() + INTERVAL '1 hour'
         WHERE id = $1",
    )
    .bind(leased.id().as_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE outbox_events
         SET created_at = clock_timestamp() - INTERVAL '2 hours'
         WHERE id = $1",
    )
    .bind(ready.id().as_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE outbox_events
         SET available_at = clock_timestamp() + INTERVAL '1 hour'
         WHERE id = $1",
    )
    .bind(delayed.id().as_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE outbox_events
         SET attempt_count = 2
         WHERE id = $1",
    )
    .bind(exhausted.id().as_uuid())
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE outbox_events
         SET published_at = clock_timestamp()
         WHERE id = $1",
    )
    .bind(published.id().as_uuid())
    .execute(&mut *connection)
    .await?;

    let status = outbox.backlog_status().await?;
    assert_eq!(
        (
            status.unpublished_total(),
            status.ready(),
            status.delayed(),
            status.actively_leased(),
            status.exhausted(),
        ),
        (4, 1, 1, 1, 1),
    );
    let oldest_age = status
        .oldest_unpublished_age()
        .ok_or_else(|| io::Error::other("nonempty backlog did not report an oldest age"))?;
    assert!(oldest_age >= Duration::from_hours(2));
    assert!(oldest_age < Duration::from_hours(2) + Duration::from_secs(30));

    drop(connection);
    cleanup(database).await
}

struct BlockingPublisher {
    calls: AtomicUsize,
    started: Notify,
}

impl BlockingPublisher {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
        }
    }
}

impl OutboxPublisher for BlockingPublisher {
    fn publish<'event>(
        &'event self,
        _event: &'event LeasedOutboxEvent,
    ) -> BoxFuture<'event, Result<(), PublishError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_one();
            futures::future::pending::<()>().await;
            Ok(())
        })
    }
}

#[tokio::test]
async fn relay_stops_claiming_on_drain_and_bounds_a_stalled_publication()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let config = OutboxConfig {
        claim_batch: 1,
        publication_timeout: Duration::from_millis(50),
        lease_duration: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(2),
        retry_delay: Duration::from_secs(5),
        ..relay_config(1)
    };
    let outbox = PostgresOutbox::new(database.pool.clone(), config)?;
    let envelope = event(30)?;
    append_committed(&outbox, &database.pool, &envelope).await?;
    let publisher = Arc::new(BlockingPublisher::new());
    let mut supervisor = Supervisor::new();
    let publisher_adapter: Arc<dyn OutboxPublisher> = publisher.clone();
    supervisor.register(
        outbox
            .relay_task(publisher_adapter)
            .ok_or_else(|| io::Error::other("enabled relay did not register"))?,
    )?;
    let handle = supervisor.start()?;

    tokio::time::timeout(Duration::from_secs(1), publisher.started.notified()).await?;
    handle.begin_drain();
    let report = tokio::time::timeout(Duration::from_millis(500), handle.shutdown()).await?;
    assert!(!report.fatal);
    assert!(report.forced.is_empty());
    assert_eq!(publisher.calls.load(Ordering::SeqCst), 1);

    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query(
        "SELECT attempt_count, last_error_class, lease_token, published_at
         FROM outbox_events WHERE id = $1",
    )
    .bind(envelope.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.try_get::<i32, _>("attempt_count")?, 1);
    assert_eq!(
        row.try_get::<Option<String>, _>("last_error_class")?
            .as_deref(),
        Some("timeout")
    );
    assert_eq!(row.try_get::<Option<Uuid>, _>("lease_token")?, None);
    assert_eq!(
        row.try_get::<Option<OffsetDateTime>, _>("published_at")?,
        None
    );

    drop(connection);
    cleanup(database).await
}
