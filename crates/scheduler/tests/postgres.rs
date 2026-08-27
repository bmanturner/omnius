//! Real PostgreSQL calendar, fencing, administration, dispatch, execution, and drain contracts.

use futures::future::BoxFuture;
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EncodedJobEnvelope, EnqueueError,
    EnqueueReceipt, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuer, JobEnvelope,
    JobEnvelopeOptions, JobHandler as _, JobPolicy, TypedJobHandler,
};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_runtime::Supervisor;
use omnius_scheduler::{
    EnvelopeFactoryError, LeasedRun, MisfirePolicy, PostgresScheduler, RunStatus, ScheduleActor,
    ScheduleDefinition, ScheduleEnvelopeFactory, ScheduleId, ScheduleName, ScheduleReason,
    ScheduledJobHandler, SchedulerConfig, SchedulerError, evaluate_occurrences, next_occurrence,
};
use omnius_test_support::PostgresFixture;
use serde::{Deserialize, Serialize};
use sqlx::{Connection as _, Row as _};
use std::{
    error::Error,
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SCHEMA_HEAD: i64 = 2_026_082_314;
const TEST_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Optional,
    5,
    10,
    1_000,
    2,
    Jitter::Full,
    30,
    4,
    Some(120),
    "scheduled",
    5,
    86_400,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    4_096,
) {
    Ok(policy) => policy,
    Err(_) => panic!("test policy must be valid"),
};
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ScheduledPayload {
    schedule_id: Uuid,
    scheduled_unix: i64,
    replay_sequence: u32,
}
impl Job for ScheduledPayload {
    const NAME: &'static str = "scheduler.test";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = TEST_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_scheduler_test";
    const RUNBOOK: &'static str = "runbooks/scheduler-test";
}

#[derive(Default)]
struct TestFactory {
    envelopes: Mutex<Vec<EncodedJobEnvelope>>,
}
impl ScheduleEnvelopeFactory for TestFactory {
    fn build(
        &self,
        schedule_id: ScheduleId,
        scheduled_for: OffsetDateTime,
        replay_sequence: u32,
    ) -> Result<EncodedJobEnvelope, EnvelopeFactoryError> {
        let options =
            JobEnvelopeOptions::new(Uuid::now_v7()).map_err(|_| EnvelopeFactoryError::Invalid)?;
        let envelope = JobEnvelope::new(
            ScheduledPayload {
                schedule_id: schedule_id.as_uuid(),
                scheduled_unix: scheduled_for.unix_timestamp(),
                replay_sequence,
            },
            options,
        )
        .and_then(|value| value.encode())
        .map_err(|_| EnvelopeFactoryError::Invalid)?;
        self.envelopes
            .lock()
            .map_err(|_| EnvelopeFactoryError::Unavailable)?
            .push(envelope.clone());
        Ok(envelope)
    }
}

#[derive(Default)]
struct AcceptingEnqueuer {
    accepted: Mutex<Vec<EncodedJobEnvelope>>,
}
impl JobEnqueuer for AcceptingEnqueuer {
    fn enqueue(
        &self,
        envelope: EncodedJobEnvelope,
    ) -> BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>> {
        Box::pin(async move {
            self.accepted
                .lock()
                .map_err(|_| EnqueueError::Unavailable)?
                .push(envelope.clone());
            Ok(EnqueueReceipt::new(
                envelope.id(),
                envelope.queue().clone(),
                OffsetDateTime::now_utc(),
            ))
        })
    }
}

struct FailingEnqueuer;
impl JobEnqueuer for FailingEnqueuer {
    fn enqueue(
        &self,
        _envelope: EncodedJobEnvelope,
    ) -> BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>> {
        Box::pin(async { Err(EnqueueError::Unavailable) })
    }
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
        max_connections: 8,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-scheduler-test".to_owned(),
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
async fn test_database() -> TestResult<TestDatabase> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(SCHEMA_HEAD, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
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
async fn cleanup(database: TestDatabase) -> TestResult {
    database.pool.close().await?;
    database.fixture.cleanup().await?;
    Ok(())
}
fn scheduler_config(owner: &str, schedule_batch: usize, dispatch_batch: usize) -> SchedulerConfig {
    SchedulerConfig {
        enabled: false,
        lease_owner: owner.to_owned(),
        schedule_claim_batch: schedule_batch,
        dispatch_claim_batch: dispatch_batch,
        poll_interval: Duration::from_millis(10),
        enqueue_timeout: Duration::from_secs(2),
        dispatch_lease_duration: Duration::from_secs(5),
        dispatch_retry_delay: Duration::from_secs(1),
        shutdown_timeout: Duration::from_secs(2),
        restart: omnius_scheduler::SchedulerRestartConfig::default(),
    }
}
fn definition(
    name: &str,
    expression: &str,
    timezone: &str,
    policy: MisfirePolicy,
    maximum: u16,
    paused: bool,
) -> Result<ScheduleDefinition, SchedulerError> {
    ScheduleDefinition::new(
        ScheduleName::try_from(name)?,
        expression,
        timezone,
        policy,
        NonZeroU16::new(maximum).ok_or(SchedulerError::InvalidDefinition)?,
        Duration::from_secs(5),
        Duration::from_secs(6),
        Duration::from_secs(300),
        paused,
    )
}
fn actor_reason() -> Result<(ScheduleActor, ScheduleReason), SchedulerError> {
    Ok((
        ScheduleActor::new("test:operator")?,
        ScheduleReason::new("operator requested schedule mutation")?,
    ))
}
async fn force_due(
    pool: &PostgresPool,
    id: ScheduleId,
    minutes_ago: i32,
) -> TestResult<OffsetDateTime> {
    let mut connection = pool.acquire().await?;
    Ok(sqlx::query_scalar("UPDATE scheduler_schedules SET next_run_at = date_trunc('minute', clock_timestamp()) - $2::integer * INTERVAL '1 minute', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL WHERE id = $1 RETURNING next_run_at").bind(id.as_uuid()).bind(minutes_ago).fetch_one(&mut *connection).await?)
}
fn context_with_deadline(
    envelope: &EncodedJobEnvelope,
    cancellation: CancellationToken,
    deadline: OffsetDateTime,
) -> TestResult<DeliveryContext> {
    Ok(DeliveryContext::from_envelope(
        envelope,
        1,
        cancellation,
        deadline,
    )?)
}
fn context(envelope: &EncodedJobEnvelope) -> TestResult<DeliveryContext> {
    context_with_deadline(
        envelope,
        CancellationToken::new(),
        OffsetDateTime::now_utc() + TimeDuration::seconds(30),
    )
}

#[test]
fn calendar_and_all_misfire_policies_are_exact_and_bounded() -> TestResult {
    let fall = definition(
        "calendar.fall",
        "30 2 * * *",
        "Europe/Stockholm",
        MisfirePolicy::FireOnce,
        1,
        false,
    )?;
    assert_eq!(
        next_occurrence(
            &fall,
            OffsetDateTime::parse("2025-10-25T01:00:00Z", &Rfc3339)?
        )?,
        OffsetDateTime::parse("2025-10-26T00:30:00Z", &Rfc3339)?
    );
    let spring = definition(
        "calendar.spring",
        "30 2 * * *",
        "Europe/Stockholm",
        MisfirePolicy::FireOnce,
        1,
        false,
    )?;
    assert_eq!(
        next_occurrence(
            &spring,
            OffsetDateTime::parse("2025-03-29T02:30:00Z", &Rfc3339)?
        )?,
        OffsetDateTime::parse("2025-03-30T01:00:00Z", &Rfc3339)?
    );
    let cursor = OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339)?;
    let now = cursor + TimeDuration::minutes(5);
    let skip = definition(
        "misfire.skip",
        "* * * * *",
        "UTC",
        MisfirePolicy::Skip,
        1,
        false,
    )?;
    assert!(
        evaluate_occurrences(&skip, cursor, now)?
            .occurrences()
            .is_empty()
    );
    let fire = definition(
        "misfire.fire",
        "* * * * *",
        "UTC",
        MisfirePolicy::FireOnce,
        1,
        false,
    )?;
    assert_eq!(
        evaluate_occurrences(&fire, cursor, now)?.occurrences(),
        &[cursor]
    );
    let catch_up = definition(
        "misfire.catch",
        "* * * * *",
        "UTC",
        MisfirePolicy::CatchUp {
            max_runs: NonZeroU16::new(2).ok_or(SchedulerError::InvalidDefinition)?,
        },
        1,
        false,
    )?;
    let plan = evaluate_occurrences(&catch_up, cursor, now)?;
    assert_eq!(plan.occurrences().len(), 2);
    assert!(plan.next_run_at() <= now);
    Ok(())
}

async fn assert_uuid_constraint(pool: &PostgresPool) -> TestResult {
    let mut connection = pool.acquire().await?;
    let non_v7 = Uuid::from_u128(0x550e_8400_e29b_41d4_a716_4466_5544_0000);
    let result = sqlx::query(
        "INSERT INTO scheduler_schedules (
            id, name, cron_expression, timezone, misfire_policy, max_concurrent_runs,
            scheduler_lease_micros, execution_lease_micros, idempotency_window_micros,
            next_run_at
         ) VALUES ($1, 'invalid.uuid', '* * * * *', 'UTC', 'fire_once', 1,
                   5000000, 6000000, 300000000, clock_timestamp())",
    )
    .bind(non_v7)
    .execute(&mut *connection)
    .await;
    assert!(result.is_err());
    Ok(())
}

async fn materialize_claimed_runs(
    pool: &PostgresPool,
    scheduler_a: &PostgresScheduler,
    scheduler_b: &PostgresScheduler,
    factory: &TestFactory,
    actor: &ScheduleActor,
    reason: &ScheduleReason,
) -> TestResult<Vec<LeasedRun>> {
    let first = scheduler_a
        .create_schedule(
            definition(
                "claims.first",
                "* * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                1,
                false,
            )?,
            actor,
            reason,
        )
        .await?;
    let second = scheduler_a
        .create_schedule(
            definition(
                "claims.second",
                "* * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                1,
                false,
            )?,
            actor,
            reason,
        )
        .await?;
    force_due(pool, first.id(), 2).await?;
    force_due(pool, second.id(), 2).await?;
    let (claims_a, claims_b) = tokio::join!(
        scheduler_a.claim_due_schedules(),
        scheduler_b.claim_due_schedules()
    );
    let claims_a = claims_a?;
    let claims_b = claims_b?;
    assert_eq!(claims_a.len(), 1);
    assert_eq!(claims_b.len(), 1);
    assert_ne!(claims_a[0].schedule().id(), claims_b[0].schedule().id());
    let current = &claims_b[0];
    let mut connection = pool.acquire().await?;
    sqlx::query("UPDATE scheduler_schedules SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
        .bind(current.schedule().id().as_uuid())
        .execute(&mut *connection)
        .await?;
    drop(connection);
    scheduler_b.materialize_due(current, factory).await?;
    let stale = &claims_a[0];
    let mut connection = pool.acquire().await?;
    sqlx::query("UPDATE scheduler_schedules SET lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
        .bind(stale.schedule().id().as_uuid())
        .execute(&mut *connection)
        .await?;
    drop(connection);
    let reclaimed = scheduler_b.claim_due_schedules().await?;
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(
        scheduler_a.materialize_due(stale, factory).await,
        Err(SchedulerError::LostLease)
    );
    scheduler_b.materialize_due(&reclaimed[0], factory).await?;
    let original = scheduler_a.claim_pending_runs().await?;
    assert_eq!(original.len(), 2);
    Ok(original)
}

#[tokio::test]
async fn claims_fences_expiry_and_ambiguous_handoff_are_duplicate_safe() -> TestResult {
    let database = test_database().await?;
    assert_uuid_constraint(&database.pool).await?;
    let scheduler_a =
        PostgresScheduler::new(database.pool.clone(), scheduler_config("replica-a", 1, 4))?;
    let scheduler_b =
        PostgresScheduler::new(database.pool.clone(), scheduler_config("replica-b", 1, 4))?;
    let factory = TestFactory::default();
    let (actor, reason) = actor_reason()?;
    let original = materialize_claimed_runs(
        &database.pool,
        &scheduler_a,
        &scheduler_b,
        &factory,
        &actor,
        &reason,
    )
    .await?;
    let accepted = AcceptingEnqueuer::default();
    accepted.enqueue(original[0].envelope().clone()).await?;
    assert_eq!(
        scheduler_a
            .dispatch_claimed(&original[1], &FailingEnqueuer)
            .await,
        Err(SchedulerError::Provider)
    );
    let mut connection = database.pool.acquire().await?;
    sqlx::query("UPDATE scheduler_job_runs SET dispatch_lease_expires_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
        .bind(original[0].id().as_uuid()).execute(&mut *connection).await?;
    sqlx::query("UPDATE scheduler_job_runs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE id = $1")
        .bind(original[1].id().as_uuid()).execute(&mut *connection).await?;
    drop(connection);
    let retried = scheduler_b.claim_pending_runs().await?;
    let same = retried
        .iter()
        .find(|run| run.id() == original[0].id())
        .ok_or("expired handoff was not reclaimed")?;
    let failed_retry = retried
        .iter()
        .find(|run| run.id() == original[1].id())
        .ok_or("failed handoff was not retried")?;
    assert_eq!(same.job_id(), original[0].job_id());
    assert_eq!(same.envelope().bytes(), original[0].envelope().bytes());
    assert_eq!(failed_retry.job_id(), original[1].job_id());
    assert_eq!(
        failed_retry.envelope().bytes(),
        original[1].envelope().bytes()
    );
    assert_eq!(
        scheduler_a.mark_dispatched(&original[0]).await,
        Err(SchedulerError::LostLease)
    );
    scheduler_b.mark_dispatched(same).await?;
    scheduler_b.mark_dispatched(failed_retry).await?;
    cleanup(database).await
}

#[tokio::test]
async fn administration_is_revision_checked_audited_and_replay_linked() -> TestResult {
    let database = test_database().await?;
    let scheduler = PostgresScheduler::new(
        database.pool.clone(),
        scheduler_config("admin-replica", 4, 4),
    )?;
    let factory = TestFactory::default();
    let (actor, reason) = actor_reason()?;
    assert!(!format!("{actor:?} {reason:?}").contains("operator requested"));
    let created = scheduler
        .create_schedule(
            definition(
                "admin.schedule",
                "* * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                2,
                false,
            )?,
            &actor,
            &reason,
        )
        .await?;
    assert!(matches!(
        scheduler
            .pause_schedule(created.id(), created.revision() + 1, &actor, &reason)
            .await,
        Err(SchedulerError::RevisionConflict)
    ));
    let paused = scheduler
        .pause_schedule(created.id(), created.revision(), &actor, &reason)
        .await?;
    force_due(&database.pool, paused.id(), 2).await?;
    assert!(scheduler.claim_due_schedules().await?.is_empty());
    let resumed = scheduler
        .resume_schedule(paused.id(), paused.revision(), &actor, &reason)
        .await?;
    let updated = scheduler
        .update_schedule(
            resumed.id(),
            resumed.revision(),
            definition(
                "admin.schedule",
                "*/2 * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                2,
                false,
            )?,
            &actor,
            &reason,
        )
        .await?;
    let scheduled_for = force_due(&database.pool, updated.id(), 4).await?;
    let claim = scheduler.claim_due_schedules().await?;
    scheduler.materialize_due(&claim[0], &factory).await?;
    assert_eq!(
        scheduler
            .replay(updated.id(), scheduled_for, &factory, &actor, &reason)
            .await?
            .as_uuid()
            .get_version_num(),
        7
    );
    let audit = scheduler.audit_records(updated.id()).await?;
    assert_eq!(
        audit
            .iter()
            .map(omnius_scheduler::AuditRecord::action)
            .collect::<Vec<_>>(),
        ["create", "pause", "resume", "update", "replay"]
    );
    assert!(format!("{:?}", audit.last().ok_or("missing audit")?).contains("REDACTED"));
    let mut connection = database.pool.acquire().await?;
    assert!(
        sqlx::query(
            "UPDATE scheduler_audit_events SET reason = 'rewritten' WHERE schedule_id = $1"
        )
        .bind(updated.id().as_uuid())
        .execute(&mut *connection)
        .await
        .is_err()
    );
    cleanup(database).await
}

async fn wait_for_schedule_lock_wait(pool: &PostgresPool, blocker_pid: i32) -> TestResult {
    let mut observer = pool.acquire().await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM pg_stat_activity
                    WHERE datname = current_database()
                      AND pid <> $1 AND pid <> pg_backend_pid()
                      AND wait_event_type = 'Lock'
                      AND query LIKE '%scheduler_schedules%'
                 )",
            )
            .bind(blocker_pid)
            .fetch_one(&mut *observer)
            .await?;
            if waiting {
                return Ok::<(), Box<dyn Error + Send + Sync>>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "schedule update did not wait for the row lock")??;
    Ok(())
}

#[tokio::test]
async fn update_cursor_uses_the_post_lock_database_clock() -> TestResult {
    let database = test_database().await?;
    let scheduler = PostgresScheduler::new(
        database.pool.clone(),
        scheduler_config("update-create-replica", 1, 1),
    )?;
    let mut update_database_config = postgres_config(database.fixture.database_url().clone());
    update_database_config.min_connections = 1;
    update_database_config.max_connections = 1;
    update_database_config.lock_timeout = Duration::from_secs(5);
    update_database_config.application_name = "omnius-scheduler-update-lock-test".to_owned();
    let update_pool =
        PostgresPool::connect(&update_database_config, DeploymentEnvironment::Test).await?;
    let updater = PostgresScheduler::new(
        update_pool.clone(),
        scheduler_config("update-replica", 1, 1),
    )?;
    let (actor, reason) = actor_reason()?;
    let created = scheduler
        .create_schedule(
            definition(
                "serialized.update",
                "* * * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                1,
                false,
            )?,
            &actor,
            &reason,
        )
        .await?;
    let mut blocker_connection = database.pool.acquire().await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker_connection)
        .await?;
    let mut blocker = blocker_connection.begin().await?;
    sqlx::query("SELECT id FROM scheduler_schedules WHERE id = $1 FOR UPDATE")
        .bind(created.id().as_uuid())
        .fetch_one(&mut *blocker)
        .await?;
    let update_id = created.id();
    let expected_revision = created.revision();
    let update = tokio::spawn(async move {
        updater
            .update_schedule(
                update_id,
                expected_revision,
                definition(
                    "serialized.update",
                    "* * * * * *",
                    "UTC",
                    MisfirePolicy::FireOnce,
                    1,
                    false,
                )?,
                &actor,
                &reason,
            )
            .await
    });
    wait_for_schedule_lock_wait(&database.pool, blocker_pid).await?;
    // Cross a complete every-second cron interval only after the update is queued on the row lock.
    sqlx::query("SELECT pg_sleep(1.1)")
        .fetch_one(&mut *blocker)
        .await?;
    let before_release: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut *blocker)
        .await?;
    blocker.commit().await?;
    let post_lock_schedule = update.await??;
    assert!(post_lock_schedule.next_run_at() > before_release);
    update_pool.close().await?;
    cleanup(database).await
}

struct BlockingHandler {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
}
impl TypedJobHandler<ScheduledPayload> for BlockingHandler {
    fn handle(
        &self,
        _job: ScheduledPayload,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.maximum.fetch_max(active, Ordering::SeqCst);
            self.entered.notify_one();
            self.release.notified().await;
            self.active.fetch_sub(1, Ordering::SeqCst);
            HandlerOutcome::Succeeded
        })
    }
}
struct OutcomeHandler(HandlerOutcome);
impl TypedJobHandler<ScheduledPayload> for OutcomeHandler {
    fn handle(
        &self,
        _job: ScheduledPayload,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move { self.0.clone() })
    }
}
struct PendingHandler;
impl TypedJobHandler<ScheduledPayload> for PendingHandler {
    fn handle(
        &self,
        _job: ScheduledPayload,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(std::future::pending())
    }
}

struct ConstructionPanicHandler;
impl TypedJobHandler<ScheduledPayload> for ConstructionPanicHandler {
    fn handle(
        &self,
        _job: ScheduledPayload,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        panic!("secret-construction-panic")
    }
}

struct PollPanicHandler;
impl TypedJobHandler<ScheduledPayload> for PollPanicHandler {
    fn handle(
        &self,
        _job: ScheduledPayload,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async { panic!("secret-poll-panic") })
    }
}

async fn assert_terminal_gate_transitions(
    scheduler: &PostgresScheduler,
    runs: &[LeasedRun],
) -> TestResult {
    let retry_gate = ScheduledJobHandler::new(
        scheduler.clone(),
        OutcomeHandler(HandlerOutcome::Retryable(
            omnius_jobs_core::HandlerFailure::new(omnius_jobs_core::FailureCode::try_from("test_retry")?),
        )),
    );
    assert!(matches!(
        retry_gate
            .handle(runs[1].envelope().clone(), context(runs[1].envelope())?)
            .await,
        HandlerOutcome::Retryable(_)
    ));
    assert_eq!(
        scheduler.run_status(runs[1].job_id()).await?,
        Some(RunStatus::Dispatched)
    );
    let permanent_gate = ScheduledJobHandler::new(
        scheduler.clone(),
        OutcomeHandler(HandlerOutcome::Permanent(
            omnius_jobs_core::HandlerFailure::new(omnius_jobs_core::FailureCode::try_from(
                "test_permanent",
            )?),
        )),
    );
    assert!(matches!(
        permanent_gate
            .handle(runs[2].envelope().clone(), context(runs[2].envelope())?)
            .await,
        HandlerOutcome::Permanent(_)
    ));
    assert_eq!(
        scheduler.run_status(runs[2].job_id()).await?,
        Some(RunStatus::Failed)
    );
    Ok(())
}
async fn assert_delivery_deadline_releases_execution(
    scheduler: &PostgresScheduler,
    run: &LeasedRun,
) -> TestResult {
    let gate = ScheduledJobHandler::<ScheduledPayload, _>::new(scheduler.clone(), PendingHandler);
    let provider_budget = Duration::from_secs(2);
    let provider_deadline = tokio::time::Instant::now() + provider_budget;
    let context_deadline = OffsetDateTime::now_utc() + TimeDuration::seconds(2);
    let outcome = tokio::time::timeout_at(
        provider_deadline,
        gate.handle(
            run.envelope().clone(),
            context_with_deadline(run.envelope(), CancellationToken::new(), context_deadline)?,
        ),
    )
    .await?;
    let HandlerOutcome::Retryable(failure) = outcome else {
        return Err("deadline did not produce a retryable outcome".into());
    };
    assert_eq!(failure.code().as_str(), "scheduled_execution_timeout");
    assert_eq!(
        scheduler.run_status(run.job_id()).await?,
        Some(RunStatus::Dispatched)
    );
    Ok(())
}

async fn assert_panic_releases_execution<H>(
    scheduler: &PostgresScheduler,
    pool: &PostgresPool,
    run: &LeasedRun,
    handler: H,
) -> TestResult
where
    H: TypedJobHandler<ScheduledPayload>,
{
    let gate = ScheduledJobHandler::<ScheduledPayload, _>::new(scheduler.clone(), handler);
    let outcome = gate
        .handle(run.envelope().clone(), context(run.envelope())?)
        .await;
    let HandlerOutcome::Permanent(failure) = outcome else {
        return Err("panic did not produce a permanent outcome".into());
    };
    assert_eq!(failure.code().as_str(), "scheduled_handler_panic");
    assert!(!format!("{failure:?}").contains("secret-"));
    assert_eq!(
        scheduler.run_status(run.job_id()).await?,
        Some(RunStatus::Failed)
    );
    let mut connection = pool.acquire().await?;
    let persisted: Option<String> =
        sqlx::query_scalar("SELECT failure_code FROM scheduler_job_runs WHERE job_id = $1")
            .bind(run.job_id().as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(persisted.as_deref(), Some("scheduled_handler_panic"));
    Ok(())
}

#[tokio::test]
async fn execution_gate_serializes_duplicates_and_enforces_schedule_concurrency() -> TestResult {
    let database = test_database().await?;
    let scheduler = PostgresScheduler::new(
        database.pool.clone(),
        scheduler_config("handler-replica", 2, 8),
    )?;
    let factory = TestFactory::default();
    let (actor, reason) = actor_reason()?;
    let schedule = scheduler
        .create_schedule(
            definition(
                "handler.schedule",
                "* * * * *",
                "UTC",
                MisfirePolicy::CatchUp {
                    max_runs: NonZeroU16::new(6).ok_or(SchedulerError::InvalidDefinition)?,
                },
                1,
                false,
            )?,
            &actor,
            &reason,
        )
        .await?;
    force_due(&database.pool, schedule.id(), 6).await?;
    let claims = scheduler.claim_due_schedules().await?;
    assert_eq!(
        scheduler.materialize_due(&claims[0], &factory).await?.len(),
        6
    );
    let runs = scheduler.claim_pending_runs().await?;
    assert_eq!(runs.len(), 6);
    for run in &runs {
        scheduler.mark_dispatched(run).await?;
    }
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let active = Arc::new(AtomicUsize::new(0));
    let maximum = Arc::new(AtomicUsize::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = Arc::new(ScheduledJobHandler::new(
        scheduler.clone(),
        BlockingHandler {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            active: Arc::clone(&active),
            maximum: Arc::clone(&maximum),
            calls: Arc::clone(&calls),
        },
    ));
    let first_envelope = runs[0].envelope().clone();
    let first_context = context(&first_envelope)?;
    let first_gate = Arc::clone(&gate);
    let first = tokio::spawn(async move { first_gate.handle(first_envelope, first_context).await });
    entered.notified().await;
    assert!(matches!(
        gate.handle(runs[0].envelope().clone(), context(runs[0].envelope())?)
            .await,
        HandlerOutcome::Retryable(_)
    ));
    assert!(matches!(
        gate.handle(runs[1].envelope().clone(), context(runs[1].envelope())?)
            .await,
        HandlerOutcome::Retryable(_)
    ));
    release.notify_one();
    assert_eq!(first.await?, HandlerOutcome::Succeeded);
    assert_eq!(maximum.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        gate.handle(runs[0].envelope().clone(), context(runs[0].envelope())?)
            .await,
        HandlerOutcome::Succeeded
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_terminal_gate_transitions(&scheduler, &runs).await?;
    assert_delivery_deadline_releases_execution(&scheduler, &runs[3]).await?;
    assert_panic_releases_execution(
        &scheduler,
        &database.pool,
        &runs[4],
        ConstructionPanicHandler,
    )
    .await?;
    assert_panic_releases_execution(&scheduler, &database.pool, &runs[5], PollPanicHandler).await?;
    cleanup(database).await
}

#[tokio::test]
async fn runtime_drain_stops_new_schedule_and_dispatch_leases() -> TestResult {
    let database = test_database().await?;
    let mut config = scheduler_config("drain-replica", 4, 4);
    config.enabled = true;
    config.poll_interval = Duration::from_secs(30);
    let scheduler = PostgresScheduler::new(database.pool.clone(), config)?;
    let factory = Arc::new(TestFactory::default());
    let enqueuer = Arc::new(AcceptingEnqueuer::default());
    let (actor, reason) = actor_reason()?;
    let schedule = scheduler
        .create_schedule(
            definition(
                "drain.schedule",
                "* * * * *",
                "UTC",
                MisfirePolicy::FireOnce,
                1,
                false,
            )?,
            &actor,
            &reason,
        )
        .await?;
    let mut supervisor = Supervisor::new();
    supervisor.register(
        scheduler
            .task(factory, enqueuer)
            .ok_or("enabled scheduler did not register task")?,
    )?;
    let handle = supervisor.start()?;
    handle.begin_drain();
    force_due(&database.pool, schedule.id(), 2).await?;
    let _report = handle.shutdown().await;
    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query("SELECT lease_token, (SELECT count(*) FROM scheduler_job_runs WHERE schedule_id = $1) AS runs FROM scheduler_schedules WHERE id = $1").bind(schedule.id().as_uuid()).fetch_one(&mut *connection).await?;
    assert!(row.try_get::<Option<Uuid>, _>("lease_token")?.is_none());
    assert_eq!(row.try_get::<i64, _>("runs")?, 0);
    cleanup(database).await
}
