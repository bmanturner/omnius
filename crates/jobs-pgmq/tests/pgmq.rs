//! Real PostgreSQL PGMQ provisioning, enqueue, worker, transaction, and retention contracts.

use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use pgmq::{PGMQueueExt, pg_ext::VisibilityTimeoutOffset};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EncodedJobEnvelope, EnqueueError,
    FailureCode, HandlerFailure, HandlerOutcome, IdempotencyRequirement, Jitter, Job,
    JobEnqueuer as _, JobEnqueuerExt as _, JobEnvelope, JobEnvelopeOptions, JobPolicy,
    TypedJobHandler,
};
use rsk_jobs_pgmq::{
    PgmqConnectError, PgmqJobConfig, PgmqJobDiagnostics, PgmqJobProvider, PgmqWorkerError,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Connection as _;
use time::OffsetDateTime;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
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
        application_name: "rsk-jobs-pgmq-test".to_owned(),
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
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

fn provider_config(cleanup_interval: Duration) -> TestResult<PgmqJobConfig> {
    Ok(PgmqJobConfig::new(
        Duration::from_secs(5),
        Duration::from_millis(20),
        Duration::from_secs(10),
        Duration::from_secs(2),
        cleanup_interval,
        8,
    )?)
}

const fn policy(
    queue: &'static str,
    attempts: u16,
    initial_backoff_ms: u64,
    maximum_backoff_ms: u64,
    jitter: Jitter,
    timeout_seconds: u32,
    retention_seconds: u64,
) -> JobPolicy {
    match JobPolicy::new(
        IdempotencyRequirement::Optional,
        attempts,
        initial_backoff_ms,
        maximum_backoff_ms,
        2,
        jitter,
        timeout_seconds,
        2,
        None,
        queue,
        2,
        retention_seconds,
        DeadLetterPolicy::Retain,
        CompatibilityPolicy::Exact,
        4_096,
    ) {
        Ok(policy) => policy,
        Err(_) => panic!("integration policy must be valid"),
    }
}

macro_rules! test_job {
    ($type:ident, $name:literal, $queue:literal, $attempts:literal, $initial:literal, $maximum:literal, $jitter:expr, $timeout:literal) => {
        #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
        struct $type {
            value: u32,
        }

        impl Job for $type {
            const NAME: &'static str = $name;
            const VERSION: u16 = 1;
            const POLICY: JobPolicy = policy(
                $queue, $attempts, $initial, $maximum, $jitter, $timeout, 3_600,
            );
            const METRICS_PREFIX: &'static str = $queue;
            const RUNBOOK: &'static str = concat!("runbooks/", $queue);
        }
    };
}

test_job!(
    SuccessJob,
    "pgmq.success",
    "success",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(WrongJob, "pgmq.wrong", "wrong", 3, 20, 40, Jitter::Full, 2);
test_job!(
    DelayedJob,
    "pgmq.delayed",
    "delayed",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(
    RetryJob,
    "pgmq.retry",
    "retry",
    3,
    100,
    200,
    Jitter::Equal,
    2
);
test_job!(
    TimeoutJob,
    "pgmq.timeout",
    "timeout",
    2,
    20,
    40,
    Jitter::Full,
    1
);
test_job!(
    PermanentJob,
    "pgmq.permanent",
    "permanent",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(
    PanicJob,
    "pgmq.panic",
    "panic_job",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(
    CancellationJob,
    "pgmq.cancel",
    "cancel",
    3,
    20,
    40,
    Jitter::Full,
    5
);
test_job!(AckJob, "pgmq.ack", "ack", 2, 20, 40, Jitter::Full, 2);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FlowJob {
    value: u32,
}

impl Job for FlowJob {
    const NAME: &'static str = "pgmq.flow";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = match JobPolicy::new(
        IdempotencyRequirement::Optional,
        2,
        20,
        40,
        2,
        Jitter::Full,
        2,
        2,
        Some(600),
        "flow",
        2,
        3_600,
        DeadLetterPolicy::Retain,
        CompatibilityPolicy::Exact,
        4_096,
    ) {
        Ok(policy) => policy,
        Err(_) => panic!("flow policy must be valid"),
    };
    const METRICS_PREFIX: &'static str = "flow";
    const RUNBOOK: &'static str = "runbooks/flow";
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RetentionJob {
    value: u32,
}

impl Job for RetentionJob {
    const NAME: &'static str = "pgmq.retention";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = policy("retention", 2, 20, 40, Jitter::Full, 2, 1);
    const METRICS_PREFIX: &'static str = "retention";
    const RUNBOOK: &'static str = "runbooks/retention";
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FenceJob {
    value: u32,
}

impl Job for FenceJob {
    const NAME: &'static str = "pgmq.fence";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = match JobPolicy::new(
        IdempotencyRequirement::Optional,
        3,
        20,
        40,
        2,
        Jitter::Full,
        2,
        1,
        None,
        "fence",
        2,
        3_600,
        DeadLetterPolicy::Retain,
        CompatibilityPolicy::Exact,
        4_096,
    ) {
        Ok(policy) => policy,
        Err(_) => panic!("fence policy must be valid"),
    };
    const METRICS_PREFIX: &'static str = "fence";
    const RUNBOOK: &'static str = "runbooks/fence";
}

fn envelope<J: Job>(payload: J, not_before: Option<OffsetDateTime>) -> TestResult<JobEnvelope<J>> {
    let mut options = JobEnvelopeOptions::new(Uuid::now_v7())?;
    if let Some(not_before) = not_before {
        options = options.with_not_before(not_before);
    }
    Ok(JobEnvelope::new(payload, options)?)
}

fn failure(code: &'static str) -> HandlerFailure {
    match FailureCode::try_from(code) {
        Ok(code) => HandlerFailure::new(code),
        Err(error) => panic!("invalid static failure code: {error}"),
    }
}

async fn provisioned_provider<J: Job>(
    database: &TestDatabase,
    config: PgmqJobConfig,
) -> TestResult<PgmqJobProvider<J>> {
    PgmqJobProvider::<J>::provision(&database.pool, &config).await?;
    Ok(PgmqJobProvider::<J>::connect(database.pool.clone(), config).await?)
}

async fn wait_for_diagnostics<J, F>(
    provider: &PgmqJobProvider<J>,
    maximum: Duration,
    predicate: F,
) -> TestResult<PgmqJobDiagnostics>
where
    J: Job,
    F: Fn(PgmqJobDiagnostics) -> bool,
{
    Ok(tokio::time::timeout(maximum, async {
        let mut interval = tokio::time::interval(Duration::from_millis(20));
        loop {
            interval.tick().await;
            let diagnostics = provider.diagnostics().await?;
            if predicate(diagnostics) {
                return Ok::<_, rsk_jobs_pgmq::PgmqDiagnosticsError>(diagnostics);
            }
        }
    })
    .await??)
}

async fn stop_worker(
    cancellation: CancellationToken,
    handle: JoinHandle<Result<(), PgmqWorkerError>>,
) -> TestResult {
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(4), handle).await???;
    Ok(())
}

async fn raw_queue_name(database: &TestDatabase, prefix: &str) -> TestResult<String> {
    let queue = PGMQueueExt::new_with_pool(database.pool.sqlx_pool()).await;
    Ok(queue
        .list_queues()
        .await?
        .unwrap_or_default()
        .into_iter()
        .find(|candidate| candidate.queue_name.starts_with(prefix))
        .ok_or("typed physical queue missing")?
        .queue_name)
}

async fn lease_newer_attempt(
    database: &TestDatabase,
    source: &str,
) -> TestResult<pgmq::Message<Value>> {
    sqlx::query(&format!(
        "UPDATE pgmq.q_{source} SET vt = clock_timestamp()"
    ))
    .execute(&database.pool.sqlx_pool())
    .await?;
    let queue = PGMQueueExt::new_with_pool(database.pool.sqlx_pool()).await;
    Ok(queue
        .read::<Value>(source, VisibilityTimeoutOffset::seconds(60))
        .await?
        .ok_or("newer lease missing")?)
}

async fn source_fence_state(
    database: &TestDatabase,
    source: &str,
) -> TestResult<(i32, bool, Value)> {
    Ok(sqlx::query_as::<_, (i32, bool, Value)>(&format!(
        "SELECT read_ct, vt > clock_timestamp() + interval '30 seconds', message \
         FROM pgmq.q_{source}"
    ))
    .fetch_one(&database.pool.sqlx_pool())
    .await?)
}

struct SuccessHandler {
    calls: Arc<AtomicUsize>,
    attempts: Arc<Mutex<Vec<u16>>>,
    completed: Arc<Notify>,
}

impl<J: Job> TypedJobHandler<J> for SuccessHandler {
    fn handle(&self, _job: J, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let calls = Arc::clone(&self.calls);
        let attempts = Arc::clone(&self.attempts);
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            if let Ok(mut attempts) = attempts.lock() {
                attempts.push(context.attempt().get());
            }
            completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

struct RetryHandler(Arc<Mutex<Vec<(u16, Instant)>>>);

impl TypedJobHandler<RetryJob> for RetryHandler {
    fn handle(&self, _job: RetryJob, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let attempts = Arc::clone(&self.0);
        Box::pin(async move {
            if let Ok(mut attempts) = attempts.lock() {
                attempts.push((context.attempt().get(), Instant::now()));
            }
            HandlerOutcome::Retryable(failure("transient"))
        })
    }
}

struct TimeoutHandler;

impl TypedJobHandler<TimeoutJob> for TimeoutHandler {
    fn handle(&self, _job: TimeoutJob, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            context.cancellation().cancelled().await;
            HandlerOutcome::Cancelled
        })
    }
}

struct PermanentThenSuccess(Arc<Notify>);

impl TypedJobHandler<PermanentJob> for PermanentThenSuccess {
    fn handle(
        &self,
        job: PermanentJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let completed = Arc::clone(&self.0);
        Box::pin(async move {
            if job.value == 1 {
                HandlerOutcome::Permanent(failure("permanent"))
            } else {
                completed.notify_one();
                HandlerOutcome::Succeeded
            }
        })
    }
}

struct PanicThenSuccess(Arc<Notify>);

impl TypedJobHandler<PanicJob> for PanicThenSuccess {
    fn handle(&self, job: PanicJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let completed = Arc::clone(&self.0);
        Box::pin(async move {
            assert_ne!(job.value, 1, "payload-bearing panic {}", job.value);
            completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

struct CancellingHandler(Arc<Notify>);

impl TypedJobHandler<CancellationJob> for CancellingHandler {
    fn handle(
        &self,
        _job: CancellationJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let started = Arc::clone(&self.0);
        Box::pin(async move {
            started.notify_one();
            context.cancellation().cancelled().await;
            HandlerOutcome::Cancelled
        })
    }
}

struct AckGateHandler {
    started: Arc<Notify>,
    release: Arc<Notify>,
}

impl TypedJobHandler<AckJob> for AckGateHandler {
    fn handle(&self, _job: AckJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let started = Arc::clone(&self.started);
        let release = Arc::clone(&self.release);
        Box::pin(async move {
            started.notify_one();
            release.notified().await;
            HandlerOutcome::Succeeded
        })
    }
}

#[derive(Clone, Copy)]
enum FencedOutcome {
    Succeeded,
    Retryable,
    Permanent,
}

struct FenceGateHandler {
    started: Arc<Notify>,
    release: Arc<Notify>,
    returned: Arc<Notify>,
    outcome: FencedOutcome,
}

impl<J: Job> TypedJobHandler<J> for FenceGateHandler {
    fn handle(&self, _job: J, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let started = Arc::clone(&self.started);
        let release = Arc::clone(&self.release);
        let returned = Arc::clone(&self.returned);
        let outcome = self.outcome;
        Box::pin(async move {
            started.notify_one();
            release.notified().await;
            returned.notify_one();
            match outcome {
                FencedOutcome::Succeeded => HandlerOutcome::Succeeded,
                FencedOutcome::Retryable => HandlerOutcome::Retryable(failure("fenced_retry")),
                FencedOutcome::Permanent => HandlerOutcome::Permanent(failure("fenced_terminal")),
            }
        })
    }
}

struct PanicOnDropFuture {
    cancellation: CancellationToken,
    cancelled_before_drop: Arc<AtomicUsize>,
}

impl Future for PanicOnDropFuture {
    type Output = HandlerOutcome;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PanicOnDropFuture {
    fn drop(&mut self) {
        self.cancelled_before_drop.store(
            usize::from(self.cancellation.is_cancelled()),
            Ordering::SeqCst,
        );
        panic!("payload-bearing handler destructor panic");
    }
}

struct PanicOnDropHandler(Arc<AtomicUsize>);

impl TypedJobHandler<TimeoutJob> for PanicOnDropHandler {
    fn handle(&self, _job: TimeoutJob, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(PanicOnDropFuture {
            cancellation: context.cancellation().clone(),
            cancelled_before_drop: Arc::clone(&self.0),
        })
    }
}

struct RetentionHandler;

impl TypedJobHandler<RetentionJob> for RetentionHandler {
    fn handle(
        &self,
        job: RetentionJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            if job.value == 1 {
                HandlerOutcome::Succeeded
            } else {
                HandlerOutcome::Permanent(failure("terminal"))
            }
        })
    }
}

struct FlowHandler {
    active: Arc<AtomicUsize>,
    maximum_active: Arc<AtomicUsize>,
    starts: Arc<Mutex<Vec<Instant>>>,
}

impl TypedJobHandler<FlowJob> for FlowHandler {
    fn handle(&self, _job: FlowJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let active = Arc::clone(&self.active);
        let maximum_active = Arc::clone(&self.maximum_active);
        let starts = Arc::clone(&self.starts);
        Box::pin(async move {
            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
            maximum_active.fetch_max(current, Ordering::SeqCst);
            if let Ok(mut starts) = starts.lock() {
                starts.push(Instant::now());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            active.fetch_sub(1, Ordering::SeqCst);
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn runtime_connect_is_verification_only() -> TestResult {
    let database = test_database().await?;
    let config = provider_config(Duration::from_secs(30))?;
    let before: bool = sqlx::query_scalar("SELECT to_regnamespace('pgmq') IS NOT NULL")
        .fetch_one(&database.pool.sqlx_pool())
        .await?;
    assert!(!before);

    let result =
        PgmqJobProvider::<SuccessJob>::connect(database.pool.clone(), config.clone()).await;
    assert!(matches!(result, Err(PgmqConnectError::Unavailable)));
    let after: bool = sqlx::query_scalar("SELECT to_regnamespace('pgmq') IS NOT NULL")
        .fetch_one(&database.pool.sqlx_pool())
        .await?;
    assert!(!after);

    PgmqJobProvider::<SuccessJob>::provision(&database.pool, &config).await?;
    PgmqJobProvider::<SuccessJob>::connect(database.pool.clone(), config).await?;
    Ok(())
}

#[tokio::test]
async fn provisioning_revokes_pg_monitor_payload_and_default_table_access() -> TestResult {
    let database = test_database().await?;
    let config = provider_config(Duration::from_secs(30))?;
    PgmqJobProvider::<SuccessJob>::provision(&database.pool, &config).await?;
    let source = raw_queue_name(&database, "j1_").await?;
    let dead = raw_queue_name(&database, "d1_").await?;
    sqlx::query("CREATE TABLE pgmq.rsk_acl_probe (payload jsonb)")
        .execute(&database.pool.sqlx_pool())
        .await?;
    let pg_monitor_can_select: bool = sqlx::query_scalar(
        "SELECT has_table_privilege('pg_monitor', $1::text, 'SELECT') \
             OR has_table_privilege('pg_monitor', $2::text, 'SELECT') \
             OR has_table_privilege('pg_monitor', $3::text, 'SELECT') \
             OR has_table_privilege('pg_monitor', $4::text, 'SELECT') \
             OR has_table_privilege('pg_monitor', 'pgmq.rsk_acl_probe', 'SELECT')",
    )
    .bind(format!("pgmq.q_{source}"))
    .bind(format!("pgmq.a_{source}"))
    .bind(format!("pgmq.q_{dead}"))
    .bind(format!("pgmq.a_{dead}"))
    .fetch_one(&database.pool.sqlx_pool())
    .await?;
    assert!(!pg_monitor_can_select);
    Ok(())
}

#[tokio::test]
async fn runtime_connect_rejects_pg_monitor_payload_access() -> TestResult {
    let database = test_database().await?;
    let config = provider_config(Duration::from_secs(30))?;
    PgmqJobProvider::<SuccessJob>::provision(&database.pool, &config).await?;
    let source = raw_queue_name(&database, "j1_").await?;
    sqlx::query(&format!(
        "GRANT SELECT ON TABLE pgmq.q_{source} TO pg_monitor"
    ))
    .execute(&database.pool.sqlx_pool())
    .await?;
    let result = PgmqJobProvider::<SuccessJob>::connect(database.pool.clone(), config).await;
    assert!(matches!(result, Err(PgmqConnectError::InsecurePermissions)));
    Ok(())
}

#[tokio::test]
async fn canonical_enqueue_process_and_mismatch_contract() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<SuccessJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    let canonical = envelope::<SuccessJob>(SuccessJob { value: 7 }, None)?;
    let encoded = canonical.encode()?;
    let receipt = provider.enqueue_typed(&canonical).await?;
    assert_eq!(receipt.job_id(), canonical.id());

    let source = raw_queue_name(&database, "j1_").await?;
    let rendered = format!("{provider:?}");
    assert!(!rendered.contains(&source));
    assert!(!rendered.contains("postgres://"));
    assert!(!rendered.contains("\"value\":7"));
    let stored: Value = sqlx::query_scalar(&format!(
        "SELECT message FROM pgmq.q_{source} ORDER BY msg_id LIMIT 1"
    ))
    .fetch_one(&database.pool.sqlx_pool())
    .await?;
    assert_eq!(stored, serde_json::from_slice::<Value>(encoded.bytes())?);
    let noncanonical = EncodedJobEnvelope::restore(
        &serde_json::to_vec_pretty(&stored)?,
        provider.definition().queue().clone(),
    )?;
    assert_eq!(
        provider.enqueue(noncanonical).await,
        Err(EnqueueError::InvalidEnvelope)
    );
    let wrong = envelope::<WrongJob>(WrongJob { value: 7 }, None)?.encode()?;
    assert_eq!(
        provider.enqueue(wrong.clone()).await,
        Err(EnqueueError::InvalidEnvelope)
    );
    let raw = PGMQueueExt::new_with_pool(database.pool.sqlx_pool()).await;
    raw.send(&source, &serde_json::from_slice::<Value>(wrong.bytes())?)
        .await?;

    let calls = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let completed = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                SuccessHandler {
                    calls: Arc::clone(&calls),
                    attempts: Arc::clone(&attempts),
                    completed: Arc::clone(&completed),
                },
                worker_cancellation,
            )
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1 && diagnostics.dead_total() == 1
    })
    .await?;
    stop_worker(cancellation, worker).await?;
    Ok(())
}

#[tokio::test]
async fn delayed_eligibility_rounds_up_to_a_whole_second() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<DelayedJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<DelayedJob>(
            DelayedJob { value: 1 },
            Some(OffsetDateTime::now_utc() + time::Duration::milliseconds(250)),
        )?)
        .await?;
    assert_eq!(provider.diagnostics().await?.source_visible(), 0);

    let completed = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let started = Instant::now();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                SuccessHandler {
                    calls: Arc::new(AtomicUsize::new(0)),
                    attempts: Arc::new(Mutex::new(Vec::new())),
                    completed,
                },
                worker_cancellation,
            )
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1
    })
    .await?;
    assert!(started.elapsed() >= Duration::from_millis(700));
    stop_worker(cancellation, worker).await
}

#[tokio::test]
async fn durable_read_count_retry_timing_and_max_attempts_dead_letter() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<RetryJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<RetryJob>(RetryJob { value: 1 }, None)?)
        .await?;
    let attempts = Arc::new(Mutex::new(Vec::new()));
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_attempts = Arc::clone(&attempts);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(RetryHandler(worker_attempts), worker_cancellation)
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(8), |diagnostics| {
        diagnostics.dead_total() == 1
    })
    .await?;
    stop_worker(cancellation, worker).await?;

    let attempts = attempts.lock().map_err(|_| "attempt lock poisoned")?;
    assert_eq!(
        attempts
            .iter()
            .map(|(attempt, _)| *attempt)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(attempts[1].1.duration_since(attempts[0].1) >= Duration::from_millis(850));
    assert!(attempts[2].1.duration_since(attempts[1].1) >= Duration::from_millis(850));
    Ok(())
}

#[tokio::test]
async fn timeout_permanent_and_panic_paths_remain_supervised() -> TestResult {
    let database = test_database().await?;
    let config = provider_config(Duration::from_secs(30))?;
    let timeout_provider = provisioned_provider::<TimeoutJob>(&database, config.clone()).await?;
    timeout_provider
        .enqueue_typed(&envelope::<TimeoutJob>(TimeoutJob { value: 1 }, None)?)
        .await?;
    let timeout_cancel = CancellationToken::new();
    let timeout_worker_provider = timeout_provider.clone();
    let timeout_worker_cancel = timeout_cancel.clone();
    let timeout_started = Instant::now();
    let timeout_worker = tokio::spawn(async move {
        timeout_worker_provider
            .run_worker(TimeoutHandler, timeout_worker_cancel)
            .await
    });
    wait_for_diagnostics(&timeout_provider, Duration::from_secs(8), |diagnostics| {
        diagnostics.dead_total() == 1
    })
    .await?;
    assert!(timeout_started.elapsed() >= Duration::from_secs(2));
    stop_worker(timeout_cancel, timeout_worker).await?;

    let permanent = provisioned_provider::<PermanentJob>(&database, config.clone()).await?;
    permanent
        .enqueue_typed(&envelope::<PermanentJob>(PermanentJob { value: 1 }, None)?)
        .await?;
    permanent
        .enqueue_typed(&envelope::<PermanentJob>(PermanentJob { value: 2 }, None)?)
        .await?;
    let permanent_completed = Arc::new(Notify::new());
    let permanent_cancel = CancellationToken::new();
    let permanent_worker_provider = permanent.clone();
    let permanent_worker_cancel = permanent_cancel.clone();
    let permanent_worker = tokio::spawn(async move {
        permanent_worker_provider
            .run_worker(
                PermanentThenSuccess(permanent_completed),
                permanent_worker_cancel,
            )
            .await
    });
    wait_for_diagnostics(&permanent, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1 && diagnostics.dead_total() == 1
    })
    .await?;
    stop_worker(permanent_cancel, permanent_worker).await?;

    let panicking = provisioned_provider::<PanicJob>(&database, config).await?;
    panicking
        .enqueue_typed(&envelope::<PanicJob>(PanicJob { value: 1 }, None)?)
        .await?;
    panicking
        .enqueue_typed(&envelope::<PanicJob>(PanicJob { value: 2 }, None)?)
        .await?;
    let panic_cancel = CancellationToken::new();
    let panic_worker_provider = panicking.clone();
    let panic_worker_cancel = panic_cancel.clone();
    let panic_worker = tokio::spawn(async move {
        panic_worker_provider
            .run_worker(
                PanicThenSuccess(Arc::new(Notify::new())),
                panic_worker_cancel,
            )
            .await
    });
    wait_for_diagnostics(&panicking, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1 && diagnostics.dead_total() == 1
    })
    .await?;
    stop_worker(panic_cancel, panic_worker).await
}

#[tokio::test]
async fn timed_out_handler_destructor_panic_is_cancelled_and_terminal() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<TimeoutJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<TimeoutJob>(TimeoutJob { value: 9 }, None)?)
        .await?;
    let cancelled_before_drop = Arc::new(AtomicUsize::new(0));
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let handler_state = Arc::clone(&cancelled_before_drop);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(PanicOnDropHandler(handler_state), worker_cancellation)
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.dead_total() == 1
    })
    .await?;
    assert_eq!(cancelled_before_drop.load(Ordering::SeqCst), 1);
    stop_worker(cancellation, worker).await
}

#[tokio::test]
async fn cancellation_drain_and_restart_redelivery_contract() -> TestResult {
    let database = test_database().await?;
    let provider = provisioned_provider::<CancellationJob>(
        &database,
        provider_config(Duration::from_secs(30))?,
    )
    .await?;
    provider
        .enqueue_typed(&envelope::<CancellationJob>(
            CancellationJob { value: 1 },
            None,
        )?)
        .await?;
    let started = Arc::new(Notify::new());
    let first_cancel = CancellationToken::new();
    let first_worker_provider = provider.clone();
    let first_worker_cancel = first_cancel.clone();
    let first_worker_started = Arc::clone(&started);
    let first_worker = tokio::spawn(async move {
        first_worker_provider
            .run_worker(CancellingHandler(first_worker_started), first_worker_cancel)
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    stop_worker(first_cancel, first_worker).await?;

    let attempts = Arc::new(Mutex::new(Vec::new()));
    let second_cancel = CancellationToken::new();
    let second_worker_provider = provider.clone();
    let second_worker_cancel = second_cancel.clone();
    let second_worker_attempts = Arc::clone(&attempts);
    let second_worker = tokio::spawn(async move {
        second_worker_provider
            .run_worker(
                SuccessHandler {
                    calls: Arc::new(AtomicUsize::new(0)),
                    attempts: second_worker_attempts,
                    completed: Arc::new(Notify::new()),
                },
                second_worker_cancel,
            )
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1
    })
    .await?;
    stop_worker(second_cancel, second_worker).await?;
    assert_eq!(
        *attempts.lock().map_err(|_| "attempt lock poisoned")?,
        vec![2]
    );
    Ok(())
}

#[tokio::test]
async fn transactional_rollback_commit_and_diagnostics_contract() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<SuccessJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    let mut connection = database.pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    provider
        .enqueue_with(
            &mut transaction,
            envelope::<SuccessJob>(SuccessJob { value: 1 }, None)?.encode()?,
        )
        .await?;
    transaction.rollback().await?;
    assert_eq!(provider.diagnostics().await?.source_total(), 0);

    let encoded = envelope::<SuccessJob>(SuccessJob { value: 2 }, None)?.encode()?;
    let expected_id = encoded.id();
    let mut transaction = connection.begin().await?;
    let staged_id = provider.enqueue_with(&mut transaction, encoded).await?;
    transaction.commit().await?;
    assert_eq!(staged_id, expected_id);
    assert_eq!(provider.diagnostics().await?.source_total(), 1);
    Ok(())
}

#[tokio::test]
async fn automatic_retention_preserves_live_source_and_leased_dead_records() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<RetentionJob>(&database, provider_config(Duration::from_mins(5))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<RetentionJob>(RetentionJob { value: 1 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<RetentionJob>(RetentionJob { value: 2 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<RetentionJob>(RetentionJob { value: 4 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<RetentionJob>(
            RetentionJob { value: 3 },
            Some(OffsetDateTime::now_utc() + time::Duration::minutes(1)),
        )?)
        .await?;
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(RetentionHandler, worker_cancellation)
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 1 && diagnostics.dead_total() == 2
    })
    .await?;
    stop_worker(cancellation, worker).await?;

    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let raw = PGMQueueExt::new_with_pool(database.pool.sqlx_pool()).await;
    let dead = raw_queue_name(&database, "d1_").await?;
    assert!(raw.read::<Value>(&dead, 30).await?.is_some());

    let cleanup_provider = PgmqJobProvider::<RetentionJob>::connect(
        database.pool.clone(),
        provider_config(Duration::from_millis(20))?,
    )
    .await?;
    let cleanup_cancel = CancellationToken::new();
    let cleanup_worker_provider = cleanup_provider.clone();
    let cleanup_worker_cancel = cleanup_cancel.clone();
    let cleanup_worker = tokio::spawn(async move {
        cleanup_worker_provider
            .run_worker(RetentionHandler, cleanup_worker_cancel)
            .await
    });
    wait_for_diagnostics(&cleanup_provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 0
    })
    .await?;
    let diagnostics = cleanup_provider.diagnostics().await?;
    assert_eq!(diagnostics.dead_total(), 1);
    assert_eq!(diagnostics.dead_visible(), 0);
    assert_eq!(diagnostics.source_total(), 1);
    stop_worker(cleanup_cancel, cleanup_worker).await
}

#[tokio::test]
async fn stale_success_cannot_archive_newer_delivery() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<FenceJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<FenceJob>(FenceJob { value: 1 }, None)?)
        .await?;
    let source = raw_queue_name(&database, "j1_").await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let returned = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_started = Arc::clone(&started);
    let worker_release = Arc::clone(&release);
    let worker_returned = Arc::clone(&returned);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                FenceGateHandler {
                    started: worker_started,
                    release: worker_release,
                    returned: worker_returned,
                    outcome: FencedOutcome::Succeeded,
                },
                worker_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    let newer = lease_newer_attempt(&database, &source).await?;
    assert_eq!(newer.read_ct, 2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(4), returned.notified()).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop_worker(cancellation, worker).await?;
    assert_eq!(
        source_fence_state(&database, &source).await?,
        (2, true, newer.message)
    );
    assert_eq!(provider.diagnostics().await?.completed(), 0);
    Ok(())
}

#[tokio::test]
async fn stale_retry_cannot_reschedule_newer_delivery() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<FenceJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<FenceJob>(FenceJob { value: 1 }, None)?)
        .await?;
    let source = raw_queue_name(&database, "j1_").await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let returned = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_started = Arc::clone(&started);
    let worker_release = Arc::clone(&release);
    let worker_returned = Arc::clone(&returned);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                FenceGateHandler {
                    started: worker_started,
                    release: worker_release,
                    returned: worker_returned,
                    outcome: FencedOutcome::Retryable,
                },
                worker_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    let newer = lease_newer_attempt(&database, &source).await?;
    assert_eq!(newer.read_ct, 2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(4), returned.notified()).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop_worker(cancellation, worker).await?;
    assert_eq!(
        source_fence_state(&database, &source).await?,
        (2, true, newer.message)
    );
    Ok(())
}

#[tokio::test]
async fn stale_terminal_outcome_cannot_delete_or_dead_letter_newer_delivery() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<FenceJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<FenceJob>(FenceJob { value: 1 }, None)?)
        .await?;
    let source = raw_queue_name(&database, "j1_").await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let returned = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_started = Arc::clone(&started);
    let worker_release = Arc::clone(&release);
    let worker_returned = Arc::clone(&returned);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                FenceGateHandler {
                    started: worker_started,
                    release: worker_release,
                    returned: worker_returned,
                    outcome: FencedOutcome::Permanent,
                },
                worker_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    let newer = lease_newer_attempt(&database, &source).await?;
    assert_eq!(newer.read_ct, 2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(4), returned.notified()).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop_worker(cancellation, worker).await?;
    assert_eq!(
        source_fence_state(&database, &source).await?,
        (2, true, newer.message)
    );
    assert_eq!(provider.diagnostics().await?.dead_total(), 0);
    Ok(())
}

#[tokio::test]
async fn client_timeout_cannot_archive_after_a_server_lock_wait() -> TestResult {
    let database = test_database().await?;
    let provisioning_config = provider_config(Duration::from_secs(30))?;
    PgmqJobProvider::<AckJob>::provision(&database.pool, &provisioning_config).await?;
    let runtime_config = PgmqJobConfig::new(
        Duration::from_millis(200),
        Duration::from_millis(20),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(30),
        8,
    )?;
    let provider =
        PgmqJobProvider::<AckJob>::connect(database.pool.clone(), runtime_config).await?;
    provider
        .enqueue_typed(&envelope::<AckJob>(AckJob { value: 1 }, None)?)
        .await?;
    let source = raw_queue_name(&database, "j1_").await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let returned = Arc::new(Notify::new());
    let worker_provider = provider.clone();
    let worker_started = Arc::clone(&started);
    let worker_release = Arc::clone(&release);
    let worker_returned = Arc::clone(&returned);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                FenceGateHandler {
                    started: worker_started,
                    release: worker_release,
                    returned: worker_returned,
                    outcome: FencedOutcome::Succeeded,
                },
                CancellationToken::new(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    let pool = database.pool.sqlx_pool();
    let mut blocker = pool.begin().await?;
    sqlx::query(&format!("SELECT msg_id FROM pgmq.q_{source} FOR UPDATE"))
        .fetch_one(&mut *blocker)
        .await?;
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(4), returned.notified()).await?;
    let result = tokio::time::timeout(Duration::from_secs(2), worker).await??;
    assert_eq!(result, Err(PgmqWorkerError::Runtime));
    blocker.rollback().await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let diagnostics = provider.diagnostics().await?;
    assert_eq!(diagnostics.source_total(), 1);
    assert_eq!(diagnostics.completed(), 0);
    Ok(())
}

#[tokio::test]
async fn acknowledgement_failure_stops_worker_without_deleting_source() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<AckJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<AckJob>(AckJob { value: 1 }, None)?)
        .await?;
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_started = Arc::clone(&started);
    let worker_release = Arc::clone(&release);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                AckGateHandler {
                    started: worker_started,
                    release: worker_release,
                },
                worker_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), started.notified()).await?;
    database.pool.close().await?;
    release.notify_one();
    let result = tokio::time::timeout(Duration::from_secs(4), worker).await??;
    assert_eq!(result, Err(PgmqWorkerError::Runtime));
    Ok(())
}

#[tokio::test]
async fn local_worker_enforces_concurrency_and_smoothed_start_rate() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<FlowJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    provider
        .enqueue_typed(&envelope::<FlowJob>(FlowJob { value: 1 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<FlowJob>(FlowJob { value: 2 }, None)?)
        .await?;
    let active = Arc::new(AtomicUsize::new(0));
    let maximum_active = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(Mutex::new(Vec::new()));
    let cancellation = CancellationToken::new();
    let worker_provider = provider.clone();
    let worker_cancellation = cancellation.clone();
    let worker_active = Arc::clone(&active);
    let worker_maximum = Arc::clone(&maximum_active);
    let worker_starts = Arc::clone(&starts);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                FlowHandler {
                    active: worker_active,
                    maximum_active: worker_maximum,
                    starts: worker_starts,
                },
                worker_cancellation,
            )
            .await
    });
    wait_for_diagnostics(&provider, Duration::from_secs(4), |diagnostics| {
        diagnostics.completed() == 2
    })
    .await?;
    stop_worker(cancellation, worker).await?;
    let starts = starts.lock().map_err(|_| "start lock poisoned")?;
    assert_eq!(starts.len(), 2);
    assert!(starts[1].duration_since(starts[0]) >= Duration::from_millis(80));
    assert_eq!(maximum_active.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn terminal_send_rolls_back_when_source_delete_fails() -> TestResult {
    let database = test_database().await?;
    let provider =
        provisioned_provider::<PermanentJob>(&database, provider_config(Duration::from_secs(30))?)
            .await?;
    let source = raw_queue_name(&database, "j1_").await?;
    sqlx::query(
        "CREATE FUNCTION public.rsk_pgmq_fail_delete()
         RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN
             RAISE EXCEPTION 'forced terminal delete failure';
             RETURN OLD;
         END
         $$",
    )
    .execute(&database.pool.sqlx_pool())
    .await?;
    sqlx::query(&format!(
        "CREATE TRIGGER rsk_pgmq_fail_delete
         BEFORE DELETE ON pgmq.q_{source}
         FOR EACH ROW EXECUTE FUNCTION public.rsk_pgmq_fail_delete()"
    ))
    .execute(&database.pool.sqlx_pool())
    .await?;
    provider
        .enqueue_typed(&envelope::<PermanentJob>(PermanentJob { value: 1 }, None)?)
        .await?;
    let worker_provider = provider.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                PermanentThenSuccess(Arc::new(Notify::new())),
                CancellationToken::new(),
            )
            .await
    });
    let result = tokio::time::timeout(Duration::from_secs(4), worker).await??;
    assert_eq!(result, Err(PgmqWorkerError::Runtime));
    let diagnostics = provider.diagnostics().await?;
    assert_eq!(diagnostics.source_total(), 1);
    assert_eq!(diagnostics.dead_total(), 0);
    Ok(())
}
