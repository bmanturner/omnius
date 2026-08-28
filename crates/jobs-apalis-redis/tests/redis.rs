//! Real Redis conformance tests for durable typed job delivery.

use std::{
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use omnius_config::ExposeSecret as _;
use omnius_jobs_apalis_redis::{
    JobDiagnostics, RedisAdminError, RedisJobConfig, RedisJobProvider, RedisReplayIdentity,
};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EnqueueError, FailureCode,
    HandlerFailure, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuerExt as _,
    JobEnvelope, JobEnvelopeOptions, JobId, JobPolicy, TypedJobHandler,
};
use omnius_test_support::RedisFixture;
use redis_apalis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::{sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const fn policy(
    queue: &'static str,
    max_attempts: u16,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    jitter: Jitter,
    timeout_seconds: u32,
) -> JobPolicy {
    policy_with_retention(
        queue,
        max_attempts,
        initial_backoff_ms,
        max_backoff_ms,
        jitter,
        timeout_seconds,
        2,
        3_600,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture keeps every changed retry and retention dimension explicit"
)]
const fn policy_with_retention(
    queue: &'static str,
    max_attempts: u16,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    jitter: Jitter,
    timeout_seconds: u32,
    max_concurrency: u16,
    retention_seconds: u64,
) -> JobPolicy {
    match JobPolicy::new(
        IdempotencyRequirement::Optional,
        max_attempts,
        initial_backoff_ms,
        max_backoff_ms,
        2,
        jitter,
        timeout_seconds,
        max_concurrency,
        None,
        queue,
        3,
        retention_seconds,
        DeadLetterPolicy::Retain,
        CompatibilityPolicy::Exact,
        4_096,
    ) {
        Ok(policy) => policy,
        Err(_) => panic!("integration test policy must be valid"),
    }
}

macro_rules! test_job {
    ($type:ident, $name:literal, $queue:literal, $attempts:literal, $initial:literal, $maximum:literal, $jitter:expr, $timeout:literal) => {
        #[derive(Clone, Deserialize, Serialize)]
        struct $type {
            value: u32,
        }

        impl Job for $type {
            const NAME: &'static str = $name;
            const VERSION: u16 = 1;
            const POLICY: JobPolicy =
                policy($queue, $attempts, $initial, $maximum, $jitter, $timeout);
            const METRICS_PREFIX: &'static str = $queue;
            const RUNBOOK: &'static str = concat!("runbooks/", $queue);
        }
    };
}

test_job!(
    SuccessJob,
    "integration.success",
    "success",
    3,
    20,
    100,
    Jitter::Full,
    2
);
test_job!(
    WrongJob,
    "integration.wrong",
    "wrong",
    3,
    20,
    100,
    Jitter::Full,
    2
);
test_job!(
    ScheduledJob,
    "integration.scheduled",
    "scheduled",
    3,
    20,
    100,
    Jitter::Full,
    2
);
test_job!(
    RetryJob,
    "integration.retry",
    "retry",
    3,
    120,
    240,
    Jitter::Equal,
    2
);
test_job!(
    TimeoutJob,
    "integration.timeout",
    "timeout",
    2,
    20,
    40,
    Jitter::Equal,
    1
);
test_job!(
    PermanentJob,
    "integration.permanent",
    "permanent",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(
    CancellationJob,
    "integration.cancellation",
    "cancellation",
    3,
    20,
    40,
    Jitter::Full,
    5
);

test_job!(
    PanicJob,
    "integration.panic",
    "panic_job",
    3,
    20,
    40,
    Jitter::Full,
    2
);
test_job!(
    PauseDrainJob,
    "integration.pause_drain",
    "pause_drain",
    3,
    20,
    40,
    Jitter::Full,
    5
);

#[derive(Clone, Deserialize, Serialize)]
struct SensitiveAdminJob {
    secret: String,
}

impl Job for SensitiveAdminJob {
    const NAME: &'static str = "integration.sensitive_admin";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = policy("sensitive_admin", 3, 20, 40, Jitter::Full, 2);
    const METRICS_PREFIX: &'static str = "sensitive_admin";
    const RUNBOOK: &'static str = "runbooks/sensitive-admin";
}

#[derive(Clone, Deserialize, Serialize)]
struct CleanupJob {
    value: u32,
}

impl Job for CleanupJob {
    const NAME: &'static str = "integration.cleanup";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = policy_with_retention("cleanup", 2, 20, 40, Jitter::Full, 10, 1, 1);
    const METRICS_PREFIX: &'static str = "cleanup";
    const RUNBOOK: &'static str = "runbooks/cleanup";
}

fn config(fixture: &RedisFixture) -> RedisJobConfig {
    RedisJobConfig::new(fixture.redis_url().clone())
        .with_namespace_prefix(format!("{}jobs", fixture.namespace().trim_end_matches(':')))
        .with_poll_interval(Duration::from_millis(20))
        .with_scheduled_poll_interval(Duration::from_millis(20))
        .with_orphan_recovery(Duration::from_millis(100), Duration::from_secs(2))
        .with_buffer_size(1)
        .with_operation_timeout(Duration::from_millis(500))
        .with_shutdown_timeout(Duration::from_secs(1))
}

fn envelope<J: Job>(payload: J, not_before: Option<OffsetDateTime>) -> TestResult<JobEnvelope<J>> {
    let mut options = JobEnvelopeOptions::new(Uuid::now_v7())?;
    if let Some(value) = not_before {
        options = options.with_not_before(value);
    }
    Ok(JobEnvelope::new(payload, options)?)
}

fn failure(code: &'static str) -> HandlerFailure {
    match FailureCode::try_from(code) {
        Ok(code) => HandlerFailure::new(code),
        Err(error) => panic!("invalid static test failure code: {error}"),
    }
}

async fn raw_connection(fixture: &RedisFixture) -> TestResult<ConnectionManager> {
    let client = redis_apalis::Client::open(fixture.redis_url().expose_secret())?;
    Ok(client.get_connection_manager().await?)
}

async fn wait_for_diagnostics<J, F>(
    provider: &RedisJobProvider<J>,
    maximum: Duration,
    predicate: F,
) -> TestResult<JobDiagnostics>
where
    J: Job,
    F: Fn(JobDiagnostics) -> bool,
{
    let result = tokio::time::timeout(maximum, async {
        let mut poll = tokio::time::interval(Duration::from_millis(20));
        loop {
            poll.tick().await;
            let diagnostics = provider.diagnostics().await?;
            if predicate(diagnostics) {
                return Ok::<_, omnius_jobs_apalis_redis::JobDiagnosticsError>(diagnostics);
            }
        }
    })
    .await??;
    Ok(result)
}

async fn stop_worker(
    cancellation: CancellationToken,
    handle: JoinHandle<Result<(), omnius_jobs_apalis_redis::RedisJobWorkerError>>,
) -> TestResult {
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), handle).await???;
    Ok(())
}

struct SuccessHandler {
    calls: Arc<AtomicUsize>,
    attempt: Arc<AtomicU16>,
    job_id: Arc<Mutex<Option<JobId>>>,
    completed: Arc<Notify>,
}

impl TypedJobHandler<SuccessJob> for SuccessHandler {
    fn handle(&self, _job: SuccessJob, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let calls = Arc::clone(&self.calls);
        let attempt = Arc::clone(&self.attempt);
        let job_id = Arc::clone(&self.job_id);
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            attempt.store(context.attempt().get(), Ordering::SeqCst);
            if let Ok(mut observed) = job_id.lock() {
                *observed = Some(context.effect_identity().job_id());
            }
            completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn enqueue_processes_canonical_envelope_and_rejects_another_definition() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let attempt = Arc::new(AtomicU16::new(0));
    let observed_id = Arc::new(Mutex::new(None));
    let completed = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker = tokio::spawn({
        let calls = Arc::clone(&calls);
        let attempt = Arc::clone(&attempt);
        let observed_id = Arc::clone(&observed_id);
        let completed = Arc::clone(&completed);
        async move {
            worker_provider
                .run_worker(
                    "success-worker",
                    SuccessHandler {
                        calls,
                        attempt,
                        job_id: observed_id,
                        completed,
                    },
                    run_cancellation,
                )
                .await
        }
    });

    let job = envelope::<SuccessJob>(SuccessJob { value: 42 }, None)?;
    let expected_id = job.id();
    let receipt = provider.enqueue_typed(&job).await?;
    assert_eq!(receipt.job_id(), expected_id);
    assert_eq!(receipt.queue().as_str(), "success");
    tokio::time::timeout(Duration::from_secs(3), completed.notified()).await?;

    let wrong = envelope::<WrongJob>(WrongJob { value: 7 }, None)?;
    assert_eq!(
        provider.enqueue_typed(&wrong).await,
        Err(EnqueueError::InvalidEnvelope)
    );
    let diagnostics = wait_for_diagnostics(&provider, Duration::from_secs(2), |value| {
        value.completed() == 1
    })
    .await?;
    assert_eq!(diagnostics.dead_lettered(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(attempt.load(Ordering::SeqCst), 1);
    let actual_id = observed_id.lock().ok().and_then(|value| *value);
    assert_eq!(actual_id, Some(expected_id));

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct IdleHandler;

impl TypedJobHandler<SuccessJob> for IdleHandler {
    fn handle(&self, _job: SuccessJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async { HandlerOutcome::Succeeded })
    }
}

#[tokio::test]
async fn same_logical_name_registers_unique_physical_workers() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let first_cancellation = CancellationToken::new();
    let second_cancellation = CancellationToken::new();
    let first_provider = provider.clone();
    let second_provider = provider.clone();
    let first_run_cancellation = first_cancellation.clone();
    let second_run_cancellation = second_cancellation.clone();
    let first = tokio::spawn(async move {
        first_provider
            .run_worker("shared-logical-worker", IdleHandler, first_run_cancellation)
            .await
    });
    let second = tokio::spawn(async move {
        second_provider
            .run_worker(
                "shared-logical-worker",
                IdleHandler,
                second_run_cancellation,
            )
            .await
    });
    let mut connection = raw_connection(&fixture).await?;
    let consumers_key = format!("{}:consumers", provider.definition().namespace());
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let count: u64 = redis_apalis::cmd("ZCARD")
                .arg(&consumers_key)
                .query_async(&mut connection)
                .await?;
            if count == 2 {
                return Ok::<(), redis_apalis::RedisError>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;

    stop_worker(first_cancellation, first).await?;
    stop_worker(second_cancellation, second).await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn enqueue_returns_unavailable_within_operation_timeout() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let timeout_config = config(&fixture).with_operation_timeout(Duration::from_millis(50));
    let provider = RedisJobProvider::<SuccessJob>::connect(&timeout_config).await?;
    let mut connection = raw_connection(&fixture).await?;
    let _: String = redis_apalis::cmd("CLIENT")
        .arg("PAUSE")
        .arg(500)
        .arg("ALL")
        .query_async(&mut connection)
        .await?;
    let started = Instant::now();
    let result = provider
        .enqueue_typed(&envelope::<SuccessJob>(SuccessJob { value: 1 }, None)?)
        .await;
    assert_eq!(result, Err(EnqueueError::Unavailable));
    assert!(started.elapsed() < Duration::from_millis(300));

    tokio::time::sleep(Duration::from_millis(600)).await;
    fixture.cleanup().await?;
    Ok(())
}

struct ScheduledHandler {
    called: Arc<Notify>,
}

impl TypedJobHandler<ScheduledJob> for ScheduledHandler {
    fn handle(
        &self,
        _job: ScheduledJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let called = Arc::clone(&self.called);
        Box::pin(async move {
            called.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn scheduled_job_is_not_delivered_before_eligibility() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<ScheduledJob>::connect(&config(&fixture)).await?;
    let called = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_called = Arc::clone(&called);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "scheduled-worker",
                ScheduledHandler {
                    called: worker_called,
                },
                run_cancellation,
            )
            .await
    });
    let eligible_at = OffsetDateTime::now_utc() + time::Duration::milliseconds(800);
    provider
        .enqueue_typed(&envelope::<ScheduledJob>(
            ScheduledJob { value: 1 },
            Some(eligible_at),
        )?)
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), called.notified())
            .await
            .is_err()
    );
    tokio::time::timeout(Duration::from_secs(3), called.notified()).await?;
    wait_for_diagnostics(&provider, Duration::from_secs(2), |value| {
        value.completed() == 1
    })
    .await?;

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct RetryHandler {
    starts: Arc<Mutex<Vec<Instant>>>,
    final_attempt: Arc<Notify>,
}

impl TypedJobHandler<RetryJob> for RetryHandler {
    fn handle(&self, _job: RetryJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let starts = Arc::clone(&self.starts);
        let final_attempt = Arc::clone(&self.final_attempt);
        Box::pin(async move {
            let attempt = if let Ok(mut values) = starts.lock() {
                values.push(Instant::now());
                values.len()
            } else {
                0
            };
            if attempt == 3 {
                final_attempt.notify_one();
            }
            HandlerOutcome::Retryable(failure("transient"))
        })
    }
}

#[tokio::test]
async fn retries_use_equal_jitter_stop_at_maximum_and_retain_dead_letter() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<RetryJob>::connect(&config(&fixture)).await?;
    let starts = Arc::new(Mutex::new(Vec::new()));
    let final_attempt = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_starts = Arc::clone(&starts);
    let worker_final = Arc::clone(&final_attempt);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "retry-worker",
                RetryHandler {
                    starts: worker_starts,
                    final_attempt: worker_final,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<RetryJob>(RetryJob { value: 1 }, None)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(4), final_attempt.notified()).await?;
    let diagnostics = wait_for_diagnostics(&provider, Duration::from_secs(2), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    assert_eq!(diagnostics.completed(), 0);
    {
        let recorded = starts
            .lock()
            .map_err(|_| std::io::Error::other("retry timestamps poisoned"))?;
        assert_eq!(recorded.len(), 3);
        assert!(recorded[1].duration_since(recorded[0]) >= Duration::from_millis(55));
        assert!(recorded[2].duration_since(recorded[1]) >= Duration::from_millis(110));
    }

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct TimeoutHandler {
    calls: Arc<AtomicUsize>,
}

impl TypedJobHandler<TimeoutJob> for TimeoutHandler {
    fn handle(&self, _job: TimeoutJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            futures::future::pending::<HandlerOutcome>().await
        })
    }
}

#[tokio::test]
async fn timed_out_attempts_retry_then_dead_letter() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<TimeoutJob>::connect(&config(&fixture)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_calls = Arc::clone(&calls);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "timeout-worker",
                TimeoutHandler {
                    calls: worker_calls,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<TimeoutJob>(TimeoutJob { value: 1 }, None)?)
        .await?;
    wait_for_diagnostics(&provider, Duration::from_secs(5), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct PermanentHandler {
    calls: Arc<AtomicUsize>,
}

impl TypedJobHandler<PermanentJob> for PermanentHandler {
    fn handle(
        &self,
        _job: PermanentJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let calls = Arc::clone(&self.calls);
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            HandlerOutcome::Permanent(failure("permanent"))
        })
    }
}

#[tokio::test]
async fn permanent_failure_dead_letters_without_retry() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<PermanentJob>::connect(&config(&fixture)).await?;
    let calls = Arc::new(AtomicUsize::new(0));
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_calls = Arc::clone(&calls);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "permanent-worker",
                PermanentHandler {
                    calls: worker_calls,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<PermanentJob>(PermanentJob { value: 1 }, None)?)
        .await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct PanicHandler {
    following_completed: Arc<Notify>,
}

impl TypedJobHandler<PanicJob> for PanicHandler {
    fn handle(&self, job: PanicJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let following_completed = Arc::clone(&self.following_completed);
        Box::pin(async move {
            assert_ne!(job.value, 1, "intentional handler panic");
            following_completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn handler_panic_is_terminal_and_following_job_still_runs() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<PanicJob>::connect(&config(&fixture)).await?;
    let following_completed = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_completed = Arc::clone(&following_completed);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "panic-worker",
                PanicHandler {
                    following_completed: worker_completed,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<PanicJob>(PanicJob { value: 1 }, None)?)
        .await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    provider
        .enqueue_typed(&envelope::<PanicJob>(PanicJob { value: 2 }, None)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), following_completed.notified()).await?;
    let diagnostics = wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.completed() == 1
    })
    .await?;
    assert_eq!(diagnostics.dead_lettered(), 1);

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

struct CancellationHandler {
    started: Arc<Notify>,
    attempt: Arc<AtomicU16>,
    finished: Arc<AtomicBool>,
}

impl TypedJobHandler<CancellationJob> for CancellationHandler {
    fn handle(
        &self,
        _job: CancellationJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let started = Arc::clone(&self.started);
        let attempt = Arc::clone(&self.attempt);
        let finished = Arc::clone(&self.finished);
        Box::pin(async move {
            attempt.store(context.attempt().get(), Ordering::SeqCst);
            started.notify_one();
            context.cancellation().cancelled().await;
            tokio::time::sleep(Duration::from_millis(100)).await;
            finished.store(true, Ordering::SeqCst);
            HandlerOutcome::Cancelled
        })
    }
}

struct CancellationRecoveryHandler {
    attempt: Arc<AtomicU16>,
    completed: Arc<Notify>,
}

impl TypedJobHandler<CancellationJob> for CancellationRecoveryHandler {
    fn handle(
        &self,
        _job: CancellationJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let attempt = Arc::clone(&self.attempt);
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            attempt.store(context.attempt().get(), Ordering::SeqCst);
            completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn cancellation_reaches_handler_and_worker_drains_within_bound() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<CancellationJob>::connect(&config(&fixture)).await?;
    let started = Arc::new(Notify::new());
    let finished = Arc::new(AtomicBool::new(false));
    let first_attempt = Arc::new(AtomicU16::new(0));
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_started = Arc::clone(&started);
    let worker_finished = Arc::clone(&finished);
    let worker_attempt = Arc::clone(&first_attempt);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "cancellation-worker",
                CancellationHandler {
                    started: worker_started,
                    finished: worker_finished,
                    attempt: worker_attempt,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<CancellationJob>(
            CancellationJob { value: 1 },
            None,
        )?)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), started.notified()).await?;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    stop_worker(cancellation, worker).await?;
    assert!(finished.load(Ordering::SeqCst));
    assert_eq!(first_attempt.load(Ordering::SeqCst), 1);
    let recovered_attempt = Arc::new(AtomicU16::new(0));
    let recovered = Arc::new(Notify::new());
    let replacement_cancellation = CancellationToken::new();
    let run_replacement_cancellation = replacement_cancellation.clone();
    let replacement_provider = provider.clone();
    let replacement_attempt = Arc::clone(&recovered_attempt);
    let replacement_completed = Arc::clone(&recovered);
    let replacement = tokio::spawn(async move {
        replacement_provider
            .run_worker(
                "cancellation-recovery-worker",
                CancellationRecoveryHandler {
                    attempt: replacement_attempt,
                    completed: replacement_completed,
                },
                run_replacement_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), recovered.notified()).await?;
    let diagnostics = wait_for_diagnostics(&provider, Duration::from_secs(2), |value| {
        value.completed() == 1
    })
    .await?;
    assert_eq!(recovered_attempt.load(Ordering::SeqCst), 2);
    assert_eq!(diagnostics.dead_lettered(), 0);
    stop_worker(replacement_cancellation, replacement).await?;

    fixture.cleanup().await?;
    Ok(())
}

struct CleanupHandler {
    held_started: Arc<Notify>,
    release_held: Arc<Notify>,
    active_completed: Arc<Notify>,
}

impl TypedJobHandler<CleanupJob> for CleanupHandler {
    fn handle(&self, job: CleanupJob, _context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        let held_started = Arc::clone(&self.held_started);
        let release_held = Arc::clone(&self.release_held);
        let active_completed = Arc::clone(&self.active_completed);
        Box::pin(async move {
            match job.value {
                1 => HandlerOutcome::Permanent(failure("cleanup_terminal")),
                2 => {
                    held_started.notify_one();
                    release_held.notified().await;
                    HandlerOutcome::Succeeded
                }
                3 => {
                    active_completed.notify_one();
                    HandlerOutcome::Succeeded
                }
                _ => HandlerOutcome::Succeeded,
            }
        })
    }
}

#[tokio::test]
async fn retention_expires_terminal_data_without_touching_live_records() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<CleanupJob>::connect(&config(&fixture)).await?;
    let held_started = Arc::new(Notify::new());
    let release_held = Arc::new(Notify::new());
    let active_completed = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker_held_started = Arc::clone(&held_started);
    let worker_release_held = Arc::clone(&release_held);
    let worker_active_completed = Arc::clone(&active_completed);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "cleanup-worker",
                CleanupHandler {
                    held_started: worker_held_started,
                    release_held: worker_release_held,
                    active_completed: worker_active_completed,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 0 }, None)?)
        .await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.completed() == 1
    })
    .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 1 }, None)?)
        .await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 2 }, None)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), held_started.notified()).await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 3 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 5 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 6 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(CleanupJob { value: 7 }, None)?)
        .await?;
    provider
        .enqueue_typed(&envelope::<CleanupJob>(
            CleanupJob { value: 4 },
            Some(OffsetDateTime::now_utc() + time::Duration::seconds(30)),
        )?)
        .await?;
    let diagnostics = wait_for_diagnostics(&provider, Duration::from_secs(5), |value| {
        value.queued() >= 1
            && value.scheduled() == 1
            && value.completed() == 0
            && value.dead_lettered() == 0
    })
    .await?;
    assert!(diagnostics.queued() >= 1);
    let mut connection = raw_connection(&fixture).await?;
    let data_key = format!("{}:data", provider.definition().namespace());
    let result_key = format!("{data_key}::result");
    let live_data: u64 = redis_apalis::cmd("HLEN")
        .arg(&data_key)
        .query_async(&mut connection)
        .await?;
    assert_eq!(live_data, 6);
    let terminal_results: u64 = redis_apalis::cmd("HLEN")
        .arg(result_key)
        .query_async(&mut connection)
        .await?;
    assert_eq!(terminal_results, 0);

    release_held.notify_one();
    tokio::time::timeout(Duration::from_secs(3), active_completed.notified()).await?;
    let diagnostics = provider.diagnostics().await?;
    assert_eq!(diagnostics.scheduled(), 1);
    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn diagnostics_reports_durable_control_and_canonical_oldest_age() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let initial = provider.diagnostics().await?;
    assert_eq!(initial.queued(), 0);
    assert_eq!(initial.scheduled(), 0);
    assert_eq!(initial.oldest_outstanding_age(), None);
    assert!(initial.oldest_outstanding_age_complete());
    assert!(!initial.paused());
    assert_eq!(initial.revision(), 0);

    provider
        .enqueue_typed(&envelope::<SuccessJob>(
            SuccessJob { value: 40 },
            Some(OffsetDateTime::now_utc() + time::Duration::seconds(30)),
        )?)
        .await?;
    tokio::time::sleep(Duration::from_millis(25)).await;
    provider
        .enqueue_typed(&envelope::<SuccessJob>(SuccessJob { value: 41 }, None)?)
        .await?;
    let diagnostics = provider.diagnostics().await?;
    assert_eq!(diagnostics.queued(), 1);
    assert_eq!(diagnostics.scheduled(), 1);
    assert!(diagnostics.oldest_outstanding_age() >= Some(Duration::from_millis(20)));
    assert!(diagnostics.oldest_outstanding_age_complete());
    assert!(!diagnostics.paused());
    assert_eq!(diagnostics.revision(), 0);

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn diagnostics_bounds_envelope_fetches_and_marks_a_partial_oldest_age() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    provider
        .enqueue_typed(&envelope::<SuccessJob>(SuccessJob { value: 42 }, None)?)
        .await?;

    let active_key = format!("{}:active", provider.definition().namespace());
    let mut connection = raw_connection(&fixture).await?;
    let record_id: String = redis_apalis::cmd("LINDEX")
        .arg(&active_key)
        .arg(0)
        .query_async(&mut connection)
        .await?;
    let mut append = redis_apalis::cmd("RPUSH");
    append.arg(&active_key);
    for _ in 0..99 {
        append.arg(&record_id);
    }
    append.arg("invalid-record-beyond-diagnostic-bound");
    let _: u64 = append.query_async(&mut connection).await?;

    let diagnostics = provider.diagnostics().await?;
    assert_eq!(diagnostics.queued(), 101);
    assert!(diagnostics.oldest_outstanding_age().is_some());
    assert!(!diagnostics.oldest_outstanding_age_complete());

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn clean_cancellation_of_an_idle_worker_is_not_a_lifecycle_failure() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker("clean-cancellation-worker", IdleHandler, run_cancellation)
            .await
    });
    let consumers_key = format!("{}:consumers", provider.definition().namespace());
    let mut connection = raw_connection(&fixture).await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let active: u64 = redis_apalis::cmd("ZCARD")
                .arg(&consumers_key)
                .query_async(&mut connection)
                .await?;
            if active == 1 {
                return Ok::<(), redis_apalis::RedisError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;

    stop_worker(cancellation, worker).await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn pause_and_resume_are_durable_and_revision_fenced() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let paused = provider.set_paused(true, 0).await?;
    assert!(paused.paused());
    assert_eq!(paused.revision(), 1);
    assert_eq!(
        provider.set_paused(false, 0).await,
        Err(RedisAdminError::RevisionConflict)
    );

    let reconnected = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    assert_eq!(reconnected.control_state().await?, paused);
    let resumed = reconnected.set_paused(false, paused.revision()).await?;
    assert!(!resumed.paused());
    assert_eq!(resumed.revision(), 2);

    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn pause_script_rejects_an_invalid_control_key_type_without_mutation() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SuccessJob>::connect(&config(&fixture)).await?;
    let control_key = format!("{}:admin:control", provider.definition().namespace());
    let mut connection = raw_connection(&fixture).await?;
    let _: u64 = redis_apalis::cmd("DEL")
        .arg(&control_key)
        .query_async(&mut connection)
        .await?;
    let _: () = redis_apalis::cmd("SET")
        .arg(&control_key)
        .arg("wrong-type")
        .query_async(&mut connection)
        .await?;
    assert_eq!(
        provider.set_paused(true, 0).await,
        Err(RedisAdminError::Unavailable)
    );
    let unchanged: String = redis_apalis::cmd("GET")
        .arg(control_key)
        .query_async(&mut connection)
        .await?;
    assert_eq!(unchanged, "wrong-type");

    fixture.cleanup().await?;
    Ok(())
}

struct SensitivePermanentHandler;

impl TypedJobHandler<SensitiveAdminJob> for SensitivePermanentHandler {
    fn handle(
        &self,
        _job: SensitiveAdminJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async { HandlerOutcome::Permanent(failure("admin_dead")) })
    }
}

struct SensitiveReplayHandler {
    seen_job_id: Arc<Mutex<Option<JobId>>>,
    completed: Arc<Notify>,
}

impl TypedJobHandler<SensitiveAdminJob> for SensitiveReplayHandler {
    fn handle(
        &self,
        _job: SensitiveAdminJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let seen_job_id = Arc::clone(&self.seen_job_id);
        let completed = Arc::clone(&self.completed);
        Box::pin(async move {
            if let Ok(mut seen) = seen_job_id.lock() {
                *seen = Some(context.effect_identity().job_id());
            }
            completed.notify_one();
            HandlerOutcome::Succeeded
        })
    }
}

#[tokio::test]
async fn dead_records_are_bounded_redacted_and_replay_exactly_once() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<SensitiveAdminJob>::connect(&config(&fixture)).await?;
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "sensitive-admin-dead-worker",
                SensitivePermanentHandler,
                run_cancellation,
            )
            .await
    });
    let secret = "super-secret-admin-payload";
    let job = envelope::<SensitiveAdminJob>(
        SensitiveAdminJob {
            secret: secret.to_owned(),
        },
        None,
    )?;
    let job_id = job.id();
    let envelope_bytes = job.encode()?.bytes().len();
    provider.enqueue_typed(&job).await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.dead_lettered() == 1
    })
    .await?;
    stop_worker(cancellation, worker).await?;

    assert_eq!(
        provider.dead_records(0).await,
        Err(RedisAdminError::InvalidLimit)
    );
    assert_eq!(
        provider.dead_records(101).await,
        Err(RedisAdminError::InvalidLimit)
    );
    let records = provider.dead_records(1).await?;
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.job_id(), job_id);
    assert_eq!(record.attempt(), 1);
    assert_eq!(record.envelope_bytes(), envelope_bytes);
    assert!(record.failed_at() >= record.created_at());
    let rendered = format!("{record:?}");
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("admin_dead"));

    let paused = provider.set_paused(true, 0).await?;
    let replay = provider
        .replay_dead(record.record_id(), paused.revision())
        .await?;
    assert_eq!(replay.record_id(), record.record_id());
    assert_eq!(replay.job_id(), job_id);
    assert_eq!(replay.identity(), RedisReplayIdentity::SameJobSameMessage);
    assert_eq!(replay.revision(), 2);
    assert_eq!(
        provider
            .replay_dead(record.record_id(), replay.revision())
            .await,
        Err(RedisAdminError::RecordNotFound)
    );
    assert!(provider.dead_records(1).await?.is_empty());

    let seen_job_id = Arc::new(Mutex::new(None));
    let completed = Arc::new(Notify::new());
    let replay_cancellation = CancellationToken::new();
    let run_replay_cancellation = replay_cancellation.clone();
    let replay_provider = provider.clone();
    let handler_seen_job_id = Arc::clone(&seen_job_id);
    let handler_completed = Arc::clone(&completed);
    let replay_worker = tokio::spawn(async move {
        replay_provider
            .run_worker(
                "sensitive-admin-replay-worker",
                SensitiveReplayHandler {
                    seen_job_id: handler_seen_job_id,
                    completed: handler_completed,
                },
                run_replay_cancellation,
            )
            .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!replay_worker.is_finished());
    provider.set_paused(false, replay.revision()).await?;
    tokio::time::timeout(Duration::from_secs(3), completed.notified()).await?;
    let seen = *seen_job_id
        .lock()
        .map_err(|_| std::io::Error::other("replay identity poisoned"))?;
    assert_eq!(seen, Some(job_id));
    stop_worker(replay_cancellation, replay_worker).await?;

    fixture.cleanup().await?;
    Ok(())
}

struct PauseDrainHandler {
    starts: Arc<AtomicUsize>,
    first_started: Arc<Notify>,
    first_cancelled: Arc<Notify>,
}

impl TypedJobHandler<PauseDrainJob> for PauseDrainHandler {
    fn handle(
        &self,
        _job: PauseDrainJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let starts = Arc::clone(&self.starts);
        let first_started = Arc::clone(&self.first_started);
        let first_cancelled = Arc::clone(&self.first_cancelled);
        Box::pin(async move {
            let invocation = starts.fetch_add(1, Ordering::SeqCst) + 1;
            if invocation == 1 {
                first_started.notify_one();
                context.cancellation().cancelled().await;
                first_cancelled.notify_one();
                HandlerOutcome::Cancelled
            } else {
                HandlerOutcome::Succeeded
            }
        })
    }
}

#[tokio::test]
async fn durable_pause_drains_active_work_and_does_not_start_a_second_delivery() -> TestResult {
    let fixture = RedisFixture::start().await?;
    let provider = RedisJobProvider::<PauseDrainJob>::connect(&config(&fixture)).await?;
    let starts = Arc::new(AtomicUsize::new(0));
    let first_started = Arc::new(Notify::new());
    let first_cancelled = Arc::new(Notify::new());
    let cancellation = CancellationToken::new();
    let run_cancellation = cancellation.clone();
    let worker_provider = provider.clone();
    let handler_starts = Arc::clone(&starts);
    let handler_first_started = Arc::clone(&first_started);
    let handler_first_cancelled = Arc::clone(&first_cancelled);
    let worker = tokio::spawn(async move {
        worker_provider
            .run_worker(
                "pause-drain-worker",
                PauseDrainHandler {
                    starts: handler_starts,
                    first_started: handler_first_started,
                    first_cancelled: handler_first_cancelled,
                },
                run_cancellation,
            )
            .await
    });
    provider
        .enqueue_typed(&envelope::<PauseDrainJob>(
            PauseDrainJob { value: 1 },
            None,
        )?)
        .await?;
    provider
        .enqueue_typed(&envelope::<PauseDrainJob>(
            PauseDrainJob { value: 2 },
            None,
        )?)
        .await?;
    tokio::time::timeout(Duration::from_secs(3), first_started.notified()).await?;
    let paused = provider.set_paused(true, 0).await?;
    assert!(paused.paused());
    let consumers_key = format!("{}:consumers", provider.definition().namespace());
    let mut connection = raw_connection(&fixture).await?;
    let consumers_type: String = redis_apalis::cmd("TYPE")
        .arg(&consumers_key)
        .query_async(&mut connection)
        .await?;
    assert_eq!(consumers_type, "string");
    let fence: String = redis_apalis::cmd("GET")
        .arg(&consumers_key)
        .query_async(&mut connection)
        .await?;
    assert_eq!(fence, "omnius-paused-v1");
    tokio::time::timeout(Duration::from_secs(3), first_cancelled.notified()).await?;
    wait_for_diagnostics(&provider, Duration::from_secs(3), |value| {
        value.paused() && value.queued() >= 1
    })
    .await?;
    let held_consumers_key = format!(
        "{}:admin:paused-consumers",
        provider.definition().namespace()
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let held_consumers: u64 = redis_apalis::cmd("ZCARD")
                .arg(&held_consumers_key)
                .query_async(&mut connection)
                .await?;
            if held_consumers == 0 {
                return Ok::<(), redis_apalis::RedisError>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert!(!worker.is_finished());
    stop_worker(cancellation, worker).await?;

    fixture.cleanup().await?;
    Ok(())
}
