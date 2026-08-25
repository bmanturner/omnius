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
use redis_apalis::aio::ConnectionManager;
use rsk_config::ExposeSecret as _;
use rsk_jobs_apalis_redis::{JobDiagnostics, RedisJobConfig, RedisJobProvider};
use rsk_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EnqueueError, FailureCode,
    HandlerFailure, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuerExt as _,
    JobEnvelope, JobEnvelopeOptions, JobId, JobPolicy, TypedJobHandler,
};
use rsk_test_support::RedisFixture;
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
                return Ok::<_, rsk_jobs_apalis_redis::JobDiagnosticsError>(diagnostics);
            }
        }
    })
    .await??;
    Ok(result)
}

async fn stop_worker(
    cancellation: CancellationToken,
    handle: JoinHandle<Result<(), rsk_jobs_apalis_redis::RedisJobWorkerError>>,
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
