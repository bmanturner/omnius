use std::{
    any::Any,
    future::Future,
    marker::PhantomData,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    task::{Context as TaskContext, Poll},
    time::Duration,
};

use futures::future::BoxFuture;
use omnius_jobs_core::{
    DeliveryContext, EncodedJobEnvelope, FailureCode, HandlerFailure, HandlerOutcome, Job,
    JobHandler, TypedJobHandler,
};
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ExecutionFence, PostgresScheduler, SchedulerError};

/// Duplicate- and concurrency-safe gate around a typed job handler.
///
/// The gate uses `DeliveryContext::effect_identity().job_id()` to locate the immutable scheduled
/// run. It serializes acquisition through the run and schedule rows, counts only live execution
/// leases, and renews the acquired `UUIDv7` fence while the bounded inner future is active.
pub struct ScheduledJobHandler<J, H> {
    scheduler: PostgresScheduler,
    inner: H,
    marker: PhantomData<fn() -> J>,
}

impl<J, H> ScheduledJobHandler<J, H> {
    /// Wraps a typed handler with the durable execution gate.
    #[must_use]
    pub const fn new(scheduler: PostgresScheduler, inner: H) -> Self {
        Self {
            scheduler,
            inner,
            marker: PhantomData,
        }
    }
}

impl<J: Job, H: TypedJobHandler<J>> JobHandler for ScheduledJobHandler<J, H> {
    fn job_name(&self) -> &'static str {
        J::NAME
    }

    fn job_version(&self) -> u16 {
        J::VERSION
    }

    fn metrics_prefix(&self) -> &'static str {
        J::METRICS_PREFIX
    }

    fn runbook(&self) -> &'static str {
        J::RUNBOOK
    }

    fn handle(
        &self,
        envelope: EncodedJobEnvelope,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            if context.is_cancelled() {
                return HandlerOutcome::Cancelled;
            }
            if envelope.id() != context.effect_identity().job_id()
                || envelope.job_name().as_str() != J::NAME
            {
                return permanent("scheduled_context_mismatch");
            }
            let Ok(envelope) = envelope.decode::<J>() else {
                return permanent("scheduled_invalid_envelope");
            };
            let job_id = context.effect_identity().job_id();
            let deadline = context.deadline();
            let Ok(acquired) = self.acquire_execution(job_id.as_uuid(), deadline).await else {
                return retryable("scheduler_gate_unavailable");
            };
            let acquisition = match acquired {
                Acquisition::Completed => return HandlerOutcome::Succeeded,
                Acquisition::Failed => return permanent("scheduled_run_failed"),
                Acquisition::Busy => return retryable("scheduled_execution_busy"),
                Acquisition::DeadlineExpired => {
                    return retryable("scheduled_execution_timeout");
                }
                Acquisition::Missing => return permanent("unscheduled_job"),
                Acquisition::Acquired {
                    fence,
                    lease_duration,
                } => (fence, lease_duration),
            };
            let (fence, lease_duration) = acquisition;
            let outcome = match bounded_execution_budget(
                lease_duration,
                deadline,
                OffsetDateTime::now_utc(),
            ) {
                None => retryable("scheduled_execution_timeout"),
                Some(execution_budget) => {
                    let payload = envelope.into_payload();
                    match catch_unwind(AssertUnwindSafe(|| {
                        self.inner.handle(payload, context.clone())
                    })) {
                        Err(payload) => {
                            discard_panic_payload(payload);
                            permanent("scheduled_handler_panic")
                        }
                        Ok(future) => {
                            let renewal_interval = lease_duration / 3;
                            let future = PanicSafeFuture::new(future);
                            tokio::pin!(future);
                            let timeout = tokio::time::sleep(execution_budget);
                            tokio::pin!(timeout);
                            let renewal = tokio::time::sleep(renewal_interval);
                            tokio::pin!(renewal);
                            loop {
                                tokio::select! {
                                    result = &mut future => {
                                        break match result {
                                            Ok(outcome) => outcome,
                                            Err(_) => permanent("scheduled_handler_panic"),
                                        };
                                    }
                                    () = &mut timeout => {
                                        break retryable("scheduled_execution_timeout");
                                    }
                                    () = context.cancellation().cancelled() => {
                                        break HandlerOutcome::Cancelled;
                                    }
                                    () = &mut renewal => {
                                        if self
                                            .renew_execution(
                                                job_id.as_uuid(),
                                                fence,
                                                lease_duration,
                                                deadline,
                                            )
                                            .await
                                            .is_err()
                                        {
                                            break retryable("scheduled_execution_lease_lost");
                                        }
                                        renewal
                                            .as_mut()
                                            .reset(tokio::time::Instant::now() + renewal_interval);
                                    }
                                }
                            }
                        }
                    }
                }
            };
            match self
                .finish_execution(job_id.as_uuid(), fence, &outcome)
                .await
            {
                Ok(()) => outcome,
                Err(_) => retryable("scheduled_execution_lease_lost"),
            }
        })
    }
}

impl<J: Job, H: TypedJobHandler<J>> ScheduledJobHandler<J, H> {
    async fn acquire_execution(
        &self,
        job_id: Uuid,
        deadline: OffsetDateTime,
    ) -> Result<Acquisition, SchedulerError> {
        let mut connection = self
            .scheduler
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result =
            Self::acquire_execution_in_transaction(&mut transaction, job_id, deadline).await;
        match result {
            Ok(value) => {
                transaction
                    .commit()
                    .await
                    .map_err(|_| SchedulerError::Database)?;
                Ok(value)
            }
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| SchedulerError::Database)?;
                Err(error)
            }
        }
    }

    async fn acquire_execution_in_transaction(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        job_id: Uuid,
        deadline: OffsetDateTime,
    ) -> Result<Acquisition, SchedulerError> {
        let Some(row) = Self::locked_execution_run(transaction, job_id).await? else {
            return Ok(Acquisition::Missing);
        };
        let status: String = row
            .try_get("status")
            .map_err(|_| SchedulerError::Database)?;
        if status == "completed" {
            return Ok(Acquisition::Completed);
        }
        if status == "failed" {
            return Ok(Acquisition::Failed);
        }
        if !matches!(status.as_str(), "dispatching" | "dispatched" | "running") {
            return Ok(Acquisition::Busy);
        }
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
        let expiry: Option<OffsetDateTime> = row
            .try_get("execution_lease_expires_at")
            .map_err(|_| SchedulerError::Database)?;
        if status == "running" && expiry.is_some_and(|value| value > now) {
            return Ok(Acquisition::Busy);
        }
        let schedule_id: Uuid = row
            .try_get("schedule_id")
            .map_err(|_| SchedulerError::Database)?;
        let schedule = Self::locked_execution_schedule(transaction, schedule_id).await?;
        let maximum = i64::from(
            schedule
                .try_get::<i32, _>("max_concurrent_runs")
                .map_err(|_| SchedulerError::Database)?,
        );
        if Self::active_execution_count(transaction, schedule_id, job_id).await? >= maximum {
            return Ok(Acquisition::Busy);
        }
        let schedule_lease_micros: i64 = schedule
            .try_get("execution_lease_micros")
            .map_err(|_| SchedulerError::Database)?;
        let schedule_lease = u64::try_from(schedule_lease_micros)
            .map(Duration::from_micros)
            .map_err(|_| SchedulerError::Database)?;
        let lease_now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
        let Some(lease_duration) = deadline_capped_lease(schedule_lease, deadline, lease_now)
        else {
            return Ok(Acquisition::DeadlineExpired);
        };
        let lease_micros =
            i64::try_from(lease_duration.as_micros()).map_err(|_| SchedulerError::Database)?;
        let fence = ExecutionFence::new();
        if !Self::claim_execution(transaction, job_id, fence, lease_micros, deadline).await? {
            return Ok(Acquisition::DeadlineExpired);
        }
        Ok(Acquisition::Acquired {
            fence,
            lease_duration,
        })
    }

    async fn locked_execution_run(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        job_id: Uuid,
    ) -> Result<Option<sqlx::postgres::PgRow>, SchedulerError> {
        sqlx::query(
            "SELECT id, schedule_id, status, execution_lease_expires_at
             FROM scheduler_job_runs WHERE job_id = $1 FOR UPDATE",
        )
        .bind(job_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| SchedulerError::Database)
    }

    async fn locked_execution_schedule(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        schedule_id: Uuid,
    ) -> Result<sqlx::postgres::PgRow, SchedulerError> {
        sqlx::query(
            "SELECT max_concurrent_runs, execution_lease_micros
             FROM scheduler_schedules WHERE id = $1 FOR UPDATE",
        )
        .bind(schedule_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|_| SchedulerError::Database)?
        .ok_or(SchedulerError::Database)
    }

    async fn active_execution_count(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        schedule_id: Uuid,
        job_id: Uuid,
    ) -> Result<i64, SchedulerError> {
        sqlx::query_scalar(
            "SELECT count(*) FROM scheduler_job_runs
             WHERE schedule_id = $1 AND job_id <> $2 AND status = 'running'
               AND execution_lease_expires_at > clock_timestamp()",
        )
        .bind(schedule_id)
        .bind(job_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|_| SchedulerError::Database)
    }

    async fn claim_execution(
        transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        job_id: Uuid,
        fence: ExecutionFence,
        lease_micros: i64,
        deadline: OffsetDateTime,
    ) -> Result<bool, SchedulerError> {
        let done = sqlx::query(
            "WITH lease_clock AS (SELECT clock_timestamp() AS now)
             UPDATE scheduler_job_runs
             SET status = 'running',
                 dispatched_at = COALESCE(dispatched_at, lease_clock.now),
                 started_at = COALESCE(started_at, lease_clock.now),
                 dispatch_lease_owner = NULL, dispatch_lease_token = NULL,
                 dispatch_lease_expires_at = NULL,
                 execution_lease_token = $2,
                 execution_lease_expires_at = LEAST(
                     lease_clock.now + $3::bigint * INTERVAL '1 microsecond',
                     $4::timestamptz - $5::bigint * INTERVAL '1 microsecond'
                 ),
                 execution_attempt_count = execution_attempt_count + 1
             FROM lease_clock
             WHERE job_id = $1 AND status IN ('dispatching', 'dispatched', 'running')
               AND (status <> 'running' OR execution_lease_expires_at <= lease_clock.now)
               AND $4::timestamptz - $5::bigint * INTERVAL '1 microsecond' > lease_clock.now",
        )
        .bind(job_id)
        .bind(fence.as_uuid())
        .bind(lease_micros)
        .bind(deadline)
        .bind(EXECUTION_FINISH_SAFETY_MICROS)
        .execute(&mut **transaction)
        .await
        .map_err(|_| SchedulerError::Database)?;
        Ok(done.rows_affected() == 1)
    }

    async fn renew_execution(
        &self,
        job_id: Uuid,
        fence: ExecutionFence,
        lease_duration: Duration,
        deadline: OffsetDateTime,
    ) -> Result<(), SchedulerError> {
        let lease_micros =
            i64::try_from(lease_duration.as_micros()).map_err(|_| SchedulerError::Database)?;
        let mut connection = self
            .scheduler
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let done = sqlx::query(
            "WITH lease_clock AS (SELECT clock_timestamp() AS now)
             UPDATE scheduler_job_runs
             SET execution_lease_expires_at = LEAST(
                 lease_clock.now + $3::bigint * INTERVAL '1 microsecond',
                 $4::timestamptz - $5::bigint * INTERVAL '1 microsecond'
             )
             FROM lease_clock
             WHERE job_id = $1 AND status = 'running' AND execution_lease_token = $2
               AND execution_lease_expires_at > lease_clock.now
               AND $4::timestamptz - $5::bigint * INTERVAL '1 microsecond' > lease_clock.now",
        )
        .bind(job_id)
        .bind(fence.as_uuid())
        .bind(lease_micros)
        .bind(deadline)
        .bind(EXECUTION_FINISH_SAFETY_MICROS)
        .execute(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        if done.rows_affected() == 1 {
            Ok(())
        } else {
            Err(SchedulerError::LostLease)
        }
    }

    async fn finish_execution(
        &self,
        job_id: Uuid,
        fence: ExecutionFence,
        outcome: &HandlerOutcome,
    ) -> Result<(), SchedulerError> {
        let (status, failure_code): (&'static str, Option<&str>) = match outcome {
            HandlerOutcome::Succeeded => ("completed", None),
            HandlerOutcome::Retryable(_) | HandlerOutcome::Cancelled => ("dispatched", None),
            HandlerOutcome::Permanent(failure) => ("failed", Some(failure.code().as_str())),
        };
        let mut connection = self
            .scheduler
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let done = sqlx::query(
            "UPDATE scheduler_job_runs
             SET status = $3,
                 execution_lease_token = NULL, execution_lease_expires_at = NULL,
                 completed_at = CASE WHEN $3 = 'completed' THEN clock_timestamp() ELSE NULL END,
                 failed_at = CASE WHEN $3 = 'failed' THEN clock_timestamp() ELSE NULL END,
                 failure_code = $4
             WHERE job_id = $1 AND status = 'running' AND execution_lease_token = $2
               AND execution_lease_expires_at > clock_timestamp()",
        )
        .bind(job_id)
        .bind(fence.as_uuid())
        .bind(status)
        .bind(failure_code)
        .execute(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        if done.rows_affected() == 1 {
            Ok(())
        } else {
            Err(SchedulerError::LostLease)
        }
    }
}

enum Acquisition {
    Completed,
    Failed,
    Busy,
    DeadlineExpired,
    Missing,
    Acquired {
        fence: ExecutionFence,
        lease_duration: Duration,
    },
}

const EXECUTION_FINISH_SAFETY: Duration = Duration::from_millis(50);
const EXECUTION_FINISH_SAFETY_MICROS: i64 = 50_000;

fn deadline_capped_lease(
    schedule_lease: Duration,
    deadline: OffsetDateTime,
    now: OffsetDateTime,
) -> Option<Duration> {
    let deadline_remaining = Duration::try_from(deadline - now).ok()?;
    let deadline_lease = deadline_remaining.checked_sub(EXECUTION_FINISH_SAFETY)?;
    let capped_lease = schedule_lease.min(deadline_lease);
    let whole_micros = u64::try_from(capped_lease.as_micros()).ok()?;
    (whole_micros != 0).then(|| Duration::from_micros(whole_micros))
}

fn bounded_execution_budget(
    lease_duration: Duration,
    deadline: OffsetDateTime,
    now: OffsetDateTime,
) -> Option<Duration> {
    let lease_budget = lease_duration.checked_sub(EXECUTION_FINISH_SAFETY)?;
    let deadline_remaining = Duration::try_from(deadline - now).ok()?;
    let deadline_budget = deadline_remaining.checked_sub(EXECUTION_FINISH_SAFETY)?;
    let budget = lease_budget.min(deadline_budget);
    (!budget.is_zero()).then_some(budget)
}

struct HandlerFuturePanicked;

struct PanicSafeFuture<'a, T> {
    inner: Option<BoxFuture<'a, T>>,
}

impl<'a, T> PanicSafeFuture<'a, T> {
    const fn new(future: BoxFuture<'a, T>) -> Self {
        Self {
            inner: Some(future),
        }
    }

    fn drop_inner(&mut self) -> Result<(), HandlerFuturePanicked> {
        let Some(future) = self.inner.take() else {
            return Ok(());
        };
        match catch_unwind(AssertUnwindSafe(|| drop(future))) {
            Ok(()) => Ok(()),
            Err(payload) => {
                discard_panic_payload(payload);
                Err(HandlerFuturePanicked)
            }
        }
    }
}

impl<T> Future for PanicSafeFuture<'_, T> {
    type Output = Result<T, HandlerFuturePanicked>;

    fn poll(mut self: Pin<&mut Self>, context: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let Some(future) = self.inner.as_mut() else {
            return Poll::Ready(Err(HandlerFuturePanicked));
        };
        let result = catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context)));
        match result {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(output)) => match self.drop_inner() {
                Ok(()) => Poll::Ready(Ok(output)),
                Err(error) => Poll::Ready(Err(error)),
            },
            Err(payload) => {
                discard_panic_payload(payload);
                Poll::Ready(Err(HandlerFuturePanicked))
            }
        }
    }
}

impl<T> Drop for PanicSafeFuture<'_, T> {
    fn drop(&mut self) {
        let _drop_result = self.drop_inner();
    }
}

fn discard_panic_payload(payload: Box<dyn Any + Send>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::mem::forget(payload);
    }
}

fn retryable(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Retryable(HandlerFailure::new(failure_code(code)))
}

fn permanent(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Permanent(HandlerFailure::new(failure_code(code)))
}

fn failure_code(value: &'static str) -> FailureCode {
    match FailureCode::try_from(value) {
        Ok(code) => code,
        Err(_) => unreachable!("static scheduler handler failure code must be valid"),
    }
}
