use std::{
    collections::HashSet,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use metrics::{counter, histogram};
use omnius_core::{ErrorCode, ServiceError};
use omnius_jobs_core::{EncodedJobEnvelope, EnqueueError, JobEnqueuer, QueueName};
use omnius_postgres::PostgresPool;
use omnius_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    AuditRecord, DispatchFence, DueSchedule, LeasedRun, MisfirePolicy, RunStatus, ScheduleActor,
    ScheduleDefinition, ScheduleEnvelopeFactory, ScheduleFence, ScheduleId, ScheduleName,
    ScheduleReason, ScheduleSnapshot, ScheduledRunId, SchedulerConfig, SchedulerConfigError,
    SchedulerError, SchedulerStatus, evaluate_occurrences, next_occurrence,
};

const MODULE_NAME: &str = "scheduler";
const TASK_NAME: &str = "postgres-scheduler";
const TASK_ERROR_CODE: &str = "SCHEDULER_DEGRADED";

/// Cloneable durable scheduler repository and runtime registration.
#[derive(Clone)]
pub struct PostgresScheduler {
    pub(crate) pool: PostgresPool,
    pub(crate) config: SchedulerConfig,
}

impl fmt::Debug for PostgresScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresScheduler")
            .field("pool", &self.pool)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PostgresScheduler {
    /// Creates a scheduler after validating every runtime bound.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerConfigError`] for invalid leasing or lifecycle policy.
    pub fn new(pool: PostgresPool, config: SchedulerConfig) -> Result<Self, SchedulerConfigError> {
        config.validate()?;
        Ok(Self { pool, config })
    }

    /// Returns whether this repository requires its degraded scheduler task.
    #[must_use]
    pub const fn runtime_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Creates and audits one schedule transactionally.
    ///
    /// The first cursor is evaluated strictly after the PostgreSQL clock observed by this call.
    ///
    /// # Errors
    ///
    /// Returns a safe scheduler category for calendar or database failure.
    pub async fn create_schedule(
        &self,
        definition: ScheduleDefinition,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduleSnapshot, SchedulerError> {
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| SchedulerError::Database)?;
        let next_run_at = next_occurrence(&definition, now)?;
        let id = ScheduleId::new();
        let (policy, catch_up) = definition.misfire_policy().database_parts();
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result = async {
            let row = sqlx::query(
                "INSERT INTO scheduler_schedules (
                    id, name, cron_expression, timezone, misfire_policy, catch_up_max_runs,
                    max_concurrent_runs, scheduler_lease_micros, execution_lease_micros,
                    idempotency_window_micros, paused, revision, next_run_at
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 1, $12)
                 RETURNING *",
            )
            .bind(id.as_uuid())
            .bind(definition.name().as_str())
            .bind(definition.expression())
            .bind(definition.timezone())
            .bind(policy)
            .bind(catch_up)
            .bind(i32::from(definition.max_concurrent_runs().get()))
            .bind(duration_micros(definition.scheduler_lease_duration())?)
            .bind(duration_micros(definition.execution_lease_duration())?)
            .bind(duration_micros(definition.idempotency_window())?)
            .bind(definition.paused())
            .bind(next_run_at)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            append_audit(&mut transaction, id, "create", actor, reason, None, 1).await?;
            decode_snapshot(&row)
        }
        .await;
        let result = finish(transaction, result).await;
        record_operation("create", result_label(&result), started.elapsed());
        result
    }

    /// Replaces mutable schedule policy only when `expected_revision` still owns it.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::RevisionConflict`] for a stale revision.
    pub async fn update_schedule(
        &self,
        id: ScheduleId,
        expected_revision: i64,
        definition: ScheduleDefinition,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduleSnapshot, SchedulerError> {
        if expected_revision <= 0 {
            return Err(SchedulerError::RevisionConflict);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let (policy, catch_up) = definition.misfire_policy().database_parts();
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result = async {
            let locked = sqlx::query(
                "SELECT revision FROM scheduler_schedules
                 WHERE id = $1 AND revision = $2
                 FOR UPDATE",
            )
            .bind(id.as_uuid())
            .bind(expected_revision)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            require_revision(&mut transaction, id, locked).await?;
            let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| SchedulerError::Database)?;
            let next_run_at = next_occurrence(&definition, now)?;
            let row = sqlx::query(
                "UPDATE scheduler_schedules
                 SET name = $3, cron_expression = $4, timezone = $5, misfire_policy = $6,
                     catch_up_max_runs = $7, max_concurrent_runs = $8,
                     scheduler_lease_micros = $9, execution_lease_micros = $10,
                     idempotency_window_micros = $11, paused = $12,
                     revision = revision + 1, next_run_at = $13,
                     lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                     updated_at = clock_timestamp()
                 WHERE id = $1 AND revision = $2
                 RETURNING *",
            )
            .bind(id.as_uuid())
            .bind(expected_revision)
            .bind(definition.name().as_str())
            .bind(definition.expression())
            .bind(definition.timezone())
            .bind(policy)
            .bind(catch_up)
            .bind(i32::from(definition.max_concurrent_runs().get()))
            .bind(duration_micros(definition.scheduler_lease_duration())?)
            .bind(duration_micros(definition.execution_lease_duration())?)
            .bind(duration_micros(definition.idempotency_window())?)
            .bind(definition.paused())
            .bind(next_run_at)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            let row = require_revision(&mut transaction, id, row).await?;
            append_audit(
                &mut transaction,
                id,
                "update",
                actor,
                reason,
                Some(expected_revision),
                expected_revision + 1,
            )
            .await?;
            decode_snapshot(&row)
        }
        .await;
        finish(transaction, result).await
    }

    /// Pauses claims and invalidates any outstanding schedule lease at a checked revision.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::RevisionConflict`] for stale mutable state.
    pub async fn pause_schedule(
        &self,
        id: ScheduleId,
        expected_revision: i64,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduleSnapshot, SchedulerError> {
        self.set_paused(id, expected_revision, true, actor, reason)
            .await
    }

    /// Resumes a schedule at the first calendar instant after the current PostgreSQL clock.
    ///
    /// Paused time is not a misfire window. A later runtime outage is handled by the configured
    /// policy from this new cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::RevisionConflict`] for stale mutable state.
    pub async fn resume_schedule(
        &self,
        id: ScheduleId,
        expected_revision: i64,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduleSnapshot, SchedulerError> {
        self.set_paused(id, expected_revision, false, actor, reason)
            .await
    }

    async fn set_paused(
        &self,
        id: ScheduleId,
        expected_revision: i64,
        paused: bool,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduleSnapshot, SchedulerError> {
        if expected_revision <= 0 {
            return Err(SchedulerError::RevisionConflict);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result = async {
            let locked = sqlx::query("SELECT *, clock_timestamp() AS operation_now FROM scheduler_schedules WHERE id = $1 AND revision = $2 FOR UPDATE")
                .bind(id.as_uuid())
                .bind(expected_revision)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| SchedulerError::Database)?;
            let Some(row) = locked else {
                let exists: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scheduler_schedules WHERE id = $1)")
                    .bind(id.as_uuid())
                    .fetch_one(&mut *transaction)
                    .await
                    .map_err(|_| SchedulerError::Database)?;
                return Err(if exists { SchedulerError::RevisionConflict } else { SchedulerError::NotFound });
            };
            let current = decode_snapshot(&row)?;
            let operation_now: OffsetDateTime = row.try_get("operation_now").map_err(|_| SchedulerError::Database)?;
            let next_run_at = if paused {
                current.next_run_at()
            } else {
                next_occurrence(current.definition(), operation_now)?
            };
            let row = sqlx::query(
                "UPDATE scheduler_schedules
                 SET paused = $3, revision = revision + 1, next_run_at = $4,
                     lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL,
                     updated_at = clock_timestamp()
                 WHERE id = $1 AND revision = $2
                 RETURNING *",
            )
            .bind(id.as_uuid())
            .bind(expected_revision)
            .bind(paused)
            .bind(next_run_at)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            append_audit(
                &mut transaction,
                id,
                if paused { "pause" } else { "resume" },
                actor,
                reason,
                Some(expected_revision),
                expected_revision + 1,
            )
            .await?;
            decode_snapshot(&row)
        }
        .await;
        finish(transaction, result).await
    }

    /// Creates and audits a new replay envelope linked to an existing normal occurrence.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::NotFound`] when the schedule or original occurrence is absent.
    pub async fn replay(
        &self,
        schedule_id: ScheduleId,
        scheduled_for: OffsetDateTime,
        factory: &dyn ScheduleEnvelopeFactory,
        actor: &ScheduleActor,
        reason: &ScheduleReason,
    ) -> Result<ScheduledRunId, SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result = async {
            let revision: Option<i64> = sqlx::query_scalar(
                "SELECT revision FROM scheduler_schedules WHERE id = $1 FOR UPDATE",
            )
            .bind(schedule_id.as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            let revision = revision.ok_or(SchedulerError::NotFound)?;
            let original: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM scheduler_job_runs
                 WHERE schedule_id = $1 AND scheduled_for = $2 AND replay_sequence = 0
                 FOR SHARE",
            )
            .bind(schedule_id.as_uuid())
            .bind(scheduled_for)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            let original = original.ok_or(SchedulerError::NotFound)?;
            let maximum: i32 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(replay_sequence), 0) FROM scheduler_job_runs
                 WHERE replay_of = $1",
            )
            .bind(original)
            .fetch_one(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            let sequence = maximum.checked_add(1).ok_or(SchedulerError::Database)?;
            let sequence_u32 = u32::try_from(sequence).map_err(|_| SchedulerError::Database)?;
            let envelope = factory
                .build(schedule_id, scheduled_for, sequence_u32)
                .map_err(|_| SchedulerError::EnvelopeFactory)?;
            let id = ScheduledRunId::new();
            insert_run(
                &mut transaction,
                id,
                schedule_id,
                scheduled_for,
                sequence,
                Some(original),
                &envelope,
            )
            .await?;
            append_audit(
                &mut transaction,
                schedule_id,
                "replay",
                actor,
                reason,
                Some(revision),
                revision,
            )
            .await?;
            Ok(id)
        }
        .await;
        finish(transaction, result).await
    }

    /// Atomically claims an ordered, disjoint batch using PostgreSQL eligibility and `UUIDv7` fences.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Database`] for acquisition, mutation, or bounded row decoding.
    pub async fn claim_due_schedules(&self) -> Result<Vec<DueSchedule>, SchedulerError> {
        let mut tokens = Vec::with_capacity(self.config.schedule_claim_batch);
        for _ in 0..self.config.schedule_claim_batch {
            tokens.push(Uuid::now_v7());
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let rows = sqlx::query(
            "WITH clock AS MATERIALIZED (
                SELECT clock_timestamp() AS claimed_at
             ), locked AS (
                SELECT schedule.id, schedule.next_run_at
                FROM scheduler_schedules AS schedule, clock
                WHERE schedule.paused = false
                  AND schedule.next_run_at <= clock.claimed_at
                  AND (schedule.lease_expires_at IS NULL OR schedule.lease_expires_at <= clock.claimed_at)
                ORDER BY schedule.next_run_at, schedule.id
                FOR UPDATE OF schedule SKIP LOCKED
                LIMIT $1
             ), numbered AS (
                SELECT id, row_number() OVER (ORDER BY next_run_at, id) AS ordinal FROM locked
             ), supplied_tokens AS (
                SELECT token, ordinal FROM unnest($2::uuid[]) WITH ORDINALITY AS supplied(token, ordinal)
             ), claimed AS (
                UPDATE scheduler_schedules AS schedule
                SET lease_owner = $3,
                    lease_token = supplied_tokens.token,
                    lease_expires_at = clock.claimed_at + schedule.scheduler_lease_micros * INTERVAL '1 microsecond'
                FROM numbered JOIN supplied_tokens USING (ordinal), clock
                WHERE schedule.id = numbered.id
                RETURNING schedule.*, clock.claimed_at
             )
             SELECT * FROM claimed ORDER BY next_run_at, id",
        )
        .bind(i64::try_from(self.config.schedule_claim_batch).map_err(|_| SchedulerError::Database)?)
        .bind(tokens)
        .bind(&self.config.lease_owner)
        .fetch_all(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        let claims: Result<Vec<_>, _> = rows.iter().map(decode_due).collect();
        let claims = claims?;
        counter!("omnius_scheduler_schedule_claimed_total").increment(claims.len() as u64);
        Ok(claims)
    }

    /// Persists fresh exact envelopes and advances a schedule only through its exact fence.
    ///
    /// Factory work and calendar evaluation happen before the database transition. A transaction
    /// then verifies the unchanged cursor, revision, and token, inserts immutable run identities,
    /// and advances the cursor atomically. Expiry permits reclaim but does not invalidate a token
    /// that has not been replaced. No envelope is handed to a provider before this commit.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::LostLease`] when another replica owns or advanced the schedule.
    pub async fn materialize_due(
        &self,
        claim: &DueSchedule,
        factory: &dyn ScheduleEnvelopeFactory,
    ) -> Result<Vec<ScheduledRunId>, SchedulerError> {
        let schedule = claim.schedule();
        let plan = evaluate_occurrences(
            schedule.definition(),
            schedule.next_run_at(),
            claim.claimed_at(),
        )?;
        let mut prepared = Vec::with_capacity(plan.occurrences().len());
        let mut job_ids = HashSet::with_capacity(plan.occurrences().len());
        for scheduled_for in plan.occurrences() {
            let envelope = factory
                .build(schedule.id(), *scheduled_for, 0)
                .map_err(|_| SchedulerError::EnvelopeFactory)?;
            if !job_ids.insert(envelope.id()) {
                return Err(SchedulerError::InvalidEnvelope);
            }
            prepared.push((ScheduledRunId::new(), *scheduled_for, envelope));
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let result = async {
            let owned: Option<i32> = sqlx::query_scalar(
                "SELECT 1 FROM scheduler_schedules
                 WHERE id = $1 AND revision = $2 AND next_run_at = $3
                   AND lease_token = $4
                 FOR UPDATE",
            )
            .bind(schedule.id().as_uuid())
            .bind(schedule.revision())
            .bind(schedule.next_run_at())
            .bind(claim.fence().as_uuid())
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            if owned.is_none() {
                return Err(SchedulerError::LostLease);
            }
            let mut ids = Vec::with_capacity(prepared.len());
            for (id, scheduled_for, envelope) in &prepared {
                insert_run(
                    &mut transaction,
                    *id,
                    schedule.id(),
                    *scheduled_for,
                    0,
                    None,
                    envelope,
                )
                .await?;
                ids.push(*id);
            }
            let updated = sqlx::query(
                "UPDATE scheduler_schedules
                 SET next_run_at = $5, lease_owner = NULL, lease_token = NULL,
                     lease_expires_at = NULL, updated_at = clock_timestamp()
                 WHERE id = $1 AND revision = $2 AND next_run_at = $3
                   AND lease_token = $4",
            )
            .bind(schedule.id().as_uuid())
            .bind(schedule.revision())
            .bind(schedule.next_run_at())
            .bind(claim.fence().as_uuid())
            .bind(plan.next_run_at())
            .execute(&mut *transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
            if updated.rows_affected() != 1 {
                return Err(SchedulerError::LostLease);
            }
            Ok(ids)
        }
        .await;
        let result = finish(transaction, result).await;
        if let Ok(ids) = &result {
            counter!("omnius_scheduler_occurrences_materialized_total").increment(ids.len() as u64);
        }
        result
    }

    /// Claims exact persisted envelopes for provider handoff using independent `UUIDv7` fences.
    ///
    /// Expired `dispatching` rows are reclaimed with the same job ID, queue, and JSON bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidEnvelope`] when durable bytes cannot be restored.
    pub async fn claim_pending_runs(&self) -> Result<Vec<LeasedRun>, SchedulerError> {
        let mut tokens = Vec::with_capacity(self.config.dispatch_claim_batch);
        for _ in 0..self.config.dispatch_claim_batch {
            tokens.push(Uuid::now_v7());
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let rows = sqlx::query(
            "WITH clock AS MATERIALIZED (
                SELECT clock_timestamp() AS claimed_at
             ), locked AS (
                SELECT run.id, run.available_at, run.scheduled_for
                FROM scheduler_job_runs AS run, clock
                WHERE run.available_at <= clock.claimed_at
                  AND (run.status = 'pending_dispatch'
                       OR (run.status = 'dispatching' AND run.dispatch_lease_expires_at <= clock.claimed_at))
                ORDER BY run.available_at, run.scheduled_for, run.id
                FOR UPDATE OF run SKIP LOCKED
                LIMIT $1
             ), numbered AS (
                SELECT id, row_number() OVER (ORDER BY available_at, scheduled_for, id) AS ordinal FROM locked
             ), supplied_tokens AS (
                SELECT token, ordinal FROM unnest($2::uuid[]) WITH ORDINALITY AS supplied(token, ordinal)
             ), claimed AS (
                UPDATE scheduler_job_runs AS run
                SET status = 'dispatching', dispatch_lease_owner = $3,
                    dispatch_lease_token = supplied_tokens.token,
                    dispatch_lease_expires_at = clock.claimed_at + $4::bigint * INTERVAL '1 microsecond',
                    dispatch_attempt_count = run.dispatch_attempt_count + 1
                FROM numbered JOIN supplied_tokens USING (ordinal), clock
                WHERE run.id = numbered.id
                RETURNING run.*
             )
             SELECT * FROM claimed ORDER BY available_at, scheduled_for, id",
        )
        .bind(i64::try_from(self.config.dispatch_claim_batch).map_err(|_| SchedulerError::Database)?)
        .bind(tokens)
        .bind(&self.config.lease_owner)
        .bind(duration_micros(self.config.dispatch_lease_duration)?)
        .fetch_all(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        let claimed: Result<Vec<_>, _> = rows.iter().map(decode_leased_run).collect();
        let claimed = claimed?;
        counter!("omnius_scheduler_dispatch_claimed_total").increment(claimed.len() as u64);
        Ok(claimed)
    }

    /// Acknowledges provider acceptance only through the live dispatch fence.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::LostLease`] for an expired or replaced handoff.
    pub async fn mark_dispatched(&self, run: &LeasedRun) -> Result<(), SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let done = sqlx::query(
            "UPDATE scheduler_job_runs
             SET status = 'dispatched', dispatched_at = COALESCE(dispatched_at, clock_timestamp()),
                 dispatch_lease_owner = NULL, dispatch_lease_token = NULL,
                 dispatch_lease_expires_at = NULL, last_dispatch_error = NULL
             WHERE id = $1 AND job_id = $2 AND status = 'dispatching'
               AND dispatch_lease_token = $3 AND dispatch_lease_expires_at > clock_timestamp()",
        )
        .bind(run.id().as_uuid())
        .bind(run.job_id().as_uuid())
        .bind(run.fence().as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        affected(done.rows_affected())
    }

    /// Records a safe handoff failure, schedules a database-clock retry, and clears the fence.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::LostLease`] for a stale handoff.
    pub async fn mark_dispatch_retry(
        &self,
        run: &LeasedRun,
        failure_class: &'static str,
    ) -> Result<(), SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let done = sqlx::query(
            "UPDATE scheduler_job_runs
             SET status = 'pending_dispatch',
                 available_at = clock_timestamp() + $4::bigint * INTERVAL '1 microsecond',
                 last_dispatch_error = $5,
                 dispatch_lease_owner = NULL, dispatch_lease_token = NULL,
                 dispatch_lease_expires_at = NULL
             WHERE id = $1 AND job_id = $2 AND status = 'dispatching'
               AND dispatch_lease_token = $3 AND dispatch_lease_expires_at > clock_timestamp()",
        )
        .bind(run.id().as_uuid())
        .bind(run.job_id().as_uuid())
        .bind(run.fence().as_uuid())
        .bind(duration_micros(self.config.dispatch_retry_delay)?)
        .bind(failure_class)
        .execute(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        affected(done.rows_affected())
    }

    /// Hands one claimed exact envelope to a provider and performs a fenced acknowledgement.
    ///
    /// Ambiguous failures become a retry of the same durable bytes and job identity.
    ///
    /// # Errors
    ///
    /// Returns a safe provider or repository category after recording retry state when still owned.
    pub async fn dispatch_claimed(
        &self,
        run: &LeasedRun,
        enqueuer: &dyn JobEnqueuer,
    ) -> Result<(), SchedulerError> {
        let outcome = tokio::time::timeout(
            self.config.enqueue_timeout,
            enqueuer.enqueue(run.envelope().clone()),
        )
        .await;
        match outcome {
            Ok(Ok(receipt))
                if receipt.job_id() == run.job_id() && receipt.queue() == run.envelope.queue() =>
            {
                self.mark_dispatched(run).await
            }
            Ok(Ok(_)) => {
                self.mark_dispatch_retry(run, "receipt_mismatch").await?;
                Err(SchedulerError::Provider)
            }
            Ok(Err(error)) => {
                self.mark_dispatch_retry(run, enqueue_class(error)).await?;
                Err(SchedulerError::Provider)
            }
            Err(_) => {
                self.mark_dispatch_retry(run, "timeout").await?;
                Err(SchedulerError::Provider)
            }
        }
    }

    /// Reads one schedule without acquiring a durable lease.
    ///
    /// # Errors
    ///
    /// Returns a safe database or bounded decoding category.
    pub async fn schedule(
        &self,
        id: ScheduleId,
    ) -> Result<Option<ScheduleSnapshot>, SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let row = sqlx::query("SELECT * FROM scheduler_schedules WHERE id = $1")
            .bind(id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| SchedulerError::Database)?;
        row.as_ref().map(decode_snapshot).transpose()
    }

    /// Reads one durable run status by immutable job identity.
    ///
    /// # Errors
    ///
    /// Returns a safe database category.
    pub async fn run_status(
        &self,
        job_id: omnius_jobs_core::JobId,
    ) -> Result<Option<RunStatus>, SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let value: Option<String> =
            sqlx::query_scalar("SELECT status FROM scheduler_job_runs WHERE job_id = $1")
                .bind(job_id.as_uuid())
                .fetch_optional(&mut *connection)
                .await
                .map_err(|_| SchedulerError::Database)?;
        value.as_deref().map(RunStatus::from_database).transpose()
    }

    /// Reads low-cardinality point-in-time scheduler counts using the PostgreSQL clock.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Database`] when the snapshot cannot be read.
    pub async fn status(&self) -> Result<SchedulerStatus, SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let row = sqlx::query(
            "SELECT
                (SELECT count(*) FROM scheduler_schedules WHERE paused = false AND next_run_at <= clock_timestamp()) AS due_schedules,
                (SELECT count(*) FROM scheduler_job_runs WHERE status IN ('pending_dispatch', 'dispatching')) AS pending_dispatch,
                (SELECT count(*) FROM scheduler_job_runs WHERE status = 'running' AND execution_lease_expires_at > clock_timestamp()) AS active_executions,
                (SELECT count(*) FROM scheduler_job_runs WHERE status = 'failed') AS failed_runs",
        )
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        Ok(SchedulerStatus {
            due_schedules: count(&row, "due_schedules")?,
            pending_dispatch: count(&row, "pending_dispatch")?,
            active_executions: count(&row, "active_executions")?,
            failed_runs: count(&row, "failed_runs")?,
        })
    }

    /// Reads append-only audit history without exposing actor or reason through `Debug`.
    ///
    /// # Errors
    ///
    /// Returns a safe database or bounded decoding category.
    pub async fn audit_records(
        &self,
        schedule_id: ScheduleId,
    ) -> Result<Vec<AuditRecord>, SchedulerError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SchedulerError::Database)?;
        let rows = sqlx::query(
            "SELECT id, schedule_id, action, actor, reason, previous_revision, new_revision, occurred_at
             FROM scheduler_audit_events WHERE schedule_id = $1 ORDER BY occurred_at, id",
        )
        .bind(schedule_id.as_uuid())
        .fetch_all(&mut *connection)
        .await
        .map_err(|_| SchedulerError::Database)?;
        rows.iter().map(decode_audit).collect()
    }

    /// Builds the degraded runtime task when scheduling is enabled.
    #[must_use]
    pub fn task(
        &self,
        factory: Arc<dyn ScheduleEnvelopeFactory>,
        enqueuer: Arc<dyn JobEnqueuer>,
    ) -> Option<TaskSpec> {
        if !self.config.enabled {
            return None;
        }
        let scheduler = self.clone();
        Some(
            TaskSpec::new(
                TASK_NAME,
                MODULE_NAME,
                Criticality::Degraded,
                self.config.shutdown_timeout,
                move |context| {
                    let scheduler = scheduler.clone();
                    let factory = Arc::clone(&factory);
                    let enqueuer = Arc::clone(&enqueuer);
                    async move { run_task(scheduler, factory, enqueuer, context).await }
                },
            )
            .with_restart_policy(RestartPolicy::on_failure(
                self.config.restart.max_restarts,
                self.config.restart.initial_backoff,
                self.config.restart.max_backoff,
                self.config.restart.jitter_percent,
            )),
        )
    }
}

async fn run_task(
    scheduler: PostgresScheduler,
    factory: Arc<dyn ScheduleEnvelopeFactory>,
    enqueuer: Arc<dyn JobEnqueuer>,
    context: TaskContext,
) -> Result<(), ServiceError> {
    loop {
        context.heartbeat();
        if stopping(&context) {
            return Ok(());
        }
        let due_schedules = scheduler
            .claim_due_schedules()
            .await
            .map_err(|_| task_error())?;
        for schedule in &due_schedules {
            match scheduler.materialize_due(schedule, factory.as_ref()).await {
                Ok(_) | Err(SchedulerError::LostLease) => {}
                Err(_) => return Err(task_error()),
            }
            context.heartbeat();
        }
        if stopping(&context) {
            return Ok(());
        }
        let runs = scheduler
            .claim_pending_runs()
            .await
            .map_err(|_| task_error())?;
        for run in &runs {
            match scheduler.dispatch_claimed(run, enqueuer.as_ref()).await {
                Ok(()) | Err(SchedulerError::LostLease) => {}
                Err(_) => return Err(task_error()),
            }
            context.heartbeat();
        }
        if due_schedules.is_empty() && runs.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(scheduler.config.poll_interval) => {}
                () = context.draining() => return Ok(()),
                () = context.shutdown_requested() => return Ok(()),
                () = context.cancelled() => return Ok(()),
            }
        }
    }
}

fn stopping(context: &TaskContext) -> bool {
    context.is_draining() || context.is_shutdown_requested() || context.is_cancelled()
}

async fn insert_run(
    transaction: &mut Transaction<'_, Postgres>,
    id: ScheduledRunId,
    schedule_id: ScheduleId,
    scheduled_for: OffsetDateTime,
    replay_sequence: i32,
    replay_of: Option<Uuid>,
    envelope: &EncodedJobEnvelope,
) -> Result<(), SchedulerError> {
    if envelope.id().as_uuid().get_version_num() != 7 {
        return Err(SchedulerError::InvalidEnvelope);
    }
    let envelope_json =
        std::str::from_utf8(envelope.bytes()).map_err(|_| SchedulerError::InvalidEnvelope)?;
    sqlx::query(
        "INSERT INTO scheduler_job_runs (
            id, schedule_id, scheduled_for, replay_sequence, replay_of,
            job_id, queue, envelope_json, status
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending_dispatch')",
    )
    .bind(id.as_uuid())
    .bind(schedule_id.as_uuid())
    .bind(scheduled_for)
    .bind(replay_sequence)
    .bind(replay_of)
    .bind(envelope.id().as_uuid())
    .bind(envelope.queue().as_str())
    .bind(envelope_json)
    .execute(&mut **transaction)
    .await
    .map_err(|_| SchedulerError::Database)?;
    Ok(())
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    schedule_id: ScheduleId,
    action: &'static str,
    actor: &ScheduleActor,
    reason: &ScheduleReason,
    previous_revision: Option<i64>,
    new_revision: i64,
) -> Result<(), SchedulerError> {
    sqlx::query(
        "INSERT INTO scheduler_audit_events (
            id, schedule_id, action, actor, reason, previous_revision, new_revision
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(schedule_id.as_uuid())
    .bind(action)
    .bind(actor.as_str())
    .bind(reason.as_str())
    .bind(previous_revision)
    .bind(new_revision)
    .execute(&mut **transaction)
    .await
    .map_err(|_| SchedulerError::Database)?;
    Ok(())
}

async fn require_revision(
    transaction: &mut Transaction<'_, Postgres>,
    id: ScheduleId,
    row: Option<PgRow>,
) -> Result<PgRow, SchedulerError> {
    if let Some(row) = row {
        return Ok(row);
    }
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM scheduler_schedules WHERE id = $1)")
            .bind(id.as_uuid())
            .fetch_one(&mut **transaction)
            .await
            .map_err(|_| SchedulerError::Database)?;
    Err(if exists {
        SchedulerError::RevisionConflict
    } else {
        SchedulerError::NotFound
    })
}

fn decode_snapshot(row: &PgRow) -> Result<ScheduleSnapshot, SchedulerError> {
    let id = ScheduleId::from_database(row.try_get("id").map_err(|_| SchedulerError::Database)?)?;
    let name = ScheduleName::try_from(
        row.try_get::<String, _>("name")
            .map_err(|_| SchedulerError::Database)?,
    )
    .map_err(|_| SchedulerError::Database)?;
    let expression: String = row
        .try_get("cron_expression")
        .map_err(|_| SchedulerError::Database)?;
    let timezone: String = row
        .try_get("timezone")
        .map_err(|_| SchedulerError::Database)?;
    let policy: String = row
        .try_get("misfire_policy")
        .map_err(|_| SchedulerError::Database)?;
    let catch_up: Option<i32> = row
        .try_get("catch_up_max_runs")
        .map_err(|_| SchedulerError::Database)?;
    let max_concurrent: i32 = row
        .try_get("max_concurrent_runs")
        .map_err(|_| SchedulerError::Database)?;
    let max_concurrent = u16::try_from(max_concurrent)
        .ok()
        .and_then(std::num::NonZeroU16::new)
        .ok_or(SchedulerError::Database)?;
    let scheduler_lease: i64 = row
        .try_get("scheduler_lease_micros")
        .map_err(|_| SchedulerError::Database)?;
    let execution_lease: i64 = row
        .try_get("execution_lease_micros")
        .map_err(|_| SchedulerError::Database)?;
    let idempotency_window: i64 = row
        .try_get("idempotency_window_micros")
        .map_err(|_| SchedulerError::Database)?;
    let definition = ScheduleDefinition::new(
        name,
        expression,
        &timezone,
        MisfirePolicy::from_database(&policy, catch_up)?,
        max_concurrent,
        duration_from_micros(scheduler_lease)?,
        duration_from_micros(execution_lease)?,
        duration_from_micros(idempotency_window)?,
        row.try_get("paused")
            .map_err(|_| SchedulerError::Database)?,
    )
    .map_err(|_| SchedulerError::Database)?;
    Ok(ScheduleSnapshot {
        id,
        definition,
        revision: row
            .try_get("revision")
            .map_err(|_| SchedulerError::Database)?,
        next_run_at: row
            .try_get("next_run_at")
            .map_err(|_| SchedulerError::Database)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| SchedulerError::Database)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| SchedulerError::Database)?,
    })
}

fn decode_due(row: &PgRow) -> Result<DueSchedule, SchedulerError> {
    Ok(DueSchedule {
        snapshot: decode_snapshot(row)?,
        fence: ScheduleFence::from_database(
            row.try_get("lease_token")
                .map_err(|_| SchedulerError::Database)?,
        )?,
        claimed_at: row
            .try_get("claimed_at")
            .map_err(|_| SchedulerError::Database)?,
        lease_expires_at: row
            .try_get("lease_expires_at")
            .map_err(|_| SchedulerError::Database)?,
    })
}

fn decode_leased_run(row: &PgRow) -> Result<LeasedRun, SchedulerError> {
    let job_uuid: Uuid = row
        .try_get("job_id")
        .map_err(|_| SchedulerError::Database)?;
    let queue = QueueName::try_from(
        row.try_get::<String, _>("queue")
            .map_err(|_| SchedulerError::Database)?,
    )
    .map_err(|_| SchedulerError::InvalidEnvelope)?;
    let envelope_json: String = row
        .try_get("envelope_json")
        .map_err(|_| SchedulerError::Database)?;
    let envelope = EncodedJobEnvelope::restore(envelope_json.as_bytes(), queue.clone())
        .map_err(|_| SchedulerError::InvalidEnvelope)?;
    if envelope.id().as_uuid() != job_uuid {
        return Err(SchedulerError::InvalidEnvelope);
    }
    Ok(LeasedRun {
        id: ScheduledRunId::from_database(
            row.try_get("id").map_err(|_| SchedulerError::Database)?,
        )?,
        schedule_id: ScheduleId::from_database(
            row.try_get("schedule_id")
                .map_err(|_| SchedulerError::Database)?,
        )?,
        scheduled_for: row
            .try_get("scheduled_for")
            .map_err(|_| SchedulerError::Database)?,
        replay_sequence: u32::try_from(
            row.try_get::<i32, _>("replay_sequence")
                .map_err(|_| SchedulerError::Database)?,
        )
        .map_err(|_| SchedulerError::Database)?,
        job_id: envelope.id(),
        queue,
        envelope,
        attempt: u32::try_from(
            row.try_get::<i32, _>("dispatch_attempt_count")
                .map_err(|_| SchedulerError::Database)?,
        )
        .map_err(|_| SchedulerError::Database)?,
        fence: DispatchFence::from_database(
            row.try_get("dispatch_lease_token")
                .map_err(|_| SchedulerError::Database)?,
        )?,
        lease_expires_at: row
            .try_get("dispatch_lease_expires_at")
            .map_err(|_| SchedulerError::Database)?,
    })
}

fn decode_audit(row: &PgRow) -> Result<AuditRecord, SchedulerError> {
    Ok(AuditRecord {
        id: row.try_get("id").map_err(|_| SchedulerError::Database)?,
        schedule_id: ScheduleId::from_database(
            row.try_get("schedule_id")
                .map_err(|_| SchedulerError::Database)?,
        )?,
        action: row
            .try_get("action")
            .map_err(|_| SchedulerError::Database)?,
        actor: row.try_get("actor").map_err(|_| SchedulerError::Database)?,
        reason: row
            .try_get("reason")
            .map_err(|_| SchedulerError::Database)?,
        previous_revision: row
            .try_get("previous_revision")
            .map_err(|_| SchedulerError::Database)?,
        new_revision: row
            .try_get("new_revision")
            .map_err(|_| SchedulerError::Database)?,
        occurred_at: row
            .try_get("occurred_at")
            .map_err(|_| SchedulerError::Database)?,
    })
}

async fn finish<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, SchedulerError>,
) -> Result<T, SchedulerError> {
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

fn duration_micros(value: Duration) -> Result<i64, SchedulerError> {
    i64::try_from(value.as_micros()).map_err(|_| SchedulerError::Database)
}

fn duration_from_micros(value: i64) -> Result<Duration, SchedulerError> {
    u64::try_from(value)
        .map(Duration::from_micros)
        .map_err(|_| SchedulerError::Database)
}

fn count(row: &PgRow, column: &str) -> Result<u64, SchedulerError> {
    let value: i64 = row.try_get(column).map_err(|_| SchedulerError::Database)?;
    u64::try_from(value).map_err(|_| SchedulerError::Database)
}

fn affected(rows: u64) -> Result<(), SchedulerError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(SchedulerError::LostLease)
    }
}

fn enqueue_class(error: EnqueueError) -> &'static str {
    match error {
        EnqueueError::InvalidEnvelope => "invalid_envelope",
        EnqueueError::Capacity => "capacity",
        EnqueueError::Unavailable => "unavailable",
        EnqueueError::Rejected => "rejected",
    }
}

fn result_label<T>(result: &Result<T, SchedulerError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(SchedulerError::LostLease) => "lost_lease",
        Err(SchedulerError::RevisionConflict) => "revision_conflict",
        Err(SchedulerError::NotFound) => "not_found",
        Err(_) => "error",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    counter!("omnius_scheduler_operations_total", "operation" => operation, "result" => result)
        .increment(1);
    histogram!("omnius_scheduler_operation_duration_seconds", "operation" => operation)
        .record(elapsed.as_secs_f64());
}

fn task_error() -> ServiceError {
    ServiceError::new(task_error_code(), "scheduler task unavailable")
}

fn task_error_code() -> ErrorCode {
    match ErrorCode::try_new(TASK_ERROR_CODE) {
        Ok(code) => code,
        Err(_) => unreachable!("static scheduler error code must be valid"),
    }
}
