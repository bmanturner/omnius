use std::{fmt, num::NonZeroU16, str::FromStr as _, time::Duration};

use chrono_tz::Tz;
use rsk_jobs_core::{EncodedJobEnvelope, JobId, QueueName};
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_CLAIM_BATCH: usize = 256;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_ENQUEUE_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(3600);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_DISPATCH_LEASE: Duration = Duration::from_hours(24);
const MAX_RESTARTS: u32 = 100;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const MAX_SCHEDULE_LEASE: Duration = Duration::from_hours(24);
const MAX_EXECUTION_LEASE: Duration = Duration::from_hours(168);
const MAX_IDEMPOTENCY_WINDOW: Duration = Duration::from_hours(744);

fn portable(value: &str, minimum: usize, maximum: usize, allowed: impl Fn(u8) -> bool) -> bool {
    (minimum..=maximum).contains(&value.len())
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().iter().copied().all(allowed)
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn actor_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'@' | b'/' | b'-')
}

fn reason_ok(value: &str) -> bool {
    (1..=256).contains(&value.len()) && !value.bytes().any(|byte| byte.is_ascii_control())
}

macro_rules! uuid_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Returns the UUID value used by fenced repository calls.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            #[allow(
                dead_code,
                reason = "some UUIDv7 fence types are intentionally write-only"
            )]
            pub(crate) fn from_database(value: Uuid) -> Result<Self, SchedulerError> {
                if value.get_version_num() == 7 {
                    Ok(Self(value))
                } else {
                    Err(SchedulerError::Database)
                }
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&"[REDACTED]")
                    .finish()
            }
        }
    };
}

uuid_type!(ScheduleId, "A durable schedule `UUIDv7` identifier.");
uuid_type!(
    ScheduledRunId,
    "An immutable scheduled-run `UUIDv7` identifier."
);
uuid_type!(ScheduleFence, "A `UUIDv7` schedule-claim fence.");
uuid_type!(DispatchFence, "A `UUIDv7` pending-dispatch fence.");
uuid_type!(ExecutionFence, "A `UUIDv7` handler-execution fence.");

/// A stable portable schedule name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScheduleName(String);

impl ScheduleName {
    /// Borrows the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ScheduleName {
    type Error = SchedulerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if portable(value, 1, 128, name_byte) {
            Ok(Self(value.to_owned()))
        } else {
            Err(SchedulerError::InvalidDefinition)
        }
    }
}

impl TryFrom<String> for ScheduleName {
    type Error = SchedulerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if portable(&value, 1, 128, name_byte) {
            Ok(Self(value))
        } else {
            Err(SchedulerError::InvalidDefinition)
        }
    }
}

impl fmt::Debug for ScheduleName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduleName")
            .field("byte_len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A bounded audit actor identity.
#[derive(Clone, Eq, PartialEq)]
pub struct ScheduleActor(String);

impl ScheduleActor {
    /// Creates a validated actor identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidActor`] for non-portable or oversized input.
    pub fn new(value: impl Into<String>) -> Result<Self, SchedulerError> {
        let value = value.into();
        if portable(&value, 1, 128, actor_byte) {
            Ok(Self(value))
        } else {
            Err(SchedulerError::InvalidActor)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScheduleActor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScheduleActor([REDACTED])")
    }
}

/// A bounded audit reason whose value is always redacted from diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct ScheduleReason(String);

impl ScheduleReason {
    /// Creates a non-empty, control-free reason.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidReason`] for invalid input.
    pub fn new(value: impl Into<String>) -> Result<Self, SchedulerError> {
        let value = value.into();
        if reason_ok(&value) {
            Ok(Self(value))
        } else {
            Err(SchedulerError::InvalidReason)
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ScheduleReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ScheduleReason([REDACTED])")
    }
}

/// Deterministic policy applied to a due occurrence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MisfirePolicy {
    /// Advance to the first future occurrence without materializing a run.
    Skip,
    /// Materialize one run for the beginning of the missed window.
    FireOnce,
    /// Materialize exact missed instants in bounded batches.
    CatchUp {
        /// Maximum rows created by one schedule claim.
        max_runs: NonZeroU16,
    },
}

impl MisfirePolicy {
    pub(crate) fn database_parts(self) -> (&'static str, Option<i32>) {
        match self {
            Self::Skip => ("skip", None),
            Self::FireOnce => ("fire_once", None),
            Self::CatchUp { max_runs } => ("catch_up", Some(i32::from(max_runs.get()))),
        }
    }

    pub(crate) fn from_database(kind: &str, maximum: Option<i32>) -> Result<Self, SchedulerError> {
        match (kind, maximum) {
            ("skip", None) => Ok(Self::Skip),
            ("fire_once", None) => Ok(Self::FireOnce),
            ("catch_up", Some(value)) => {
                let value = u16::try_from(value).map_err(|_| SchedulerError::Database)?;
                let max_runs = NonZeroU16::new(value).ok_or(SchedulerError::Database)?;
                if max_runs.get() <= 1000 {
                    Ok(Self::CatchUp { max_runs })
                } else {
                    Err(SchedulerError::Database)
                }
            }
            _ => Err(SchedulerError::Database),
        }
    }
}

/// Validated immutable schedule policy used by create and update.
#[derive(Clone)]
pub struct ScheduleDefinition {
    name: ScheduleName,
    expression: String,
    timezone: Tz,
    misfire_policy: MisfirePolicy,
    max_concurrent_runs: NonZeroU16,
    scheduler_lease_duration: Duration,
    execution_lease_duration: Duration,
    idempotency_window: Duration,
    paused: bool,
}

impl ScheduleDefinition {
    /// Validates a Croner expression, IANA time zone, bounds, and lease policy.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::InvalidDefinition`] without retaining parser input.
    #[expect(
        clippy::too_many_arguments,
        reason = "all persisted schedule policy is explicit"
    )]
    pub fn new(
        name: ScheduleName,
        expression: impl Into<String>,
        timezone: &str,
        misfire_policy: MisfirePolicy,
        max_concurrent_runs: NonZeroU16,
        scheduler_lease_duration: Duration,
        execution_lease_duration: Duration,
        idempotency_window: Duration,
        paused: bool,
    ) -> Result<Self, SchedulerError> {
        let expression = expression.into();
        if !(1..=512).contains(&expression.len())
            || expression.bytes().any(|byte| byte.is_ascii_control())
            || croner::Cron::from_str(&expression).is_err()
        {
            return Err(SchedulerError::InvalidDefinition);
        }
        let timezone = Tz::from_str(timezone).map_err(|_| SchedulerError::InvalidDefinition)?;
        if max_concurrent_runs.get() > 1000
            || scheduler_lease_duration < Duration::from_secs(1)
            || scheduler_lease_duration > MAX_SCHEDULE_LEASE
            || execution_lease_duration < Duration::from_secs(2)
            || execution_lease_duration > MAX_EXECUTION_LEASE
            || idempotency_window < Duration::from_secs(1)
            || idempotency_window > MAX_IDEMPOTENCY_WINDOW
        {
            return Err(SchedulerError::InvalidDefinition);
        }
        if let MisfirePolicy::CatchUp { max_runs } = misfire_policy
            && max_runs.get() > 1000
        {
            return Err(SchedulerError::InvalidDefinition);
        }
        Ok(Self {
            name,
            expression,
            timezone,
            misfire_policy,
            max_concurrent_runs,
            scheduler_lease_duration,
            execution_lease_duration,
            idempotency_window,
            paused,
        })
    }

    /// Stable name.
    #[must_use]
    pub const fn name(&self) -> &ScheduleName {
        &self.name
    }

    /// Canonical Croner expression.
    #[must_use]
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// Canonical IANA time-zone name.
    #[must_use]
    pub fn timezone(&self) -> &'static str {
        self.timezone.name()
    }

    /// Parsed time zone used by the evaluator.
    #[must_use]
    pub const fn timezone_value(&self) -> Tz {
        self.timezone
    }

    /// Misfire policy.
    #[must_use]
    pub const fn misfire_policy(&self) -> MisfirePolicy {
        self.misfire_policy
    }

    /// Maximum simultaneously live executions for this schedule.
    #[must_use]
    pub const fn max_concurrent_runs(&self) -> NonZeroU16 {
        self.max_concurrent_runs
    }

    /// Schedule-claim lease duration.
    #[must_use]
    pub const fn scheduler_lease_duration(&self) -> Duration {
        self.scheduler_lease_duration
    }

    /// Handler execution lease duration.
    #[must_use]
    pub const fn execution_lease_duration(&self) -> Duration {
        self.execution_lease_duration
    }

    /// Persisted idempotency horizon. Exact cron instants are still always distinct identities.
    #[must_use]
    pub const fn idempotency_window(&self) -> Duration {
        self.idempotency_window
    }

    /// Initial or updated pause state.
    #[must_use]
    pub const fn paused(&self) -> bool {
        self.paused
    }
}

impl fmt::Debug for ScheduleDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduleDefinition")
            .field("name", &self.name)
            .field("expression", &"[REDACTED]")
            .field("timezone", &self.timezone.name())
            .field("misfire_policy", &self.misfire_policy)
            .field("max_concurrent_runs", &self.max_concurrent_runs)
            .field("scheduler_lease_duration", &self.scheduler_lease_duration)
            .field("execution_lease_duration", &self.execution_lease_duration)
            .field("idempotency_window", &self.idempotency_window)
            .field("paused", &self.paused)
            .finish()
    }
}

/// Bounded supervisor restart declaration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerRestartConfig {
    /// Maximum restarts inside the supervisor window.
    pub max_restarts: u32,
    /// Initial backoff.
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum backoff.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
    /// Symmetric jitter percentage.
    pub jitter_percent: u8,
}

impl Default for SchedulerRestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 8,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            jitter_percent: 20,
        }
    }
}

/// Hard-bounded scheduler leasing, dispatch, and lifecycle configuration.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SchedulerConfig {
    /// Enables runtime task registration. Repository administration remains available when disabled.
    pub enabled: bool,
    /// Static owner written to schedule and dispatch leases.
    pub lease_owner: String,
    /// Maximum schedules claimed in one database transition.
    pub schedule_claim_batch: usize,
    /// Maximum runs claimed for dispatch in one database transition.
    pub dispatch_claim_batch: usize,
    /// Delay after no work is found.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Deadline for one provider handoff.
    #[serde(with = "humantime_serde")]
    pub enqueue_timeout: Duration,
    /// Lease around a provider handoff; it must exceed the enqueue deadline.
    #[serde(with = "humantime_serde")]
    pub dispatch_lease_duration: Duration,
    /// Database-clock delay after a failed handoff.
    #[serde(with = "humantime_serde")]
    pub dispatch_retry_delay: Duration,
    /// Graceful task shutdown bound.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Supervisor restart declaration.
    pub restart: SchedulerRestartConfig,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lease_owner: "scheduler".to_owned(),
            schedule_claim_batch: 16,
            dispatch_claim_batch: 32,
            poll_interval: Duration::from_millis(250),
            enqueue_timeout: Duration::from_secs(5),
            dispatch_lease_duration: Duration::from_secs(30),
            dispatch_retry_delay: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(120),
            restart: SchedulerRestartConfig::default(),
        }
    }
}

impl SchedulerConfig {
    /// Validates every count, duration, owner, and restart bound.
    ///
    /// # Errors
    ///
    /// Returns a stable [`SchedulerConfigError`] category.
    pub fn validate(&self) -> Result<(), SchedulerConfigError> {
        if !portable(&self.lease_owner, 1, 128, actor_byte) {
            return Err(SchedulerConfigError::InvalidLeaseOwner);
        }
        if !(1..=MAX_CLAIM_BATCH).contains(&self.schedule_claim_batch) {
            return Err(SchedulerConfigError::InvalidScheduleClaimBatch);
        }
        if !(1..=MAX_CLAIM_BATCH).contains(&self.dispatch_claim_batch) {
            return Err(SchedulerConfigError::InvalidDispatchClaimBatch);
        }
        if self.poll_interval.is_zero() || self.poll_interval > MAX_POLL_INTERVAL {
            return Err(SchedulerConfigError::InvalidPollInterval);
        }
        if self.enqueue_timeout.is_zero() || self.enqueue_timeout > MAX_ENQUEUE_TIMEOUT {
            return Err(SchedulerConfigError::InvalidEnqueueTimeout);
        }
        if self.dispatch_lease_duration > MAX_DISPATCH_LEASE
            || self.dispatch_lease_duration
                < self.enqueue_timeout.saturating_add(Duration::from_secs(1))
        {
            return Err(SchedulerConfigError::InvalidDispatchLease);
        }
        if self.dispatch_retry_delay.is_zero() || self.dispatch_retry_delay > MAX_RETRY_DELAY {
            return Err(SchedulerConfigError::InvalidRetryDelay);
        }
        if self.shutdown_timeout.is_zero() || self.shutdown_timeout > MAX_SHUTDOWN_TIMEOUT {
            return Err(SchedulerConfigError::InvalidShutdownTimeout);
        }
        if self.restart.max_restarts > MAX_RESTARTS
            || self.restart.initial_backoff.is_zero()
            || self.restart.initial_backoff > self.restart.max_backoff
            || self.restart.max_backoff > MAX_BACKOFF
            || self.restart.jitter_percent > 100
        {
            return Err(SchedulerConfigError::InvalidRestart);
        }
        Ok(())
    }
}

impl fmt::Debug for SchedulerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulerConfig")
            .field("enabled", &self.enabled)
            .field("lease_owner", &"[REDACTED]")
            .field("schedule_claim_batch", &self.schedule_claim_batch)
            .field("dispatch_claim_batch", &self.dispatch_claim_batch)
            .field("poll_interval", &self.poll_interval)
            .field("enqueue_timeout", &self.enqueue_timeout)
            .field("dispatch_lease_duration", &self.dispatch_lease_duration)
            .field("dispatch_retry_delay", &self.dispatch_retry_delay)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("restart", &self.restart)
            .finish()
    }
}

/// Stable configuration failure categories.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SchedulerConfigError {
    /// Lease owner is not portable or bounded.
    #[error("scheduler lease owner is invalid")]
    InvalidLeaseOwner,
    /// Schedule claim batch is out of range.
    #[error("scheduler schedule claim batch is invalid")]
    InvalidScheduleClaimBatch,
    /// Dispatch claim batch is out of range.
    #[error("scheduler dispatch claim batch is invalid")]
    InvalidDispatchClaimBatch,
    /// Poll interval is out of range.
    #[error("scheduler poll interval is invalid")]
    InvalidPollInterval,
    /// Provider deadline is out of range.
    #[error("scheduler enqueue timeout is invalid")]
    InvalidEnqueueTimeout,
    /// Dispatch lease is inconsistent or out of range.
    #[error("scheduler dispatch lease is invalid")]
    InvalidDispatchLease,
    /// Dispatch retry delay is out of range.
    #[error("scheduler retry delay is invalid")]
    InvalidRetryDelay,
    /// Shutdown deadline is out of range.
    #[error("scheduler shutdown timeout is invalid")]
    InvalidShutdownTimeout,
    /// Restart declaration is invalid.
    #[error("scheduler restart policy is invalid")]
    InvalidRestart,
}

/// Safe scheduler failure categories with no SQL, parser, actor, reason, or payload data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SchedulerError {
    /// Schedule policy or calendar input is invalid.
    #[error("schedule definition is invalid")]
    InvalidDefinition,
    /// Audit actor input is invalid.
    #[error("schedule actor is invalid")]
    InvalidActor,
    /// Audit reason input is invalid.
    #[error("schedule reason is invalid")]
    InvalidReason,
    /// Calendar evaluation failed.
    #[error("schedule calendar evaluation failed")]
    Calendar,
    /// Envelope factory rejected the occurrence.
    #[error("scheduled job envelope generation failed")]
    EnvelopeFactory,
    /// Factory result was malformed, reused, or inconsistent.
    #[error("scheduled job envelope is invalid")]
    InvalidEnvelope,
    /// PostgreSQL acquisition, execution, or row decoding failed.
    #[error("scheduler database operation failed")]
    Database,
    /// Referenced durable schedule or run does not exist.
    #[error("scheduled resource was not found")]
    NotFound,
    /// Expected revision no longer owns the mutable schedule state.
    #[error("schedule revision conflict")]
    RevisionConflict,
    /// Lease is absent, expired, replaced, or already finalized.
    #[error("scheduler lease was lost")]
    LostLease,
    /// Provider handoff failed after durable retry state was recorded.
    #[error("scheduled job provider is unavailable")]
    Provider,
}

/// Safe envelope-factory failure classification.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EnvelopeFactoryError {
    /// Occurrence cannot be encoded as the declared job.
    #[error("scheduled envelope input is invalid")]
    Invalid,
    /// Factory dependency is temporarily unavailable.
    #[error("scheduled envelope factory is unavailable")]
    Unavailable,
}

/// Object-safe application boundary for a fresh validated job envelope.
pub trait ScheduleEnvelopeFactory: Send + Sync + 'static {
    /// Builds a new envelope for an exact intended occurrence or replay.
    ///
    /// The implementation must create a fresh job `UUIDv7` on every call. The scheduler rejects a
    /// job ID reused within a materialization batch and the database rejects reuse across batches.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeFactoryError`] when it cannot create a valid envelope.
    fn build(
        &self,
        schedule_id: ScheduleId,
        scheduled_for: OffsetDateTime,
        replay_sequence: u32,
    ) -> Result<EncodedJobEnvelope, EnvelopeFactoryError>;
}

/// Persisted schedule point-in-time state.
#[derive(Clone, Debug)]
pub struct ScheduleSnapshot {
    pub(crate) id: ScheduleId,
    pub(crate) definition: ScheduleDefinition,
    pub(crate) revision: i64,
    pub(crate) next_run_at: OffsetDateTime,
    pub(crate) created_at: OffsetDateTime,
    pub(crate) updated_at: OffsetDateTime,
}

impl ScheduleSnapshot {
    /// Schedule identifier.
    #[must_use]
    pub const fn id(&self) -> ScheduleId {
        self.id
    }
    /// Full validated definition.
    #[must_use]
    pub const fn definition(&self) -> &ScheduleDefinition {
        &self.definition
    }
    /// Optimistic concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }
    /// Next intended exact UTC occurrence.
    #[must_use]
    pub const fn next_run_at(&self) -> OffsetDateTime {
        self.next_run_at
    }
    /// Creation time from PostgreSQL.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
    /// Last mutation time from PostgreSQL.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// One live, fenced schedule claim.
#[derive(Clone, Debug)]
pub struct DueSchedule {
    pub(crate) snapshot: ScheduleSnapshot,
    pub(crate) fence: ScheduleFence,
    pub(crate) claimed_at: OffsetDateTime,
    pub(crate) lease_expires_at: OffsetDateTime,
}

impl DueSchedule {
    /// Claimed schedule state.
    #[must_use]
    pub const fn schedule(&self) -> &ScheduleSnapshot {
        &self.snapshot
    }
    /// Fence required to materialize and advance.
    #[must_use]
    pub const fn fence(&self) -> ScheduleFence {
        self.fence
    }
    /// PostgreSQL clock used as the deterministic misfire boundary.
    #[must_use]
    pub const fn claimed_at(&self) -> OffsetDateTime {
        self.claimed_at
    }
    /// PostgreSQL lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }
}

/// Durable run lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunStatus {
    /// Waiting for provider handoff.
    PendingDispatch,
    /// Provider handoff owns a live lease.
    Dispatching,
    /// Provider accepted the exact envelope.
    Dispatched,
    /// Handler owns a live execution fence.
    Running,
    /// Effect completed and duplicate deliveries are no-ops.
    Completed,
    /// Handler returned a permanent failure.
    Failed,
}

impl RunStatus {
    pub(crate) fn from_database(value: &str) -> Result<Self, SchedulerError> {
        match value {
            "pending_dispatch" => Ok(Self::PendingDispatch),
            "dispatching" => Ok(Self::Dispatching),
            "dispatched" => Ok(Self::Dispatched),
            "running" => Ok(Self::Running),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            _ => Err(SchedulerError::Database),
        }
    }
}

/// One pending provider handoff owned by a live dispatch fence.
#[derive(Clone)]
pub struct LeasedRun {
    pub(crate) id: ScheduledRunId,
    pub(crate) schedule_id: ScheduleId,
    pub(crate) scheduled_for: OffsetDateTime,
    pub(crate) replay_sequence: u32,
    pub(crate) job_id: JobId,
    pub(crate) queue: QueueName,
    pub(crate) envelope: EncodedJobEnvelope,
    pub(crate) attempt: u32,
    pub(crate) fence: DispatchFence,
    pub(crate) lease_expires_at: OffsetDateTime,
}

impl LeasedRun {
    /// Immutable run identifier.
    #[must_use]
    pub const fn id(&self) -> ScheduledRunId {
        self.id
    }
    /// Parent schedule.
    #[must_use]
    pub const fn schedule_id(&self) -> ScheduleId {
        self.schedule_id
    }
    /// Exact intended UTC instant.
    #[must_use]
    pub const fn scheduled_for(&self) -> OffsetDateTime {
        self.scheduled_for
    }
    /// Zero for normal occurrences and positive for replays.
    #[must_use]
    pub const fn replay_sequence(&self) -> u32 {
        self.replay_sequence
    }
    /// Exact persisted job identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
    /// Exact persisted validated envelope.
    #[must_use]
    pub const fn envelope(&self) -> &EncodedJobEnvelope {
        &self.envelope
    }
    /// One-based handoff attempt.
    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }
    /// Fence required for acknowledgement or retry.
    #[must_use]
    pub const fn fence(&self) -> DispatchFence {
        self.fence
    }
    /// PostgreSQL lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }
}

impl fmt::Debug for LeasedRun {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedRun")
            .field("id", &self.id)
            .field("schedule_id", &self.schedule_id)
            .field("scheduled_for", &self.scheduled_for)
            .field("replay_sequence", &self.replay_sequence)
            .field("job_id", &self.job_id)
            .field("queue", &self.queue)
            .field("envelope", &"[REDACTED]")
            .field("attempt", &self.attempt)
            .field("fence", &self.fence)
            .field("lease_expires_at", &self.lease_expires_at)
            .finish_non_exhaustive()
    }
}

/// Low-cardinality scheduler status snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulerStatus {
    /// Unpaused schedules currently due by the PostgreSQL clock.
    pub due_schedules: u64,
    /// Runs awaiting or retrying handoff.
    pub pending_dispatch: u64,
    /// Runs with a live execution fence.
    pub active_executions: u64,
    /// Permanently failed runs.
    pub failed_runs: u64,
}

/// Redacted append-only administration audit record.
#[derive(Clone)]
pub struct AuditRecord {
    pub(crate) id: Uuid,
    pub(crate) schedule_id: ScheduleId,
    pub(crate) action: String,
    pub(crate) actor: String,
    pub(crate) reason: String,
    pub(crate) previous_revision: Option<i64>,
    pub(crate) new_revision: i64,
    pub(crate) occurred_at: OffsetDateTime,
}

impl AuditRecord {
    /// Audit identifier.
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.id
    }
    /// Schedule identifier.
    #[must_use]
    pub const fn schedule_id(&self) -> ScheduleId {
        self.schedule_id
    }
    /// Validated actor that performed the operation.
    #[must_use]
    pub fn actor(&self) -> &str {
        &self.actor
    }
    /// Validated reason supplied for the operation.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
    /// Stable action category.
    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }
    /// Previous revision when the action mutated existing state.
    #[must_use]
    pub const fn previous_revision(&self) -> Option<i64> {
        self.previous_revision
    }
    /// Revision after the action. Replay records the unchanged schedule revision.
    #[must_use]
    pub const fn new_revision(&self) -> i64 {
        self.new_revision
    }
    /// PostgreSQL occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
}

impl fmt::Debug for AuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuditRecord")
            .field("id", &self.id)
            .field("schedule_id", &self.schedule_id)
            .field("action", &self.action)
            .field("actor", &"[REDACTED]")
            .field("reason", &"[REDACTED]")
            .field("previous_revision", &self.previous_revision)
            .field("new_revision", &self.new_revision)
            .field("occurred_at", &self.occurred_at)
            .finish()
    }
}
