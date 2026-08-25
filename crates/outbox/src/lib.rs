//! Transactional PostgreSQL outbox and bounded at-least-once relay.
//!
//! [`PostgresOutbox::append`] only inserts through a caller-owned connection. The caller therefore
//! decides whether business state and publication intent commit or roll back together. Relay
//! delivery is at least once: a publisher can observe a duplicate after lease expiry or process
//! restart, so downstream effects must be idempotent.

#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use futures::future::BoxFuture;
use metrics::{counter, histogram};
use rsk_core::{ErrorCode, ServiceError};
use rsk_jobs_core::{Destination, DomainEvent, EnvelopeError, EventEnvelope, EventId, EventLimits};
use rsk_postgres::PostgresPool;
use rsk_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use serde::Deserialize;
use serde_json::value::RawValue;
use sqlx::{PgConnection, Row as _, types::Json};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Static module metrics prefix.
pub const METRICS_PREFIX: &str = "rsk_outbox";
/// Stable supervisor catalog name for the relay.
pub const RELAY_TASK_NAME: &str = "outbox-relay";

const MODULE_NAME: &str = "outbox";
const RELAY_ERROR_CODE: &str = "OUTBOX_RELAY_UNAVAILABLE";
const MAX_CLAIM_BATCH: usize = 32;
const MAX_CLEANUP_BATCH: usize = 1_000;
const MAX_ATTEMPTS: u32 = 100;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_LEASE_DURATION: Duration = Duration::from_hours(1);
const MAX_PUBLICATION_TIMEOUT: Duration = Duration::from_mins(10);
const MAX_RETRY_DELAY: Duration = Duration::from_hours(24);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_hours(1);
const MIN_RETENTION: Duration = Duration::from_hours(1);
const MAX_RETENTION: Duration = Duration::from_hours(8_760);
const MAX_RESTARTS: u32 = 32;
const MAX_RESTART_BACKOFF: Duration = Duration::from_secs(60);
const MAX_JITTER_PERCENT: u8 = 50;
const MAX_EVENT_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Bounded supervisor restart declaration for the required relay task.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OutboxRestartConfig {
    /// Maximum restart attempts after the first run.
    pub max_restarts: u32,
    /// Delay before the first restart attempt.
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum exponential restart delay.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
    /// Symmetric supervisor jitter percentage.
    pub jitter_percent: u8,
}

impl Default for OutboxRestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 8,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            jitter_percent: 20,
        }
    }
}

/// Validated, hard-bounded outbox relay and retention policy.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OutboxConfig {
    /// Enables relay task registration. Transactional append remains available when disabled.
    pub enabled: bool,
    /// Static identity written into every lease owned by this relay instance.
    pub lease_owner: String,
    /// Maximum rows locked and returned by one atomic claim.
    pub claim_batch: usize,
    /// Delay after an empty claim.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Database-clock lease duration for a claimed batch.
    #[serde(with = "humantime_serde")]
    pub lease_duration: Duration,
    /// Deadline for one external publication attempt.
    #[serde(with = "humantime_serde")]
    pub publication_timeout: Duration,
    /// Database-clock delay before a failed event becomes available again.
    #[serde(with = "humantime_serde")]
    pub retry_delay: Duration,
    /// Supervisor deadline for graceful relay shutdown.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Events at this attempt count are no longer claimable.
    pub max_attempts: u32,
    /// Age after which published and exhausted records may be removed.
    #[serde(with = "humantime_serde")]
    pub retention: Duration,
    /// Maximum rows removed by one retention cleanup.
    pub cleanup_batch: usize,
    /// Bounded supervisor restart declaration.
    pub restart: OutboxRestartConfig,
}

impl Default for OutboxConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lease_owner: "outbox-relay".to_owned(),
            claim_batch: 16,
            poll_interval: Duration::from_millis(250),
            lease_duration: Duration::from_secs(120),
            publication_timeout: Duration::from_secs(5),
            retry_delay: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(120),
            max_attempts: 20,
            retention: Duration::from_hours(720),
            cleanup_batch: 500,
            restart: OutboxRestartConfig::default(),
        }
    }
}

impl fmt::Debug for OutboxConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxConfig")
            .field("enabled", &self.enabled)
            .field("lease_owner", &"[REDACTED]")
            .field("claim_batch", &self.claim_batch)
            .field("poll_interval", &self.poll_interval)
            .field("lease_duration", &self.lease_duration)
            .field("publication_timeout", &self.publication_timeout)
            .field("retry_delay", &self.retry_delay)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("max_attempts", &self.max_attempts)
            .field("retention", &self.retention)
            .field("cleanup_batch", &self.cleanup_batch)
            .field("restart", &self.restart)
            .finish()
    }
}

impl OutboxConfig {
    /// Validates every count, string, duration, retained-memory, and restart bound.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxConfigError`] when the policy cannot safely bound a relay attempt.
    pub fn validate(&self) -> Result<(), OutboxConfigError> {
        if !portable_owner(&self.lease_owner) {
            return Err(OutboxConfigError::InvalidLeaseOwner);
        }
        if !(1..=MAX_CLAIM_BATCH).contains(&self.claim_batch) {
            return Err(OutboxConfigError::InvalidClaimBatch);
        }
        if self.poll_interval.is_zero() || self.poll_interval > MAX_POLL_INTERVAL {
            return Err(OutboxConfigError::InvalidPollInterval);
        }
        if self.publication_timeout.is_zero() || self.publication_timeout > MAX_PUBLICATION_TIMEOUT
        {
            return Err(OutboxConfigError::InvalidPublicationTimeout);
        }
        if self.retry_delay.is_zero() || self.retry_delay > MAX_RETRY_DELAY {
            return Err(OutboxConfigError::InvalidRetryDelay);
        }
        let batch_window = self
            .publication_timeout
            .checked_mul(
                u32::try_from(self.claim_batch)
                    .map_err(|_| OutboxConfigError::InvalidClaimBatch)?,
            )
            .and_then(|duration| duration.checked_add(Duration::from_secs(1)))
            .ok_or(OutboxConfigError::InvalidLeaseDuration)?;
        if self.lease_duration < batch_window || self.lease_duration > MAX_LEASE_DURATION {
            return Err(OutboxConfigError::InvalidLeaseDuration);
        }
        if self.shutdown_timeout < batch_window || self.shutdown_timeout > MAX_SHUTDOWN_TIMEOUT {
            return Err(OutboxConfigError::InvalidShutdownTimeout);
        }
        if !(1..=MAX_ATTEMPTS).contains(&self.max_attempts) {
            return Err(OutboxConfigError::InvalidMaxAttempts);
        }
        if !(MIN_RETENTION..=MAX_RETENTION).contains(&self.retention) {
            return Err(OutboxConfigError::InvalidRetention);
        }
        if !(1..=MAX_CLEANUP_BATCH).contains(&self.cleanup_batch) {
            return Err(OutboxConfigError::InvalidCleanupBatch);
        }
        if !(1..=MAX_RESTARTS).contains(&self.restart.max_restarts)
            || self.restart.initial_backoff.is_zero()
            || self.restart.initial_backoff > self.restart.max_backoff
            || self.restart.max_backoff > MAX_RESTART_BACKOFF
            || self.restart.jitter_percent > MAX_JITTER_PERCENT
        {
            return Err(OutboxConfigError::InvalidRestartPolicy);
        }
        Ok(())
    }
}

/// Invalid bounded outbox composition policy.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OutboxConfigError {
    /// Lease owner was empty, oversized, or outside its portable grammar.
    #[error("outbox lease owner is invalid")]
    InvalidLeaseOwner,
    /// Claim row count was zero or exceeded its fixed memory bound.
    #[error("outbox claim batch is invalid")]
    InvalidClaimBatch,
    /// Empty-poll delay was zero or too large.
    #[error("outbox poll interval is invalid")]
    InvalidPollInterval,
    /// Lease cannot cover every sequential publication in one batch.
    #[error("outbox lease duration is invalid")]
    InvalidLeaseDuration,
    /// Per-publication deadline was zero or too large.
    #[error("outbox publication timeout is invalid")]
    InvalidPublicationTimeout,
    /// Retry delay was zero or too large.
    #[error("outbox retry delay is invalid")]
    InvalidRetryDelay,
    /// Shutdown cannot cover every sequential publication in one batch.
    #[error("outbox shutdown timeout is invalid")]
    InvalidShutdownTimeout,
    /// Attempt limit was zero or too large.
    #[error("outbox maximum attempts is invalid")]
    InvalidMaxAttempts,
    /// Retention period was outside the fixed safety policy.
    #[error("outbox retention is invalid")]
    InvalidRetention,
    /// Cleanup row count was zero or too large.
    #[error("outbox cleanup batch is invalid")]
    InvalidCleanupBatch,
    /// Restart count, delay, or jitter was outside its fixed bound.
    #[error("outbox restart policy is invalid")]
    InvalidRestartPolicy,
}

/// Portable, bounded failure classification safe for storage and metrics mapping.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FailureClass(String);

impl FailureClass {
    /// Borrows the safe class.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn timeout() -> Self {
        Self("timeout".to_owned())
    }
}

impl TryFrom<&str> for FailureClass {
    type Error = FailureClassError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !portable_lower(value, 64) {
            return Err(FailureClassError);
        }
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for FailureClass {
    type Error = FailureClassError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if !portable_lower(&value, 64) {
            return Err(FailureClassError);
        }
        Ok(Self(value))
    }
}

impl fmt::Display for FailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl fmt::Debug for FailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("FailureClass")
            .field(&self.0)
            .finish()
    }
}

/// Rejected unsafe failure class.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("outbox failure class is invalid")]
pub struct FailureClassError;

/// Safe external publisher failure. Provider diagnostics are deliberately not retained.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("outbox publication failed with class {class}")]
pub struct PublishError {
    class: FailureClass,
}

impl PublishError {
    /// Creates a failure from a bounded, operator-safe class.
    #[must_use]
    pub const fn new(class: FailureClass) -> Self {
        Self { class }
    }

    /// Returns the safe retry classification.
    #[must_use]
    pub const fn class(&self) -> &FailureClass {
        &self.class
    }
}

/// Object-safe adapter boundary for later external publication providers.
pub trait OutboxPublisher: Send + Sync + 'static {
    /// Publishes one claimed event. Implementations must use the event ID as their idempotency key.
    fn publish<'event>(
        &'event self,
        event: &'event LeasedOutboxEvent,
    ) -> BoxFuture<'event, Result<(), PublishError>>;
}

/// Opaque `UUIDv7` lease fence.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct LeaseToken(Uuid);

impl LeaseToken {
    /// Returns the UUID value for propagation to fenced repository calls.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }

    fn from_database(value: Uuid) -> Result<Self, OutboxError> {
        if value.get_version_num() == 7 {
            Ok(Self(value))
        } else {
            Err(OutboxError::Database)
        }
    }
}

impl fmt::Debug for LeaseToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LeaseToken")
            .field(&"[REDACTED]")
            .finish()
    }
}

/// One bounded row owned through a live lease token.
pub struct LeasedOutboxEvent {
    id: EventId,
    aggregate_type: String,
    aggregate_id: String,
    event_type: String,
    event_version: u16,
    source: String,
    subject: String,
    tenant_id: Option<Uuid>,
    occurred_at: OffsetDateTime,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    traceparent: Option<String>,
    payload: Box<RawValue>,
    destination: String,
    available_at: OffsetDateTime,
    attempt_count: u32,
    lease_owner: String,
    lease_token: LeaseToken,
    lease_expires_at: OffsetDateTime,
}

impl LeasedOutboxEvent {
    /// Stable domain event identifier.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }
    /// Validated aggregate kind.
    #[must_use]
    pub fn aggregate_type(&self) -> &str {
        &self.aggregate_type
    }
    /// Bounded aggregate identifier.
    #[must_use]
    pub fn aggregate_id(&self) -> &str {
        &self.aggregate_id
    }
    /// Stable event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }
    /// Event schema version.
    #[must_use]
    pub const fn event_version(&self) -> u16 {
        self.event_version
    }
    /// Producer identity.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }
    /// Event subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Optional tenant UUID.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<Uuid> {
        self.tenant_id
    }
    /// Domain occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
    /// Correlation UUID.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
    /// Optional cause UUID.
    #[must_use]
    pub const fn causation_id(&self) -> Option<Uuid> {
        self.causation_id
    }
    /// Optional W3C trace context.
    #[must_use]
    pub fn traceparent(&self) -> Option<&str> {
        self.traceparent.as_deref()
    }
    /// Exact bounded JSON object read from JSONB.
    #[must_use]
    pub fn payload_json(&self) -> &RawValue {
        &self.payload
    }
    /// External destination selected by application composition.
    #[must_use]
    pub fn destination(&self) -> &str {
        &self.destination
    }
    /// Database availability time used for claim ordering.
    #[must_use]
    pub const fn available_at(&self) -> OffsetDateTime {
        self.available_at
    }
    /// Attempt number incremented by this claim.
    #[must_use]
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }
    /// Static lease owner identity.
    #[must_use]
    pub fn lease_owner(&self) -> &str {
        &self.lease_owner
    }
    /// Fence required for publication and failure transitions.
    #[must_use]
    pub const fn lease_token(&self) -> LeaseToken {
        self.lease_token
    }
    /// Database-clock lease expiry.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }
}

impl fmt::Debug for LeasedOutboxEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LeasedOutboxEvent")
            .field("id", &self.id)
            .field("event_type", &self.event_type)
            .field("event_version", &self.event_version)
            .field("occurred_at", &self.occurred_at)
            .field("correlation_id", &self.correlation_id)
            .field("has_causation", &self.causation_id.is_some())
            .field("has_tenant", &self.tenant_id.is_some())
            .field("has_traceparent", &self.traceparent.is_some())
            .field("payload_bytes", &self.payload.get().len())
            .field("attempt_count", &self.attempt_count)
            .field("lease_token", &self.lease_token)
            .field("lease_expires_at", &self.lease_expires_at)
            .finish_non_exhaustive()
    }
}

/// Safe outbox repository failure with no SQL or provider diagnostic retention.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OutboxError {
    /// Aggregate type was empty, oversized, or outside the database grammar.
    #[error("outbox aggregate type is invalid")]
    InvalidAggregateType,
    /// Aggregate identifier was empty, oversized, or contained control bytes.
    #[error("outbox aggregate identifier is invalid")]
    InvalidAggregateId,
    /// Event schema version cannot be represented by the durable schema.
    #[error("outbox event version is invalid")]
    InvalidEventVersion,
    /// Event envelope failed bounded canonical encoding.
    #[error("outbox event encoding failed")]
    Encode,
    /// Retry delay was zero or exceeded its fixed bound.
    #[error("outbox retry delay is invalid")]
    InvalidRetryDelay,
    /// The supplied lease is expired, replaced, published, or absent.
    #[error("outbox lease was lost")]
    LostLease,
    /// PostgreSQL acquisition, execution, or bounded row decoding failed.
    #[error("outbox database operation failed")]
    Database,
}

impl From<EnvelopeError> for OutboxError {
    fn from(_: EnvelopeError) -> Self {
        Self::Encode
    }
}

/// Cloneable PostgreSQL repository and relay registration.
#[derive(Clone)]
pub struct PostgresOutbox {
    pool: PostgresPool,
    config: OutboxConfig,
}

impl fmt::Debug for PostgresOutbox {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresOutbox")
            .field("pool", &self.pool)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PostgresOutbox {
    /// Creates a repository after validating all relay and retention bounds.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxConfigError`] when any policy is unbounded or inconsistent.
    pub fn new(pool: PostgresPool, config: OutboxConfig) -> Result<Self, OutboxConfigError> {
        config.validate()?;
        Ok(Self { pool, config })
    }

    /// Encodes and appends one event through the caller's existing transaction connection.
    ///
    /// This method never starts, commits, rolls back, or retries a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError`] for invalid aggregate data, bounded envelope encoding, or insertion.
    #[expect(
        clippy::too_many_arguments,
        reason = "the transactional intent makes every indexed event dimension explicit"
    )]
    pub async fn append<E: DomainEvent>(
        &self,
        connection: &mut PgConnection,
        envelope: &EventEnvelope<E>,
        aggregate_type: &str,
        aggregate_id: &str,
        destination: &Destination,
        available_at: OffsetDateTime,
        limits: EventLimits,
    ) -> Result<EventId, OutboxError> {
        if !portable_lower(aggregate_type, 128) {
            return Err(OutboxError::InvalidAggregateType);
        }
        if !bounded_identifier(aggregate_id, 256) {
            return Err(OutboxError::InvalidAggregateId);
        }
        let event_version = i16::try_from(envelope.version().get())
            .map_err(|_| OutboxError::InvalidEventVersion)?;
        let payload =
            String::from_utf8(envelope.encode(limits)?).map_err(|_| OutboxError::Encode)?;
        let tenant_id = envelope
            .tenant_id()
            .map(|tenant| Uuid::parse_str(tenant.as_str()).map_err(|_| OutboxError::Encode))
            .transpose()?;
        let started = Instant::now();
        let result = sqlx::query(
            "INSERT INTO outbox_events (
                id, aggregate_type, aggregate_id, event_type, event_version, source, subject,
                tenant_id, occurred_at, correlation_id, causation_id, traceparent, payload,
                destination, available_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::jsonb, $14, $15
             )",
        )
        .bind(envelope.id().as_uuid())
        .bind(aggregate_type)
        .bind(aggregate_id)
        .bind(envelope.event_name().as_str())
        .bind(event_version)
        .bind(envelope.source().as_str())
        .bind(envelope.subject().as_str())
        .bind(tenant_id)
        .bind(envelope.occurred_at())
        .bind(envelope.correlation_id())
        .bind(envelope.causation_id())
        .bind(
            envelope
                .traceparent()
                .map(rsk_jobs_core::Traceparent::as_str),
        )
        .bind(payload)
        .bind(destination.as_str())
        .bind(available_at)
        .execute(connection)
        .await
        .map(|_| envelope.id())
        .map_err(|_| OutboxError::Database);
        record_operation("append", result_label(&result), started.elapsed());
        if result.is_ok() {
            counter!("rsk_outbox_appended_total").increment(1);
        }
        result
    }

    /// Atomically leases an ordered, disjoint batch through the owned pool.
    ///
    /// PostgreSQL `clock_timestamp()` controls eligibility and expiry. Each row receives a distinct
    /// application-generated `UUIDv7` fence in one CTE statement.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError::Database`] for acquisition, execution, or bounded decoding failure.
    pub async fn claim(&self) -> Result<Vec<LeasedOutboxEvent>, OutboxError> {
        let started = Instant::now();
        let mut tokens = Vec::with_capacity(self.config.claim_batch);
        for _ in 0..self.config.claim_batch {
            tokens.push(Uuid::now_v7());
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OutboxError::Database)?;
        let rows = sqlx::query(
            "WITH locked AS (
                SELECT id, available_at, occurred_at
                FROM outbox_events
                WHERE published_at IS NULL
                  AND available_at <= clock_timestamp()
                  AND attempt_count < $1
                  AND (lease_expires_at IS NULL OR lease_expires_at <= clock_timestamp())
                ORDER BY available_at, occurred_at, id
                FOR UPDATE SKIP LOCKED
                LIMIT $2
             ), numbered AS (
                SELECT id, row_number() OVER (ORDER BY available_at, occurred_at, id) AS ordinal
                FROM locked
             ), supplied_tokens AS (
                SELECT token, ordinal
                FROM unnest($3::uuid[]) WITH ORDINALITY AS supplied(token, ordinal)
             ), claimed AS (
                UPDATE outbox_events AS event
                SET lease_owner = $4,
                    lease_token = supplied_tokens.token,
                    lease_expires_at = clock_timestamp() + $5::bigint * INTERVAL '1 microsecond',
                    attempt_count = event.attempt_count + 1
                FROM numbered
                JOIN supplied_tokens USING (ordinal)
                WHERE event.id = numbered.id
                RETURNING event.*
             )
             SELECT * FROM claimed ORDER BY available_at, occurred_at, id",
        )
        .bind(i32::try_from(self.config.max_attempts).map_err(|_| OutboxError::Database)?)
        .bind(i64::try_from(self.config.claim_batch).map_err(|_| OutboxError::Database)?)
        .bind(tokens)
        .bind(&self.config.lease_owner)
        .bind(duration_micros(self.config.lease_duration))
        .fetch_all(&mut *connection)
        .await
        .map_err(|_| OutboxError::Database);
        let result: Result<Vec<LeasedOutboxEvent>, OutboxError> = match rows {
            Ok(rows) => rows.iter().map(decode_claimed).collect(),
            Err(error) => Err(error),
        };
        record_operation("claim", result_label(&result), started.elapsed());
        if let Ok(events) = &result {
            counter!("rsk_outbox_claimed_total").increment(events.len() as u64);
        }
        result
    }

    /// Marks a live fenced lease published using the PostgreSQL clock and clears the lease.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError::LostLease`] when the token is stale or expired.
    pub async fn mark_published(&self, id: EventId, token: LeaseToken) -> Result<(), OutboxError> {
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OutboxError::Database)?;
        let result = sqlx::query(
            "UPDATE outbox_events
             SET published_at = clock_timestamp(),
                 lease_owner = NULL,
                 lease_token = NULL,
                 lease_expires_at = NULL,
                 last_error_class = NULL
             WHERE id = $1
               AND published_at IS NULL
               AND lease_token = $2
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(id.as_uuid())
        .bind(token.as_uuid())
        .execute(&mut *connection)
        .await
        .map_err(|_| OutboxError::Database)
        .and_then(|done| {
            if done.rows_affected() == 1 {
                Ok(())
            } else {
                Err(OutboxError::LostLease)
            }
        });
        record_operation("mark_published", result_label(&result), started.elapsed());
        result
    }

    /// Records a safe failure, schedules the next attempt from the PostgreSQL clock, and clears the
    /// live fenced lease.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError::InvalidRetryDelay`], [`OutboxError::LostLease`], or a database error.
    pub async fn mark_failed(
        &self,
        id: EventId,
        token: LeaseToken,
        class: &FailureClass,
        retry_delay: Duration,
    ) -> Result<(), OutboxError> {
        if retry_delay.is_zero() || retry_delay > MAX_RETRY_DELAY {
            return Err(OutboxError::InvalidRetryDelay);
        }
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OutboxError::Database)?;
        let result = sqlx::query(
            "UPDATE outbox_events
             SET last_error_class = $3,
                 available_at = clock_timestamp() + $4::bigint * INTERVAL '1 microsecond',
                 lease_owner = NULL,
                 lease_token = NULL,
                 lease_expires_at = NULL
             WHERE id = $1
               AND published_at IS NULL
               AND lease_token = $2
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(id.as_uuid())
        .bind(token.as_uuid())
        .bind(class.as_str())
        .bind(duration_micros(retry_delay))
        .execute(&mut *connection)
        .await
        .map_err(|_| OutboxError::Database)
        .and_then(|done| {
            if done.rows_affected() == 1 {
                Ok(())
            } else {
                Err(OutboxError::LostLease)
            }
        });
        record_operation("mark_failed", result_label(&result), started.elapsed());
        result
    }

    /// Deletes at most the configured batch of unleased published or exhausted retained records.
    ///
    /// # Errors
    ///
    /// Returns [`OutboxError::Database`] when cleanup cannot acquire or execute.
    pub async fn cleanup_retained(&self) -> Result<u64, OutboxError> {
        let started = Instant::now();
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OutboxError::Database)?;
        let result = sqlx::query(
            "WITH candidates AS (
                SELECT id
                FROM outbox_events
                WHERE (lease_token IS NULL OR lease_expires_at <= clock_timestamp())
                  AND (
                    (published_at IS NOT NULL
                     AND published_at < clock_timestamp() - $1::bigint * INTERVAL '1 microsecond')
                    OR
                    (published_at IS NULL
                     AND attempt_count >= $2
                     AND available_at < clock_timestamp() - $1::bigint * INTERVAL '1 microsecond')
                  )
                ORDER BY COALESCE(published_at, available_at), id
                FOR UPDATE SKIP LOCKED
                LIMIT $3
             )
             DELETE FROM outbox_events AS event
             USING candidates
             WHERE event.id = candidates.id",
        )
        .bind(duration_micros(self.config.retention))
        .bind(i32::try_from(self.config.max_attempts).map_err(|_| OutboxError::Database)?)
        .bind(i64::try_from(self.config.cleanup_batch).map_err(|_| OutboxError::Database)?)
        .execute(&mut *connection)
        .await
        .map(|done| done.rows_affected())
        .map_err(|_| OutboxError::Database);
        record_operation("cleanup", result_label(&result), started.elapsed());
        if let Ok(rows) = result {
            counter!("rsk_outbox_cleaned_total").increment(rows);
            Ok(rows)
        } else {
            result
        }
    }

    /// Builds the required `outbox-relay` catalog task when relay is enabled.
    #[must_use]
    pub fn relay_task(&self, publisher: Arc<dyn OutboxPublisher>) -> Option<TaskSpec> {
        if !self.config.enabled {
            return None;
        }
        let outbox = self.clone();
        Some(
            TaskSpec::new(
                RELAY_TASK_NAME,
                MODULE_NAME,
                Criticality::Required,
                self.config.shutdown_timeout,
                move |context| {
                    let outbox = outbox.clone();
                    let publisher = Arc::clone(&publisher);
                    async move { run_relay(outbox, publisher, context).await }
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

async fn run_relay(
    outbox: PostgresOutbox,
    publisher: Arc<dyn OutboxPublisher>,
    context: TaskContext,
) -> Result<(), ServiceError> {
    loop {
        context.heartbeat();
        if context.is_draining() || context.is_shutdown_requested() || context.is_cancelled() {
            await_shutdown(&context).await;
            return Ok(());
        }
        let events = outbox.claim().await.map_err(|_| relay_error())?;
        if events.is_empty() {
            tokio::select! {
                () = tokio::time::sleep(outbox.config.poll_interval) => {}
                () = context.draining() => {
                    await_shutdown(&context).await;
                    return Ok(());
                }
                () = context.shutdown_requested() => return Ok(()),
                () = context.cancelled() => return Ok(()),
            }
            continue;
        }
        for event in events {
            let publication =
                tokio::time::timeout(outbox.config.publication_timeout, publisher.publish(&event))
                    .await;
            match publication {
                Ok(Ok(())) => match outbox.mark_published(event.id(), event.lease_token()).await {
                    Ok(()) => record_publish("ok"),
                    Err(OutboxError::LostLease) => record_publish("lost_lease"),
                    Err(_) => return Err(relay_error()),
                },
                Ok(Err(error)) => {
                    match outbox
                        .mark_failed(
                            event.id(),
                            event.lease_token(),
                            error.class(),
                            outbox.config.retry_delay,
                        )
                        .await
                    {
                        Ok(()) => record_publish("error"),
                        Err(OutboxError::LostLease) => record_publish("lost_lease"),
                        Err(_) => return Err(relay_error()),
                    }
                }
                Err(_) => {
                    match outbox
                        .mark_failed(
                            event.id(),
                            event.lease_token(),
                            &FailureClass::timeout(),
                            outbox.config.retry_delay,
                        )
                        .await
                    {
                        Ok(()) => record_publish("timeout"),
                        Err(OutboxError::LostLease) => record_publish("lost_lease"),
                        Err(_) => return Err(relay_error()),
                    }
                }
            }
            context.heartbeat();
        }
    }
}

async fn await_shutdown(context: &TaskContext) {
    if context.is_shutdown_requested() || context.is_cancelled() {
        return;
    }
    tokio::select! {
        () = context.shutdown_requested() => {}
        () = context.cancelled() => {}
    }
}

fn decode_claimed(row: &sqlx::postgres::PgRow) -> Result<LeasedOutboxEvent, OutboxError> {
    let id: Uuid = row.try_get("id").map_err(|_| OutboxError::Database)?;
    let aggregate_type: String = row
        .try_get("aggregate_type")
        .map_err(|_| OutboxError::Database)?;
    let aggregate_id: String = row
        .try_get("aggregate_id")
        .map_err(|_| OutboxError::Database)?;
    let event_type: String = row
        .try_get("event_type")
        .map_err(|_| OutboxError::Database)?;
    let event_version: i16 = row
        .try_get("event_version")
        .map_err(|_| OutboxError::Database)?;
    let source: String = row.try_get("source").map_err(|_| OutboxError::Database)?;
    let subject: String = row.try_get("subject").map_err(|_| OutboxError::Database)?;
    let tenant_id: Option<Uuid> = row
        .try_get("tenant_id")
        .map_err(|_| OutboxError::Database)?;
    let occurred_at = row
        .try_get("occurred_at")
        .map_err(|_| OutboxError::Database)?;
    let correlation_id: Uuid = row
        .try_get("correlation_id")
        .map_err(|_| OutboxError::Database)?;
    let causation_id: Option<Uuid> = row
        .try_get("causation_id")
        .map_err(|_| OutboxError::Database)?;
    let traceparent: Option<String> = row
        .try_get("traceparent")
        .map_err(|_| OutboxError::Database)?;
    let Json(payload): Json<Box<RawValue>> =
        row.try_get("payload").map_err(|_| OutboxError::Database)?;
    let destination: String = row
        .try_get("destination")
        .map_err(|_| OutboxError::Database)?;
    let available_at = row
        .try_get("available_at")
        .map_err(|_| OutboxError::Database)?;
    let attempt_count: i32 = row
        .try_get("attempt_count")
        .map_err(|_| OutboxError::Database)?;
    let lease_owner: String = row
        .try_get("lease_owner")
        .map_err(|_| OutboxError::Database)?;
    let lease_token: Uuid = row
        .try_get("lease_token")
        .map_err(|_| OutboxError::Database)?;
    let lease_expires_at = row
        .try_get("lease_expires_at")
        .map_err(|_| OutboxError::Database)?;

    if !portable_lower(&aggregate_type, 128)
        || !bounded_identifier(&aggregate_id, 256)
        || !portable_lower(&event_type, 128)
        || event_version <= 0
        || !portable_source(&source)
        || !portable_subject(&subject)
        || !portable_destination(&destination)
        || !portable_owner(&lease_owner)
        || payload.get().len() > MAX_EVENT_JSON_BYTES
        || !payload.get().trim_start().starts_with('{')
        || attempt_count <= 0
        || tenant_id.is_some_and(|value| value.get_version_num() != 7)
        || correlation_id.get_version_num() != 7
        || causation_id.is_some_and(|value| !value.is_nil() && value.get_version_num() != 7)
        || traceparent
            .as_deref()
            .is_some_and(|value| !valid_traceparent(value))
    {
        return Err(OutboxError::Database);
    }

    Ok(LeasedOutboxEvent {
        id: EventId::from_uuid(id).map_err(|_| OutboxError::Database)?,
        aggregate_type,
        aggregate_id,
        event_type,
        event_version: u16::try_from(event_version).map_err(|_| OutboxError::Database)?,
        source,
        subject,
        tenant_id,
        occurred_at,
        correlation_id,
        causation_id,
        traceparent,
        payload,
        destination,
        available_at,
        attempt_count: u32::try_from(attempt_count).map_err(|_| OutboxError::Database)?,
        lease_owner,
        lease_token: LeaseToken::from_database(lease_token)?,
        lease_expires_at,
    })
}

fn portable_lower(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
}

fn portable_owner(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn portable_source(value: &str) -> bool {
    portable_owner(value)
}

fn portable_subject(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')
        })
}

fn portable_destination(value: &str) -> bool {
    portable_subject(value)
}

fn bounded_identifier(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn valid_traceparent(value: &str) -> bool {
    if value.len() != 55 {
        return false;
    }
    let bytes = value.as_bytes();
    &bytes[..2] == b"00"
        && bytes[2] == b'-'
        && bytes[35] == b'-'
        && bytes[52] == b'-'
        && bytes
            .iter()
            .enumerate()
            .filter(|(index, _)| !matches!(index, 2 | 35 | 52))
            .all(|(_, byte)| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && !bytes[3..35].iter().all(|byte| *byte == b'0')
        && !bytes[36..52].iter().all(|byte| *byte == b'0')
}

fn duration_micros(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

fn relay_error() -> ServiceError {
    ServiceError::new(relay_error_code(), "outbox relay unavailable")
}

fn relay_error_code() -> ErrorCode {
    match ErrorCode::try_new(RELAY_ERROR_CODE) {
        Ok(code) => code,
        Err(_) => unreachable!("static outbox relay error code must be valid"),
    }
}

fn result_label<T>(result: &Result<T, OutboxError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(OutboxError::LostLease) => "lost_lease",
        Err(_) => "error",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    counter!("rsk_outbox_operations_total", "operation" => operation, "result" => result)
        .increment(1);
    histogram!("rsk_outbox_operation_duration_seconds", "operation" => operation)
        .record(elapsed.as_secs_f64());
}

fn record_publish(result: &'static str) {
    counter!("rsk_outbox_publications_total", "result" => result).increment(1);
}
