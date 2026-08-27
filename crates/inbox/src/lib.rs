//! Transactional PostgreSQL event inbox and deduplication.
//!
//! The inbox owns neither a connection nor a transaction. Callers claim an event, apply its
//! business effect, and complete the returned claim in one explicit transaction so all three
//! changes commit or roll back together.

#![forbid(unsafe_code)]

use std::{
    fmt,
    time::{Duration, Instant},
};

use omnius_jobs_core::{
    DomainEvent, EventEnvelope, EventId, EventLimits, EventName, TenantId, Version,
};
use sha2::{Digest, Sha256};
use sqlx::{PgConnection, Row, postgres::PgRow};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// Maximum producer length accepted by the database schema.
pub const MAX_PRODUCER_BYTES: usize = 128;
/// Maximum canonical payload accepted before hashing.
pub const MAX_CANONICAL_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Maximum retention interval accepted by the inbox.
pub const MAX_RETENTION: Duration = Duration::from_hours(8_760);
/// Maximum receipts removed by one cleanup call.
pub const MAX_CLEANUP_BATCH_SIZE: u16 = 1_000;

const MIN_RETENTION: Duration = Duration::from_secs(1);

/// A bounded portable event producer identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Producer(String);

impl Producer {
    /// Borrows the validated producer.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn validate(value: &str) -> Result<(), ProducerError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(ProducerError::Empty);
        }
        if bytes.len() > MAX_PRODUCER_BYTES {
            return Err(ProducerError::TooLong);
        }
        if !bytes[0].is_ascii_alphanumeric()
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(ProducerError::Invalid);
        }
        Ok(())
    }
}

impl TryFrom<&str> for Producer {
    type Error = ProducerError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::validate(value)?;
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for Producer {
    type Error = ProducerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value))
    }
}

impl fmt::Debug for Producer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Producer")
            .field("value", &"[REDACTED]")
            .field("byte_len", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Producer validation failures that never retain the rejected value.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProducerError {
    /// A producer must not be empty.
    #[error("producer must not be empty")]
    Empty,
    /// A producer exceeds the schema limit.
    #[error("producer exceeds the byte limit")]
    TooLong,
    /// A producer is not portable.
    #[error("producer has invalid syntax")]
    Invalid,
}

/// A validated retention interval with millisecond precision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Retention {
    duration: Duration,
    milliseconds: i64,
}

impl Retention {
    /// Validates a receipt-retention interval.
    ///
    /// # Errors
    ///
    /// Returns [`RetentionError`] when the interval is shorter than one second, longer than one
    /// year, or not exactly representable in PostgreSQL milliseconds.
    pub fn new(duration: Duration) -> Result<Self, RetentionError> {
        if !(MIN_RETENTION..=MAX_RETENTION).contains(&duration) {
            return Err(RetentionError::OutOfRange);
        }
        if !duration.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(RetentionError::Precision);
        }
        let milliseconds =
            i64::try_from(duration.as_millis()).map_err(|_| RetentionError::OutOfRange)?;
        Ok(Self {
            duration,
            milliseconds,
        })
    }

    /// Returns the validated interval.
    #[must_use]
    pub const fn as_duration(self) -> Duration {
        self.duration
    }
}

/// Retention validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RetentionError {
    /// The interval is outside the supported hard bounds.
    #[error("inbox retention is outside the supported range")]
    OutOfRange,
    /// The interval has finer than millisecond precision.
    #[error("inbox retention must use millisecond precision")]
    Precision,
}

/// A validated bounded cleanup batch size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanupBatchSize(u16);

impl CleanupBatchSize {
    /// Validates a cleanup batch size.
    ///
    /// # Errors
    ///
    /// Returns [`CleanupBatchSizeError`] for zero or a value above
    /// [`MAX_CLEANUP_BATCH_SIZE`].
    pub const fn new(value: u16) -> Result<Self, CleanupBatchSizeError> {
        if value == 0 || value > MAX_CLEANUP_BATCH_SIZE {
            return Err(CleanupBatchSizeError);
        }
        Ok(Self(value))
    }

    /// Returns the validated batch size.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Cleanup batch validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("inbox cleanup batch size is outside the supported range")]
pub struct CleanupBatchSizeError;

/// A SHA-256 digest of exact, bounded canonical JSON object bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct PayloadSha256([u8; 32]);

impl PayloadSha256 {
    /// Validates canonical JSON object bytes and hashes them without materializing a JSON tree.
    ///
    /// The caller's canonical JSON profile is part of the immutable identity: whitespace,
    /// ordering, duplicate members, and every envelope header remain byte-significant.
    ///
    /// # Errors
    ///
    /// Returns [`InboxEventError`] when the input is empty, oversized, malformed, or not an object.
    pub fn from_canonical_payload(payload: &[u8]) -> Result<Self, InboxEventError> {
        if payload.is_empty() {
            return Err(InboxEventError::Payload);
        }
        if payload.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(InboxEventError::PayloadTooLarge);
        }
        let raw: &serde_json::value::RawValue =
            serde_json::from_slice(payload).map_err(|_| InboxEventError::Payload)?;
        if raw
            .get()
            .as_bytes()
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            != Some(b'{')
        {
            return Err(InboxEventError::Payload);
        }
        Ok(Self(Sha256::digest(payload).into()))
    }

    /// Borrows the exact digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PayloadSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PayloadSha256")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// Complete immutable input used to classify an inbox delivery.
#[derive(Clone, Eq, PartialEq)]
pub struct InboxEvent {
    producer: Producer,
    event_id: EventId,
    event_type: EventName,
    event_version: Version,
    tenant_id: Option<Uuid>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    payload_sha256: PayloadSha256,
    retention: Retention,
}

impl InboxEvent {
    /// Builds a bounded inbox input and hashes the canonicalized payload.
    ///
    /// # Errors
    ///
    /// Returns [`InboxEventError`] for a header that cannot fit the inbox schema, mismatched event
    /// type/version headers, a non-v7 correlation or causation identifier, an invalid tenant
    /// identifier, or an invalid payload.
    #[expect(
        clippy::too_many_arguments,
        reason = "the immutable inbox header is one atomic input"
    )]
    pub fn new(
        producer: Producer,
        event_id: EventId,
        event_type: EventName,
        event_version: Version,
        tenant_id: Option<&TenantId>,
        correlation_id: Uuid,
        causation_id: Option<Uuid>,
        canonical_payload: &[u8],
        retention: Retention,
    ) -> Result<Self, InboxEventError> {
        if event_version.get() > i16::MAX.cast_unsigned()
            || event_type
                .as_str()
                .rsplit_once(".v")
                .and_then(|(_, suffix)| suffix.parse::<u16>().ok())
                != Some(event_version.get())
        {
            return Err(InboxEventError::Version);
        }
        if correlation_id.get_version_num() != 7 {
            return Err(InboxEventError::CorrelationId);
        }
        if causation_id.is_some_and(|value| value.get_version_num() != 7) {
            return Err(InboxEventError::CausationId);
        }
        let tenant_id = tenant_id
            .map(|value| Uuid::parse_str(value.as_str()))
            .transpose()
            .map_err(|_| InboxEventError::TenantId)?;
        if tenant_id.is_some_and(|value| value.get_version_num() != 7) {
            return Err(InboxEventError::TenantId);
        }
        let payload_sha256 = PayloadSha256::from_canonical_payload(canonical_payload)?;
        Ok(Self {
            producer,
            event_id,
            event_type,
            event_version,
            tenant_id,
            correlation_id,
            causation_id,
            payload_sha256,
            retention,
        })
    }

    /// Builds an inbox input from the complete canonical typed event envelope.
    ///
    /// # Errors
    ///
    /// Returns [`InboxEventError`] when bounded envelope serialization fails or a derived header
    /// cannot be represented by the inbox schema.
    pub fn from_envelope<E: DomainEvent>(
        envelope: &EventEnvelope<E>,
        limits: EventLimits,
        retention: Retention,
    ) -> Result<Self, InboxEventError> {
        let payload = envelope
            .encode(limits)
            .map_err(|_| InboxEventError::Payload)?;
        let producer = Producer::try_from(envelope.source().as_str())
            .map_err(|_| InboxEventError::Producer)?;
        Self::new(
            producer,
            envelope.id(),
            envelope.event_name().clone(),
            envelope.version(),
            envelope.tenant_id(),
            envelope.correlation_id(),
            envelope.causation_id(),
            &payload,
            retention,
        )
    }

    /// Event identifier.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event_id
    }

    /// Event schema version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.event_version
    }

    /// Payload fingerprint used for exact duplicate classification.
    #[must_use]
    pub const fn payload_sha256(&self) -> PayloadSha256 {
        self.payload_sha256
    }

    /// Receipt retention interval.
    #[must_use]
    pub const fn retention(&self) -> Retention {
        self.retention
    }

    fn database_version(&self) -> Result<i16, InboxStoreError> {
        i16::try_from(self.event_version.get()).map_err(|_| InboxStoreError::CorruptInput)
    }
}

impl fmt::Debug for InboxEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboxEvent")
            .field("event_id", &self.event_id)
            .field("version", &self.event_version)
            .field("has_tenant", &self.tenant_id.is_some())
            .field("has_causation", &self.causation_id.is_some())
            .field("payload_sha256", &self.payload_sha256)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

/// Inbox-event validation failures that never retain rejected headers or payloads.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InboxEventError {
    /// The event type and numeric version disagree or cannot fit PostgreSQL `smallint`.
    #[error("inbox event version is invalid")]
    Version,
    /// The producer derived from an envelope is invalid.
    #[error("inbox event producer is invalid")]
    Producer,
    /// The tenant is not a v7 UUID.
    #[error("inbox event tenant identifier is invalid")]
    TenantId,
    /// The correlation identifier is not a v7 UUID.
    #[error("inbox event correlation identifier is invalid")]
    CorrelationId,
    /// The causation identifier is not a v7 UUID.
    #[error("inbox event causation identifier is invalid")]
    CausationId,
    /// The canonical payload is invalid.
    #[error("inbox event payload is invalid")]
    Payload,
    /// The canonical payload exceeds the hard limit.
    #[error("inbox event payload exceeds the byte limit")]
    PayloadTooLarge,
}

/// Proof that this transaction inserted and owns an unprocessed receipt.
///
/// Values can only be obtained from [`ClaimOutcome::Claimed`] and are consumed by completion.
pub struct ClaimedInboxEvent {
    event: InboxEvent,
    received_at: OffsetDateTime,
}

impl ClaimedInboxEvent {
    /// Event identifier available to the protected business effect.
    #[must_use]
    pub const fn event_id(&self) -> EventId {
        self.event.event_id
    }
}

impl fmt::Debug for ClaimedInboxEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedInboxEvent")
            .field("event_id", &self.event.event_id)
            .finish_non_exhaustive()
    }
}

/// Atomic classification of an inbox delivery.
#[derive(Debug)]
pub enum ClaimOutcome {
    /// This transaction inserted the receipt and may apply the business effect.
    Claimed(ClaimedInboxEvent),
    /// An exact immutable match was already processed and committed.
    Duplicate,
    /// An exact immutable match exists but has not been completed.
    InProgress,
    /// The producer/event identity exists with different immutable headers or payload.
    Conflict,
}

/// Transactional inbox operations that never own or nest a transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresInbox;

impl PostgresInbox {
    /// Creates a stateless transactional inbox helper.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Inserts a receipt or locks and classifies the existing producer/event identity.
    ///
    /// PostgreSQL uniqueness serializes concurrent claims. This helper uses the caller's
    /// connection and never begins, commits, rolls back, or retries a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`InboxStoreError`] for unavailable/transient PostgreSQL, a lost claim, corrupt
    /// stored data, or a persistence constraint failure.
    pub async fn claim_with(
        &self,
        connection: &mut PgConnection,
        event: InboxEvent,
    ) -> Result<ClaimOutcome, InboxStoreError> {
        let started = Instant::now();
        let result = self.claim_inner(connection, event).await;
        record_operation("claim", claim_result_label(&result), started.elapsed());
        result
    }

    /// Completes only a claim returned to this transaction by [`Self::claim_with`].
    ///
    /// The database-issued receipt timestamp and every immutable header fence the update. The
    /// claim is consumed so safe callers cannot complete it twice. This helper never begins,
    /// commits, rolls back, or retries a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`InboxStoreError::InvalidProcessedAt`] when `processed_at` precedes receipt time,
    /// [`InboxStoreError::ClaimLost`] when the receipt is absent, completed, or no longer matches,
    /// and safe persistence errors for database failures.
    pub async fn complete_with(
        &self,
        connection: &mut PgConnection,
        claim: ClaimedInboxEvent,
        processed_at: OffsetDateTime,
    ) -> Result<(), InboxStoreError> {
        let started = Instant::now();
        let result = self.complete_inner(connection, claim, processed_at).await;
        record_operation(
            "complete",
            completion_result_label(result.as_ref().err().copied()),
            started.elapsed(),
        );
        result
    }

    /// Deletes at most `batch_size` expired processed receipts in stable order.
    ///
    /// Locked rows are skipped and unprocessed receipts are never selected. PostgreSQL
    /// `clock_timestamp()` is the sole expiry clock. This helper never owns a transaction.
    ///
    /// # Errors
    ///
    /// Returns [`InboxStoreError`] for safe persistence failures.
    pub async fn cleanup_expired_with(
        &self,
        connection: &mut PgConnection,
        batch_size: CleanupBatchSize,
    ) -> Result<u64, InboxStoreError> {
        let started = Instant::now();
        let result = sqlx::query(
            "WITH expired AS (
                 SELECT producer, event_id
                 FROM inbox_receipts
                 WHERE processed_at IS NOT NULL
                   AND expires_at <= clock_timestamp()
                 ORDER BY expires_at, producer, event_id
                 LIMIT $1
                 FOR UPDATE SKIP LOCKED
             )
             DELETE FROM inbox_receipts AS receipt
             USING expired
             WHERE receipt.producer = expired.producer
               AND receipt.event_id = expired.event_id",
        )
        .bind(i64::from(batch_size.get()))
        .execute(&mut *connection)
        .await
        .map(|done| done.rows_affected())
        .map_err(|error| map_sqlx_error(&error));
        record_operation("cleanup", cleanup_result_label(&result), started.elapsed());
        result
    }

    async fn claim_inner(
        &self,
        connection: &mut PgConnection,
        event: InboxEvent,
    ) -> Result<ClaimOutcome, InboxStoreError> {
        let event_version = event.database_version()?;
        let received_at = sqlx::query_scalar::<_, OffsetDateTime>(
            "INSERT INTO inbox_receipts (
                 producer, event_id, event_type, event_version, tenant_id, correlation_id,
                 causation_id, payload_sha256, received_at, expires_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, clock_timestamp(),
                     clock_timestamp() + ($9 * INTERVAL '1 millisecond'))
             ON CONFLICT (producer, event_id) DO NOTHING
             RETURNING received_at",
        )
        .bind(event.producer.as_str())
        .bind(event.event_id.as_uuid())
        .bind(event.event_type.as_str())
        .bind(event_version)
        .bind(event.tenant_id)
        .bind(event.correlation_id)
        .bind(event.causation_id)
        .bind(event.payload_sha256.as_bytes().as_slice())
        .bind(event.retention.milliseconds)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;

        if let Some(received_at) = received_at {
            return Ok(ClaimOutcome::Claimed(ClaimedInboxEvent {
                event,
                received_at,
            }));
        }

        let existing = lock_receipt(connection, &event)
            .await?
            .ok_or(InboxStoreError::ClaimLost)?;
        if !existing.is_well_formed() {
            return Err(InboxStoreError::CorruptData);
        }
        if !existing.immutable_matches(&event) {
            return Ok(ClaimOutcome::Conflict);
        }
        if existing.processed_at.is_some() {
            Ok(ClaimOutcome::Duplicate)
        } else {
            Ok(ClaimOutcome::InProgress)
        }
    }

    async fn complete_inner(
        &self,
        connection: &mut PgConnection,
        claim: ClaimedInboxEvent,
        processed_at: OffsetDateTime,
    ) -> Result<(), InboxStoreError> {
        if processed_at < claim.received_at {
            return Err(InboxStoreError::InvalidProcessedAt);
        }
        let event = &claim.event;
        let event_version = event.database_version()?;
        let completed = sqlx::query(
            "UPDATE inbox_receipts
             SET processed_at = $1
             WHERE producer = $2
               AND event_id = $3
               AND received_at = $4
               AND event_type = $5
               AND event_version = $6
               AND tenant_id IS NOT DISTINCT FROM $7
               AND correlation_id = $8
               AND causation_id IS NOT DISTINCT FROM $9
               AND payload_sha256 = $10
               AND processed_at IS NULL",
        )
        .bind(processed_at)
        .bind(event.producer.as_str())
        .bind(event.event_id.as_uuid())
        .bind(claim.received_at)
        .bind(event.event_type.as_str())
        .bind(event_version)
        .bind(event.tenant_id)
        .bind(event.correlation_id)
        .bind(event.causation_id)
        .bind(event.payload_sha256.as_bytes().as_slice())
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if completed.rows_affected() == 1 {
            return Ok(());
        }

        let existing = lock_receipt(connection, event).await?;
        match existing {
            None => Err(InboxStoreError::ClaimLost),
            Some(existing)
                if existing.is_well_formed()
                    && existing.received_at == claim.received_at
                    && existing.immutable_matches(event) =>
            {
                Err(InboxStoreError::ClaimLost)
            }
            Some(_) => Err(InboxStoreError::CorruptData),
        }
    }
}

struct ExistingReceipt {
    event_type: String,
    event_version: i16,
    tenant_id: Option<Uuid>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    payload_sha256: Vec<u8>,
    received_at: OffsetDateTime,
    processed_at: Option<OffsetDateTime>,
}

impl ExistingReceipt {
    fn from_row(row: &PgRow) -> Result<Self, InboxStoreError> {
        Ok(Self {
            event_type: row
                .try_get("event_type")
                .map_err(|_| InboxStoreError::CorruptData)?,
            event_version: row
                .try_get("event_version")
                .map_err(|_| InboxStoreError::CorruptData)?,
            tenant_id: row
                .try_get("tenant_id")
                .map_err(|_| InboxStoreError::CorruptData)?,
            correlation_id: row
                .try_get("correlation_id")
                .map_err(|_| InboxStoreError::CorruptData)?,
            causation_id: row
                .try_get("causation_id")
                .map_err(|_| InboxStoreError::CorruptData)?,
            payload_sha256: row
                .try_get("payload_sha256")
                .map_err(|_| InboxStoreError::CorruptData)?,
            received_at: row
                .try_get("received_at")
                .map_err(|_| InboxStoreError::CorruptData)?,
            processed_at: row
                .try_get("processed_at")
                .map_err(|_| InboxStoreError::CorruptData)?,
        })
    }

    fn is_well_formed(&self) -> bool {
        self.event_version > 0
            && self.payload_sha256.len() == 32
            && self.correlation_id.get_version_num() == 7
            && self
                .causation_id
                .is_none_or(|value| value.get_version_num() == 7)
            && self
                .tenant_id
                .is_none_or(|value| value.get_version_num() == 7)
    }

    fn immutable_matches(&self, event: &InboxEvent) -> bool {
        self.event_type == event.event_type.as_str()
            && u16::try_from(self.event_version).ok() == Some(event.event_version.get())
            && self.tenant_id == event.tenant_id
            && self.correlation_id == event.correlation_id
            && self.causation_id == event.causation_id
            && self.payload_sha256.as_slice() == event.payload_sha256.as_bytes()
    }
}

async fn lock_receipt(
    connection: &mut PgConnection,
    event: &InboxEvent,
) -> Result<Option<ExistingReceipt>, InboxStoreError> {
    sqlx::query(
        "SELECT event_type, event_version, tenant_id, correlation_id, causation_id,
                payload_sha256, received_at, processed_at
         FROM inbox_receipts
         WHERE producer = $1 AND event_id = $2
         FOR UPDATE",
    )
    .bind(event.producer.as_str())
    .bind(event.event_id.as_uuid())
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?
    .map(|row| ExistingReceipt::from_row(&row))
    .transpose()
}

/// Stable value-free persistence failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum InboxStoreError {
    /// The caller supplied an internally inconsistent validated input.
    #[error("inbox input is inconsistent")]
    CorruptInput,
    /// The claim is absent, completed, or no longer owned by this transaction.
    #[error("inbox claim is no longer owned")]
    ClaimLost,
    /// Completion time precedes the database receipt time.
    #[error("inbox completion time precedes receipt time")]
    InvalidProcessedAt,
    /// PostgreSQL requested a safe caller-owned transaction retry.
    #[error("inbox persistence transaction must be retried")]
    Transient,
    /// PostgreSQL is unavailable.
    #[error("inbox persistence is unavailable")]
    Unavailable,
    /// Persistence rejected a bounded value or invariant.
    #[error("inbox persistence constraint failed")]
    ConstraintViolation,
    /// Persisted receipt state violates the inbox schema contract.
    #[error("inbox persisted state is invalid")]
    CorruptData,
}

fn map_sqlx_error(error: &sqlx::Error) -> InboxStoreError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "40001" | "40P01" | "55P03") => {
            InboxStoreError::Transient
        }
        Some(code)
            if matches!(
                code.as_ref(),
                "22003" | "22007" | "22008" | "23502" | "23505" | "23514"
            ) =>
        {
            InboxStoreError::ConstraintViolation
        }
        _ => InboxStoreError::Unavailable,
    }
}

fn claim_result_label(result: &Result<ClaimOutcome, InboxStoreError>) -> &'static str {
    match result {
        Ok(ClaimOutcome::Claimed(_)) => "claimed",
        Ok(ClaimOutcome::Duplicate) => "duplicate",
        Ok(ClaimOutcome::InProgress) => "in_progress",
        Ok(ClaimOutcome::Conflict) => "conflict",
        Err(error) => error_label(*error),
    }
}

fn completion_result_label(error: Option<InboxStoreError>) -> &'static str {
    error.map_or("completed", error_label)
}

fn cleanup_result_label(result: &Result<u64, InboxStoreError>) -> &'static str {
    match result {
        Ok(_) => "completed",
        Err(error) => error_label(*error),
    }
}

const fn error_label(error: InboxStoreError) -> &'static str {
    match error {
        InboxStoreError::CorruptInput => "corrupt_input",
        InboxStoreError::ClaimLost => "claim_lost",
        InboxStoreError::InvalidProcessedAt => "invalid_processed_at",
        InboxStoreError::Transient => "transient",
        InboxStoreError::Unavailable => "unavailable",
        InboxStoreError::ConstraintViolation => "constraint_violation",
        InboxStoreError::CorruptData => "corrupt_data",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "omnius_inbox_operations_total",
        "operation" => operation,
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_inbox_operation_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}
