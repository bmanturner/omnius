use std::{fmt, time::Duration};

use futures::future::BoxFuture;
use omnius_postgres::{PostgresError, PostgresPool};
use serde_json::Value;
use sqlx::{Connection as _, Row as _};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ParsedProviderEvent, ProviderId, VerifiedRequest};

const MAX_FAILURE_CLASS_BYTES: usize = 64;
const MAX_DURATION_MICROS: u128 = i64::MAX as u128;
const MAX_BATCH_SIZE: u16 = 100;
const MAX_ATTEMPTS: u16 = 20;
const MAX_LEASE_DURATION: Duration = Duration::from_mins(5);
const MAX_RETRY_DELAY: Duration = Duration::from_hours(1);

/// `UUIDv7` identity of one durable webhook receipt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReceiptId(Uuid);

impl ReceiptId {
    /// Generates a fresh `UUIDv7` receipt identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the database representation.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ReceiptId {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable bounded failure classification safe for metrics and persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct FailureClass(String);

impl FailureClass {
    /// Creates a lowercase identifier containing ASCII letters, digits, `_`, `.`, or `-`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidFailureClass`] when the value is empty, oversized, or malformed.
    pub fn parse(value: impl Into<String>) -> Result<Self, InvalidFailureClass> {
        let value = value.into();
        let mut bytes = value.bytes();
        let valid = value.len() <= MAX_FAILURE_CLASS_BYTES
            && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'.' | b'-')
            });
        if valid {
            Ok(Self(value))
        } else {
            Err(InvalidFailureClass)
        }
    }

    /// Classification used when no registered domain handler owns a verified event.
    #[must_use]
    pub fn unsupported_event() -> Self {
        Self("unsupported_event".to_owned())
    }

    /// Classification used when handler execution exceeds its fixed budget.
    #[must_use]
    pub fn handler_timeout() -> Self {
        Self("handler_timeout".to_owned())
    }

    /// Returns the safe persistence representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
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

/// A failure class is outside its low-cardinality safe syntax.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("webhook failure classification is invalid")]
pub struct InvalidFailureClass;

/// Fully verified and parsed receipt proposed for atomic persistence.
#[derive(Clone)]
pub struct NewReceipt {
    id: ReceiptId,
    provider: ProviderId,
    scope: String,
    event_id: String,
    content_digest: [u8; 32],
    event_type: String,
    event_version: u16,
    parsed_payload: Value,
    verified_at: OffsetDateTime,
    provider_timestamp: OffsetDateTime,
    occurred_at: Option<OffsetDateTime>,
    retain_until: OffsetDateTime,
}

impl NewReceipt {
    #[must_use]
    pub(crate) fn from_verified(
        verified: VerifiedRequest,
        parsed: ParsedProviderEvent,
        content_digest: [u8; 32],
        verified_at: OffsetDateTime,
        retain_until: OffsetDateTime,
    ) -> Self {
        let (provider, scope, event_id, provider_timestamp) = verified.into_parts();
        let (event_type, event_version, occurred_at, parsed_payload) = parsed.into_parts();
        Self {
            id: ReceiptId::new(),
            provider,
            scope,
            event_id,
            content_digest,
            event_type,
            event_version,
            parsed_payload,
            verified_at,
            provider_timestamp,
            occurred_at,
            retain_until,
        }
    }

    /// Returns the proposed receipt identity.
    #[must_use]
    pub const fn id(&self) -> ReceiptId {
        self.id
    }

    /// Returns the immutable provider fence.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the immutable content digest.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns the authenticated provider scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the authenticated provider event identity.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the provider-owned event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the provider schema version.
    #[must_use]
    pub const fn event_version(&self) -> u16 {
        self.event_version
    }

    /// Returns the bounded safe payload projection.
    #[must_use]
    pub const fn parsed_payload(&self) -> &Value {
        &self.parsed_payload
    }

    /// Returns when signature and timestamp verification completed.
    #[must_use]
    pub const fn verified_at(&self) -> OffsetDateTime {
        self.verified_at
    }

    /// Returns the provider timestamp authenticated by the adapter.
    #[must_use]
    pub const fn provider_timestamp(&self) -> OffsetDateTime {
        self.provider_timestamp
    }

    /// Returns the optional provider event occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> Option<OffsetDateTime> {
        self.occurred_at
    }

    /// Returns the terminal retention deadline.
    #[must_use]
    pub const fn retain_until(&self) -> OffsetDateTime {
        self.retain_until
    }
}

impl fmt::Debug for NewReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NewReceipt")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("scope", &"[REDACTED]")
            .field("event_id", &"[REDACTED]")
            .field("content_digest", &"[REDACTED]")
            .field("event_type", &self.event_type)
            .field("event_version", &self.event_version)
            .field("parsed_payload", &"[REDACTED]")
            .field("verified_at", &self.verified_at)
            .finish_non_exhaustive()
    }
}

/// Atomic database classification of a verified event identity and digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveDisposition {
    /// A new receipt was committed.
    Accepted(ReceiptId),
    /// A committed receipt already has the same identity and digest.
    Duplicate(ReceiptId),
    /// A committed receipt has the same identity and a different digest.
    Conflict,
}

/// Persistence seam used by the transport-neutral receive service.
pub trait ReceiptRepository: Send + Sync + 'static {
    /// Atomically inserts or classifies one verified event using the database unique constraint.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ReceiptStoreError`] when persistence is unavailable or inconsistent.
    fn receive<'a>(
        &'a self,
        receipt: &'a NewReceipt,
    ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>>;
}

/// One live, database-fenced processing lease.
pub struct ClaimedReceipt {
    id: ReceiptId,
    provider: ProviderId,
    scope: String,
    event_id: String,
    event_type: String,
    event_version: u16,
    parsed_payload: Value,
    lease_token: Uuid,
    lease_expires_at: OffsetDateTime,
    attempt_count: u16,
}

impl ClaimedReceipt {
    /// Returns the stable idempotency identity handlers must use for external effects.
    #[must_use]
    pub const fn id(&self) -> ReceiptId {
        self.id
    }

    /// Returns the provider adapter identity.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the authenticated provider scope.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    /// Returns the authenticated provider event identity.
    #[must_use]
    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    /// Returns the provider-owned event type.
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// Returns the provider schema version.
    #[must_use]
    pub const fn event_version(&self) -> u16 {
        self.event_version
    }

    /// Returns the safe provider-selected payload projection.
    #[must_use]
    pub const fn parsed_payload(&self) -> &Value {
        &self.parsed_payload
    }

    /// Returns the attempt count including this lease.
    #[must_use]
    pub const fn attempt_count(&self) -> u16 {
        self.attempt_count
    }

    /// Returns the database-clock expiry of this fencing token.
    #[must_use]
    pub const fn lease_expires_at(&self) -> OffsetDateTime {
        self.lease_expires_at
    }
}

impl fmt::Debug for ClaimedReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClaimedReceipt")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("scope", &"[REDACTED]")
            .field("event_id", &"[REDACTED]")
            .field("event_type", &self.event_type)
            .field("event_version", &self.event_version)
            .field("parsed_payload", &"[REDACTED]")
            .field("lease_token", &self.lease_token)
            .field("lease_expires_at", &self.lease_expires_at)
            .field("attempt_count", &self.attempt_count)
            .finish()
    }
}

/// PostgreSQL-authoritative webhook receipt repository and lease queue.
#[derive(Clone)]
pub struct PostgresReceiptStore {
    pool: PostgresPool,
}

impl PostgresReceiptStore {
    /// Creates a receipt store over the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Claims a bounded ready batch using database row locks and fresh fencing tokens.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError::InvalidInput`] for invalid bounds or another safe store
    /// failure when PostgreSQL is unavailable or contains inconsistent data.
    pub async fn claim_ready(
        &self,
        limit: u16,
        max_attempts: u16,
        lease_duration: Duration,
    ) -> Result<Vec<ClaimedReceipt>, ReceiptStoreError> {
        if limit == 0
            || limit > MAX_BATCH_SIZE
            || max_attempts == 0
            || max_attempts > MAX_ATTEMPTS
            || lease_duration.is_zero()
            || lease_duration > MAX_LEASE_DURATION
        {
            return Err(ReceiptStoreError::InvalidInput);
        }
        let lease_token = Uuid::now_v7();
        let lease_micros = duration_micros(lease_duration)?;
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let rows = sqlx::query(
            "WITH candidates AS ( \
                SELECT id FROM webhook_receipts \
                WHERE status = 'pending' AND available_at <= clock_timestamp() \
                  AND attempt_count < $2 \
                ORDER BY available_at, id \
                LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE webhook_receipts AS receipt SET \
                status = 'processing', attempt_count = receipt.attempt_count + 1, \
                lease_token = $3, \
                lease_expires_at = clock_timestamp() + $4::bigint * interval '1 microsecond', \
                updated_at = clock_timestamp() \
             FROM candidates WHERE receipt.id = candidates.id \
             RETURNING receipt.id, receipt.provider, receipt.provider_scope, receipt.event_id, \
                       receipt.event_type, receipt.event_version, receipt.parsed_payload, \
                       receipt.lease_expires_at, receipt.attempt_count",
        )
        .bind(i64::from(limit))
        .bind(i32::from(max_attempts))
        .bind(lease_token)
        .bind(lease_micros)
        .fetch_all(&mut *connection)
        .await
        .map_err(store_database)?;
        rows.iter()
            .map(|row| claimed_receipt(row, lease_token))
            .collect()
    }

    /// Dead-letters a bounded batch stranded by a reduced runtime attempt cap.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ReceiptStoreError`] when bounds are invalid or persistence fails.
    pub async fn dead_letter_pending_over_attempt_cap(
        &self,
        limit: u16,
        max_attempts: u16,
    ) -> Result<u64, ReceiptStoreError> {
        if limit == 0 || limit > MAX_BATCH_SIZE || max_attempts == 0 || max_attempts > MAX_ATTEMPTS
        {
            return Err(ReceiptStoreError::InvalidInput);
        }
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let result = sqlx::query(
            "WITH stranded AS ( \
                SELECT id FROM webhook_receipts \
                WHERE status = 'pending' AND attempt_count >= $2 \
                ORDER BY available_at, id LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE webhook_receipts AS receipt SET \
                status = 'dead_letter', dead_lettered_at = clock_timestamp(), \
                last_error_class = 'attempt_limit_reduced', updated_at = clock_timestamp() \
             FROM stranded WHERE receipt.id = stranded.id",
        )
        .bind(i64::from(limit))
        .bind(i32::from(max_attempts))
        .execute(&mut *connection)
        .await
        .map_err(store_database)?;
        Ok(result.rows_affected())
    }

    /// Recovers a bounded batch of expired leases, dead-lettering exhausted receipts.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ReceiptStoreError`] when bounds are invalid or persistence fails.
    pub async fn recover_expired(
        &self,
        limit: u16,
        max_attempts: u16,
    ) -> Result<u64, ReceiptStoreError> {
        if limit == 0 || limit > MAX_BATCH_SIZE || max_attempts == 0 || max_attempts > MAX_ATTEMPTS
        {
            return Err(ReceiptStoreError::InvalidInput);
        }
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let result = sqlx::query(
            "WITH expired AS ( \
                SELECT id FROM webhook_receipts \
                WHERE status = 'processing' AND lease_expires_at <= clock_timestamp() \
                ORDER BY lease_expires_at, id LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             UPDATE webhook_receipts AS receipt SET \
                status = CASE WHEN receipt.attempt_count >= $2 THEN 'dead_letter' ELSE 'pending' END, \
                available_at = clock_timestamp(), lease_token = NULL, lease_expires_at = NULL, \
                dead_lettered_at = CASE WHEN receipt.attempt_count >= $2 THEN clock_timestamp() ELSE NULL END, \
                last_error_class = 'lease_expired', updated_at = clock_timestamp() \
             FROM expired WHERE receipt.id = expired.id",
        )
        .bind(i64::from(limit))
        .bind(i32::from(max_attempts))
        .execute(&mut *connection)
        .await
        .map_err(store_database)?;
        Ok(result.rows_affected())
    }

    /// Completes a receipt only while its exact fencing token is live.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError::LostLease`] when the token expired or was superseded.
    pub async fn complete(&self, receipt: &ClaimedReceipt) -> Result<(), ReceiptStoreError> {
        self.finish(receipt, "processed", None).await
    }

    /// Releases a live lease for bounded delayed retry.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError::LostLease`] when the token expired or was superseded.
    pub async fn retry(
        &self,
        receipt: &ClaimedReceipt,
        class: &FailureClass,
        delay: Duration,
    ) -> Result<(), ReceiptStoreError> {
        if delay.is_zero() || delay > MAX_RETRY_DELAY {
            return Err(ReceiptStoreError::InvalidInput);
        }
        let delay_micros = duration_micros(delay)?;
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let result = sqlx::query(
            "UPDATE webhook_receipts SET status = 'pending', \
                available_at = clock_timestamp() + $3::bigint * interval '1 microsecond', \
                lease_token = NULL, lease_expires_at = NULL, last_error_class = $4, \
                updated_at = clock_timestamp() \
             WHERE id = $1 AND status = 'processing' AND lease_token = $2 \
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(receipt.id.as_uuid())
        .bind(receipt.lease_token)
        .bind(delay_micros)
        .bind(class.as_str())
        .execute(&mut *connection)
        .await
        .map_err(store_database)?;
        require_fence(result.rows_affected())
    }

    /// Dead-letters a receipt only while its exact fencing token is live.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError::LostLease`] when the token expired or was superseded.
    pub async fn dead_letter(
        &self,
        receipt: &ClaimedReceipt,
        class: &FailureClass,
    ) -> Result<(), ReceiptStoreError> {
        self.finish(receipt, "dead_letter", Some(class)).await
    }

    /// Deletes a bounded batch of terminal receipts after their retention deadline.
    ///
    /// # Errors
    ///
    /// Returns a safe [`ReceiptStoreError`] for an invalid limit or persistence failure.
    pub async fn cleanup_retained(&self, limit: u16) -> Result<u64, ReceiptStoreError> {
        if limit == 0 || limit > MAX_BATCH_SIZE {
            return Err(ReceiptStoreError::InvalidInput);
        }
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let result = sqlx::query(
            "WITH expired AS ( \
                SELECT id FROM webhook_receipts \
                WHERE status IN ('processed', 'dead_letter') \
                  AND retain_until <= clock_timestamp() \
                ORDER BY retain_until, id LIMIT $1 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM webhook_receipts AS receipt USING expired \
             WHERE receipt.id = expired.id",
        )
        .bind(i64::from(limit))
        .execute(&mut *connection)
        .await
        .map_err(store_database)?;
        Ok(result.rows_affected())
    }

    async fn finish(
        &self,
        receipt: &ClaimedReceipt,
        status: &'static str,
        class: Option<&FailureClass>,
    ) -> Result<(), ReceiptStoreError> {
        let mut connection = self.pool.acquire().await.map_err(store_pool)?;
        let result = sqlx::query(
            "UPDATE webhook_receipts SET status = $3, lease_token = NULL, lease_expires_at = NULL, \
                processed_at = CASE WHEN $3 = 'processed' THEN clock_timestamp() ELSE NULL END, \
                dead_lettered_at = CASE WHEN $3 = 'dead_letter' THEN clock_timestamp() ELSE NULL END, \
                last_error_class = $4, updated_at = clock_timestamp() \
             WHERE id = $1 AND status = 'processing' AND lease_token = $2 \
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(receipt.id.as_uuid())
        .bind(receipt.lease_token)
        .bind(status)
        .bind(class.map(FailureClass::as_str))
        .execute(&mut *connection)
        .await
        .map_err(store_database)?;
        require_fence(result.rows_affected())
    }
}

impl ReceiptRepository for PostgresReceiptStore {
    fn receive<'a>(
        &'a self,
        receipt: &'a NewReceipt,
    ) -> BoxFuture<'a, Result<ReceiveDisposition, ReceiptStoreError>> {
        Box::pin(async move {
            let mut connection = self.pool.acquire().await.map_err(store_pool)?;
            let mut transaction = connection.begin().await.map_err(store_database)?;
            let inserted = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO webhook_receipts ( \
                    id, provider, provider_scope, event_id, content_digest, event_type, \
                    event_version, parsed_payload, verified_at, provider_timestamp, occurred_at, \
                    status, attempt_count, available_at, retain_until, created_at, updated_at \
                 ) VALUES ( \
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                    'pending', 0, $9, $12, $9, $9 \
                 ) ON CONFLICT (provider, provider_scope, event_id) DO NOTHING \
                 RETURNING id",
            )
            .bind(receipt.id.as_uuid())
            .bind(receipt.provider.as_str())
            .bind(&receipt.scope)
            .bind(&receipt.event_id)
            .bind(receipt.content_digest.as_slice())
            .bind(&receipt.event_type)
            .bind(i32::from(receipt.event_version))
            .bind(&receipt.parsed_payload)
            .bind(receipt.verified_at)
            .bind(receipt.provider_timestamp)
            .bind(receipt.occurred_at)
            .bind(receipt.retain_until)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(store_database)?;
            let disposition = if let Some(id) = inserted {
                ReceiveDisposition::Accepted(ReceiptId(id))
            } else {
                let row = sqlx::query(
                    "SELECT id, content_digest FROM webhook_receipts \
                     WHERE provider = $1 AND provider_scope = $2 AND event_id = $3",
                )
                .bind(receipt.provider.as_str())
                .bind(&receipt.scope)
                .bind(&receipt.event_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(store_database)?
                .ok_or(ReceiptStoreError::Database)?;
                let existing_id: Uuid =
                    row.try_get("id").map_err(|_| ReceiptStoreError::Database)?;
                let existing_digest: Vec<u8> = row
                    .try_get("content_digest")
                    .map_err(|_| ReceiptStoreError::Database)?;
                if existing_digest.as_slice() == receipt.content_digest.as_slice() {
                    ReceiveDisposition::Duplicate(ReceiptId(existing_id))
                } else {
                    ReceiveDisposition::Conflict
                }
            };
            transaction.commit().await.map_err(store_database)?;
            Ok(disposition)
        })
    }
}

/// Safe durable receipt operation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReceiptStoreError {
    /// A caller-supplied resource or duration bound is invalid.
    #[error("webhook receipt request is invalid")]
    InvalidInput,
    /// PostgreSQL is unavailable or returned inconsistent receipt data.
    #[error("webhook receipt persistence is unavailable")]
    Database,
    /// A processing lease expired or was superseded.
    #[error("webhook receipt lease was lost")]
    LostLease,
}

fn claimed_receipt(
    row: &sqlx::postgres::PgRow,
    lease_token: Uuid,
) -> Result<ClaimedReceipt, ReceiptStoreError> {
    let id: Uuid = row.try_get("id").map_err(|_| ReceiptStoreError::Database)?;
    let provider: String = row
        .try_get("provider")
        .map_err(|_| ReceiptStoreError::Database)?;
    let event_version: i32 = row
        .try_get("event_version")
        .map_err(|_| ReceiptStoreError::Database)?;
    let attempt_count: i32 = row
        .try_get("attempt_count")
        .map_err(|_| ReceiptStoreError::Database)?;
    Ok(ClaimedReceipt {
        id: ReceiptId(id),
        provider: ProviderId::parse(provider).map_err(|_| ReceiptStoreError::Database)?,
        scope: row
            .try_get("provider_scope")
            .map_err(|_| ReceiptStoreError::Database)?,
        event_id: row
            .try_get("event_id")
            .map_err(|_| ReceiptStoreError::Database)?,
        event_type: row
            .try_get("event_type")
            .map_err(|_| ReceiptStoreError::Database)?,
        event_version: u16::try_from(event_version).map_err(|_| ReceiptStoreError::Database)?,
        parsed_payload: row
            .try_get("parsed_payload")
            .map_err(|_| ReceiptStoreError::Database)?,
        lease_token,
        lease_expires_at: row
            .try_get("lease_expires_at")
            .map_err(|_| ReceiptStoreError::Database)?,
        attempt_count: u16::try_from(attempt_count).map_err(|_| ReceiptStoreError::Database)?,
    })
}

fn duration_micros(duration: Duration) -> Result<i64, ReceiptStoreError> {
    if duration.is_zero() || duration.as_micros() > MAX_DURATION_MICROS {
        return Err(ReceiptStoreError::InvalidInput);
    }
    i64::try_from(duration.as_micros()).map_err(|_| ReceiptStoreError::InvalidInput)
}

fn require_fence(rows_affected: u64) -> Result<(), ReceiptStoreError> {
    if rows_affected == 1 {
        Ok(())
    } else {
        Err(ReceiptStoreError::LostLease)
    }
}

fn store_pool(_error: PostgresError) -> ReceiptStoreError {
    ReceiptStoreError::Database
}

fn store_database(_error: sqlx::Error) -> ReceiptStoreError {
    ReceiptStoreError::Database
}
