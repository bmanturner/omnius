//! Transactional PostgreSQL idempotency claims and bounded response replay.
//!
//! This store owns neither a pool nor a transaction. Callers should claim, perform the protected
//! business effect, and complete the claim in one explicit transaction so all three commit or
//! roll back together.

use std::{
    fmt,
    time::{Duration, Instant},
};

use omnius_postgres::{RetryableSqlState, RetryableTransactionError};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use thiserror::Error;

const MAX_VALUE_BYTES: usize = 128;
const MAX_CONTENT_TYPE_BYTES: usize = 255;
const MAX_TTL: Duration = Duration::from_hours(720);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_TTL: Duration = Duration::from_hours(24);
const DEFAULT_RESPONSE_BYTES: usize = 64 * 1024;

/// A validated, opaque idempotency key.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validates and owns a key containing 1–128 visible ASCII bytes.
    ///
    /// # Errors
    /// Returns [`IdempotencyKeyError`] when the value is empty, oversized, or not visible ASCII.
    pub fn new(value: String) -> Result<Self, IdempotencyKeyError> {
        if value.is_empty() {
            return Err(IdempotencyKeyError::Empty);
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(IdempotencyKeyError::TooLong);
        }
        if !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
            return Err(IdempotencyKeyError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyKey([REDACTED])")
    }
}

impl TryFrom<String> for IdempotencyKey {
    type Error = IdempotencyKeyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for IdempotencyKey {
    type Error = IdempotencyKeyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

/// Idempotency-key validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyKeyError {
    /// A key was empty.
    #[error("idempotency key must not be empty")]
    Empty,
    /// A key exceeded 128 bytes.
    #[error("idempotency key must not exceed 128 bytes")]
    TooLong,
    /// A key contained whitespace, controls, or non-ASCII data.
    #[error("idempotency key must contain only visible ASCII")]
    InvalidCharacter,
}

/// A validated principal or tenant scope value.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct IdempotencyScopeValue(String);

impl IdempotencyScopeValue {
    /// Validates and owns a non-empty, trimmed value of at most 128 bytes.
    ///
    /// # Errors
    /// Returns [`IdempotencyScopeValueError`] for invalid values.
    pub fn new(value: String) -> Result<Self, IdempotencyScopeValueError> {
        if value.is_empty() {
            return Err(IdempotencyScopeValueError::Empty);
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(IdempotencyScopeValueError::TooLong);
        }
        if value.trim() != value {
            return Err(IdempotencyScopeValueError::SurroundingWhitespace);
        }
        if value.chars().any(char::is_control) {
            return Err(IdempotencyScopeValueError::ControlCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the validated scope value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IdempotencyScopeValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdempotencyScopeValue([REDACTED])")
    }
}

impl TryFrom<String> for IdempotencyScopeValue {
    type Error = IdempotencyScopeValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for IdempotencyScopeValue {
    type Error = IdempotencyScopeValueError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_owned())
    }
}

/// Scope-value validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyScopeValueError {
    /// A present scope value was empty.
    #[error("idempotency scope value must not be empty")]
    Empty,
    /// A scope value exceeded 128 bytes.
    #[error("idempotency scope value must not exceed 128 bytes")]
    TooLong,
    /// A scope value had leading or trailing whitespace.
    #[error("idempotency scope value must not have surrounding whitespace")]
    SurroundingWhitespace,
    /// A scope value contained a control character.
    #[error("idempotency scope value must not contain control characters")]
    ControlCharacter,
}

/// Principal and tenant dimensions isolating an idempotency key.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct IdempotencyScope {
    principal: Option<IdempotencyScopeValue>,
    tenant: Option<IdempotencyScopeValue>,
}

impl IdempotencyScope {
    /// Builds a scope from validated components. Both may be absent for an anonymous operation.
    #[must_use]
    pub const fn new(
        principal: Option<IdempotencyScopeValue>,
        tenant: Option<IdempotencyScopeValue>,
    ) -> Self {
        Self { principal, tenant }
    }

    /// Builds an anonymous scope.
    #[must_use]
    pub const fn unscoped() -> Self {
        Self {
            principal: None,
            tenant: None,
        }
    }

    /// Returns the optional principal scope.
    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_ref().map(IdempotencyScopeValue::as_str)
    }

    /// Returns the optional tenant scope.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.tenant.as_ref().map(IdempotencyScopeValue::as_str)
    }
}

/// A caller-declared, low-cardinality operation identity.
///
/// Requiring a static value prevents request-derived route values from entering this namespace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct IdempotencyOperation(&'static str);

impl IdempotencyOperation {
    /// Validates a 1–128 byte static operation name.
    ///
    /// # Errors
    /// Returns [`IdempotencyOperationError`] for invalid names.
    pub fn new(value: &'static str) -> Result<Self, IdempotencyOperationError> {
        if value.is_empty() {
            return Err(IdempotencyOperationError::Empty);
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(IdempotencyOperationError::TooLong);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/')
        }) {
            return Err(IdempotencyOperationError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the stable operation identity.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

/// Operation-name validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyOperationError {
    /// The name was empty.
    #[error("idempotency operation must not be empty")]
    Empty,
    /// The name exceeded 128 bytes.
    #[error("idempotency operation must not exceed 128 bytes")]
    TooLong,
    /// The name contained an unsupported character.
    #[error("idempotency operation contains an invalid character")]
    InvalidCharacter,
}

/// A SHA-256 fingerprint of the complete canonical request representation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RequestFingerprint([u8; 32]);

impl RequestFingerprint {
    /// Hashes a canonical request representation with SHA-256.
    #[must_use]
    pub fn sha256(canonical_request: &[u8]) -> Self {
        Self(Sha256::digest(canonical_request).into())
    }

    /// Restores an exact 32-byte SHA-256 digest.
    ///
    /// # Errors
    /// Returns [`RequestFingerprintError`] when the digest length is not 32.
    pub fn from_digest(digest: &[u8]) -> Result<Self, RequestFingerprintError> {
        <[u8; 32]>::try_from(digest)
            .map(Self)
            .map_err(|_| RequestFingerprintError::InvalidLength)
    }

    /// Returns the digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for RequestFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestFingerprint([REDACTED])")
    }
}

/// Fingerprint restoration failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RequestFingerprintError {
    /// SHA-256 digests are exactly 32 bytes.
    #[error("request fingerprint must be exactly 32 bytes")]
    InvalidLength,
}

/// The complete validated identity of one idempotent request.
#[derive(Clone, Eq, PartialEq)]
pub struct IdempotencyRequest {
    scope: IdempotencyScope,
    operation: IdempotencyOperation,
    key: IdempotencyKey,
    fingerprint: RequestFingerprint,
}

impl IdempotencyRequest {
    /// Builds an identity from validated values.
    #[must_use]
    pub const fn new(
        scope: IdempotencyScope,
        operation: IdempotencyOperation,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
    ) -> Self {
        Self {
            scope,
            operation,
            key,
            fingerprint,
        }
    }

    /// Returns the scope.
    #[must_use]
    pub const fn scope(&self) -> &IdempotencyScope {
        &self.scope
    }

    /// Returns the operation.
    #[must_use]
    pub const fn operation(&self) -> IdempotencyOperation {
        self.operation
    }

    /// Returns the key.
    #[must_use]
    pub const fn key(&self) -> &IdempotencyKey {
        &self.key
    }

    /// Returns the request fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> RequestFingerprint {
        self.fingerprint
    }
}

impl fmt::Debug for IdempotencyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdempotencyRequest")
            .field("operation", &self.operation)
            .field("scope", &"[REDACTED]")
            .field("key", &"[REDACTED]")
            .field("fingerprint", &"[REDACTED]")
            .finish()
    }
}

/// A bounded response safe for exact replay.
///
/// Only status, optional content type, and body are stored. Per-request headers are not replayed.
#[derive(Clone, Eq, PartialEq)]
pub struct SafeResponse {
    status: u16,
    content_type: Option<String>,
    body: Vec<u8>,
}

impl SafeResponse {
    /// Validates and owns a replayable response, with an absolute 2 MiB body bound.
    ///
    /// # Errors
    /// Returns [`SafeResponseError`] for invalid status, content type, or size.
    pub fn new(
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    ) -> Result<Self, SafeResponseError> {
        if !(100..=599).contains(&status) {
            return Err(SafeResponseError::InvalidStatus);
        }
        if let Some(value) = content_type.as_deref()
            && (value.is_empty()
                || value.len() > MAX_CONTENT_TYPE_BYTES
                || value.trim() != value
                || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte)))
        {
            return Err(SafeResponseError::InvalidContentType);
        }
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(SafeResponseError::BodyTooLarge);
        }
        Ok(Self {
            status,
            content_type,
            body,
        })
    }

    /// Returns the original HTTP status.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Returns the original content type.
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    /// Returns the original body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for SafeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeResponse")
            .field("status", &self.status)
            .field("content_type", &self.content_type)
            .field("body", &"[REDACTED]")
            .finish()
    }
}

/// Safe-response validation failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SafeResponseError {
    /// HTTP status was outside 100–599.
    #[error("safe response status must be between 100 and 599")]
    InvalidStatus,
    /// Content type was empty, oversized, non-canonical, or contained unsafe bytes.
    #[error("safe response content type is invalid")]
    InvalidContentType,
    /// Body exceeded 2 MiB.
    #[error("safe response body exceeds the absolute bound")]
    BodyTooLarge,
}

/// Bounded idempotency persistence policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct IdempotencyConfig {
    /// Whether persistence is enabled. Disabled stores always start and complete as a no-op.
    pub enabled: bool,
    /// Lifetime before a key may be reclaimed.
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
    /// Maximum response body persisted by this store.
    pub max_response_bytes: usize,
}

impl Default for IdempotencyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl: DEFAULT_TTL,
            max_response_bytes: DEFAULT_RESPONSE_BYTES,
        }
    }
}

impl IdempotencyConfig {
    /// Validates TTL (1 second–30 days) and response size (1 byte–2 MiB).
    ///
    /// # Errors
    /// Returns [`IdempotencyConfigError`] when a bound is invalid.
    pub fn validate(self) -> Result<Self, IdempotencyConfigError> {
        if self.ttl < Duration::from_secs(1) || self.ttl > MAX_TTL {
            return Err(IdempotencyConfigError::InvalidTtl);
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > MAX_RESPONSE_BYTES {
            return Err(IdempotencyConfigError::InvalidResponseBound);
        }
        Ok(self)
    }
}

/// Idempotency configuration failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyConfigError {
    /// TTL was outside 1 second–30 days.
    #[error("idempotency TTL must be between 1 second and 30 days")]
    InvalidTtl,
    /// Response bound was outside 1 byte–2 MiB.
    #[error("idempotency response bound must be between 1 byte and 2 MiB")]
    InvalidResponseBound,
}

/// Result of atomically claiming an idempotency identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// The caller owns a new or reclaimed claim and may perform the business effect.
    Started,
    /// The same active request completed; return its exact original response.
    Replay(SafeResponse),
    /// The same active request remains in progress.
    InProgress,
}

/// Checked-query PostgreSQL store without an owned pool or hidden transaction.
#[derive(Clone, Copy, Debug)]
pub struct PostgresIdempotencyStore {
    config: IdempotencyConfig,
}

impl PostgresIdempotencyStore {
    /// Creates a store after validating its bounds.
    ///
    /// # Errors
    /// Returns [`IdempotencyConfigError`] for invalid configuration.
    pub fn new(config: IdempotencyConfig) -> Result<Self, IdempotencyConfigError> {
        Ok(Self {
            config: config.validate()?,
        })
    }

    /// Returns the validated configuration.
    #[must_use]
    pub const fn config(self) -> IdempotencyConfig {
        self.config
    }

    /// Inserts a claim or locks and classifies the existing identity.
    ///
    /// Expired rows are reclaimed. A different active hash conflicts; the same hash returns replay
    /// or in-progress. Use an explicit caller transaction to atomically coordinate the business
    /// effect and completion; this method never starts or commits one.
    ///
    /// # Errors
    /// Returns [`IdempotencyStoreError`] for conflicts, transient/unavailable PostgreSQL, lost
    /// ownership, or corrupt persisted state.
    pub async fn claim_with(
        &self,
        connection: &mut PgConnection,
        request: &IdempotencyRequest,
    ) -> Result<ClaimOutcome, IdempotencyStoreError> {
        let started = Instant::now();
        let result = self.claim_inner(connection, request).await;
        record_operation("claim", claim_result_label(&result), started.elapsed());
        result
    }

    /// Persists a bounded safe response only for a matching, unexpired in-progress claim.
    ///
    /// This method uses the caller's connection and never starts or commits a transaction.
    ///
    /// # Errors
    /// Returns [`IdempotencyStoreError`] if the claim is expired, lost, conflicting, unavailable,
    /// transient, corrupt, or the response exceeds the configured bound.
    pub async fn complete_with(
        &self,
        connection: &mut PgConnection,
        request: &IdempotencyRequest,
        response: &SafeResponse,
    ) -> Result<(), IdempotencyStoreError> {
        let started = Instant::now();
        let result = self.complete_inner(connection, request, response).await;
        record_operation(
            "complete",
            completion_result_label(result),
            started.elapsed(),
        );
        result
    }

    async fn claim_inner(
        &self,
        connection: &mut PgConnection,
        request: &IdempotencyRequest,
    ) -> Result<ClaimOutcome, IdempotencyStoreError> {
        if !self.config.enabled {
            return Ok(ClaimOutcome::Started);
        }
        let ttl_millis = self.config.ttl.as_secs_f64() * 1_000.0;
        let fingerprint = request.fingerprint.as_bytes();
        let inserted = sqlx::query_scalar!(
            r#"
            INSERT INTO idempotency_records (
                principal_scope, tenant_scope, operation, idempotency_key, request_hash,
                status, expires_at, created_at
            )
            VALUES ($1, $2, $3, $4, $5, 'in_progress',
                    clock_timestamp() + ($6 * INTERVAL '1 millisecond'), clock_timestamp())
            ON CONFLICT (principal_scope, tenant_scope, operation, idempotency_key) DO NOTHING
            RETURNING TRUE AS "inserted!"
            "#,
            request.scope.principal(),
            request.scope.tenant(),
            request.operation.as_str(),
            request.key.as_str(),
            fingerprint.as_slice(),
            ttl_millis,
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if inserted.is_some() {
            return Ok(ClaimOutcome::Started);
        }

        let existing = lock_record(connection, request)
            .await?
            .ok_or(IdempotencyStoreError::ClaimLost)?;
        if existing.expired {
            let reclaimed = sqlx::query!(
                r#"
                UPDATE idempotency_records
                SET request_hash = $5, status = 'in_progress', response_status = NULL,
                    response_content_type = NULL, response_body = NULL,
                    expires_at = clock_timestamp() + ($6 * INTERVAL '1 millisecond'),
                    created_at = clock_timestamp(), completed_at = NULL
                WHERE principal_scope IS NOT DISTINCT FROM $1
                  AND tenant_scope IS NOT DISTINCT FROM $2
                  AND operation = $3 AND idempotency_key = $4
                  AND expires_at <= clock_timestamp()
                "#,
                request.scope.principal(),
                request.scope.tenant(),
                request.operation.as_str(),
                request.key.as_str(),
                fingerprint.as_slice(),
                ttl_millis,
            )
            .execute(&mut *connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
            return if reclaimed.rows_affected() == 1 {
                Ok(ClaimOutcome::Started)
            } else {
                Err(IdempotencyStoreError::ClaimLost)
            };
        }

        let stored = RequestFingerprint::from_digest(&existing.request_hash)
            .map_err(|_| IdempotencyStoreError::CorruptData)?;
        if stored != request.fingerprint {
            return Err(IdempotencyStoreError::Conflict);
        }
        match existing.status.as_str() {
            "in_progress" if existing.is_clean_in_progress() => Ok(ClaimOutcome::InProgress),
            "completed" => {
                restore_response(existing, self.config.max_response_bytes).map(ClaimOutcome::Replay)
            }
            _ => Err(IdempotencyStoreError::CorruptData),
        }
    }

    async fn complete_inner(
        &self,
        connection: &mut PgConnection,
        request: &IdempotencyRequest,
        response: &SafeResponse,
    ) -> Result<(), IdempotencyStoreError> {
        if !self.config.enabled {
            return Ok(());
        }
        if response.body.len() > self.config.max_response_bytes {
            return Err(IdempotencyStoreError::ResponseTooLarge);
        }
        let fingerprint = request.fingerprint.as_bytes();
        let status =
            i16::try_from(response.status).map_err(|_| IdempotencyStoreError::CorruptData)?;
        let completed = sqlx::query_scalar!(
            r#"
            UPDATE idempotency_records
            SET status = 'completed', response_status = $6, response_content_type = $7,
                response_body = $8, completed_at = clock_timestamp()
            WHERE principal_scope IS NOT DISTINCT FROM $1
              AND tenant_scope IS NOT DISTINCT FROM $2
              AND operation = $3 AND idempotency_key = $4 AND request_hash = $5
              AND status = 'in_progress' AND expires_at > clock_timestamp()
            RETURNING TRUE AS "completed!"
            "#,
            request.scope.principal(),
            request.scope.tenant(),
            request.operation.as_str(),
            request.key.as_str(),
            fingerprint.as_slice(),
            status,
            response.content_type(),
            response.body(),
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if completed.is_some() {
            return Ok(());
        }

        let Some(existing) = lock_record(connection, request).await? else {
            return Err(IdempotencyStoreError::ClaimLost);
        };
        if existing.expired {
            return Err(IdempotencyStoreError::ClaimExpired);
        }
        let stored = RequestFingerprint::from_digest(&existing.request_hash)
            .map_err(|_| IdempotencyStoreError::CorruptData)?;
        if stored != request.fingerprint {
            return Err(IdempotencyStoreError::Conflict);
        }
        Err(match existing.status.as_str() {
            "in_progress" | "completed" => IdempotencyStoreError::ClaimLost,
            _ => IdempotencyStoreError::CorruptData,
        })
    }
}

#[derive(Debug)]
struct RecordRow {
    request_hash: Vec<u8>,
    status: String,
    response_status: Option<i16>,
    response_content_type: Option<String>,
    response_body: Option<Vec<u8>>,
    expired: bool,
    completed: bool,
}

impl RecordRow {
    fn is_clean_in_progress(&self) -> bool {
        self.response_status.is_none()
            && self.response_content_type.is_none()
            && self.response_body.is_none()
            && !self.completed
    }
}

async fn lock_record(
    connection: &mut PgConnection,
    request: &IdempotencyRequest,
) -> Result<Option<RecordRow>, IdempotencyStoreError> {
    sqlx::query_as!(
        RecordRow,
        r#"
        SELECT request_hash, status, response_status, response_content_type, response_body,
               expires_at <= clock_timestamp() AS "expired!",
               completed_at IS NOT NULL AS "completed!"
        FROM idempotency_records
        WHERE principal_scope IS NOT DISTINCT FROM $1
          AND tenant_scope IS NOT DISTINCT FROM $2
          AND operation = $3 AND idempotency_key = $4
        FOR UPDATE
        "#,
        request.scope.principal(),
        request.scope.tenant(),
        request.operation.as_str(),
        request.key.as_str(),
    )
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))
}

fn restore_response(
    record: RecordRow,
    configured_max: usize,
) -> Result<SafeResponse, IdempotencyStoreError> {
    let status = record
        .response_status
        .and_then(|value| u16::try_from(value).ok())
        .ok_or(IdempotencyStoreError::CorruptData)?;
    let body = record
        .response_body
        .ok_or(IdempotencyStoreError::CorruptData)?;
    if !record.completed || body.len() > configured_max {
        return Err(IdempotencyStoreError::CorruptData);
    }
    SafeResponse::new(status, record.response_content_type, body)
        .map_err(|_| IdempotencyStoreError::CorruptData)
}

/// Stable, value-free persistence failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdempotencyStoreError {
    /// An active identity was reused with a different fingerprint.
    #[error("idempotency identity conflicts with an active request")]
    Conflict,
    /// Ownership disappeared or the claim was already completed.
    #[error("idempotency claim ownership was lost")]
    ClaimLost,
    /// Completion happened after expiry.
    #[error("idempotency claim has expired")]
    ClaimExpired,
    /// The response exceeded the configured bound.
    #[error("idempotency response exceeds the configured bound")]
    ResponseTooLarge,
    /// The caller's whole transaction may be replayed for this SQLSTATE.
    #[error("idempotency transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// PostgreSQL was unavailable or returned an unclassified error.
    #[error("idempotency persistence is unavailable")]
    Unavailable,
    /// PostgreSQL rejected values that passed public validation.
    #[error("idempotency persistence rejected the requested state")]
    ConstraintViolation,
    /// Persisted state violated the idempotency contract.
    #[error("idempotency persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for IdempotencyStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> IdempotencyStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return IdempotencyStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23505" | "23514" | "23502" | "22003") => {
            IdempotencyStoreError::ConstraintViolation
        }
        _ => IdempotencyStoreError::Unavailable,
    }
}

fn claim_result_label(result: &Result<ClaimOutcome, IdempotencyStoreError>) -> &'static str {
    match result {
        Ok(ClaimOutcome::Started) => "started",
        Ok(ClaimOutcome::Replay(_)) => "replay",
        Ok(ClaimOutcome::InProgress) => "in_progress",
        Err(error) => error_label(*error),
    }
}

fn completion_result_label(result: Result<(), IdempotencyStoreError>) -> &'static str {
    match result {
        Ok(()) => "completed",
        Err(error) => error_label(error),
    }
}

const fn error_label(error: IdempotencyStoreError) -> &'static str {
    match error {
        IdempotencyStoreError::Conflict => "conflict",
        IdempotencyStoreError::ClaimLost => "claim_lost",
        IdempotencyStoreError::ClaimExpired => "expired",
        IdempotencyStoreError::ResponseTooLarge => "response_too_large",
        IdempotencyStoreError::Transient(_) => "transient",
        IdempotencyStoreError::Unavailable => "unavailable",
        IdempotencyStoreError::ConstraintViolation => "constraint_violation",
        IdempotencyStoreError::CorruptData => "corrupt",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "omnius_idempotency_operations_total",
        "operation" => operation,
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_idempotency_operation_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_validation_enforces_bound_and_visible_ascii() {
        assert_eq!(
            IdempotencyKey::new(String::new()),
            Err(IdempotencyKeyError::Empty)
        );
        assert_eq!(
            IdempotencyKey::new("x".repeat(MAX_VALUE_BYTES + 1)),
            Err(IdempotencyKeyError::TooLong)
        );
        assert_eq!(
            IdempotencyKey::new("has space".to_owned()),
            Err(IdempotencyKeyError::InvalidCharacter)
        );
        assert!(IdempotencyKey::new("request-1".to_owned()).is_ok());
    }

    #[test]
    fn scope_and_operation_validation_are_canonical_and_bounded() {
        assert_eq!(
            IdempotencyScopeValue::new(" tenant".to_owned()),
            Err(IdempotencyScopeValueError::SurroundingWhitespace)
        );
        assert_eq!(
            IdempotencyScopeValue::new("tenant\0".to_owned()),
            Err(IdempotencyScopeValueError::ControlCharacter)
        );
        assert!(IdempotencyScopeValue::new("tenant-α".to_owned()).is_ok());
        assert_eq!(
            IdempotencyOperation::new("widgets create"),
            Err(IdempotencyOperationError::InvalidCharacter)
        );
        assert!(IdempotencyOperation::new("widgets.create").is_ok());
    }

    #[test]
    fn fingerprint_uses_sha256_and_requires_exact_length() {
        assert_eq!(
            RequestFingerprint::sha256(b"abc").as_bytes(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        assert_eq!(
            RequestFingerprint::from_digest(&[0; 31]),
            Err(RequestFingerprintError::InvalidLength)
        );
    }

    #[test]
    fn config_validation_enforces_fixed_bounds() {
        let valid = IdempotencyConfig::default();
        assert_eq!(valid.validate(), Ok(valid));
        assert_eq!(
            IdempotencyConfig {
                ttl: Duration::ZERO,
                ..valid
            }
            .validate(),
            Err(IdempotencyConfigError::InvalidTtl)
        );
        assert_eq!(
            IdempotencyConfig {
                ttl: MAX_TTL + Duration::from_secs(1),
                ..valid
            }
            .validate(),
            Err(IdempotencyConfigError::InvalidTtl)
        );
        assert_eq!(
            IdempotencyConfig {
                max_response_bytes: MAX_RESPONSE_BYTES + 1,
                ..valid
            }
            .validate(),
            Err(IdempotencyConfigError::InvalidResponseBound)
        );
    }

    #[test]
    fn safe_response_validation_bounds_replay_data() {
        assert_eq!(
            SafeResponse::new(99, None, Vec::new()),
            Err(SafeResponseError::InvalidStatus)
        );
        assert_eq!(
            SafeResponse::new(200, Some("text/plain\r\nx: y".to_owned()), Vec::new()),
            Err(SafeResponseError::InvalidContentType)
        );
        assert_eq!(
            SafeResponse::new(200, None, vec![0; MAX_RESPONSE_BYTES + 1]),
            Err(SafeResponseError::BodyTooLarge)
        );
        assert!(
            SafeResponse::new(201, Some("application/json".to_owned()), b"{}".to_vec()).is_ok()
        );
    }
}
