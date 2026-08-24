//! Durable, atomic issuance and consumption of OIDC callback state.

use std::{fmt, time::Instant};

use metrics::{counter, histogram};
use rsk_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::Row as _;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::flow::{AuthorizationStart, PendingAuthorization, TakenAuthorization};

const MAX_CLEANUP_BATCH: u32 = 10_000;

/// Opaque row handle that applications keep only in server-side session state.
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
pub struct PendingAuthorizationId(Uuid);

impl fmt::Debug for PendingAuthorizationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingAuthorizationId([REDACTED])")
    }
}

/// Browser redirect produced only after its pending authorization is durable.
pub struct IssuedAuthorization {
    authorization_url: rsk_outbound_http::Url,
    pending_id: PendingAuthorizationId,
}

impl IssuedAuthorization {
    /// Borrows the provider authorization URL to send to the browser.
    #[must_use]
    pub const fn authorization_url(&self) -> &rsk_outbound_http::Url {
        &self.authorization_url
    }

    /// Borrows the opaque handle to store in the server-side session.
    #[must_use]
    pub const fn pending_id(&self) -> &PendingAuthorizationId {
        &self.pending_id
    }

    /// Consumes the issued authorization into its browser URL and server-side handle.
    #[must_use]
    pub fn into_parts(self) -> (rsk_outbound_http::Url, PendingAuthorizationId) {
        (self.authorization_url, self.pending_id)
    }
}

impl fmt::Debug for IssuedAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IssuedAuthorization([REDACTED])")
    }
}

/// PostgreSQL-backed pending authorization store shared by every service instance.
#[derive(Clone, Debug)]
pub struct OidcPendingStore {
    pool: PostgresPool,
}

impl OidcPendingStore {
    /// Creates a pending store from the managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Persists callback secrets before exposing the provider redirect URL.
    ///
    /// # Errors
    /// Returns a stable error if serialization fails, the state collides, or PostgreSQL is unavailable.
    pub async fn issue(
        &self,
        start: AuthorizationStart,
    ) -> Result<IssuedAuthorization, OidcPendingStoreError> {
        let started = Instant::now();
        let AuthorizationStart {
            authorization_url,
            pending,
        } = start;
        let pending_id = PendingAuthorizationId(Uuid::now_v7());
        let authorization = serde_json::to_value(&pending)
            .map_err(|_| OidcPendingStoreError::InvalidAuthorization)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OidcPendingStoreError::Unavailable)?;
        let result = sqlx::query(
            "INSERT INTO oidc_pending_authorizations \
             (id, state_digest, payload, expires_at, created_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(pending_id.0)
        .bind(pending.state_digest.as_slice())
        .bind(authorization)
        .bind(pending.expires_at)
        .bind(OffsetDateTime::now_utc())
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))
        .map(|_| IssuedAuthorization {
            authorization_url,
            pending_id,
        });
        record(
            "issue",
            result
                .as_ref()
                .map_or_else(|error| error.label(), |_| "success"),
            started.elapsed(),
        );
        result
    }

    /// Atomically removes and returns pending state selected by its server-side handle.
    ///
    /// The row is deleted before deserialization or expiry checks, so every callback attempt
    /// consumes it even when callback validation later fails.
    ///
    /// # Errors
    /// Returns [`OidcPendingStoreError::UnavailableAuthorization`] when the handle is unknown or
    /// already consumed, and a stable value-free error for corrupt or unavailable storage.
    pub async fn take(
        &self,
        pending_id: PendingAuthorizationId,
    ) -> Result<TakenAuthorization, OidcPendingStoreError> {
        let started = Instant::now();
        let result = self.take_inner(pending_id).await;
        record(
            "take",
            result
                .as_ref()
                .map_or_else(|error| error.label(), |_| "success"),
            started.elapsed(),
        );
        result
    }

    async fn take_inner(
        &self,
        pending_id: PendingAuthorizationId,
    ) -> Result<TakenAuthorization, OidcPendingStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OidcPendingStoreError::Unavailable)?;
        let row = sqlx::query(
            "DELETE FROM oidc_pending_authorizations \
             WHERE id = $1 \
             RETURNING payload, expires_at",
        )
        .bind(pending_id.0)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?
        .ok_or(OidcPendingStoreError::UnavailableAuthorization)?;
        let authorization: Value = row
            .try_get("payload")
            .map_err(|_| OidcPendingStoreError::CorruptAuthorization)?;
        let expires_at: OffsetDateTime = row
            .try_get("expires_at")
            .map_err(|_| OidcPendingStoreError::CorruptAuthorization)?;
        if OffsetDateTime::now_utc() >= expires_at {
            return Err(OidcPendingStoreError::ExpiredAuthorization);
        }
        let pending: PendingAuthorization = serde_json::from_value(authorization)
            .map_err(|_| OidcPendingStoreError::CorruptAuthorization)?;
        Ok(TakenAuthorization { pending })
    }

    /// Deletes a bounded batch of expired pending authorizations for scheduled cleanup.
    ///
    /// # Errors
    /// Returns a stable error for an invalid batch size or unavailable PostgreSQL.
    pub async fn cleanup_expired(&self, max_rows: u32) -> Result<u64, OidcPendingStoreError> {
        if max_rows == 0 || max_rows > MAX_CLEANUP_BATCH {
            return Err(OidcPendingStoreError::InvalidCleanupBatch);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OidcPendingStoreError::Unavailable)?;
        let result = sqlx::query(
            "WITH expired AS ( \
                 SELECT state_digest FROM oidc_pending_authorizations \
                 WHERE expires_at <= $1 ORDER BY expires_at LIMIT $2 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             DELETE FROM oidc_pending_authorizations AS pending \
             USING expired WHERE pending.state_digest = expired.state_digest",
        )
        .bind(OffsetDateTime::now_utc())
        .bind(i64::from(max_rows))
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        Ok(result.rows_affected())
    }
}

/// Stable, value-free pending authorization storage failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OidcPendingStoreError {
    /// The authorization could not be represented for durable storage.
    #[error("OIDC pending authorization is invalid")]
    InvalidAuthorization,
    /// The state is unknown, was consumed, or collided with an existing state.
    #[error("OIDC pending authorization is unavailable")]
    UnavailableAuthorization,
    /// The pending authorization expired and was consumed.
    #[error("OIDC pending authorization has expired")]
    ExpiredAuthorization,
    /// Stored authorization state violated the module contract and was consumed.
    #[error("OIDC pending authorization is corrupt")]
    CorruptAuthorization,
    /// PostgreSQL is unavailable.
    #[error("OIDC pending authorization storage is unavailable")]
    Unavailable,
    /// The operation encountered a safe-to-retry SQL conflict.
    #[error("OIDC pending authorization storage encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// The cleanup batch size is outside the supported bound.
    #[error("OIDC pending authorization cleanup batch is invalid")]
    InvalidCleanupBatch,
}

impl OidcPendingStoreError {
    const fn label(self) -> &'static str {
        match self {
            Self::InvalidAuthorization => "invalid_authorization",
            Self::UnavailableAuthorization => "unavailable_authorization",
            Self::ExpiredAuthorization => "expired_authorization",
            Self::CorruptAuthorization => "corrupt_authorization",
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::InvalidCleanupBatch => "invalid_cleanup_batch",
        }
    }
}

impl RetryableTransactionError for OidcPendingStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> OidcPendingStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return OidcPendingStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23505") => {
            OidcPendingStoreError::UnavailableAuthorization
        }
        Some(code) if matches!(code.as_ref(), "23502" | "23514") => {
            OidcPendingStoreError::InvalidAuthorization
        }
        _ => OidcPendingStoreError::Unavailable,
    }
}

fn record(operation: &'static str, result: &'static str, elapsed: std::time::Duration) {
    counter!(
        "rsk_auth_oidc_pending_operations_total",
        "operation" => operation,
        "result" => result,
    )
    .increment(1);
    histogram!(
        "rsk_auth_oidc_pending_operation_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}
