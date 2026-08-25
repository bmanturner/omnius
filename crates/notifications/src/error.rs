use rsk_audit::AuditSinkError;
use rsk_postgres::{PostgresError, RetryableSqlState, RetryableTransactionError};
use thiserror::Error;

use crate::{NotificationValidationError, UnsubscribeTokenError};

/// Stable, value-free notification service failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum NotificationError {
    /// A public value failed bounded validation.
    #[error("notification request is invalid")]
    InvalidRequest,
    /// PostgreSQL reported a retryable transaction conflict.
    #[error("notification transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted notification state failed a schema invariant.
    #[error("notification persistence rejected requested state")]
    ConstraintViolation,
    /// PostgreSQL was unavailable or returned an unclassified failure.
    #[error("notification persistence is unavailable")]
    DatabaseUnavailable,
    /// Persisted state was missing or internally inconsistent.
    #[error("notification state is unavailable")]
    InvalidState,
    /// Digest members selected incompatible delivery presentation.
    #[error("notification digest selection conflicts with its existing bucket")]
    DigestConflict,
    /// The fixed digest member ceiling was reached.
    #[error("notification digest bucket is full")]
    DigestFull,
    /// No delivery exists inside the requested tenant fence.
    #[error("notification delivery was not found")]
    NotFound,
    /// A capability was malformed, mismatched, expired, revoked, or consumed.
    #[error("unsubscribe capability is invalid")]
    InvalidUnsubscribe,
    /// Audit persistence is disabled for a mutating preference service.
    #[error("notification preference audit is required")]
    AuditRequired,
    /// Atomic audit persistence failed.
    #[error("notification preference audit is unavailable")]
    AuditUnavailable,
    /// An email value reconstructed from authoritative persistence was invalid.
    #[error("notification email presentation is invalid")]
    InvalidEmailPresentation,
    /// A durable job envelope could not be constructed or restored.
    #[error("notification job envelope is invalid")]
    InvalidJobEnvelope,
}

impl RetryableTransactionError for NotificationError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl From<NotificationValidationError> for NotificationError {
    fn from(_: NotificationValidationError) -> Self {
        Self::InvalidRequest
    }
}

impl From<UnsubscribeTokenError> for NotificationError {
    fn from(error: UnsubscribeTokenError) -> Self {
        match error {
            UnsubscribeTokenError::InvalidPresentation => Self::InvalidUnsubscribe,
            UnsubscribeTokenError::EntropyUnavailable | UnsubscribeTokenError::InvalidPepper => {
                Self::InvalidState
            }
        }
    }
}

impl From<PostgresError> for NotificationError {
    fn from(_: PostgresError) -> Self {
        Self::DatabaseUnavailable
    }
}

impl From<AuditSinkError> for NotificationError {
    fn from(error: AuditSinkError) -> Self {
        match error {
            AuditSinkError::Transient(state) => Self::Transient(state),
            AuditSinkError::ConstraintViolation | AuditSinkError::Unavailable => {
                Self::AuditUnavailable
            }
        }
    }
}

pub(crate) fn map_sqlx(error: &sqlx::Error) -> NotificationError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return NotificationError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("23502" | "23503" | "23505" | "23514" | "22001" | "55000") => {
            NotificationError::ConstraintViolation
        }
        _ => NotificationError::DatabaseUnavailable,
    }
}
