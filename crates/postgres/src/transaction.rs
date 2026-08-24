use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use sqlx::{Connection as _, PgConnection};
use thiserror::Error;

use crate::{PostgresConnection, PostgresPool};

const MAX_ATTEMPTS: u8 = 10;
const MAX_BASE_DELAY: Duration = Duration::from_secs(5);
const MAX_DELAY: Duration = Duration::from_secs(30);
const MAX_JITTER: Duration = Duration::from_secs(5);

/// PostgreSQL isolation for an explicitly repeatable transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TransactionIsolation {
    /// PostgreSQL's default statement-snapshot isolation.
    ReadCommitted,
    /// One snapshot for the complete transaction.
    RepeatableRead,
    /// Serializable execution with PostgreSQL conflict detection.
    Serializable,
}

impl TransactionIsolation {
    const fn begin_statement(self) -> &'static str {
        match self {
            Self::ReadCommitted => "BEGIN ISOLATION LEVEL READ COMMITTED",
            Self::RepeatableRead => "BEGIN ISOLATION LEVEL REPEATABLE READ",
            Self::Serializable => "BEGIN ISOLATION LEVEL SERIALIZABLE",
        }
    }
}

/// Bounded replay policy for a whole transaction closure.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TransactionRetryConfig {
    /// Total attempts, including the first execution.
    pub max_attempts: u8,
    /// Initial delay before the first replay.
    #[serde(with = "humantime_serde")]
    pub base_delay: Duration,
    /// Maximum exponential delay before jitter.
    #[serde(with = "humantime_serde")]
    pub max_delay: Duration,
    /// Maximum additional per-attempt jitter.
    #[serde(with = "humantime_serde")]
    pub max_jitter: Duration,
    /// Isolation level used for every fresh attempt.
    pub isolation: TransactionIsolation,
}

impl TransactionRetryConfig {
    /// Validates fixed attempt and delay bounds.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionRetryConfigError`] for zero/unbounded attempts,
    /// delays outside fixed limits, or reversed delay relationships.
    pub fn validate(self) -> Result<(), TransactionRetryConfigError> {
        if self.max_attempts == 0 || self.max_attempts > MAX_ATTEMPTS {
            return Err(TransactionRetryConfigError::InvalidAttempts);
        }
        if self.base_delay < Duration::from_millis(1)
            || self.base_delay > MAX_BASE_DELAY
            || self.max_delay < self.base_delay
            || self.max_delay > MAX_DELAY
            || self.max_jitter > MAX_JITTER
        {
            return Err(TransactionRetryConfigError::InvalidDelay);
        }
        Ok(())
    }
}

/// Stable retry configuration failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TransactionRetryConfigError {
    /// Attempts must be in the inclusive range 1–10.
    #[error("transaction retry attempts must be between 1 and 10")]
    InvalidAttempts,
    /// Backoff and jitter exceeded fixed safety relationships.
    #[error("transaction retry delay policy is invalid")]
    InvalidDelay,
}

/// PostgreSQL failures safe for unconditional replay of a whole transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryableSqlState {
    /// `40001`: serialization failure.
    SerializationFailure,
    /// `40P01`: deadlock detected.
    DeadlockDetected,
}

impl RetryableSqlState {
    /// Classifies a `SQLx` error without retaining its statement or values.
    #[must_use]
    pub fn from_sqlx(error: &sqlx::Error) -> Option<Self> {
        let code = error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)?;
        match code.as_ref() {
            "40001" => Some(Self::SerializationFailure),
            "40P01" => Some(Self::DeadlockDetected),
            _ => None,
        }
    }

    /// Returns the stable SQLSTATE metric label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SerializationFailure => "40001",
            Self::DeadlockDetected => "40P01",
        }
    }
}

/// Allows an operation error to expose only a safe replay classification.
pub trait RetryableTransactionError: Error + Send + Sync + 'static {
    /// Returns a replay-safe SQLSTATE when the complete closure may be rerun.
    fn retryable_sql_state(&self) -> Option<RetryableSqlState>;
}

impl RetryableTransactionError for sqlx::Error {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        RetryableSqlState::from_sqlx(self)
    }
}

/// Runs explicitly repeatable whole transactions on fresh leases.
#[derive(Clone)]
pub struct PostgresTransactionRunner {
    pool: PostgresPool,
    config: TransactionRetryConfig,
    sequence: Arc<AtomicU64>,
}

impl PostgresTransactionRunner {
    /// Creates a runner with bounded replay policy.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionRetryConfigError`] for invalid retry policy.
    pub fn new(
        pool: PostgresPool,
        config: TransactionRetryConfig,
    ) -> Result<Self, TransactionRetryConfigError> {
        config.validate()?;
        Ok(Self {
            pool,
            config,
            sequence: Arc::new(AtomicU64::new(jitter_seed())),
        })
    }

    /// Runs a complete replay-safe closure in a fresh transaction per attempt.
    ///
    /// The closure must contain all database-dependent decisions and must not
    /// perform external side effects, network calls, or consume non-repeatable
    /// input. Only operation-body SQLSTATE `40001` and `40P01` are retried.
    /// Commit failures are never retried because their outcome may be ambiguous.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionRunError`] for acquisition, begin, operation,
    /// rollback, commit, or exhausted replay failures.
    pub async fn run_repeatable<T, E, F>(
        &self,
        operation: &'static str,
        mut transaction: F,
    ) -> Result<T, TransactionRunError<E>>
    where
        T: Send,
        E: RetryableTransactionError,
        F: for<'connection> AsyncFnMut(&'connection mut PgConnection) -> Result<T, E> + Send,
    {
        let started = Instant::now();
        for attempt in 1..=self.config.max_attempts {
            let Ok(mut connection) = self.pool.acquire().await else {
                record_completion(operation, "acquire_error", started.elapsed());
                return Err(TransactionRunError::Acquire);
            };
            let Ok(mut transaction_handle) = connection
                .begin_with(self.config.isolation.begin_statement())
                .await
            else {
                record_completion(operation, "begin_error", started.elapsed());
                return Err(TransactionRunError::Begin);
            };

            match transaction(&mut transaction_handle).await {
                Ok(value) => {
                    if transaction_handle.commit().await.is_err() {
                        discard(connection);
                        record_completion(operation, "commit_error", started.elapsed());
                        return Err(TransactionRunError::Commit);
                    }
                    record_completion(operation, "ok", started.elapsed());
                    return Ok(value);
                }
                Err(error) => {
                    let retry_state = error.retryable_sql_state();
                    if transaction_handle.rollback().await.is_err() {
                        discard(connection);
                        record_completion(operation, "rollback_error", started.elapsed());
                        return Err(TransactionRunError::Rollback);
                    }
                    drop(connection);
                    let Some(state) = retry_state else {
                        record_completion(operation, "operation_error", started.elapsed());
                        return Err(TransactionRunError::Operation(error));
                    };
                    if attempt == self.config.max_attempts {
                        record_completion(operation, "exhausted", started.elapsed());
                        return Err(TransactionRunError::RetryExhausted {
                            attempts: attempt,
                            last_error: error,
                        });
                    }
                    self.wait_before_retry(operation, attempt, state).await;
                }
            }
        }
        unreachable!("validated transaction attempt count is positive")
    }

    async fn wait_before_retry(
        &self,
        operation: &'static str,
        attempt: u8,
        state: RetryableSqlState,
    ) {
        let delay = retry_delay(
            self.config,
            attempt,
            self.sequence.fetch_add(1, Ordering::Relaxed),
        );
        metrics::counter!(
            "rsk_postgres_transaction_retries_total",
            "operation" => operation,
            "sqlstate" => state.as_str()
        )
        .increment(1);
        tracing::warn!(
            operation,
            attempt,
            sqlstate = state.as_str(),
            delay_ms = delay.as_millis(),
            "replaying transient PostgreSQL transaction"
        );
        tokio::time::sleep(delay).await;
    }
}

impl fmt::Debug for PostgresTransactionRunner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresTransactionRunner")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// Stable transaction-stage failure with an optional safe operation error.
#[derive(Debug)]
pub enum TransactionRunError<E> {
    /// A pool lease could not be acquired.
    Acquire,
    /// PostgreSQL rejected transaction start.
    Begin,
    /// The operation failed with a non-retryable error.
    Operation(E),
    /// Explicit rollback failed.
    Rollback,
    /// Commit failed and its outcome may be ambiguous. Commit errors are never
    /// replayed, including errors that carry a normally transient SQLSTATE.
    Commit,
    /// Every configured attempt failed with a safe transient SQLSTATE.
    RetryExhausted {
        /// Total closure executions.
        attempts: u8,
        /// Last operation error.
        last_error: E,
    },
}

impl<E> fmt::Display for TransactionRunError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Acquire => "PostgreSQL transaction acquisition failed",
            Self::Begin => "PostgreSQL transaction begin failed",
            Self::Operation(_) => "PostgreSQL transaction operation failed",
            Self::Rollback => "PostgreSQL transaction rollback failed",
            Self::Commit => "PostgreSQL transaction commit outcome is unknown",
            Self::RetryExhausted { .. } => "PostgreSQL transaction retries exhausted",
        })
    }
}

impl<E: Error + 'static> Error for TransactionRunError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Operation(error)
            | Self::RetryExhausted {
                last_error: error, ..
            } => Some(error),
            _ => None,
        }
    }
}

fn discard(connection: PostgresConnection) {
    drop(tokio::spawn(async move {
        let _ = connection.discard().await;
    }));
}

fn retry_delay(config: TransactionRetryConfig, attempt: u8, seed: u64) -> Duration {
    let exponent = u32::from(attempt.saturating_sub(1)).min(31);
    let backoff = config
        .base_delay
        .saturating_mul(1_u32 << exponent)
        .min(config.max_delay);
    let jitter_nanos = u64::try_from(config.max_jitter.as_nanos()).unwrap_or(u64::MAX);
    let jitter = if jitter_nanos == 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(mix(seed ^ u64::from(attempt)) % jitter_nanos.saturating_add(1))
    };
    backoff.saturating_add(jitter)
}

fn jitter_seed() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let folded = u64::try_from(time).unwrap_or_else(|_| {
        let high = u64::try_from(time >> 64).unwrap_or(u64::MAX);
        let low = u64::try_from(time & u128::from(u64::MAX)).unwrap_or(u64::MAX);
        high ^ low
    });
    mix(folded ^ u64::from(std::process::id()))
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn record_completion(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_postgres_transactions_total",
        "operation" => operation,
        "result" => result
    )
    .increment(1);
    metrics::histogram!(
        "rsk_postgres_transaction_duration_seconds",
        "operation" => operation
    )
    .record(elapsed.as_secs_f64());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_retry_policy_bounds() {
        let config = TransactionRetryConfig {
            max_attempts: 0,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_secs(1),
            max_jitter: Duration::ZERO,
            isolation: TransactionIsolation::Serializable,
        };
        assert_eq!(
            config.validate(),
            Err(TransactionRetryConfigError::InvalidAttempts)
        );
    }

    #[test]
    fn deterministic_delay_is_bounded() {
        let config = TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(20),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        };
        assert_eq!(retry_delay(config, 1, 42), retry_delay(config, 1, 42));
        assert!(retry_delay(config, 3, 42) <= Duration::from_millis(25));
    }
}
