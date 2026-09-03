//! Bounded `SQLx` PostgreSQL pooling, lifecycle telemetry, and cached health integration.

mod config;
mod pool;
mod transaction;

pub use config::{PostgresConfig, PostgresConfigError, PostgresTlsMode};
pub use pool::{PostgresConnection, PostgresError, PostgresPool, PostgresPoolStats};
pub use sqlx;
pub use transaction::{
    PostgresTransactionRunner, RetryableSqlState, RetryableTransactionError, TransactionIsolation,
    TransactionRetryConfig, TransactionRetryConfigError, TransactionRunError,
};
