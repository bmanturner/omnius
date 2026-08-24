//! Bounded `SQLx` PostgreSQL pooling, lifecycle telemetry, and cached health integration.

mod config;
mod pool;

pub use config::{PostgresConfig, PostgresConfigError, PostgresTlsMode};
pub use pool::{PostgresConnection, PostgresError, PostgresPool, PostgresPoolStats};
