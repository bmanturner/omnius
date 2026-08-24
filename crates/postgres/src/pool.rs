use std::{
    fmt,
    ops::{Deref, DerefMut},
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use rsk_config::{DeploymentEnvironment, ExposeSecret as _};
use rsk_core::ErrorCode;
use rsk_health::{CheckFailure, HealthCheckSpec};
use rsk_runtime::Criticality;
use sqlx::{
    ConnectOptions as _, Executor as _, PgPool, Postgres,
    pool::PoolConnection,
    postgres::{PgConnectOptions, PgConnection, PgPoolOptions, PgSslMode},
};
use thiserror::Error;

use crate::config::{PostgresConfig, PostgresConfigError, PostgresTlsMode, effective_lifetime};

const HEALTH_CHECK_NAME: &str = "postgres-connectivity";
const MODULE_NAME: &str = "postgres";
const UNAVAILABLE_CODE: &str = "DATABASE_UNAVAILABLE";

/// Owned `SQLx` PostgreSQL pool with bounded lifecycle and stable telemetry.
#[derive(Clone)]
pub struct PostgresPool {
    inner: PgPool,
    max_connections: u32,
    acquire_timeout: Duration,
    effective_max_lifetime: Duration,
    health_timeout: Duration,
    shutdown_timeout: Duration,
}

impl PostgresPool {
    /// Eagerly opens and initializes a bounded PostgreSQL pool.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresError`] for invalid policy, connection failure, or a
    /// startup deadline. Errors never retain or render the secret URL.
    pub async fn connect(
        config: &PostgresConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<Self, PostgresError> {
        config
            .validate_for(deployment)
            .map_err(PostgresError::Config)?;
        let connect_options = PgConnectOptions::from_str(config.url.expose_secret())
            .map_err(|_| PostgresError::Config(PostgresConfigError::InvalidUrl))?;
        let ssl_mode = match config.tls_mode {
            PostgresTlsMode::Disable => PgSslMode::Disable,
            PostgresTlsMode::VerifyFull => PgSslMode::VerifyFull,
        };
        let statement_timeout = postgres_duration(config.statement_timeout);
        let lock_timeout = postgres_duration(config.lock_timeout);
        let connect_options = connect_options
            .ssl_mode(ssl_mode)
            .application_name(&config.application_name)
            .options([
                ("statement_timeout", statement_timeout),
                ("lock_timeout", lock_timeout),
                ("timezone", "UTC".to_owned()),
            ])
            .disable_statement_logging();

        let initialization_sql: Arc<[String]> = config.initialization_sql.clone().into();
        let effective_max_lifetime = effective_lifetime(config, jitter_seed());
        let pool_options = PgPoolOptions::new()
            .min_connections(config.min_connections)
            .max_connections(config.max_connections)
            .acquire_timeout(config.connect_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(effective_max_lifetime)
            .test_before_acquire(true)
            .after_connect(move |connection, _metadata| {
                let statements = Arc::clone(&initialization_sql);
                Box::pin(async move {
                    for statement in statements.iter() {
                        connection.execute(statement.as_str()).await?;
                    }
                    Ok(())
                })
            });

        let started = Instant::now();
        let connected = tokio::time::timeout(
            config.connect_timeout,
            pool_options.connect_with(connect_options),
        )
        .await;
        let inner = match connected {
            Ok(Ok(pool)) => {
                record_operation("connect", "ok", started.elapsed());
                pool
            }
            Ok(Err(sqlx::Error::PoolTimedOut)) | Err(_) => {
                record_operation("connect", "timeout", started.elapsed());
                return Err(PostgresError::ConnectTimeout);
            }
            Ok(Err(_)) => {
                record_operation("connect", "error", started.elapsed());
                return Err(PostgresError::Connect);
            }
        };
        let pool = Self {
            inner,
            max_connections: config.max_connections,
            acquire_timeout: config.acquire_timeout,
            effective_max_lifetime,
            health_timeout: config.health_timeout,
            shutdown_timeout: config.shutdown_timeout,
        };
        pool.record_stats();
        Ok(pool)
    }

    /// Acquires one connection with bounded result and latency telemetry.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresError`] when saturated, closed, timed out, or unable
    /// to establish a replacement connection.
    pub async fn acquire(&self) -> Result<PostgresConnection, PostgresError> {
        let started = Instant::now();
        let result = tokio::time::timeout(self.acquire_timeout, self.inner.acquire()).await;
        let mapped = match result {
            Ok(Ok(connection)) => {
                record_operation("acquire", "ok", started.elapsed());
                Ok(PostgresConnection {
                    connection: Some(connection),
                    pool: self.clone(),
                })
            }
            Err(_) | Ok(Err(sqlx::Error::PoolTimedOut)) => {
                record_operation("acquire", "timeout", started.elapsed());
                Err(PostgresError::AcquireTimeout)
            }
            Ok(Err(sqlx::Error::PoolClosed)) => {
                record_operation("acquire", "closed", started.elapsed());
                Err(PostgresError::Closed)
            }
            Ok(Err(_)) => {
                record_operation("acquire", "error", started.elapsed());
                Err(PostgresError::Acquire)
            }
        };
        self.record_stats();
        mapped
    }

    /// Returns a required cached-health check for `postgres-connectivity`.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        let pool = self.clone();
        HealthCheckSpec::new(
            HEALTH_CHECK_NAME,
            MODULE_NAME,
            Criticality::Required,
            self.health_timeout,
            move || {
                let pool = pool.clone();
                async move { pool.check_health().await }
            },
        )
    }

    /// Returns a low-cardinality point-in-time utilization snapshot.
    #[must_use]
    pub fn stats(&self) -> PostgresPoolStats {
        let size = self.inner.size();
        let idle = u32::try_from(self.inner.num_idle()).unwrap_or(u32::MAX);
        PostgresPoolStats {
            size,
            idle,
            in_use: size.saturating_sub(idle),
            max: self.max_connections,
            closed: self.inner.is_closed(),
        }
    }

    /// Returns the process-jittered maximum lifetime applied to connections.
    #[must_use]
    pub const fn effective_max_lifetime(&self) -> Duration {
        self.effective_max_lifetime
    }

    /// Marks the pool closed, wakes waiters, and waits under the configured
    /// deadline for leased connections to return and close.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresError::CloseTimeout`] if a lease outlives the bounded
    /// shutdown deadline. The pool remains closed after this error.
    pub async fn close(&self) -> Result<(), PostgresError> {
        let started = Instant::now();
        if tokio::time::timeout(self.shutdown_timeout, self.inner.close())
            .await
            .is_ok()
        {
            record_operation("close", "ok", started.elapsed());
            self.record_stats();
            Ok(())
        } else {
            record_operation("close", "timeout", started.elapsed());
            self.record_stats();
            Err(PostgresError::CloseTimeout)
        }
    }

    async fn check_health(&self) -> Result<(), CheckFailure> {
        let started = Instant::now();
        let healthy = match self.acquire().await {
            Ok(mut connection) => {
                matches!(
                    sqlx::query_scalar::<_, i32>("SELECT 1")
                        .fetch_one(&mut *connection)
                        .await,
                    Ok(1)
                )
            }
            Err(_) => false,
        };
        if healthy {
            record_operation("health", "ok", started.elapsed());
            Ok(())
        } else {
            record_operation("health", "error", started.elapsed());
            Err(CheckFailure::new(unavailable_code()))
        }
    }

    fn record_stats(&self) {
        let stats = self.stats();
        metrics::gauge!("rsk_postgres_pool_connections", "state" => "total")
            .set(f64::from(stats.size));

        metrics::gauge!("rsk_postgres_pool_connections", "state" => "idle")
            .set(f64::from(stats.idle));
        metrics::gauge!("rsk_postgres_pool_connections", "state" => "in_use")
            .set(f64::from(stats.in_use));
        metrics::gauge!("rsk_postgres_pool_utilization_ratio").set(stats.utilization());
    }
}

impl fmt::Debug for PostgresPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresPool")
            .field("stats", &self.stats())
            .field("effective_max_lifetime", &self.effective_max_lifetime)
            .finish_non_exhaustive()
    }
}
/// A leased PostgreSQL connection that updates pool telemetry on release.
pub struct PostgresConnection {
    connection: Option<PoolConnection<Postgres>>,
    pool: PostgresPool,
}

impl PostgresConnection {
    /// Closes this physical connection instead of returning it to the pool.
    ///
    /// Use this after session-scoped state may have been left behind, such as
    /// an interrupted advisory-lock operation.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresError::Discard`] when graceful physical close fails.
    pub async fn discard(mut self) -> Result<(), PostgresError> {
        let Some(connection) = self.connection.take() else {
            return Ok(());
        };
        let result = connection.close().await.map_err(|_| PostgresError::Discard);
        self.pool.record_stats();
        result
    }
}

impl Deref for PostgresConnection {
    type Target = PgConnection;

    fn deref(&self) -> &Self::Target {
        match self.connection.as_deref() {
            Some(connection) => connection,
            None => unreachable!("leased PostgreSQL connection has already been released"),
        }
    }
}

impl DerefMut for PostgresConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.connection.as_deref_mut() {
            Some(connection) => connection,
            None => unreachable!("leased PostgreSQL connection has already been released"),
        }
    }
}

impl fmt::Debug for PostgresConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresConnection")
            .field("pool_stats", &self.pool.stats())
            .finish_non_exhaustive()
    }
}

impl Drop for PostgresConnection {
    fn drop(&mut self) {
        let Some(mut connection) = self.connection.take() else {
            return;
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let returned = connection.return_to_pool();
            let pool = self.pool.clone();
            runtime.spawn(async move {
                returned.await;
                drop(connection);
                pool.record_stats();
            });
            return;
        }

        let returned = connection.return_to_pool();
        drop(returned);
        self.pool.record_stats();
        let spawned = std::thread::Builder::new()
            .name("rsk-postgres-release".to_owned())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    std::mem::forget(connection);
                    return;
                };
                runtime.block_on(async move {
                    drop(connection);
                    tokio::task::yield_now().await;
                });
            });
        if let Ok(thread) = spawned {
            drop(thread);
        }
    }
}

/// Stable pool state without endpoint, query, or credential labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresPoolStats {
    /// Total open connections, including idle connections.
    pub size: u32,
    /// Connections immediately available for acquisition.
    pub idle: u32,
    /// Connections currently leased or being used.
    pub in_use: u32,
    /// Configured maximum connection count.
    pub max: u32,
    /// Whether pool shutdown has begun.
    pub closed: bool,
}

impl PostgresPoolStats {
    /// Returns whether every configured connection slot is in use.
    #[must_use]
    pub const fn saturated(self) -> bool {
        self.max > 0 && self.in_use >= self.max
    }

    /// Returns bounded utilization in the inclusive range `0.0..=1.0`.
    #[must_use]
    pub fn utilization(self) -> f64 {
        if self.max == 0 {
            0.0
        } else {
            (f64::from(self.in_use) / f64::from(self.max)).clamp(0.0, 1.0)
        }
    }
}

/// Safe PostgreSQL pool failure classification.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PostgresError {
    /// Typed configuration policy was invalid.
    #[error(transparent)]
    Config(#[from] PostgresConfigError),
    /// Initial eager connection failed before startup.
    #[error("PostgreSQL pool connection failed")]
    Connect,
    /// Initial eager connection exceeded its startup deadline.
    #[error("PostgreSQL pool connection deadline exceeded")]
    ConnectTimeout,
    /// Pool acquisition failed.
    #[error("PostgreSQL pool acquisition failed")]
    Acquire,
    /// Pool acquisition exceeded its configured deadline.
    #[error("PostgreSQL pool acquisition deadline exceeded")]
    AcquireTimeout,
    /// Pool shutdown has begun and acquisitions are rejected.
    #[error("PostgreSQL pool is closed")]
    Closed,
    /// A tainted physical connection could not be closed gracefully.
    #[error("PostgreSQL connection discard failed")]
    Discard,
    /// Checked-out connections outlived the pool shutdown deadline.
    #[error("PostgreSQL pool close deadline exceeded")]
    CloseTimeout,
}

fn record_operation(operation: &'static str, status: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_postgres_pool_operations_total",
        "operation" => operation,
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "rsk_postgres_pool_operation_duration_seconds",
        "operation" => operation,
        "status" => status
    )
    .record(elapsed.as_secs_f64());
}

fn postgres_duration(duration: Duration) -> String {
    format!("{}ms", duration.as_millis())
}

fn jitter_seed() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let bytes = time.to_le_bytes();
    let low = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let high = u64::from_le_bytes([
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let folded = low ^ high;
    folded ^ u64::from(std::process::id())
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static PostgreSQL health code must be valid")
    };
    code
}
