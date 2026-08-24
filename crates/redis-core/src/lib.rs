//! Multiplexed Redis connectivity with bounded configuration, reconnects, namespaces, telemetry,
//! dedicated-connection construction, and cached-health integration.
//!
//! Ordinary non-blocking commands share one cheap-to-clone [`redis::aio::ConnectionManager`].
//! No generic async pool is used. Blocking and Pub/Sub providers must request a dedicated physical
//! connection rather than use [`RedisCore::query`].

mod config;

use config::build_key;
pub use config::{RedisConfig, RedisConfigError, RedisReconnectConfig};
use redis::{
    AsyncConnectionConfig, Cmd, ConnectionInfo, FromRedisValue, aio::ConnectionManagerConfig,
};
use rsk_config::DeploymentEnvironment;
use rsk_core::ErrorCode;
use rsk_health::{CheckFailure, HealthCheckSpec};
use rsk_runtime::Criticality;
use std::{fmt, time::Instant};
use thiserror::Error;

const HEALTH_CHECK_NAME: &str = "redis-connectivity";
const MODULE_NAME: &str = "redis-core";
const UNAVAILABLE_CODE: &str = "REDIS_UNAVAILABLE";
const CLIENT_LIBRARY_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Fixed, low-cardinality command families used by Redis telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisCommandFamily {
    /// Cache reads, writes, and invalidations.
    Cache,
    /// Session persistence commands.
    Session,
    /// Rate-limit atomic operations.
    RateLimit,
    /// Loss-tolerant Pub/Sub control commands.
    PubSub,
    /// Job-provider commands.
    Jobs,
    /// Connectivity health checks.
    Health,
}

impl RedisCommandFamily {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Session => "session",
            Self::RateLimit => "rate_limit",
            Self::PubSub => "pubsub",
            Self::Jobs => "jobs",
            Self::Health => "health",
        }
    }
}

/// Purpose of a separately owned physical Redis connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DedicatedConnectionKind {
    /// Commands that may block at the Redis protocol level.
    Blocking,
    /// Provider-specific commands that must not share backpressure with ordinary requests.
    Provider,
}

impl DedicatedConnectionKind {
    const fn client_suffix(self) -> &'static str {
        match self {
            Self::Blocking => "blocking",
            Self::Provider => "provider",
        }
    }
}

/// Enabled Redis capability backed by one automatically reconnecting multiplexed connection.
#[derive(Clone)]
pub struct RedisCore {
    client: redis::Client,
    manager: redis::aio::ConnectionManager,
    client_name: String,
    key_prefix: String,
    schema_version: String,
    max_value_bytes: usize,
    connection_timeout: std::time::Duration,
    command_timeout: std::time::Duration,
    health_timeout: std::time::Duration,
}

impl RedisCore {
    /// Validates configuration and eagerly establishes the shared connection manager when enabled.
    ///
    /// `Ok(None)` is the explicit disabled outcome. The manager performs multiplexing and bounded
    /// automatic reconnects; this constructor never creates a generic connection pool.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCoreError`] for invalid policy, startup timeout, connection failure, or
    /// inability to configure the stable client name. Errors never retain or render the URL.
    pub async fn connect(
        config: &RedisConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<Option<Self>, RedisCoreError> {
        config.validate_for(deployment)?;
        if !config.enabled {
            return Ok(None);
        }
        let Some(connection_info) = config.connection_info()? else {
            return Err(RedisConfigError::MissingUrl.into());
        };
        let connection_info = with_library_identity(connection_info, &config.client_name);
        let client = redis::Client::open(connection_info).map_err(|_| RedisCoreError::Connect)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(config.connection_timeout))
            .set_response_timeout(Some(config.command_timeout))
            .set_min_delay(config.reconnect.min_delay)
            .set_max_delay(config.reconnect.max_delay)
            .set_exponent_base(config.reconnect.exponent_base)
            .set_number_of_retries(config.reconnect.max_retries);
        let started = Instant::now();
        let startup = async {
            let mut manager = client
                .get_connection_manager_with_config(manager_config)
                .await
                .map_err(|_| RedisCoreError::Connect)?;
            redis::cmd("CLIENT")
                .arg("SETNAME")
                .arg(&config.client_name)
                .query_async::<()>(&mut manager)
                .await
                .map_err(|_| RedisCoreError::ClientName)?;
            Ok::<_, RedisCoreError>(manager)
        };
        let manager = match tokio::time::timeout(config.startup_timeout, startup).await {
            Ok(Ok(manager)) => manager,
            Err(_) => {
                record_operation("connect", "timeout", started.elapsed());
                return Err(RedisCoreError::ConnectTimeout);
            }
            Ok(Err(error)) => {
                record_operation("connect", "error", started.elapsed());
                return Err(error);
            }
        };
        record_operation("connect", "ok", started.elapsed());
        Ok(Some(Self {
            client,
            manager,
            client_name: config.client_name.clone(),
            key_prefix: config.key_prefix.clone(),
            schema_version: config.schema_version.clone(),
            max_value_bytes: config.max_value_bytes,
            connection_timeout: config.connection_timeout,
            command_timeout: config.command_timeout,
            health_timeout: config.health_timeout,
        }))
    }

    /// Executes an ordinary non-blocking command through the shared multiplexed manager.
    ///
    /// The command family is a closed enum, so metrics never include command text, keys, tenants,
    /// or other unbounded values. Blocking and Pub/Sub work must use dedicated connections.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCoreError::Command`] for Redis, authentication, reconnect, or response
    /// timeout failures.
    pub async fn query<T>(
        &self,
        family: RedisCommandFamily,
        command: Cmd,
    ) -> Result<T, RedisCoreError>
    where
        T: FromRedisValue,
    {
        let started = Instant::now();
        let mut manager = self.manager.clone();
        let mut pipeline = redis::pipe();
        pipeline
            .cmd("CLIENT")
            .arg("SETNAME")
            .arg(&self.client_name)
            .ignore()
            .add_command(command);
        let result = tokio::time::timeout(
            self.command_timeout,
            pipeline.query_async::<(T,)>(&mut manager),
        )
        .await;
        if let Ok(Ok((value,))) = result {
            record_command(family, "ok", started.elapsed());
            Ok(value)
        } else {
            record_command(family, "error", started.elapsed());
            Err(RedisCoreError::Command)
        }
    }

    /// Opens a separate physical multiplexed connection for blocking or isolated provider work.
    ///
    /// This connection is intentionally not the shared manager and does not reconnect
    /// automatically. The owning provider must bound blocking commands and define retry safety.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCoreError::DedicatedConnection`] when connection or client naming fails.
    pub async fn dedicated_connection(
        &self,
        kind: DedicatedConnectionKind,
    ) -> Result<redis::aio::MultiplexedConnection, RedisCoreError> {
        let config = AsyncConnectionConfig::new()
            .set_connection_timeout(Some(self.connection_timeout))
            .set_response_timeout(match kind {
                DedicatedConnectionKind::Blocking => None,
                DedicatedConnectionKind::Provider => Some(self.command_timeout),
            });
        let mut connection = self
            .client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(|_| RedisCoreError::DedicatedConnection)?;
        let name = format!("{}-{}", self.client_name, kind.client_suffix());
        let mut naming_command = redis::cmd("CLIENT");
        naming_command.arg("SETNAME").arg(name);
        let naming = naming_command.query_async::<()>(&mut connection);
        tokio::time::timeout(self.command_timeout, naming)
            .await
            .map_err(|_| RedisCoreError::DedicatedConnection)?
            .map_err(|_| RedisCoreError::DedicatedConnection)?;
        Ok(connection)
    }

    /// Opens a separate physical Pub/Sub connection.
    ///
    /// Pub/Sub backpressure and subscription traffic never share the ordinary command manager.
    /// The owning Pub/Sub provider must apply operation deadlines and loss-tolerant failure policy.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCoreError::DedicatedConnection`] when connection setup exceeds its deadline
    /// or fails.
    pub async fn dedicated_pubsub(&self) -> Result<redis::aio::PubSub, RedisCoreError> {
        tokio::time::timeout(self.connection_timeout, self.client.get_async_pubsub())
            .await
            .map_err(|_| RedisCoreError::DedicatedConnection)?
            .map_err(|_| RedisCoreError::DedicatedConnection)
    }

    /// Builds one bounded, versioned key from portable components.
    ///
    /// # Errors
    ///
    /// Returns [`RedisConfigError::InvalidKey`] for invalid components or an oversized key.
    pub fn key(&self, components: &[&str]) -> Result<String, RedisConfigError> {
        build_key(&self.key_prefix, &self.schema_version, components)
    }

    /// Rejects an oversized serialized value before a Redis command is allocated or sent.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCoreError::ValueTooLarge`] when `value` exceeds the configured bound.
    pub fn ensure_value_size(&self, value: &[u8]) -> Result<(), RedisCoreError> {
        if value.len() > self.max_value_bytes {
            Err(RedisCoreError::ValueTooLarge)
        } else {
            Ok(())
        }
    }

    /// Returns the configured maximum serialized value size.
    #[must_use]
    pub const fn max_value_bytes(&self) -> usize {
        self.max_value_bytes
    }

    /// Returns the default degraded cached-health check for `redis-connectivity`.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        self.health_check_with_criticality(Criticality::Degraded)
    }

    /// Returns a cached-health check with caller-selected capability criticality.
    ///
    /// Authoritative session, rate-limit, or job modules may select `Required`; cache and Pub/Sub
    /// modules normally retain `Degraded`.
    #[must_use]
    pub fn health_check_with_criticality(&self, criticality: Criticality) -> HealthCheckSpec {
        let redis = self.clone();
        HealthCheckSpec::new(
            HEALTH_CHECK_NAME,
            MODULE_NAME,
            criticality,
            self.health_timeout,
            move || {
                let redis = redis.clone();
                async move { redis.check_health().await }
            },
        )
    }

    async fn check_health(&self) -> Result<(), CheckFailure> {
        let command = redis::cmd("PING");
        match self
            .query::<String>(RedisCommandFamily::Health, command)
            .await
        {
            Ok(response) if response == "PONG" => Ok(()),
            Ok(_) | Err(_) => Err(CheckFailure::new(unavailable_code())),
        }
    }
}

impl fmt::Debug for RedisCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCore")
            .field("client_name", &self.client_name)
            .field("key_prefix", &self.key_prefix)
            .field("schema_version", &self.schema_version)
            .field("max_value_bytes", &self.max_value_bytes)
            .finish_non_exhaustive()
    }
}

/// Stable Redis lifecycle and command failure categories.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisCoreError {
    /// Typed Redis configuration was invalid.
    #[error(transparent)]
    Config(#[from] RedisConfigError),
    /// Eager manager connection failed.
    #[error("Redis connection failed")]
    Connect,
    /// Eager manager connection exceeded its startup deadline.
    #[error("Redis connection deadline exceeded")]
    ConnectTimeout,
    /// Stable client-name setup failed.
    #[error("Redis client name setup failed")]
    ClientName,
    /// An ordinary command failed or exceeded its response deadline.
    #[error("Redis command failed")]
    Command,
    /// A dedicated physical connection could not be created or named.
    #[error("dedicated Redis connection failed")]
    DedicatedConnection,
    /// A serialized value exceeded the configured bound.
    #[error("Redis value exceeds the configured size limit")]
    ValueTooLarge,
}

fn with_library_identity(mut info: ConnectionInfo, client_name: &str) -> ConnectionInfo {
    let redis = info
        .redis_settings()
        .clone()
        .set_lib_name(client_name, CLIENT_LIBRARY_VERSION);
    info = info.set_redis_settings(redis);
    info
}

fn record_command(family: RedisCommandFamily, status: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "rsk_redis_core_commands_total",
        "family" => family.metric_label(),
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "rsk_redis_core_command_duration_seconds",
        "family" => family.metric_label(),
        "status" => status
    )
    .record(elapsed.as_secs_f64());
}

fn record_operation(operation: &'static str, status: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "rsk_redis_core_operations_total",
        "operation" => operation,
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "rsk_redis_core_operation_duration_seconds",
        "operation" => operation,
        "status" => status
    )
    .record(elapsed.as_secs_f64());
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static Redis health code must be valid")
    };
    code
}
