//! Required-readiness Redis browser session persistence.
//!
//! The maintained `tower-sessions-redis-store` uses one multiplexed Fred client and Redis `EXAT`
//! expiry. It has no key-prefix hook, so deployments must dedicate the selected Redis database or
//! instance to session records. This adapter intentionally does not add a second pool or cleanup
//! loop and never presents Redis sessions as a degraded cache.
mod lifecycle;
mod store;

use lifecycle::probe_permissions;
pub use lifecycle::{RedisSessionLifecycle, RedisSessionLifecycleError};
pub use store::FeatureStableRedisStore;

use fred::prelude::{
    Client, ClientInterface as _, ClientLike as _, Config as FredConfig, ConnectionConfig,
    PerformanceConfig, ReconnectPolicy,
};
use metrics::counter;
use omnius_auth_core::{SessionConfig, SessionConfigError, SessionSameSite, SessionStoreKind};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _};
use omnius_core::ErrorCode;
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_redis_core::{RedisConfig, RedisConfigError};
use omnius_runtime::Criticality;
use std::{collections::HashMap, fmt, time::Duration};
use thiserror::Error;
use time::OffsetDateTime;
use tower_sessions::{
    SessionManagerLayer, SessionStore as _,
    cookie::SameSite,
    session::{Expiry, Id, Record},
};

const HEALTH_CHECK_NAME: &str = "session-store";
const MODULE_NAME: &str = "auth-session-redis";
const UNAVAILABLE_CODE: &str = "SESSION_STORE_UNAVAILABLE";

/// Explicit isolation required because the maintained store writes raw session-ID keys.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisSessionIsolation {
    /// The Redis deployment is dedicated to this service's browser sessions.
    DedicatedInstance,
    /// The URL selects this explicitly dedicated logical Redis database.
    Database(u8),
}

/// Enabled Redis session capability backed by one multiplexed Fred client.
#[derive(Clone)]
pub struct RedisSessionStore {
    client: Client,
    session: SessionConfig,
    client_name: String,
    health_timeout: Duration,
}

impl fmt::Debug for RedisSessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisSessionStore")
            .field("cookie_name", &self.session.cookie_name)
            .field("health_timeout", &self.health_timeout)
            .finish_non_exhaustive()
    }
}

impl RedisSessionStore {
    /// Validates both policies and eagerly establishes the authoritative store when enabled.
    ///
    /// `Ok(None)` is the explicit browser-session disabled outcome. When sessions are enabled,
    /// disabled/unreachable Redis is an error and routes must not be exposed.
    ///
    /// # Errors
    ///
    /// Returns [`RedisSessionError`] for mismatched providers, unsafe Redis policy, URL parsing,
    /// connection failure, or startup timeout. Errors never retain or render the Redis URL.
    pub async fn connect(
        session: &SessionConfig,
        redis: &RedisConfig,
        isolation: RedisSessionIsolation,
        deployment: DeploymentEnvironment,
    ) -> Result<Option<Self>, RedisSessionError> {
        if !session.enabled {
            return Ok(None);
        }
        if session.store != SessionStoreKind::Redis {
            return Err(SessionConfigError::WrongStore.into());
        }
        session.validate_for(deployment)?;
        redis.validate_for(deployment)?;
        if !redis.enabled {
            return Err(RedisSessionError::RedisDisabled);
        }
        let url = redis.url.as_ref().ok_or(RedisSessionError::MissingUrl)?;
        let mut fred_config =
            FredConfig::from_url(url.expose_secret()).map_err(|_| RedisSessionError::InvalidUrl)?;
        if matches!(
            isolation,
            RedisSessionIsolation::Database(database)
                if fred_config.database != Some(database)
        ) {
            return Err(RedisSessionError::IsolationMismatch);
        }
        fred_config.fail_fast = true;
        let connection = ConnectionConfig {
            connection_timeout: redis.connection_timeout,
            internal_command_timeout: redis.command_timeout,
            reconnect_on_auth_error: true,
            auto_client_setname: true,
            ..ConnectionConfig::default()
        };
        let performance = PerformanceConfig {
            default_command_timeout: redis.command_timeout,
            ..PerformanceConfig::default()
        };
        let max_attempts = u32::try_from(redis.reconnect.max_retries)
            .map_err(|_| RedisSessionError::ReconnectPolicy)?;
        let exponent_base = u32::from(redis.reconnect.exponent_base);
        let reconnect = ReconnectPolicy::new_exponential(
            max_attempts,
            duration_millis(redis.reconnect.min_delay),
            duration_millis(redis.reconnect.max_delay),
            exponent_base,
        );
        let client = Client::new(
            fred_config,
            Some(performance),
            Some(connection),
            Some(reconnect),
        );
        let _router = client.connect();
        let started = std::time::Instant::now();
        let startup = async {
            client
                .wait_for_connect()
                .await
                .map_err(|_| RedisSessionError::Connect)?;
            probe_session_store(&client, &redis.client_name)
                .await
                .map_err(|()| RedisSessionError::Connect)
        };
        match tokio::time::timeout(redis.startup_timeout, startup).await {
            Ok(Ok(())) => record_operation("connect", "ok", started.elapsed()),
            Ok(Err(error)) => {
                record_operation("connect", "error", started.elapsed());
                return Err(error);
            }
            Err(_) => {
                record_operation("connect", "timeout", started.elapsed());
                return Err(RedisSessionError::ConnectTimeout);
            }
        }
        Ok(Some(Self {
            client,
            session: session.clone(),
            client_name: redis.client_name.clone(),
            health_timeout: redis.health_timeout,
        }))
    }

    /// Constructs the lifecycle adapter over the same multiplexed Fred client.
    #[must_use]
    pub fn lifecycle(&self) -> RedisSessionLifecycle {
        RedisSessionLifecycle::new(self.client.clone(), self.session.clone())
    }

    /// Builds the maintained Redis storage/session layer with canonical cookie policy.
    ///
    /// The layer saves only modified records, always uses path `/`, and never
    /// sets `Domain`. Lifecycle registration and every validated touch replace
    /// inactivity expiry with an absolute `AtDateTime` deadline capped by the
    /// configured absolute timeout.
    /// # Errors
    ///
    /// Returns [`SessionConfigError::InvalidIdleTimeout`] if the validated duration cannot be
    /// represented by `time`.
    pub fn session_manager_layer(
        &self,
    ) -> Result<SessionManagerLayer<FeatureStableRedisStore>, SessionConfigError> {
        let idle_timeout = time::Duration::try_from(self.session.idle_timeout)
            .map_err(|_| SessionConfigError::InvalidIdleTimeout)?;
        let store = FeatureStableRedisStore::new(self.client.clone());
        Ok(SessionManagerLayer::new(store)
            .with_name(self.session.cookie_name.clone())
            .with_http_only(self.session.http_only)
            .with_same_site(match self.session.same_site {
                SessionSameSite::Lax => SameSite::Lax,
                SessionSameSite::Strict => SameSite::Strict,
            })
            .with_expiry(Expiry::OnInactivity(idle_timeout))
            .with_secure(self.session.secure)
            .with_path("/")
            .with_always_save(false))
    }

    /// Builds the required cached-readiness check for the authoritative session store.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        let client = self.client.clone();
        let client_name = self.client_name.clone();
        HealthCheckSpec::new(
            HEALTH_CHECK_NAME,
            MODULE_NAME,
            Criticality::Required,
            self.health_timeout,
            move || {
                let client = client.clone();
                let client_name = client_name.clone();
                async move {
                    if probe_session_store(&client, &client_name).await.is_ok() {
                        record_operation("health", "ok", Duration::ZERO);
                        Ok(())
                    } else {
                        record_operation("health", "error", Duration::ZERO);
                        Err(CheckFailure::new(unavailable_code()))
                    }
                }
            },
        )
    }

    /// Gracefully closes the Fred router and Redis connection.
    pub async fn shutdown(&self) {
        let _result = self.client.quit().await;
    }
}

/// Safe Redis session startup failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedisSessionError {
    /// Shared browser-session policy was invalid.
    #[error("browser session configuration is invalid")]
    SessionConfig,
    /// Shared Redis policy was invalid.
    #[error("Redis session policy is invalid")]
    RedisConfig,
    /// Fred requires an integer reconnect exponent or narrower attempt count.
    #[error("Redis session reconnect policy is unsupported")]
    ReconnectPolicy,
    /// Sessions were enabled while Redis was disabled.
    #[error("authoritative Redis session store is disabled")]
    RedisDisabled,
    /// Enabled Redis did not provide a URL.
    #[error("authoritative Redis session URL is missing")]
    MissingUrl,
    /// Fred rejected the redacted URL.
    #[error("authoritative Redis session URL is invalid")]
    InvalidUrl,
    /// The declared dedicated logical database did not match the URL.
    #[error("Redis session isolation does not match the configured URL")]
    IsolationMismatch,
    /// Eager Redis connection failed.
    #[error("authoritative Redis session store is unavailable")]
    Connect,
    /// Eager Redis connection exceeded the startup deadline.
    #[error("authoritative Redis session startup timed out")]
    ConnectTimeout,
}

impl From<SessionConfigError> for RedisSessionError {
    fn from(_error: SessionConfigError) -> Self {
        Self::SessionConfig
    }
}

impl From<RedisConfigError> for RedisSessionError {
    fn from(_error: RedisConfigError) -> Self {
        Self::RedisConfig
    }
}

async fn probe_session_store(client: &Client, client_name: &str) -> Result<(), ()> {
    client.client_setname(client_name).await.map_err(|_| ())?;
    let store = FeatureStableRedisStore::new(client.clone());
    let mut record = Record {
        id: Id::default(),
        data: HashMap::new(),
        expiry_date: OffsetDateTime::now_utc() + time::Duration::seconds(30),
    };
    store.create(&mut record).await.map_err(|_| ())?;
    let loaded = store.load(&record.id).await;
    let permissions = probe_permissions(client, &record.id.to_string()).await;
    let deleted = store.delete(&record.id).await;
    match (loaded, permissions, deleted) {
        (Ok(Some(loaded)), Ok(()), Ok(())) if loaded.id == record.id => Ok(()),
        _ => Err(()),
    }
}

fn duration_millis(duration: Duration) -> u32 {
    u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static Redis session health code must be valid")
    };
    code
}

fn record_operation(operation: &'static str, status: &'static str, elapsed: Duration) {
    counter!(
        "omnius_auth_session_redis_operations_total",
        "operation" => operation,
        "status" => status
    )
    .increment(1);
    metrics::histogram!(
        "omnius_auth_session_redis_operation_duration_seconds",
        "operation" => operation,
        "status" => status
    )
    .record(elapsed);
}
