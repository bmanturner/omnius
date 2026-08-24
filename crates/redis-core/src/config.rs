use std::{fmt, time::Duration};

use redis::{ConnectionAddr, ConnectionInfo, IntoConnectionInfo as _};
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

const MAX_URL_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 64;
const MAX_KEY_BYTES: usize = 512;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FAST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_STARTUP_TIMEOUT: Duration = Duration::from_mins(2);
const MAX_RETRIES: usize = 32;

/// Bounded automatic reconnect behavior for the shared connection manager.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RedisReconnectConfig {
    /// Minimum reconnect delay.
    #[serde(with = "humantime_serde")]
    pub min_delay: Duration,
    /// Maximum reconnect delay.
    #[serde(with = "humantime_serde")]
    pub max_delay: Duration,
    /// Integer exponential backoff base shared by all supported Redis clients.
    pub exponent_base: u16,
    /// Maximum reconnect attempts in one reconnect cycle.
    pub max_retries: usize,
}

impl Default for RedisReconnectConfig {
    fn default() -> Self {
        Self {
            min_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            exponent_base: 2,
            max_retries: 6,
        }
    }
}

/// Secret-safe Redis connectivity and namespace policy.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RedisConfig {
    /// Enables the optional Redis capability.
    pub enabled: bool,
    /// Redis or Valkey connection URL, including authentication when configured.
    pub url: Option<SecretString>,
    /// Per-attempt TCP/TLS connection deadline.
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    /// Total eager startup deadline including reconnect attempts.
    #[serde(with = "humantime_serde")]
    pub startup_timeout: Duration,
    /// Per-command response deadline enforced by the manager.
    #[serde(with = "humantime_serde")]
    pub command_timeout: Duration,
    /// Cached health-check deadline.
    #[serde(with = "humantime_serde")]
    pub health_timeout: Duration,
    /// Stable Redis client/library identity.
    pub client_name: String,
    /// Application-wide key prefix.
    pub key_prefix: String,
    /// Key-schema version appended after the prefix.
    pub schema_version: String,
    /// Maximum serialized value accepted by shared helpers.
    pub max_value_bytes: usize,
    /// Automatic connection-manager reconnect policy.
    pub reconnect: RedisReconnectConfig,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            connection_timeout: Duration::from_secs(3),
            startup_timeout: Duration::from_secs(15),
            command_timeout: Duration::from_secs(2),
            health_timeout: Duration::from_secs(3),
            client_name: "rsk-service".to_owned(),
            key_prefix: "rsk".to_owned(),
            schema_version: "v1".to_owned(),
            max_value_bytes: 1024 * 1024,
            reconnect: RedisReconnectConfig::default(),
        }
    }
}

impl RedisConfig {
    /// Validates secret, timeout, reconnect, TLS, namespace, and value-size policy.
    ///
    /// A disabled configuration may omit `url`; every other field remains validated so a later
    /// runtime enablement cannot activate latent unsafe values.
    ///
    /// # Errors
    ///
    /// Returns [`RedisConfigError`] for malformed, unsafe, unbounded, or inconsistent values.
    pub fn validate_for(&self, deployment: DeploymentEnvironment) -> Result<(), RedisConfigError> {
        bounded_duration(
            "connection_timeout",
            self.connection_timeout,
            MAX_FAST_TIMEOUT,
        )?;
        bounded_duration("startup_timeout", self.startup_timeout, MAX_STARTUP_TIMEOUT)?;
        bounded_duration("command_timeout", self.command_timeout, MAX_FAST_TIMEOUT)?;
        bounded_duration("health_timeout", self.health_timeout, MAX_FAST_TIMEOUT)?;
        if self.startup_timeout < self.connection_timeout {
            return Err(RedisConfigError::StartupBeforeConnection);
        }
        if self.health_timeout < self.command_timeout {
            return Err(RedisConfigError::HealthBeforeCommand);
        }
        if self.reconnect.min_delay.is_zero()
            || self.reconnect.min_delay > self.reconnect.max_delay
            || self.reconnect.max_delay > MAX_FAST_TIMEOUT
            || !(1..=10).contains(&self.reconnect.exponent_base)
            || !(1..=MAX_RETRIES).contains(&self.reconnect.max_retries)
        {
            return Err(RedisConfigError::InvalidReconnect);
        }
        if !portable_name(&self.client_name)
            || !portable_name(&self.key_prefix)
            || !portable_name(&self.schema_version)
        {
            return Err(RedisConfigError::InvalidIdentifier);
        }
        if self.max_value_bytes == 0 || self.max_value_bytes > MAX_VALUE_BYTES {
            return Err(RedisConfigError::InvalidValueLimit);
        }

        let Some(info) = self.connection_info()? else {
            return if self.enabled {
                Err(RedisConfigError::MissingUrl)
            } else {
                Ok(())
            };
        };
        if deployment == DeploymentEnvironment::Production {
            match info.addr() {
                ConnectionAddr::TcpTls {
                    insecure: false, ..
                } if info
                    .redis_settings()
                    .password()
                    .is_some_and(|password| !password.is_empty()) => {}
                ConnectionAddr::TcpTls { .. } => {
                    return Err(RedisConfigError::ProductionAuthenticationRequired);
                }
                ConnectionAddr::Tcp(_, _) | ConnectionAddr::Unix(_) => {
                    return Err(RedisConfigError::ProductionTlsRequired);
                }
                _ => return Err(RedisConfigError::ProductionTlsRequired),
            }
        }
        Ok(())
    }

    pub(crate) fn connection_info(&self) -> Result<Option<ConnectionInfo>, RedisConfigError> {
        let Some(url) = &self.url else {
            return Ok(None);
        };
        let exposed = url.expose_secret();
        if exposed.trim().is_empty() || exposed.len() > MAX_URL_BYTES {
            return Err(RedisConfigError::InvalidUrl);
        }
        let info = exposed
            .into_connection_info()
            .map_err(|_| RedisConfigError::InvalidUrl)?;
        if !info.addr().is_supported() {
            return Err(RedisConfigError::UnsupportedTransport);
        }
        Ok(Some(info))
    }

    /// Constructs one versioned Redis key from bounded portable components.
    ///
    /// # Errors
    ///
    /// Returns [`RedisConfigError::InvalidKey`] for an empty list, invalid component, or key over
    /// 512 bytes.
    pub fn key(&self, components: &[&str]) -> Result<String, RedisConfigError> {
        build_key(&self.key_prefix, &self.schema_version, components)
    }
}

impl fmt::Debug for RedisConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisConfig")
            .field("enabled", &self.enabled)
            .field("url_configured", &self.url.is_some())
            .field("connection_timeout", &self.connection_timeout)
            .field("startup_timeout", &self.startup_timeout)
            .field("command_timeout", &self.command_timeout)
            .field("health_timeout", &self.health_timeout)
            .field("client_name", &self.client_name)
            .field("key_prefix", &self.key_prefix)
            .field("schema_version", &self.schema_version)
            .field("max_value_bytes", &self.max_value_bytes)
            .field("reconnect", &self.reconnect)
            .finish()
    }
}

/// Invalid Redis configuration without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisConfigError {
    /// Redis was enabled without a connection URL.
    #[error("enabled Redis configuration requires a URL")]
    MissingUrl,
    /// The secret URL was empty, oversized, or malformed.
    #[error("Redis URL is invalid")]
    InvalidUrl,
    /// The URL selected a transport unavailable in this build.
    #[error("Redis URL uses an unsupported transport")]
    UnsupportedTransport,
    /// Production TCP connections require verified TLS.
    #[error("production Redis connections require verified TLS")]
    ProductionTlsRequired,
    /// Production TLS connections require authentication credentials.
    #[error("production Redis connections require authentication")]
    ProductionAuthenticationRequired,
    /// A duration was zero or exceeded its fixed safety bound.
    #[error("Redis duration is outside its safety bound: {0}")]
    InvalidDuration(&'static str),
    /// Total startup time was shorter than one connection attempt.
    #[error("Redis startup timeout must be at least the connection timeout")]
    StartupBeforeConnection,
    /// Health checks could expire before the command response timeout.
    #[error("Redis health timeout must be at least the command timeout")]
    HealthBeforeCommand,
    /// Reconnect delay, exponent, or retry count was invalid.
    #[error("Redis reconnect policy is invalid")]
    InvalidReconnect,
    /// Client name, key prefix, or schema version was invalid.
    #[error("Redis identifier is invalid")]
    InvalidIdentifier,
    /// The serialized value limit was zero or exceeded 16 MiB.
    #[error("Redis value-size limit is invalid")]
    InvalidValueLimit,
    /// A namespaced key component or final key was invalid.
    #[error("Redis key is invalid")]
    InvalidKey,
}

pub(crate) fn build_key(
    key_prefix: &str,
    schema_version: &str,
    components: &[&str],
) -> Result<String, RedisConfigError> {
    if !portable_name(key_prefix)
        || !portable_name(schema_version)
        || components.is_empty()
        || components.iter().any(|component| !portable_name(component))
    {
        return Err(RedisConfigError::InvalidKey);
    }
    let mut key = String::with_capacity(
        key_prefix.len()
            + schema_version.len()
            + components.iter().map(|part| part.len() + 1).sum::<usize>()
            + 1,
    );
    key.push_str(key_prefix);
    key.push(':');
    key.push_str(schema_version);
    for component in components {
        key.push(':');
        key.push_str(component);
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(RedisConfigError::InvalidKey);
    }
    Ok(key)
}

fn portable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn bounded_duration(
    name: &'static str,
    duration: Duration,
    maximum: Duration,
) -> Result<(), RedisConfigError> {
    if duration.is_zero() || duration > maximum {
        Err(RedisConfigError::InvalidDuration(name))
    } else {
        Ok(())
    }
}
