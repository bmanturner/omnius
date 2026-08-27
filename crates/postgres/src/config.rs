use std::{str::FromStr, time::Duration};

use crate::transaction::{TransactionRetryConfig, TransactionRetryConfigError};
use garde::Validate;
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use serde::Deserialize;
use sqlx::postgres::PgConnectOptions;
use thiserror::Error;

const MAX_FAST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SESSION_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CONNECTION_LIFETIME: Duration = Duration::from_hours(24);
const MAX_CONNECTIONS: u32 = 1024;
const MAX_URL_BYTES: usize = 4096;
const MAX_INIT_STATEMENTS: usize = 8;
const MAX_INIT_STATEMENT_BYTES: usize = 1024;

/// TLS verification policy for PostgreSQL connections.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum PostgresTlsMode {
    /// Plaintext transport, permitted only in development and tests.
    Disable,
    /// TLS with certificate-chain and hostname verification.
    VerifyFull,
}

/// Explicit, secret-safe PostgreSQL pool policy.
#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PostgresConfig {
    /// PostgreSQL connection URL. This field is always redacted.
    #[garde(skip)]
    pub url: SecretString,
    /// Transport verification policy.
    #[garde(skip)]
    pub tls_mode: PostgresTlsMode,
    /// Minimum maintained connection count.
    #[garde(skip)]
    pub min_connections: u32,
    /// Maximum concurrent connection count per process.
    #[garde(skip)]
    pub max_connections: u32,
    /// Overall eager startup connection deadline.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub connect_timeout: Duration,
    /// `SQLx` pool acquisition deadline.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub acquire_timeout: Duration,
    /// Idle connection retirement threshold.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub idle_timeout: Duration,
    /// Upper connection lifetime before process-level jitter.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub max_lifetime: Duration,
    /// Randomized subtraction from maximum lifetime across process replicas.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub max_lifetime_jitter: Duration,
    /// Stable PostgreSQL `application_name` value.
    #[garde(skip)]
    pub application_name: String,
    /// Trusted initialization statements run on every new connection.
    #[garde(skip)]
    pub initialization_sql: Vec<String>,
    /// Per-connection PostgreSQL statement timeout.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub statement_timeout: Duration,
    /// Per-connection PostgreSQL lock acquisition timeout.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub lock_timeout: Duration,
    /// Cached readiness check deadline.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub health_timeout: Duration,
    /// Graceful pool close deadline.
    #[serde(with = "humantime_serde")]
    #[garde(skip)]
    pub shutdown_timeout: Duration,
    /// Whole-transaction replay policy for safe transient SQLSTATEs.
    #[garde(skip)]
    pub transaction_retry: TransactionRetryConfig,
}

impl PostgresConfig {
    /// Validates pool relationships and deployment-specific TLS policy.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresConfigError`] for malformed URLs, unsafe production
    /// TLS, unbounded values, or inconsistent pool relationships.
    pub fn validate_for(
        &self,
        deployment: DeploymentEnvironment,
    ) -> Result<(), PostgresConfigError> {
        if self.url.expose_secret().trim().is_empty()
            || self.url.expose_secret().len() > MAX_URL_BYTES
            || PgConnectOptions::from_str(self.url.expose_secret()).is_err()
        {
            return Err(PostgresConfigError::InvalidUrl);
        }
        if deployment == DeploymentEnvironment::Production
            && self.tls_mode != PostgresTlsMode::VerifyFull
        {
            return Err(PostgresConfigError::ProductionTlsRequired);
        }
        if self.max_connections == 0
            || self.max_connections > MAX_CONNECTIONS
            || self.min_connections > self.max_connections
        {
            return Err(PostgresConfigError::InvalidPoolSize);
        }
        bounded_duration("connect_timeout", self.connect_timeout, MAX_FAST_TIMEOUT)?;
        bounded_duration("acquire_timeout", self.acquire_timeout, MAX_FAST_TIMEOUT)?;
        bounded_duration("health_timeout", self.health_timeout, MAX_FAST_TIMEOUT)?;
        bounded_duration("shutdown_timeout", self.shutdown_timeout, MAX_FAST_TIMEOUT)?;
        bounded_duration("idle_timeout", self.idle_timeout, MAX_CONNECTION_LIFETIME)?;
        bounded_duration("max_lifetime", self.max_lifetime, MAX_CONNECTION_LIFETIME)?;
        bounded_duration(
            "statement_timeout",
            self.statement_timeout,
            MAX_SESSION_TIMEOUT,
        )?;
        bounded_duration("lock_timeout", self.lock_timeout, MAX_FAST_TIMEOUT)?;
        if self.connect_timeout < self.acquire_timeout {
            return Err(PostgresConfigError::ConnectBeforeAcquire);
        }
        if self.health_timeout < self.acquire_timeout {
            return Err(PostgresConfigError::HealthBeforeAcquire);
        }
        if self.idle_timeout > self.max_lifetime {
            return Err(PostgresConfigError::IdleAfterLifetime);
        }
        if self.max_lifetime_jitter >= self.max_lifetime {
            return Err(PostgresConfigError::InvalidLifetimeJitter);
        }
        if self.lock_timeout > self.statement_timeout {
            return Err(PostgresConfigError::LockAfterStatement);
        }
        if !valid_application_name(&self.application_name) {
            return Err(PostgresConfigError::InvalidApplicationName);
        }
        if self.initialization_sql.len() > MAX_INIT_STATEMENTS
            || self.initialization_sql.iter().any(|statement| {
                statement.trim().is_empty()
                    || statement.len() > MAX_INIT_STATEMENT_BYTES
                    || statement.contains('\0')
            })
        {
            return Err(PostgresConfigError::InvalidInitializationSql);
        }
        self.transaction_retry.validate()?;
        Ok(())
    }
}

/// Invalid PostgreSQL configuration without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PostgresConfigError {
    /// The secret URL was empty, malformed, or not a PostgreSQL URL.
    #[error("PostgreSQL URL is invalid")]
    InvalidUrl,
    /// Production requires certificate and hostname verification.
    #[error("production PostgreSQL connections require verify-full TLS")]
    ProductionTlsRequired,
    /// Pool minimum/maximum counts were inconsistent.
    #[error("PostgreSQL pool size must satisfy 0 <= min <= max <= 1024 and max > 0")]
    InvalidPoolSize,
    /// A duration was zero or exceeded its fixed safety bound.
    #[error("PostgreSQL duration is outside its safety bound: {0}")]
    InvalidDuration(&'static str),
    /// Startup timeout was shorter than one acquisition attempt.
    #[error("PostgreSQL connect timeout must be at least acquire timeout")]
    ConnectBeforeAcquire,
    /// Health deadline was shorter than the pool acquisition deadline.
    #[error("PostgreSQL health timeout must be at least acquire timeout")]
    HealthBeforeAcquire,
    /// Idle retirement would never precede maximum lifetime.
    #[error("PostgreSQL idle timeout must not exceed maximum lifetime")]
    IdleAfterLifetime,
    /// Lifetime jitter must leave a positive effective lifetime.
    #[error("PostgreSQL lifetime jitter must be shorter than maximum lifetime")]
    InvalidLifetimeJitter,
    /// Lock waits cannot outlive their enclosing statement.
    #[error("PostgreSQL lock timeout must not exceed statement timeout")]
    LockAfterStatement,
    /// Application name was empty, unbounded, or contained unsafe syntax.
    #[error("PostgreSQL application name is invalid")]
    InvalidApplicationName,
    /// Initialization statements exceeded count/size/syntax bounds.
    #[error("PostgreSQL initialization SQL is invalid")]
    InvalidInitializationSql,
    /// Whole-transaction retry policy was invalid.
    #[error(transparent)]
    TransactionRetry(#[from] TransactionRetryConfigError),
}

pub(crate) fn effective_lifetime(config: &PostgresConfig, seed: u64) -> Duration {
    let jitter_nanos = u64::try_from(config.max_lifetime_jitter.as_nanos()).unwrap_or(u64::MAX);
    let offset = if jitter_nanos == 0 {
        0
    } else {
        mix(seed) % jitter_nanos.saturating_add(1)
    };
    config
        .max_lifetime
        .saturating_sub(Duration::from_nanos(offset))
}

fn bounded_duration(
    name: &'static str,
    duration: Duration,
    maximum: Duration,
) -> Result<(), PostgresConfigError> {
    if duration < Duration::from_millis(1) || duration > maximum {
        Err(PostgresConfigError::InvalidDuration(name))
    } else {
        Ok(())
    }
}

fn valid_application_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn mix(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> PostgresConfig {
        PostgresConfig {
            url: SecretString::from("postgres://user:secret@localhost/database"),
            tls_mode: PostgresTlsMode::Disable,
            min_connections: 1,
            max_connections: 4,
            connect_timeout: Duration::from_secs(2),
            acquire_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
            max_lifetime_jitter: Duration::from_secs(10),
            application_name: "omnius-test".to_owned(),
            initialization_sql: vec!["SET search_path TO public".to_owned()],
            statement_timeout: Duration::from_secs(5),
            transaction_retry: TransactionRetryConfig {
                max_attempts: 3,
                base_delay: Duration::from_millis(5),
                max_delay: Duration::from_millis(50),
                max_jitter: Duration::from_millis(5),
                isolation: crate::TransactionIsolation::Serializable,
            },
            lock_timeout: Duration::from_secs(1),
            health_timeout: Duration::from_secs(2),
            shutdown_timeout: Duration::from_secs(2),
        }
    }

    #[test]
    fn accepts_explicit_test_policy_and_bounds_lifetime_jitter() -> Result<(), PostgresConfigError>
    {
        let config = valid_config();
        config.validate_for(DeploymentEnvironment::Test)?;
        let lifetime = effective_lifetime(&config, 42);
        assert!(lifetime <= config.max_lifetime);
        assert!(
            lifetime
                >= config
                    .max_lifetime
                    .saturating_sub(config.max_lifetime_jitter)
        );
        Ok(())
    }

    #[test]
    fn rejects_unsafe_production_tls_and_relationships() {
        let mut config = valid_config();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(PostgresConfigError::ProductionTlsRequired)
        );
        config.tls_mode = PostgresTlsMode::VerifyFull;
        config.min_connections = 5;
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(PostgresConfigError::InvalidPoolSize)
        );
    }

    #[test]
    fn rejects_malformed_url_and_secret_safe_diagnostics() {
        let mut config = valid_config();
        config.url = SecretString::from("not-a-url-with-secret-value");
        let Err(error) = config.validate_for(DeploymentEnvironment::Test) else {
            panic!("malformed PostgreSQL URL was accepted");
        };
        assert_eq!(error, PostgresConfigError::InvalidUrl);
        assert!(!format!("{error:?}").contains("secret-value"));
    }

    #[test]
    fn rejects_timeout_and_initialization_policy_violations() {
        let mut config = valid_config();
        config.health_timeout = Duration::from_millis(500);
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(PostgresConfigError::HealthBeforeAcquire)
        );
        config.health_timeout = Duration::from_secs(2);
        config.initialization_sql = vec![String::new()];
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(PostgresConfigError::InvalidInitializationSql)
        );
        config.initialization_sql = Vec::new();
        config.transaction_retry.max_attempts = 0;
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(PostgresConfigError::TransactionRetry(
                TransactionRetryConfigError::InvalidAttempts,
            ))
        );
    }

    #[test]
    fn rejects_sub_millisecond_server_timeouts_and_unbounded_pool_size() {
        let mut config = valid_config();
        config.statement_timeout = Duration::from_micros(500);
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(PostgresConfigError::InvalidDuration("statement_timeout"))
        );

        config.statement_timeout = Duration::from_secs(5);
        config.max_connections = MAX_CONNECTIONS + 1;
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(PostgresConfigError::InvalidPoolSize)
        );
    }
}
