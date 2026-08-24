use std::{collections::HashSet, fmt, time::Duration};

use argon2::Params;
use rsk_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

const MIN_MEMORY_KIB: u32 = 19 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MIN_ITERATIONS: u32 = 2;
const MAX_ITERATIONS: u32 = 10;
const MAX_PARALLELISM: u32 = 16;
const MIN_PASSWORD_BYTES: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
const MIN_TOKEN_TTL: Duration = Duration::from_mins(5);
const MAX_TOKEN_TTL: Duration = Duration::from_hours(24);
const MAX_PEPPERS: usize = 3;
const MAX_PEPPER_BYTES: usize = 32;

/// Serializable, non-secret password policy parameters.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordPolicyConfig {
    /// Argon2 memory cost in KiB.
    pub memory_kib: u32,
    /// Argon2 time cost.
    pub iterations: u32,
    /// Argon2 degree of parallelism.
    pub parallelism: u32,
    /// Minimum accepted password length in bytes for a new password.
    pub min_password_bytes: usize,
    /// Maximum accepted candidate password length in bytes.
    pub max_password_bytes: usize,
    /// Password-recovery token lifetime.
    #[serde(with = "humantime_serde")]
    pub recovery_ttl: Duration,
    /// Email-verification token lifetime.
    #[serde(with = "humantime_serde")]
    pub verification_ttl: Duration,
}

impl Default for PasswordPolicyConfig {
    fn default() -> Self {
        Self {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: 1,
            min_password_bytes: MIN_PASSWORD_BYTES,
            max_password_bytes: MAX_PASSWORD_BYTES,
            recovery_ttl: Duration::from_mins(15),
            verification_ttl: Duration::from_hours(24),
        }
    }
}

/// One versioned optional Argon2 pepper.
///
/// Version zero conventionally denotes an unpeppered legacy policy. Secret
/// material is redacted and zeroized by [`SecretString`].
#[derive(Clone)]
pub struct PasswordPepper {
    version: u32,
    secret: Option<SecretString>,
}

impl PasswordPepper {
    /// Creates an unpeppered policy epoch.
    #[must_use]
    pub const fn unpeppered(version: u32) -> Self {
        Self {
            version,
            secret: None,
        }
    }

    /// Creates a peppered policy epoch.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordPolicyError::InvalidPepper`] for an empty or oversized secret.
    pub fn new(version: u32, secret: SecretString) -> Result<Self, PasswordPolicyError> {
        let length = secret.expose_secret().len();
        if length == 0 || length > MAX_PEPPER_BYTES {
            return Err(PasswordPolicyError::InvalidPepper);
        }
        Ok(Self {
            version,
            secret: Some(secret),
        })
    }

    /// Returns the persisted pepper epoch.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn secret(&self) -> Option<&[u8]> {
        self.secret
            .as_ref()
            .map(|secret| secret.expose_secret().as_bytes())
    }
}

impl fmt::Debug for PasswordPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordPepper")
            .field("version", &self.version)
            .field("secret", &self.secret.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Validated password and token policy with a bounded pepper rotation ring.
#[derive(Clone, Debug)]
pub struct PasswordPolicy {
    config: PasswordPolicyConfig,
    params: Params,
    peppers: Vec<PasswordPepper>,
}

impl PasswordPolicy {
    /// Validates policy bounds and installs the active pepper followed by legacy epochs.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordPolicyError`] for weak, hostile, duplicate, or oversized policy values.
    pub fn new(
        config: PasswordPolicyConfig,
        active: PasswordPepper,
        previous: Vec<PasswordPepper>,
    ) -> Result<Self, PasswordPolicyError> {
        validate_config(config)?;
        if previous.len() + 1 > MAX_PEPPERS {
            return Err(PasswordPolicyError::TooManyPeppers);
        }
        let mut peppers = Vec::with_capacity(previous.len() + 1);
        peppers.push(active);
        peppers.extend(previous);
        let mut versions = HashSet::with_capacity(peppers.len());
        if !peppers.iter().all(|pepper| versions.insert(pepper.version)) {
            return Err(PasswordPolicyError::DuplicatePepperVersion);
        }
        let params = Params::new(
            config.memory_kib,
            config.iterations,
            config.parallelism,
            Some(32),
        )
        .map_err(|_| PasswordPolicyError::InvalidArgon2Parameters)?;
        Ok(Self {
            config,
            params,
            peppers,
        })
    }

    /// Creates the default security-minimum policy without a pepper.
    ///
    /// # Errors
    ///
    /// Returns an error only if the compiled defaults violate Argon2 bounds.
    pub fn default_unpeppered() -> Result<Self, PasswordPolicyError> {
        Self::new(
            PasswordPolicyConfig::default(),
            PasswordPepper::unpeppered(0),
            Vec::new(),
        )
    }

    /// Returns the validated non-secret configuration.
    #[must_use]
    pub const fn config(&self) -> PasswordPolicyConfig {
        self.config
    }

    pub(crate) const fn params(&self) -> &Params {
        &self.params
    }

    pub(crate) fn active_pepper(&self) -> &PasswordPepper {
        &self.peppers[0]
    }

    pub(crate) fn pepper(&self, version: u32) -> Option<&PasswordPepper> {
        self.peppers.iter().find(|pepper| pepper.version == version)
    }
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self::default_unpeppered()
            .unwrap_or_else(|_| unreachable!("compiled password policy defaults must be valid"))
    }
}

/// Safe password-policy validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PasswordPolicyError {
    /// Argon2 memory fell outside the supported security and resource bounds.
    #[error("password memory cost is outside supported bounds")]
    InvalidMemory,
    /// Argon2 iterations fell outside the supported security and resource bounds.
    #[error("password iteration cost is outside supported bounds")]
    InvalidIterations,
    /// Argon2 parallelism fell outside supported bounds.
    #[error("password parallelism is outside supported bounds")]
    InvalidParallelism,
    /// Password input bounds were invalid or weak.
    #[error("password input bounds are invalid")]
    InvalidPasswordBounds,
    /// A token lifetime fell outside supported bounds.
    #[error("password token lifetime is outside supported bounds")]
    InvalidTokenTtl,
    /// Argon2 rejected the validated parameter combination.
    #[error("password hashing parameters are invalid")]
    InvalidArgon2Parameters,
    /// A pepper was empty or exceeded the Argon2 secret bound.
    #[error("password pepper is invalid")]
    InvalidPepper,
    /// More pepper epochs were retained than the bounded verifier permits.
    #[error("password pepper history is too large")]
    TooManyPeppers,
    /// Pepper epochs must be unique.
    #[error("password pepper versions must be unique")]
    DuplicatePepperVersion,
}

fn validate_config(config: PasswordPolicyConfig) -> Result<(), PasswordPolicyError> {
    if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&config.memory_kib) {
        return Err(PasswordPolicyError::InvalidMemory);
    }
    if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&config.iterations) {
        return Err(PasswordPolicyError::InvalidIterations);
    }
    if !(1..=MAX_PARALLELISM).contains(&config.parallelism) {
        return Err(PasswordPolicyError::InvalidParallelism);
    }
    if config.min_password_bytes < MIN_PASSWORD_BYTES
        || config.max_password_bytes > MAX_PASSWORD_BYTES
        || config.min_password_bytes > config.max_password_bytes
    {
        return Err(PasswordPolicyError::InvalidPasswordBounds);
    }
    if !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&config.recovery_ttl)
        || !(MIN_TOKEN_TTL..=MAX_TOKEN_TTL).contains(&config.verification_ttl)
    {
        return Err(PasswordPolicyError::InvalidTokenTtl);
    }
    Ok(())
}
