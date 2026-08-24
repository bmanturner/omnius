use std::{fmt, time::Duration};

use rsk_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

const MIN_PEPPER_BYTES: usize = 32;
const MAX_PEPPER_BYTES: usize = 4_096;
const MIN_MAX_SCOPES: usize = 1;
const MAX_MAX_SCOPES: usize = 128;
const MIN_KEY_LIFETIME: Duration = Duration::from_secs(60);
const MAX_KEY_LIFETIME: Duration = Duration::from_hours(8_760);
const MIN_LAST_USED_WRITE_INTERVAL: Duration = Duration::from_secs(60);
const MAX_LAST_USED_WRITE_INTERVAL: Duration = Duration::from_hours(24);
const REDACTED: &str = "[REDACTED]";

/// Strict resource and secret policy for API-key authentication.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiKeyConfig {
    /// Whether API-key authentication is enabled.
    pub enabled: bool,
    /// Secret HMAC key used to derive persisted API-key digests.
    pub pepper: SecretString,
    /// Maximum number of scopes accepted on one key.
    pub max_scopes: usize,
    /// Maximum requested lifetime accepted when issuing or rotating a key.
    #[serde(with = "humantime_serde")]
    pub max_key_lifetime: Duration,
    /// Minimum interval between best-effort `last_used_at` persistence writes.
    #[serde(with = "humantime_serde")]
    pub last_used_write_interval: Duration,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            pepper: SecretString::from(String::new()),
            max_scopes: 32,
            max_key_lifetime: Duration::from_hours(2_160),
            last_used_write_interval: Duration::from_mins(5),
        }
    }
}

impl fmt::Debug for ApiKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyConfig")
            .field("enabled", &self.enabled)
            .field("pepper", &REDACTED)
            .field("max_scopes", &self.max_scopes)
            .field("max_key_lifetime", &self.max_key_lifetime)
            .field("last_used_write_interval", &self.last_used_write_interval)
            .finish()
    }
}

impl ApiKeyConfig {
    /// Validates the pepper and every resource or persistence bound.
    ///
    /// Disabled configuration may omit the pepper, but any configured pepper is
    /// still validated so enabling the capability cannot activate weak material.
    ///
    /// # Errors
    ///
    /// Returns a stable, value-free classification for an invalid bound or pepper.
    pub fn validate(&self) -> Result<(), ApiKeyConfigError> {
        let pepper_len = self.pepper.expose_secret().len();
        if (self.enabled || pepper_len != 0)
            && !(MIN_PEPPER_BYTES..=MAX_PEPPER_BYTES).contains(&pepper_len)
        {
            return Err(ApiKeyConfigError::InvalidPepper);
        }
        if !(MIN_MAX_SCOPES..=MAX_MAX_SCOPES).contains(&self.max_scopes) {
            return Err(ApiKeyConfigError::InvalidMaxScopes);
        }
        if !(MIN_KEY_LIFETIME..=MAX_KEY_LIFETIME).contains(&self.max_key_lifetime) {
            return Err(ApiKeyConfigError::InvalidMaxKeyLifetime);
        }
        if !(MIN_LAST_USED_WRITE_INTERVAL..=MAX_LAST_USED_WRITE_INTERVAL)
            .contains(&self.last_used_write_interval)
        {
            return Err(ApiKeyConfigError::InvalidLastUsedWriteInterval);
        }
        Ok(())
    }
}

/// Stable, value-free API-key configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ApiKeyConfigError {
    /// The enabled pepper is missing, too short, or oversized.
    #[error("API-key pepper configuration is invalid")]
    InvalidPepper,
    /// The per-key scope limit is outside its fixed bound.
    #[error("API-key scope limit is invalid")]
    InvalidMaxScopes,
    /// The maximum key lifetime is outside its fixed bound.
    #[error("API-key lifetime limit is invalid")]
    InvalidMaxKeyLifetime,
    /// The `last_used_at` write interval is outside its fixed bound.
    #[error("API-key last-used write interval is invalid")]
    InvalidLastUsedWriteInterval,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> ApiKeyConfig {
        ApiKeyConfig {
            enabled: true,
            pepper: SecretString::from("p".repeat(MIN_PEPPER_BYTES)),
            ..ApiKeyConfig::default()
        }
    }

    #[test]
    fn enabled_configuration_requires_a_bounded_pepper() {
        let mut config = enabled_config();
        assert_eq!(config.validate(), Ok(()));

        config.pepper = SecretString::from("short".to_owned());
        assert_eq!(config.validate(), Err(ApiKeyConfigError::InvalidPepper));

        config.pepper = SecretString::from("p".repeat(MAX_PEPPER_BYTES + 1));
        assert_eq!(config.validate(), Err(ApiKeyConfigError::InvalidPepper));
    }

    #[test]
    fn disabled_defaults_are_valid_without_a_pepper() {
        assert_eq!(ApiKeyConfig::default().validate(), Ok(()));
    }

    #[test]
    fn resource_and_write_bounds_are_enforced() {
        let mut config = enabled_config();
        config.max_scopes = 0;
        assert_eq!(config.validate(), Err(ApiKeyConfigError::InvalidMaxScopes));

        config = enabled_config();
        config.max_key_lifetime = MAX_KEY_LIFETIME + Duration::from_secs(1);
        assert_eq!(
            config.validate(),
            Err(ApiKeyConfigError::InvalidMaxKeyLifetime)
        );

        config = enabled_config();
        config.last_used_write_interval = Duration::ZERO;
        assert_eq!(
            config.validate(),
            Err(ApiKeyConfigError::InvalidLastUsedWriteInterval)
        );
    }

    #[test]
    fn serde_is_strict_and_debug_redacts_the_pepper() -> Result<(), Box<dyn std::error::Error>> {
        let input = format!(
            "enabled = true\npepper = {:?}\nmax_scopes = 16\nmax_key_lifetime = \"30d\"\nlast_used_write_interval = \"5m\"\n",
            "secret-pepper-value-that-is-long-enough"
        );
        let config: ApiKeyConfig = toml::from_str(&input)?;
        assert_eq!(config.validate(), Ok(()));
        assert!(!format!("{config:?}").contains("secret-pepper-value"));

        let unknown = format!("{input}legacy_pepper = \"forbidden\"\n");
        assert!(toml::from_str::<ApiKeyConfig>(&unknown).is_err());
        Ok(())
    }
}
