use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rsk_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;
use zeroize::{Zeroize as _, Zeroizing};

/// Interoperable RFC 6238 token width.
pub const TOTP_DIGITS: u8 = 6;
/// Interoperable RFC 6238 time step in seconds.
pub const TOTP_STEP_SECONDS: u64 = 30;

const MAX_ISSUER_BYTES: usize = 128;
const MAX_SKEW: u16 = 2;
const MIN_RECENT_AUTH_AGE: Duration = Duration::from_secs(60);
const MAX_RECENT_AUTH_AGE: Duration = Duration::from_hours(1);
const MIN_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const MAX_FAILURE_WINDOW: Duration = Duration::from_hours(1);
const MIN_FAILURE_THRESHOLD: u32 = 3;
const MAX_FAILURE_THRESHOLD: u32 = 20;
const MIN_LOCK_DURATION: Duration = Duration::from_secs(30);
const MAX_LOCK_DURATION: Duration = Duration::from_hours(24);
const MIN_RECOVERY_CODES: usize = 5;
const MAX_RECOVERY_CODES: usize = 20;
const MASTER_KEY_BYTES: usize = 32;

/// Strict TOTP capability configuration.
///
/// The encryption master key is accepted only as canonical unpadded base64url
/// containing exactly 32 bytes. Debug output never includes the key.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TotpConfig {
    /// Enables the optional capability.
    pub enabled: bool,
    /// Base64url-encoded 256-bit master key. It is required when enabled.
    pub encryption_key: Option<SecretString>,
    /// Authenticator-visible issuer, bounded to 128 UTF-8 bytes.
    pub issuer: String,
    /// Number of adjacent 30-second steps accepted on either side of the current step.
    pub skew: u16,
    /// Maximum age of the first factor for enrollment and disable operations.
    #[serde(with = "humantime_serde")]
    pub recent_auth_max_age: Duration,
    /// Rolling window in which failed verification attempts accumulate.
    #[serde(with = "humantime_serde")]
    pub verification_failure_window: Duration,
    /// Failures within the rolling window that trigger a durable lock.
    pub verification_failure_threshold: u32,
    /// Duration of a durable verification lock.
    #[serde(with = "humantime_serde")]
    pub verification_lock_duration: Duration,
    /// Number of one-time recovery codes issued when enrollment is confirmed.
    pub recovery_code_count: usize,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            encryption_key: None,
            issuer: "Service Kit".to_owned(),
            skew: 1,
            recent_auth_max_age: Duration::from_mins(10),
            verification_failure_window: Duration::from_mins(5),
            verification_failure_threshold: 5,
            verification_lock_duration: Duration::from_mins(15),
            recovery_code_count: 10,
        }
    }
}

impl fmt::Debug for TotpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpConfig")
            .field("enabled", &self.enabled)
            .field(
                "encryption_key",
                &self.encryption_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("issuer", &self.issuer)
            .field("digits", &TOTP_DIGITS)
            .field("step_seconds", &TOTP_STEP_SECONDS)
            .field("skew", &self.skew)
            .field("recent_auth_max_age", &self.recent_auth_max_age)
            .field(
                "verification_failure_window",
                &self.verification_failure_window,
            )
            .field(
                "verification_failure_threshold",
                &self.verification_failure_threshold,
            )
            .field(
                "verification_lock_duration",
                &self.verification_lock_duration,
            )
            .field("recovery_code_count", &self.recovery_code_count)
            .finish()
    }
}

impl TotpConfig {
    /// Validates all security and resource bounds without exposing secret values.
    ///
    /// # Errors
    ///
    /// Returns a stable [`TotpConfigError`] when a field is missing, malformed,
    /// weak, or outside its supported bound.
    pub fn validate(&self) -> Result<(), TotpConfigError> {
        validate_issuer(&self.issuer)?;
        if self.skew > MAX_SKEW {
            return Err(TotpConfigError::InvalidSkew);
        }
        if !(MIN_RECENT_AUTH_AGE..=MAX_RECENT_AUTH_AGE).contains(&self.recent_auth_max_age) {
            return Err(TotpConfigError::InvalidRecentAuthenticationAge);
        }
        if !(MIN_FAILURE_WINDOW..=MAX_FAILURE_WINDOW).contains(&self.verification_failure_window) {
            return Err(TotpConfigError::InvalidFailureWindow);
        }
        if !(MIN_FAILURE_THRESHOLD..=MAX_FAILURE_THRESHOLD)
            .contains(&self.verification_failure_threshold)
        {
            return Err(TotpConfigError::InvalidFailureThreshold);
        }
        if !(MIN_LOCK_DURATION..=MAX_LOCK_DURATION).contains(&self.verification_lock_duration) {
            return Err(TotpConfigError::InvalidLockDuration);
        }
        if !(MIN_RECOVERY_CODES..=MAX_RECOVERY_CODES).contains(&self.recovery_code_count) {
            return Err(TotpConfigError::InvalidRecoveryCodeCount);
        }
        match self.encryption_key.as_ref() {
            Some(key) => {
                let _decoded = decode_master_key(key)?;
            }
            None if self.enabled => return Err(TotpConfigError::InvalidEncryptionMasterKey),
            None => {}
        }
        Ok(())
    }

    pub(crate) fn decoded_master_key(
        &self,
    ) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>, TotpConfigError> {
        let key = self
            .encryption_key
            .as_ref()
            .ok_or(TotpConfigError::InvalidEncryptionMasterKey)?;
        decode_master_key(key)
    }
}

/// Value-free TOTP configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TotpConfigError {
    /// The master key was missing, non-canonical, or not exactly 256 bits.
    #[error("TOTP encryption master key is invalid")]
    InvalidEncryptionMasterKey,
    /// The authenticator issuer was empty, oversized, or unsafe.
    #[error("TOTP issuer is invalid")]
    InvalidIssuer,
    /// Time-step skew exceeded the supported two-step maximum.
    #[error("TOTP verification skew is outside supported bounds")]
    InvalidSkew,
    /// Recent-authentication age was outside supported bounds.
    #[error("TOTP recent-authentication age is outside supported bounds")]
    InvalidRecentAuthenticationAge,
    /// Verification failure window was outside supported bounds.
    #[error("TOTP verification failure window is outside supported bounds")]
    InvalidFailureWindow,
    /// Verification failure threshold was outside supported bounds.
    #[error("TOTP verification failure threshold is outside supported bounds")]
    InvalidFailureThreshold,
    /// Verification lock duration was outside supported bounds.
    #[error("TOTP verification lock duration is outside supported bounds")]
    InvalidLockDuration,
    /// Recovery-code count was outside supported bounds.
    #[error("TOTP recovery-code count is outside supported bounds")]
    InvalidRecoveryCodeCount,
}

fn validate_issuer(issuer: &str) -> Result<(), TotpConfigError> {
    if issuer.is_empty()
        || issuer.len() > MAX_ISSUER_BYTES
        || issuer.trim() != issuer
        || issuer.contains(':')
        || issuer.chars().any(char::is_control)
    {
        Err(TotpConfigError::InvalidIssuer)
    } else {
        Ok(())
    }
}

fn decode_master_key(
    encoded: &SecretString,
) -> Result<Zeroizing<[u8; MASTER_KEY_BYTES]>, TotpConfigError> {
    let encoded = encoded.expose_secret();
    let mut decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| TotpConfigError::InvalidEncryptionMasterKey)?;
    if decoded.len() != MASTER_KEY_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        decoded.zeroize();
        return Err(TotpConfigError::InvalidEncryptionMasterKey);
    }
    let mut key = Zeroizing::new([0_u8; MASTER_KEY_BYTES]);
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> TotpConfig {
        TotpConfig {
            enabled: true,
            encryption_key: Some(SecretString::from(URL_SAFE_NO_PAD.encode([7_u8; 32]))),
            ..TotpConfig::default()
        }
    }

    #[test]
    fn config_accepts_only_a_canonical_32_byte_base64url_key() {
        let valid = enabled_config();
        assert!(valid.validate().is_ok());
        let missing = TotpConfig {
            enabled: true,
            ..TotpConfig::default()
        };
        assert_eq!(
            missing.validate(),
            Err(TotpConfigError::InvalidEncryptionMasterKey)
        );

        let mut invalid = valid.clone();
        invalid.encryption_key = Some(SecretString::from(URL_SAFE_NO_PAD.encode([7_u8; 31])));
        assert_eq!(
            invalid.validate(),
            Err(TotpConfigError::InvalidEncryptionMasterKey)
        );

        invalid.encryption_key = Some(SecretString::from(format!(
            "{}=",
            URL_SAFE_NO_PAD.encode([7_u8; 32])
        )));
        assert_eq!(
            invalid.validate(),
            Err(TotpConfigError::InvalidEncryptionMasterKey)
        );
    }

    #[test]
    fn config_bounds_skew_failure_policy_recent_auth_and_recovery_count() {
        let mut config = enabled_config();
        config.skew = 3;
        assert_eq!(config.validate(), Err(TotpConfigError::InvalidSkew));

        config = enabled_config();
        config.verification_failure_threshold = 2;
        assert_eq!(
            config.validate(),
            Err(TotpConfigError::InvalidFailureThreshold)
        );

        config = enabled_config();
        config.recent_auth_max_age = Duration::from_secs(30);
        assert_eq!(
            config.validate(),
            Err(TotpConfigError::InvalidRecentAuthenticationAge)
        );

        config = enabled_config();
        config.recovery_code_count = 21;
        assert_eq!(
            config.validate(),
            Err(TotpConfigError::InvalidRecoveryCodeCount)
        );
    }

    #[test]
    fn strict_deserialization_rejects_unknown_fields_and_debug_redacts_key() {
        let json = format!(
            r#"{{"enabled":true,"encryption_key":"{}","issuer":"Example","unknown":1}}"#,
            URL_SAFE_NO_PAD.encode([9_u8; 32])
        );
        assert!(serde_json::from_str::<TotpConfig>(&json).is_err());

        let config = enabled_config();
        let debug = format!("{config:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(
            !debug.contains(
                config
                    .encryption_key
                    .as_ref()
                    .map_or("", |key| key.expose_secret())
            )
        );
    }
}
