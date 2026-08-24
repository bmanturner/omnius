use std::time::Duration;

use rsk_config::DeploymentEnvironment;
use serde::Deserialize;
use thiserror::Error;
use tower_sessions::cookie::SameSite;

const DEFAULT_COOKIE_NAME: &str = "__Host-rsk_session";
const MIN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IDLE_TIMEOUT: Duration = Duration::from_hours(720);
const MAX_ABSOLUTE_TIMEOUT: Duration = Duration::from_hours(8_760);

/// Browser cookie same-site policy supported by the session capability.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionSameSite {
    /// Send the cookie on same-site requests and top-level cross-site navigation.
    #[default]
    Lax,
    /// Send the cookie only on same-site requests.
    Strict,
}

impl From<SessionSameSite> for SameSite {
    fn from(value: SessionSameSite) -> Self {
        match value {
            SessionSameSite::Lax => Self::Lax,
            SessionSameSite::Strict => Self::Strict,
        }
    }
}

/// Session persistence provider accepted by this capability.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SessionStoreKind {
    /// PostgreSQL through the maintained `SQLx` store.
    #[default]
    Postgres,
}

/// Validated browser-session and cookie configuration.
///
/// Cookie path is always `/` and a cookie domain is never set. Production also
/// requires a `__Host-` name together with `Secure` and `HttpOnly`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SessionConfig {
    /// Whether browser-session authentication is enabled.
    pub enabled: bool,
    /// Selected persistence provider.
    pub store: SessionStoreKind,
    /// Cookie name sent to the browser.
    pub cookie_name: String,
    /// Whether the cookie is limited to secure transports.
    pub secure: bool,
    /// Whether browser scripts are denied access to the cookie.
    pub http_only: bool,
    /// Same-site cookie policy.
    pub same_site: SessionSameSite,
    /// Maximum inactivity before a provider session expires.
    #[serde(with = "humantime_serde")]
    pub idle_timeout: Duration,
    /// Maximum lifetime from registration, independent of activity.
    #[serde(with = "humantime_serde")]
    pub absolute_timeout: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            store: SessionStoreKind::Postgres,
            cookie_name: DEFAULT_COOKIE_NAME.to_owned(),
            secure: true,
            http_only: true,
            same_site: SessionSameSite::Lax,
            idle_timeout: Duration::from_hours(12),
            absolute_timeout: Duration::from_hours(720),
        }
    }
}

impl SessionConfig {
    /// Validates global timeout and cookie invariants plus deployment policy.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`SessionConfigError`] when the configuration is
    /// malformed or production cookie protections are disabled.
    pub fn validate_for(
        &self,
        deployment: DeploymentEnvironment,
    ) -> Result<(), SessionConfigError> {
        if !valid_cookie_name(&self.cookie_name) {
            return Err(SessionConfigError::InvalidCookieName);
        }
        if self.cookie_name.starts_with("__Host-") && !self.secure {
            return Err(SessionConfigError::HostCookieMustBeSecure);
        }
        if self.idle_timeout < MIN_TIMEOUT || self.idle_timeout > MAX_IDLE_TIMEOUT {
            return Err(SessionConfigError::InvalidIdleTimeout);
        }
        if self.absolute_timeout < self.idle_timeout || self.absolute_timeout > MAX_ABSOLUTE_TIMEOUT
        {
            return Err(SessionConfigError::InvalidAbsoluteTimeout);
        }
        if deployment == DeploymentEnvironment::Production {
            if !self.cookie_name.starts_with("__Host-") {
                return Err(SessionConfigError::ProductionHostCookieRequired);
            }
            debug_assert!(self.secure);
            if !self.http_only {
                return Err(SessionConfigError::ProductionHttpOnlyCookieRequired);
            }
        }
        Ok(())
    }
}

fn valid_cookie_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Safe session configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionConfigError {
    /// The caller attempted to construct a disabled session capability.
    #[error("browser sessions are disabled")]
    Disabled,
    /// Cookie name is empty, too long, or outside the HTTP token grammar.
    #[error("session cookie name is invalid")]
    InvalidCookieName,
    /// Idle timeout is outside supported bounds.
    #[error("session idle timeout is invalid")]
    InvalidIdleTimeout,
    /// Absolute timeout is shorter than idle timeout or outside supported bounds.
    #[error("session absolute timeout is invalid")]
    InvalidAbsoluteTimeout,
    /// Production cookies must use the `__Host-` prefix.
    #[error("production session cookie requires the host prefix")]
    ProductionHostCookieRequired,
    /// Host-prefixed cookies must be secure in every deployment.
    #[error("host-prefixed session cookie must be secure")]
    HostCookieMustBeSecure,
    /// Production cookies must be HTTP-only.
    #[error("production session cookie must be HTTP-only")]
    ProductionHttpOnlyCookieRequired,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_and_deployment_validation_enforce_cookie_policy() -> Result<(), serde_json::Error> {
        let development: SessionConfig = serde_json::from_value(serde_json::json!({
            "cookie_name": "local_session",
            "secure": false,
            "http_only": false,
            "same_site": "strict",
            "idle_timeout": "15m",
            "absolute_timeout": "1d"
        }))?;

        assert_eq!(
            development.validate_for(DeploymentEnvironment::Development),
            Ok(())
        );
        assert_eq!(
            development.validate_for(DeploymentEnvironment::Production),
            Err(SessionConfigError::ProductionHostCookieRequired)
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_invalid_names_and_timeout_relationships() {
        let invalid_name = SessionConfig {
            cookie_name: "has whitespace".to_owned(),
            ..SessionConfig::default()
        };
        assert_eq!(
            invalid_name.validate_for(DeploymentEnvironment::Test),
            Err(SessionConfigError::InvalidCookieName)
        );

        let invalid_timeout = SessionConfig {
            absolute_timeout: Duration::from_secs(1),
            ..SessionConfig::default()
        };
        assert_eq!(
            invalid_timeout.validate_for(DeploymentEnvironment::Test),
            Err(SessionConfigError::InvalidAbsoluteTimeout)
        );
    }

    #[test]
    fn host_prefix_requires_secure_in_every_environment() {
        let config = SessionConfig {
            secure: false,
            ..SessionConfig::default()
        };
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Development),
            Err(SessionConfigError::HostCookieMustBeSecure)
        );
    }

    #[test]
    fn production_requires_http_only() {
        let config = SessionConfig {
            http_only: false,
            ..SessionConfig::default()
        };
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(SessionConfigError::ProductionHttpOnlyCookieRequired)
        );
    }
}
