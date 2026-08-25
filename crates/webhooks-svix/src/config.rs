use std::{fmt, time::Duration};

use serde::{Deserialize, Deserializer};
use url::Url;

use crate::{ApplicationId, ConfigError, Destination, SvixToken, value::validate_server_url};

const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_DRAIN_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REPLAY_WAIT_TIMEOUT: Duration = Duration::from_secs(600);
const MIN_REPLAY_POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_REPLAY_POLL_INTERVAL: Duration = Duration::from_secs(10);
const MAX_REPLAY_POLLS: u16 = 600;
const MAX_STATUS_ATTEMPTS: u16 = 100;
const MAX_REQUEST_PAYLOAD_BYTES: usize = 1_048_576;

fn default_request_timeout() -> Duration {
    Duration::from_secs(15)
}

fn default_drain_timeout() -> Duration {
    Duration::from_secs(10)
}

fn default_replay_poll_interval() -> Duration {
    Duration::from_millis(250)
}

fn default_replay_wait_timeout() -> Duration {
    Duration::from_secs(60)
}

const fn default_replay_max_polls() -> u16 {
    120
}

const fn default_max_status_attempts() -> u16 {
    50
}

const fn default_max_payload_bytes() -> usize {
    256 * 1024
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSvixConfig {
    token: SvixToken,
    application_id: String,
    destination: String,
    #[serde(default)]
    server_url: Option<Url>,
    #[serde(default)]
    allow_insecure_loopback: bool,
    #[serde(default = "default_request_timeout", with = "humantime_serde")]
    request_timeout: Duration,
    #[serde(default = "default_drain_timeout", with = "humantime_serde")]
    drain_timeout: Duration,
    #[serde(default = "default_replay_poll_interval", with = "humantime_serde")]
    replay_poll_interval: Duration,
    #[serde(default = "default_replay_wait_timeout", with = "humantime_serde")]
    replay_wait_timeout: Duration,
    #[serde(default = "default_replay_max_polls")]
    replay_max_polls: u16,
    #[serde(default = "default_max_status_attempts")]
    max_status_attempts: u16,
    #[serde(default = "default_max_payload_bytes")]
    max_payload_bytes: usize,
}

/// Strict, bounded Svix adapter configuration.
///
/// SDK retries are intentionally not configurable: the concrete adapter always sets
/// `SvixOptions::num_retries` to zero. SDK 1.99.1 cannot accept the shared outbound HTTP client or
/// enforce proxy failure; unknown `proxy` and retry fields therefore fail closed during strict
/// deserialization rather than silently bypassing policy.
#[derive(Clone)]
pub struct SvixConfig {
    token: SvixToken,
    application_id: ApplicationId,
    destination: Destination,
    server_url: Option<Url>,
    allow_insecure_loopback: bool,
    request_timeout: Duration,
    drain_timeout: Duration,
    replay_poll_interval: Duration,
    replay_wait_timeout: Duration,
    replay_max_polls: u16,
    max_status_attempts: u16,
    max_payload_bytes: usize,
}

impl SvixConfig {
    /// Creates a validated configuration with bounded production defaults and the managed Svix URL.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when any default or supplied value violates a hard bound.
    pub fn new(
        token: SvixToken,
        application_id: ApplicationId,
        destination: Destination,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            token,
            application_id,
            destination,
            server_url: None,
            allow_insecure_loopback: false,
            request_timeout: default_request_timeout(),
            drain_timeout: default_drain_timeout(),
            replay_poll_interval: default_replay_poll_interval(),
            replay_wait_timeout: default_replay_wait_timeout(),
            replay_max_polls: default_replay_max_polls(),
            max_status_attempts: default_max_status_attempts(),
            max_payload_bytes: default_max_payload_bytes(),
        };
        config.validate()?;
        Ok(config)
    }

    /// Selects a self-hosted API URL and controls the explicit loopback development exception.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the URL or loopback exception is unsafe.
    pub fn with_server_url(
        mut self,
        server_url: Url,
        allow_insecure_loopback: bool,
    ) -> Result<Self, ConfigError> {
        self.server_url = Some(server_url);
        self.allow_insecure_loopback = allow_insecure_loopback;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the bounded operation and shutdown deadlines.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when either timeout is zero or exceeds its ceiling.
    pub fn with_timeouts(
        mut self,
        request_timeout: Duration,
        drain_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        self.request_timeout = request_timeout;
        self.drain_timeout = drain_timeout;
        self.validate()?;
        Ok(self)
    }

    /// Replaces bounded replay polling controls.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when any replay polling bound is invalid.
    pub fn with_replay_policy(
        mut self,
        poll_interval: Duration,
        wait_timeout: Duration,
        max_polls: u16,
    ) -> Result<Self, ConfigError> {
        self.replay_poll_interval = poll_interval;
        self.replay_wait_timeout = wait_timeout;
        self.replay_max_polls = max_polls;
        self.validate()?;
        Ok(self)
    }

    /// Replaces response and request-body safety caps.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when either capacity is zero or exceeds its ceiling.
    pub fn with_limits(
        mut self,
        max_status_attempts: u16,
        max_payload_bytes: usize,
    ) -> Result<Self, ConfigError> {
        self.max_status_attempts = max_status_attempts;
        self.max_payload_bytes = max_payload_bytes;
        self.validate()?;
        Ok(self)
    }

    /// Validates every absolute safety ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for any unsafe token, URL, timeout, replay, or capacity value.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.token.expose().is_empty() {
            return Err(ConfigError::InvalidToken);
        }
        if let Some(url) = &self.server_url {
            validate_server_url(url, self.allow_insecure_loopback)
                .map_err(|_| ConfigError::InvalidServerUrl)?;
        }
        if self.request_timeout.is_zero()
            || self.request_timeout > MAX_REQUEST_TIMEOUT
            || self.drain_timeout.is_zero()
            || self.drain_timeout > MAX_DRAIN_TIMEOUT
        {
            return Err(ConfigError::InvalidTimeout);
        }
        if self.replay_poll_interval < MIN_REPLAY_POLL_INTERVAL
            || self.replay_poll_interval > MAX_REPLAY_POLL_INTERVAL
            || self.replay_wait_timeout.is_zero()
            || self.replay_wait_timeout > MAX_REPLAY_WAIT_TIMEOUT
            || self.replay_max_polls == 0
            || self.replay_max_polls > MAX_REPLAY_POLLS
        {
            return Err(ConfigError::InvalidReplayBounds);
        }
        if self.max_status_attempts == 0
            || self.max_status_attempts > MAX_STATUS_ATTEMPTS
            || self.max_payload_bytes == 0
            || self.max_payload_bytes > MAX_REQUEST_PAYLOAD_BYTES
        {
            return Err(ConfigError::InvalidCapacity);
        }
        Ok(())
    }

    /// Returns the configured stable application mapping.
    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application_id
    }

    /// Returns the configured outbox destination.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Returns the explicit SDK total request timeout.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Returns the bounded shutdown drain timeout.
    #[must_use]
    pub const fn drain_timeout(&self) -> Duration {
        self.drain_timeout
    }

    /// Returns the maximum delivery attempts accepted from one provider response.
    #[must_use]
    pub const fn max_status_attempts(&self) -> u16 {
        self.max_status_attempts
    }

    /// Returns the maximum canonical event envelope size.
    #[must_use]
    pub const fn max_payload_bytes(&self) -> usize {
        self.max_payload_bytes
    }

    pub(crate) const fn token(&self) -> &SvixToken {
        &self.token
    }

    pub(crate) fn server_url_string(&self) -> Option<String> {
        self.server_url
            .as_ref()
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
    }

    pub(crate) const fn replay_poll_interval(&self) -> Duration {
        self.replay_poll_interval
    }

    pub(crate) const fn replay_wait_timeout(&self) -> Duration {
        self.replay_wait_timeout
    }

    pub(crate) const fn replay_max_polls(&self) -> u16 {
        self.replay_max_polls
    }
}

impl<'de> Deserialize<'de> for SvixConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawSvixConfig::deserialize(deserializer)?;
        let config = Self {
            token: raw.token,
            application_id: ApplicationId::new(raw.application_id)
                .map_err(serde::de::Error::custom)?,
            destination: Destination::new(raw.destination).map_err(serde::de::Error::custom)?,
            server_url: raw.server_url,
            allow_insecure_loopback: raw.allow_insecure_loopback,
            request_timeout: raw.request_timeout,
            drain_timeout: raw.drain_timeout,
            replay_poll_interval: raw.replay_poll_interval,
            replay_wait_timeout: raw.replay_wait_timeout,
            replay_max_polls: raw.replay_max_polls,
            max_status_attempts: raw.max_status_attempts,
            max_payload_bytes: raw.max_payload_bytes,
        };
        config.validate().map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

impl fmt::Debug for SvixConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SvixConfig")
            .field("token", &"[REDACTED]")
            .field(
                "server_url",
                &self.server_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("application_id", &self.application_id)
            .field("destination", &self.destination)
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .field("request_timeout", &self.request_timeout)
            .field("drain_timeout", &self.drain_timeout)
            .field("replay_poll_interval", &self.replay_poll_interval)
            .field("replay_wait_timeout", &self.replay_wait_timeout)
            .field("replay_max_polls", &self.replay_max_polls)
            .field("max_status_attempts", &self.max_status_attempts)
            .field("max_payload_bytes", &self.max_payload_bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use rsk_config::SecretString;

    use super::*;

    #[test]
    fn sdk_server_url_has_no_trailing_separator() -> Result<(), Box<dyn std::error::Error>> {
        let config = SvixConfig::new(
            SvixToken::new(SecretString::from("test_token".to_owned()))?,
            ApplicationId::new("tenant_demo")?,
            Destination::new("svix")?,
        )?
        .with_server_url(Url::parse("https://svix.example.test/")?, false)?;

        assert_eq!(
            config.server_url_string().as_deref(),
            Some("https://svix.example.test")
        );
        Ok(())
    }
}
