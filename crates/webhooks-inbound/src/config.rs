use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use http::HeaderName;
use omnius_config::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use thiserror::Error;

use crate::provider::FixtureVerificationPolicy;
use crate::{
    FixtureHmacSha256Adapter, ProviderAdapter, ProviderId, ProviderRegistry, RegistryError,
};

const MAX_PROVIDERS: usize = 32;
const MIN_BODY_BYTES: usize = 1;
const MAX_BODY_BYTES: usize = 2 * 1024 * 1024;
const MIN_HEADER_BYTES: usize = 256;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 128;
const MAX_SAFE_PAYLOAD_BYTES: usize = 256 * 1024;
const MIN_SECRET_BYTES: usize = 32;
const MAX_SECRET_BYTES: usize = 4_096;
const MAX_ROTATED_KEYS: usize = 3;
const MAX_ATTEMPTS: u16 = 20;
const MAX_BATCH_SIZE: u16 = 100;
const MAX_LEASE: Duration = Duration::from_mins(5);
const MAX_HANDLER_TIMEOUT: Duration = Duration::from_mins(4);
const MAX_POLL_INTERVAL: Duration = Duration::from_mins(1);
const MAX_RETRY_DELAY: Duration = Duration::from_hours(1);
const MAX_RETENTION: Duration = Duration::from_hours(2_160);
const MAX_REPLAY_WINDOW: Duration = Duration::from_hours(24);
const MAX_FUTURE_TOLERANCE: Duration = Duration::from_mins(10);

/// Strict resource, receipt, and deterministic fixture-provider configuration.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebhookConfig {
    /// Enables callback routing and background receipt processing.
    pub enabled: bool,
    /// Maximum exact raw body accepted by the callback route.
    pub max_body_bytes: usize,
    /// Maximum number of HTTP header values accepted before adapter verification.
    pub max_header_count: usize,
    /// Maximum aggregate HTTP header-name and value bytes accepted before verification.
    pub max_header_bytes: usize,
    /// Maximum serialized safe parsed payload persisted in one receipt.
    pub max_safe_payload_bytes: usize,
    /// Terminal receipt retention period.
    #[serde(with = "humantime_serde")]
    pub retention: Duration,
    /// Bounded lease-processor policy.
    pub processing: ProcessorConfig,
    /// Explicit deterministic test/development HMAC providers.
    pub fixture_hmac_providers: Vec<FixtureHmacProviderConfig>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_body_bytes: 1024 * 1024,
            max_header_count: 64,
            max_header_bytes: 32 * 1024,
            max_safe_payload_bytes: 128 * 1024,
            retention: Duration::from_hours(720),
            processing: ProcessorConfig::default(),
            fixture_hmac_providers: Vec::new(),
        }
    }
}

impl fmt::Debug for WebhookConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookConfig")
            .field("enabled", &self.enabled)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_header_count", &self.max_header_count)
            .field("max_header_bytes", &self.max_header_bytes)
            .field("max_safe_payload_bytes", &self.max_safe_payload_bytes)
            .field("retention", &self.retention)
            .field("processing", &self.processing)
            .field("fixture_hmac_providers", &self.fixture_hmac_providers)
            .finish()
    }
}

impl WebhookConfig {
    /// Validates every resource, timing, provider, header, and secret bound.
    ///
    /// Disabled configuration may omit providers. Configured providers are always validated.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`WebhookConfigError`] classification for invalid policy.
    pub fn validate(&self) -> Result<(), WebhookConfigError> {
        if self.enabled && self.fixture_hmac_providers.is_empty() {
            return Err(WebhookConfigError::MissingProvider);
        }
        if self.fixture_hmac_providers.len() > MAX_PROVIDERS {
            return Err(WebhookConfigError::InvalidProviderCount);
        }
        if !(MIN_BODY_BYTES..=MAX_BODY_BYTES).contains(&self.max_body_bytes) {
            return Err(WebhookConfigError::InvalidBodyLimit);
        }
        if self.max_header_count == 0 || self.max_header_count > MAX_HEADER_COUNT {
            return Err(WebhookConfigError::InvalidHeaderLimit);
        }
        if !(MIN_HEADER_BYTES..=MAX_HEADER_BYTES).contains(&self.max_header_bytes) {
            return Err(WebhookConfigError::InvalidHeaderLimit);
        }
        if self.max_safe_payload_bytes == 0
            || self.max_safe_payload_bytes > MAX_SAFE_PAYLOAD_BYTES
            || self.max_safe_payload_bytes > self.max_body_bytes
        {
            return Err(WebhookConfigError::InvalidPayloadLimit);
        }
        if self.retention < Duration::from_hours(1) || self.retention > MAX_RETENTION {
            return Err(WebhookConfigError::InvalidRetention);
        }
        self.processing.validate()?;

        let mut provider_ids = HashSet::new();
        let mut minimum_receipt_retention = Duration::ZERO;
        for provider in &self.fixture_hmac_providers {
            let provider_minimum = provider
                .replay_window
                .saturating_add(provider.future_tolerance)
                .saturating_add(Duration::from_secs(1));
            minimum_receipt_retention = minimum_receipt_retention.max(provider_minimum);
            provider.validate()?;
            if !provider_ids.insert(provider.provider.as_str()) {
                return Err(WebhookConfigError::DuplicateProvider);
            }
        }
        if self.retention < minimum_receipt_retention {
            return Err(WebhookConfigError::RetentionShorterThanAcceptance);
        }
        Ok(())
    }

    /// Builds an immutable provider registry from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookConfigError`] when any configuration is invalid or duplicated.
    pub fn build_registry(&self) -> Result<ProviderRegistry, WebhookConfigError> {
        self.validate()?;
        let adapters = self
            .fixture_hmac_providers
            .iter()
            .map(FixtureHmacProviderConfig::build)
            .collect::<Result<Vec<_>, _>>()?;
        let registry = ProviderRegistry::new(adapters).map_err(WebhookConfigError::from)?;
        self.validate_against_registry(&registry)?;
        Ok(registry)
    }

    /// Validates that durable identity fences outlive every inclusive timestamp acceptance window.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookConfigError`] when configuration is invalid or retention cannot cover a
    /// registered provider's replay window, future tolerance, and inclusive timestamp edge.
    pub fn validate_against_registry(
        &self,
        registry: &ProviderRegistry,
    ) -> Result<(), WebhookConfigError> {
        self.validate()?;
        if self.retention < registry.minimum_receipt_retention() {
            return Err(WebhookConfigError::RetentionShorterThanAcceptance);
        }
        Ok(())
    }
}

/// Bounded asynchronous receipt processor policy.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessorConfig {
    /// Maximum receipts leased per database claim.
    pub batch_size: u16,
    /// Maximum delivery attempts, including claims lost to expiry.
    pub max_attempts: u16,
    /// Database-clock lease duration.
    #[serde(with = "humantime_serde")]
    pub lease_duration: Duration,
    /// Maximum duration of one handler invocation.
    #[serde(with = "humantime_serde")]
    pub handler_timeout: Duration,
    /// Idle polling interval.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Initial retry delay.
    #[serde(with = "humantime_serde")]
    pub retry_base_delay: Duration,
    /// Maximum retry delay.
    #[serde(with = "humantime_serde")]
    pub retry_max_delay: Duration,
    /// Maximum terminal receipts removed in one retention sweep.
    pub cleanup_batch_size: u16,
    /// Supervisor drain bound for the processor task.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            batch_size: 32,
            max_attempts: 8,
            lease_duration: Duration::from_secs(60),
            handler_timeout: Duration::from_secs(30),
            poll_interval: Duration::from_secs(1),
            retry_base_delay: Duration::from_secs(2),
            retry_max_delay: Duration::from_mins(5),
            cleanup_batch_size: 100,
            shutdown_timeout: Duration::from_secs(10),
        }
    }
}

impl ProcessorConfig {
    pub(crate) fn validate(self) -> Result<(), WebhookConfigError> {
        if self.batch_size == 0
            || self.batch_size > MAX_BATCH_SIZE
            || self.cleanup_batch_size == 0
            || self.cleanup_batch_size > MAX_BATCH_SIZE
        {
            return Err(WebhookConfigError::InvalidBatchSize);
        }
        if self.max_attempts == 0 || self.max_attempts > MAX_ATTEMPTS {
            return Err(WebhookConfigError::InvalidAttempts);
        }
        if self.lease_duration < Duration::from_secs(1) || self.lease_duration > MAX_LEASE {
            return Err(WebhookConfigError::InvalidLease);
        }
        if self.handler_timeout.is_zero()
            || self.handler_timeout > MAX_HANDLER_TIMEOUT
            || self.handler_timeout.saturating_add(Duration::from_secs(1)) > self.lease_duration
        {
            return Err(WebhookConfigError::InvalidHandlerTimeout);
        }
        if self.poll_interval < Duration::from_millis(10) || self.poll_interval > MAX_POLL_INTERVAL
        {
            return Err(WebhookConfigError::InvalidPollInterval);
        }
        if self.retry_base_delay.is_zero()
            || self.retry_base_delay > self.retry_max_delay
            || self.retry_max_delay > MAX_RETRY_DELAY
        {
            return Err(WebhookConfigError::InvalidRetryDelay);
        }
        if self.shutdown_timeout.is_zero() || self.shutdown_timeout > Duration::from_mins(1) {
            return Err(WebhookConfigError::InvalidShutdownTimeout);
        }
        Ok(())
    }
}

/// Configuration for the explicit deterministic HMAC fixture protocol.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureHmacProviderConfig {
    /// Provider route identifier.
    pub provider: String,
    /// Header containing exactly one `v1=` hexadecimal signature.
    pub signature_header: String,
    /// Header containing exactly one signed Unix timestamp.
    pub timestamp_header: String,
    /// Header containing exactly one signed provider scope.
    pub scope_header: String,
    /// Header containing exactly one signed event identity.
    pub event_id_header: String,
    /// Current secret followed by bounded rotation fallbacks.
    pub secrets: Vec<SecretString>,
    /// Maximum accepted age of an authenticated timestamp.
    #[serde(with = "humantime_serde")]
    pub replay_window: Duration,
    /// Maximum accepted future clock skew.
    #[serde(with = "humantime_serde")]
    pub future_tolerance: Duration,
}

impl fmt::Debug for FixtureHmacProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FixtureHmacProviderConfig")
            .field("provider", &self.provider)
            .field("signature_header", &self.signature_header)
            .field("timestamp_header", &self.timestamp_header)
            .field("scope_header", &self.scope_header)
            .field("event_id_header", &self.event_id_header)
            .field("secrets", &"[REDACTED]")
            .field("replay_window", &self.replay_window)
            .field("future_tolerance", &self.future_tolerance)
            .finish()
    }
}

impl FixtureHmacProviderConfig {
    fn validate(&self) -> Result<(), WebhookConfigError> {
        ProviderId::parse(self.provider.clone())
            .map_err(|_| WebhookConfigError::InvalidProvider)?;
        let headers = [
            &self.signature_header,
            &self.timestamp_header,
            &self.scope_header,
            &self.event_id_header,
        ];
        let parsed = headers
            .iter()
            .map(|header| {
                HeaderName::from_bytes(header.as_bytes())
                    .map_err(|_| WebhookConfigError::InvalidHeaderName)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let distinct = parsed.iter().collect::<HashSet<_>>();
        if distinct.len() != parsed.len() {
            return Err(WebhookConfigError::DuplicateHeaderName);
        }
        if self.secrets.is_empty() || self.secrets.len() > MAX_ROTATED_KEYS {
            return Err(WebhookConfigError::InvalidSecretCount);
        }
        if self.secrets.iter().any(|secret| {
            !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.expose_secret().len())
        }) {
            return Err(WebhookConfigError::InvalidSecret);
        }
        if self.replay_window < Duration::from_secs(1) || self.replay_window > MAX_REPLAY_WINDOW {
            return Err(WebhookConfigError::InvalidReplayWindow);
        }
        if self.future_tolerance > MAX_FUTURE_TOLERANCE {
            return Err(WebhookConfigError::InvalidFutureTolerance);
        }
        Ok(())
    }

    fn build(&self) -> Result<Arc<dyn ProviderAdapter>, WebhookConfigError> {
        self.validate()?;
        let provider = ProviderId::parse(self.provider.clone())
            .map_err(|_| WebhookConfigError::InvalidProvider)?;
        let header = |value: &str| {
            HeaderName::from_bytes(value.as_bytes())
                .map_err(|_| WebhookConfigError::InvalidHeaderName)
        };
        let secrets = self.secrets.clone();
        Ok(Arc::new(FixtureHmacSha256Adapter::new(
            provider,
            FixtureVerificationPolicy::new(
                header(&self.signature_header)?,
                header(&self.timestamp_header)?,
                self.replay_window,
                self.future_tolerance,
            ),
            header(&self.scope_header)?,
            header(&self.event_id_header)?,
            secrets,
        )))
    }
}

/// Stable, value-free inbound webhook configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WebhookConfigError {
    /// Enabled configuration has no provider adapter.
    #[error("enabled inbound webhooks require a provider")]
    MissingProvider,
    /// The configured provider count exceeds the fixed registry bound.
    #[error("inbound webhook provider count is invalid")]
    InvalidProviderCount,
    /// A provider route identifier is invalid.
    #[error("inbound webhook provider identifier is invalid")]
    InvalidProvider,
    /// A provider route is configured more than once.
    #[error("inbound webhook provider is duplicated")]
    DuplicateProvider,
    /// The exact raw-body limit is invalid.
    #[error("inbound webhook body limit is invalid")]
    InvalidBodyLimit,
    /// A header count or aggregate byte limit is invalid.
    #[error("inbound webhook header limit is invalid")]
    InvalidHeaderLimit,
    /// A persisted safe payload limit is invalid.
    #[error("inbound webhook payload limit is invalid")]
    InvalidPayloadLimit,
    /// Durable identity retention cannot cover an inclusive timestamp acceptance lifetime.
    #[error("inbound webhook retention is shorter than provider acceptance policy")]
    RetentionShorterThanAcceptance,
    /// Receipt retention is outside the fixed bound.
    #[error("inbound webhook retention is invalid")]
    InvalidRetention,
    /// A provider header name is invalid.
    #[error("inbound webhook header name is invalid")]
    InvalidHeaderName,
    /// Two provider semantics are assigned to the same header.
    #[error("inbound webhook header name is duplicated")]
    DuplicateHeaderName,
    /// The rotation key count is invalid.
    #[error("inbound webhook signing key count is invalid")]
    InvalidSecretCount,
    /// A signing key is missing, weak, or oversized.
    #[error("inbound webhook signing key is invalid")]
    InvalidSecret,
    /// A replay window is outside the fixed bound.
    #[error("inbound webhook replay window is invalid")]
    InvalidReplayWindow,
    /// A future timestamp tolerance is outside the fixed bound.
    #[error("inbound webhook future tolerance is invalid")]
    InvalidFutureTolerance,
    /// A processor batch size is invalid.
    #[error("inbound webhook processor batch size is invalid")]
    InvalidBatchSize,
    /// A processor attempt bound is invalid.
    #[error("inbound webhook processor attempt limit is invalid")]
    InvalidAttempts,
    /// A processor lease duration is invalid.
    #[error("inbound webhook processor lease is invalid")]
    InvalidLease,
    /// Handler timeout does not fit strictly inside the lease.
    #[error("inbound webhook handler timeout is invalid")]
    InvalidHandlerTimeout,
    /// Polling interval is invalid.
    #[error("inbound webhook polling interval is invalid")]
    InvalidPollInterval,
    /// Retry delays are invalid.
    #[error("inbound webhook retry delay is invalid")]
    InvalidRetryDelay,
    /// Processor shutdown timeout is invalid.
    #[error("inbound webhook shutdown timeout is invalid")]
    InvalidShutdownTimeout,
}

impl From<RegistryError> for WebhookConfigError {
    fn from(value: RegistryError) -> Self {
        match value {
            RegistryError::DuplicateProvider => Self::DuplicateProvider,
            RegistryError::TooManyProviders => Self::InvalidProviderCount,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> WebhookConfig {
        WebhookConfig {
            enabled: true,
            fixture_hmac_providers: vec![FixtureHmacProviderConfig {
                provider: "fixture".to_owned(),
                signature_header: "x-fixture-signature".to_owned(),
                timestamp_header: "x-fixture-timestamp".to_owned(),
                scope_header: "x-fixture-scope".to_owned(),
                event_id_header: "x-fixture-event-id".to_owned(),
                secrets: vec![SecretString::from("s".repeat(MIN_SECRET_BYTES))],
                replay_window: Duration::from_mins(5),
                future_tolerance: Duration::from_secs(30),
            }],
            ..WebhookConfig::default()
        }
    }

    #[test]
    fn strict_configuration_redacts_rotated_secrets() -> Result<(), Box<dyn std::error::Error>> {
        let source = r#"
enabled = true
max_body_bytes = 4096
max_header_count = 32
max_header_bytes = 4096
max_safe_payload_bytes = 2048
retention = "30d"

[processing]
batch_size = 16
max_attempts = 5
lease_duration = "60s"
handler_timeout = "30s"
poll_interval = "1s"
retry_base_delay = "2s"
retry_max_delay = "2m"
cleanup_batch_size = 50
shutdown_timeout = "10s"

[[fixture_hmac_providers]]
provider = "fixture"
signature_header = "x-fixture-signature"
timestamp_header = "x-fixture-timestamp"
scope_header = "x-fixture-scope"
event_id_header = "x-fixture-event-id"
secrets = ["secret-material-that-is-at-least-thirty-two-bytes"]
replay_window = "5m"
future_tolerance = "30s"
"#;
        let parsed: WebhookConfig = toml::from_str(source)?;
        parsed.validate()?;
        assert!(!format!("{parsed:?}").contains("secret-material"));
        assert!(toml::from_str::<WebhookConfig>(&format!("{source}\nlegacy = true\n")).is_err());
        Ok(())
    }

    #[test]
    fn enabled_configuration_enforces_unique_providers_headers_and_secrets() {
        let mut config = enabled_config();
        assert_eq!(config.validate(), Ok(()));
        config.fixture_hmac_providers[0].event_id_header =
            config.fixture_hmac_providers[0].scope_header.clone();
        assert_eq!(
            config.validate(),
            Err(WebhookConfigError::DuplicateHeaderName)
        );

        config = enabled_config();
        config.fixture_hmac_providers[0].secrets[0] = SecretString::from("weak".to_owned());
        assert_eq!(config.validate(), Err(WebhookConfigError::InvalidSecret));
    }

    #[test]
    fn retention_covers_the_full_timestamp_acceptance_lifetime_inclusively()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = enabled_config();
        let replay = Duration::from_hours(2);
        let future = Duration::from_secs(30);
        let minimum = replay + future + Duration::from_secs(1);
        config.fixture_hmac_providers[0].replay_window = replay;
        config.fixture_hmac_providers[0].future_tolerance = future;
        config.retention = minimum;
        assert_eq!(config.validate(), Ok(()));

        config.retention = minimum
            .checked_sub(Duration::from_secs(1))
            .ok_or("minimum retention must exceed one second")?;
        assert_eq!(
            config.validate(),
            Err(WebhookConfigError::RetentionShorterThanAcceptance)
        );
        Ok(())
    }
}
