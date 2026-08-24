use std::{collections::HashSet, fmt, time::Duration};

use rsk_config::DeploymentEnvironment;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use webauthn_rs::prelude::WebauthnBuilder;

const MAX_RP_ID_BYTES: usize = 253;
const MAX_RP_NAME_BYTES: usize = 255;
const MAX_ORIGINS: usize = 8;
const MIN_CEREMONY_TTL: Duration = Duration::from_secs(30);
const MAX_CEREMONY_TTL: Duration = Duration::from_mins(10);
const MIN_RECENT_AUTH_AGE: Duration = Duration::from_secs(30);
const MAX_RECENT_AUTH_AGE: Duration = Duration::from_hours(24);
const MAX_CREDENTIALS_PER_USER: usize = 32;
const MAX_PENDING_CEREMONIES: usize = 100_000;
const MAX_PENDING_CEREMONIES_PER_USER: usize = 32;

/// Strict relying-party and lifecycle policy for the optional passkey capability.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct WebAuthnConfig {
    /// Whether passkey registration and authentication are enabled.
    pub enabled: bool,
    /// Stable `WebAuthn` relying-party identifier.
    pub rp_id: String,
    /// Human-readable relying-party name presented by authenticators.
    pub rp_name: String,
    /// Exact browser origins accepted by the relying party.
    pub origins: Vec<String>,
    /// Lifetime of server-side registration and authentication state.
    #[serde(with = "humantime_serde")]
    pub ceremony_ttl: Duration,
    /// Maximum age of authentication accepted for credential lifecycle changes.
    #[serde(with = "humantime_serde")]
    pub recent_auth_age: Duration,
    /// Maximum number of credentials retained for one user, including disabled credentials.
    pub max_credentials_per_user: usize,
    /// Hard global bound for unexpired server-side ceremony rows.
    pub max_pending_ceremonies: usize,
    /// Hard anonymous partition for unexpired discoverable-authentication ceremony rows.
    pub max_pending_discoverable_ceremonies: usize,
    /// Hard per-user bound for unexpired account-bound ceremony rows.
    pub max_pending_ceremonies_per_user: usize,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: String::new(),
            rp_name: String::new(),
            origins: Vec::new(),
            ceremony_ttl: Duration::from_mins(5),
            recent_auth_age: Duration::from_mins(15),
            max_credentials_per_user: 10,
            max_pending_ceremonies: 10_000,
            max_pending_discoverable_ceremonies: 2_500,
            max_pending_ceremonies_per_user: 5,
        }
    }
}

impl fmt::Debug for WebAuthnConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebAuthnConfig")
            .field("enabled", &self.enabled)
            .field("rp_id", &"[REDACTED]")
            .field("rp_name", &"[REDACTED]")
            .field("origins", &"[REDACTED]")
            .field("origin_count", &self.origins.len())
            .field("ceremony_ttl", &self.ceremony_ttl)
            .field("recent_auth_age", &self.recent_auth_age)
            .field("max_credentials_per_user", &self.max_credentials_per_user)
            .field("max_pending_ceremonies", &self.max_pending_ceremonies)
            .field(
                "max_pending_discoverable_ceremonies",
                &self.max_pending_discoverable_ceremonies,
            )
            .field(
                "max_pending_ceremonies_per_user",
                &self.max_pending_ceremonies_per_user,
            )
            .finish()
    }
}

impl WebAuthnConfig {
    /// Validates exact-origin trust and bounded ceremony/lifecycle resources.
    ///
    /// Disabled configuration is intentionally inert. Enabled configuration requires a complete
    /// relying party. Production accepts HTTPS origins only; development and test additionally
    /// accept exact `http://localhost` origins.
    ///
    /// # Errors
    ///
    /// Returns a stable, value-free error when trust anchors or bounds are invalid.
    pub fn validate_for(
        &self,
        deployment: DeploymentEnvironment,
    ) -> Result<(), WebAuthnConfigError> {
        if !self.enabled {
            return Ok(());
        }
        self.parsed_origins(deployment).map(|_| ())
    }

    pub(crate) fn parsed_origins(
        &self,
        deployment: DeploymentEnvironment,
    ) -> Result<Vec<Url>, WebAuthnConfigError> {
        if !valid_text(&self.rp_id, MAX_RP_ID_BYTES)
            || self.rp_id.trim() != self.rp_id
            || self.rp_id.contains('/')
        {
            return Err(WebAuthnConfigError::InvalidRpId);
        }
        if !valid_text(&self.rp_name, MAX_RP_NAME_BYTES) || self.rp_name.trim() != self.rp_name {
            return Err(WebAuthnConfigError::InvalidRpName);
        }
        if self.origins.is_empty() || self.origins.len() > MAX_ORIGINS {
            return Err(WebAuthnConfigError::InvalidOrigins);
        }
        if !(MIN_CEREMONY_TTL..=MAX_CEREMONY_TTL).contains(&self.ceremony_ttl) {
            return Err(WebAuthnConfigError::InvalidCeremonyTtl);
        }
        if !(MIN_RECENT_AUTH_AGE..=MAX_RECENT_AUTH_AGE).contains(&self.recent_auth_age) {
            return Err(WebAuthnConfigError::InvalidRecentAuthAge);
        }
        if !(1..=MAX_CREDENTIALS_PER_USER).contains(&self.max_credentials_per_user) {
            return Err(WebAuthnConfigError::InvalidCredentialLimit);
        }
        let authenticated_capacity = self
            .max_pending_ceremonies
            .checked_sub(self.max_pending_discoverable_ceremonies);
        if !(2..=MAX_PENDING_CEREMONIES).contains(&self.max_pending_ceremonies)
            || !(1..=MAX_PENDING_CEREMONIES_PER_USER)
                .contains(&self.max_pending_ceremonies_per_user)
            || authenticated_capacity.is_none_or(|capacity| {
                capacity == 0 || self.max_pending_ceremonies_per_user > capacity
            })
        {
            return Err(WebAuthnConfigError::InvalidCeremonyCapacity);
        }

        let mut parsed = Vec::with_capacity(self.origins.len());
        let mut unique = HashSet::with_capacity(self.origins.len());
        for configured in &self.origins {
            if configured.len() > 2_048 || !unique.insert(configured.as_str()) {
                return Err(WebAuthnConfigError::InvalidOrigins);
            }
            let origin = Url::parse(configured).map_err(|_| WebAuthnConfigError::InvalidOrigins)?;
            if !valid_exact_origin(&origin, deployment)
                || WebauthnBuilder::new(&self.rp_id, &origin).is_err()
                || parsed.iter().any(|existing| existing == &origin)
            {
                return Err(WebAuthnConfigError::InvalidOrigins);
            }
            parsed.push(origin);
        }
        Ok(parsed)
    }
}

fn valid_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_exact_origin(origin: &Url, deployment: DeploymentEnvironment) -> bool {
    if origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return false;
    }
    match origin.scheme() {
        "https" => true,
        "http" => {
            deployment != DeploymentEnvironment::Production
                && origin.host_str() == Some("localhost")
        }
        _ => false,
    }
}

/// Stable passkey configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum WebAuthnConfigError {
    /// Relying-party ID is empty, malformed, or unbounded.
    #[error("WebAuthn relying-party ID is invalid")]
    InvalidRpId,
    /// Relying-party display name is empty or unbounded.
    #[error("WebAuthn relying-party name is invalid")]
    InvalidRpName,
    /// Origin trust anchors are empty, duplicated, insecure, or incompatible with the RP ID.
    #[error("WebAuthn origin configuration is invalid")]
    InvalidOrigins,
    /// Ceremony state lifetime is outside supported bounds.
    #[error("WebAuthn ceremony lifetime is invalid")]
    InvalidCeremonyTtl,
    /// Recent-authentication lifetime is outside supported bounds.
    #[error("WebAuthn recent-authentication age is invalid")]
    InvalidRecentAuthAge,
    /// Per-user credential limit is outside supported bounds.
    #[error("WebAuthn credential limit is invalid")]
    InvalidCredentialLimit,
    /// Global, anonymous-partition, or per-user ceremony capacity is outside supported bounds.
    #[error("WebAuthn ceremony capacity is invalid")]
    InvalidCeremonyCapacity,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> WebAuthnConfig {
        WebAuthnConfig {
            enabled: true,
            rp_id: "example.test".to_owned(),
            rp_name: "Example".to_owned(),
            origins: vec![
                "https://login.example.test".to_owned(),
                "https://admin.example.test:8443".to_owned(),
            ],
            ..WebAuthnConfig::default()
        }
    }

    #[test]
    fn enabled_configuration_requires_exact_bounded_trust_anchors() {
        let config = enabled_config();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Ok(())
        );

        let mut arbitrary_path = config.clone();
        arbitrary_path.origins[0] = "https://login.example.test/passkeys".to_owned();
        assert_eq!(
            arbitrary_path.validate_for(DeploymentEnvironment::Production),
            Err(WebAuthnConfigError::InvalidOrigins)
        );

        let mut mismatched_rp = config;
        mismatched_rp.rp_id = "other.test".to_owned();
        assert_eq!(
            mismatched_rp.validate_for(DeploymentEnvironment::Production),
            Err(WebAuthnConfigError::InvalidOrigins)
        );
    }

    #[test]
    fn insecure_origin_is_limited_to_exact_localhost_outside_production() {
        let mut config = enabled_config();
        config.rp_id = "localhost".to_owned();
        config.origins = vec!["http://localhost:3000".to_owned()];
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Development),
            Ok(())
        );
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(WebAuthnConfigError::InvalidOrigins)
        );

        config.origins = vec!["http://app.example.test".to_owned()];
        config.rp_id = "example.test".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(WebAuthnConfigError::InvalidOrigins)
        );
    }

    #[test]
    fn debug_output_redacts_relying_party_values() {
        let rendered = format!("{:?}", enabled_config());
        assert!(!rendered.contains("example.test"));
        assert!(!rendered.contains("Example"));
        assert!(rendered.contains("[REDACTED]"));
    }

    #[test]
    fn serde_rejects_unknown_fields_and_hostile_bounds() {
        let unknown = r#"
            enabled = true
            rp_id = "example.test"
            rp_name = "Example"
            origins = ["https://example.test"]
            ceremony_ttl = "5m"
            recent_auth_age = "15m"
            max_credentials_per_user = 10
            allow_any_port = true
        "#;
        assert!(toml::from_str::<WebAuthnConfig>(unknown).is_err());

        let mut config = enabled_config();
        config.max_credentials_per_user = MAX_CREDENTIALS_PER_USER + 1;
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(WebAuthnConfigError::InvalidCredentialLimit)
        );
    }
}
