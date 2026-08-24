use std::{collections::HashSet, fmt, time::Duration};

use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rsk_outbound_http::Url;
use serde::Deserialize;
use thiserror::Error;

const MAX_PROVIDERS: usize = 16;
const MAX_PROVIDER_ID_BYTES: usize = 64;
const MAX_ISSUER_BYTES: usize = 2_048;
const MAX_CLIENT_ID_BYTES: usize = 512;
const MAX_CLIENT_SECRET_BYTES: usize = 4_096;
const MAX_REDIRECT_URI_BYTES: usize = 2_048;
const MAX_SCOPES: usize = 32;
const MAX_SCOPE_BYTES: usize = 256;
const MIN_PENDING_FLOW_TTL: Duration = Duration::from_secs(60);
const MAX_PENDING_FLOW_TTL: Duration = Duration::from_mins(15);
const MIN_LINK_PROOF_MAX_AGE: Duration = Duration::from_secs(30);
const MAX_LINK_PROOF_MAX_AGE: Duration = Duration::from_hours(1);
const MIN_RESPONSE_BODY_BYTES: usize = 1_024;
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const REDACTED: &str = "[REDACTED]";

/// One explicitly trusted `OpenID` Connect provider.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcProviderConfig {
    /// Stable, low-cardinality identifier used to select this provider.
    pub provider_id: String,
    /// Exact issuer URL expected from discovery and verified ID tokens.
    pub issuer: String,
    /// OAuth 2.0 client identifier registered with the provider.
    pub client_id: String,
    /// OAuth 2.0 client secret, retained in redacted and zeroizing storage.
    pub client_secret: SecretString,
    /// The one exact redirect URI registered for this client.
    pub redirect_uri: String,
    /// Unique authorization scopes; `openid` is required.
    pub scopes: Vec<String>,
}

impl fmt::Debug for OidcProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcProviderConfig")
            .field("provider_id", &self.provider_id)
            .field("issuer", &self.issuer)
            .field("client_id", &self.client_id)
            .field("client_secret", &REDACTED)
            .field("redirect_uri", &self.redirect_uri)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Strict resource and trust policy for OIDC authorization-code flows.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcConfig {
    /// Whether OIDC authentication is enabled.
    pub enabled: bool,
    /// Explicitly trusted providers available when OIDC is enabled.
    pub providers: Vec<OidcProviderConfig>,
    /// Maximum lifetime of a pending authorization flow.
    #[serde(with = "humantime_serde")]
    pub pending_flow_ttl: Duration,
    /// Maximum age of the authenticated principal allowed to initiate account linking.
    #[serde(with = "humantime_serde")]
    pub link_proof_max_age: Duration,
    /// Maximum discovery, JWKS, or token response body accepted from a provider.
    pub response_body_limit_bytes: usize,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            providers: Vec::new(),
            pending_flow_ttl: Duration::from_mins(5),
            link_proof_max_age: Duration::from_mins(5),
            response_body_limit_bytes: 256 * 1024,
        }
    }
}

impl OidcConfig {
    /// Validates provider trust anchors, redirect URIs, scopes, and fixed resource bounds.
    ///
    /// Disabled configuration accepts an empty provider list but still validates global bounds.
    ///
    /// # Errors
    ///
    /// Returns a stable value-free classification for malformed, duplicate, insecure, or
    /// unbounded configuration.
    pub fn validate_for(&self, deployment: DeploymentEnvironment) -> Result<(), OidcConfigError> {
        if !(MIN_PENDING_FLOW_TTL..=MAX_PENDING_FLOW_TTL).contains(&self.pending_flow_ttl) {
            return Err(OidcConfigError::InvalidPendingFlowTtl);
        }
        if !(MIN_RESPONSE_BODY_BYTES..=MAX_RESPONSE_BODY_BYTES)
            .contains(&self.response_body_limit_bytes)
        {
            return Err(OidcConfigError::InvalidResponseBodyLimit);
        }
        if !(MIN_LINK_PROOF_MAX_AGE..=MAX_LINK_PROOF_MAX_AGE).contains(&self.link_proof_max_age) {
            return Err(OidcConfigError::InvalidLinkProofMaxAge);
        }
        if !self.enabled {
            if self.providers.len() > MAX_PROVIDERS {
                return Err(OidcConfigError::InvalidProviders);
            }
            return Ok(());
        }
        if self.providers.is_empty() || self.providers.len() > MAX_PROVIDERS {
            return Err(OidcConfigError::InvalidProviders);
        }

        let mut provider_ids = HashSet::with_capacity(self.providers.len());
        let mut issuers = HashSet::with_capacity(self.providers.len());
        for provider in &self.providers {
            if !valid_provider_id(&provider.provider_id)
                || !provider_ids.insert(provider.provider_id.as_str())
            {
                return Err(OidcConfigError::InvalidProviderId);
            }
            if !valid_issuer(&provider.issuer, deployment)
                || !issuers.insert(provider.issuer.as_str())
            {
                return Err(OidcConfigError::InvalidIssuer);
            }
            if !valid_bounded_text(&provider.client_id, MAX_CLIENT_ID_BYTES) {
                return Err(OidcConfigError::InvalidClientId);
            }
            let secret = provider.client_secret.expose_secret();
            if secret.is_empty() || secret.len() > MAX_CLIENT_SECRET_BYTES {
                return Err(OidcConfigError::InvalidClientSecret);
            }
            if !valid_redirect_uri(&provider.redirect_uri, deployment) {
                return Err(OidcConfigError::InvalidRedirectUri);
            }
            if !valid_scopes(&provider.scopes) {
                return Err(OidcConfigError::InvalidScopes);
            }
        }
        Ok(())
    }
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_issuer(value: &str, deployment: DeploymentEnvironment) -> bool {
    if !valid_bounded_text(value, MAX_ISSUER_BYTES) {
        return false;
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    valid_http_url(&url, deployment) && url.query().is_none()
}

fn valid_redirect_uri(value: &str, deployment: DeploymentEnvironment) -> bool {
    if !valid_bounded_text(value, MAX_REDIRECT_URI_BYTES) {
        return false;
    }
    Url::parse(value).is_ok_and(|url| valid_http_url(&url, deployment))
}

fn valid_http_url(url: &Url, deployment: DeploymentEnvironment) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && (url.scheme() == "https" || deployment != DeploymentEnvironment::Production)
}

fn valid_scopes(scopes: &[String]) -> bool {
    if scopes.is_empty() || scopes.len() > MAX_SCOPES {
        return false;
    }
    let mut unique = HashSet::with_capacity(scopes.len());
    scopes.iter().all(|scope| {
        !scope.is_empty()
            && scope.len() <= MAX_SCOPE_BYTES
            && scope.bytes().all(|byte| {
                byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte)
            })
            && unique.insert(scope.as_str())
    }) && unique.contains("openid")
}

/// Stable, value-free OIDC configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OidcConfigError {
    /// The enabled provider list is empty or exceeds its fixed bound.
    #[error("OIDC provider configuration is invalid")]
    InvalidProviders,
    /// A provider identifier is malformed or duplicated.
    #[error("OIDC provider identifier is invalid")]
    InvalidProviderId,
    /// An issuer is malformed, duplicated, credentialed, fragmented, or insecure.
    #[error("OIDC issuer configuration is invalid")]
    InvalidIssuer,
    /// A client identifier is empty, oversized, or contains control characters.
    #[error("OIDC client identifier is invalid")]
    InvalidClientId,
    /// A client secret is empty or oversized.
    #[error("OIDC client secret is invalid")]
    InvalidClientSecret,
    /// A redirect URI is malformed, credentialed, fragmented, or insecure.
    #[error("OIDC redirect URI is invalid")]
    InvalidRedirectUri,
    /// Provider scopes are empty, duplicated, malformed, oversized, or omit `openid`.
    #[error("OIDC scope configuration is invalid")]
    InvalidScopes,
    /// The pending-flow lifetime is outside its fixed bound.
    #[error("OIDC pending-flow lifetime is invalid")]
    InvalidPendingFlowTtl,
    /// The account-link proof age is outside its fixed bound.
    #[error("OIDC account-link proof age is invalid")]
    InvalidLinkProofMaxAge,
    /// The provider response-body limit is outside its fixed bound.
    #[error("OIDC response-body limit is invalid")]
    InvalidResponseBodyLimit,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> OidcProviderConfig {
        OidcProviderConfig {
            provider_id: "example".to_owned(),
            issuer: "https://issuer.example.test".to_owned(),
            client_id: "client".to_owned(),
            client_secret: SecretString::from("secret".to_owned()),
            redirect_uri: "https://service.example.test/auth/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
        }
    }

    fn enabled_config() -> OidcConfig {
        OidcConfig {
            enabled: true,
            providers: vec![provider()],
            ..OidcConfig::default()
        }
    }

    #[test]
    fn enabled_configuration_requires_unique_provider_ids_and_issuers() {
        let mut config = enabled_config();
        config.providers.push(provider());
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(OidcConfigError::InvalidProviderId)
        );

        config.providers[1].provider_id = "other".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(OidcConfigError::InvalidIssuer)
        );
    }

    #[test]
    fn production_rejects_insecure_or_credentialed_urls() {
        let mut config = enabled_config();
        config.providers[0].issuer = "http://issuer.example.test".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Err(OidcConfigError::InvalidIssuer)
        );
        assert_eq!(config.validate_for(DeploymentEnvironment::Test), Ok(()));

        config.providers[0].issuer = "https://user@issuer.example.test".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(OidcConfigError::InvalidIssuer)
        );
    }

    #[test]
    fn scopes_must_be_unique_bounded_and_include_openid() {
        let mut config = enabled_config();
        config.providers[0].scopes = vec!["profile".to_owned()];
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(OidcConfigError::InvalidScopes)
        );

        config.providers[0].scopes = vec!["openid".to_owned(), "openid".to_owned()];
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Test),
            Err(OidcConfigError::InvalidScopes)
        );
    }

    #[test]
    fn strict_serde_redacts_client_secret_debug_output() -> Result<(), serde_json::Error> {
        let config: OidcConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "providers": [{
                "provider_id": "example",
                "issuer": "https://issuer.example.test",
                "client_id": "client",
                "client_secret": "super-secret-value",
                "redirect_uri": "https://service.example.test/auth/callback",
                "scopes": ["openid"]
            }]
        }))?;
        assert!(!format!("{config:?}").contains("super-secret-value"));
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn toml_uses_human_readable_pending_flow_duration() -> Result<(), toml::de::Error> {
        let config: OidcConfig = toml::from_str(
            r#"
            enabled = true
            pending_flow_ttl = "5m"

            [[providers]]
            provider_id = "example"
            issuer = "https://issuer.example.test"
            client_id = "client"
            client_secret = "secret"
            redirect_uri = "https://service.example.test/auth/callback"
            scopes = ["openid"]
            "#,
        )?;
        assert_eq!(config.pending_flow_ttl, Duration::from_secs(300));
        Ok(())
    }
}
