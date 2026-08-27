use std::{collections::HashSet, time::Duration};

use jsonwebtoken::Algorithm;
use omnius_config::DeploymentEnvironment;
use omnius_outbound_http::Url;
use serde::Deserialize;
use thiserror::Error;

const MAX_ISSUERS: usize = 8;
const MAX_AUDIENCES: usize = 16;
const MAX_TOKEN_TYPES: usize = 4;
const MAX_IDENTIFIER_BYTES: usize = 2_048;

/// Asymmetric JWT signature algorithms accepted by the verifier.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq)]
pub enum JwtAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    #[default]
    RS256,
    /// RSASSA-PSS with SHA-256.
    PS256,
    /// ECDSA P-256 with SHA-256.
    ES256,
    /// Edwards-curve `EdDSA`.
    EdDSA,
}

impl From<JwtAlgorithm> for Algorithm {
    fn from(value: JwtAlgorithm) -> Self {
        match value {
            JwtAlgorithm::RS256 => Self::RS256,
            JwtAlgorithm::PS256 => Self::PS256,
            JwtAlgorithm::ES256 => Self::ES256,
            JwtAlgorithm::EdDSA => Self::EdDSA,
        }
    }
}

/// One trusted token issuer and its explicit no-redirect JWKS endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct JwtIssuerConfig {
    /// Exact value accepted in the `iss` claim.
    pub issuer: String,
    /// Explicit endpoint used to fetch this issuer's public verification keys.
    pub jwks_url: String,
}

/// Bounded resource-server JWT and JWKS policy.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct JwtConfig {
    /// Whether bearer verification is enabled.
    pub enabled: bool,
    /// Trusted issuers and their key endpoints.
    pub issuers: Vec<JwtIssuerConfig>,
    /// Accepted audience values.
    pub audiences: Vec<String>,
    /// Explicit asymmetric algorithm allowlist.
    pub algorithms: Vec<JwtAlgorithm>,
    /// Accepted access-token `typ` header values.
    pub token_types: Vec<String>,
    /// Clock skew applied to `exp` and `nbf` checks.
    #[serde(with = "humantime_serde")]
    pub clock_skew: Duration,
    /// Fresh lifetime of a successfully validated JWKS cache entry.
    #[serde(with = "humantime_serde")]
    pub cache_ttl: Duration,
    /// Minimum interval between forced unknown-`kid` refresh attempts.
    #[serde(with = "humantime_serde")]
    pub min_refresh_interval: Duration,
    /// Maximum accepted lifetime from `iat` through `exp`.
    #[serde(with = "humantime_serde")]
    pub max_token_lifetime: Duration,
    /// Maximum encoded bearer-token size.
    pub max_token_bytes: usize,
    /// Maximum decoded JWKS response size.
    pub max_jwks_bytes: usize,
    /// Maximum number of keys accepted from one issuer.
    pub max_keys_per_issuer: usize,
    /// Maximum `kid` size.
    pub max_kid_bytes: usize,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuers: Vec::new(),
            audiences: Vec::new(),
            algorithms: vec![JwtAlgorithm::RS256],
            token_types: vec!["at+jwt".to_owned()],
            clock_skew: Duration::from_secs(30),
            cache_ttl: Duration::from_mins(15),
            min_refresh_interval: Duration::from_secs(30),
            max_token_lifetime: Duration::from_hours(1),
            max_token_bytes: 16 * 1_024,
            max_jwks_bytes: 256 * 1_024,
            max_keys_per_issuer: 64,
            max_kid_bytes: 128,
        }
    }
}

impl JwtConfig {
    /// Validates all trust and resource bounds for one deployment.
    ///
    /// # Errors
    ///
    /// Returns a value-free configuration error when a bound or trust anchor is invalid.
    pub fn validate_for(&self, deployment: DeploymentEnvironment) -> Result<(), JwtConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.issuers.is_empty() || self.issuers.len() > MAX_ISSUERS {
            return Err(JwtConfigError::InvalidIssuers);
        }
        if self.audiences.is_empty() || self.audiences.len() > MAX_AUDIENCES {
            return Err(JwtConfigError::InvalidAudiences);
        }
        if self.algorithms.is_empty() {
            return Err(JwtConfigError::InvalidAlgorithms);
        }
        if self.token_types.is_empty() || self.token_types.len() > MAX_TOKEN_TYPES {
            return Err(JwtConfigError::InvalidTokenTypes);
        }
        if self.clock_skew > Duration::from_mins(5) {
            return Err(JwtConfigError::InvalidClockSkew);
        }
        if self.cache_ttl < Duration::from_secs(30) || self.cache_ttl > Duration::from_hours(24) {
            return Err(JwtConfigError::InvalidCacheTtl);
        }
        if self.min_refresh_interval < Duration::from_secs(1)
            || self.min_refresh_interval > self.cache_ttl
        {
            return Err(JwtConfigError::InvalidRefreshInterval);
        }
        if self.max_token_lifetime < Duration::from_secs(60)
            || self.max_token_lifetime > Duration::from_hours(24)
        {
            return Err(JwtConfigError::InvalidTokenLifetime);
        }
        if !(512..=32 * 1_024).contains(&self.max_token_bytes)
            || !(1_024..=1_024 * 1_024).contains(&self.max_jwks_bytes)
            || !(1..=128).contains(&self.max_keys_per_issuer)
            || !(1..=256).contains(&self.max_kid_bytes)
        {
            return Err(JwtConfigError::InvalidResourceBounds);
        }

        let mut issuers = HashSet::with_capacity(self.issuers.len());
        let mut endpoints = HashSet::with_capacity(self.issuers.len());
        for issuer in &self.issuers {
            if !valid_identifier(&issuer.issuer) || !issuers.insert(issuer.issuer.as_str()) {
                return Err(JwtConfigError::InvalidIssuers);
            }
            let endpoint =
                Url::parse(&issuer.jwks_url).map_err(|_| JwtConfigError::InvalidJwksEndpoint)?;
            if endpoint.fragment().is_some()
                || endpoint.username() != ""
                || endpoint.password().is_some()
                || endpoint.scheme() != "https" && deployment == DeploymentEnvironment::Production
                || !matches!(endpoint.scheme(), "http" | "https")
                || !endpoints.insert(issuer.jwks_url.as_str())
            {
                return Err(JwtConfigError::InvalidJwksEndpoint);
            }
        }
        if !all_unique_valid(&self.audiences) {
            return Err(JwtConfigError::InvalidAudiences);
        }
        if !all_unique_valid(&self.token_types) {
            return Err(JwtConfigError::InvalidTokenTypes);
        }
        let algorithm_count = self
            .algorithms
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .len();
        if algorithm_count != self.algorithms.len() {
            return Err(JwtConfigError::InvalidAlgorithms);
        }
        Ok(())
    }
}

fn all_unique_valid(values: &[String]) -> bool {
    let mut unique = HashSet::with_capacity(values.len());
    values
        .iter()
        .all(|value| valid_identifier(value) && unique.insert(value.as_str()))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES && !value.chars().any(char::is_control)
}

/// Stable JWT configuration failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JwtConfigError {
    /// Trusted issuer configuration is empty, duplicated, or malformed.
    #[error("JWT issuer configuration is invalid")]
    InvalidIssuers,
    /// Audience configuration is empty, duplicated, or malformed.
    #[error("JWT audience configuration is invalid")]
    InvalidAudiences,
    /// Algorithm allowlist is empty or duplicated.
    #[error("JWT algorithm configuration is invalid")]
    InvalidAlgorithms,
    /// Access-token type allowlist is empty, duplicated, or malformed.
    #[error("JWT token-type configuration is invalid")]
    InvalidTokenTypes,
    /// Clock skew exceeds the supported bound.
    #[error("JWT clock-skew configuration is invalid")]
    InvalidClockSkew,
    /// JWKS cache lifetime is outside supported bounds.
    #[error("JWT cache lifetime is invalid")]
    InvalidCacheTtl,
    /// Unknown-key refresh interval is outside supported bounds.
    #[error("JWT refresh interval is invalid")]
    InvalidRefreshInterval,
    /// Maximum access-token lifetime is outside supported bounds.
    #[error("JWT token lifetime is invalid")]
    InvalidTokenLifetime,
    /// Token, key-set, key-count, or key-ID bounds are invalid.
    #[error("JWT resource bounds are invalid")]
    InvalidResourceBounds,
    /// A JWKS endpoint is malformed, duplicated, credentialed, or insecure.
    #[error("JWT JWKS endpoint is invalid")]
    InvalidJwksEndpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_config() -> JwtConfig {
        JwtConfig {
            enabled: true,
            issuers: vec![JwtIssuerConfig {
                issuer: "https://issuer.example.test".to_owned(),
                jwks_url: "https://issuer.example.test/jwks".to_owned(),
            }],
            audiences: vec!["omnius-api".to_owned()],
            ..JwtConfig::default()
        }
    }

    #[test]
    fn validation_requires_explicit_trust_and_production_https() {
        let config = enabled_config();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production),
            Ok(())
        );

        let mut insecure = config.clone();
        insecure.issuers[0].jwks_url = "http://issuer.example.test/jwks".to_owned();
        assert_eq!(
            insecure.validate_for(DeploymentEnvironment::Production),
            Err(JwtConfigError::InvalidJwksEndpoint)
        );
        assert_eq!(insecure.validate_for(DeploymentEnvironment::Test), Ok(()));

        let mut empty_audiences = config;
        empty_audiences.audiences.clear();
        assert_eq!(
            empty_audiences.validate_for(DeploymentEnvironment::Test),
            Err(JwtConfigError::InvalidAudiences)
        );
    }

    #[test]
    fn strict_serde_preserves_bounded_defaults() -> Result<(), serde_json::Error> {
        let config: JwtConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "issuers": [{
                "issuer": "https://issuer.example.test",
                "jwks_url": "https://issuer.example.test/jwks"
            }],
            "audiences": ["omnius-api"]
        }))?;
        assert_eq!(config.algorithms, [JwtAlgorithm::RS256]);
        assert_eq!(config.token_types, ["at+jwt"]);
        assert_eq!(config.max_token_lifetime, Duration::from_hours(1));
        Ok(())
    }
}
