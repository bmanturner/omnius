//! Strict authorization-server configuration and construction.

use std::{collections::HashSet, fmt, sync::Arc, time::Duration};

use omnius_auth_core::{AssuranceLevel, Scope};
use omnius_config::{DeploymentEnvironment, SecretString};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::{
    crypto::{RsaPublicJwk, SigningKeyRing, TokenPepper},
    error::AuthorizationServerConfigError,
    types::{IssuerUri, ResourceUri},
};

const MAX_RESOURCES: usize = 16;
const MAX_TOTAL_SCOPES: usize = 128;
const MAX_SIGNING_KEYS: usize = 8;
const MAX_RESOURCE_NAME_BYTES: usize = 128;
const MAX_RESOURCE_DESCRIPTION_BYTES: usize = 1_024;
const MAX_SCOPE_DESCRIPTION_BYTES: usize = 512;
const MIN_AUTHORIZATION_REQUEST_TTL: Duration = Duration::from_secs(60);
const MAX_AUTHORIZATION_REQUEST_TTL: Duration = Duration::from_mins(15);
const MIN_AUTHORIZATION_CODE_TTL: Duration = Duration::from_secs(30);
const MAX_AUTHORIZATION_CODE_TTL: Duration = Duration::from_mins(10);
const MIN_ACCESS_TOKEN_TTL: Duration = Duration::from_mins(1);
const MAX_ACCESS_TOKEN_TTL: Duration = Duration::from_hours(1);
const MIN_ID_TOKEN_TTL: Duration = Duration::from_mins(1);
const MAX_ID_TOKEN_TTL: Duration = Duration::from_mins(15);
const MIN_REFRESH_TOKEN_TTL: Duration = Duration::from_hours(24);
const MAX_REFRESH_TOKEN_TTL: Duration = Duration::from_secs(86_400 * 90);
const MIN_CLIENT_METADATA_CACHE_TTL: Duration = Duration::from_mins(1);
const MAX_CLIENT_METADATA_CACHE_TTL: Duration = Duration::from_hours(24);
const MIN_AUTHORIZATION_REQUEST_BYTES: usize = 4 * 1_024;
const MAX_AUTHORIZATION_REQUEST_BYTES: usize = 64 * 1_024;
const MIN_CLIENT_METADATA_BYTES: usize = 4 * 1_024;
const MAX_CLIENT_METADATA_BYTES: usize = 256 * 1_024;
const REDACTED: &str = "[REDACTED]";
const RESERVED_SCOPES: [&str; 3] = ["openid", "email", "offline_access"];

/// Only signing algorithm supported by the provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum KeyAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
}

/// Configuration-deployment state of one signing key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KeyState {
    /// Sole key allowed to sign new tokens.
    Active,
    /// Public verification-only key retained through its last token expiry.
    Retiring,
}

/// One configured RS256 key and its rotation state.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningKeyConfig {
    /// Unique bounded key identifier.
    pub kid: String,
    /// Fixed algorithm; any value other than `RS256` fails deserialization.
    pub algorithm: KeyAlgorithm,
    /// Active or retiring deployment state.
    pub state: KeyState,
    /// Canonical public RSA verification JWK.
    pub public_jwk: RsaPublicJwk,
    /// Active-only private PKCS#8 PEM retained in redacted, zeroizing storage.
    #[serde(default)]
    pub private_key_pkcs8_pem: Option<SecretString>,
    /// Retiring-only publication deadline.
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub verification_until: Option<OffsetDateTime>,
}

impl fmt::Debug for SigningKeyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyConfig")
            .field("kid", &self.kid)
            .field("algorithm", &self.algorithm)
            .field("state", &self.state)
            .field("public_jwk", &self.public_jwk)
            .field(
                "private_key_pkcs8_pem",
                &self.private_key_pkcs8_pem.as_ref().map(|_| REDACTED),
            )
            .field("verification_until", &self.verification_until)
            .finish()
    }
}

/// One described resource scope.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceScopeConfig {
    /// Exact RFC 6749 scope token.
    pub name: Scope,
    /// Bounded human-readable consent description.
    pub description: String,
}

/// One exact audience and its consent display policy.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceConfig {
    /// Exact absolute resource URI used as the access-token audience.
    pub uri: String,
    /// Bounded human-readable resource name.
    pub name: String,
    /// Bounded human-readable resource description.
    pub description: String,
    /// Minimum authentication assurance required by this resource.
    pub minimum_assurance: AssuranceLevel,
    /// Unique described scopes owned by this resource.
    pub scopes: Vec<ResourceScopeConfig>,
}

/// Strict `[auth.authorization_server]` configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthorizationServerConfig {
    /// Whether the first-party issuer is enabled.
    pub enabled: bool,
    /// Root issuer URI. Production requires canonical HTTPS without a trailing slash.
    pub issuer: String,
    /// Canonical unpadded base64url 32-byte HMAC pepper, required when enabled.
    pub token_pepper: Option<TokenPepper>,
    /// Pending authorization transaction lifetime.
    #[serde(with = "humantime_serde")]
    pub authorization_request_ttl: Duration,
    /// Single-use authorization code lifetime.
    #[serde(with = "humantime_serde")]
    pub authorization_code_ttl: Duration,
    /// Resource access-token lifetime.
    #[serde(with = "humantime_serde")]
    pub access_token_ttl: Duration,
    /// OpenID Connect ID Token lifetime.
    #[serde(with = "humantime_serde")]
    pub id_token_ttl: Duration,
    /// Rotating refresh-token family lifetime.
    #[serde(with = "humantime_serde")]
    pub refresh_token_ttl: Duration,
    /// Validated Client ID Metadata Document cache lifetime.
    #[serde(with = "humantime_serde")]
    pub client_metadata_cache_ttl: Duration,
    /// Maximum accepted authorization request body/query bytes.
    pub max_authorization_request_bytes: usize,
    /// Maximum decoded client metadata document bytes.
    pub max_client_metadata_bytes: usize,
    /// Optional DCR compatibility switch; disabled by default.
    pub dynamic_client_registration: bool,
    /// Exact configured resource audiences.
    pub resources: Vec<ResourceConfig>,
    /// Active and retiring signing-key declarations.
    pub signing_keys: Vec<SigningKeyConfig>,
}

impl Default for AuthorizationServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            token_pepper: None,
            authorization_request_ttl: Duration::from_mins(10),
            authorization_code_ttl: Duration::from_mins(2),
            access_token_ttl: Duration::from_mins(10),
            id_token_ttl: Duration::from_mins(10),
            refresh_token_ttl: Duration::from_secs(86_400 * 30),
            client_metadata_cache_ttl: Duration::from_mins(15),
            max_authorization_request_bytes: 16 * 1_024,
            max_client_metadata_bytes: 64 * 1_024,
            dynamic_client_registration: false,
            resources: Vec::new(),
            signing_keys: Vec::new(),
        }
    }
}

/// Validated immutable resource declaration.
#[derive(Clone, Debug)]
pub struct ResourceDeclaration {
    uri: ResourceUri,
    name: String,
    description: String,
    minimum_assurance: AssuranceLevel,
    scopes: Vec<DescribedScope>,
}

impl ResourceDeclaration {
    /// Exact access-token audience URI.
    #[must_use]
    pub const fn uri(&self) -> &ResourceUri {
        &self.uri
    }

    /// Safe resource display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Safe resource display description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Minimum assurance required for grants to this resource.
    #[must_use]
    pub const fn minimum_assurance(&self) -> AssuranceLevel {
        self.minimum_assurance
    }

    /// Sorted unique resource scopes.
    #[must_use]
    pub fn scopes(&self) -> &[DescribedScope] {
        &self.scopes
    }
}

/// One validated scope and its consent description.
#[derive(Clone, Debug)]
pub struct DescribedScope {
    name: Scope,
    description: String,
}

impl DescribedScope {
    /// Exact scope token.
    #[must_use]
    pub const fn name(&self) -> &Scope {
        &self.name
    }

    /// Safe consent description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// Immutable, validated provider configuration ready for composition.
#[derive(Clone, Debug)]
pub struct ValidatedAuthorizationServerConfig {
    issuer: IssuerUri,
    token_pepper: TokenPepper,
    resources: Arc<[ResourceDeclaration]>,
    signing_keys: SigningKeyRing,
    authorization_request_ttl: Duration,
    authorization_code_ttl: Duration,
    access_token_ttl: Duration,
    id_token_ttl: Duration,
    refresh_token_ttl: Duration,
    client_metadata_cache_ttl: Duration,
    max_authorization_request_bytes: usize,
    max_client_metadata_bytes: usize,
    dynamic_client_registration: bool,
}

impl ValidatedAuthorizationServerConfig {
    /// Exact validated issuer.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        &self.issuer
    }

    /// Secret token digest key.
    #[must_use]
    pub const fn token_pepper(&self) -> &TokenPepper {
        &self.token_pepper
    }

    /// Sorted exact resource declarations.
    #[must_use]
    pub fn resources(&self) -> &[ResourceDeclaration] {
        &self.resources
    }

    /// Validated active signer and verification key snapshot.
    #[must_use]
    pub const fn signing_keys(&self) -> &SigningKeyRing {
        &self.signing_keys
    }

    /// Authorization request lifetime.
    #[must_use]
    pub const fn authorization_request_ttl(&self) -> Duration {
        self.authorization_request_ttl
    }

    /// Authorization code lifetime.
    #[must_use]
    pub const fn authorization_code_ttl(&self) -> Duration {
        self.authorization_code_ttl
    }

    /// Access-token lifetime.
    #[must_use]
    pub const fn access_token_ttl(&self) -> Duration {
        self.access_token_ttl
    }

    /// ID Token lifetime.
    #[must_use]
    pub const fn id_token_ttl(&self) -> Duration {
        self.id_token_ttl
    }

    /// Refresh-token lifetime.
    #[must_use]
    pub const fn refresh_token_ttl(&self) -> Duration {
        self.refresh_token_ttl
    }

    /// Client metadata cache lifetime.
    #[must_use]
    pub const fn client_metadata_cache_ttl(&self) -> Duration {
        self.client_metadata_cache_ttl
    }

    /// Authorization-request byte ceiling.
    #[must_use]
    pub const fn max_authorization_request_bytes(&self) -> usize {
        self.max_authorization_request_bytes
    }

    /// Client metadata byte ceiling.
    #[must_use]
    pub const fn max_client_metadata_bytes(&self) -> usize {
        self.max_client_metadata_bytes
    }

    /// Whether optional DCR compatibility is mounted by composition.
    #[must_use]
    pub const fn dynamic_client_registration(&self) -> bool {
        self.dynamic_client_registration
    }
}

impl AuthorizationServerConfig {
    /// Validates all fields for one deployment without retaining a built service.
    pub fn validate_for(
        &self,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<(), AuthorizationServerConfigError> {
        self.build_for(deployment, now).map(drop)
    }

    /// Constructs an immutable validated configuration, or `None` when disabled.
    ///
    /// Disabled configuration still enforces all global bounds. If resources or
    /// keys are supplied while disabled, they are validated rather than ignored.
    pub fn build_for(
        &self,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<Option<ValidatedAuthorizationServerConfig>, AuthorizationServerConfigError> {
        validate_lifetimes(self)?;
        validate_byte_limits(self)?;
        if self.resources.len() > MAX_RESOURCES {
            return Err(AuthorizationServerConfigError::InvalidResources);
        }
        if self.signing_keys.len() > MAX_SIGNING_KEYS {
            return Err(AuthorizationServerConfigError::InvalidSigningKeys);
        }
        let production = deployment == DeploymentEnvironment::Production;
        let resources = if self.resources.is_empty() {
            Vec::new()
        } else {
            validate_resources(&self.resources, production)?
        };
        let signing_keys = if self.signing_keys.is_empty() {
            None
        } else {
            Some(SigningKeyRing::from_config(&self.signing_keys, now)?)
        };
        if !self.enabled {
            if !self.issuer.is_empty() {
                IssuerUri::parse(self.issuer.clone(), production)
                    .map_err(|_| AuthorizationServerConfigError::InvalidIssuer)?;
            }
            return Ok(None);
        }
        let issuer = IssuerUri::parse(self.issuer.clone(), production)
            .map_err(|_| AuthorizationServerConfigError::InvalidIssuer)?;
        let token_pepper = self
            .token_pepper
            .clone()
            .ok_or(AuthorizationServerConfigError::InvalidTokenPepper)?;
        if resources.is_empty() {
            return Err(AuthorizationServerConfigError::InvalidResources);
        }
        let signing_keys =
            signing_keys.ok_or(AuthorizationServerConfigError::InvalidSigningKeys)?;
        Ok(Some(ValidatedAuthorizationServerConfig {
            issuer,
            token_pepper,
            resources: resources.into(),
            signing_keys,
            authorization_request_ttl: self.authorization_request_ttl,
            authorization_code_ttl: self.authorization_code_ttl,
            access_token_ttl: self.access_token_ttl,
            id_token_ttl: self.id_token_ttl,
            refresh_token_ttl: self.refresh_token_ttl,
            client_metadata_cache_ttl: self.client_metadata_cache_ttl,
            max_authorization_request_bytes: self.max_authorization_request_bytes,
            max_client_metadata_bytes: self.max_client_metadata_bytes,
            dynamic_client_registration: self.dynamic_client_registration,
        }))
    }
}

fn validate_lifetimes(
    config: &AuthorizationServerConfig,
) -> Result<(), AuthorizationServerConfigError> {
    if !(MIN_AUTHORIZATION_REQUEST_TTL..=MAX_AUTHORIZATION_REQUEST_TTL)
        .contains(&config.authorization_request_ttl)
        || !(MIN_AUTHORIZATION_CODE_TTL..=MAX_AUTHORIZATION_CODE_TTL)
            .contains(&config.authorization_code_ttl)
        || !(MIN_ACCESS_TOKEN_TTL..=MAX_ACCESS_TOKEN_TTL).contains(&config.access_token_ttl)
        || !(MIN_ID_TOKEN_TTL..=MAX_ID_TOKEN_TTL).contains(&config.id_token_ttl)
        || !(MIN_REFRESH_TOKEN_TTL..=MAX_REFRESH_TOKEN_TTL).contains(&config.refresh_token_ttl)
        || !(MIN_CLIENT_METADATA_CACHE_TTL..=MAX_CLIENT_METADATA_CACHE_TTL)
            .contains(&config.client_metadata_cache_ttl)
    {
        return Err(AuthorizationServerConfigError::InvalidLifetime);
    }
    Ok(())
}

fn validate_byte_limits(
    config: &AuthorizationServerConfig,
) -> Result<(), AuthorizationServerConfigError> {
    if !(MIN_AUTHORIZATION_REQUEST_BYTES..=MAX_AUTHORIZATION_REQUEST_BYTES)
        .contains(&config.max_authorization_request_bytes)
        || !(MIN_CLIENT_METADATA_BYTES..=MAX_CLIENT_METADATA_BYTES)
            .contains(&config.max_client_metadata_bytes)
    {
        return Err(AuthorizationServerConfigError::InvalidByteLimit);
    }
    Ok(())
}

fn validate_resources(
    configs: &[ResourceConfig],
    production: bool,
) -> Result<Vec<ResourceDeclaration>, AuthorizationServerConfigError> {
    if configs.is_empty() || configs.len() > MAX_RESOURCES {
        return Err(AuthorizationServerConfigError::InvalidResources);
    }
    let mut uris = HashSet::with_capacity(configs.len());
    let mut names = HashSet::with_capacity(configs.len());
    let mut all_scopes = HashSet::new();
    let mut resources = Vec::with_capacity(configs.len());
    for config in configs {
        let uri = ResourceUri::parse(config.uri.clone(), production)
            .map_err(|_| AuthorizationServerConfigError::InvalidResources)?;
        if !valid_display_text(&config.name, MAX_RESOURCE_NAME_BYTES)
            || !valid_display_text(&config.description, MAX_RESOURCE_DESCRIPTION_BYTES)
            || !uris.insert(uri.as_str().to_owned())
            || !names.insert(config.name.as_str())
            || config.scopes.is_empty()
        {
            return Err(AuthorizationServerConfigError::InvalidResources);
        }
        let mut scopes = Vec::with_capacity(config.scopes.len());
        for scope in &config.scopes {
            if RESERVED_SCOPES.contains(&scope.name.as_str())
                || !valid_display_text(&scope.description, MAX_SCOPE_DESCRIPTION_BYTES)
                || !all_scopes.insert(scope.name.as_str().to_owned())
                || all_scopes.len() + RESERVED_SCOPES.len() > MAX_TOTAL_SCOPES
            {
                return Err(AuthorizationServerConfigError::InvalidScopes);
            }
            scopes.push(DescribedScope {
                name: scope.name.clone(),
                description: scope.description.clone(),
            });
        }
        scopes.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        resources.push(ResourceDeclaration {
            uri,
            name: config.name.clone(),
            description: config.description.clone(),
            minimum_assurance: config.minimum_assurance,
            scopes,
        });
    }
    resources.sort_unstable_by(|left, right| left.uri.cmp(&right.uri));
    Ok(resources)
}

fn valid_display_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use omnius_config::SecretString;

    use super::*;
    use crate::crypto::{TEST_RSA_E, TEST_RSA_N, TEST_RSA_PRIVATE_KEY};

    fn signing_key() -> SigningKeyConfig {
        SigningKeyConfig {
            kid: "active-1".to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk: RsaPublicJwk {
                kty: "RSA".to_owned(),
                public_key_use: "sig".to_owned(),
                key_ops: vec!["verify".to_owned()],
                alg: "RS256".to_owned(),
                kid: "active-1".to_owned(),
                n: TEST_RSA_N.to_owned(),
                e: TEST_RSA_E.to_owned(),
            },
            private_key_pkcs8_pem: Some(SecretString::from(TEST_RSA_PRIVATE_KEY.to_owned())),
            verification_until: None,
        }
    }

    fn enabled_config() -> AuthorizationServerConfig {
        AuthorizationServerConfig {
            enabled: true,
            issuer: "https://issuer.example.test".to_owned(),
            token_pepper: Some(
                TokenPepper::parse(&URL_SAFE_NO_PAD.encode([9_u8; 32]))
                    .unwrap_or_else(|_| unreachable!()),
            ),
            resources: vec![ResourceConfig {
                uri: "https://issuer.example.test".to_owned(),
                name: "Root API".to_owned(),
                description: "Root API resource".to_owned(),
                minimum_assurance: AssuranceLevel::Aal1,
                scopes: vec![ResourceScopeConfig {
                    name: Scope::new("records:read").unwrap_or_else(|_| unreachable!()),
                    description: "Read records".to_owned(),
                }],
            }],
            signing_keys: vec![signing_key()],
            ..AuthorizationServerConfig::default()
        }
    }

    #[test]
    fn defaults_should_match_fixed_protocol_policy() {
        let config = AuthorizationServerConfig::default();
        assert!(!config.enabled);
        assert!(!config.dynamic_client_registration);
        assert_eq!(config.authorization_request_ttl, Duration::from_mins(10));
        assert_eq!(config.authorization_code_ttl, Duration::from_mins(2));
        assert_eq!(config.access_token_ttl, Duration::from_mins(10));
        assert_eq!(config.id_token_ttl, Duration::from_mins(10));
        assert_eq!(config.refresh_token_ttl, Duration::from_secs(86_400 * 30));
        assert_eq!(config.client_metadata_cache_ttl, Duration::from_mins(15));
        assert_eq!(config.max_authorization_request_bytes, 16 * 1_024);
        assert_eq!(config.max_client_metadata_bytes, 64 * 1_024);
    }

    #[test]
    fn strict_deserialization_should_reject_unknown_fields_and_padded_pepper() {
        let unknown =
            toml::from_str::<AuthorizationServerConfig>("enabled = false\nunknown = true\n");
        assert!(unknown.is_err());
        let padded = toml::from_str::<AuthorizationServerConfig>(
            "enabled = false\ntoken_pepper = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='\n",
        );
        assert!(padded.is_err());
    }

    #[test]
    fn production_should_require_root_https_issuer() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut config = enabled_config();
        config.issuer = "http://issuer.example.test".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production, now),
            Err(AuthorizationServerConfigError::InvalidIssuer)
        );
        config.issuer = "https://issuer.example.test/path".to_owned();
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production, now),
            Err(AuthorizationServerConfigError::InvalidIssuer)
        );
    }

    #[test]
    fn lifetime_and_byte_bounds_should_be_exact() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut config = enabled_config();
        config.authorization_code_ttl = Duration::from_secs(29);
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production, now),
            Err(AuthorizationServerConfigError::InvalidLifetime)
        );
        config.authorization_code_ttl = Duration::from_secs(30);
        config.max_client_metadata_bytes = MIN_CLIENT_METADATA_BYTES - 1;
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production, now),
            Err(AuthorizationServerConfigError::InvalidByteLimit)
        );
    }

    #[test]
    fn resource_audiences_and_scopes_should_be_globally_unique() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let mut config = enabled_config();
        config.resources.push(ResourceConfig {
            uri: "https://other.example.test".to_owned(),
            name: "Other API".to_owned(),
            description: "Other resource".to_owned(),
            minimum_assurance: AssuranceLevel::Aal2,
            scopes: vec![ResourceScopeConfig {
                name: Scope::new("records:read").unwrap_or_else(|_| unreachable!()),
                description: "Duplicate read scope".to_owned(),
            }],
        });
        assert_eq!(
            config.validate_for(DeploymentEnvironment::Production, now),
            Err(AuthorizationServerConfigError::InvalidScopes)
        );
    }

    #[test]
    fn active_key_should_match_public_jwk_and_redact_private_material() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let config = enabled_config();
        assert!(
            config
                .validate_for(DeploymentEnvironment::Production, now)
                .is_ok()
        );
        let debug = format!("{:?}", config.signing_keys[0]);
        assert!(debug.contains(REDACTED));
        assert!(!debug.contains("PRIVATE KEY"));
    }
}
