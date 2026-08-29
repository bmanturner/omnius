//! Immutable, deterministic OAuth/OIDC discovery and JWKS snapshots.

use std::{collections::BTreeMap, sync::Arc};

use serde::Serialize;

use crate::config::{ResourceDeclaration, ValidatedAuthorizationServerConfig};

const AUTHORIZATION_PATH: &str = "/oauth/authorize";
const TOKEN_PATH: &str = "/oauth/token";
const JWKS_PATH: &str = "/oauth/jwks.json";
const REGISTRATION_PATH: &str = "/oauth/register";
const REVOCATION_PATH: &str = "/oauth/revoke";
const USERINFO_PATH: &str = "/oauth/userinfo";
const LOGOUT_PATH: &str = "/oauth/logout";

/// RFC 8414 authorization-server metadata for the implemented subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationServerMetadata {
    /// Exact token issuer.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// Public signing-key endpoint.
    pub jwks_uri: String,
    /// Optional DCR endpoint, omitted while DCR is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// RFC 7009 token revocation endpoint.
    pub revocation_endpoint: String,
    /// Implemented scopes across OIDC and configured resources.
    pub scopes_supported: Vec<String>,
    /// Authorization code only.
    pub response_types_supported: Vec<String>,
    /// Query response mode only.
    pub response_modes_supported: Vec<String>,
    /// Authorization code and refresh token grants only.
    pub grant_types_supported: Vec<String>,
    /// Private-key JWT assertions use RS256 only.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// Implemented token endpoint client authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Implemented revocation endpoint client authentication methods.
    pub revocation_endpoint_auth_methods_supported: Vec<String>,
    /// Private-key JWT assertions at revocation use RS256 only.
    pub revocation_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// PKCE S256 only.
    pub code_challenge_methods_supported: Vec<String>,
    /// RFC 9207 issuer response parameter support.
    pub authorization_response_iss_parameter_supported: bool,
    /// HTTPS Client ID Metadata Document resolution support.
    pub client_id_metadata_document_supported: bool,
}

/// OpenID Provider discovery metadata for the implemented subset.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OpenIdProviderMetadata {
    /// Exact token issuer, identical to RFC 8414 metadata.
    pub issuer: String,
    /// Authorization endpoint.
    pub authorization_endpoint: String,
    /// Token endpoint.
    pub token_endpoint: String,
    /// UserInfo endpoint.
    pub userinfo_endpoint: String,
    /// Public signing-key endpoint.
    pub jwks_uri: String,
    /// Optional DCR endpoint, omitted while DCR is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_endpoint: Option<String>,
    /// RP-Initiated Logout endpoint.
    pub end_session_endpoint: String,
    /// Implemented OIDC and configured resource scopes.
    pub scopes_supported: Vec<String>,
    /// Authorization code only.
    pub response_types_supported: Vec<String>,
    /// Query response mode only.
    pub response_modes_supported: Vec<String>,
    /// Authorization code and refresh token grants only.
    pub grant_types_supported: Vec<String>,
    /// Public subject identifiers only.
    pub subject_types_supported: Vec<String>,
    /// RS256 ID Tokens only.
    pub id_token_signing_alg_values_supported: Vec<String>,
    /// Implemented token endpoint client authentication methods.
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Private-key JWT assertions use RS256 only.
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// PKCE S256 only.
    pub code_challenge_methods_supported: Vec<String>,
    /// Claims the provider can emit under the implemented scopes.
    pub claims_supported: Vec<String>,
    /// RFC 9207 issuer response parameter support.
    pub authorization_response_iss_parameter_supported: bool,
    /// HTTPS Client ID Metadata Document resolution support.
    pub client_id_metadata_document_supported: bool,
}

/// RFC 9728 protected-resource metadata for one exact configured audience.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtectedResourceMetadata {
    /// Exact resource identifier.
    pub resource: String,
    /// Sole trusted authorization server for this first-party resource.
    pub authorization_servers: Vec<String>,
    /// Resource scopes supported for this audience.
    pub scopes_supported: Vec<String>,
    /// Bearer tokens are accepted in the Authorization header only.
    pub bearer_methods_supported: Vec<String>,
    /// Access tokens are RS256-signed JWTs.
    pub resource_signing_alg_values_supported: Vec<String>,
}

/// Immutable mutually consistent discovery and protected-resource documents.
#[derive(Clone, Debug)]
pub struct MetadataSnapshots {
    authorization_server: Arc<AuthorizationServerMetadata>,
    openid_provider: Arc<OpenIdProviderMetadata>,
    protected_resources: Arc<BTreeMap<String, Arc<ProtectedResourceMetadata>>>,
}

impl MetadataSnapshots {
    /// Derives all endpoint URLs and advertised behavior from validated configuration.
    #[must_use]
    pub fn new(config: &ValidatedAuthorizationServerConfig) -> Self {
        let issuer = config.issuer();
        let scopes_supported = all_scopes(config.resources());
        let registration_endpoint = config
            .dynamic_client_registration()
            .then(|| issuer.endpoint(REGISTRATION_PATH));
        let authorization_endpoint = issuer.endpoint(AUTHORIZATION_PATH);
        let token_endpoint = issuer.endpoint(TOKEN_PATH);
        let jwks_uri = issuer.endpoint(JWKS_PATH);
        let common_auth_methods = vec![
            "none".to_owned(),
            "client_secret_basic".to_owned(),
            "private_key_jwt".to_owned(),
        ];
        let authorization_server = Arc::new(AuthorizationServerMetadata {
            issuer: issuer.as_str().to_owned(),
            authorization_endpoint: authorization_endpoint.clone(),
            token_endpoint: token_endpoint.clone(),
            jwks_uri: jwks_uri.clone(),
            registration_endpoint: registration_endpoint.clone(),
            revocation_endpoint: issuer.endpoint(REVOCATION_PATH),
            scopes_supported: scopes_supported.clone(),
            response_types_supported: vec!["code".to_owned()],
            response_modes_supported: vec!["query".to_owned()],
            token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ],
            token_endpoint_auth_methods_supported: common_auth_methods.clone(),
            revocation_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_owned()],
            revocation_endpoint_auth_methods_supported: common_auth_methods.clone(),
            code_challenge_methods_supported: vec!["S256".to_owned()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
        });
        let openid_provider = Arc::new(OpenIdProviderMetadata {
            issuer: issuer.as_str().to_owned(),
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint: issuer.endpoint(USERINFO_PATH),
            jwks_uri,
            registration_endpoint,
            end_session_endpoint: issuer.endpoint(LOGOUT_PATH),
            scopes_supported,
            response_types_supported: vec!["code".to_owned()],
            response_modes_supported: vec!["query".to_owned()],
            grant_types_supported: vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ],
            subject_types_supported: vec!["public".to_owned()],
            id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
            token_endpoint_auth_methods_supported: common_auth_methods,
            token_endpoint_auth_signing_alg_values_supported: vec!["RS256".to_owned()],
            code_challenge_methods_supported: vec!["S256".to_owned()],
            claims_supported: vec![
                "acr".to_owned(),
                "amr".to_owned(),
                "aud".to_owned(),
                "auth_time".to_owned(),
                "azp".to_owned(),
                "email".to_owned(),
                "email_verified".to_owned(),
                "exp".to_owned(),
                "iat".to_owned(),
                "iss".to_owned(),
                "nonce".to_owned(),
                "sub".to_owned(),
            ],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
        });
        let protected_resources = config
            .resources()
            .iter()
            .map(|resource| {
                let document = Arc::new(protected_resource(issuer.as_str(), resource));
                (resource.uri().as_str().to_owned(), document)
            })
            .collect::<BTreeMap<_, _>>();
        Self {
            authorization_server,
            openid_provider,
            protected_resources: Arc::new(protected_resources),
        }
    }

    /// RFC 8414 snapshot.
    #[must_use]
    pub fn authorization_server(&self) -> &AuthorizationServerMetadata {
        &self.authorization_server
    }

    /// OpenID Provider discovery snapshot.
    #[must_use]
    pub fn openid_provider(&self) -> &OpenIdProviderMetadata {
        &self.openid_provider
    }

    /// Protected-resource snapshot for one exact configured audience.
    #[must_use]
    pub fn protected_resource(&self, resource: &str) -> Option<&ProtectedResourceMetadata> {
        self.protected_resources.get(resource).map(AsRef::as_ref)
    }

    /// All protected-resource snapshots in exact URI order.
    #[must_use]
    pub fn protected_resources(&self) -> &BTreeMap<String, Arc<ProtectedResourceMetadata>> {
        &self.protected_resources
    }
}

fn all_scopes(resources: &[ResourceDeclaration]) -> Vec<String> {
    let mut scopes = vec![
        "email".to_owned(),
        "offline_access".to_owned(),
        "openid".to_owned(),
    ];
    scopes.extend(resources.iter().flat_map(|resource| {
        resource
            .scopes()
            .iter()
            .map(|scope| scope.name().as_str().to_owned())
    }));
    scopes.sort_unstable();
    scopes
}

fn protected_resource(issuer: &str, resource: &ResourceDeclaration) -> ProtectedResourceMetadata {
    ProtectedResourceMetadata {
        resource: resource.uri().as_str().to_owned(),
        authorization_servers: vec![issuer.to_owned()],
        scopes_supported: resource
            .scopes()
            .iter()
            .map(|scope| scope.name().as_str().to_owned())
            .collect(),
        bearer_methods_supported: vec!["header".to_owned()],
        resource_signing_alg_values_supported: vec!["RS256".to_owned()],
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use omnius_auth_core::{AssuranceLevel, Scope};
    use omnius_config::{DeploymentEnvironment, SecretString};
    use time::OffsetDateTime;

    use super::*;
    use crate::{
        config::{
            AuthorizationServerConfig, KeyAlgorithm, KeyState, ResourceConfig, ResourceScopeConfig,
            SigningKeyConfig,
        },
        crypto::{RsaPublicJwk, TEST_RSA_E, TEST_RSA_N, TEST_RSA_PRIVATE_KEY, TokenPepper},
    };

    fn config(dynamic_registration: bool) -> AuthorizationServerConfig {
        AuthorizationServerConfig {
            enabled: true,
            issuer: "https://issuer.example.test".to_owned(),
            token_pepper: TokenPepper::parse(&URL_SAFE_NO_PAD.encode([8_u8; 32])).ok(),
            dynamic_client_registration: dynamic_registration,
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
            signing_keys: vec![SigningKeyConfig {
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
            }],
            ..AuthorizationServerConfig::default()
        }
    }

    fn snapshots(
        dynamic_registration: bool,
    ) -> Result<MetadataSnapshots, Box<dyn std::error::Error>> {
        let validated = config(dynamic_registration)
            .build_for(
                DeploymentEnvironment::Production,
                OffsetDateTime::UNIX_EPOCH,
            )?
            .ok_or("enabled configuration was not built")?;
        Ok(MetadataSnapshots::new(&validated))
    }

    #[test]
    fn discovery_documents_should_share_exact_issuer_and_endpoints()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshots = snapshots(false)?;
        let oauth = snapshots.authorization_server();
        let oidc = snapshots.openid_provider();
        assert_eq!(oauth.issuer, oidc.issuer);
        assert_eq!(oauth.authorization_endpoint, oidc.authorization_endpoint);
        assert_eq!(oauth.token_endpoint, oidc.token_endpoint);
        assert_eq!(oauth.jwks_uri, oidc.jwks_uri);
        assert_eq!(oauth.registration_endpoint, None);
        assert_eq!(oidc.registration_endpoint, None);
        assert_eq!(oauth.response_types_supported, ["code"]);
        assert_eq!(oidc.id_token_signing_alg_values_supported, ["RS256"]);
        Ok(())
    }

    #[test]
    fn dcr_endpoint_should_be_advertised_only_when_enabled()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(
            snapshots(false)?
                .authorization_server()
                .registration_endpoint
                .is_none()
        );
        assert_eq!(
            snapshots(true)?
                .authorization_server()
                .registration_endpoint
                .as_deref(),
            Some("https://issuer.example.test/oauth/register")
        );
        Ok(())
    }

    #[test]
    fn protected_resource_should_match_validated_configuration()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshots = snapshots(false)?;
        let resource = snapshots
            .protected_resource("https://issuer.example.test")
            .ok_or("resource metadata missing")?;
        assert_eq!(
            resource.authorization_servers,
            ["https://issuer.example.test"]
        );
        assert_eq!(resource.scopes_supported, ["records:read"]);
        assert_eq!(resource.resource_signing_alg_values_supported, ["RS256"]);
        Ok(())
    }

    #[test]
    fn metadata_serialization_should_be_deterministic_and_omit_unmounted_behavior()
    -> Result<(), Box<dyn std::error::Error>> {
        let snapshots = snapshots(false)?;
        let first = serde_json::to_string(snapshots.authorization_server())?;
        let second = serde_json::to_string(snapshots.authorization_server())?;
        assert_eq!(first, second);
        assert!(!first.contains("registration_endpoint"));
        assert!(!first.contains("implicit"));
        assert!(!first.contains("device"));
        assert!(!first.contains("introspection"));
        Ok(())
    }
}
