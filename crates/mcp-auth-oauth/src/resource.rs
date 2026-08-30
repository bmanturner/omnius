use std::sync::Arc;

use omnius_auth_core::Scope;
use omnius_auth_oauth_server::{IssuerUri, MAX_SCOPES, ResourceUri};
use serde::Serialize;
use thiserror::Error;
use url::Url;

/// Maximum serialized size of the immutable protected-resource metadata document.
pub const MAX_PROTECTED_RESOURCE_METADATA_BYTES: usize = 32 * 1024;
/// Bounded public-cache lifetime for protected-resource metadata.
pub const PROTECTED_RESOURCE_METADATA_MAX_AGE_SECONDS: u16 = 300;
/// Exact cache policy emitted with protected-resource metadata.
pub const PROTECTED_RESOURCE_METADATA_CACHE_CONTROL: &str = "public, max-age=300, must-revalidate";
/// MIME type emitted with protected-resource metadata.
pub const PROTECTED_RESOURCE_METADATA_CONTENT_TYPE: &str = "application/json";

const PROTECTED_RESOURCE_WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";
const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// A protected-resource configuration was invalid.
///
/// Every variant is value-free so configuration errors cannot echo URI or scope input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtectedResourceError {
    /// The resource was not a canonical absolute URI usable as an MCP audience.
    #[error("MCP resource identity is invalid")]
    InvalidResource,
    /// No resource scope was declared.
    #[error("MCP protected resource must declare at least one scope")]
    MissingScopes,
    /// A bounded collection limit was exceeded.
    #[error("MCP protected-resource configuration exceeds a fixed bound")]
    CollectionLimit,
    /// The same scope was declared more than once.
    #[error("MCP protected-resource configuration contains a duplicate scope")]
    DuplicateScope,
    /// A refresh-token scope was incorrectly advertised as a resource capability.
    #[error("MCP protected resource contains a non-resource scope")]
    NonResourceScope,
    /// An operation requested a scope the resource does not advertise.
    #[error("MCP operation requires an unsupported resource scope")]
    UnsupportedOperationScope,
    /// The immutable metadata snapshot could not be constructed within its bound.
    #[error("MCP protected-resource metadata is unavailable")]
    MetadataUnavailable,
}

/// Canonical absolute MCP resource, token audience, trusted issuer, and RFC 9728 URL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpResourceIdentity {
    resource: ResourceUri,
    issuer: IssuerUri,
    protected_resource_metadata_url: String,
}

impl McpResourceIdentity {
    /// Parses one canonical resource identifier and one canonical issuer.
    ///
    /// MCP resource identifiers cannot contain a query because the identifier is
    /// also used as an exact token audience and to derive a stable well-known URL.
    /// Production mode requires HTTPS for both values.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedResourceError::InvalidResource`] for a non-canonical,
    /// relative, credential-bearing, fragmented, query-bearing, or insecure value.
    pub fn parse(
        resource: impl Into<String>,
        issuer: impl Into<String>,
        production: bool,
    ) -> Result<Self, ProtectedResourceError> {
        let resource = ResourceUri::parse(resource, production)
            .map_err(|_| ProtectedResourceError::InvalidResource)?;
        let issuer = IssuerUri::parse(issuer, production)
            .map_err(|_| ProtectedResourceError::InvalidResource)?;
        Self::new(resource, issuer)
    }

    /// Builds an MCP identity from values already validated by the OAuth core.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedResourceError::InvalidResource`] when the resource has
    /// a query component or its RFC 9728 metadata URL cannot be derived.
    pub fn new(resource: ResourceUri, issuer: IssuerUri) -> Result<Self, ProtectedResourceError> {
        let parsed =
            Url::parse(resource.as_str()).map_err(|_| ProtectedResourceError::InvalidResource)?;
        if parsed.query().is_some() {
            return Err(ProtectedResourceError::InvalidResource);
        }

        let suffix = match parsed.path() {
            "/" => "",
            path => path,
        };
        let origin = parsed.origin().ascii_serialization();
        let mut protected_resource_metadata_url = String::with_capacity(
            origin.len() + PROTECTED_RESOURCE_WELL_KNOWN_PATH.len() + suffix.len(),
        );
        protected_resource_metadata_url.push_str(&origin);
        protected_resource_metadata_url.push_str(PROTECTED_RESOURCE_WELL_KNOWN_PATH);
        protected_resource_metadata_url.push_str(suffix);

        Url::parse(&protected_resource_metadata_url)
            .map_err(|_| ProtectedResourceError::InvalidResource)?;

        Ok(Self {
            resource,
            issuer,
            protected_resource_metadata_url,
        })
    }

    /// Returns the exact RFC 8707 resource indicator and access-token audience.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns the sole trusted authorization-server issuer.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        &self.issuer
    }

    /// Returns the absolute RFC 9728 protected-resource metadata URL.
    #[must_use]
    pub fn protected_resource_metadata_url(&self) -> &str {
        &self.protected_resource_metadata_url
    }
}

/// Exact RFC 9728 metadata for the canonical MCP protected resource.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct McpProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
    bearer_methods_supported: Vec<String>,
    resource_signing_alg_values_supported: Vec<String>,
}

impl McpProtectedResourceMetadata {
    /// Returns the exact resource identifier.
    #[must_use]
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// Returns the complete trusted authorization-server list.
    #[must_use]
    pub fn authorization_servers(&self) -> &[String] {
        &self.authorization_servers
    }

    /// Returns the complete sorted resource-scope list.
    #[must_use]
    pub fn scopes_supported(&self) -> &[String] {
        &self.scopes_supported
    }

    /// Returns the supported bearer-token presentation methods.
    #[must_use]
    pub fn bearer_methods_supported(&self) -> &[String] {
        &self.bearer_methods_supported
    }

    /// Returns the accepted access-token signing algorithms.
    #[must_use]
    pub fn resource_signing_alg_values_supported(&self) -> &[String] {
        &self.resource_signing_alg_values_supported
    }
}

/// Immutable MCP protected-resource profile shared by authentication and metadata routes.
#[derive(Clone, Debug)]
pub struct McpProtectedResource {
    identity: McpResourceIdentity,
    supported_scopes: Arc<[Scope]>,
    metadata: Arc<McpProtectedResourceMetadata>,
    metadata_json: Arc<[u8]>,
}

impl McpProtectedResource {
    /// Creates one mutually consistent metadata, audience, issuer, and scope snapshot.
    ///
    /// Scopes are sorted but duplicates are rejected. `offline_access` is never a
    /// resource capability and therefore cannot be advertised by this profile.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedResourceError`] when scopes or the serialized metadata
    /// violate a fixed configuration bound.
    pub fn new(
        identity: McpResourceIdentity,
        mut supported_scopes: Vec<Scope>,
    ) -> Result<Self, ProtectedResourceError> {
        if supported_scopes.is_empty() {
            return Err(ProtectedResourceError::MissingScopes);
        }
        if supported_scopes.len() > MAX_SCOPES {
            return Err(ProtectedResourceError::CollectionLimit);
        }
        supported_scopes.sort_unstable();
        if supported_scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProtectedResourceError::DuplicateScope);
        }
        if supported_scopes
            .iter()
            .any(|scope| scope.as_str() == OFFLINE_ACCESS_SCOPE)
        {
            return Err(ProtectedResourceError::NonResourceScope);
        }

        let metadata = Arc::new(McpProtectedResourceMetadata {
            resource: identity.resource().as_str().to_owned(),
            authorization_servers: vec![identity.issuer().as_str().to_owned()],
            scopes_supported: supported_scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            bearer_methods_supported: vec!["header".to_owned()],
            resource_signing_alg_values_supported: vec!["RS256".to_owned()],
        });
        let metadata_json = serde_json::to_vec(metadata.as_ref())
            .map_err(|_| ProtectedResourceError::MetadataUnavailable)?;
        if metadata_json.len() > MAX_PROTECTED_RESOURCE_METADATA_BYTES {
            return Err(ProtectedResourceError::MetadataUnavailable);
        }

        Ok(Self {
            identity,
            supported_scopes: supported_scopes.into(),
            metadata,
            metadata_json: metadata_json.into(),
        })
    }

    /// Returns the canonical resource identity shared by all decisions.
    #[must_use]
    pub const fn identity(&self) -> &McpResourceIdentity {
        &self.identity
    }

    /// Returns the exact resource indicator and token audience.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        self.identity.resource()
    }

    /// Returns the sole trusted issuer.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        self.identity.issuer()
    }

    /// Returns the complete sorted scope policy configured on the token verifier.
    #[must_use]
    pub fn supported_scopes(&self) -> &[Scope] {
        &self.supported_scopes
    }

    /// Returns the exact immutable RFC 9728 document.
    #[must_use]
    pub fn metadata(&self) -> &McpProtectedResourceMetadata {
        &self.metadata
    }

    /// Returns the pre-serialized bounded metadata response body.
    #[must_use]
    pub fn metadata_json(&self) -> &[u8] {
        &self.metadata_json
    }

    /// Validates and binds required operation scopes to this exact resource.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectedResourceError`] for an empty, oversized, duplicate, or
    /// unsupported operation scope set.
    pub fn operation_requirements(
        &self,
        mut required_scopes: Vec<Scope>,
    ) -> Result<OperationRequirements, ProtectedResourceError> {
        if required_scopes.is_empty() {
            return Err(ProtectedResourceError::MissingScopes);
        }
        if required_scopes.len() > MAX_SCOPES {
            return Err(ProtectedResourceError::CollectionLimit);
        }
        required_scopes.sort_unstable();
        if required_scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProtectedResourceError::DuplicateScope);
        }
        if required_scopes
            .iter()
            .any(|scope| self.supported_scopes.binary_search(scope).is_err())
        {
            return Err(ProtectedResourceError::UnsupportedOperationScope);
        }
        Ok(OperationRequirements {
            resource: self.resource().clone(),
            required_scopes: required_scopes.into(),
        })
    }
}

/// Complete sorted scope requirements bound to one exact MCP resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRequirements {
    resource: ResourceUri,
    required_scopes: Arc<[Scope]>,
}

impl OperationRequirements {
    /// Returns the resource to which these requirements are bound.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns every scope required by the operation in deterministic order.
    #[must_use]
    pub fn required_scopes(&self) -> &[Scope] {
        &self.required_scopes
    }
}
