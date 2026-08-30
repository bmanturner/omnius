//! Immutable, authorization-aware MCP resource projections over the canonical registry.
//!
//! This crate is SDK- and transport-independent. Discovery consults only a narrow
//! authorization port, while every read and hierarchy operation invokes the shared
//! [`omnius_mcp_server_core::McpKernel`] with [`omnius_mcp_server_core::McpPrimitive::Resource`].
//!
//! The only baseline is MCP 2026-07-28. Extension-gated declarations remain invisible and
//! unreadable unless every required exact identifier-and-revision unit was negotiated.
//! Domain results deliberately remain independent of RMCP wire types so future result adapters
//! cannot alter application contracts.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod catalog;
mod projection;
mod result;
mod uri;
mod value;
pub use omnius_mcp_server_core::{McpExtension, McpExtensionId, McpExtensionRevision};

pub use catalog::{
    ExactResourceDeclaration, ResourceCatalog, ResourceTemplateDeclaration, TenantBinding,
};
pub use projection::{
    AuthorizedCatalogMetadata, AuthorizedResource, AuthorizedResourceCatalog,
    AuthorizedResourceTemplate, ResourceAuthorizationAction, ResourceAuthorizationTarget,
    ResourceAuthorizationUri, ResourceAuthorizer, ResourceOperation, ResourceProjection,
    ResourceRequest,
};
pub use result::{
    ResourceCacheMetadata, ResourceContent, ResourceHierarchy, ResourceObjectReference,
    ResourceProvenance, ResourceRangeResponse, ResourceResult,
};
pub use uri::{ResourceUri, ResourceUriTemplate};
pub use value::{
    ByteRange, CacheControl, CacheScope, CatalogRevision, MAX_CACHE_AGE_SECONDS,
    MAX_REQUIRED_EXTENSIONS, MAX_RESOURCE_CONTENT_BYTES, MAX_RESOURCE_RANGE_BYTES, MimeType,
    OpaqueResourceValue, PublicResourceName, ResourceCompatibility, ResourceDescription,
    ResourceError, ResourceErrorCode, ResourceLimits, ResourceMetadata, ResourceTitle,
    SchemaRevision, Sha256Digest, TemplateVariableName,
};
