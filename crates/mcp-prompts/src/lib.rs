//! Canonical MCP projection of exact immutable prompt-catalog revisions.
//!
//! Canonical discovery and retrieval remain SDK-independent and authorization-filtered.
//! The exact exported RMCP adapter is a leaf boundary that converts current protocol values
//! before delegating to the immutable canonical projection and dispatch seam.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod adapter;
mod catalog;
mod projection;
mod value;

pub use adapter::{META_PROMPT_METADATA, RmcpPromptAdapter};
pub use catalog::{PromptCatalogError, PromptDefinition, PromptMetadata, PromptProjectionCatalog};
pub use projection::{
    AuthorizedListMetadata, AuthorizedPromptList, CanonicalPrompt, CanonicalPromptResult,
    META_CACHE_CONTROL, META_CACHE_SCOPE, META_CATALOG_ETAG, META_CATALOG_REVISION, META_TTL_MS,
    McpPromptProjection, PrivilegedDeveloperInstruction, PrivilegedSystemInstruction,
    PromptAuthorizationAction, PromptAuthorizationDecision, PromptAuthorizationError,
    PromptAuthorizationTarget, PromptAuthorizer, PromptGetRequest, PromptProjectionError,
    PromptProjectionErrorCode, UntrustedUserContent,
};
pub use value::{
    CacheControl, CacheScope, CatalogEtag, CatalogRevision, CompatibilityStatus,
    PromptCompatibility, PromptValueError, PublicPromptName, SchemaRevision,
};

/// The sole MCP protocol revision implemented by this prompt projection.
pub const MCP_PROMPTS_PROTOCOL_REVISION: &str = "2026-07-28";
