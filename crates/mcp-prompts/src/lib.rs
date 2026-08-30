//! Canonical MCP projection of exact immutable prompt-catalog revisions.
//!
//! This crate is transport-independent and contains no RMCP types. Discovery is
//! filtered through a narrow authorization port. Retrieval validates and renders
//! an exact published revision, then executes only through the canonical MCP
//! kernel and shared capability registry.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod catalog;
mod projection;
mod value;

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
