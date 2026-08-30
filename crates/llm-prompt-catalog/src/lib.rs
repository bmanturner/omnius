//! Immutable prompt revisions, strict rendering, authorized deterministic context, and cache policy.
//!
//! PostgreSQL prompt persistence is provided here. Authorization, retrieval, and exact-fence
//! cache implementations remain explicit composition-owned adapters.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cache;
mod catalog;
mod context;
mod id;
mod postgres;
mod render;

pub use cache::{
    AdmittedCacheValue, ApplicationCache, ApplicationCacheDescriptor, ApplicationCacheKey,
    ApplicationCachePolicy, ApplicationCacheStore, CacheContentKind, CacheDependencies, CacheFence,
    CacheKeyError, CacheLease, CacheModelSemantics, CachePolicyError, CachePromptSemantics,
    CacheSecurityScope, CacheStoreError, CacheWriteOutcome, ProviderCacheAdmission,
    ProviderCacheBreakpoint, ProviderCacheControls, ProviderCacheError, ProviderCacheMode,
    ProviderCachePolicy, admit_provider_cache,
};
pub use catalog::{
    CatalogError, PromptAccess, PromptBody, PromptCatalog, PromptCatalogStore, PromptRevision,
    PromptStatus, PromptStoreError, PromptTemplates,
};
pub use context::{
    AssembledContext, AuthorizedContextRequest, ContextAssembler, ContextAssemblyError,
    ContextAuthorizationDecision, ContextAuthorizationError, ContextAuthorizationPort,
    ContextAuthorizationRequest, ContextBudget, ContextError, ContextIdentity, ContextManifest,
    ContextProvenance, ContextRecord, ContextRetrievalError, ContextRetrievalPort,
    ContextSourceKind, RetrievedContextBatch, TruncationReason, TrustDomain,
};
pub use id::{
    AuthorizationId, CapabilityRevisionId, ContentDigest, DataClassification, EvaluationSetId,
    ModelRevisionId, OwnerId, PolicyRevisionId, PrincipalId, PromptId, PromptRevisionNumber,
    RouteId, SchemaRevisionId, SourceId, SourceRevisionId, TenantId, ToolId, ToolRevisionId,
    UntrustedText, ValueError,
};
pub use postgres::PostgresPromptCatalogStore;
pub use render::{
    PrivilegedInstruction, PromptRenderer, RenderError, RenderLimits, RenderedPrompt,
};
