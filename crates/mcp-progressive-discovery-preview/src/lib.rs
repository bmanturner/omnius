//! Experimental progressive-discovery projection seams over canonical authorized registry views.
//!
//! This crate owns no route, RPC, method, notification, or MCP wire type. It prepares bounded
//! compact partition/search/page data for a future settled standard while existing standardized
//! discovery and list methods remain unchanged. Activation requires both explicit server
//! configuration and an exact request-scoped extension negotiation in [`McpRequestContext`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cursor;
mod model;
mod preview;
mod service;

pub use model::{
    AuthorizationRevision, AuthorizedCatalogPort, AuthorizedCatalogSnapshot,
    AuthorizedSnapshotRequest, CapabilityKind, CatalogEntry, CompactCapability, DiscoveryClock,
    DiscoveryEntryMetadata, DiscoveryFilter, DiscoveryLimits, DiscoveryMetadataProvider,
    DiscoveryModelError, FutureDiscoveryMetadata, HARD_MAX_PAGE_SIZE, HARD_MAX_SCAN_ENTRIES,
    RegistryCatalogProjection, RegistryProjectionError, ResourceDiscoveryHints,
};
pub use omnius_mcp_server_core::McpRequestContext;
pub use preview::{
    DiscoveryPreviewConfig, DiscoveryPreviewReason, DiscoveryPreviewStatus,
    PROGRESSIVE_DISCOVERY_PREVIEW_ID, PROGRESSIVE_DISCOVERY_PREVIEW_REVISION,
};
pub use service::{
    CatalogHit, DiscoveryError, DiscoveryPage, DiscoveryPageAdapter, DiscoveryProjectionOutcome,
    DiscoveryProjectionRequest, DiscoveryPublicCode, DiscoveryReasonCode, DiscoveryRequestError,
    DiscoveryTelemetry, ProgressiveDiscoveryProjection,
};
