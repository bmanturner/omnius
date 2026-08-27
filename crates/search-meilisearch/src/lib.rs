//! Tenant-fenced derived search projections and the maintained-SDK Meilisearch adapter.
//!
//! The crate deliberately separates five boundaries:
//!
//! - [`SearchProvider`] receives only [`TenantScopedQuery`] values constructed by [`SearchService`].
//! - [`BatchReauthorizer`] reloads authoritative existence, revision, and authorization before IDs
//!   leave the service; indexed presentation fields and provider totals are never returned.
//! - [`OutboxSearchProjector`] converts at-least-once outbox delivery into fenced, idempotent
//!   projection records and deterministic provider upserts/deletes.
//! - [`ReindexCoordinator`] persists schema versions and backfill cursors before atomically exposing
//!   a prepared index through the stable provider alias.
//! - [`PostgresSearchStore`] stores only projection/reindex control state and identifiers. It never
//!   stores indexed document content and is not a replacement for the application's source store.
//!
//! Application composition must inject the canonical [`omnius_auth_core::Principal`], a source-aware
//! [`BatchReauthorizer`], and an [`OutboxProjectionResolver`] that reloads source-of-truth data rather
//! than trusting event payloads.

#![forbid(unsafe_code)]

mod config;
mod health;
mod meilisearch;
mod model;
mod postgres;
mod projection;
mod provider;
mod service;

/// Deterministic contract fakes. Captured query/filter fields are redacted from `Debug` output.
pub mod testing;

pub use config::{
    HARD_MAX_DOCUMENT_BYTES, HARD_MAX_FILTER_BYTES, HARD_MAX_HITS, HARD_MAX_OFFSET,
    HARD_MAX_QUERY_BYTES, SearchConfigError, SearchLimits, SearchMeilisearchConfig,
};
pub use health::search_provider_health_check;
pub use meilisearch::{MeilisearchAdapter, MeilisearchAdapterError};
pub use model::{
    AuthorizedSource, FieldName, FilterValue, IndexAlias, IndexSchema, ProjectionDocument,
    ProjectionMutation, ReindexCursor, SearchCandidate, SearchFilter, SearchHit, SearchInput,
    SearchModelError, SearchResponse, SourceId, SourceRevision, TenantScopedQuery,
};
pub use postgres::PostgresSearchStore;
pub use projection::{
    OutboxSearchProjector, ProjectionBuildError, ProjectionFailure, ReindexCoordinator,
    ReindexError,
};
pub use provider::{
    ActivationOutcome, BatchReauthorizer, OutboxProjectionResolver, ProjectionClaim,
    ProjectionClaimContext, ProjectionClaimRequest, ProjectionFreshness, ProjectionLedger,
    ProjectionResolveError, ProjectionStoreError, ProjectionTarget, ProviderPage,
    ReauthorizationError, ReindexState, ReindexStatus, ReindexStore, ReindexStoreError,
    SearchProvider, SearchProviderError,
};
pub use service::{SearchError, SearchService};
