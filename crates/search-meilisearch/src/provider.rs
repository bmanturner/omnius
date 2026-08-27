use std::{fmt, time::Duration};

use futures::future::BoxFuture;
use omnius_auth_core::{Principal, TenantId};
use omnius_outbox::LeasedOutboxEvent;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    IndexAlias, IndexSchema, ProjectionMutation, ReindexCursor, SearchCandidate, SourceId,
    SourceRevision, TenantScopedQuery,
};

/// Safe, stable classifications for provider failures. Provider diagnostics are never retained.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SearchProviderError {
    /// The configured end-to-end deadline elapsed.
    #[error("search provider timed out")]
    Timeout,
    /// The provider could not be reached or returned an internal failure.
    #[error("search provider is unavailable")]
    Unavailable,
    /// The provider rejected a bounded request or its schema.
    #[error("search provider rejected the request")]
    Rejected,
    /// The provider returned data that violated the adapter contract.
    #[error("search provider returned an invalid response")]
    InvalidResponse,
    /// A requested index or projection document was absent.
    #[error("search provider resource was not found")]
    NotFound,
    /// A versioned index exists with a different schema marker.
    #[error("search provider index schema conflicts with persisted state")]
    SchemaConflict,
}

impl SearchProviderError {
    pub(crate) const fn failure_class(self) -> &'static str {
        match self {
            Self::Timeout => "search_provider_timeout",
            Self::Unavailable => "search_provider_unavailable",
            Self::Rejected => "search_provider_rejected",
            Self::InvalidResponse => "search_provider_invalid_response",
            Self::NotFound => "search_provider_not_found",
            Self::SchemaConflict => "search_provider_schema_conflict",
        }
    }
}

/// One bounded page of derived identities returned by a provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPage {
    hits: Vec<SearchCandidate>,
}

impl ProviderPage {
    /// Creates a page. The caller-facing service independently enforces its configured hit bound.
    #[must_use]
    pub const fn new(hits: Vec<SearchCandidate>) -> Self {
        Self { hits }
    }

    /// Borrows ordered provider candidates.
    #[must_use]
    pub fn hits(&self) -> &[SearchCandidate] {
        &self.hits
    }

    pub(crate) fn into_hits(self) -> Vec<SearchCandidate> {
        self.hits
    }
}

/// Selects whether a projection mutation targets the stable alias or a versioned backfill index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionTarget {
    /// The currently active stable alias with its asserted schema marker.
    Active(IndexSchema),
    /// A staging index for this exact schema version.
    Version(IndexSchema),
}

/// Result of an idempotent alias activation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationOutcome {
    /// The version was swapped or renamed into the stable alias.
    Activated,
    /// The stable alias already carried the requested schema marker.
    AlreadyActive,
}

/// Provider-neutral derived-search port.
///
/// `TenantScopedQuery` cannot be built by callers. Implementations receive a mandatory canonical
/// tenant and must preserve its rendered predicate. Projection writes likewise receive a tenant
/// separate from application document fields.
pub trait SearchProvider: Send + Sync + 'static {
    /// Searches the stable logical alias using one mandatory tenant-scoped query.
    fn search<'a>(
        &'a self,
        alias: &'a IndexAlias,
        query: &'a TenantScopedQuery,
    ) -> BoxFuture<'a, Result<ProviderPage, SearchProviderError>>;

    /// Applies one complete idempotent upsert or delete to an active or versioned target.
    fn apply<'a>(
        &'a self,
        target: &'a ProjectionTarget,
        tenant_id: TenantId,
        mutation: &'a ProjectionMutation,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>>;

    /// Idempotently creates and configures one versioned staging index with a schema marker.
    fn prepare_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>>;

    /// Idempotently makes a prepared version available under its stable alias.
    fn activate_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<ActivationOutcome, SearchProviderError>>;

    /// Checks provider connectivity and validates the active alias marker.
    fn health<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>>;
}

/// Safe batch authorization failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReauthorizationError {
    /// The authoritative source or authorization service was unavailable.
    #[error("search result reauthorization is unavailable")]
    Unavailable,
    /// The reauthorizer returned duplicate, cross-batch, or otherwise invalid identities.
    #[error("search result reauthorization returned an invalid response")]
    InvalidResponse,
}

/// Application port that both verifies current source existence/revision and authorizes visibility.
pub trait BatchReauthorizer: Send + Sync + 'static {
    /// Returns only sources that still exist, still have the candidate revision, and are visible to
    /// the canonical principal. Missing, stale, and unauthorized inputs must be omitted.
    fn reauthorize<'a>(
        &'a self,
        principal: &'a Principal,
        candidates: &'a [SearchCandidate],
    ) -> BoxFuture<'a, Result<Vec<crate::AuthorizedSource>, ReauthorizationError>>;
}

/// Safe application resolver failure for outbox projection.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProjectionResolveError {
    /// The authoritative source store was temporarily unavailable.
    #[error("search projection source is unavailable")]
    Unavailable,
    /// The event was unsupported or violated the declared projection contract.
    #[error("search projection event is invalid")]
    InvalidEvent,
}

/// Application adapter that reloads authoritative source state for an outbox event.
pub trait OutboxProjectionResolver: Send + Sync + 'static {
    /// Resolves the event to a complete mutation. Implementations must load source-of-truth data;
    /// the untrusted outbox payload is context, never the authoritative search document.
    fn resolve<'a>(
        &'a self,
        event: &'a LeasedOutboxEvent,
        tenant_id: TenantId,
    ) -> BoxFuture<'a, Result<ProjectionMutation, ProjectionResolveError>>;
}

/// Immutable event, tenant, and version target shared by one projection claim.
pub struct ProjectionClaimContext<'a> {
    event_id: Uuid,
    tenant_id: TenantId,
    schema: &'a IndexSchema,
    occurred_at: OffsetDateTime,
}

impl<'a> ProjectionClaimContext<'a> {
    /// Creates a validated projection context for one schema target.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionStoreError::InvalidClaim`] for a non-UUIDv7 event or unsupported version.
    pub fn new(
        event_id: Uuid,
        tenant_id: TenantId,
        schema: &'a IndexSchema,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, ProjectionStoreError> {
        if event_id.get_version_num() != 7
            || event_id.get_variant() != uuid::Variant::RFC4122
            || schema.version() > i32::MAX as u32
        {
            return Err(ProjectionStoreError::InvalidClaim);
        }
        Ok(Self {
            event_id,
            tenant_id,
            schema,
            occurred_at,
        })
    }
}

/// Immutable identity of one projection attempt stored before touching the external index.
pub struct ProjectionClaimRequest<'a> {
    event_id: Uuid,
    tenant_id: TenantId,
    alias: &'a IndexAlias,
    schema_version: u32,
    source_id: &'a SourceId,
    revision: SourceRevision,
    operation: &'static str,
    occurred_at: OffsetDateTime,
    lease_duration: Duration,
}

impl<'a> ProjectionClaimRequest<'a> {
    /// Creates a validated upsert ledger claim for direct projection-store integration.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionStoreError::InvalidClaim`] for an unsafe lease.
    pub fn upsert(
        context: &ProjectionClaimContext<'a>,
        source_id: &'a SourceId,
        revision: SourceRevision,
        lease_duration: Duration,
    ) -> Result<Self, ProjectionStoreError> {
        Self::for_operation(context, source_id, revision, "upsert", lease_duration)
    }

    /// Creates a validated deletion ledger claim for direct projection-store integration.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionStoreError::InvalidClaim`] for an unsafe lease.
    pub fn delete(
        context: &ProjectionClaimContext<'a>,
        source_id: &'a SourceId,
        revision: SourceRevision,
        lease_duration: Duration,
    ) -> Result<Self, ProjectionStoreError> {
        Self::for_operation(context, source_id, revision, "delete", lease_duration)
    }

    pub(crate) fn for_operation(
        context: &ProjectionClaimContext<'a>,
        source_id: &'a SourceId,
        revision: SourceRevision,
        operation: &'static str,
        lease_duration: Duration,
    ) -> Result<Self, ProjectionStoreError> {
        if lease_duration.is_zero() || lease_duration > Duration::from_hours(168) {
            return Err(ProjectionStoreError::InvalidClaim);
        }
        Ok(Self {
            event_id: context.event_id,
            tenant_id: context.tenant_id,
            alias: context.schema.alias(),
            schema_version: context.schema.version(),
            source_id,
            revision,
            operation,
            occurred_at: context.occurred_at,
            lease_duration,
        })
    }

    /// Returns the outbox event `UUIDv7` idempotency key.
    #[must_use]
    pub const fn event_id(&self) -> Uuid {
        self.event_id
    }

    /// Returns the mandatory canonical tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the logical index alias.
    #[must_use]
    pub const fn alias(&self) -> &IndexAlias {
        self.alias
    }

    /// Returns the immutable target schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        self.source_id
    }

    /// Returns the monotonic source revision.
    #[must_use]
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }

    /// Returns `upsert` or `delete`.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Returns the domain event occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    /// Returns the validated database lease duration.
    #[must_use]
    pub const fn lease_duration(&self) -> Duration {
        self.lease_duration
    }
}

impl fmt::Debug for ProjectionClaimRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionClaimRequest")
            .field("event_id", &self.event_id)
            .field("tenant_id", &"[REDACTED]")
            .field("alias", &self.alias)
            .field("schema_version", &self.schema_version)
            .field("source_id", &self.source_id)
            .field("revision", &self.revision)
            .field("operation", &self.operation)
            .field("occurred_at", &self.occurred_at)
            .field("lease_duration", &self.lease_duration)
            .finish()
    }
}

/// Outcome of atomically claiming an idempotent projection record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionClaim {
    /// This caller owns the projection through an opaque `UUIDv7` fence.
    Acquired {
        /// Opaque `UUIDv7` lease fence required by completion or failure.
        lease_token: Uuid,
    },
    /// This exact event was already completed.
    AlreadyApplied,
    /// A later authoritative event for the same source was already completed.
    Superseded,
    /// Another live projection lease owns this source.
    Busy,
}

/// Stable PostgreSQL projection-ledger failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProjectionStoreError {
    /// A public direct claim contained a non-UUIDv7 event or unsafe lease duration.
    #[error("search projection claim is invalid")]
    InvalidClaim,
    /// Database access failed or persisted rows violated invariants.
    #[error("search projection storage is unavailable")]
    Unavailable,
    /// An event UUID was reused with different immutable projection identity.
    #[error("search projection event identity conflicts with persisted state")]
    IdentityConflict,
    /// A lease token no longer owns the projection row.
    #[error("search projection lease fence was lost")]
    FenceLost,
}

/// Durable idempotency and lease boundary for at-least-once outbox projection.
pub trait ProjectionLedger: Send + Sync + 'static {
    /// Claims or classifies one immutable projection event.
    fn claim<'a>(
        &'a self,
        request: ProjectionClaimRequest<'a>,
    ) -> BoxFuture<'a, Result<ProjectionClaim, ProjectionStoreError>>;

    /// Fenced completion after the provider task is terminal and successful.
    fn complete(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
    ) -> BoxFuture<'_, Result<(), ProjectionStoreError>>;

    /// Releases a failed attempt while retaining only a bounded safe class.
    fn fail(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
        failure_class: &'static str,
    ) -> BoxFuture<'_, Result<(), ProjectionStoreError>>;
}

/// Durable reindex lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReindexStatus {
    /// Version registered; staging setup may still be incomplete.
    Preparing,
    /// Staging index exists and backfill may advance.
    Backfilling,
    /// Backfill completed and version is eligible for activation.
    Ready,
    /// Version is active under the stable alias.
    Active,
    /// Version was replaced by a later activation.
    Retired,
}

impl ReindexStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Preparing => "preparing",
            Self::Backfilling => "backfilling",
            Self::Ready => "ready",
            Self::Active => "active",
            Self::Retired => "retired",
        }
    }

    pub(crate) fn from_database(value: &str) -> Result<Self, ReindexStoreError> {
        match value {
            "preparing" => Ok(Self::Preparing),
            "backfilling" => Ok(Self::Backfilling),
            "ready" => Ok(Self::Ready),
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            _ => Err(ReindexStoreError::Unavailable),
        }
    }
}

/// Restartable state and optimistic generation for one schema version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReindexState {
    /// Logical alias.
    pub alias: IndexAlias,
    /// Schema version.
    pub version: u32,
    /// Current lifecycle state.
    pub status: ReindexStatus,
    /// Opaque next-source cursor, absent before/after a complete backfill.
    pub cursor: Option<ReindexCursor>,
    /// Count durably reported by completed backfill pages.
    pub projected_count: u64,
    /// Optimistic concurrency generation.
    pub generation: u64,
    /// When this version was activated, if active or retired.
    pub activated_at: Option<OffsetDateTime>,
}

/// Freshness anchor used by the degraded provider health check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectionFreshness {
    /// Activation time of the current schema.
    pub activated_at: OffsetDateTime,
    /// Latest successfully completed live projection, when any.
    pub last_projected_at: Option<OffsetDateTime>,
}

/// Stable reindex-state storage failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReindexStoreError {
    /// Database access failed or returned corrupt state.
    #[error("search reindex state is unavailable")]
    Unavailable,
    /// A registered alias/version carried another schema digest.
    #[error("search reindex schema conflicts with persisted state")]
    SchemaConflict,
    /// The expected generation or lifecycle state was stale.
    #[error("search reindex state changed concurrently")]
    Conflict,
    /// No active index exists for the alias.
    #[error("search index alias is not active")]
    NotActive,
}

/// Durable state port for reindex, replay cursor, alias activation, and staleness.
pub trait ReindexStore: Send + Sync + 'static {
    /// Registers an immutable alias/version/schema digest or loads its existing state.
    fn register<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>>;

    /// Marks provider staging complete and enters restartable backfill.
    fn begin_backfill<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>>;

    /// Atomically persists the next cursor and cumulative count.
    fn advance<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
        cursor: &'a ReindexCursor,
        projected_delta: u32,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>>;

    /// Marks backfill complete and removes the cursor.
    fn mark_ready<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>>;

    /// Transactionally changes the durable active alias after an idempotent provider activation.
    fn activate<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>>;

    /// Returns active-alias projection freshness without reading indexed content.
    fn freshness<'a>(
        &'a self,
        alias: &'a IndexAlias,
    ) -> BoxFuture<'a, Result<ProjectionFreshness, ReindexStoreError>>;
}
