use std::sync::Arc;

use futures::future::BoxFuture;
use rsk_auth_core::TenantId;
use rsk_outbox::{FailureClass, LeasedOutboxEvent, OutboxPublisher, PublishError};
use thiserror::Error;

use crate::{
    IndexSchema, OutboxProjectionResolver, ProjectionClaim, ProjectionClaimContext,
    ProjectionClaimRequest, ProjectionLedger, ProjectionMutation, ProjectionResolveError,
    ProjectionStoreError, ProjectionTarget, ReindexCursor, ReindexState, ReindexStatus,
    ReindexStore, ReindexStoreError, SearchMeilisearchConfig, SearchModelError, SearchProvider,
    SearchProviderError,
};

/// At-least-once outbox consumer that writes only authoritative, tenant-scoped projections.
pub struct OutboxSearchProjector {
    provider: Arc<dyn SearchProvider>,
    ledger: Arc<dyn ProjectionLedger>,
    resolver: Arc<dyn OutboxProjectionResolver>,
    schema: IndexSchema,
    reindex_schema: Option<IndexSchema>,
    projection_lease: std::time::Duration,
    max_document_bytes: usize,
    failure_classes: FailureClasses,
}

impl OutboxSearchProjector {
    /// Builds the outbox publisher and pre-validates every stable failure class.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionBuildError`] for invalid configuration or an internal failure-class contract.
    pub fn new(
        provider: Arc<dyn SearchProvider>,
        ledger: Arc<dyn ProjectionLedger>,
        resolver: Arc<dyn OutboxProjectionResolver>,
        schema: IndexSchema,
        config: &SearchMeilisearchConfig,
    ) -> Result<Self, ProjectionBuildError> {
        config
            .validate()
            .map_err(|_| ProjectionBuildError::Configuration)?;
        Ok(Self {
            provider,
            ledger,
            resolver,
            schema,
            reindex_schema: None,
            projection_lease: config.projection_lease,
            max_document_bytes: config.limits.max_document_bytes,
            failure_classes: FailureClasses::new()?,
        })
    }

    /// Enables dual writes to a newer same-alias staging schema during backfill.
    ///
    /// Composition must install this projector before reading the first authoritative backfill
    /// page and retain it until activation completes. Both provider writes must succeed before the
    /// event ledger completes, so changes racing a copied source page cannot be lost at activation.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectionBuildError::InvalidReindexTarget`] unless the target has the same alias
    /// and a strictly newer schema version.
    pub fn with_reindex_target(
        mut self,
        reindex_schema: IndexSchema,
    ) -> Result<Self, ProjectionBuildError> {
        if reindex_schema.alias() != self.schema.alias()
            || reindex_schema.version() <= self.schema.version()
        {
            return Err(ProjectionBuildError::InvalidReindexTarget);
        }
        self.reindex_schema = Some(reindex_schema);
        Ok(self)
    }

    /// Projects one leased event. This is also the behavior used by [`OutboxPublisher`].
    ///
    /// Provider upserts/deletes are deterministic and may safely repeat after a process exits between
    /// provider success and fenced ledger completion.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure classification suitable for outbox retry bookkeeping.
    pub async fn project(&self, event: &LeasedOutboxEvent) -> Result<(), ProjectionFailure> {
        let tenant_uuid = event.tenant_id().ok_or(ProjectionFailure::InvalidEvent)?;
        let tenant_id =
            TenantId::from_uuid(tenant_uuid).map_err(|_| ProjectionFailure::InvalidEvent)?;
        let mutation = self
            .resolver
            .resolve(event, tenant_id)
            .await
            .map_err(ProjectionFailure::Resolve)?;
        if mutation == ProjectionMutation::Ignore {
            return Ok(());
        }
        if let ProjectionMutation::Upsert(document) = &mutation
            && document
                .indexed_len_upper_bound()
                .map_err(ProjectionFailure::InvalidDocument)?
                > self.max_document_bytes
        {
            return Err(ProjectionFailure::InvalidDocument(
                SearchModelError::DocumentTooLarge,
            ));
        }

        self.project_resolved(
            event.id().as_uuid(),
            event.occurred_at(),
            tenant_id,
            &mutation,
        )
        .await
    }

    async fn project_resolved(
        &self,
        event_id: uuid::Uuid,
        occurred_at: time::OffsetDateTime,
        tenant_id: TenantId,
        mutation: &ProjectionMutation,
    ) -> Result<(), ProjectionFailure> {
        self.project_target(
            event_id,
            occurred_at,
            tenant_id,
            mutation,
            &self.schema,
            ProjectionTarget::Active(self.schema.clone()),
        )
        .await?;
        if let Some(reindex_schema) = &self.reindex_schema {
            self.project_target(
                event_id,
                occurred_at,
                tenant_id,
                mutation,
                reindex_schema,
                ProjectionTarget::Version(reindex_schema.clone()),
            )
            .await?;
        }
        Ok(())
    }

    async fn project_target(
        &self,
        event_id: uuid::Uuid,
        occurred_at: time::OffsetDateTime,
        tenant_id: TenantId,
        mutation: &ProjectionMutation,
        schema: &IndexSchema,
        target: ProjectionTarget,
    ) -> Result<(), ProjectionFailure> {
        let source_id = mutation
            .source_id()
            .ok_or(ProjectionFailure::InvalidEvent)?;
        let revision = mutation.revision().ok_or(ProjectionFailure::InvalidEvent)?;
        let operation = mutation
            .operation()
            .ok_or(ProjectionFailure::InvalidEvent)?;
        let context = ProjectionClaimContext::new(event_id, tenant_id, schema, occurred_at)
            .map_err(ProjectionFailure::Store)?;
        let request = ProjectionClaimRequest::for_operation(
            &context,
            source_id,
            revision,
            operation,
            self.projection_lease,
        )
        .map_err(ProjectionFailure::Store)?;
        let claim = self
            .ledger
            .claim(request)
            .await
            .map_err(ProjectionFailure::Store)?;
        let lease_token = match claim {
            ProjectionClaim::Acquired { lease_token } => lease_token,
            ProjectionClaim::AlreadyApplied | ProjectionClaim::Superseded => return Ok(()),
            ProjectionClaim::Busy => return Err(ProjectionFailure::Busy),
        };
        if let Err(error) = self.provider.apply(&target, tenant_id, mutation).await {
            self.ledger
                .fail(event_id, lease_token, error.failure_class())
                .await
                .map_err(ProjectionFailure::Store)?;
            return Err(ProjectionFailure::Provider(error));
        }
        self.ledger
            .complete(event_id, lease_token)
            .await
            .map_err(ProjectionFailure::Store)
    }

    fn publish_error(&self, failure: ProjectionFailure) -> PublishError {
        PublishError::new(self.failure_classes.for_failure(failure))
    }
}

impl OutboxPublisher for OutboxSearchProjector {
    fn publish<'event>(
        &'event self,
        event: &'event LeasedOutboxEvent,
    ) -> BoxFuture<'event, Result<(), PublishError>> {
        Box::pin(async move {
            self.project(event)
                .await
                .map_err(|failure| self.publish_error(failure))
        })
    }
}

/// Safe internal projection outcome used to select a prevalidated outbox failure class.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProjectionFailure {
    /// Event tenant metadata was absent or malformed.
    #[error("search projection event is invalid")]
    InvalidEvent,
    /// Authoritative source resolution failed.
    #[error(transparent)]
    Resolve(ProjectionResolveError),
    /// Projection document validation failed.
    #[error(transparent)]
    InvalidDocument(SearchModelError),
    /// Another live lease is applying a mutation for this source.
    #[error("search projection source is busy")]
    Busy,
    /// Durable ledger access failed.
    #[error(transparent)]
    Store(ProjectionStoreError),
    /// External provider access failed.
    #[error(transparent)]
    Provider(SearchProviderError),
}

/// Outbox projector construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProjectionBuildError {
    /// Search configuration failed validation.
    #[error("search projection configuration is invalid")]
    Configuration,
    /// A dual-write target did not share the active alias or was not a newer schema.
    #[error("search projection reindex target is invalid")]
    InvalidReindexTarget,
    /// A static failure class violated the outbox grammar.
    #[error("search projection failure class is invalid")]
    FailureClass,
}

struct FailureClasses {
    invalid_event: FailureClass,
    invalid_document: FailureClass,
    source_unavailable: FailureClass,
    busy: FailureClass,
    store: FailureClass,
    provider_timeout: FailureClass,
    provider_unavailable: FailureClass,
    provider_rejected: FailureClass,
    provider_invalid: FailureClass,
    provider_not_found: FailureClass,
    schema_conflict: FailureClass,
}

impl FailureClasses {
    fn new() -> Result<Self, ProjectionBuildError> {
        Ok(Self {
            invalid_event: failure_class("search_invalid_event")?,
            invalid_document: failure_class("search_invalid_document")?,
            source_unavailable: failure_class("search_source_unavailable")?,
            busy: failure_class("search_projection_busy")?,
            store: failure_class("search_projection_store")?,
            provider_timeout: failure_class("search_provider_timeout")?,
            provider_unavailable: failure_class("search_provider_unavailable")?,
            provider_rejected: failure_class("search_provider_rejected")?,
            provider_invalid: failure_class("search_provider_invalid_response")?,
            provider_not_found: failure_class("search_provider_not_found")?,
            schema_conflict: failure_class("search_provider_schema_conflict")?,
        })
    }

    fn for_failure(&self, failure: ProjectionFailure) -> FailureClass {
        match failure {
            ProjectionFailure::InvalidEvent
            | ProjectionFailure::Resolve(ProjectionResolveError::InvalidEvent) => {
                self.invalid_event.clone()
            }
            ProjectionFailure::Resolve(ProjectionResolveError::Unavailable) => {
                self.source_unavailable.clone()
            }
            ProjectionFailure::InvalidDocument(_) => self.invalid_document.clone(),
            ProjectionFailure::Busy => self.busy.clone(),
            ProjectionFailure::Store(_) => self.store.clone(),
            ProjectionFailure::Provider(SearchProviderError::Timeout) => {
                self.provider_timeout.clone()
            }
            ProjectionFailure::Provider(SearchProviderError::Unavailable) => {
                self.provider_unavailable.clone()
            }
            ProjectionFailure::Provider(SearchProviderError::Rejected) => {
                self.provider_rejected.clone()
            }
            ProjectionFailure::Provider(SearchProviderError::InvalidResponse) => {
                self.provider_invalid.clone()
            }
            ProjectionFailure::Provider(SearchProviderError::NotFound) => {
                self.provider_not_found.clone()
            }
            ProjectionFailure::Provider(SearchProviderError::SchemaConflict) => {
                self.schema_conflict.clone()
            }
        }
    }
}

fn failure_class(value: &'static str) -> Result<FailureClass, ProjectionBuildError> {
    FailureClass::try_from(value).map_err(|_| ProjectionBuildError::FailureClass)
}

/// Coordinates restartable staging/backfill/activation without treating indexed data as authority.
pub struct ReindexCoordinator {
    provider: Arc<dyn SearchProvider>,
    store: Arc<dyn ReindexStore>,
    ledger: Arc<dyn ProjectionLedger>,
    projection_lease: std::time::Duration,
}

impl ReindexCoordinator {
    /// Creates a reindex coordinator over injected provider and durable state ports.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError::Configuration`] when projection lease bounds are invalid.
    pub fn new(
        provider: Arc<dyn SearchProvider>,
        store: Arc<dyn ReindexStore>,
        ledger: Arc<dyn ProjectionLedger>,
        config: &SearchMeilisearchConfig,
    ) -> Result<Self, ReindexError> {
        config.validate().map_err(|_| ReindexError::Configuration)?;
        Ok(Self {
            provider,
            store,
            ledger,
            projection_lease: config.projection_lease,
        })
    }

    /// Registers the immutable schema and idempotently prepares its versioned staging index.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError`] for storage/provider failure or an invalid existing lifecycle state.
    pub async fn begin(&self, schema: &IndexSchema) -> Result<ReindexState, ReindexError> {
        let state = self
            .store
            .register(schema)
            .await
            .map_err(ReindexError::Store)?;
        match state.status {
            ReindexStatus::Preparing => {
                self.provider
                    .prepare_index(schema)
                    .await
                    .map_err(ReindexError::Provider)?;
                self.store
                    .begin_backfill(schema, state.generation)
                    .await
                    .map_err(ReindexError::Store)
            }
            ReindexStatus::Backfilling
            | ReindexStatus::Ready
            | ReindexStatus::Active
            | ReindexStatus::Retired => Ok(state),
        }
    }

    /// Applies one authoritative backfill mutation through the same version-scoped source fence as
    /// live dual writes. A copied older revision cannot overwrite a newer staging mutation.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError`] for a busy source fence, provider failure, or ledger failure.
    pub async fn project_backfill(
        &self,
        schema: &IndexSchema,
        tenant_id: TenantId,
        mutation: &ProjectionMutation,
    ) -> Result<(), ReindexError> {
        if mutation == &ProjectionMutation::Ignore {
            return Ok(());
        }
        let source_id = mutation.source_id().ok_or(ReindexError::InvalidMutation)?;
        let revision = mutation.revision().ok_or(ReindexError::InvalidMutation)?;
        let operation = mutation.operation().ok_or(ReindexError::InvalidMutation)?;
        let event_id = uuid::Uuid::now_v7();
        let context = ProjectionClaimContext::new(
            event_id,
            tenant_id,
            schema,
            time::OffsetDateTime::now_utc(),
        )
        .map_err(ReindexError::ProjectionStore)?;
        let request = ProjectionClaimRequest::for_operation(
            &context,
            source_id,
            revision,
            operation,
            self.projection_lease,
        )
        .map_err(ReindexError::ProjectionStore)?;
        let lease_token = match self
            .ledger
            .claim(request)
            .await
            .map_err(ReindexError::ProjectionStore)?
        {
            ProjectionClaim::Acquired { lease_token } => lease_token,
            ProjectionClaim::AlreadyApplied | ProjectionClaim::Superseded => return Ok(()),
            ProjectionClaim::Busy => return Err(ReindexError::Busy),
        };
        let target = ProjectionTarget::Version(schema.clone());
        if let Err(error) = self.provider.apply(&target, tenant_id, mutation).await {
            self.ledger
                .fail(event_id, lease_token, error.failure_class())
                .await
                .map_err(ReindexError::ProjectionStore)?;
            return Err(ReindexError::Provider(error));
        }
        self.ledger
            .complete(event_id, lease_token)
            .await
            .map_err(ReindexError::ProjectionStore)
    }

    /// Persists one completed backfill-page cursor with optimistic generation fencing.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError::Store`] on a stale generation or database failure.
    pub async fn advance(
        &self,
        schema: &IndexSchema,
        expected_generation: u64,
        cursor: &ReindexCursor,
        projected_delta: u32,
    ) -> Result<ReindexState, ReindexError> {
        self.store
            .advance(schema, expected_generation, cursor, projected_delta)
            .await
            .map_err(ReindexError::Store)
    }

    /// Marks a completely backfilled version ready for activation.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError::Store`] on a stale generation or database failure.
    pub async fn mark_ready(
        &self,
        schema: &IndexSchema,
        expected_generation: u64,
    ) -> Result<ReindexState, ReindexError> {
        self.store
            .mark_ready(schema, expected_generation)
            .await
            .map_err(ReindexError::Store)
    }

    /// Idempotently activates the ready provider version, then commits the durable alias mapping.
    ///
    /// The provider schema sentinel makes a retry after process exit safe: a completed swap returns
    /// [`crate::ActivationOutcome::AlreadyActive`] rather than swapping back.
    ///
    /// # Errors
    ///
    /// Returns [`ReindexError`] unless the durable state is ready/active and both operations succeed.
    pub async fn activate(&self, schema: &IndexSchema) -> Result<ReindexState, ReindexError> {
        let state = self
            .store
            .register(schema)
            .await
            .map_err(ReindexError::Store)?;
        if state.status == ReindexStatus::Active {
            return Ok(state);
        }
        if state.status != ReindexStatus::Ready {
            return Err(ReindexError::Store(ReindexStoreError::Conflict));
        }
        let _outcome = self
            .provider
            .activate_index(schema)
            .await
            .map_err(ReindexError::Provider)?;
        self.store
            .activate(schema, state.generation)
            .await
            .map_err(ReindexError::Store)
    }
}

/// Reindex coordination failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReindexError {
    /// Reindex configuration failed validation.
    #[error("search reindex configuration is invalid")]
    Configuration,
    /// A backfill mutation lacked a source identity or revision.
    #[error("search reindex mutation is invalid")]
    InvalidMutation,
    /// A live or recovering projection owns the staging source fence.
    #[error("search reindex source is busy")]
    Busy,
    /// Projection ledger access failed.
    #[error(transparent)]
    ProjectionStore(ProjectionStoreError),
    /// Durable state access failed.
    #[error(transparent)]
    Store(ReindexStoreError),
    /// Provider access failed.
    #[error(transparent)]
    Provider(SearchProviderError),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, HashMap},
        error::Error,
        sync::{Arc, Mutex},
    };

    use futures::future::BoxFuture;
    use rsk_outbox::LeasedOutboxEvent;
    use serde_json::json;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;
    use crate::{
        FieldName, IndexAlias, ProjectionDocument, SourceId, SourceRevision,
        testing::FakeSearchProvider,
    };

    #[derive(Default)]
    struct LedgerState {
        leases: HashMap<Uuid, u32>,
        completed: Vec<u32>,
        failed: Vec<u32>,
    }

    #[derive(Default)]
    struct RecordingLedger(Mutex<LedgerState>);

    impl ProjectionLedger for RecordingLedger {
        fn claim<'a>(
            &'a self,
            request: ProjectionClaimRequest<'a>,
        ) -> BoxFuture<'a, Result<ProjectionClaim, ProjectionStoreError>> {
            Box::pin(async move {
                let token = Uuid::now_v7();
                self.0
                    .lock()
                    .map_err(|_| ProjectionStoreError::Unavailable)?
                    .leases
                    .insert(token, request.schema_version());
                Ok(ProjectionClaim::Acquired { lease_token: token })
            })
        }

        fn complete(
            &self,
            _event_id: Uuid,
            lease_token: Uuid,
        ) -> BoxFuture<'_, Result<(), ProjectionStoreError>> {
            Box::pin(async move {
                let mut state = self
                    .0
                    .lock()
                    .map_err(|_| ProjectionStoreError::Unavailable)?;
                let version = state
                    .leases
                    .remove(&lease_token)
                    .ok_or(ProjectionStoreError::FenceLost)?;
                state.completed.push(version);
                Ok(())
            })
        }

        fn fail(
            &self,
            _event_id: Uuid,
            lease_token: Uuid,
            _failure_class: &'static str,
        ) -> BoxFuture<'_, Result<(), ProjectionStoreError>> {
            Box::pin(async move {
                let mut state = self
                    .0
                    .lock()
                    .map_err(|_| ProjectionStoreError::Unavailable)?;
                let version = state
                    .leases
                    .remove(&lease_token)
                    .ok_or(ProjectionStoreError::FenceLost)?;
                state.failed.push(version);
                Ok(())
            })
        }
    }

    struct IgnoredResolver;

    impl OutboxProjectionResolver for IgnoredResolver {
        fn resolve<'a>(
            &'a self,
            _event: &'a LeasedOutboxEvent,
            _tenant_id: TenantId,
        ) -> BoxFuture<'a, Result<ProjectionMutation, ProjectionResolveError>> {
            Box::pin(async { Ok(ProjectionMutation::Ignore) })
        }
    }

    fn schema(version: u32) -> Result<IndexSchema, SearchModelError> {
        IndexSchema::new(
            IndexAlias::new("records")?,
            version,
            vec![FieldName::new("title")?],
            Vec::new(),
        )
    }

    #[tokio::test]
    async fn staging_failure_does_not_complete_its_version_ledger() -> Result<(), Box<dyn Error>> {
        let provider = Arc::new(FakeSearchProvider::default());
        provider.enqueue_apply_result(Ok(()))?;
        provider.enqueue_apply_result(Err(SearchProviderError::Unavailable))?;
        let ledger = Arc::new(RecordingLedger::default());
        let projector = OutboxSearchProjector {
            provider: provider.clone(),
            ledger: ledger.clone(),
            resolver: Arc::new(IgnoredResolver),
            schema: schema(1)?,
            reindex_schema: Some(schema(2)?),
            projection_lease: std::time::Duration::from_secs(5),
            max_document_bytes: 65_536,
            failure_classes: FailureClasses::new()?,
        };
        let mut fields = BTreeMap::new();
        fields.insert("title".to_owned(), json!("current"));
        let mutation = ProjectionMutation::Upsert(ProjectionDocument::new(
            SourceId::new("record-one")?,
            SourceRevision::new(2)?,
            fields,
        )?);

        assert_eq!(
            projector
                .project_resolved(
                    Uuid::now_v7(),
                    OffsetDateTime::now_utc(),
                    TenantId::new(),
                    &mutation,
                )
                .await,
            Err(ProjectionFailure::Provider(
                SearchProviderError::Unavailable
            ))
        );
        let mutations = provider.mutations()?;
        assert!(matches!(&mutations[0].0, ProjectionTarget::Active(_)));
        assert!(matches!(&mutations[1].0, ProjectionTarget::Version(_)));
        let state = ledger
            .0
            .lock()
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        assert_eq!(state.completed, vec![1]);
        assert_eq!(state.failed, vec![2]);
        Ok(())
    }

    #[tokio::test]
    async fn active_schema_conflict_fails_instead_of_completing_ledger()
    -> Result<(), Box<dyn Error>> {
        let provider = Arc::new(FakeSearchProvider::default());
        provider.enqueue_apply_result(Err(SearchProviderError::SchemaConflict))?;
        let ledger = Arc::new(RecordingLedger::default());
        let projector = OutboxSearchProjector {
            provider,
            ledger: ledger.clone(),
            resolver: Arc::new(IgnoredResolver),
            schema: schema(1)?,
            reindex_schema: None,
            projection_lease: std::time::Duration::from_secs(5),
            max_document_bytes: 65_536,
            failure_classes: FailureClasses::new()?,
        };
        let mut fields = BTreeMap::new();
        fields.insert("title".to_owned(), json!("stale projector"));
        let mutation = ProjectionMutation::Upsert(ProjectionDocument::new(
            SourceId::new("record-stale-projector")?,
            SourceRevision::new(2)?,
            fields,
        )?);

        assert_eq!(
            projector
                .project_resolved(
                    Uuid::now_v7(),
                    OffsetDateTime::now_utc(),
                    TenantId::new(),
                    &mutation,
                )
                .await,
            Err(ProjectionFailure::Provider(
                SearchProviderError::SchemaConflict
            ))
        );
        let state = ledger
            .0
            .lock()
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        assert!(state.completed.is_empty());
        assert_eq!(state.failed, vec![1]);
        Ok(())
    }
}
