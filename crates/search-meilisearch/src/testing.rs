use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{Arc, Mutex},
};

use futures::future::BoxFuture;
use omnius_auth_core::{Principal, TenantId};

use crate::{
    ActivationOutcome, AuthorizedSource, BatchReauthorizer, IndexAlias, IndexSchema,
    ProjectionMutation, ProjectionTarget, ProviderPage, ReauthorizationError, SearchCandidate,
    SearchProvider, SearchProviderError, SourceId, SourceRevision, TenantScopedQuery,
};

/// Captured provider query metadata. Debug output redacts tenant, query, and filter values.
#[derive(Clone)]
pub struct CapturedSearch {
    alias: IndexAlias,
    tenant_id: TenantId,
    query: String,
    rendered_filter: String,
    limit: usize,
    offset: usize,
}

impl CapturedSearch {
    /// Returns the logical alias.
    #[must_use]
    pub const fn alias(&self) -> &IndexAlias {
        &self.alias
    }

    /// Returns the canonical tenant supplied by the service.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Borrows captured query text for deterministic tests.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Borrows the exact provider filter for tenant-fence contract assertions.
    #[must_use]
    pub fn rendered_filter(&self) -> &str {
        &self.rendered_filter
    }

    /// Returns the bounded hit count.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the bounded offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Debug for CapturedSearch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapturedSearch")
            .field("alias", &self.alias)
            .field("tenant_id", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("rendered_filter", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("offset", &self.offset)
            .finish()
    }
}

/// One projection mutation captured by [`FakeSearchProvider`].
pub type CapturedMutation = (ProjectionTarget, TenantId, ProjectionMutation);

type CapturedAuthorizationCall = (Option<TenantId>, Vec<(SourceId, SourceRevision)>);

#[derive(Default)]
struct FakeProviderState {
    pages: VecDeque<Result<ProviderPage, SearchProviderError>>,
    apply_results: VecDeque<Result<(), SearchProviderError>>,
    searches: Vec<CapturedSearch>,
    mutations: Vec<CapturedMutation>,
    prepared: Vec<IndexSchema>,
    activated: Vec<IndexSchema>,
    health_error: Option<SearchProviderError>,
}

/// Deterministic provider fake for service, projector, health, and reindex contracts.
#[derive(Clone, Default)]
pub struct FakeSearchProvider {
    state: Arc<Mutex<FakeProviderState>>,
}

impl fmt::Debug for FakeSearchProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeSearchProvider")
            .finish_non_exhaustive()
    }
}

impl FakeSearchProvider {
    /// Enqueues one successful provider page from source/revision pairs.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if the fake's synchronization was poisoned.
    pub fn enqueue_hits(
        &self,
        hits: Vec<(SourceId, SourceRevision)>,
    ) -> Result<(), SearchProviderError> {
        let page = ProviderPage::new(
            hits.into_iter()
                .map(|(source_id, revision)| SearchCandidate::new(source_id, revision))
                .collect(),
        );
        self.enqueue_page(Ok(page))
    }

    /// Enqueues a success or safe provider failure.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if synchronization was poisoned.
    pub fn enqueue_page(
        &self,
        page: Result<ProviderPage, SearchProviderError>,
    ) -> Result<(), SearchProviderError> {
        self.state
            .lock()
            .map_err(|_| SearchProviderError::Unavailable)?
            .pages
            .push_back(page);
        Ok(())
    }

    /// Enqueues one projection-apply success or failure.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if synchronization was poisoned.
    pub fn enqueue_apply_result(
        &self,
        result: Result<(), SearchProviderError>,
    ) -> Result<(), SearchProviderError> {
        self.state
            .lock()
            .map_err(|_| SearchProviderError::Unavailable)?
            .apply_results
            .push_back(result);
        Ok(())
    }

    /// Configures subsequent health checks.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if synchronization was poisoned.
    pub fn set_health_error(
        &self,
        error: Option<SearchProviderError>,
    ) -> Result<(), SearchProviderError> {
        self.state
            .lock()
            .map_err(|_| SearchProviderError::Unavailable)?
            .health_error = error;
        Ok(())
    }

    /// Returns captured searches.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if synchronization was poisoned.
    pub fn searches(&self) -> Result<Vec<CapturedSearch>, SearchProviderError> {
        self.state
            .lock()
            .map(|state| state.searches.clone())
            .map_err(|_| SearchProviderError::Unavailable)
    }

    /// Returns captured projection mutations.
    ///
    /// # Errors
    ///
    /// Returns [`SearchProviderError::Unavailable`] if synchronization was poisoned.
    pub fn mutations(&self) -> Result<Vec<CapturedMutation>, SearchProviderError> {
        self.state
            .lock()
            .map(|state| state.mutations.clone())
            .map_err(|_| SearchProviderError::Unavailable)
    }
}

impl SearchProvider for FakeSearchProvider {
    fn search<'a>(
        &'a self,
        alias: &'a IndexAlias,
        query: &'a TenantScopedQuery,
    ) -> BoxFuture<'a, Result<ProviderPage, SearchProviderError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SearchProviderError::Unavailable)?;
            state.searches.push(CapturedSearch {
                alias: alias.clone(),
                tenant_id: query.tenant_id(),
                query: query.query().to_owned(),
                rendered_filter: query.rendered_filter().to_owned(),
                limit: query.limit(),
                offset: query.offset(),
            });
            state
                .pages
                .pop_front()
                .unwrap_or_else(|| Ok(ProviderPage::new(Vec::new())))
        })
    }

    fn apply<'a>(
        &'a self,
        target: &'a ProjectionTarget,
        tenant_id: TenantId,
        mutation: &'a ProjectionMutation,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SearchProviderError::Unavailable)?;
            state
                .mutations
                .push((target.clone(), tenant_id, mutation.clone()));
            state.apply_results.pop_front().unwrap_or(Ok(()))
        })
    }

    fn prepare_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| SearchProviderError::Unavailable)?
                .prepared
                .push(schema.clone());
            Ok(())
        })
    }

    fn activate_index<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<ActivationOutcome, SearchProviderError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| SearchProviderError::Unavailable)?;
            let outcome = if state.activated.contains(schema) {
                ActivationOutcome::AlreadyActive
            } else {
                state.activated.push(schema.clone());
                ActivationOutcome::Activated
            };
            Ok(outcome)
        })
    }

    fn health<'a>(
        &'a self,
        _schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<(), SearchProviderError>> {
        Box::pin(async move {
            match self
                .state
                .lock()
                .map_err(|_| SearchProviderError::Unavailable)?
                .health_error
            {
                Some(error) => Err(error),
                None => Ok(()),
            }
        })
    }
}

#[derive(Default)]
struct FakeReauthorizerState {
    current: BTreeMap<SourceId, SourceRevision>,
    calls: Vec<CapturedAuthorizationCall>,
    error: Option<ReauthorizationError>,
}

/// Deterministic authoritative existence/revision/authorization fake.
#[derive(Clone, Default)]
pub struct FakeBatchReauthorizer {
    state: Arc<Mutex<FakeReauthorizerState>>,
}

impl fmt::Debug for FakeBatchReauthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBatchReauthorizer")
            .finish_non_exhaustive()
    }
}

impl FakeBatchReauthorizer {
    /// Makes exactly one source revision visible. A different revision is treated as stale.
    ///
    /// # Errors
    ///
    /// Returns [`ReauthorizationError::Unavailable`] if synchronization was poisoned.
    pub fn authorize(
        &self,
        source_id: SourceId,
        revision: SourceRevision,
    ) -> Result<(), ReauthorizationError> {
        self.state
            .lock()
            .map_err(|_| ReauthorizationError::Unavailable)?
            .current
            .insert(source_id, revision);
        Ok(())
    }

    /// Removes a source from authoritative visibility.
    ///
    /// # Errors
    ///
    /// Returns [`ReauthorizationError::Unavailable`] if synchronization was poisoned.
    pub fn remove(&self, source_id: &SourceId) -> Result<(), ReauthorizationError> {
        self.state
            .lock()
            .map_err(|_| ReauthorizationError::Unavailable)?
            .current
            .remove(source_id);
        Ok(())
    }

    /// Configures a safe failure for subsequent calls.
    ///
    /// # Errors
    ///
    /// Returns [`ReauthorizationError::Unavailable`] if synchronization was poisoned.
    pub fn set_error(
        &self,
        error: Option<ReauthorizationError>,
    ) -> Result<(), ReauthorizationError> {
        self.state
            .lock()
            .map_err(|_| ReauthorizationError::Unavailable)?
            .error = error;
        Ok(())
    }

    /// Returns the number of batch calls.
    ///
    /// # Errors
    ///
    /// Returns [`ReauthorizationError::Unavailable`] if synchronization was poisoned.
    pub fn call_count(&self) -> Result<usize, ReauthorizationError> {
        self.state
            .lock()
            .map(|state| state.calls.len())
            .map_err(|_| ReauthorizationError::Unavailable)
    }
}

impl BatchReauthorizer for FakeBatchReauthorizer {
    fn reauthorize<'a>(
        &'a self,
        principal: &'a Principal,
        candidates: &'a [SearchCandidate],
    ) -> BoxFuture<'a, Result<Vec<AuthorizedSource>, ReauthorizationError>> {
        Box::pin(async move {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ReauthorizationError::Unavailable)?;
            if let Some(error) = state.error {
                return Err(error);
            }
            state.calls.push((
                principal.tenant_id,
                candidates
                    .iter()
                    .map(|candidate| (candidate.source_id().clone(), candidate.revision()))
                    .collect(),
            ));
            Ok(candidates
                .iter()
                .filter_map(|candidate| {
                    state
                        .current
                        .get(candidate.source_id())
                        .filter(|revision| **revision == candidate.revision())
                        .map(|revision| {
                            AuthorizedSource::new(candidate.source_id().clone(), *revision)
                        })
                })
                .collect())
        })
    }
}
