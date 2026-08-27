use std::{collections::BTreeMap, sync::Arc};

use omnius_auth_core::Principal;
use thiserror::Error;

use crate::{
    AuthorizedSource, BatchReauthorizer, IndexSchema, ReauthorizationError, SearchHit, SearchInput,
    SearchMeilisearchConfig, SearchModelError, SearchProvider, SearchProviderError, SearchResponse,
    SourceId, SourceRevision, TenantScopedQuery,
};

/// Tenant-fenced derived-search application service.
pub struct SearchService {
    provider: Arc<dyn SearchProvider>,
    reauthorizer: Arc<dyn BatchReauthorizer>,
    schema: IndexSchema,
    config: SearchMeilisearchConfig,
}

impl SearchService {
    /// Creates a service using one active versioned schema.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError::Configuration`] before retaining invalid provider configuration.
    pub fn new(
        provider: Arc<dyn SearchProvider>,
        reauthorizer: Arc<dyn BatchReauthorizer>,
        schema: IndexSchema,
        config: SearchMeilisearchConfig,
    ) -> Result<Self, SearchError> {
        config.validate().map_err(|_| SearchError::Configuration)?;
        Ok(Self {
            provider,
            reauthorizer,
            schema,
            config,
        })
    }

    /// Searches the derived index and returns only authoritative, current, authorized identities.
    ///
    /// The tenant is derived exclusively from the canonical principal. Every candidate is passed to
    /// one bounded batch reauthorization call. Provider totals and indexed presentation fields are
    /// deliberately not exposed.
    ///
    /// # Errors
    ///
    /// Returns [`SearchError`] for missing tenant context, invalid bounds, provider failure, or a
    /// malformed reauthorizer response.
    pub async fn search(
        &self,
        principal: &Principal,
        input: SearchInput,
    ) -> Result<SearchResponse, SearchError> {
        let tenant_id = principal.tenant_id.ok_or(SearchError::TenantRequired)?;
        let requested_limit = input.limit_for_service();
        let scoped = TenantScopedQuery::build(tenant_id, &self.schema, input, self.config.limits)
            .map_err(SearchError::InvalidInput)?;
        let page = self
            .provider
            .search(self.schema.alias(), &scoped)
            .await
            .map_err(SearchError::Provider)?;
        let candidates = page.into_hits();
        if candidates.len() > requested_limit
            || candidates.len() > self.config.limits.max_reauthorization_batch
        {
            return Err(SearchError::Provider(SearchProviderError::InvalidResponse));
        }

        let mut indexed = BTreeMap::<SourceId, SourceRevision>::new();
        for candidate in &candidates {
            if indexed
                .insert(candidate.source_id().clone(), candidate.revision())
                .is_some()
            {
                return Err(SearchError::Provider(SearchProviderError::InvalidResponse));
            }
        }

        let authorized = self
            .reauthorizer
            .reauthorize(principal, &candidates)
            .await
            .map_err(SearchError::Reauthorization)?;
        let authorized = validate_authorized(&indexed, authorized)?;
        let provider_page_full = candidates.len() == requested_limit;
        let hits = candidates
            .into_iter()
            .filter_map(|candidate| {
                authorized
                    .get(candidate.source_id())
                    .filter(|revision| **revision == candidate.revision())
                    .map(|revision| SearchHit::new(candidate.source_id().clone(), *revision))
            })
            .collect();
        Ok(SearchResponse::new(hits, provider_page_full))
    }

    /// Returns the active schema declaration used to validate every filter.
    #[must_use]
    pub const fn schema(&self) -> &IndexSchema {
        &self.schema
    }
}

/// Safe public search failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SearchError {
    /// Provider configuration failed validation.
    #[error("search service configuration is invalid")]
    Configuration,
    /// The canonical principal has no tenant context.
    #[error("tenant context is required for search")]
    TenantRequired,
    /// Query, filters, limit, offset, or document bounds were invalid.
    #[error("search input is invalid: {0}")]
    InvalidInput(SearchModelError),
    /// The provider failed with a redacted stable classification.
    #[error(transparent)]
    Provider(SearchProviderError),
    /// Authoritative result validation failed.
    #[error(transparent)]
    Reauthorization(ReauthorizationError),
}

fn validate_authorized(
    indexed: &BTreeMap<SourceId, SourceRevision>,
    authorized: Vec<AuthorizedSource>,
) -> Result<BTreeMap<SourceId, SourceRevision>, SearchError> {
    let mut validated = BTreeMap::new();
    for source in authorized {
        let Some(indexed_revision) = indexed.get(source.source_id()) else {
            return Err(SearchError::Reauthorization(
                ReauthorizationError::InvalidResponse,
            ));
        };
        if *indexed_revision != source.revision() {
            continue;
        }
        if validated
            .insert(source.source_id().clone(), source.revision())
            .is_some()
        {
            return Err(SearchError::Reauthorization(
                ReauthorizationError::InvalidResponse,
            ));
        }
    }
    Ok(validated)
}
