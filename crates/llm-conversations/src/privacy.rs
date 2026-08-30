use async_trait::async_trait;
use omnius_privacy::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterName, AdapterWork,
    DataInventoryAdapter, InventoryCategory, InventoryDescriptor, PrivacyValueError,
};

use crate::{ConversationAuthorization, ConversationRepositoryError, ConversationRepositoryResult};

/// Persistence port used by the canonical privacy inventory adapter.
///
/// Implementations must apply the tenant and principal filters, lifecycle request identity,
/// adapter identity, attempt, and monotonic fence in the same durable transaction as the
/// mutation. Exact replays return the original content-free evidence. A lower fence or changed
/// immutable request facts return [`ConversationRepositoryError::InvalidData`].
#[async_trait]
pub trait ConversationInventoryRepository: Send + Sync {
    /// Reconciles export, deletion, anonymization, retention, or legal-hold work.
    async fn reconcile_conversation_inventory(
        &self,
        authorization: &ConversationAuthorization,
        descriptor: &InventoryDescriptor,
        work: &AdapterWork,
    ) -> ConversationRepositoryResult<AdapterEvidence>;
}

/// Canonical privacy inventory adapter for tenant- and principal-owned conversation data.
///
/// Tenant-wide work without an authenticated subject is rejected rather than weaken the
/// conversation repository's mandatory tenant-plus-principal authorization boundary.
pub struct ConversationDataInventoryAdapter<R> {
    descriptor: InventoryDescriptor,
    repository: R,
}

impl<R> ConversationDataInventoryAdapter<R> {
    /// Creates revision 1 of the stable PostgreSQL conversation inventory adapter.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyValueError`] only if the compile-time stable adapter name violates the
    /// canonical privacy identifier grammar.
    pub fn new(repository: R) -> Result<Self, PrivacyValueError> {
        let name = AdapterName::new("llm.conversations")?;
        Ok(Self {
            descriptor: InventoryDescriptor::new(name, InventoryCategory::PostgreSql),
            repository,
        })
    }

    /// Borrows the backing persistence port.
    #[must_use]
    pub const fn repository(&self) -> &R {
        &self.repository
    }
}

impl<R> std::fmt::Debug for ConversationDataInventoryAdapter<R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConversationDataInventoryAdapter")
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

impl<R> DataInventoryAdapter for ConversationDataInventoryAdapter<R>
where
    R: ConversationInventoryRepository,
{
    fn descriptor(&self) -> &InventoryDescriptor {
        &self.descriptor
    }

    fn reconcile<'a>(&'a self, work: &'a AdapterWork) -> AdapterFuture<'a> {
        Box::pin(async move {
            let Some(principal_id) = work.subject_id else {
                return Err(AdapterFailure::new(
                    AdapterFailureCode::UnsupportedOperation,
                ));
            };
            let authorization = ConversationAuthorization::new(work.tenant_id, principal_id);
            self.repository
                .reconcile_conversation_inventory(&authorization, &self.descriptor, work)
                .await
                .map_err(map_repository_error)
        })
    }
}

const fn map_repository_error(error: ConversationRepositoryError) -> AdapterFailure {
    let code = match error {
        ConversationRepositoryError::Unavailable => AdapterFailureCode::Unavailable,
        ConversationRepositoryError::InvalidData => AdapterFailureCode::InvalidState,
        ConversationRepositoryError::Timeout => AdapterFailureCode::Timeout,
    };
    AdapterFailure::new(code)
}
