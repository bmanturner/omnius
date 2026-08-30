use std::{collections::BTreeMap, fmt, num::NonZeroU16, sync::Arc};

pub use omnius_privacy::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterName, AdapterWork,
    DataInventoryAdapter, EvidenceDigest, InventoryCategory, InventoryDescriptor, InventoryEffect,
    InventoryRegistry as PrivacyInventoryRegistry,
    InventoryRegistryError as PrivacyInventoryRegistryError, InventoryRequirement, LifecycleKind,
    LifecycleRequestId, RequiredInventoryManifest,
};
use thiserror::Error;

const REQUIRED_LLM_INVENTORY_COUNT: usize = 6;

/// Closed LLM data stores included in every privacy lifecycle fan-out.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LlmInventoryKind {
    /// Durable conversation and message data.
    Conversation,
    /// Usage facts removable where legal obligations permit.
    UsageMetadata,
    /// Uploaded or generated media and application-owned files.
    MediaObject,
    /// Application and provider prompt-cache records.
    Cache,
    /// Evaluation inputs, outputs, and derived artifacts.
    EvaluationArtifact,
    /// Provider-side retained data and deletion APIs.
    ProviderSide,
}

impl LlmInventoryKind {
    /// Every required LLM inventory kind in deterministic order.
    pub const ALL: [Self; REQUIRED_LLM_INVENTORY_COUNT] = [
        Self::Conversation,
        Self::UsageMetadata,
        Self::MediaObject,
        Self::Cache,
        Self::EvaluationArtifact,
        Self::ProviderSide,
    ];
}

/// One independently configured LLM member of the durable privacy inventory.
#[derive(Clone, Eq, PartialEq)]
pub struct LlmInventoryRequirement {
    kind: LlmInventoryKind,
    requirement: InventoryRequirement,
}

impl LlmInventoryRequirement {
    /// Creates a requirement with a stable adapter identity, category, and minimum revision.
    #[must_use]
    pub const fn new(
        kind: LlmInventoryKind,
        name: AdapterName,
        category: InventoryCategory,
        minimum_revision: NonZeroU16,
    ) -> Self {
        Self {
            kind,
            requirement: InventoryRequirement::new(name, category, minimum_revision),
        }
    }

    /// Returns the closed LLM inventory kind.
    #[must_use]
    pub const fn kind(&self) -> LlmInventoryKind {
        self.kind
    }

    /// Returns the stable privacy adapter identity.
    #[must_use]
    pub const fn adapter_name(&self) -> &AdapterName {
        self.requirement.name()
    }

    /// Returns the privacy inventory category.
    #[must_use]
    pub const fn category(&self) -> InventoryCategory {
        self.requirement.category()
    }

    /// Returns the minimum compatible privacy adapter revision.
    #[must_use]
    pub const fn minimum_revision(&self) -> NonZeroU16 {
        self.requirement.minimum_revision()
    }
}

impl fmt::Debug for LlmInventoryRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmInventoryRequirement")
            .field("kind", &self.kind)
            .field("adapter_name", &"[redacted]")
            .field("category", &self.category())
            .field("minimum_revision", &self.minimum_revision())
            .finish_non_exhaustive()
    }
}

/// Complete LLM fan-out plan consumed by the durable privacy lifecycle.
///
/// The privacy subsystem remains the sole owner of lifecycle requests, retries,
/// deadlines, legal holds, adapter revision snapshots, and monotonically increasing
/// mutation fences. The plan requires every closed LLM kind while allowing multiple
/// adapters for multi-store kinds such as cache, media, and evaluation artifacts.
#[derive(Clone)]
pub struct LlmInventoryPlan {
    requirements: BTreeMap<LlmInventoryKind, Vec<LlmInventoryRequirement>>,
    manifest: RequiredInventoryManifest,
}

impl LlmInventoryPlan {
    /// Validates a complete independent LLM inventory manifest fragment.
    ///
    /// # Errors
    ///
    /// Returns [`LlmInventoryPlanError`] for a missing LLM kind, a non-provider
    /// category for provider-side data, duplicate adapter names, or an invalid manifest.
    pub fn new(
        requirements: impl IntoIterator<Item = LlmInventoryRequirement>,
    ) -> Result<Self, LlmInventoryPlanError> {
        let mut by_kind = BTreeMap::<_, Vec<_>>::new();
        for requirement in requirements {
            let kind = requirement.kind();
            if kind == LlmInventoryKind::ProviderSide
                && requirement.category() != InventoryCategory::Provider
            {
                return Err(LlmInventoryPlanError::ProviderCategoryMismatch);
            }
            by_kind.entry(kind).or_default().push(requirement);
        }
        for required in LlmInventoryKind::ALL {
            if !by_kind.contains_key(&required) {
                return Err(LlmInventoryPlanError::MissingKind(required));
            }
        }

        let manifest = RequiredInventoryManifest::new(
            by_kind
                .values()
                .flatten()
                .map(|requirement| requirement.requirement.clone()),
        )?;
        Ok(Self {
            requirements: by_kind,
            manifest,
        })
    }

    /// Returns the total required LLM adapter count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requirements.values().map(Vec::len).sum()
    }

    /// Reports whether the plan is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }

    /// Borrows every required adapter for one closed LLM inventory kind.
    #[must_use]
    pub fn requirements_for(&self, kind: LlmInventoryKind) -> &[LlmInventoryRequirement] {
        self.requirements.get(&kind).map_or(&[], Vec::as_slice)
    }

    /// Borrows the validated LLM-only manifest fragment.
    ///
    /// Composition must merge [`Self::privacy_requirements`] with requirements
    /// contributed by non-LLM modules before constructing the process-wide privacy registry.
    #[must_use]
    pub const fn required_manifest(&self) -> &RequiredInventoryManifest {
        &self.manifest
    }

    /// Clones all canonical privacy requirements for process-wide manifest composition.
    pub fn privacy_requirements(&self) -> impl Iterator<Item = InventoryRequirement> + '_ {
        self.requirements
            .values()
            .flatten()
            .map(|requirement| requirement.requirement.clone())
    }

    /// Merges the complete LLM requirements with independently configured module requirements.
    ///
    /// # Errors
    ///
    /// Returns [`LlmInventoryPlanError`] when the exact process-wide manifest is duplicate,
    /// empty, or above the privacy subsystem's fixed bound.
    pub fn compose_manifest(
        &self,
        additional: impl IntoIterator<Item = InventoryRequirement>,
    ) -> Result<RequiredInventoryManifest, LlmInventoryPlanError> {
        Ok(RequiredInventoryManifest::new(
            self.privacy_requirements().chain(additional),
        )?)
    }

    /// Builds the process-wide privacy registry with exact LLM and non-LLM coverage.
    ///
    /// Applications call this during startup. Missing LLM adapters, unexpected adapters,
    /// category mismatches, and stale adapter revisions fail registry construction.
    ///
    /// # Errors
    ///
    /// Returns [`LlmInventoryPlanError`] for any manifest or exact registry mismatch.
    pub fn compose_registry(
        &self,
        additional: impl IntoIterator<Item = InventoryRequirement>,
        adapters: impl IntoIterator<Item = Arc<dyn DataInventoryAdapter>>,
    ) -> Result<PrivacyInventoryRegistry, LlmInventoryPlanError> {
        let manifest = self.compose_manifest(additional)?;
        Ok(PrivacyInventoryRegistry::new(manifest, adapters)?)
    }
}

impl fmt::Debug for LlmInventoryPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmInventoryPlan")
            .field("required_count", &self.len())
            .finish()
    }
}

/// Closed LLM inventory-plan construction and registry failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LlmInventoryPlanError {
    /// A required LLM inventory kind was absent.
    #[error("required LLM inventory kind is missing")]
    MissingKind(LlmInventoryKind),
    /// Provider-side data did not use the canonical provider inventory category.
    #[error("provider-side LLM inventory must use the provider category")]
    ProviderCategoryMismatch,
    /// The canonical privacy manifest or registry rejected the plan.
    #[error(transparent)]
    Privacy(#[from] PrivacyInventoryRegistryError),
}
