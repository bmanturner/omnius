use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_ID_BYTES: usize = 256;

/// One independently matchable provider/model capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    /// Plain text input.
    TextInput,
    /// Image input.
    ImageInput,
    /// Audio input.
    AudioInput,
    /// Video input.
    VideoInput,
    /// File input.
    FileInput,
    /// Resource-reference input.
    ResourceInput,
    /// Plain text output.
    TextOutput,
    /// Structured JSON output.
    StructuredOutput,
    /// Image output.
    ImageOutput,
    /// Audio output.
    AudioOutput,
    /// Video output.
    VideoOutput,
    /// File output.
    FileOutput,
    /// Resource-reference output.
    ResourceOutput,
    /// Citation or annotation output.
    AnnotationOutput,
    /// Provider-executed step output.
    ExecutionStepOutput,
    /// Provider-native strict JSON Schema output.
    StrictJsonSchema,
    /// Provider-native strict tool/function JSON output.
    StrictToolOutput,
    /// Client-defined tool calls.
    Tools,
    /// Multiple tool calls in one turn.
    ParallelToolCalls,
    /// Incremental response streaming.
    Streaming,
    /// Resumable provider conversations.
    ResumableConversations,
    /// Source citations.
    Citations,
    /// Grounding annotations.
    Grounding,
    /// Token scores or log probabilities.
    TokenScores,
    /// Provider safety metadata.
    SafetyMetadata,
    /// Provider search results.
    SearchResults,
    /// Provider-executed steps.
    ProviderExecutedSteps,
    /// Safe reasoning summaries.
    ReasoningSummaries,
    /// Opaque provider reasoning state.
    OpaqueReasoningState,
    /// Embedding operation support.
    Embeddings,
    /// Reranking operation support.
    Reranking,
    /// Transcription operation support.
    Transcription,
    /// Speech generation support.
    SpeechGeneration,
    /// Image generation support.
    ImageGeneration,
    /// Video generation support.
    VideoGeneration,
    /// Provider prompt caching.
    PromptCaching,
    /// Explicit provider cache controls.
    CacheControls,
}

/// Provenance category for one capability claim.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityEvidenceSource {
    /// Operator-reviewed configuration.
    Configured,
    /// Versioned provider documentation.
    ProviderDocumentation,
    /// Deterministic compatibility cassette.
    Cassette,
    /// Authenticated provider discovery.
    ProviderDiscovery,
}

/// Versioned evidence supporting one capability claim.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityEvidence {
    source: CapabilityEvidenceSource,
    revision: String,
}

impl CapabilityEvidence {
    /// Creates evidence tied to a non-empty source revision.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::InvalidDeclaration`] for an invalid revision.
    pub fn new(
        source: CapabilityEvidenceSource,
        revision: impl Into<String>,
    ) -> Result<Self, CapabilityRegistryError> {
        let revision = revision.into();
        validate_id(&revision)?;
        Ok(Self { source, revision })
    }

    /// Returns the evidence source.
    #[must_use]
    pub const fn source(&self) -> CapabilityEvidenceSource {
        self.source
    }

    /// Returns the evidence revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// Exact provider/model/revision identity used for capability admission.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilityKey {
    provider: String,
    model: String,
    revision: String,
}

impl ModelCapabilityKey {
    /// Creates an exact runtime model identity.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::InvalidDeclaration`] when an identity is empty or too large.
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, CapabilityRegistryError> {
        let value = Self {
            provider: provider.into(),
            model: model.into(),
            revision: revision.into(),
        };
        validate_id(&value.provider)?;
        validate_id(&value.model)?;
        validate_id(&value.revision)?;
        Ok(value)
    }

    /// Returns the provider identifier.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the runtime model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the declared model revision.
    #[must_use]
    pub fn revision(&self) -> &str {
        &self.revision
    }
}

/// Evidence-backed capability declaration for one exact model revision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilityDeclaration {
    key: ModelCapabilityKey,
    registry_revision: String,
    evidence: BTreeMap<ModelCapability, CapabilityEvidence>,
    regions: BTreeSet<String>,
    max_context_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
}

impl ModelCapabilityDeclaration {
    /// Creates a declaration from explicit evidence rather than model-name inference.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::InvalidDeclaration`] for invalid revisions, regions, or limits.
    pub fn new(
        key: ModelCapabilityKey,
        registry_revision: impl Into<String>,
        evidence: BTreeMap<ModelCapability, CapabilityEvidence>,
        regions: BTreeSet<String>,
        max_context_tokens: Option<u64>,
        max_output_tokens: Option<u64>,
    ) -> Result<Self, CapabilityRegistryError> {
        let registry_revision = registry_revision.into();
        validate_id(&registry_revision)?;
        for region in &regions {
            validate_id(region)?;
        }
        if max_context_tokens == Some(0) || max_output_tokens == Some(0) {
            return Err(CapabilityRegistryError::InvalidDeclaration);
        }
        Ok(Self {
            key,
            registry_revision,
            evidence,
            regions,
            max_context_tokens,
            max_output_tokens,
        })
    }

    /// Returns the exact model identity.
    #[must_use]
    pub const fn key(&self) -> &ModelCapabilityKey {
        &self.key
    }

    /// Returns the registry revision that admitted this declaration.
    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    /// Returns the declared capabilities and their evidence.
    #[must_use]
    pub const fn evidence(&self) -> &BTreeMap<ModelCapability, CapabilityEvidence> {
        &self.evidence
    }

    /// Returns explicitly declared regions.
    #[must_use]
    pub const fn regions(&self) -> &BTreeSet<String> {
        &self.regions
    }

    /// Returns the maximum context size when declared.
    #[must_use]
    pub const fn max_context_tokens(&self) -> Option<u64> {
        self.max_context_tokens
    }

    /// Returns the maximum output size when declared.
    #[must_use]
    pub const fn max_output_tokens(&self) -> Option<u64> {
        self.max_output_tokens
    }

    /// Reports whether this exact declaration contains a capability claim.
    #[must_use]
    pub fn supports(&self, capability: ModelCapability) -> bool {
        self.evidence.contains_key(&capability)
    }
}

/// Required and preferred constraints for one exact model target.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModelCapabilityRequirements {
    required: BTreeSet<ModelCapability>,
    preferred: BTreeSet<ModelCapability>,
    region: Option<String>,
    minimum_context_tokens: Option<u64>,
    minimum_output_tokens: Option<u64>,
}

impl ModelCapabilityRequirements {
    /// Creates capability requirements.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::InvalidRequirements`] for overlap, invalid region, or zero limits.
    pub fn new(
        required: BTreeSet<ModelCapability>,
        preferred: BTreeSet<ModelCapability>,
        region: Option<String>,
        minimum_context_tokens: Option<u64>,
        minimum_output_tokens: Option<u64>,
    ) -> Result<Self, CapabilityRegistryError> {
        if !required.is_disjoint(&preferred)
            || minimum_context_tokens == Some(0)
            || minimum_output_tokens == Some(0)
        {
            return Err(CapabilityRegistryError::InvalidRequirements);
        }
        if let Some(region) = &region {
            validate_id(region).map_err(|_| CapabilityRegistryError::InvalidRequirements)?;
        }
        Ok(Self {
            required,
            preferred,
            region,
            minimum_context_tokens,
            minimum_output_tokens,
        })
    }

    /// Returns the hard capability requirements.
    #[must_use]
    pub const fn required(&self) -> &BTreeSet<ModelCapability> {
        &self.required
    }

    /// Returns the soft capability preferences.
    #[must_use]
    pub const fn preferred(&self) -> &BTreeSet<ModelCapability> {
        &self.preferred
    }
}

/// Successful exact-target admission with observable unmet preferences.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelCapabilityAdmission {
    key: ModelCapabilityKey,
    registry_revision: String,
    unmet_preferred: BTreeSet<ModelCapability>,
}

impl ModelCapabilityAdmission {
    /// Returns the exact admitted model target.
    #[must_use]
    pub const fn key(&self) -> &ModelCapabilityKey {
        &self.key
    }

    /// Returns the declaration registry revision.
    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    /// Returns preferences that were not satisfied.
    #[must_use]
    pub const fn unmet_preferred(&self) -> &BTreeSet<ModelCapability> {
        &self.unmet_preferred
    }
}

/// Immutable exact-target capability registry.
#[derive(Clone, Debug, Default)]
pub struct ModelCapabilityRegistry {
    declarations: BTreeMap<ModelCapabilityKey, ModelCapabilityDeclaration>,
}

impl ModelCapabilityRegistry {
    /// Builds a registry and rejects duplicate exact model identities.
    ///
    /// # Errors
    ///
    /// Returns [`CapabilityRegistryError::DuplicateDeclaration`] for duplicates.
    pub fn new(
        declarations: impl IntoIterator<Item = ModelCapabilityDeclaration>,
    ) -> Result<Self, CapabilityRegistryError> {
        let mut registry = Self::default();
        for declaration in declarations {
            let key = declaration.key.clone();
            if registry.declarations.insert(key, declaration).is_some() {
                return Err(CapabilityRegistryError::DuplicateDeclaration);
            }
        }
        Ok(registry)
    }

    /// Looks up one exact provider/model/revision declaration.
    #[must_use]
    pub fn get(&self, key: &ModelCapabilityKey) -> Option<&ModelCapabilityDeclaration> {
        self.declarations.get(key)
    }

    /// Admits only the requested exact target; this method never chooses or reroutes to another model.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the exact declaration or any hard requirement is unavailable.
    pub fn admit_exact(
        &self,
        key: &ModelCapabilityKey,
        requirements: &ModelCapabilityRequirements,
    ) -> Result<ModelCapabilityAdmission, CapabilityRegistryError> {
        let declaration = self
            .declarations
            .get(key)
            .ok_or(CapabilityRegistryError::UnknownModelRevision)?;
        let missing = requirements
            .required
            .iter()
            .copied()
            .filter(|capability| !declaration.supports(*capability))
            .collect::<BTreeSet<_>>();
        if !missing.is_empty() {
            return Err(CapabilityRegistryError::UnsupportedRequirements { missing });
        }
        if requirements
            .region
            .as_ref()
            .is_some_and(|region| !declaration.regions.contains(region))
        {
            return Err(CapabilityRegistryError::RegionUnavailable);
        }
        if requirements.minimum_context_tokens.is_some_and(|minimum| {
            declaration
                .max_context_tokens
                .is_none_or(|maximum| maximum < minimum)
        }) || requirements.minimum_output_tokens.is_some_and(|minimum| {
            declaration
                .max_output_tokens
                .is_none_or(|maximum| maximum < minimum)
        }) {
            return Err(CapabilityRegistryError::InsufficientLimits);
        }
        let unmet_preferred = requirements
            .preferred
            .iter()
            .copied()
            .filter(|capability| !declaration.supports(*capability))
            .collect();
        Ok(ModelCapabilityAdmission {
            key: declaration.key.clone(),
            registry_revision: declaration.registry_revision.clone(),
            unmet_preferred,
        })
    }
}

/// Value-free capability declaration or admission failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum CapabilityRegistryError {
    /// A declaration identifier, region, or limit is invalid.
    #[error("model capability declaration is invalid")]
    InvalidDeclaration,
    /// Requirement sets, region, or limits are invalid.
    #[error("model capability requirements are invalid")]
    InvalidRequirements,
    /// The same exact provider/model/revision was declared twice.
    #[error("model capability declaration is duplicated")]
    DuplicateDeclaration,
    /// The exact provider/model/revision has no evidence-backed declaration.
    #[error("model capability revision is unknown")]
    UnknownModelRevision,
    /// One or more hard capabilities are absent.
    #[error("model capability requirements are unsupported")]
    UnsupportedRequirements {
        /// Deterministically ordered missing capabilities.
        missing: BTreeSet<ModelCapability>,
    },
    /// The exact model is not declared in the required region.
    #[error("model capability region is unavailable")]
    RegionUnavailable,
    /// Declared context or output limits do not satisfy the request.
    #[error("model capability limits are insufficient")]
    InsufficientLimits,
}

impl CapabilityRegistryError {
    /// Returns missing hard capabilities for an unsupported-requirements error.
    #[must_use]
    pub const fn missing(&self) -> Option<&BTreeSet<ModelCapability>> {
        match self {
            Self::UnsupportedRequirements { missing } => Some(missing),
            _ => None,
        }
    }
}

fn validate_id(value: &str) -> Result<(), CapabilityRegistryError> {
    if value.trim().is_empty() || value.len() > MAX_ID_BYTES {
        Err(CapabilityRegistryError::InvalidDeclaration)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> Result<ModelCapabilityDeclaration, CapabilityRegistryError> {
        let evidence = BTreeMap::from([
            (
                ModelCapability::TextInput,
                CapabilityEvidence::new(CapabilityEvidenceSource::Cassette, "cassette-v1")?,
            ),
            (
                ModelCapability::TextOutput,
                CapabilityEvidence::new(
                    CapabilityEvidenceSource::ProviderDocumentation,
                    "docs-2026-08-24",
                )?,
            ),
            (
                ModelCapability::Tools,
                CapabilityEvidence::new(CapabilityEvidenceSource::Cassette, "tools-v2")?,
            ),
        ]);
        ModelCapabilityDeclaration::new(
            ModelCapabilityKey::new("provider-a", "runtime-model", "2026-08")?,
            "registry-7",
            evidence,
            BTreeSet::from(["us-east".to_owned()]),
            Some(128_000),
            Some(8_192),
        )
    }

    #[test]
    fn exact_admission_reports_preferences_without_downgrading() -> Result<(), Box<dyn Error>> {
        let declaration = declaration()?;
        let key = declaration.key().clone();
        let registry = ModelCapabilityRegistry::new([declaration])?;
        let requirements = ModelCapabilityRequirements::new(
            BTreeSet::from([ModelCapability::TextInput, ModelCapability::Tools]),
            BTreeSet::from([ModelCapability::Citations]),
            Some("us-east".to_owned()),
            Some(100_000),
            Some(4_096),
        )?;

        let admission = registry.admit_exact(&key, &requirements)?;
        assert_eq!(admission.key(), &key);
        assert_eq!(admission.registry_revision(), "registry-7");
        assert_eq!(
            admission.unmet_preferred(),
            &BTreeSet::from([ModelCapability::Citations])
        );
        Ok(())
    }

    #[test]
    fn hard_requirement_failure_is_typed_and_deterministic() -> Result<(), Box<dyn Error>> {
        let declaration = declaration()?;
        let key = declaration.key().clone();
        let registry = ModelCapabilityRegistry::new([declaration])?;
        let requirements = ModelCapabilityRequirements::new(
            BTreeSet::from([
                ModelCapability::AudioInput,
                ModelCapability::StrictJsonSchema,
            ]),
            BTreeSet::new(),
            None,
            None,
            None,
        )?;

        let Err(error) = registry.admit_exact(&key, &requirements) else {
            return Err("missing hard capabilities were admitted".into());
        };
        assert_eq!(
            error.missing(),
            Some(&BTreeSet::from([
                ModelCapability::AudioInput,
                ModelCapability::StrictJsonSchema,
            ]))
        );
        assert!(!format!("{error:?}").contains("runtime-model"));
        Ok(())
    }

    #[test]
    fn unknown_exact_revision_never_reroutes() -> Result<(), Box<dyn Error>> {
        let registry = ModelCapabilityRegistry::new([declaration()?])?;
        let other_revision = ModelCapabilityKey::new("provider-a", "runtime-model", "future")?;
        let Err(error) =
            registry.admit_exact(&other_revision, &ModelCapabilityRequirements::default())
        else {
            return Err("unknown exact revision was admitted".into());
        };
        assert_eq!(error, CapabilityRegistryError::UnknownModelRevision);
        Ok(())
    }

    #[test]
    fn duplicate_evidence_revision_is_rejected() -> Result<(), Box<dyn Error>> {
        let declaration = declaration()?;
        let Err(error) = ModelCapabilityRegistry::new([declaration.clone(), declaration]) else {
            return Err("duplicate exact declaration was accepted".into());
        };
        assert_eq!(error, CapabilityRegistryError::DuplicateDeclaration);
        Ok(())
    }

    use std::error::Error;
}
