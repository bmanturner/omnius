use std::collections::{BTreeMap, BTreeSet};

use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, CapabilityRegistryError, ModelCapability,
    ModelCapabilityDeclaration, ModelCapabilityKey,
};

/// Registry schema revision for Bedrock completion and streaming declarations.
pub const BEDROCK_CAPABILITY_REGISTRY_REVISION: &str = "bedrock-rig-0.42.0-2026-08-30";

/// Builds the deterministic evidence-backed Bedrock completion and streaming fixture.
///
/// Model identifiers and model revisions remain runtime data. The declaration
/// claims only the canonical text completion and stream path implemented by
/// this adapter; model-specific tools, media, structured output, citations,
/// reasoning, limits, and other capabilities require separate evidence.
///
/// # Errors
///
/// Returns a typed capability-registry error when any runtime identifier or
/// evidence revision is empty or exceeds the core registry bounds.
pub fn capability_declaration(
    model: String,
    revision: String,
    region: String,
    evidence_revision: String,
) -> Result<ModelCapabilityDeclaration, CapabilityRegistryError> {
    let evidence = CapabilityEvidence::new(
        CapabilityEvidenceSource::ProviderDocumentation,
        evidence_revision,
    )?;
    let capabilities = BTreeMap::from([
        (ModelCapability::TextInput, evidence.clone()),
        (ModelCapability::TextOutput, evidence.clone()),
        (ModelCapability::Streaming, evidence),
    ]);
    let key = ModelCapabilityKey::new("bedrock", model, revision)?;
    ModelCapabilityDeclaration::new(
        key,
        BEDROCK_CAPABILITY_REGISTRY_REVISION,
        capabilities,
        BTreeSet::from([region]),
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use omnius_llm_core::{CapabilityEvidenceSource, ModelCapability};

    use super::{BEDROCK_CAPABILITY_REGISTRY_REVISION, capability_declaration};

    #[test]
    fn fixture_declares_only_revisioned_text_completion_and_streaming()
    -> Result<(), omnius_llm_core::CapabilityRegistryError> {
        let evidence_revision = "rig-bedrock-0.42.0-source";
        let declaration = capability_declaration(
            "runtime-model-id".to_owned(),
            "model-revision-2026-08-30".to_owned(),
            "us-east-1".to_owned(),
            evidence_revision.to_owned(),
        )?;

        assert_eq!(declaration.key().provider(), "bedrock");
        assert_eq!(declaration.key().model(), "runtime-model-id");
        assert_eq!(declaration.key().revision(), "model-revision-2026-08-30");
        assert_eq!(
            declaration.registry_revision(),
            BEDROCK_CAPABILITY_REGISTRY_REVISION
        );
        assert!(declaration.supports(ModelCapability::TextInput));
        assert!(declaration.supports(ModelCapability::TextOutput));
        assert!(declaration.supports(ModelCapability::Streaming));
        assert!(!declaration.supports(ModelCapability::Tools));
        assert_eq!(declaration.evidence().len(), 3);
        for evidence in declaration.evidence().values() {
            assert_eq!(
                evidence.source(),
                CapabilityEvidenceSource::ProviderDocumentation
            );
            assert_eq!(evidence.revision(), evidence_revision);
        }
        Ok(())
    }
}
