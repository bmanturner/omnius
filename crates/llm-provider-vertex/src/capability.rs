use std::collections::{BTreeMap, BTreeSet};

use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, CapabilityRegistryError, ModelCapability,
    ModelCapabilityDeclaration, ModelCapabilityKey,
};
use omnius_llm_provider_rig::CatalogProvider;

/// Revision of this adapter's conservative Vertex capability declaration.
pub const VERTEX_CAPABILITY_REGISTRY_REVISION: &str = "vertex-rig-0.42.0-2026-08-30";

/// Declares the evidence-backed capabilities of one exact Vertex model revision.
///
/// The declaration is deliberately conservative: it contains only canonical
/// text input and text output, which the shared Rig adapter can preserve end
/// to end. It never declares streaming because Rig Vertex AI 0.42.0 returns an
/// explicit unsupported error for that operation.
///
/// # Errors
///
/// Returns [`CapabilityRegistryError::InvalidDeclaration`] for an empty or
/// overlong model, revision, location, or evidence revision.
pub fn capability_declaration(
    model: String,
    revision: String,
    location: String,
    evidence_revision: String,
) -> Result<ModelCapabilityDeclaration, CapabilityRegistryError> {
    let evidence = CapabilityEvidence::new(
        CapabilityEvidenceSource::ProviderDocumentation,
        evidence_revision,
    )?;
    let evidence = BTreeMap::from([
        (ModelCapability::TextInput, evidence.clone()),
        (ModelCapability::TextOutput, evidence),
    ]);
    ModelCapabilityDeclaration::new(
        ModelCapabilityKey::new(CatalogProvider::Vertex.as_str().to_owned(), model, revision)?,
        VERTEX_CAPABILITY_REGISTRY_REVISION,
        evidence,
        BTreeSet::from([location]),
        None,
        None,
    )
}
