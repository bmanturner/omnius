use std::{collections::BTreeMap, fmt, num::NonZeroUsize};

use omnius_agent_capability_registry::{
    CapabilityDocument, CapabilityKey, CapabilityRegistry, Exposure,
};
use omnius_llm_core::{ContractError, SchemaDefinition, ToolDefinition};
use thiserror::Error;

/// One provider-neutral tool projected from an exact registry document revision.
pub struct CatalogTool {
    capability: CapabilityKey,
    definition: ToolDefinition,
    document: CapabilityDocument,
}

impl CatalogTool {
    /// Borrows the exact registry revision backing this tool.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Borrows the provider-neutral model-facing definition.
    #[must_use]
    pub const fn definition(&self) -> &ToolDefinition {
        &self.definition
    }

    pub(crate) const fn document(&self) -> &CapabilityDocument {
        &self.document
    }
}

impl fmt::Debug for CatalogTool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogTool")
            .field("capability", &self.capability)
            .field("definition", &self.definition)
            .finish_non_exhaustive()
    }
}

/// Deterministically ordered tools derived exclusively from the capability registry.
pub struct ToolCatalog {
    tools: BTreeMap<String, CatalogTool>,
}

impl ToolCatalog {
    /// Projects available registry documents that explicitly expose `LlmTool`.
    ///
    /// Capability identifiers are the stable model-facing names. Multiple
    /// simultaneously available LLM-tool revisions for one identifier are
    /// rejected rather than selecting a revision implicitly.
    ///
    /// # Errors
    ///
    /// Returns [`ToolCatalogError`] for an excessive catalog, ambiguous tool
    /// identity, or a canonical LLM definition conversion failure.
    pub fn project(
        registry: &CapabilityRegistry,
        max_tools: NonZeroUsize,
    ) -> Result<Self, ToolCatalogError> {
        let mut tools = BTreeMap::new();
        for availability in registry.availability_snapshot().capabilities() {
            if !availability.runtime().is_available() {
                continue;
            }
            let Some(document) = registry.document(availability.capability()) else {
                return Err(ToolCatalogError::RegistryInconsistent);
            };
            if document
                .exposures
                .binary_search(&Exposure::LlmTool)
                .is_err()
            {
                continue;
            }
            if tools.len() >= max_tools.get() {
                return Err(ToolCatalogError::CatalogTooLarge);
            }

            let name = document.id.as_str().to_owned();
            if tools.contains_key(&name) {
                return Err(ToolCatalogError::AmbiguousToolName);
            }
            let input_schema = SchemaDefinition::Object(document.input_schema.as_map().clone());
            let output_schema = SchemaDefinition::Object(document.output_schema.as_map().clone());
            let definition = ToolDefinition::new(name.clone(), input_schema)?.with_details(
                document
                    .description
                    .as_ref()
                    .map(|description| description.as_str().to_owned()),
                Some(document.id.as_str().to_owned()),
                Some(output_schema),
            )?;
            tools.insert(
                name,
                CatalogTool {
                    capability: document.key(),
                    definition,
                    document: document.clone(),
                },
            );
        }
        Ok(Self { tools })
    }

    /// Returns the number of projected tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Returns whether the projected catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// Iterates tools in stable catalog-name order.
    #[must_use]
    pub fn tools(&self) -> impl ExactSizeIterator<Item = &CatalogTool> {
        self.tools.values()
    }

    /// Resolves one exact catalog tool by model-facing name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&CatalogTool> {
        self.tools.get(name)
    }
}

impl fmt::Debug for ToolCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolCatalog")
            .field("tool_count", &self.tools.len())
            .finish()
    }
}

/// A fixed, declaration-content-free catalog projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolCatalogError {
    /// The configured finite catalog bound was exceeded.
    #[error("LLM tool catalog exceeds its fixed bound")]
    CatalogTooLarge,
    /// More than one available revision projected to the same model tool name.
    #[error("LLM tool catalog contains an ambiguous tool name")]
    AmbiguousToolName,
    /// Registry availability referenced no corresponding registry document.
    #[error("capability registry snapshot is inconsistent")]
    RegistryInconsistent,
    /// Registry metadata could not form a canonical LLM tool definition.
    #[error("registry document cannot form a canonical LLM tool definition")]
    InvalidDefinition,
}

impl From<ContractError> for ToolCatalogError {
    fn from(_: ContractError) -> Self {
        Self::InvalidDefinition
    }
}
