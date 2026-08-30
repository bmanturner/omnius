use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use omnius_agent_capability_registry::{CapabilityKey, Exposure};
use omnius_llm_prompt_catalog::{
    ContentDigest, PromptId, PromptRenderer, PromptRevision, PromptRevisionNumber, PromptStatus,
    RenderLimits,
};
use omnius_mcp_server_core::McpExtension;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::{
    CacheControl, CacheScope, CatalogRevision, CompatibilityStatus, PromptCompatibility,
    PublicPromptName, SchemaRevision,
};

const MAX_TITLE_BYTES: usize = 128;
const MAX_DESCRIPTION_BYTES: usize = 2_048;
const MAX_REQUIRED_EXTENSIONS: usize = 32;

/// A fixed, value-free projection catalog construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PromptCatalogError {
    /// Public title, description, compatibility, or extension metadata was invalid.
    #[error("MCP prompt metadata is invalid")]
    InvalidMetadata,
    /// One immutable catalog contained the same public name more than once.
    #[error("MCP prompt public name is duplicated")]
    DuplicatePublicName,
    /// A draft or deprecated prompt-catalog revision was supplied.
    #[error("MCP prompt revision is not published")]
    NotPublished,
    /// The exact published revision could not be compiled under its fixed limits.
    #[error("MCP prompt renderer could not be compiled")]
    InvalidRenderer,
    /// A successor catalog removed an active name or changed a shared-name contract or window.
    #[error("MCP prompt successor catalog is incompatible")]
    IncompatibleSuccessor,
}

/// Exact public metadata for one immutable prompt projection.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptMetadata {
    public_name: PublicPromptName,
    title: String,
    description: String,
    argument_schema: Value,
    schema_revision: SchemaRevision,
    compatibility: PromptCompatibility,
    prompt_id: PromptId,
    prompt_revision: PromptRevisionNumber,
    prompt_digest: ContentDigest,
    capability: CapabilityKey,
    exposure: Exposure,
    required_extensions: BTreeSet<McpExtension>,
}

impl PromptMetadata {
    /// Borrows the explicit stable public MCP name.
    #[must_use]
    pub const fn public_name(&self) -> &PublicPromptName {
        &self.public_name
    }

    /// Borrows the reviewed public title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Borrows the reviewed public description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Borrows the canonical Draft 2020-12 argument schema.
    #[must_use]
    pub const fn argument_schema(&self) -> &Value {
        &self.argument_schema
    }

    /// Borrows the explicit projected schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &SchemaRevision {
        &self.schema_revision
    }

    /// Borrows active or deprecated compatibility metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &PromptCompatibility {
        &self.compatibility
    }

    /// Borrows the stable prompt-catalog identifier.
    #[must_use]
    pub const fn prompt_id(&self) -> &PromptId {
        &self.prompt_id
    }

    /// Returns the exact immutable prompt-catalog revision.
    #[must_use]
    pub const fn prompt_revision(&self) -> PromptRevisionNumber {
        self.prompt_revision
    }

    /// Returns the digest binding the exact immutable prompt content.
    #[must_use]
    pub const fn prompt_digest(&self) -> ContentDigest {
        self.prompt_digest
    }

    /// Borrows the sole canonical capability revision invoked by this projection.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the fixed canonical registry exposure.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// Borrows sorted, duplicate-free exact extension requirements.
    #[must_use]
    pub const fn required_extensions(&self) -> &BTreeSet<McpExtension> {
        &self.required_extensions
    }

    pub(crate) fn visible_clone(&self, replacement_visible: bool) -> Self {
        let mut visible = self.clone();
        if visible.compatibility.status() == CompatibilityStatus::Deprecated && !replacement_visible
        {
            visible.compatibility = visible.compatibility.without_replacement();
        }
        visible
    }

    fn has_same_immutable_contract(&self, other: &Self) -> bool {
        let Self {
            public_name,
            title,
            description,
            argument_schema,
            schema_revision,
            compatibility: _,
            prompt_id,
            prompt_revision,
            prompt_digest,
            capability,
            exposure,
            required_extensions,
        } = self;
        let Self {
            public_name: other_public_name,
            title: other_title,
            description: other_description,
            argument_schema: other_argument_schema,
            schema_revision: other_schema_revision,
            compatibility: _,
            prompt_id: other_prompt_id,
            prompt_revision: other_prompt_revision,
            prompt_digest: other_prompt_digest,
            capability: other_capability,
            exposure: other_exposure,
            required_extensions: other_required_extensions,
        } = other;

        (
            public_name,
            title,
            description,
            argument_schema,
            schema_revision,
            prompt_id,
            prompt_revision,
            prompt_digest,
            capability,
            exposure,
            required_extensions,
        ) == (
            other_public_name,
            other_title,
            other_description,
            other_argument_schema,
            other_schema_revision,
            other_prompt_id,
            other_prompt_revision,
            other_prompt_digest,
            other_capability,
            other_exposure,
            other_required_extensions,
        )
    }
}

impl fmt::Debug for PromptMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptMetadata([redacted])")
    }
}

/// A construction value for one exact published prompt projection.
///
/// Construction compiles [`PromptRenderer`] exactly once. The resulting value
/// can only enter an immutable [`PromptProjectionCatalog`].
pub struct PromptDefinition {
    pub(crate) metadata: PromptMetadata,
    pub(crate) renderer: PromptRenderer,
    render_limits: RenderLimits,
}

impl PromptDefinition {
    /// Validates public metadata and compiles one exact published prompt revision.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`PromptCatalogError`] for draft or deprecated revisions,
    /// duplicate or excessive extension requirements, invalid public text, a
    /// self-referential replacement, or renderer compilation failure.
    #[expect(
        clippy::too_many_arguments,
        reason = "all immutable public contract fields are explicit"
    )]
    pub fn new(
        public_name: PublicPromptName,
        title: impl Into<String>,
        description: impl Into<String>,
        schema_revision: SchemaRevision,
        compatibility: PromptCompatibility,
        capability: CapabilityKey,
        required_extensions: impl IntoIterator<Item = McpExtension>,
        revision: &PromptRevision,
        render_limits: RenderLimits,
    ) -> Result<Self, PromptCatalogError> {
        if revision.status() != PromptStatus::Published {
            return Err(PromptCatalogError::NotPublished);
        }
        let title = title.into();
        let description = description.into();
        if !valid_public_text(&title, MAX_TITLE_BYTES)
            || !valid_public_text(&description, MAX_DESCRIPTION_BYTES)
            || compatibility.replacement() == Some(&public_name)
        {
            return Err(PromptCatalogError::InvalidMetadata);
        }
        let mut required = BTreeSet::new();
        for extension in required_extensions {
            if required.len() >= MAX_REQUIRED_EXTENSIONS || !required.insert(extension) {
                return Err(PromptCatalogError::InvalidMetadata);
            }
        }
        let renderer = PromptRenderer::compile(revision, render_limits)
            .map_err(|_| PromptCatalogError::InvalidRenderer)?;
        let metadata = PromptMetadata {
            public_name,
            title,
            description,
            argument_schema: revision.body().input_schema().clone(),
            schema_revision,
            compatibility,
            prompt_id: revision.id().clone(),
            prompt_revision: revision.revision(),
            prompt_digest: revision.content_digest(),
            capability,
            exposure: Exposure::McpPrompt,
            required_extensions: required,
        };
        Ok(Self {
            metadata,
            renderer,
            render_limits,
        })
    }

    /// Borrows the exact immutable metadata that will be projected.
    #[must_use]
    pub const fn metadata(&self) -> &PromptMetadata {
        &self.metadata
    }

    /// Returns the immutable rendering resource contract for this public name.
    #[must_use]
    pub const fn render_limits(&self) -> RenderLimits {
        self.render_limits
    }
}

impl fmt::Debug for PromptDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptDefinition([redacted])")
    }
}

/// An immutable, deterministic, duplicate-free prompt projection catalog.
pub struct PromptProjectionCatalog {
    pub(crate) revision: CatalogRevision,
    pub(crate) cache_control: CacheControl,
    pub(crate) entries: BTreeMap<PublicPromptName, PromptDefinition>,
}

impl PromptProjectionCatalog {
    /// Builds an immutable catalog keyed by explicit stable public names.
    ///
    /// # Errors
    ///
    /// Returns [`PromptCatalogError::InvalidMetadata`] for shared cache scope or
    /// a deprecated name without an in-catalog active replacement, and
    /// [`PromptCatalogError::DuplicatePublicName`] for a repeated public name.
    pub fn new(
        revision: CatalogRevision,
        cache_control: CacheControl,
        definitions: impl IntoIterator<Item = PromptDefinition>,
    ) -> Result<Self, PromptCatalogError> {
        if cache_control.scope() != CacheScope::Private {
            return Err(PromptCatalogError::InvalidMetadata);
        }
        let mut entries = BTreeMap::new();
        for definition in definitions {
            let key = definition.metadata.public_name.clone();
            if entries.insert(key, definition).is_some() {
                return Err(PromptCatalogError::DuplicatePublicName);
            }
        }
        for definition in entries.values() {
            if definition.metadata.compatibility.status() != CompatibilityStatus::Deprecated {
                continue;
            }
            let replacement = definition
                .metadata
                .compatibility
                .replacement()
                .ok_or(PromptCatalogError::InvalidMetadata)?;
            let replacement_definition = entries
                .get(replacement)
                .ok_or(PromptCatalogError::InvalidMetadata)?;
            if replacement_definition.metadata.compatibility.status() != CompatibilityStatus::Active
            {
                return Err(PromptCatalogError::InvalidMetadata);
            }
        }
        Ok(Self {
            revision,
            cache_control,
            entries,
        })
    }

    /// Borrows the bounded opaque catalog revision.
    #[must_use]
    pub const fn revision(&self) -> &CatalogRevision {
        &self.revision
    }

    /// Borrows prevalidated cache scope, TTL, and canonical header control.
    #[must_use]
    pub const fn cache_control(&self) -> &CacheControl {
        &self.cache_control
    }

    /// Returns whether the immutable catalog has no prompt definitions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of unique public names in the immutable catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Validates that a later catalog preserves every shared-name prompt contract.
    ///
    /// Active names may remain active or enter a complete deprecation window.
    /// Deprecated names may retain the exact same window or be removed. A new
    /// catalog may add separately versioned names.
    ///
    /// # Errors
    ///
    /// Returns [`PromptCatalogError::IncompatibleSuccessor`] when an active name
    /// is removed, a shared immutable contract changes, a deprecated name is
    /// reactivated, or a documented deprecation window changes.
    pub fn validate_successor(&self, successor: &Self) -> Result<(), PromptCatalogError> {
        for (public_name, current) in &self.entries {
            let Some(next) = successor.entries.get(public_name) else {
                if current.metadata.compatibility.status() == CompatibilityStatus::Active {
                    return Err(PromptCatalogError::IncompatibleSuccessor);
                }
                continue;
            };

            if !current.metadata.has_same_immutable_contract(&next.metadata)
                || current.render_limits != next.render_limits
            {
                return Err(PromptCatalogError::IncompatibleSuccessor);
            }

            if current.metadata.compatibility.status() == CompatibilityStatus::Deprecated
                && (next.metadata.compatibility.status() != CompatibilityStatus::Deprecated
                    || current.metadata.compatibility != next.metadata.compatibility)
            {
                return Err(PromptCatalogError::IncompatibleSuccessor);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for PromptProjectionCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptProjectionCatalog([redacted])")
    }
}

fn valid_public_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}
