use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
};

use omnius_agent_capability_registry::{
    CapabilityKey, ConfirmationPolicy, Exposure, IdempotencyPolicy, Permission, SideEffect,
    TenantMode,
};
use omnius_mcp_server_core::{McpExtension, McpKernel};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    CatalogRevision, JsonSchemaDocument, SchemaRevision, ToolDescription, ToolName, ToolTitle,
};
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Maximum catalog cache lifetime.
pub const MAX_CATALOG_TTL_MS: u32 = 3_600_000;
/// Maximum exact extension requirements on one tool declaration.
pub const MAX_REQUIRED_EXTENSIONS: usize = 32;

/// Compatibility and deprecation state of a public tool name.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CompatibilityState {
    /// This public name is the active contract revision.
    Active,
    /// This public name remains visible during an explicit compatibility window.
    Deprecated {
        /// Optional active replacement public name.
        replacement: Option<ToolName>,
    },
}

impl CompatibilityState {
    /// Returns whether callers should migrate away from this public name.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, Self::Deprecated { .. })
    }

    /// Returns the optional active replacement.
    #[must_use]
    pub const fn replacement(&self) -> Option<&ToolName> {
        match self {
            Self::Active => None,
            Self::Deprecated { replacement } => replacement.as_ref(),
        }
    }
}

impl fmt::Debug for CompatibilityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompatibilityState([redacted])")
    }
}

/// One immutable explicit MCP tool exposure declaration.
#[derive(Clone, Eq, PartialEq)]
pub struct ToolDeclaration {
    name: ToolName,
    capability: CapabilityKey,
    title: ToolTitle,
    description: Option<ToolDescription>,
    input_schema: JsonSchemaDocument,
    output_schema: JsonSchemaDocument,
    schema_revision: SchemaRevision,
    compatibility: CompatibilityState,
    required_extensions: BTreeSet<McpExtension>,
}

impl ToolDeclaration {
    /// Creates one explicit versioned MCP-tool declaration.
    ///
    /// The projection exposure is fixed to [`Exposure::McpTool`]; no caller-selectable exposure or
    /// executable handler is accepted here.
    ///
    /// # Errors
    ///
    /// Returns [`ToolDeclarationError::DuplicateExtension`] when an identifier appears more than
    /// once, even at different revisions. Returns [`ToolDeclarationError::TooManyExtensions`] when
    /// more than 32 requirements are supplied.
    #[expect(
        clippy::too_many_arguments,
        reason = "the declaration deliberately owns each independent public contract field"
    )]
    pub fn new(
        name: ToolName,
        capability: CapabilityKey,
        title: ToolTitle,
        description: Option<ToolDescription>,
        input_schema: JsonSchemaDocument,
        output_schema: JsonSchemaDocument,
        schema_revision: SchemaRevision,
        compatibility: CompatibilityState,
        required_extensions: impl IntoIterator<Item = McpExtension>,
    ) -> Result<Self, ToolDeclarationError> {
        let mut extensions = BTreeSet::new();
        let mut extension_ids = BTreeSet::new();
        for requirement in required_extensions {
            if extension_ids.contains(requirement.id()) {
                return Err(ToolDeclarationError::DuplicateExtension);
            }
            if extensions.len() == MAX_REQUIRED_EXTENSIONS {
                return Err(ToolDeclarationError::TooManyExtensions);
            }
            extension_ids.insert(requirement.id().clone());
            extensions.insert(requirement);
        }
        Ok(Self {
            name,
            capability,
            title,
            description,
            input_schema,
            output_schema,
            schema_revision,
            compatibility,
            required_extensions: extensions,
        })
    }

    /// Returns the stable versioned public name.
    #[must_use]
    pub const fn name(&self) -> &ToolName {
        &self.name
    }

    /// Returns the canonical registry capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the fixed canonical registry exposure.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        Exposure::McpTool
    }

    /// Returns the public title.
    #[must_use]
    pub const fn title(&self) -> &ToolTitle {
        &self.title
    }

    /// Returns the optional public description.
    #[must_use]
    pub const fn description(&self) -> Option<&ToolDescription> {
        self.description.as_ref()
    }

    /// Returns the compiled arbitrary input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &JsonSchemaDocument {
        &self.input_schema
    }

    /// Returns the compiled arbitrary output schema.
    #[must_use]
    pub const fn output_schema(&self) -> &JsonSchemaDocument {
        &self.output_schema
    }

    /// Returns the explicit schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &SchemaRevision {
        &self.schema_revision
    }

    /// Returns active or deprecated compatibility metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &CompatibilityState {
        &self.compatibility
    }

    /// Returns exact required extensions in deterministic order.
    #[must_use]
    pub const fn required_extensions(&self) -> &BTreeSet<McpExtension> {
        &self.required_extensions
    }
}

impl fmt::Debug for ToolDeclaration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolDeclaration([redacted])")
    }
}

/// A tool declaration was noncanonical.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolDeclarationError {
    /// An extension identifier appeared more than once.
    #[error("tool extension requirement identifiers must be unique")]
    DuplicateExtension,
    /// More than 32 extension requirements were supplied.
    #[error("tool extension requirements exceed their fixed item bound")]
    TooManyExtensions,
}

/// An authorized public tool-list entry.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ToolDescriptor {
    name: ToolName,
    title: ToolTitle,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<ToolDescription>,
    #[serde(rename = "inputSchema")]
    input_schema: JsonSchemaDocument,
    #[serde(rename = "outputSchema")]
    output_schema: JsonSchemaDocument,
    #[serde(rename = "schemaRevision")]
    schema_revision: SchemaRevision,
    compatibility: CompatibilityState,
    #[serde(rename = "requiredExtensions")]
    required_extensions: BTreeSet<McpExtension>,
    permissions: Vec<Permission>,
    #[serde(rename = "sideEffect")]
    side_effect: SideEffect,
    confirmation: ConfirmationPolicy,
    idempotency: IdempotencyPolicy,
    #[serde(rename = "tenantModes")]
    tenant_modes: Vec<TenantMode>,
}

impl ToolDescriptor {
    /// Returns the stable versioned public name.
    #[must_use]
    pub const fn name(&self) -> &ToolName {
        &self.name
    }

    /// Returns the public title.
    #[must_use]
    pub const fn title(&self) -> &ToolTitle {
        &self.title
    }

    /// Returns the optional public description.
    #[must_use]
    pub const fn description(&self) -> Option<&ToolDescription> {
        self.description.as_ref()
    }

    /// Returns the arbitrary input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &JsonSchemaDocument {
        &self.input_schema
    }

    /// Returns the arbitrary output schema.
    #[must_use]
    pub const fn output_schema(&self) -> &JsonSchemaDocument {
        &self.output_schema
    }

    /// Returns the explicit schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &SchemaRevision {
        &self.schema_revision
    }

    /// Returns active or deprecated compatibility metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &CompatibilityState {
        &self.compatibility
    }

    /// Returns exact required extensions.
    #[must_use]
    pub const fn required_extensions(&self) -> &BTreeSet<McpExtension> {
        &self.required_extensions
    }

    /// Returns canonical required permissions.
    #[must_use]
    pub fn permissions(&self) -> &[Permission] {
        &self.permissions
    }

    /// Returns the canonical side-effect class.
    #[must_use]
    pub const fn side_effect(&self) -> SideEffect {
        self.side_effect
    }

    /// Returns the canonical confirmation policy.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationPolicy {
        self.confirmation
    }

    /// Returns the canonical idempotency policy.
    #[must_use]
    pub const fn idempotency(&self) -> IdempotencyPolicy {
        self.idempotency
    }

    /// Returns canonical supported tenant modes.
    #[must_use]
    pub fn tenant_modes(&self) -> &[TenantMode] {
        &self.tenant_modes
    }
}

impl fmt::Debug for ToolDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolDescriptor([redacted])")
    }
}

pub(crate) struct CatalogEntry {
    pub(crate) declaration: ToolDeclaration,
    pub(crate) descriptor: ToolDescriptor,
}

/// One immutable duplicate-free, deterministic MCP tool catalog.
pub struct ToolCatalog {
    revision: CatalogRevision,
    cache_control: CatalogCacheControl,
    entries: BTreeMap<ToolName, CatalogEntry>,
}

impl ToolCatalog {
    pub(crate) fn compile(
        revision: CatalogRevision,
        cache_control: CatalogCacheControl,
        declarations: impl IntoIterator<Item = ToolDeclaration>,
        kernel: &McpKernel,
    ) -> Result<Self, ToolCatalogError> {
        if cache_control.scope() == CatalogCacheScope::Public {
            return Err(ToolCatalogError::PublicCacheForbidden);
        }
        let mut entries = BTreeMap::new();
        let mut capabilities = BTreeSet::new();
        for declaration in declarations {
            if !capabilities.insert(declaration.capability.clone()) {
                return Err(ToolCatalogError::DuplicateCapability);
            }
            let Some(document) = kernel.document(&declaration.capability) else {
                return Err(ToolCatalogError::MissingCapability);
            };
            if document
                .exposures
                .binary_search(&Exposure::McpTool)
                .is_err()
            {
                return Err(ToolCatalogError::ExposureNotDeclared);
            }
            let descriptor = ToolDescriptor {
                name: declaration.name.clone(),
                title: declaration.title.clone(),
                description: declaration.description.clone(),
                input_schema: declaration.input_schema.clone(),
                output_schema: declaration.output_schema.clone(),
                schema_revision: declaration.schema_revision.clone(),
                compatibility: declaration.compatibility.clone(),
                required_extensions: declaration.required_extensions.clone(),
                permissions: document.permissions.clone(),
                side_effect: document.side_effect,
                confirmation: document.confirmation,
                idempotency: document.idempotency,
                tenant_modes: document.tenant_modes.clone(),
            };
            if entries
                .insert(
                    declaration.name.clone(),
                    CatalogEntry {
                        declaration,
                        descriptor,
                    },
                )
                .is_some()
            {
                return Err(ToolCatalogError::DuplicateName);
            }
        }

        for (name, entry) in &entries {
            if let Some(replacement) = entry.declaration.compatibility.replacement() {
                let Some(target) = entries.get(replacement) else {
                    return Err(ToolCatalogError::InvalidCompatibility);
                };
                if replacement == name || target.declaration.compatibility.is_deprecated() {
                    return Err(ToolCatalogError::InvalidCompatibility);
                }
            }
        }

        Ok(Self {
            revision,
            cache_control,
            entries,
        })
    }

    /// Returns the bounded immutable catalog revision.
    #[must_use]
    pub const fn revision(&self) -> &CatalogRevision {
        &self.revision
    }

    /// Returns the prevalidated private cache control.
    #[must_use]
    pub const fn cache_control(&self) -> CatalogCacheControl {
        self.cache_control
    }

    /// Returns the number of duplicate-free declarations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the catalog contains no declaration.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn entries(&self) -> &BTreeMap<ToolName, CatalogEntry> {
        &self.entries
    }

    pub(crate) fn entry(&self, name: &ToolName) -> Option<&CatalogEntry> {
        self.entries.get(name)
    }
}

impl fmt::Debug for ToolCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolCatalog([redacted])")
    }
}

/// Catalog construction failed closed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolCatalogError {
    /// Two public declarations used the same name.
    #[error("tool catalog public names must be unique")]
    DuplicateName,
    /// Two public declarations targeted the same registry capability revision.
    #[error("tool catalog capability revisions must be unique")]
    DuplicateCapability,
    /// A declaration targeted a capability absent from the shared kernel registry.
    #[error("tool catalog capability is unavailable")]
    MissingCapability,
    /// The registry capability did not explicitly declare MCP-tool exposure.
    #[error("tool catalog capability is not exposed as an MCP tool")]
    ExposureNotDeclared,
    /// Deprecated replacement metadata did not name an active catalog entry.
    #[error("tool catalog compatibility metadata is invalid")]
    InvalidCompatibility,
    /// Authorization-filtered catalogs cannot be shared across callers.
    #[error("tool catalog cache scope must be private")]
    PublicCacheForbidden,
}

/// Cache scope for a catalog list.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogCacheScope {
    /// The authorized list is identical for every caller and may be shared.
    Public,
    /// The list may be reused only for the same authenticated principal and tenant context.
    Private,
}

impl CatalogCacheScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// Prevalidated catalog cache control.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CatalogCacheControl {
    ttl_ms: u32,
    scope: CatalogCacheScope,
}

impl CatalogCacheControl {
    /// Creates cache control with a positive whole-second lifetime bounded to one hour.
    ///
    /// Public scope is appropriate only when authorization guarantees an identical list for every
    /// caller. Authorization-sensitive views must use [`CatalogCacheScope::Private`].
    ///
    /// # Errors
    ///
    /// Returns [`CacheControlError`] when the lifetime is zero, exceeds one hour, or is not
    /// divisible by 1000.
    pub const fn new(ttl_ms: u32, scope: CatalogCacheScope) -> Result<Self, CacheControlError> {
        if ttl_ms == 0 || ttl_ms > MAX_CATALOG_TTL_MS || !ttl_ms.is_multiple_of(1_000) {
            return Err(CacheControlError);
        }
        Ok(Self { ttl_ms, scope })
    }

    /// Creates private cache control with a positive bounded whole-second lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`CacheControlError`] when the lifetime is invalid.
    pub const fn private(ttl_ms: u32) -> Result<Self, CacheControlError> {
        Self::new(ttl_ms, CatalogCacheScope::Private)
    }

    /// Creates public cache control with a positive bounded whole-second lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`CacheControlError`] when the lifetime is invalid.
    pub const fn public(ttl_ms: u32) -> Result<Self, CacheControlError> {
        Self::new(ttl_ms, CatalogCacheScope::Public)
    }

    /// Returns the cache lifetime in milliseconds.
    #[must_use]
    pub const fn ttl_ms(self) -> u32 {
        self.ttl_ms
    }

    /// Returns the validated cache scope.
    #[must_use]
    pub const fn scope(self) -> CatalogCacheScope {
        self.scope
    }

    fn header_value(self) -> String {
        format!("{}, max-age={}", self.scope.as_str(), self.ttl_ms / 1_000)
    }
}

impl fmt::Debug for CatalogCacheControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatalogCacheControl([redacted])")
    }
}

/// Catalog cache control exceeded its fixed bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("catalog cache control is invalid")]
pub struct CacheControlError;

/// Visibility-sensitive quoted SHA-256 catalog entity tag.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CatalogEtag(String);

impl CatalogEtag {
    /// Borrows the quoted `"sha256:<64 lowercase hex>"` entity tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CatalogEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatalogEtag([redacted])")
    }
}

/// Required exact `_meta` concepts for one authorized catalog view.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct CatalogMeta {
    #[serde(rename = "io.omnius.mcp/catalogRevision")]
    catalog_revision: CatalogRevision,
    #[serde(rename = "io.omnius.mcp/catalogEtag")]
    catalog_etag: CatalogEtag,
    #[serde(rename = "io.omnius.mcp/ttlMs")]
    ttl_ms: u32,
    #[serde(rename = "io.omnius.mcp/cacheScope")]
    cache_scope: CatalogCacheScope,
    #[serde(rename = "io.omnius.mcp/cacheControl")]
    cache_control: String,
}

impl CatalogMeta {
    /// Returns the immutable catalog revision.
    #[must_use]
    pub const fn catalog_revision(&self) -> &CatalogRevision {
        &self.catalog_revision
    }

    /// Returns the visibility-sensitive quoted catalog `ETag`.
    #[must_use]
    pub const fn catalog_etag(&self) -> &CatalogEtag {
        &self.catalog_etag
    }

    /// Returns the cache lifetime in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> u32 {
        self.ttl_ms
    }

    /// Returns the validated cache scope.
    #[must_use]
    pub const fn cache_scope(&self) -> CatalogCacheScope {
        self.cache_scope
    }

    /// Returns the exact `<scope>, max-age=<ttlMs/1000>` cache control value.
    #[must_use]
    pub fn cache_control(&self) -> &str {
        &self.cache_control
    }
}

impl fmt::Debug for CatalogMeta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatalogMeta([redacted])")
    }
}

/// A deterministically ordered authorized tool list and its `_meta` concepts.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct ToolList {
    tools: Vec<ToolDescriptor>,
    #[serde(rename = "_meta")]
    meta: CatalogMeta,
}

impl ToolList {
    pub(crate) fn new(
        mut tools: Vec<ToolDescriptor>,
        revision: &CatalogRevision,
        cache_control: CatalogCacheControl,
    ) -> Result<Self, CatalogMetadataError> {
        let visible_names = tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<BTreeSet<_>>();
        for tool in &mut tools {
            if let CompatibilityState::Deprecated { replacement } = &mut tool.compatibility
                && replacement
                    .as_ref()
                    .is_some_and(|target| !visible_names.contains(target))
            {
                *replacement = None;
            }
        }
        let catalog_etag = catalog_etag(revision, &tools)?;
        Ok(Self {
            tools,
            meta: CatalogMeta {
                catalog_revision: revision.clone(),
                catalog_etag,
                ttl_ms: cache_control.ttl_ms(),
                cache_scope: cache_control.scope(),
                cache_control: cache_control.header_value(),
            },
        })
    }

    /// Returns authorized entries in deterministic public-name order.
    #[must_use]
    pub fn tools(&self) -> &[ToolDescriptor] {
        &self.tools
    }

    /// Returns catalog revision, `ETag`, and cache control under the `_meta` concept.
    #[must_use]
    pub const fn meta(&self) -> &CatalogMeta {
        &self.meta
    }
}

impl fmt::Debug for ToolList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolList([redacted])")
    }
}

/// Visibility-sensitive catalog metadata construction failed without exposing values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("catalog metadata construction failed")]
pub struct CatalogMetadataError;

fn catalog_etag(
    revision: &CatalogRevision,
    tools: &[ToolDescriptor],
) -> Result<CatalogEtag, CatalogMetadataError> {
    let mut hasher = Sha256::new();
    hasher.update(b"omnius.mcp.tools.catalog.v1\0");
    hash_field(&mut hasher, revision.as_str().as_bytes());
    serde_json::to_writer(HashWriter(&mut hasher), tools).map_err(|_| CatalogMetadataError)?;
    let digest = hasher.finalize();
    let mut value = String::with_capacity(73);
    value.push('"');
    value.push_str("sha256:");
    for byte in digest {
        value.push(char::from(HEX_LOWER[usize::from(byte >> 4)]));
        value.push(char::from(HEX_LOWER[usize::from(byte & 0x0f)]));
    }
    value.push('"');
    Ok(CatalogEtag(value))
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

struct HashWriter<'a>(&'a mut Sha256);

impl io::Write for HashWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
