use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use omnius_agent_capability_registry::CapabilityDocument;
use omnius_mcp_server_core::{McpExposureFilter, McpPrimitive, McpRequestContext};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

/// Absolute number of authorized entries any snapshot may retain.
pub const HARD_MAX_SCAN_ENTRIES: usize = 2_048;
/// Absolute number of hits any page may return.
pub const HARD_MAX_PAGE_SIZE: u16 = 100;

const MAX_AUTHORIZATION_REVISION_BYTES: usize = 128;
const MAX_CAPABILITY_ID_BYTES: usize = 192;
const MAX_CAPABILITY_VERSION_BYTES: usize = 64;
const MAX_TITLE_BYTES: usize = 256;
const MAX_SUMMARY_BYTES: usize = 2_048;
const MAX_PARTITION_BYTES: usize = 96;
const MAX_TAG_BYTES: usize = 64;
const MAX_TAGS: usize = 16;
const MAX_SEARCH_TERM_BYTES: usize = 128;
const MAX_SEARCH_TERMS: usize = 32;
const MAX_FILTER_VALUES: usize = 16;
const MAX_RESULT_CONTRACT_BYTES: usize = 96;
const MAX_FUTURE_METADATA_FIELDS: usize = 16;
const MAX_FUTURE_METADATA_KEY_BYTES: usize = 96;
const MAX_FUTURE_METADATA_VALUE_BYTES: usize = 4_096;
const MAX_CURSOR_TTL_SECONDS: u64 = 3_600;
const SNAPSHOT_DOMAIN: &[u8] = b"omnius.progressive-discovery.authorized-snapshot.v2";

/// Compact capability category prepared for internal progressive discovery.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CapabilityKind {
    /// Canonical tool declaration adapted by the current MCP result layer.
    Tool,
    /// Canonical resource or resource-template declaration.
    Resource,
    /// Canonical prompt declaration.
    Prompt,
}

impl CapabilityKind {
    pub(crate) const fn binding_tag(self) -> u8 {
        match self {
            Self::Tool => 1,
            Self::Resource => 2,
            Self::Prompt => 3,
        }
    }

    const fn from_mcp(primitive: McpPrimitive) -> Self {
        match primitive {
            McpPrimitive::Tool => Self::Tool,
            McpPrimitive::Resource => Self::Resource,
            McpPrimitive::Prompt => Self::Prompt,
        }
    }
}

/// Storage-neutral resource capability facts; this type does not resolve or read resources.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the four booleans are independent storage-neutral resource capabilities"
)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceDiscoveryHints {
    /// The registered resource resolver supports bounded range requests.
    pub range_ready: bool,
    /// The registered resource resolver supports hierarchy traversal.
    pub hierarchy_ready: bool,
    /// The registered resource resolver can report content checksums.
    pub checksum_ready: bool,
    /// The registered resource resolver can return object references.
    pub object_reference_ready: bool,
}

/// Compact authorized facts consumed by internal projections, never a replacement MCP result type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactCapability {
    kind: CapabilityKind,
    canonical_result_contract: Option<String>,
    resource_hints: Option<ResourceDiscoveryHints>,
}

impl CompactCapability {
    /// Creates tool facts pointing at an existing canonical result contract revision.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when the contract is empty, oversized,
    /// surrounded by whitespace, or contains control characters.
    pub fn tool(canonical_result_contract: impl Into<String>) -> Result<Self, DiscoveryModelError> {
        let contract = canonical_result_contract.into();
        validate_text(&contract, MAX_RESULT_CONTRACT_BYTES)?;
        Ok(Self {
            kind: CapabilityKind::Tool,
            canonical_result_contract: Some(contract),
            resource_hints: None,
        })
    }

    /// Creates storage-neutral resource capability facts.
    #[must_use]
    pub const fn resource(resource_hints: ResourceDiscoveryHints) -> Self {
        Self {
            kind: CapabilityKind::Resource,
            canonical_result_contract: None,
            resource_hints: Some(resource_hints),
        }
    }

    /// Creates prompt capability facts.
    #[must_use]
    pub const fn prompt() -> Self {
        Self {
            kind: CapabilityKind::Prompt,
            canonical_result_contract: None,
            resource_hints: None,
        }
    }

    /// Returns the compact capability category.
    #[must_use]
    pub const fn kind(&self) -> CapabilityKind {
        self.kind
    }

    /// Returns the existing canonical result contract identifier, when applicable.
    #[must_use]
    pub fn canonical_result_contract(&self) -> Option<&str> {
        self.canonical_result_contract.as_deref()
    }

    /// Returns storage-neutral resource hints, when applicable.
    #[must_use]
    pub const fn resource_hints(&self) -> Option<ResourceDiscoveryHints> {
        self.resource_hints
    }
}

/// Bounded opaque canonical bytes for future metadata this preview does not interpret.
///
/// Fields are retained losslessly and included in the authorized snapshot fingerprint. They never
/// participate in authorization because providers are invoked only after canonical filtering.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct FutureDiscoveryMetadata {
    fields: BTreeMap<String, Vec<u8>>,
}

impl FutureDiscoveryMetadata {
    /// Validates and retains bounded unknown metadata without interpreting it.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when the field count, key, or value violates
    /// its bound, or [`DiscoveryModelError::DuplicateValue`] when a key occurs more than once.
    pub fn try_new(
        fields: impl IntoIterator<Item = (String, Vec<u8>)>,
    ) -> Result<Self, DiscoveryModelError> {
        let mut validated = BTreeMap::new();
        for (key, value) in fields {
            if validated.len() >= MAX_FUTURE_METADATA_FIELDS
                || value.len() > MAX_FUTURE_METADATA_VALUE_BYTES
            {
                return Err(DiscoveryModelError::InvalidEntry);
            }
            validate_token(&key, MAX_FUTURE_METADATA_KEY_BYTES)?;
            if validated.insert(key, value).is_some() {
                return Err(DiscoveryModelError::DuplicateValue);
            }
        }
        Ok(Self { fields: validated })
    }

    /// Borrows unknown fields in deterministic key order.
    #[must_use]
    pub const fn fields(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.fields
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "opaque future metadata is deliberately represented only by its field count"
)]
impl fmt::Debug for FutureDiscoveryMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FutureDiscoveryMetadata")
            .field("field_count", &self.fields.len())
            .finish()
    }
}

/// Provider-owned search and compact facts attached only after registry authorization.
#[derive(Clone, Eq, PartialEq)]
pub struct DiscoveryEntryMetadata {
    partition: String,
    tags: BTreeSet<String>,
    search_terms: BTreeSet<String>,
    compact: CompactCapability,
    future: FutureDiscoveryMetadata,
}

impl DiscoveryEntryMetadata {
    /// Creates bounded metadata with deterministic set ordering.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when the partition, tag, or search-term
    /// bounds are violated or resource hints are inconsistent, or
    /// [`DiscoveryModelError::DuplicateValue`] when a tag or search term occurs more than once.
    pub fn try_new(
        partition: impl Into<String>,
        tags: impl IntoIterator<Item = String>,
        search_terms: impl IntoIterator<Item = String>,
        compact: CompactCapability,
        future: FutureDiscoveryMetadata,
    ) -> Result<Self, DiscoveryModelError> {
        let partition = partition.into();
        validate_token(&partition, MAX_PARTITION_BYTES)?;
        if compact.kind() == CapabilityKind::Resource && compact.resource_hints().is_none()
            || compact.kind() != CapabilityKind::Resource && compact.resource_hints().is_some()
        {
            return Err(DiscoveryModelError::InvalidEntry);
        }
        Ok(Self {
            partition,
            tags: collect_tokens(tags, MAX_TAGS, MAX_TAG_BYTES)?,
            search_terms: collect_text(search_terms, MAX_SEARCH_TERMS, MAX_SEARCH_TERM_BYTES)?,
            compact,
            future,
        })
    }

    /// Returns the deterministic partition key.
    #[must_use]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    /// Returns deterministic tags.
    #[must_use]
    pub const fn tags(&self) -> &BTreeSet<String> {
        &self.tags
    }

    /// Returns deterministic additional search terms.
    #[must_use]
    pub const fn search_terms(&self) -> &BTreeSet<String> {
        &self.search_terms
    }

    /// Returns compact capability facts.
    #[must_use]
    pub const fn compact(&self) -> &CompactCapability {
        &self.compact
    }

    /// Returns losslessly retained unknown metadata.
    #[must_use]
    pub const fn future(&self) -> &FutureDiscoveryMetadata {
        &self.future
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "provider-owned search metadata is deliberately reduced to counts and safe facts"
)]
impl fmt::Debug for DiscoveryEntryMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DiscoveryEntryMetadata")
            .field("kind", &self.compact.kind())
            .field("tag_count", &self.tags.len())
            .field("search_term_count", &self.search_terms.len())
            .field("future", &self.future)
            .finish()
    }
}

/// One authorized registry projection prepared for deterministic search.
#[derive(Clone, Eq, PartialEq)]
pub struct CatalogEntry {
    capability_id: String,
    capability_version: String,
    title: String,
    summary: Option<String>,
    metadata: DiscoveryEntryMetadata,
    normalized_id: String,
    normalized_title: String,
    normalized_summary: String,
    normalized_tags: BTreeSet<String>,
    normalized_search_terms: BTreeSet<String>,
}

impl CatalogEntry {
    /// Creates a bounded internal entry from canonical, already-authorized declaration facts.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when an identifier, version, title, or
    /// summary violates its length, whitespace, or character constraints.
    pub fn try_new(
        capability_id: impl Into<String>,
        capability_version: impl Into<String>,
        title: impl Into<String>,
        summary: Option<String>,
        metadata: DiscoveryEntryMetadata,
    ) -> Result<Self, DiscoveryModelError> {
        let capability_id = capability_id.into();
        let capability_version = capability_version.into();
        let title = title.into();
        validate_text(&capability_id, MAX_CAPABILITY_ID_BYTES)?;
        validate_token(&capability_version, MAX_CAPABILITY_VERSION_BYTES)?;
        validate_display_text(&title, MAX_TITLE_BYTES)?;
        if summary
            .as_ref()
            .is_some_and(|value| validate_summary(value).is_err())
        {
            return Err(DiscoveryModelError::InvalidEntry);
        }
        let normalized_id = normalize(&capability_id);
        let normalized_title = normalize(&title);
        let normalized_summary = summary.as_deref().map_or_else(String::new, normalize);
        let normalized_tags = metadata.tags.iter().map(|value| normalize(value)).collect();
        let normalized_search_terms = metadata
            .search_terms
            .iter()
            .map(|value| normalize(value))
            .collect();
        Ok(Self {
            capability_id,
            capability_version,
            title,
            summary,
            metadata,
            normalized_id,
            normalized_title,
            normalized_summary,
            normalized_tags,
            normalized_search_terms,
        })
    }

    fn from_document(
        document: &CapabilityDocument,
        metadata: DiscoveryEntryMetadata,
    ) -> Result<Self, DiscoveryModelError> {
        Self::try_new(
            document.id.as_str(),
            document.version.as_str(),
            document.title.as_str(),
            document
                .description
                .as_ref()
                .map(|value| value.as_str().to_owned()),
            metadata,
        )
    }

    /// Returns the stable canonical capability identifier.
    #[must_use]
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    /// Returns the exact canonical capability version.
    #[must_use]
    pub fn capability_version(&self) -> &str {
        &self.capability_version
    }

    /// Returns the display title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the optional authorized summary.
    #[must_use]
    pub fn summary(&self) -> Option<&str> {
        self.summary.as_deref()
    }

    /// Returns compact, search, tag, partition, and retained future metadata.
    #[must_use]
    pub const fn metadata(&self) -> &DiscoveryEntryMetadata {
        &self.metadata
    }

    pub(crate) fn rank(&self, normalized_query: &str) -> Option<u32> {
        if normalized_query.is_empty() {
            return Some(0);
        }
        if self.normalized_id == normalized_query {
            return Some(10_000);
        }
        let mut score = 0_u32;
        for token in normalized_query.split(' ') {
            if token.is_empty() {
                continue;
            }
            let token_score = if self.normalized_id.starts_with(token) {
                600
            } else if self.normalized_tags.contains(token)
                || self.normalized_search_terms.contains(token)
            {
                500
            } else if contains_word(&self.normalized_title, token) {
                400
            } else if self.normalized_title.contains(token) {
                300
            } else if self.normalized_id.contains(token) {
                200
            } else if self.normalized_summary.contains(token) {
                100
            } else {
                return None;
            };
            score = score.saturating_add(token_score);
        }
        Some(score)
    }

    fn stable_key(&self) -> (&str, &str, CapabilityKind) {
        (
            &self.capability_id,
            &self.capability_version,
            self.metadata.compact.kind(),
        )
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "authorized catalog content and normalized search material are deliberately redacted"
)]
impl fmt::Debug for CatalogEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatalogEntry")
            .field("content", &"[redacted]")
            .field("kind", &self.metadata.compact.kind())
            .finish()
    }
}

/// Bounded revision supplied by the trusted authorization-policy adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationRevision(String);

impl AuthorizationRevision {
    /// Creates one opaque server-side authorization revision.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when the revision is empty, oversized, or
    /// contains whitespace or control characters.
    pub fn try_new(value: impl Into<String>) -> Result<Self, DiscoveryModelError> {
        let value = value.into();
        validate_token(&value, MAX_AUTHORIZATION_REVISION_BYTES)?;
        Ok(Self(value))
    }

    /// Borrows the opaque revision.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "the opaque authorization revision is deliberately fully redacted"
)]
impl fmt::Debug for AuthorizationRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizationRevision([redacted])")
    }
}

/// Immutable private view produced after canonical authorization and tenant filtering.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizedCatalogSnapshot {
    authorization_revision: AuthorizationRevision,
    fingerprint: [u8; 32],
    entries: Vec<CatalogEntry>,
}

impl AuthorizedCatalogSnapshot {
    /// Builds a deterministic bounded snapshot and derives its fingerprint from the authorized set.
    ///
    /// A repeated adapter authorization revision cannot preserve a cursor when any projected entry
    /// changes because the independently derived fingerprint covers all ordered entry fields.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::SnapshotTooLarge`] when the hard entry ceiling is exceeded,
    /// or [`DiscoveryModelError::DuplicateValue`] when ordered entry identities collide.
    pub fn try_new(
        authorization_revision: AuthorizationRevision,
        mut entries: Vec<CatalogEntry>,
    ) -> Result<Self, DiscoveryModelError> {
        if entries.len() > HARD_MAX_SCAN_ENTRIES {
            return Err(DiscoveryModelError::SnapshotTooLarge);
        }
        entries.sort_by(|left, right| left.stable_key().cmp(&right.stable_key()));
        if entries
            .windows(2)
            .any(|pair| pair[0].stable_key() == pair[1].stable_key())
        {
            return Err(DiscoveryModelError::DuplicateValue);
        }
        let fingerprint = fingerprint(&entries)?;
        Ok(Self {
            authorization_revision,
            fingerprint,
            entries,
        })
    }

    /// Borrows the trusted authorization revision bound to cursors.
    #[must_use]
    pub const fn authorization_revision(&self) -> &AuthorizationRevision {
        &self.authorization_revision
    }

    #[must_use]
    pub(crate) const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Borrows entries in deterministic capability/version/kind order.
    #[must_use]
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "the authorization revision, fingerprint, and authorized entries are deliberately redacted"
)]
impl fmt::Debug for AuthorizedCatalogSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedCatalogSnapshot([redacted])")
    }
}

/// Request presented to the canonical authorization-filtered registry projection.
#[derive(Clone, Copy)]
pub struct AuthorizedSnapshotRequest<'a> {
    request_context: &'a McpRequestContext,
    max_entries: usize,
}

impl<'a> AuthorizedSnapshotRequest<'a> {
    pub(crate) const fn new(request_context: &'a McpRequestContext, max_entries: usize) -> Self {
        Self {
            request_context,
            max_entries,
        }
    }

    /// Returns the authoritative request-scoped identity, tenant, and extension context.
    #[must_use]
    pub const fn request_context(self) -> &'a McpRequestContext {
        self.request_context
    }

    /// Returns the strict maximum number of authorized entries the caller will scan.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }
}

#[allow(
    clippy::missing_fields_in_debug,
    reason = "the authoritative request context is deliberately omitted from diagnostics"
)]
impl fmt::Debug for AuthorizedSnapshotRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedSnapshotRequest")
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

/// Port returning a fresh, canonical, authorization-filtered registry snapshot for every request.
pub trait AuthorizedCatalogPort {
    /// Adapter-specific error, deliberately discarded at the projection boundary.
    type Error;

    /// Returns only tenant- and principal-visible entries plus the current authorization revision.
    ///
    /// # Errors
    ///
    /// Returns the adapter's [`Self::Error`] when a fresh authorization-filtered snapshot cannot
    /// be produced.
    fn authorized_snapshot(
        &self,
        request: AuthorizedSnapshotRequest<'_>,
    ) -> Result<AuthorizedCatalogSnapshot, Self::Error>;
}

/// Trusted metadata adapter invoked only for declarations already admitted by the core filter.
pub trait DiscoveryMetadataProvider {
    /// Adapter-specific failure.
    type Error;

    /// Returns the current server-side authorization-policy revision for this canonical request.
    ///
    /// # Errors
    ///
    /// Returns the provider's [`Self::Error`] when the current policy revision cannot be read.
    fn authorization_revision(
        &self,
        request: &McpRequestContext,
    ) -> Result<AuthorizationRevision, Self::Error>;

    /// Projects compact metadata for one already-authorized canonical declaration.
    ///
    /// # Errors
    ///
    /// Returns the provider's [`Self::Error`] when compact metadata cannot be projected.
    fn metadata(
        &self,
        request: &McpRequestContext,
        document: &CapabilityDocument,
        kind: CapabilityKind,
    ) -> Result<DiscoveryEntryMetadata, Self::Error>;
}

/// Concrete projection over the core's fresh authorization-filtered shared-registry view.
pub struct RegistryCatalogProjection<M> {
    filter: McpExposureFilter,
    metadata: M,
}

impl<M> RegistryCatalogProjection<M> {
    /// Creates a registry projection without adding any route, RPC, method, or notification.
    #[must_use]
    pub const fn new(filter: McpExposureFilter, metadata: M) -> Self {
        Self { filter, metadata }
    }
}

impl<M> AuthorizedCatalogPort for RegistryCatalogProjection<M>
where
    M: DiscoveryMetadataProvider,
{
    type Error = RegistryProjectionError;

    fn authorized_snapshot(
        &self,
        request: AuthorizedSnapshotRequest<'_>,
    ) -> Result<AuthorizedCatalogSnapshot, Self::Error> {
        let context = request.request_context();
        let authorization_revision = self
            .metadata
            .authorization_revision(context)
            .map_err(|_| RegistryProjectionError)?;
        let mut entries = Vec::new();
        for primitive in [
            McpPrimitive::Tool,
            McpPrimitive::Resource,
            McpPrimitive::Prompt,
        ] {
            let kind = CapabilityKind::from_mcp(primitive);
            let authorized = self.filter.authorized(context, primitive);
            for document in authorized.documents() {
                if entries.len() >= request.max_entries() {
                    return Err(RegistryProjectionError);
                }
                let metadata = self
                    .metadata
                    .metadata(context, document, kind)
                    .map_err(|_| RegistryProjectionError)?;
                if metadata.compact().kind() != kind {
                    return Err(RegistryProjectionError);
                }
                entries.push(
                    CatalogEntry::from_document(document, metadata)
                        .map_err(|_| RegistryProjectionError)?,
                );
            }
        }
        AuthorizedCatalogSnapshot::try_new(authorization_revision, entries)
            .map_err(|_| RegistryProjectionError)
    }
}

/// Redacted registry or metadata projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authorized discovery projection failed")]
pub struct RegistryProjectionError;

/// Trusted time port used for cursor expiry; request metadata cannot supply the clock.
pub trait DiscoveryClock {
    /// Returns current Unix time in seconds.
    fn now_unix(&self) -> u64;
}

/// Canonical, bounded search filters.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DiscoveryFilter {
    partitions: BTreeSet<String>,
    tags: BTreeSet<String>,
    kinds: BTreeSet<CapabilityKind>,
}

impl DiscoveryFilter {
    /// Creates filters with stable set ordering and no duplicate values.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidEntry`] when a filter count or value violates its
    /// bound, or [`DiscoveryModelError::DuplicateValue`] when a value occurs more than once.
    pub fn try_new(
        partitions: impl IntoIterator<Item = String>,
        tags: impl IntoIterator<Item = String>,
        kinds: impl IntoIterator<Item = CapabilityKind>,
    ) -> Result<Self, DiscoveryModelError> {
        let partitions = collect_tokens(partitions, MAX_FILTER_VALUES, MAX_PARTITION_BYTES)?;
        let tags = collect_tokens(tags, MAX_FILTER_VALUES, MAX_TAG_BYTES)?;
        let kinds = collect_unique(kinds, MAX_FILTER_VALUES)?;
        Ok(Self {
            partitions,
            tags,
            kinds,
        })
    }

    pub(crate) fn matches(&self, entry: &CatalogEntry) -> bool {
        let metadata = entry.metadata();
        (self.partitions.is_empty() || self.partitions.contains(metadata.partition()))
            && (self.tags.is_empty() || self.tags.iter().all(|tag| metadata.tags().contains(tag)))
            && (self.kinds.is_empty() || self.kinds.contains(&metadata.compact().kind()))
    }

    pub(crate) fn binding_parts(
        &self,
    ) -> (
        &BTreeSet<String>,
        &BTreeSet<String>,
        &BTreeSet<CapabilityKind>,
    ) {
        (&self.partitions, &self.tags, &self.kinds)
    }
}

/// Page, scan, and cursor ceilings for one discovery projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryLimits {
    max_page_size: u16,
    max_scan_entries: usize,
    cursor_ttl_seconds: u64,
}

impl DiscoveryLimits {
    /// Creates non-zero limits within hard page, scan, and expiry ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`DiscoveryModelError::InvalidLimits`] when any limit is zero or exceeds its hard
    /// ceiling.
    pub fn try_new(
        max_page_size: u16,
        max_scan_entries: usize,
        cursor_ttl_seconds: u64,
    ) -> Result<Self, DiscoveryModelError> {
        if max_page_size == 0
            || max_page_size > HARD_MAX_PAGE_SIZE
            || max_scan_entries == 0
            || max_scan_entries > HARD_MAX_SCAN_ENTRIES
            || cursor_ttl_seconds == 0
            || cursor_ttl_seconds > MAX_CURSOR_TTL_SECONDS
        {
            return Err(DiscoveryModelError::InvalidLimits);
        }
        Ok(Self {
            max_page_size,
            max_scan_entries,
            cursor_ttl_seconds,
        })
    }

    pub(crate) const fn max_page_size(self) -> u16 {
        self.max_page_size
    }

    pub(crate) const fn max_scan_entries(self) -> usize {
        self.max_scan_entries
    }

    pub(crate) const fn cursor_ttl_seconds(self) -> u64 {
        self.cursor_ttl_seconds
    }
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_page_size: 50,
            max_scan_entries: 512,
            cursor_ttl_seconds: 300,
        }
    }
}

/// Invalid catalog entry, filter, snapshot, or service ceiling.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DiscoveryModelError {
    /// A catalog fact is empty, oversized, inconsistent, or contains control characters.
    #[error("invalid discovery catalog entry")]
    InvalidEntry,
    /// A set contains a duplicate value.
    #[error("duplicate discovery value")]
    DuplicateValue,
    /// The authorized snapshot exceeds the hard scan ceiling.
    #[error("authorized discovery snapshot too large")]
    SnapshotTooLarge,
    /// Page, scan, or cursor limits are invalid.
    #[error("invalid discovery limits")]
    InvalidLimits,
}

pub(crate) fn normalize(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for word in value.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.extend(word.chars().flat_map(char::to_lowercase));
    }
    normalized
}

fn fingerprint(entries: &[CatalogEntry]) -> Result<[u8; 32], DiscoveryModelError> {
    let mut hash = Sha256::new();
    hash.update(SNAPSHOT_DOMAIN);
    hash_count(&mut hash, entries.len())?;
    for entry in entries {
        hash_component(&mut hash, entry.capability_id.as_bytes())?;
        hash_component(&mut hash, entry.capability_version.as_bytes())?;
        hash_component(&mut hash, entry.title.as_bytes())?;
        hash_optional(&mut hash, entry.summary.as_deref())?;
        let metadata = entry.metadata();
        hash_component(&mut hash, metadata.partition.as_bytes())?;
        hash_strings(&mut hash, &metadata.tags)?;
        hash_strings(&mut hash, &metadata.search_terms)?;
        hash.update([metadata.compact.kind().binding_tag()]);
        hash_optional(&mut hash, metadata.compact.canonical_result_contract())?;
        match metadata.compact.resource_hints() {
            Some(hints) => hash.update([
                1,
                u8::from(hints.range_ready),
                u8::from(hints.hierarchy_ready),
                u8::from(hints.checksum_ready),
                u8::from(hints.object_reference_ready),
            ]),
            None => hash.update([0, 0, 0, 0, 0]),
        }
        hash_count(&mut hash, metadata.future.fields.len())?;
        for (key, value) in &metadata.future.fields {
            hash_component(&mut hash, key.as_bytes())?;
            hash_component(&mut hash, value)?;
        }
    }
    Ok(hash.finalize().into())
}

fn hash_strings(hash: &mut Sha256, values: &BTreeSet<String>) -> Result<(), DiscoveryModelError> {
    hash_count(hash, values.len())?;
    for value in values {
        hash_component(hash, value.as_bytes())?;
    }
    Ok(())
}

fn hash_optional(hash: &mut Sha256, value: Option<&str>) -> Result<(), DiscoveryModelError> {
    if let Some(value) = value {
        hash.update([1]);
        return hash_component(hash, value.as_bytes());
    }
    hash.update([0]);
    Ok(())
}

fn hash_count(hash: &mut Sha256, count: usize) -> Result<(), DiscoveryModelError> {
    let count = u64::try_from(count).map_err(|_| DiscoveryModelError::InvalidEntry)?;
    hash.update(count.to_be_bytes());
    Ok(())
}

fn hash_component(hash: &mut Sha256, value: &[u8]) -> Result<(), DiscoveryModelError> {
    hash_count(hash, value.len())?;
    hash.update(value);
    Ok(())
}

fn validate_display_text(value: &str, max_bytes: usize) -> Result<(), DiscoveryModelError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(DiscoveryModelError::InvalidEntry);
    }
    Ok(())
}

fn validate_summary(value: &str) -> Result<(), DiscoveryModelError> {
    if value.len() > MAX_SUMMARY_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(DiscoveryModelError::InvalidEntry);
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), DiscoveryModelError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(DiscoveryModelError::InvalidEntry);
    }
    Ok(())
}

fn validate_token(value: &str, max_bytes: usize) -> Result<(), DiscoveryModelError> {
    validate_text(value, max_bytes)?;
    if value.chars().any(char::is_whitespace) {
        return Err(DiscoveryModelError::InvalidEntry);
    }
    Ok(())
}

fn collect_tokens(
    values: impl IntoIterator<Item = String>,
    maximum_items: usize,
    max_bytes: usize,
) -> Result<BTreeSet<String>, DiscoveryModelError> {
    let mut collected = BTreeSet::new();
    for value in values {
        if collected.len() >= maximum_items {
            return Err(DiscoveryModelError::InvalidEntry);
        }
        validate_token(&value, max_bytes)?;
        if !collected.insert(value) {
            return Err(DiscoveryModelError::DuplicateValue);
        }
    }
    Ok(collected)
}

fn collect_text(
    values: impl IntoIterator<Item = String>,
    maximum_items: usize,
    max_bytes: usize,
) -> Result<BTreeSet<String>, DiscoveryModelError> {
    let mut collected = BTreeSet::new();
    for value in values {
        if collected.len() >= maximum_items {
            return Err(DiscoveryModelError::InvalidEntry);
        }
        validate_text(&value, max_bytes)?;
        if !collected.insert(value) {
            return Err(DiscoveryModelError::DuplicateValue);
        }
    }
    Ok(collected)
}

fn collect_unique<T: Ord>(
    values: impl IntoIterator<Item = T>,
    maximum_items: usize,
) -> Result<BTreeSet<T>, DiscoveryModelError> {
    let mut collected = BTreeSet::new();
    for value in values {
        if collected.len() >= maximum_items {
            return Err(DiscoveryModelError::InvalidEntry);
        }
        if !collected.insert(value) {
            return Err(DiscoveryModelError::DuplicateValue);
        }
    }
    Ok(collected)
}

fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack.split(' ').any(|word| word == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(kind: CapabilityKind) -> Result<DiscoveryEntryMetadata, DiscoveryModelError> {
        let compact = match kind {
            CapabilityKind::Tool => CompactCapability::tool("canonical-result-v1")?,
            CapabilityKind::Resource => CompactCapability::resource(ResourceDiscoveryHints {
                range_ready: true,
                ..ResourceDiscoveryHints::default()
            }),
            CapabilityKind::Prompt => CompactCapability::prompt(),
        };
        DiscoveryEntryMetadata::try_new(
            "primary",
            ["search".to_owned()],
            ["record lookup".to_owned()],
            compact,
            FutureDiscoveryMetadata::try_new([("future.v1".to_owned(), vec![0, 1, 255])])?,
        )
    }

    fn entry(id: &str, version: &str) -> Result<CatalogEntry, DiscoveryModelError> {
        CatalogEntry::try_new(
            id,
            version,
            format!("Title {id}"),
            Some("summary".to_owned()),
            metadata(CapabilityKind::Tool)?,
        )
    }

    #[test]
    fn snapshot_fingerprint_is_deterministic_and_not_an_adapter_revision()
    -> Result<(), Box<dyn std::error::Error>> {
        let revision = AuthorizationRevision::try_new("policy-7")?;
        let first = AuthorizedCatalogSnapshot::try_new(
            revision.clone(),
            vec![entry("tool.z", "1.0.0")?, entry("tool.a", "1.0.0")?],
        )?;
        let reordered = AuthorizedCatalogSnapshot::try_new(
            revision.clone(),
            vec![entry("tool.a", "1.0.0")?, entry("tool.z", "1.0.0")?],
        )?;
        let changed = AuthorizedCatalogSnapshot::try_new(
            revision,
            vec![entry("tool.a", "1.0.1")?, entry("tool.z", "1.0.0")?],
        )?;

        assert_eq!(first.fingerprint(), reordered.fingerprint());
        assert_ne!(first.fingerprint(), changed.fingerprint());
        assert_eq!(first.entries()[0].capability_id(), "tool.a");
        assert_eq!(
            first.entries()[0].metadata().future().fields()["future.v1"],
            vec![0, 1, 255]
        );
        Ok(())
    }
}
