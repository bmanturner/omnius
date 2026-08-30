use std::fmt;

use omnius_agent_capability_registry::CapabilityKey;
use serde::Deserialize;

use crate::{ByteRange, CacheControl, MimeType, OpaqueResourceValue, ResourceUri, Sha256Digest};

/// Decoded canonical resource content independent of any MCP SDK representation.
pub enum ResourceContent {
    /// Canonical UTF-8 text.
    Text(String),
    /// Canonical decoded binary bytes.
    Binary(Vec<u8>),
}

impl ResourceContent {
    /// Returns UTF-8 text when this is textual content.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::Binary(_) => None,
        }
    }

    /// Returns decoded bytes when this is binary content.
    #[must_use]
    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Self::Text(_) => None,
            Self::Binary(bytes) => Some(bytes),
        }
    }

    /// Returns the decoded byte length.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Binary(bytes) => bytes.len(),
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        match self {
            Self::Text(text) => text.as_bytes(),
            Self::Binary(bytes) => bytes,
        }
    }
}

/// Prevalidated cache metadata returned by the canonical registry.
pub struct ResourceCacheMetadata {
    etag: Sha256Digest,
    control: CacheControl,
}

impl ResourceCacheMetadata {
    pub(crate) const fn new(etag: Sha256Digest, control: CacheControl) -> Self {
        Self { etag, control }
    }

    /// Returns the canonical entity tag.
    #[must_use]
    pub const fn etag(&self) -> &Sha256Digest {
        &self.etag
    }

    /// Returns validated cache-control metadata.
    #[must_use]
    pub const fn control(&self) -> CacheControl {
        self.control
    }
}

/// Domain-safe provenance retained internally rather than implicitly wire-exposed.
pub struct ResourceProvenance {
    capability: CapabilityKey,
    source_revision: OpaqueResourceValue,
}

impl ResourceProvenance {
    pub(crate) const fn new(
        capability: CapabilityKey,
        source_revision: OpaqueResourceValue,
    ) -> Self {
        Self {
            capability,
            source_revision,
        }
    }

    /// Returns the canonical capability revision that produced this result.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the bounded application provenance revision.
    #[must_use]
    pub const fn source_revision(&self) -> &OpaqueResourceValue {
        &self.source_revision
    }
}

/// Canonical metadata for a bounded inclusive range response.
pub struct ResourceRangeResponse {
    range: ByteRange,
    total_length: u64,
}

impl ResourceRangeResponse {
    pub(crate) const fn new(range: ByteRange, total_length: u64) -> Self {
        Self {
            range,
            total_length,
        }
    }

    /// Returns the exact fulfilled range.
    #[must_use]
    pub const fn range(&self) -> ByteRange {
        self.range
    }

    /// Returns the bounded complete object length.
    #[must_use]
    pub const fn total_length(&self) -> u64 {
        self.total_length
    }
}

/// Hierarchy-ready metadata from the internal canonical resource port.
pub struct ResourceHierarchy {
    parent: Option<ResourceUri>,
    children: Vec<ResourceUri>,
    next_cursor: Option<OpaqueResourceValue>,
}

impl ResourceHierarchy {
    pub(crate) const fn new(
        parent: Option<ResourceUri>,
        children: Vec<ResourceUri>,
        next_cursor: Option<OpaqueResourceValue>,
    ) -> Self {
        Self {
            parent,
            children,
            next_cursor,
        }
    }

    /// Returns the validated optional parent URI.
    #[must_use]
    pub const fn parent(&self) -> Option<&ResourceUri> {
        self.parent.as_ref()
    }

    /// Returns validated hierarchy child URIs.
    #[must_use]
    pub fn children(&self) -> &[ResourceUri] {
        &self.children
    }

    /// Returns the bounded opaque continuation cursor.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<&OpaqueResourceValue> {
        self.next_cursor.as_ref()
    }
}

/// Object-reference-ready metadata without implicit fetching semantics.
pub struct ResourceObjectReference {
    store: OpaqueResourceValue,
    object_id: OpaqueResourceValue,
    version: Option<OpaqueResourceValue>,
}

impl ResourceObjectReference {
    pub(crate) const fn new(
        store: OpaqueResourceValue,
        object_id: OpaqueResourceValue,
        version: Option<OpaqueResourceValue>,
    ) -> Self {
        Self {
            store,
            object_id,
            version,
        }
    }

    /// Returns the bounded logical store identifier.
    #[must_use]
    pub const fn store(&self) -> &OpaqueResourceValue {
        &self.store
    }

    /// Returns the bounded opaque object identifier.
    #[must_use]
    pub const fn object_id(&self) -> &OpaqueResourceValue {
        &self.object_id
    }

    /// Returns the optional bounded object version.
    #[must_use]
    pub const fn version(&self) -> Option<&OpaqueResourceValue> {
        self.version.as_ref()
    }
}

/// A fully validated canonical registry result ready for an explicit wire adapter.
pub struct ResourceResult {
    uri: ResourceUri,
    mime_type: MimeType,
    content: ResourceContent,
    provenance: ResourceProvenance,
    cache: ResourceCacheMetadata,
    range: Option<ResourceRangeResponse>,
    hierarchy: Option<ResourceHierarchy>,
    checksum: Sha256Digest,
    object_reference: Option<ResourceObjectReference>,
}

impl ResourceResult {
    #[expect(
        clippy::too_many_arguments,
        reason = "the canonical result deliberately preserves each independent resource contract"
    )]
    pub(crate) const fn new(
        uri: ResourceUri,
        mime_type: MimeType,
        content: ResourceContent,
        provenance: ResourceProvenance,
        cache: ResourceCacheMetadata,
        range: Option<ResourceRangeResponse>,
        hierarchy: Option<ResourceHierarchy>,
        checksum: Sha256Digest,
        object_reference: Option<ResourceObjectReference>,
    ) -> Self {
        Self {
            uri,
            mime_type,
            content,
            provenance,
            cache,
            range,
            hierarchy,
            checksum,
            object_reference,
        }
    }

    /// Returns the exact requested canonical URI echoed by the registry result.
    #[must_use]
    pub const fn uri(&self) -> &ResourceUri {
        &self.uri
    }

    /// Returns the normalized validated MIME type.
    #[must_use]
    pub const fn mime_type(&self) -> &MimeType {
        &self.mime_type
    }

    /// Returns canonical text or decoded binary content.
    #[must_use]
    pub const fn content(&self) -> &ResourceContent {
        &self.content
    }

    /// Returns internal domain-safe provenance for deliberate adapter handling.
    #[must_use]
    pub const fn provenance(&self) -> &ResourceProvenance {
        &self.provenance
    }

    /// Returns validated cache metadata.
    #[must_use]
    pub const fn cache(&self) -> &ResourceCacheMetadata {
        &self.cache
    }

    /// Returns exact bounded range metadata when a range was requested.
    #[must_use]
    pub const fn range(&self) -> Option<&ResourceRangeResponse> {
        self.range.as_ref()
    }

    /// Returns hierarchy-ready internal metadata when supplied.
    #[must_use]
    pub const fn hierarchy(&self) -> Option<&ResourceHierarchy> {
        self.hierarchy.as_ref()
    }

    /// Returns the verified SHA-256 checksum of the returned decoded bytes.
    #[must_use]
    pub const fn checksum(&self) -> &Sha256Digest {
        &self.checksum
    }

    /// Returns bounded object-reference-ready metadata without fetching it.
    #[must_use]
    pub const fn object_reference(&self) -> Option<&ResourceObjectReference> {
        self.object_reference.as_ref()
    }
}

impl fmt::Debug for ResourceResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceResult([redacted])")
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawResourceResult {
    pub(crate) uri: String,
    pub(crate) mime_type: String,
    pub(crate) content: RawResourceContent,
    pub(crate) provenance: RawProvenance,
    pub(crate) cache: RawCacheMetadata,
    #[serde(default)]
    pub(crate) range: Option<RawRangeResponse>,
    #[serde(default)]
    pub(crate) hierarchy: Option<RawHierarchy>,
    pub(crate) checksum: String,
    #[serde(default)]
    pub(crate) object_reference: Option<RawObjectReference>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub(crate) enum RawResourceContent {
    Text { text: String },
    Binary { base64: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawProvenance {
    pub(crate) capability_id: String,
    pub(crate) capability_version: String,
    pub(crate) source_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCacheMetadata {
    pub(crate) scope: RawCacheScope,
    pub(crate) max_age_seconds: u32,
    pub(crate) etag: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RawCacheScope {
    Private,
    Public,
    NoStore,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawRangeResponse {
    pub(crate) start: u64,
    pub(crate) end_inclusive: u64,
    pub(crate) total_length: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawHierarchy {
    #[serde(default)]
    pub(crate) parent_uri: Option<String>,
    #[serde(default)]
    pub(crate) child_uris: Vec<String>,
    #[serde(default)]
    pub(crate) next_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawObjectReference {
    pub(crate) store: String,
    pub(crate) object_id: String,
    #[serde(default)]
    pub(crate) version: Option<String>,
}
