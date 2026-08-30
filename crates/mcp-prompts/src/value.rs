use std::{fmt, sync::Arc};

use omnius_mcp_server_core::McpContractChange;
use serde::{Serialize, Serializer};
use thiserror::Error;

const MAX_PUBLIC_NAME_BYTES: usize = 128;
const MAX_SCHEMA_REVISION_BYTES: usize = 64;
const MAX_CATALOG_REVISION_BYTES: usize = 128;
const MAX_CACHE_TTL_MS: u64 = 86_400_000;

/// A fixed category for invalid public prompt projection values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PromptValueError {
    /// A public prompt name was not a stable, explicitly versioned name.
    #[error("public prompt name is invalid")]
    PublicName,
    /// A schema revision was empty, oversized, or malformed.
    #[error("prompt schema revision is invalid")]
    SchemaRevision,
    /// A catalog revision was empty, oversized, or malformed.
    #[error("prompt catalog revision is invalid")]
    CatalogRevision,
    /// Cache control was outside its fixed safe boundary.
    #[error("prompt cache control is invalid")]
    CacheControl,
}

/// An explicit, stable, versioned public MCP prompt name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicPromptName(Arc<str>);

impl PublicPromptName {
    /// Validates and owns a public name such as `omnius.support.summarize.v1`.
    ///
    /// # Errors
    ///
    /// Returns [`PromptValueError::PublicName`] unless the name is lowercase,
    /// namespaced, bounded, and ends in a positive `.vN` version segment.
    pub fn new(value: impl Into<String>) -> Result<Self, PromptValueError> {
        let value = value.into();
        let Some((prefix, version)) = value.rsplit_once(".v") else {
            return Err(PromptValueError::PublicName);
        };
        let mut prefix_segments = prefix.split('.');
        let Some(first) = prefix_segments.next() else {
            return Err(PromptValueError::PublicName);
        };
        let has_second = prefix_segments.next().is_some();
        let valid_segment = |segment: &str| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        };
        if value.len() > MAX_PUBLIC_NAME_BYTES
            || !has_second
            || !valid_segment(first)
            || prefix.split('.').any(|segment| !valid_segment(segment))
            || version.is_empty()
            || version.starts_with('0')
            || !version.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(PromptValueError::PublicName);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Borrows the stable public name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl Serialize for PublicPromptName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl fmt::Debug for PublicPromptName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicPromptName([redacted])")
    }
}

/// An explicit bounded revision for the projected argument schema.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SchemaRevision(String);

impl SchemaRevision {
    /// Validates and owns an opaque schema revision.
    ///
    /// # Errors
    ///
    /// Returns [`PromptValueError::SchemaRevision`] for an empty, oversized, or
    /// malformed revision.
    pub fn new(value: impl Into<String>) -> Result<Self, PromptValueError> {
        let value = value.into();
        if !valid_opaque(&value, MAX_SCHEMA_REVISION_BYTES) {
            return Err(PromptValueError::SchemaRevision);
        }
        Ok(Self(value))
    }

    /// Borrows the schema revision.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SchemaRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SchemaRevision([redacted])")
    }
}

/// A bounded opaque revision for one immutable projection catalog.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct CatalogRevision(String);

impl CatalogRevision {
    /// Validates and owns an opaque catalog revision.
    ///
    /// # Errors
    ///
    /// Returns [`PromptValueError::CatalogRevision`] for an empty, oversized,
    /// or malformed revision.
    pub fn new(value: impl Into<String>) -> Result<Self, PromptValueError> {
        let value = value.into();
        if !valid_opaque(&value, MAX_CATALOG_REVISION_BYTES) {
            return Err(PromptValueError::CatalogRevision);
        }
        Ok(Self(value))
    }

    /// Borrows the opaque catalog revision.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CatalogRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatalogRevision([redacted])")
    }
}

/// Shared-cache visibility for authorized prompt discovery metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheScope {
    /// Metadata is safe for shared caches.
    Public,
    /// Metadata is authorization-sensitive and restricted to a private cache.
    Private,
}

impl CacheScope {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
        }
    }
}

/// Prevalidated cache metadata for authorized prompt discovery.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheControl {
    scope: CacheScope,
    ttl_ms: u64,
    header_value: String,
}

impl CacheControl {
    /// Creates canonical cache control from an explicit scope and TTL.
    ///
    /// # Errors
    ///
    /// Returns [`PromptValueError::CacheControl`] when `ttl_ms` is zero, exceeds
    /// one day, or is not divisible by 1000.
    pub fn new(scope: CacheScope, ttl_ms: u64) -> Result<Self, PromptValueError> {
        if ttl_ms == 0 || ttl_ms > MAX_CACHE_TTL_MS || !ttl_ms.is_multiple_of(1_000) {
            return Err(PromptValueError::CacheControl);
        }
        let max_age_seconds = ttl_ms / 1_000;
        Ok(Self {
            scope,
            ttl_ms,
            header_value: format!("{}, max-age={max_age_seconds}", scope.as_str()),
        })
    }

    /// Returns the explicit cache scope.
    #[must_use]
    pub const fn scope(&self) -> CacheScope {
        self.scope
    }

    /// Returns the bounded TTL in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// Borrows the canonical `<scope>, max-age=<ttlMs/1000>` value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.header_value
    }
}

impl fmt::Debug for CacheControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheControl([redacted])")
    }
}

/// A visibility-sensitive quoted SHA-256 entity tag for an authorized prompt list.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CatalogEtag(String);

impl CatalogEtag {
    pub(crate) fn from_sha256(digest: [u8; 32]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(73);
        value.push_str("\"sha256:");
        for byte in digest {
            value.push(char::from(HEX[usize::from(byte >> 4)]));
            value.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        value.push('"');
        Self(value)
    }

    /// Borrows the canonical quoted `"sha256:<64 lowercase hex>"` value.
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

/// Public compatibility state for a stable prompt name and schema revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityStatus {
    /// The public prompt name is active for new clients.
    Active,
    /// The public prompt name remains compatible but clients should migrate.
    Deprecated,
}

/// Explicit compatibility and deprecation metadata for a public prompt name.
///
/// Active names carry no deprecation window. Deprecated names always carry
/// both the schema revision where the window began and a reviewed contract
/// change classification.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PromptCompatibility {
    status: CompatibilityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    since_schema_revision: Option<SchemaRevision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    change: Option<McpContractChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replacement: Option<PublicPromptName>,
}

impl PromptCompatibility {
    /// Creates active compatibility metadata without a deprecation window.
    #[must_use]
    pub const fn active() -> Self {
        Self {
            status: CompatibilityStatus::Active,
            since_schema_revision: None,
            change: None,
            replacement: None,
        }
    }

    /// Creates a complete deprecated compatibility window.
    #[must_use]
    pub fn deprecated(
        since_schema_revision: SchemaRevision,
        change: McpContractChange,
        replacement: Option<PublicPromptName>,
    ) -> Self {
        Self {
            status: CompatibilityStatus::Deprecated,
            since_schema_revision: Some(since_schema_revision),
            change: Some(change),
            replacement,
        }
    }

    /// Returns the compatibility state.
    #[must_use]
    pub const fn status(&self) -> CompatibilityStatus {
        self.status
    }

    /// Borrows the schema revision where the deprecation window began.
    #[must_use]
    pub const fn since_schema_revision(&self) -> Option<&SchemaRevision> {
        self.since_schema_revision.as_ref()
    }

    /// Returns the reviewed incompatible contract change classification.
    #[must_use]
    pub const fn change(&self) -> Option<McpContractChange> {
        self.change
    }

    /// Borrows the explicit replacement public name, when declared.
    #[must_use]
    pub const fn replacement(&self) -> Option<&PublicPromptName> {
        self.replacement.as_ref()
    }

    pub(crate) fn without_replacement(&self) -> Self {
        Self {
            status: self.status,
            since_schema_revision: self.since_schema_revision.clone(),
            change: self.change,
            replacement: None,
        }
    }
}

impl fmt::Debug for PromptCompatibility {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PromptCompatibility([redacted])")
    }
}

fn valid_opaque(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-' | b'@')
        })
}
