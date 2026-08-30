use std::{collections::BTreeSet, fmt};

use omnius_mcp_server_core::{McpContractChange, McpExtension};
use serde::Serialize;

/// Maximum decoded resource content accepted from the canonical registry.
pub const MAX_RESOURCE_CONTENT_BYTES: u64 = 8 * 1_024 * 1_024;
/// Maximum number of bytes in one resource range response.
pub const MAX_RESOURCE_RANGE_BYTES: u64 = 1_024 * 1_024;
/// Maximum cache lifetime accepted from a declaration or registry result.
pub const MAX_CACHE_AGE_SECONDS: u32 = 86_400;
/// Maximum extension requirements accepted on one catalog declaration.
pub const MAX_REQUIRED_EXTENSIONS: usize = 32;

/// Stable, value-free resource projection failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceErrorCode {
    /// A public value violated its fixed grammar or bound.
    InvalidValue,
    /// An immutable catalog declaration was inconsistent or ambiguous.
    InvalidDeclaration,
    /// A request violated a declared contract.
    InvalidRequest,
    /// The request was rejected without revealing policy or catalog state.
    Rejected,
    /// Execution could not complete within current lifecycle bounds.
    Unavailable,
    /// Registry output violated the declared canonical result contract.
    InvalidOutput,
    /// An internal operation failed without caller-actionable detail.
    Internal,
}

/// A redacted failure at the MCP resource projection boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResourceError {
    code: ResourceErrorCode,
}

impl ResourceError {
    /// Returns the fixed public failure category.
    #[must_use]
    pub const fn code(self) -> ResourceErrorCode {
        self.code
    }

    pub(crate) const fn invalid_value() -> Self {
        Self {
            code: ResourceErrorCode::InvalidValue,
        }
    }

    pub(crate) const fn invalid_declaration() -> Self {
        Self {
            code: ResourceErrorCode::InvalidDeclaration,
        }
    }

    pub(crate) const fn invalid_request() -> Self {
        Self {
            code: ResourceErrorCode::InvalidRequest,
        }
    }

    pub(crate) const fn rejected() -> Self {
        Self {
            code: ResourceErrorCode::Rejected,
        }
    }

    pub(crate) const fn unavailable() -> Self {
        Self {
            code: ResourceErrorCode::Unavailable,
        }
    }

    pub(crate) const fn invalid_output() -> Self {
        Self {
            code: ResourceErrorCode::InvalidOutput,
        }
    }

    pub(crate) const fn internal() -> Self {
        Self {
            code: ResourceErrorCode::Internal,
        }
    }
}

impl fmt::Debug for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceError([redacted])")
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP resource projection failed")
    }
}

impl std::error::Error for ResourceError {}

macro_rules! bounded_string_type {
    ($name:ident, $doc:literal, $validator:ident) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a public value.
            ///
            /// # Errors
            ///
            /// Returns a redacted error when the value violates its fixed grammar or bound.
            pub fn new(value: String) -> Result<Self, ResourceError> {
                if !$validator(&value) {
                    return Err(ResourceError::invalid_value());
                }
                Ok(Self(value))
            }

            /// Borrows the validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

bounded_string_type!(
    PublicResourceName,
    "An explicit stable resource name ending in a public `@vN` revision.",
    validate_public_name
);
bounded_string_type!(
    SchemaRevision,
    "A bounded opaque revision of a resource result schema.",
    validate_opaque_revision
);
bounded_string_type!(
    CatalogRevision,
    "A bounded opaque immutable resource catalog revision.",
    validate_opaque_revision
);
bounded_string_type!(
    TemplateVariableName,
    "A strict lower-snake-case resource template variable name.",
    validate_template_variable
);
bounded_string_type!(
    OpaqueResourceValue,
    "A bounded non-secret opaque resource metadata value.",
    validate_opaque_resource_value
);

/// A bounded human-readable resource title.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceTitle(String);

impl ResourceTitle {
    /// Validates and owns a title.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an empty, excessive, or control-bearing title.
    pub fn new(value: String) -> Result<Self, ResourceError> {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self(value))
    }

    /// Borrows the title.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceTitle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceTitle([redacted])")
    }
}

/// A bounded human-readable resource description.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceDescription(String);

impl ResourceDescription {
    /// Validates and owns a description.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for an excessive or control-bearing description.
    pub fn new(value: String) -> Result<Self, ResourceError> {
        if value.len() > 2_048 || value.chars().any(char::is_control) {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self(value))
    }

    /// Borrows the description.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceDescription([redacted])")
    }
}

/// A normalized, bounded MIME media type.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MimeType(String);

impl MimeType {
    /// Parses and normalizes a MIME type and token-valued parameters.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for malformed, excessive, or non-canonical media types.
    pub fn new(value: impl AsRef<str>) -> Result<Self, ResourceError> {
        let normalized = normalize_mime(value.as_ref()).ok_or_else(ResourceError::invalid_value)?;
        Ok(Self(normalized))
    }

    /// Borrows the normalized MIME value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Reports whether this MIME type is safe to pair with canonical UTF-8 text content.
    #[must_use]
    pub fn is_textual(&self) -> bool {
        let media_type = self.0.split(';').next().unwrap_or_default();
        media_type.starts_with("text/")
            || matches!(
                media_type,
                "application/json"
                    | "application/xml"
                    | "application/javascript"
                    | "application/graphql-response+json"
            )
            || media_type.ends_with("+json")
            || media_type.ends_with("+xml")
    }

    /// Reports whether an absent or explicit charset agrees with canonical UTF-8 text.
    ///
    /// An explicit charset must be `utf-8` or `utf8`, compared case-insensitively.
    #[must_use]
    pub fn is_utf8_compatible(&self) -> bool {
        self.0
            .split(';')
            .skip(1)
            .find_map(|parameter| parameter.trim().strip_prefix("charset="))
            .is_none_or(|charset| {
                charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("utf8")
            })
    }
}

impl fmt::Debug for MimeType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MimeType([redacted])")
    }
}

/// A validated lowercase SHA-256 checksum or entity tag.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Validates a `sha256:<64 lowercase hex>` value.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the checksum is not canonical.
    pub fn new(value: String) -> Result<Self, ResourceError> {
        if !is_sha256(&value) {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self(value))
    }

    pub(crate) fn from_hex(hex: &str) -> Self {
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        value.push_str(hex);
        Self(value)
    }

    /// Borrows the canonical checksum.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest([redacted])")
    }
}

/// Compatibility state for one explicit public resource name.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ResourceCompatibility {
    /// The public name and schema revision are active.
    Active,
    /// The public name remains available under an explicit deprecation contract.
    Deprecated {
        /// Schema revision in which deprecation became active.
        since_schema_revision: SchemaRevision,
        /// Reviewed classification of the incompatible contract change.
        change: McpContractChange,
        /// Optional explicit replacement public name.
        #[serde(skip_serializing_if = "Option::is_none")]
        replacement: Option<PublicResourceName>,
    },
}

impl ResourceCompatibility {
    /// Returns whether callers should migrate away from this public name.
    #[must_use]
    pub const fn is_deprecated(&self) -> bool {
        matches!(self, Self::Deprecated { .. })
    }

    /// Returns the schema revision in which deprecation became active.
    #[must_use]
    pub const fn since_schema_revision(&self) -> Option<&SchemaRevision> {
        match self {
            Self::Active => None,
            Self::Deprecated {
                since_schema_revision,
                ..
            } => Some(since_schema_revision),
        }
    }

    /// Returns the reviewed incompatible contract change classification.
    #[must_use]
    pub const fn change(&self) -> Option<McpContractChange> {
        match self {
            Self::Active => None,
            Self::Deprecated { change, .. } => Some(*change),
        }
    }

    /// Returns the optional active replacement public name.
    #[must_use]
    pub const fn replacement(&self) -> Option<&PublicResourceName> {
        match self {
            Self::Active
            | Self::Deprecated {
                replacement: None, ..
            } => None,
            Self::Deprecated {
                replacement: Some(replacement),
                ..
            } => Some(replacement),
        }
    }
}

/// Cache visibility for canonical resource metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheScope {
    /// Cache entries may be reused only within the authorized private cache partition.
    Private,
    /// Cache entries may be reused publicly for explicitly global projections.
    Public,
    /// The result must not be stored.
    NoStore,
}

/// A prevalidated cache-control contract.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
pub struct CacheControl {
    scope: CacheScope,
    max_age_seconds: u32,
}

impl CacheControl {
    /// Creates bounded private cache control.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the lifetime exceeds the global bound.
    pub fn private(max_age_seconds: u32) -> Result<Self, ResourceError> {
        Self::cacheable(CacheScope::Private, max_age_seconds)
    }

    /// Creates bounded public cache control for an explicitly global declaration.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the lifetime exceeds the global bound.
    pub fn public(max_age_seconds: u32) -> Result<Self, ResourceError> {
        Self::cacheable(CacheScope::Public, max_age_seconds)
    }

    /// Creates a no-store cache contract.
    #[must_use]
    pub const fn no_store() -> Self {
        Self {
            scope: CacheScope::NoStore,
            max_age_seconds: 0,
        }
    }

    fn cacheable(scope: CacheScope, max_age_seconds: u32) -> Result<Self, ResourceError> {
        if max_age_seconds > MAX_CACHE_AGE_SECONDS {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self {
            scope,
            max_age_seconds,
        })
    }

    /// Returns the validated visibility scope.
    #[must_use]
    pub const fn scope(self) -> CacheScope {
        self.scope
    }

    /// Returns the bounded cache lifetime.
    #[must_use]
    pub const fn max_age_seconds(self) -> u32 {
        self.max_age_seconds
    }

    /// Returns a canonical HTTP-compatible cache-control value.
    #[must_use]
    pub fn header_value(self) -> String {
        match self.scope {
            CacheScope::Private => format!("private, max-age={}", self.max_age_seconds),
            CacheScope::Public => format!("public, max-age={}", self.max_age_seconds),
            CacheScope::NoStore => "no-store".to_owned(),
        }
    }
}

impl fmt::Debug for CacheControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CacheControl([validated])")
    }
}

/// Immutable metadata shared by exact-resource and resource-template declarations.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceMetadata {
    name: PublicResourceName,
    title: ResourceTitle,
    description: Option<ResourceDescription>,
    schema_revision: SchemaRevision,
    compatibility: ResourceCompatibility,
    mime_type: Option<MimeType>,
    required_extensions: BTreeSet<McpExtension>,
}

impl ResourceMetadata {
    /// Creates explicit public metadata for one stable declaration.
    #[must_use]
    pub fn new(
        name: PublicResourceName,
        title: ResourceTitle,
        description: Option<ResourceDescription>,
        schema_revision: SchemaRevision,
        compatibility: ResourceCompatibility,
        mime_type: Option<MimeType>,
        required_extensions: BTreeSet<McpExtension>,
    ) -> Self {
        Self {
            name,
            title,
            description,
            schema_revision,
            compatibility,
            mime_type,
            required_extensions,
        }
    }

    /// Returns the stable versioned public name.
    #[must_use]
    pub const fn name(&self) -> &PublicResourceName {
        &self.name
    }

    /// Returns the human-readable title.
    #[must_use]
    pub const fn title(&self) -> &ResourceTitle {
        &self.title
    }

    /// Returns the optional bounded description.
    #[must_use]
    pub const fn description(&self) -> Option<&ResourceDescription> {
        self.description.as_ref()
    }

    /// Returns the declared schema revision.
    #[must_use]
    pub const fn schema_revision(&self) -> &SchemaRevision {
        &self.schema_revision
    }

    /// Returns active or deprecated compatibility metadata.
    #[must_use]
    pub const fn compatibility(&self) -> &ResourceCompatibility {
        &self.compatibility
    }

    /// Returns the optional advertised MIME type.
    #[must_use]
    pub const fn mime_type(&self) -> Option<&MimeType> {
        self.mime_type.as_ref()
    }

    /// Borrows the deny-by-default exact extension requirements.
    #[must_use]
    pub const fn required_extensions(&self) -> &BTreeSet<McpExtension> {
        &self.required_extensions
    }
}

/// Declared result and cache bounds for one resource projection.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResourceLimits {
    max_content_bytes: u64,
    max_range_bytes: Option<u64>,
    cache_control: CacheControl,
}

impl ResourceLimits {
    /// Creates fixed content, optional range, and cache bounds.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when any bound is zero, excessive, or inconsistent.
    pub fn new(
        max_content_bytes: u64,
        max_range_bytes: Option<u64>,
        cache_control: CacheControl,
    ) -> Result<Self, ResourceError> {
        if max_content_bytes == 0 || max_content_bytes > MAX_RESOURCE_CONTENT_BYTES {
            return Err(ResourceError::invalid_value());
        }
        if let Some(range) = max_range_bytes
            && (range == 0 || range > MAX_RESOURCE_RANGE_BYTES || range > max_content_bytes)
        {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self {
            max_content_bytes,
            max_range_bytes,
            cache_control,
        })
    }

    /// Returns the maximum declared decoded content size.
    #[must_use]
    pub const fn max_content_bytes(self) -> u64 {
        self.max_content_bytes
    }

    /// Returns the maximum range size when byte ranges are supported.
    #[must_use]
    pub const fn max_range_bytes(self) -> Option<u64> {
        self.max_range_bytes
    }

    /// Returns the maximum declared cache policy.
    #[must_use]
    pub const fn cache_control(self) -> CacheControl {
        self.cache_control
    }
}

impl fmt::Debug for ResourceLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResourceLimits([validated])")
    }
}

/// A globally bounded inclusive byte range.
#[derive(Clone, Copy, Eq, PartialEq, Serialize)]
pub struct ByteRange {
    start: u64,
    end_inclusive: u64,
}

impl ByteRange {
    /// Creates an inclusive byte range within the global per-request bound.
    ///
    /// # Errors
    ///
    /// Returns a redacted error for reversed, excessive, or final-index ranges that cannot
    /// have a representable `total_length` greater than the inclusive end.
    pub fn new(start: u64, end_inclusive: u64) -> Result<Self, ResourceError> {
        if end_inclusive == u64::MAX {
            return Err(ResourceError::invalid_value());
        }
        let length = end_inclusive
            .checked_sub(start)
            .and_then(|difference| difference.checked_add(1))
            .ok_or_else(ResourceError::invalid_value)?;
        if length > MAX_RESOURCE_RANGE_BYTES {
            return Err(ResourceError::invalid_value());
        }
        Ok(Self {
            start,
            end_inclusive,
        })
    }

    /// Returns the first requested byte offset.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the inclusive final requested byte offset.
    #[must_use]
    pub const fn end_inclusive(self) -> u64 {
        self.end_inclusive
    }

    /// Returns the number of requested bytes.
    #[must_use]
    pub const fn length(self) -> u64 {
        self.end_inclusive - self.start + 1
    }
}

impl fmt::Debug for ByteRange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ByteRange([validated])")
    }
}

fn validate_public_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 128 || value.contains("::") || value.contains('/') {
        return false;
    }
    let Some((stem, version)) = value.rsplit_once("@v") else {
        return false;
    };
    if stem.is_empty()
        || version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return false;
    }
    let mut previous_separator = true;
    for byte in stem.bytes() {
        let separator = matches!(byte, b'.' | b'-');
        if separator && previous_separator {
            return false;
        }
        if !separator && !byte.is_ascii_lowercase() && !byte.is_ascii_digit() {
            return false;
        }
        previous_separator = separator;
    }
    !previous_separator && stem.as_bytes()[0].is_ascii_lowercase()
}

fn validate_opaque_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn validate_template_variable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        && !value.ends_with('_')
        && !value.contains("__")
}

fn validate_opaque_resource_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn normalize_mime(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 127 || !value.is_ascii() {
        return None;
    }
    let mut parts = value.split(';');
    let media_type = parts.next()?.trim();
    if media_type != media_type.to_ascii_lowercase() {
        return None;
    }
    let (top_level, subtype) = media_type.split_once('/')?;
    if top_level.is_empty()
        || subtype.is_empty()
        || subtype.contains('/')
        || !top_level.bytes().all(is_mime_token)
        || !subtype.bytes().all(is_mime_token)
    {
        return None;
    }
    let mut normalized = media_type.to_owned();
    let mut parameter_names = BTreeSet::new();
    for parameter in parts {
        let parameter = parameter.trim();
        let (name, parameter_value) = parameter.split_once('=')?;
        if name.is_empty()
            || parameter_value.is_empty()
            || name != name.to_ascii_lowercase()
            || !name.bytes().all(is_mime_token)
            || !parameter_value.bytes().all(is_mime_token)
            || !parameter_names.insert(name)
        {
            return None;
        }
        normalized.push_str("; ");
        normalized.push_str(name);
        normalized.push('=');
        normalized.push_str(parameter_value);
    }
    Some(normalized)
}

fn is_mime_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
        )
}

fn is_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
