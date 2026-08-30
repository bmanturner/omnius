use std::{fmt, io};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::request::BinarySource;
use crate::value::{
    ContractError, JsonObject, UtcTimestamp, deserialize_optional_non_null, validate_identifier,
    validate_mime_type, validate_reference,
};

fn nullable_positive_rate_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "type": ["number", "null"],
        "exclusiveMinimum": 0
    })
}

fn nullable_sha256_schema(_generator: &mut SchemaGenerator) -> Schema {
    schemars::json_schema!({
        "type": ["string", "null"],
        "pattern": "^[a-f0-9]{64}$"
    })
}

/// Explicit resource bounds applied to canonical request and response content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "resource bounds are clearest when every field is explicitly named as a maximum"
)]
pub struct ContentLimits {
    max_string_bytes: usize,
    max_json_bytes: usize,
    max_inline_binary_bytes: usize,
    max_collection_items: usize,
    max_json_nodes: usize,
    max_nesting_depth: usize,
}

impl ContentLimits {
    /// Default maximum UTF-8 bytes in any one content string.
    pub const DEFAULT_MAX_STRING_BYTES: usize = 1_048_576;
    /// Default maximum serialized bytes in any one arbitrary JSON value or object.
    pub const DEFAULT_MAX_JSON_BYTES: usize = 4_194_304;
    /// Default maximum decoded bytes in one inline binary source.
    pub const DEFAULT_MAX_INLINE_BINARY_BYTES: usize = 786_432;
    /// Default maximum entries in any one ordered content collection or JSON container.
    pub const DEFAULT_MAX_COLLECTION_ITEMS: usize = 1_024;
    /// Default maximum value nodes in any one arbitrary JSON value or object.
    pub const DEFAULT_MAX_JSON_NODES: usize = 16_384;
    /// Default maximum nesting depth across content parts and arbitrary JSON.
    pub const DEFAULT_MAX_NESTING_DEPTH: usize = 32;

    /// Creates a complete set of positive content bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when any bound is zero.
    pub fn new(
        max_string_bytes: usize,
        max_json_bytes: usize,
        max_inline_binary_bytes: usize,
        max_collection_items: usize,
        max_json_nodes: usize,
        max_nesting_depth: usize,
    ) -> Result<Self, ContractError> {
        let limits = Self {
            max_string_bytes,
            max_json_bytes,
            max_inline_binary_bytes,
            max_collection_items,
            max_json_nodes,
            max_nesting_depth,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Returns the maximum UTF-8 bytes in one string.
    #[must_use]
    pub const fn max_string_bytes(self) -> usize {
        self.max_string_bytes
    }

    /// Returns the maximum serialized bytes in one arbitrary JSON value or object.
    #[must_use]
    pub const fn max_json_bytes(self) -> usize {
        self.max_json_bytes
    }

    /// Returns the maximum decoded bytes in one inline binary source.
    #[must_use]
    pub const fn max_inline_binary_bytes(self) -> usize {
        self.max_inline_binary_bytes
    }

    /// Returns the maximum entries in one ordered collection or JSON container.
    #[must_use]
    pub const fn max_collection_items(self) -> usize {
        self.max_collection_items
    }

    /// Returns the maximum nodes in one arbitrary JSON value or object.
    #[must_use]
    pub const fn max_json_nodes(self) -> usize {
        self.max_json_nodes
    }

    /// Returns the maximum nesting depth across content and arbitrary JSON.
    #[must_use]
    pub const fn max_nesting_depth(self) -> usize {
        self.max_nesting_depth
    }

    /// Replaces the per-string byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_string_bytes(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_string_bytes = value;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the per-JSON serialized byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_json_bytes(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_json_bytes = value;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the decoded inline-binary byte bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_inline_binary_bytes(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_inline_binary_bytes = value;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the per-container item bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_collection_items(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_collection_items = value;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the per-JSON node bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_json_nodes(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_json_nodes = value;
        self.validate()?;
        Ok(self)
    }

    /// Replaces the content nesting-depth bound.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when `value` is zero.
    pub fn with_max_nesting_depth(mut self, value: usize) -> Result<Self, ContractError> {
        self.max_nesting_depth = value;
        self.validate()?;
        Ok(self)
    }

    fn validate(self) -> Result<(), ContractError> {
        if self.max_string_bytes == 0
            || self.max_json_bytes == 0
            || self.max_inline_binary_bytes == 0
            || self.max_collection_items == 0
            || self.max_json_nodes == 0
            || self.max_nesting_depth == 0
        {
            Err(ContractError::InvalidPositiveLimit)
        } else {
            Ok(())
        }
    }
}

impl Default for ContentLimits {
    fn default() -> Self {
        Self {
            max_string_bytes: Self::DEFAULT_MAX_STRING_BYTES,
            max_json_bytes: Self::DEFAULT_MAX_JSON_BYTES,
            max_inline_binary_bytes: Self::DEFAULT_MAX_INLINE_BINARY_BYTES,
            max_collection_items: Self::DEFAULT_MAX_COLLECTION_ITEMS,
            max_json_nodes: Self::DEFAULT_MAX_JSON_NODES,
            max_nesting_depth: Self::DEFAULT_MAX_NESTING_DEPTH,
        }
    }
}

pub(crate) fn validate_bounded_string(
    value: &str,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if value.len() > limits.max_string_bytes {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_ordered_item_count(
    count: usize,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if count > limits.max_collection_items {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_content_node_count(
    count: usize,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if count > limits.max_json_nodes {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_content_depth(
    depth: usize,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if depth > limits.max_nesting_depth {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_nested_content_collection(
    count: usize,
    limits: &ContentLimits,
    parent_depth: usize,
) -> Result<usize, ContractError> {
    validate_ordered_item_count(count, limits)?;
    let child_depth = next_depth(parent_depth)?;
    validate_content_depth(child_depth, limits)?;
    Ok(child_depth)
}

pub(crate) fn validate_bounded_json(
    value: &Value,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    let mut nodes = 0;
    validate_json_value(value, limits, depth, &mut nodes)?;
    validate_serialized_size(value, limits)
}

pub(crate) fn validate_bounded_json_object(
    value: &JsonObject,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    validate_content_depth(depth, limits)?;
    validate_ordered_item_count(value.len(), limits)?;
    let mut nodes = 1;
    validate_content_node_count(nodes, limits)?;
    let child_depth = next_depth(depth)?;
    for (key, child) in value {
        validate_bounded_string(key, limits)?;
        validate_json_value(child, limits, child_depth, &mut nodes)?;
    }
    validate_serialized_size(value, limits)
}

pub(crate) fn validate_binary_source(
    source: &BinarySource,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    match source {
        BinarySource::Inline(source) => {
            let encoded = source.data_base64();
            validate_reference(encoded)?;
            validate_bounded_string(encoded, limits)?;
            let decoded_bytes = validate_base64_decoded_len(encoded)?;
            if decoded_bytes > limits.max_inline_binary_bytes {
                Err(ContractError::InvalidContent)
            } else {
                Ok(())
            }
        }
        BinarySource::Url(source) => {
            validate_bounded_string(source.url(), limits)?;
            validate_absolute_uri(source.url())
        }
        BinarySource::Object(source) => {
            validate_reference(source.object_key())?;
            validate_bounded_string(source.object_key(), limits)
        }
    }
}

fn validate_json_value(
    value: &Value,
    limits: &ContentLimits,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ContractError> {
    validate_content_depth(depth, limits)?;
    *nodes = nodes.checked_add(1).ok_or(ContractError::InvalidContent)?;
    validate_content_node_count(*nodes, limits)?;
    match value {
        Value::Array(values) => {
            validate_ordered_item_count(values.len(), limits)?;
            let child_depth = next_depth(depth)?;
            values
                .iter()
                .try_for_each(|value| validate_json_value(value, limits, child_depth, nodes))
        }
        Value::Object(values) => {
            validate_ordered_item_count(values.len(), limits)?;
            let child_depth = next_depth(depth)?;
            for (key, value) in values {
                validate_bounded_string(key, limits)?;
                validate_json_value(value, limits, child_depth, nodes)?;
            }
            Ok(())
        }
        Value::String(value) => validate_bounded_string(value, limits),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn next_depth(depth: usize) -> Result<usize, ContractError> {
    depth.checked_add(1).ok_or(ContractError::InvalidContent)
}

fn validate_serialized_size<T: Serialize + ?Sized>(
    value: &T,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    let mut writer = LimitedWriter::new(limits.max_json_bytes);
    serde_json::to_writer(&mut writer, value).map_err(|_| ContractError::InvalidContent)
}

struct LimitedWriter {
    remaining: usize,
}

impl LimitedWriter {
    const fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }
}

impl io::Write for LimitedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(io::Error::other("canonical JSON content limit exceeded"));
        }
        self.remaining -= buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn validate_base64_decoded_len(encoded: &str) -> Result<usize, ContractError> {
    let bytes = encoded.as_bytes();
    if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
        return Err(ContractError::InvalidContent);
    }
    let padding = if bytes.ends_with(b"==") {
        2
    } else {
        usize::from(bytes.ends_with(b"="))
    };
    let data_len = bytes
        .len()
        .checked_sub(padding)
        .ok_or(ContractError::InvalidContent)?;
    if !bytes[..data_len]
        .iter()
        .all(|byte| base64_value(*byte).is_some())
        || !bytes[data_len..].iter().all(|byte| *byte == b'=')
    {
        return Err(ContractError::InvalidContent);
    }
    if padding == 1
        && base64_value(bytes[data_len - 1]).ok_or(ContractError::InvalidContent)? & 0b11 != 0
    {
        return Err(ContractError::InvalidContent);
    }
    if padding == 2
        && base64_value(bytes[data_len - 1]).ok_or(ContractError::InvalidContent)? & 0b1111 != 0
    {
        return Err(ContractError::InvalidContent);
    }
    bytes
        .len()
        .checked_div(4)
        .and_then(|length| length.checked_mul(3))
        .and_then(|length| length.checked_sub(padding))
        .ok_or(ContractError::InvalidContent)
}

const fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn validate_absolute_uri(value: &str) -> Result<(), ContractError> {
    Url::parse(value)
        .map(|_| ())
        .map_err(|_| ContractError::InvalidReference)
}

fn validate_part_id(value: &str, limits: &ContentLimits) -> Result<(), ContractError> {
    validate_identifier(value)?;
    validate_bounded_string(value, limits)
}

fn validate_optional_string(
    value: Option<&str>,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| validate_bounded_string(value, limits))
}

fn validate_optional_timestamp(
    value: Option<UtcTimestamp>,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        let serialized_limit = limits
            .max_string_bytes
            .checked_add(2)
            .ok_or(ContractError::InvalidContent)?;
        let mut writer = LimitedWriter::new(serialized_limit);
        serde_json::to_writer(&mut writer, &value).map_err(|_| ContractError::InvalidContent)?;
    }
    Ok(())
}

fn validate_optional_identifier(
    value: Option<&str>,
    limits: &ContentLimits,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        validate_part_id(value, limits)?;
    }
    Ok(())
}

fn validate_positive(value: Option<u32>) -> Result<(), ContractError> {
    if value == Some(0) {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

fn validate_offsets(start: Option<u64>, end: Option<u64>) -> Result<(), ContractError> {
    if matches!((start, end), (Some(start), Some(end)) if end < start) {
        Err(ContractError::InvalidContent)
    } else {
        Ok(())
    }
}

fn validate_optional_object(
    value: Option<&JsonObject>,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| {
        validate_bounded_json_object(value, limits, depth)
    })
}

fn validate_optional_json(
    value: Option<&Value>,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| validate_bounded_json(value, limits, depth))
}

fn validate_metadata(
    annotations: Option<&JsonObject>,
    provider_metadata: Option<&JsonObject>,
    limits: &ContentLimits,
    depth: usize,
) -> Result<(), ContractError> {
    let child_depth = next_depth(depth)?;
    validate_optional_object(annotations, limits, child_depth)?;
    validate_optional_object(provider_metadata, limits, child_depth)
}

fn validate_sha256(value: Option<&str>, limits: &ContentLimits) -> Result<(), ContractError> {
    if let Some(value) = value {
        validate_bounded_string(value, limits)?;
        if value.len() != 64
            || !value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(ContractError::InvalidContent);
        }
    }
    Ok(())
}

macro_rules! metadata_methods {
    () => {
        /// Adds deterministic annotations and provider provenance metadata.
        ///
        /// # Errors
        ///
        /// Returns [`ContractError::InvalidContent`] when metadata exceeds default bounds.
        pub fn with_metadata(
            mut self,
            annotations: Option<JsonObject>,
            provider_metadata: Option<JsonObject>,
        ) -> Result<Self, ContractError> {
            self.annotations = annotations;
            self.provider_metadata = provider_metadata;
            self.validate(&ContentLimits::default())?;
            Ok(self)
        }

        /// Borrows optional deterministic annotations.
        #[must_use]
        pub const fn annotations(&self) -> Option<&JsonObject> {
            self.annotations.as_ref()
        }

        /// Borrows optional deterministic provider metadata.
        #[must_use]
        pub const fn provider_metadata(&self) -> Option<&JsonObject> {
            self.provider_metadata.as_ref()
        }
    };
}

macro_rules! redacted_debug {
    ($type:ty, $label:literal) => {
        impl fmt::Debug for $type {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([REDACTED])"))
            }
        }
    };
}

/// The semantic category of a canonical annotation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnnotationType {
    /// A citation annotation.
    Citation,
    /// A grounding annotation.
    Grounding,
    /// A URL annotation.
    Url,
    /// A file-path annotation.
    FilePath,
    /// A token-score annotation.
    TokenScore,
    /// A log-probability annotation.
    LogProbability,
    /// A safety annotation.
    Safety,
    /// A moderation annotation.
    Moderation,
    /// A provider-specific typed annotation.
    Provider,
}

/// A provider-executed operation category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionOperation {
    /// Provider web search.
    WebSearch,
    /// Provider file search.
    FileSearch,
    /// Provider code execution.
    CodeExecution,
    /// Provider shell execution.
    Shell,
    /// Provider computer use.
    ComputerUse,
    /// Provider image generation.
    ImageGeneration,
    /// Provider audio generation.
    AudioGeneration,
    /// Provider video generation.
    VideoGeneration,
    /// Provider MCP execution.
    Mcp,
    /// Another provider-native tool.
    ProviderTool,
    /// A future or uncategorized operation.
    Other,
}

/// Lifecycle state of a provider-executed operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    /// Waiting to begin.
    Queued,
    /// Currently executing.
    Running,
    /// Completed successfully.
    Completed,
    /// Failed.
    Failed,
    /// Cancelled.
    Cancelled,
}

/// Safety disposition assigned to output content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafetyDisposition {
    /// Content is allowed.
    Allowed,
    /// Unsafe material was filtered.
    Filtered,
    /// Output was blocked.
    Blocked,
    /// The request was refused.
    Refused,
    /// Human or policy review is required.
    ReviewRequired,
}

/// Provider-sanctioned reasoning representation retained by the canonical boundary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasoningRepresentation {
    /// A provider-returned safe reasoning summary.
    Summary,
    /// A provider-returned continuation signature.
    Signature,
    /// Provider-encrypted opaque continuation state.
    OpaqueEncrypted,
}

/// A typed citation associated with canonical output.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CitationOutputPart {
    id: String,
    source: JsonObject,
    part_id: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl CitationOutputPart {
    /// Creates a citation with a deterministic arbitrary source object.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, source: JsonObject) -> Result<Self, ContractError> {
        let part = Self {
            id,
            source,
            part_id: None,
            start: None,
            end: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Associates the citation with a part and optional half-open offsets.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when `end` precedes `start` or an identifier
    /// exceeds default bounds.
    pub fn with_location(
        mut self,
        part_id: Option<String>,
        start: Option<u64>,
        end: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.part_id = part_id;
        self.start = start;
        self.end = end;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the deterministic citation source object.
    #[must_use]
    pub const fn source(&self) -> &JsonObject {
        &self.source
    }

    /// Borrows the associated output-part identifier.
    #[must_use]
    pub fn part_id(&self) -> Option<&str> {
        self.part_id.as_deref()
    }

    /// Returns the optional inclusive start offset.
    #[must_use]
    pub const fn start(&self) -> Option<u64> {
        self.start
    }

    /// Returns the optional exclusive end offset.
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        self.end
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_optional_identifier(self.part_id.as_deref(), limits)?;
        validate_offsets(self.start, self.end)?;
        validate_bounded_json_object(&self.source, limits, next_depth(depth)?)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(CitationOutputPart, "CitationOutputPart");

/// A typed provider or policy refusal.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalOutputPart {
    id: String,
    category: String,
    message: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "bool")]
    retryable: Option<bool>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl RefusalOutputPart {
    /// Creates a typed refusal.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, category: String, message: String) -> Result<Self, ContractError> {
        let part = Self {
            id,
            category,
            message,
            retryable: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Records whether the refusal may be retried.
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = Some(retryable);
        self
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the safe refusal category.
    #[must_use]
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Borrows the safe refusal message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns whether retrying may be appropriate.
    #[must_use]
    pub const fn retryable(&self) -> Option<bool> {
        self.retryable
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_bounded_string(&self.category, limits)?;
        validate_bounded_string(&self.message, limits)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(RefusalOutputPart, "RefusalOutputPart");

/// An image output with a bounded inline, URL, or object source.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageOutputPart {
    id: String,
    mime_type: String,
    source: BinarySource,
    #[schemars(range(min = 1))]
    width: Option<u32>,
    #[schemars(range(min = 1))]
    height: Option<u32>,
    generation_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl ImageOutputPart {
    /// Creates an image output.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
        let part = Self {
            id,
            mime_type,
            source,
            width: None,
            height: None,
            generation_id: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds known positive pixel dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for a zero dimension.
    pub fn with_dimensions(
        mut self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> Result<Self, ContractError> {
        self.width = width;
        self.height = height;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Adds a provider generation identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when the identifier exceeds default bounds.
    pub fn with_generation_id(
        mut self,
        generation_id: Option<String>,
    ) -> Result<Self, ContractError> {
        self.generation_id = generation_id;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the image MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Returns the optional width in pixels.
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        self.width
    }

    /// Returns the optional height in pixels.
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        self.height
    }

    /// Borrows the optional provider generation identifier.
    #[must_use]
    pub fn generation_id(&self) -> Option<&str> {
        self.generation_id.as_deref()
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_mime_type(&self.mime_type)?;
        validate_bounded_string(&self.mime_type, limits)?;
        validate_binary_source(&self.source, limits)?;
        validate_positive(self.width)?;
        validate_positive(self.height)?;
        validate_optional_string(self.generation_id.as_deref(), limits)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(ImageOutputPart, "ImageOutputPart");

/// An audio output with a bounded inline, URL, or object source.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudioOutputPart {
    id: String,
    mime_type: String,
    source: BinarySource,
    duration_ms: Option<u64>,
    #[schemars(range(min = 1))]
    sample_rate_hz: Option<u32>,
    transcript: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl AudioOutputPart {
    /// Creates an audio output.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
        let part = Self {
            id,
            mime_type,
            source,
            duration_ms: None,
            sample_rate_hz: None,
            transcript: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds known duration, sample rate, and transcript information.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for a zero sample rate or oversized transcript.
    pub fn with_media_details(
        mut self,
        duration_ms: Option<u64>,
        sample_rate_hz: Option<u32>,
        transcript: Option<String>,
    ) -> Result<Self, ContractError> {
        self.duration_ms = duration_ms;
        self.sample_rate_hz = sample_rate_hz;
        self.transcript = transcript;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the audio MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Returns the optional duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        self.duration_ms
    }

    /// Returns the optional sample rate in hertz.
    #[must_use]
    pub const fn sample_rate_hz(&self) -> Option<u32> {
        self.sample_rate_hz
    }

    /// Borrows the optional transcript.
    #[must_use]
    pub fn transcript(&self) -> Option<&str> {
        self.transcript.as_deref()
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_mime_type(&self.mime_type)?;
        validate_bounded_string(&self.mime_type, limits)?;
        validate_binary_source(&self.source, limits)?;
        validate_positive(self.sample_rate_hz)?;
        validate_optional_string(self.transcript.as_deref(), limits)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(AudioOutputPart, "AudioOutputPart");

/// A video output with a bounded inline, URL, or object source.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoOutputPart {
    id: String,
    mime_type: String,
    source: BinarySource,
    duration_ms: Option<u64>,
    #[schemars(range(min = 1))]
    width: Option<u32>,
    #[schemars(range(min = 1))]
    height: Option<u32>,
    #[schemars(schema_with = "nullable_positive_rate_schema")]
    frame_rate: Option<f64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl VideoOutputPart {
    /// Creates a video output.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
        let part = Self {
            id,
            mime_type,
            source,
            duration_ms: None,
            width: None,
            height: None,
            frame_rate: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds known duration, dimensions, and frame rate.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for zero dimensions or a non-positive,
    /// non-finite frame rate.
    pub fn with_media_details(
        mut self,
        duration_ms: Option<u64>,
        width: Option<u32>,
        height: Option<u32>,
        frame_rate: Option<f64>,
    ) -> Result<Self, ContractError> {
        self.duration_ms = duration_ms;
        self.width = width;
        self.height = height;
        self.frame_rate = frame_rate;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the video MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Returns the optional duration in milliseconds.
    #[must_use]
    pub const fn duration_ms(&self) -> Option<u64> {
        self.duration_ms
    }

    /// Returns the optional width in pixels.
    #[must_use]
    pub const fn width(&self) -> Option<u32> {
        self.width
    }

    /// Returns the optional height in pixels.
    #[must_use]
    pub const fn height(&self) -> Option<u32> {
        self.height
    }

    /// Returns the optional frame rate.
    #[must_use]
    pub const fn frame_rate(&self) -> Option<f64> {
        self.frame_rate
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_mime_type(&self.mime_type)?;
        validate_bounded_string(&self.mime_type, limits)?;
        validate_binary_source(&self.source, limits)?;
        validate_positive(self.width)?;
        validate_positive(self.height)?;
        if self
            .frame_rate
            .is_some_and(|rate| !rate.is_finite() || rate <= 0.0)
        {
            return Err(ContractError::InvalidContent);
        }
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(VideoOutputPart, "VideoOutputPart");

/// A file output with integrity and size metadata.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileOutputPart {
    id: String,
    filename: Option<String>,
    mime_type: String,
    source: BinarySource,
    #[schemars(schema_with = "nullable_sha256_schema")]
    sha256: Option<String>,
    size_bytes: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl FileOutputPart {
    /// Creates a file output.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
        let part = Self {
            id,
            filename: None,
            mime_type,
            source,
            sha256: None,
            size_bytes: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds filename, lowercase SHA-256 digest, and size metadata.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] for an invalid digest or oversized string.
    pub fn with_file_details(
        mut self,
        filename: Option<String>,
        sha256: Option<String>,
        size_bytes: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.filename = filename;
        self.sha256 = sha256;
        self.size_bytes = size_bytes;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the optional filename.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }

    /// Borrows the file MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Borrows the optional lowercase SHA-256 digest.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        self.sha256.as_deref()
    }

    /// Returns the optional file size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u64> {
        self.size_bytes
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_mime_type(&self.mime_type)?;
        validate_bounded_string(&self.mime_type, limits)?;
        validate_binary_source(&self.source, limits)?;
        validate_optional_string(self.filename.as_deref(), limits)?;
        validate_sha256(self.sha256.as_deref(), limits)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(FileOutputPart, "FileOutputPart");

/// A provider- or application-hosted resource output.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceOutputPart {
    id: String,
    uri: String,
    name: Option<String>,
    mime_type: Option<String>,
    source: Option<BinarySource>,
    expires_at: Option<UtcTimestamp>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    resource_metadata: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl ResourceOutputPart {
    /// Creates a resource with an absolute URI.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] for a malformed or relative URI.
    pub fn new(id: String, uri: String) -> Result<Self, ContractError> {
        let part = Self {
            id,
            uri,
            name: None,
            mime_type: None,
            source: None,
            expires_at: None,
            resource_metadata: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds lifecycle, binary, and deterministic resource metadata.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn with_resource_details(
        mut self,
        name: Option<String>,
        mime_type: Option<String>,
        source: Option<BinarySource>,
        expires_at: Option<UtcTimestamp>,
        resource_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.name = name;
        self.mime_type = mime_type;
        self.source = source;
        self.expires_at = expires_at;
        self.resource_metadata = resource_metadata;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the absolute resource URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Borrows the optional resource name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Borrows the optional MIME type.
    #[must_use]
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }

    /// Borrows the optional binary source.
    #[must_use]
    pub const fn source(&self) -> Option<&BinarySource> {
        self.source.as_ref()
    }

    /// Returns the optional expiry timestamp.
    #[must_use]
    pub const fn expires_at(&self) -> Option<UtcTimestamp> {
        self.expires_at
    }

    /// Borrows optional deterministic resource metadata.
    #[must_use]
    pub const fn resource_metadata(&self) -> Option<&JsonObject> {
        self.resource_metadata.as_ref()
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_bounded_string(&self.uri, limits)?;
        validate_absolute_uri(&self.uri)?;
        validate_optional_string(self.name.as_deref(), limits)?;
        if let Some(mime_type) = self.mime_type.as_deref() {
            validate_mime_type(mime_type)?;
            validate_bounded_string(mime_type, limits)?;
        }
        if let Some(source) = self.source.as_ref() {
            validate_binary_source(source, limits)?;
        }
        validate_optional_timestamp(self.expires_at, limits)?;
        let child_depth = next_depth(depth)?;
        validate_optional_object(self.resource_metadata.as_ref(), limits, child_depth)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(ResourceOutputPart, "ResourceOutputPart");

/// A typed annotation associated with canonical output.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnotationOutputPart {
    id: String,
    annotation_type: AnnotationType,
    data: Value,
    part_id: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl AnnotationOutputPart {
    /// Creates a typed annotation with arbitrary JSON data.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(
        id: String,
        annotation_type: AnnotationType,
        data: Value,
    ) -> Result<Self, ContractError> {
        let part = Self {
            id,
            annotation_type,
            data,
            part_id: None,
            start: None,
            end: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Associates the annotation with a part and optional half-open offsets.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when `end` precedes `start` or an identifier
    /// exceeds default bounds.
    pub fn with_location(
        mut self,
        part_id: Option<String>,
        start: Option<u64>,
        end: Option<u64>,
    ) -> Result<Self, ContractError> {
        self.part_id = part_id;
        self.start = start;
        self.end = end;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the typed annotation category.
    #[must_use]
    pub const fn annotation_type(&self) -> AnnotationType {
        self.annotation_type
    }

    /// Borrows the arbitrary annotation data.
    #[must_use]
    pub const fn data(&self) -> &Value {
        &self.data
    }

    /// Borrows the associated output-part identifier.
    #[must_use]
    pub fn part_id(&self) -> Option<&str> {
        self.part_id.as_deref()
    }

    /// Returns the optional inclusive start offset.
    #[must_use]
    pub const fn start(&self) -> Option<u64> {
        self.start
    }

    /// Returns the optional exclusive end offset.
    #[must_use]
    pub const fn end(&self) -> Option<u64> {
        self.end
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_optional_identifier(self.part_id.as_deref(), limits)?;
        validate_offsets(self.start, self.end)?;
        validate_bounded_json(&self.data, limits, next_depth(depth)?)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(AnnotationOutputPart, "AnnotationOutputPart");

/// One provider-executed operation retained with its inputs, outputs, and lifecycle.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStepOutputPart {
    id: String,
    step_id: String,
    operation: ExecutionOperation,
    status: ExecutionStatus,
    input: Option<Value>,
    output: Option<Value>,
    error: Option<JsonObject>,
    started_at: Option<UtcTimestamp>,
    completed_at: Option<UtcTimestamp>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl ExecutionStepOutputPart {
    /// Creates a typed provider-executed operation.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when identifiers violate default bounds.
    pub fn new(
        id: String,
        step_id: String,
        operation: ExecutionOperation,
        status: ExecutionStatus,
    ) -> Result<Self, ContractError> {
        let part = Self {
            id,
            step_id,
            operation,
            status,
            input: None,
            output: None,
            error: None,
            started_at: None,
            completed_at: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds arbitrary operation input, output, and structured error values.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when a JSON value exceeds default bounds.
    pub fn with_values(
        mut self,
        input: Option<Value>,
        output: Option<Value>,
        error: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        self.input = input;
        self.output = output;
        self.error = error;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Adds optional normalized timestamps.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidContent`] when completion precedes start.
    pub fn with_timestamps(
        mut self,
        started_at: Option<UtcTimestamp>,
        completed_at: Option<UtcTimestamp>,
    ) -> Result<Self, ContractError> {
        self.started_at = started_at;
        self.completed_at = completed_at;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the provider step identifier.
    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the typed operation category.
    #[must_use]
    pub const fn operation(&self) -> ExecutionOperation {
        self.operation
    }

    /// Returns the execution status.
    #[must_use]
    pub const fn status(&self) -> ExecutionStatus {
        self.status
    }

    /// Borrows arbitrary operation input.
    #[must_use]
    pub const fn input(&self) -> Option<&Value> {
        self.input.as_ref()
    }

    /// Borrows arbitrary operation output.
    #[must_use]
    pub const fn output(&self) -> Option<&Value> {
        self.output.as_ref()
    }

    /// Borrows the optional structured error.
    #[must_use]
    pub const fn error(&self) -> Option<&JsonObject> {
        self.error.as_ref()
    }

    /// Returns the optional start timestamp.
    #[must_use]
    pub const fn started_at(&self) -> Option<UtcTimestamp> {
        self.started_at
    }

    /// Returns the optional completion timestamp.
    #[must_use]
    pub const fn completed_at(&self) -> Option<UtcTimestamp> {
        self.completed_at
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_part_id(&self.step_id, limits)?;
        if matches!(
            (self.started_at, self.completed_at),
            (Some(started_at), Some(completed_at)) if completed_at < started_at
        ) {
            return Err(ContractError::InvalidContent);
        }
        validate_optional_timestamp(self.started_at, limits)?;
        validate_optional_timestamp(self.completed_at, limits)?;
        let child_depth = next_depth(depth)?;
        validate_optional_json(self.input.as_ref(), limits, child_depth)?;
        validate_optional_json(self.output.as_ref(), limits, child_depth)?;
        validate_optional_object(self.error.as_ref(), limits, child_depth)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(ExecutionStepOutputPart, "ExecutionStepOutputPart");

/// A typed safety or guardrail outcome.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafetyOutputPart {
    id: String,
    disposition: SafetyDisposition,
    category: Option<String>,
    message: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    scores: Option<JsonObject>,
    policy_id: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl SafetyOutputPart {
    /// Creates a typed safety outcome.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the identifier violates default bounds.
    pub fn new(id: String, disposition: SafetyDisposition) -> Result<Self, ContractError> {
        let part = Self {
            id,
            disposition,
            category: None,
            message: None,
            scores: None,
            policy_id: None,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Adds safety category, message, scores, and policy identity.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn with_safety_details(
        mut self,
        category: Option<String>,
        message: Option<String>,
        scores: Option<JsonObject>,
        policy_id: Option<String>,
    ) -> Result<Self, ContractError> {
        self.category = category;
        self.message = message;
        self.scores = scores;
        self.policy_id = policy_id;
        self.validate(&ContentLimits::default())?;
        Ok(self)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the typed disposition.
    #[must_use]
    pub const fn disposition(&self) -> SafetyDisposition {
        self.disposition
    }

    /// Borrows the optional safety category.
    #[must_use]
    pub fn category(&self) -> Option<&str> {
        self.category.as_deref()
    }

    /// Borrows the optional safe message.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Borrows optional deterministic scores.
    #[must_use]
    pub const fn scores(&self) -> Option<&JsonObject> {
        self.scores.as_ref()
    }

    /// Borrows the optional policy identifier.
    #[must_use]
    pub fn policy_id(&self) -> Option<&str> {
        self.policy_id.as_deref()
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_optional_string(self.category.as_deref(), limits)?;
        validate_optional_string(self.message.as_deref(), limits)?;
        validate_optional_string(self.policy_id.as_deref(), limits)?;
        validate_optional_object(self.scores.as_ref(), limits, next_depth(depth)?)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(SafetyOutputPart, "SafetyOutputPart");

/// Provider-sanctioned reasoning summary, signature, or opaque encrypted state.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningOutputPart {
    id: String,
    representation: ReasoningRepresentation,
    data: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl ReasoningOutputPart {
    /// Creates one of the only provider-sanctioned reasoning representations.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(
        id: String,
        representation: ReasoningRepresentation,
        data: String,
    ) -> Result<Self, ContractError> {
        let part = Self {
            id,
            representation,
            data,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the sanctioned representation category.
    #[must_use]
    pub const fn representation(&self) -> ReasoningRepresentation {
        self.representation
    }

    /// Borrows the provider-returned sanctioned data.
    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_bounded_string(&self.data, limits)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(ReasoningOutputPart, "ReasoningOutputPart");

/// A losslessly retained policy-approved future provider output item.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownOutputPart {
    id: String,
    provider_kind: String,
    payload: Value,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    annotations: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl UnknownOutputPart {
    /// Creates a losslessly retained future provider output item.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when content violates default bounds.
    pub fn new(id: String, provider_kind: String, payload: Value) -> Result<Self, ContractError> {
        let part = Self {
            id,
            provider_kind,
            payload,
            annotations: None,
            provider_metadata: None,
        };
        part.validate(&ContentLimits::default())?;
        Ok(part)
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the namespaced provider kind.
    #[must_use]
    pub fn provider_kind(&self) -> &str {
        &self.provider_kind
    }

    /// Borrows the losslessly retained arbitrary payload.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    metadata_methods!();

    /// Validates the part against explicit bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any invariant or bound is violated.
    pub fn validate(&self, limits: &ContentLimits) -> Result<(), ContractError> {
        self.validate_with_limits(limits, 0)
    }

    pub(crate) fn validate_with_limits(
        &self,
        limits: &ContentLimits,
        depth: usize,
    ) -> Result<(), ContractError> {
        validate_content_depth(depth, limits)?;
        validate_part_id(&self.id, limits)?;
        validate_identifier(&self.provider_kind)?;
        validate_bounded_string(&self.provider_kind, limits)?;
        validate_bounded_json(&self.payload, limits, next_depth(depth)?)?;
        validate_metadata(
            self.annotations.as_ref(),
            self.provider_metadata.as_ref(),
            limits,
            depth,
        )
    }
}

redacted_debug!(UnknownOutputPart, "UnknownOutputPart");
