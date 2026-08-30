use std::{collections::BTreeSet, fmt};

use serde::{Serialize, Serializer, ser::SerializeStruct};
use serde_json::Value;
use thiserror::Error;

use crate::JsonSchemaDocument;

/// Maximum ordered content blocks in one tool representation.
pub const MAX_CONTENT_BLOCKS: usize = 64;
/// Maximum UTF-8 bytes in one text content block.
pub const MAX_TEXT_CONTENT_BYTES: usize = 1_048_576;
/// Maximum decoded bytes in one image, audio, or embedded binary block.
pub const MAX_BINARY_CONTENT_BYTES: usize = 8_388_608;
/// Maximum UTF-8 bytes in an embedded resource URI.
pub const MAX_RESOURCE_URI_BYTES: usize = 2_048;
/// Maximum UTF-8 bytes in a media type.
pub const MAX_MEDIA_TYPE_BYTES: usize = 255;
/// Maximum input requests in one input-required result.
pub const MAX_INPUT_REQUESTS: usize = 16;
/// Maximum UTF-8 bytes in one input request identifier.
pub const MAX_INPUT_REQUEST_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in one input request prompt.
pub const MAX_INPUT_PROMPT_BYTES: usize = 4_096;
/// Maximum UTF-8 bytes in opaque request state.
pub const MAX_REQUEST_STATE_BYTES: usize = 8_192;

/// A bounded content or input-required construction failure.
///
/// Rejected content is deliberately absent from every variant and rendering.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResultBuildError {
    /// A required collection or string was empty.
    #[error("tool result value must not be empty")]
    Empty,
    /// A collection exceeded its fixed item bound.
    #[error("tool result collection exceeds its fixed item bound")]
    TooMany,
    /// A string or binary value exceeded its fixed byte bound.
    #[error("tool result value exceeds its fixed byte bound")]
    TooLong,
    /// A public value did not satisfy its fixed grammar.
    #[error("tool result value has an invalid format")]
    InvalidFormat,
    /// Input request identifiers were not unique.
    #[error("input request identifiers must be unique")]
    DuplicateRequestId,
}

/// Bounded UTF-8 tool content.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TextContent(String);

impl TextContent {
    /// Creates nonempty bounded text content.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering rejected text.
    pub fn new(text: impl Into<String>) -> Result<Self, ResultBuildError> {
        let text = text.into();
        validate_nonempty_length(&text, MAX_TEXT_CONTENT_BYTES)?;
        Ok(Self(text))
    }

    /// Borrows the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TextContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TextContent([redacted])")
    }
}

/// A bounded validated media type.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MediaType(String);

impl MediaType {
    /// Creates a bounded media type with a syntactically valid type and subtype.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering the rejected value.
    pub fn new(value: impl Into<String>) -> Result<Self, ResultBuildError> {
        let value = value.into();
        validate_nonempty_length(&value, MAX_MEDIA_TYPE_BYTES)?;
        if !valid_media_type(&value) {
            return Err(ResultBuildError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrows the validated media type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MediaType([redacted])")
    }
}

/// A bounded validated embedded-resource URI.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EmbeddedResourceUri(String);

impl EmbeddedResourceUri {
    /// Creates a bounded absolute resource URI.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering the rejected URI.
    pub fn new(value: impl Into<String>) -> Result<Self, ResultBuildError> {
        let value = value.into();
        validate_nonempty_length(&value, MAX_RESOURCE_URI_BYTES)?;
        if !valid_resource_uri(&value) {
            return Err(ResultBuildError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrows the validated URI.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EmbeddedResourceUri {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmbeddedResourceUri([redacted])")
    }
}

/// Decoded bounded binary content with its authoritative media type.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct BinaryContent {
    #[serde(rename = "mediaType")]
    media_type: MediaType,
    data: Vec<u8>,
}

impl BinaryContent {
    /// Creates bounded binary content.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError::TooLong`] when decoded bytes exceed the fixed limit.
    pub fn new(media_type: MediaType, data: Vec<u8>) -> Result<Self, ResultBuildError> {
        if data.len() > MAX_BINARY_CONTENT_BYTES {
            return Err(ResultBuildError::TooLong);
        }
        Ok(Self { media_type, data })
    }

    /// Returns the authoritative media type.
    #[must_use]
    pub const fn media_type(&self) -> &MediaType {
        &self.media_type
    }

    /// Borrows decoded bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl fmt::Debug for BinaryContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BinaryContent([redacted])")
    }
}

/// Bounded decoded bytes for an embedded resource.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EmbeddedBinaryContent(Vec<u8>);

impl EmbeddedBinaryContent {
    /// Creates bounded decoded embedded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError::TooLong`] when decoded bytes exceed the fixed limit.
    pub fn new(data: Vec<u8>) -> Result<Self, ResultBuildError> {
        if data.len() > MAX_BINARY_CONTENT_BYTES {
            return Err(ResultBuildError::TooLong);
        }
        Ok(Self(data))
    }

    /// Borrows decoded bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for EmbeddedBinaryContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmbeddedBinaryContent([redacted])")
    }
}

/// Text or decoded binary contents of an embedded resource.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub enum EmbeddedResourceContents {
    /// UTF-8 embedded resource text.
    Text {
        /// Validated embedded text.
        text: TextContent,
    },
    /// Decoded embedded resource bytes.
    Binary {
        /// Validated decoded embedded bytes.
        data: EmbeddedBinaryContent,
    },
}

impl EmbeddedResourceContents {
    /// Creates bounded embedded binary contents.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError::TooLong`] when decoded bytes exceed the fixed limit.
    pub fn binary(data: Vec<u8>) -> Result<Self, ResultBuildError> {
        Ok(Self::Binary {
            data: EmbeddedBinaryContent::new(data)?,
        })
    }

    /// Creates embedded text contents from an already validated text value.
    #[must_use]
    pub fn text(text: TextContent) -> Self {
        Self::Text { text }
    }
}

impl fmt::Debug for EmbeddedResourceContents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmbeddedResourceContents([redacted])")
    }
}

/// Bounded embedded resource content carried by a tool result.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct EmbeddedResource {
    uri: EmbeddedResourceUri,
    #[serde(rename = "mediaType", skip_serializing_if = "Option::is_none")]
    media_type: Option<MediaType>,
    contents: EmbeddedResourceContents,
}

impl EmbeddedResource {
    /// Creates an embedded resource block.
    #[must_use]
    pub fn new(
        uri: EmbeddedResourceUri,
        media_type: Option<MediaType>,
        contents: EmbeddedResourceContents,
    ) -> Self {
        Self {
            uri,
            media_type,
            contents,
        }
    }

    /// Returns the resource URI.
    #[must_use]
    pub const fn uri(&self) -> &EmbeddedResourceUri {
        &self.uri
    }

    /// Returns the optional authoritative media type.
    #[must_use]
    pub const fn media_type(&self) -> Option<&MediaType> {
        self.media_type.as_ref()
    }

    /// Returns the embedded contents.
    #[must_use]
    pub const fn contents(&self) -> &EmbeddedResourceContents {
        &self.contents
    }
}

impl fmt::Debug for EmbeddedResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EmbeddedResource([redacted])")
    }
}

/// One ordered, bounded canonical content block.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// UTF-8 text.
    Text {
        /// Validated text.
        text: TextContent,
    },
    /// Decoded image bytes and media type.
    Image {
        /// Validated image content.
        image: BinaryContent,
    },
    /// Decoded audio bytes and media type.
    Audio {
        /// Validated audio content.
        audio: BinaryContent,
    },
    /// An embedded resource.
    EmbeddedResource {
        /// Validated embedded resource.
        resource: EmbeddedResource,
    },
}

impl fmt::Debug for ContentBlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentBlock([redacted])")
    }
}

/// Nonempty bounded ordered content blocks.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct BoundedContent(Vec<ContentBlock>);

impl BoundedContent {
    /// Creates nonempty bounded ordered content.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] for an empty or excessive content list.
    pub fn new(content: Vec<ContentBlock>) -> Result<Self, ResultBuildError> {
        validate_content_list(&content)?;
        Ok(Self(content))
    }

    /// Returns ordered content blocks.
    #[must_use]
    pub fn blocks(&self) -> &[ContentBlock] {
        &self.0
    }
}

impl fmt::Debug for BoundedContent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BoundedContent([redacted])")
    }
}

/// The single unambiguous representation of a successful complete result.
#[derive(Clone, PartialEq, Serialize)]
#[serde(tag = "representation", rename_all = "snake_case")]
pub enum ToolRepresentation {
    /// Ordered content with no independently duplicated structured value.
    ContentOnly {
        /// Authoritative ordered content.
        content: BoundedContent,
    },
    /// An arbitrary JSON value with no independently duplicated content.
    StructuredOnly {
        /// Authoritative arbitrary structured value.
        structured: Value,
    },
    /// An authoritative arbitrary JSON value plus explicitly supplementary ordered content.
    AuthoritativeStructured {
        /// Authoritative arbitrary structured value.
        structured: Value,
        /// Ordered content that is explicitly supplementary to `structured`.
        #[serde(rename = "supplementaryContent")]
        supplementary_content: BoundedContent,
    },
}

impl ToolRepresentation {
    /// Creates a nonempty bounded content-only representation.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] for an empty or excessive content list.
    pub fn content_only(content: Vec<ContentBlock>) -> Result<Self, ResultBuildError> {
        Ok(Self::ContentOnly {
            content: BoundedContent::new(content)?,
        })
    }

    /// Creates an arbitrary structured-only representation.
    #[must_use]
    pub fn structured_only(structured: Value) -> Self {
        Self::StructuredOnly { structured }
    }

    /// Creates an authoritative structured value with nonempty explicitly supplementary content.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] for an empty or excessive supplementary content list.
    pub fn authoritative_structured(
        structured: Value,
        supplementary_content: Vec<ContentBlock>,
    ) -> Result<Self, ResultBuildError> {
        Ok(Self::AuthoritativeStructured {
            structured,
            supplementary_content: BoundedContent::new(supplementary_content)?,
        })
    }
}

impl fmt::Debug for ToolRepresentation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolRepresentation([redacted])")
    }
}

/// Fixed tool-level failure categories safe for public results.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailureCode {
    /// Registry policy or routed execution was rejected without revealing why.
    Rejected,
    /// Registry policy evidence was invalid or incomplete.
    InvalidRequest,
    /// Execution could not complete within current availability bounds.
    Unavailable,
    /// Execution or validated output adaptation failed.
    Internal,
}

/// A fixed value-free tool-level error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ToolFailure {
    code: ToolFailureCode,
}

impl ToolFailure {
    /// Creates a fixed public tool-level failure.
    #[must_use]
    pub const fn new(code: ToolFailureCode) -> Self {
        Self { code }
    }

    /// Returns the fixed failure category.
    #[must_use]
    pub const fn code(self) -> ToolFailureCode {
        self.code
    }

    /// Returns the fixed caller-safe message for this category.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self.code {
            ToolFailureCode::Rejected => "tool request was rejected",
            ToolFailureCode::InvalidRequest => "tool request is invalid",
            ToolFailureCode::Unavailable => "tool is unavailable",
            ToolFailureCode::Internal => "tool execution failed",
        }
    }
}

impl fmt::Debug for ToolFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolFailure([redacted])")
    }
}

impl Serialize for ToolFailure {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ToolFailure", 2)?;
        state.serialize_field("code", &self.code)?;
        state.serialize_field("message", self.message())?;
        state.end()
    }
}

/// Success or tool-level error for a complete result.
#[derive(Clone, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ToolOutcome {
    /// Successful execution in exactly one declared representation.
    Success {
        /// The single declared success representation.
        representation: ToolRepresentation,
    },
    /// A fixed caller-safe tool-level failure.
    Error {
        /// The fixed redacted error.
        error: ToolFailure,
    },
}

impl fmt::Debug for ToolOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolOutcome([redacted])")
    }
}

/// A completed canonical tool result.
#[derive(Clone, PartialEq)]
pub struct CompleteToolResult {
    outcome: ToolOutcome,
}

impl CompleteToolResult {
    /// Creates a successful complete result.
    #[must_use]
    pub fn success(representation: ToolRepresentation) -> Self {
        Self {
            outcome: ToolOutcome::Success { representation },
        }
    }

    /// Creates a complete tool-level error.
    #[must_use]
    pub const fn error(error: ToolFailure) -> Self {
        Self {
            outcome: ToolOutcome::Error { error },
        }
    }

    /// Returns the complete outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ToolOutcome {
        &self.outcome
    }
}

impl fmt::Debug for CompleteToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CompleteToolResult([redacted])")
    }
}

/// A bounded request identifier for one additional input.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct InputRequestId(String);

impl InputRequestId {
    /// Creates a bounded printable request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering the rejected identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, ResultBuildError> {
        let value = value.into();
        validate_nonempty_length(&value, MAX_INPUT_REQUEST_ID_BYTES)?;
        if !value.is_ascii() || !value.bytes().all(|byte| matches!(byte, b'!'..=b'~')) {
            return Err(ResultBuildError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrows the request identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InputRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputRequestId([redacted])")
    }
}

/// A bounded prompt explaining one additional input request.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct InputPrompt(String);

impl InputPrompt {
    /// Creates a bounded input prompt.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering the rejected prompt.
    pub fn new(value: impl Into<String>) -> Result<Self, ResultBuildError> {
        let value = value.into();
        validate_nonempty_length(&value, MAX_INPUT_PROMPT_BYTES)?;
        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        {
            return Err(ResultBuildError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrows the input prompt.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InputPrompt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputPrompt([redacted])")
    }
}

/// Bounded opaque state binding an input-required round trip.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RequestState(String);

impl RequestState {
    /// Creates bounded printable opaque request state.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] without retaining or rendering rejected state.
    pub fn new(value: impl Into<String>) -> Result<Self, ResultBuildError> {
        let value = value.into();
        validate_nonempty_length(&value, MAX_REQUEST_STATE_BYTES)?;
        if !value.is_ascii() || !value.bytes().all(|byte| matches!(byte, b'!'..=b'~')) {
            return Err(ResultBuildError::InvalidFormat);
        }
        Ok(Self(value))
    }

    /// Borrows the opaque request state.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestState([redacted])")
    }
}

/// One bounded additional-input request with an arbitrary local-only schema.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct InputRequest {
    id: InputRequestId,
    prompt: InputPrompt,
    schema: JsonSchemaDocument,
}

impl InputRequest {
    /// Creates one additional-input request.
    #[must_use]
    pub fn new(id: InputRequestId, prompt: InputPrompt, schema: JsonSchemaDocument) -> Self {
        Self { id, prompt, schema }
    }

    /// Returns the stable request identifier.
    #[must_use]
    pub const fn id(&self) -> &InputRequestId {
        &self.id
    }

    /// Returns the caller-facing prompt.
    #[must_use]
    pub const fn prompt(&self) -> &InputPrompt {
        &self.prompt
    }

    /// Returns the compiled response schema.
    #[must_use]
    pub const fn schema(&self) -> &JsonSchemaDocument {
        &self.schema
    }
}

impl fmt::Debug for InputRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputRequest([redacted])")
    }
}

/// A bounded canonical result requesting additional caller input.
#[derive(Clone, Eq, PartialEq)]
pub struct InputRequiredToolResult {
    requests: Vec<InputRequest>,
    request_state: RequestState,
}

impl InputRequiredToolResult {
    /// Creates a nonempty, duplicate-free bounded input-required result.
    ///
    /// # Errors
    ///
    /// Returns [`ResultBuildError`] for empty, excessive, or duplicate requests.
    pub fn new(
        requests: Vec<InputRequest>,
        request_state: RequestState,
    ) -> Result<Self, ResultBuildError> {
        if requests.is_empty() {
            return Err(ResultBuildError::Empty);
        }
        if requests.len() > MAX_INPUT_REQUESTS {
            return Err(ResultBuildError::TooMany);
        }
        let unique = requests
            .iter()
            .map(InputRequest::id)
            .collect::<BTreeSet<_>>();
        if unique.len() != requests.len() {
            return Err(ResultBuildError::DuplicateRequestId);
        }
        Ok(Self {
            requests,
            request_state,
        })
    }

    /// Returns ordered additional-input requests.
    #[must_use]
    pub fn requests(&self) -> &[InputRequest] {
        &self.requests
    }

    /// Returns opaque round-trip request state.
    #[must_use]
    pub const fn request_state(&self) -> &RequestState {
        &self.request_state
    }
}

impl fmt::Debug for InputRequiredToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InputRequiredToolResult([redacted])")
    }
}

/// Canonical RMCP-independent complete-or-input-required tool result algebra.
#[derive(Clone, PartialEq)]
pub enum CanonicalToolResult {
    /// Execution completed with success or a tool-level error.
    Complete(CompleteToolResult),
    /// Execution paused for bounded additional caller input.
    InputRequired(InputRequiredToolResult),
}

impl CanonicalToolResult {
    /// Creates a successful complete result.
    #[must_use]
    pub fn success(representation: ToolRepresentation) -> Self {
        Self::Complete(CompleteToolResult::success(representation))
    }

    /// Creates a complete tool-level error.
    #[must_use]
    pub const fn error(error: ToolFailure) -> Self {
        Self::Complete(CompleteToolResult::error(error))
    }

    /// Creates an input-required result.
    #[must_use]
    pub const fn input_required(result: InputRequiredToolResult) -> Self {
        Self::InputRequired(result)
    }
}

impl fmt::Debug for CanonicalToolResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalToolResult([redacted])")
    }
}

/// Adaptation seam between the canonical result algebra and a concrete protocol result model.
pub trait ToolResultAdapter {
    /// Concrete result representation produced by this adapter.
    type Output;
    /// Fixed adapter failure type.
    type Error;

    /// Adapts one canonical result without changing domain execution behavior.
    ///
    /// # Errors
    ///
    /// Returns the adapter's fixed error when the target representation cannot express a canonical
    /// result.
    fn adapt(&self, result: CanonicalToolResult) -> Result<Self::Output, Self::Error>;
}

fn validate_content_list(content: &[ContentBlock]) -> Result<(), ResultBuildError> {
    if content.is_empty() {
        return Err(ResultBuildError::Empty);
    }
    if content.len() > MAX_CONTENT_BLOCKS {
        return Err(ResultBuildError::TooMany);
    }
    Ok(())
}

fn validate_nonempty_length(value: &str, maximum: usize) -> Result<(), ResultBuildError> {
    if value.is_empty() {
        return Err(ResultBuildError::Empty);
    }
    if value.len() > maximum {
        return Err(ResultBuildError::TooLong);
    }
    Ok(())
}

fn valid_media_type(value: &str) -> bool {
    if !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_whitespace)
        || value.as_bytes().last().is_some_and(u8::is_ascii_whitespace)
    {
        return false;
    }
    let mut segments = value.split(';');
    let Some(essence) = segments.next() else {
        return false;
    };
    let mut parts = essence.split('/');
    let Some(kind) = parts.next() else {
        return false;
    };
    let Some(subtype) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && valid_media_token(kind)
        && valid_media_token(subtype)
        && segments.all(valid_media_parameter)
}

fn valid_media_parameter(parameter: &str) -> bool {
    let Some((name, value)) = parameter.trim().split_once('=') else {
        return false;
    };
    valid_media_token(name)
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, b'!'..=b'~') && byte != b';')
}

fn valid_media_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-'
                )
        })
}

fn valid_resource_uri(value: &str) -> bool {
    if !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    !remainder.is_empty()
        && scheme
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && scheme.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'+' | b'-' | b'.')
        })
}
