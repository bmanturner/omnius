use std::{collections::BTreeSet, fmt};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};
use serde_json::Value;
use url::Url;

use crate::value::{
    ContractError, JsonObject, LlmRequestId, SchemaVersion, deserialize_optional_non_null,
    validate_identifier, validate_mime_type, validate_name, validate_reference,
};

/// The source of a binary input part.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum BinarySource {
    /// Base64-encoded bytes carried directly in the request.
    Inline(InlineBinarySource),
    /// Bytes retrievable through a URI.
    Url(UrlBinarySource),
    /// Bytes stored under an application object-storage key.
    Object(ObjectBinarySource),
}

impl BinarySource {
    /// Creates an inline base64 source.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the encoded value is empty.
    pub fn inline(data_base64: String) -> Result<Self, ContractError> {
        Ok(Self::Inline(InlineBinarySource::new(data_base64)?))
    }

    /// Creates a URL source.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the URL is malformed or non-absolute.
    pub fn url(url: String) -> Result<Self, ContractError> {
        Ok(Self::Url(UrlBinarySource::new(url)?))
    }

    /// Creates an object-storage source.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the object key is empty.
    pub fn object(object_key: String) -> Result<Self, ContractError> {
        Ok(Self::Object(ObjectBinarySource::new(object_key)?))
    }

    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Inline(source) => validate_reference(source.data_base64()),
            Self::Url(source) => source.validate(),
            Self::Object(source) => validate_reference(source.object_key()),
        }
    }
}

impl fmt::Debug for BinarySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Inline(_) => "BinarySource::Inline([REDACTED])",
            Self::Url(_) => "BinarySource::Url([REDACTED])",
            Self::Object(_) => "BinarySource::Object([REDACTED])",
        })
    }
}

/// An inline base64 binary source.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InlineBinarySource {
    data_base64: String,
}

impl InlineBinarySource {
    /// Validates and owns an inline base64 value.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the value is empty.
    pub fn new(data_base64: String) -> Result<Self, ContractError> {
        validate_reference(&data_base64)?;
        Ok(Self { data_base64 })
    }

    /// Borrows the encoded bytes.
    #[must_use]
    pub fn data_base64(&self) -> &str {
        &self.data_base64
    }
}

/// A URI-backed binary source.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UrlBinarySource {
    #[schemars(url)]
    url: String,
}

impl UrlBinarySource {
    /// Validates and owns a binary URL.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the URL is malformed or non-absolute.
    pub fn new(url: String) -> Result<Self, ContractError> {
        validate_url(&url)?;
        Ok(Self { url })
    }

    /// Borrows the URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_url(&self.url)
    }
}

/// An object-storage-backed binary source.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectBinarySource {
    object_key: String,
}

impl ObjectBinarySource {
    /// Validates and owns an object key.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidReference`] when the key is empty.
    pub fn new(object_key: String) -> Result<Self, ContractError> {
        validate_reference(&object_key)?;
        Ok(Self { object_key })
    }

    /// Borrows the object key.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// The canonical role of an LLM request message.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// System-level instructions.
    System,
    /// Application-developer instructions.
    Developer,
    /// End-user input.
    User,
    /// Prior assistant output.
    Assistant,
    /// Tool-originated input.
    Tool,
}

/// The status of a prior or returned tool result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultStatus {
    /// The tool completed successfully.
    Success,
    /// The tool returned an error result.
    Error,
    /// The tool execution was cancelled.
    Cancelled,
}

/// A plaintext message input part.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextInputPart {
    text: String,
}

impl TextInputPart {
    /// Owns a plaintext input part.
    #[must_use]
    pub const fn new(text: String) -> Self {
        Self { text }
    }

    /// Borrows the plaintext directly.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

/// An arbitrary JSON message input part.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredInputPart {
    value: Value,
}

impl StructuredInputPart {
    /// Owns an arbitrary JSON input value.
    #[must_use]
    pub const fn new(value: Value) -> Self {
        Self { value }
    }

    /// Borrows the arbitrary JSON value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
}

macro_rules! binary_input_part {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            mime_type: String,
            source: BinarySource,
        }

        impl $name {
            /// Validates and owns a typed binary input part.
            ///
            /// # Errors
            ///
            /// Returns a value-free [`ContractError`] when the MIME type or source is invalid.
            pub fn new(mime_type: String, source: BinarySource) -> Result<Self, ContractError> {
                validate_mime_type(&mime_type)?;
                source.validate()?;
                Ok(Self { mime_type, source })
            }

            /// Borrows the MIME type.
            #[must_use]
            pub fn mime_type(&self) -> &str {
                &self.mime_type
            }

            /// Borrows the binary source.
            #[must_use]
            pub const fn source(&self) -> &BinarySource {
                &self.source
            }
        }
    };
}

binary_input_part!(ImageInputPart, "An image message input part.");
binary_input_part!(AudioInputPart, "An audio message input part.");
binary_input_part!(VideoInputPart, "A video message input part.");

/// A file message input part.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileInputPart {
    mime_type: String,
    source: BinarySource,
    filename: Option<String>,
}

impl FileInputPart {
    /// Validates and owns a file input part.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the MIME type, source, or supplied
    /// filename is invalid.
    pub fn new(
        mime_type: String,
        source: BinarySource,
        filename: Option<String>,
    ) -> Result<Self, ContractError> {
        validate_mime_type(&mime_type)?;
        source.validate()?;
        if let Some(filename) = filename.as_deref() {
            validate_name(filename)?;
        }
        Ok(Self {
            mime_type,
            source,
            filename,
        })
    }

    /// Borrows the MIME type.
    #[must_use]
    pub fn mime_type(&self) -> &str {
        &self.mime_type
    }

    /// Borrows the binary source.
    #[must_use]
    pub const fn source(&self) -> &BinarySource {
        &self.source
    }

    /// Borrows the optional filename.
    #[must_use]
    pub fn filename(&self) -> Option<&str> {
        self.filename.as_deref()
    }
}

/// A URI resource reference input part.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceInputPart {
    uri: String,
    mime_type: Option<String>,
}

impl ResourceInputPart {
    /// Validates and owns a resource reference.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the URI or supplied MIME type is invalid.
    pub fn new(uri: String, mime_type: Option<String>) -> Result<Self, ContractError> {
        validate_reference(&uri)?;
        if let Some(mime_type) = mime_type.as_deref() {
            validate_mime_type(mime_type)?;
        }
        Ok(Self { uri, mime_type })
    }

    /// Borrows the resource URI.
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Borrows the optional MIME type.
    #[must_use]
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }
}

/// A prior tool result carried as message input.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultInputPart {
    call_id: String,
    status: ToolResultStatus,
    content: Vec<Value>,
}

impl ToolResultInputPart {
    /// Validates and owns a prior tool result.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::EmptyIdentifier`] when the call identifier is empty.
    pub fn new(
        call_id: String,
        status: ToolResultStatus,
        content: Vec<Value>,
    ) -> Result<Self, ContractError> {
        validate_identifier(&call_id)?;
        Ok(Self {
            call_id,
            status,
            content,
        })
    }

    /// Borrows the stable tool call identifier.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }

    /// Returns the result status.
    #[must_use]
    pub const fn status(&self) -> ToolResultStatus {
        self.status
    }

    /// Borrows the ordered arbitrary result content.
    #[must_use]
    pub fn content(&self) -> &[Value] {
        &self.content
    }
}

/// One ordered, heterogeneous message input part.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LlmInputPart {
    /// Plaintext input.
    Text(TextInputPart),
    /// Arbitrary structured JSON input.
    Structured(StructuredInputPart),
    /// Image input.
    Image(ImageInputPart),
    /// Audio input.
    Audio(AudioInputPart),
    /// Video input.
    Video(VideoInputPart),
    /// File input.
    File(FileInputPart),
    /// URI resource input.
    Resource(ResourceInputPart),
    /// Prior tool result input.
    ToolResult(ToolResultInputPart),
}

impl LlmInputPart {
    /// Creates a plaintext input part.
    #[must_use]
    pub const fn text(text: String) -> Self {
        Self::Text(TextInputPart::new(text))
    }

    /// Creates an arbitrary structured input part.
    #[must_use]
    pub const fn structured(value: Value) -> Self {
        Self::Structured(StructuredInputPart::new(value))
    }

    /// Returns the plaintext for a text part without a provider wrapper.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(part) => Some(part.text()),
            _ => None,
        }
    }

    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Text(_) | Self::Structured(_) => Ok(()),
            Self::Image(part) => {
                validate_mime_type(part.mime_type())?;
                part.source().validate()
            }
            Self::Audio(part) => {
                validate_mime_type(part.mime_type())?;
                part.source().validate()
            }
            Self::Video(part) => {
                validate_mime_type(part.mime_type())?;
                part.source().validate()
            }
            Self::File(part) => {
                validate_mime_type(part.mime_type())?;
                part.source().validate()?;
                if let Some(filename) = part.filename() {
                    validate_name(filename)?;
                }
                Ok(())
            }
            Self::Resource(part) => {
                validate_reference(part.uri())?;
                if let Some(mime_type) = part.mime_type() {
                    validate_mime_type(mime_type)?;
                }
                Ok(())
            }
            Self::ToolResult(part) => validate_identifier(part.call_id()),
        }
    }
}

impl fmt::Debug for LlmInputPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Text(_) => "LlmInputPart::Text([REDACTED])",
            Self::Structured(_) => "LlmInputPart::Structured([REDACTED])",
            Self::Image(_) => "LlmInputPart::Image([REDACTED])",
            Self::Audio(_) => "LlmInputPart::Audio([REDACTED])",
            Self::Video(_) => "LlmInputPart::Video([REDACTED])",
            Self::File(_) => "LlmInputPart::File([REDACTED])",
            Self::Resource(_) => "LlmInputPart::Resource([REDACTED])",
            Self::ToolResult(_) => "LlmInputPart::ToolResult([REDACTED])",
        })
    }
}

/// One canonical ordered request message.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmMessage {
    id: Option<String>,
    role: MessageRole,
    name: Option<String>,
    content: Vec<LlmInputPart>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    metadata: Option<JsonObject>,
}

impl LlmMessage {
    /// Creates an unnamed message with ordered content.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a nested part is invalid.
    pub fn new(role: MessageRole, content: Vec<LlmInputPart>) -> Result<Self, ContractError> {
        let message = Self {
            id: None,
            role,
            name: None,
            content,
            metadata: None,
        };
        message.validate()?;
        Ok(message)
    }

    /// Adds optional stable message identity and name.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied identity or name is invalid.
    pub fn with_identity(
        mut self,
        id: Option<String>,
        name: Option<String>,
    ) -> Result<Self, ContractError> {
        if let Some(id) = id.as_deref() {
            validate_identifier(id)?;
        }
        if let Some(name) = name.as_deref() {
            validate_name(name)?;
        }
        self.id = id;
        self.name = name;
        Ok(self)
    }

    /// Adds arbitrary deterministic message metadata.
    #[must_use]
    pub fn with_metadata(mut self, metadata: JsonObject) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Borrows the optional stable message identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// Returns the message role.
    #[must_use]
    pub const fn role(&self) -> MessageRole {
        self.role
    }

    /// Borrows the optional message name.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Borrows the ordered input parts.
    #[must_use]
    pub fn content(&self) -> &[LlmInputPart] {
        &self.content
    }

    /// Borrows optional deterministic metadata.
    #[must_use]
    pub const fn metadata(&self) -> Option<&JsonObject> {
        self.metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        if let Some(id) = self.id() {
            validate_identifier(id)?;
        }
        if let Some(name) = self.name() {
            validate_name(name)?;
        }
        self.content.iter().try_for_each(LlmInputPart::validate)
    }
}

impl fmt::Debug for LlmMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmMessage")
            .field("role", &self.role)
            .field("content_parts", &self.content.len())
            .finish_non_exhaustive()
    }
}

/// Provider-neutral route requirements for one request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    id: String,
    revision: Option<u64>,
    #[serde(default)]
    required_capabilities: Vec<String>,
    #[serde(default)]
    preferred_capabilities: Vec<String>,
}

impl Route {
    /// Creates validated route requirements.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an invalid route name, zero revision,
    /// invalid capability name, or duplicate capability.
    pub fn new(
        id: String,
        revision: Option<u64>,
        required_capabilities: Vec<String>,
        preferred_capabilities: Vec<String>,
    ) -> Result<Self, ContractError> {
        let route = Self {
            id,
            revision,
            required_capabilities,
            preferred_capabilities,
        };
        route.validate()?;
        Ok(route)
    }

    /// Borrows the stable route identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the optional positive route revision.
    #[must_use]
    pub const fn revision(&self) -> Option<u64> {
        self.revision
    }

    /// Borrows ordered required capabilities.
    #[must_use]
    pub fn required_capabilities(&self) -> &[String] {
        &self.required_capabilities
    }

    /// Borrows ordered preferred capabilities.
    #[must_use]
    pub fn preferred_capabilities(&self) -> &[String] {
        &self.preferred_capabilities
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_name(&self.id)?;
        if self.revision == Some(0) {
            return Err(ContractError::InvalidRevision);
        }
        validate_unique_names(
            &self.required_capabilities,
            ContractError::DuplicateRequiredCapability,
        )?;
        validate_unique_names(
            &self.preferred_capabilities,
            ContractError::DuplicatePreferredCapability,
        )
    }
}

/// Optional provider-neutral generation controls.
#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationConfig {
    temperature: Option<f64>,
    top_p: Option<f64>,
    max_output_tokens: Option<u64>,
    candidate_count: Option<u32>,
    #[serde(default)]
    stop: Vec<String>,
    seed: Option<i64>,
}

impl GenerationConfig {
    /// Creates generation controls.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for non-finite controls, invalid `top_p`,
    /// or zero positive limits.
    pub fn new(
        temperature: Option<f64>,
        top_p: Option<f64>,
        max_output_tokens: Option<u64>,
        candidate_count: Option<u32>,
        stop: Vec<String>,
        seed: Option<i64>,
    ) -> Result<Self, ContractError> {
        let generation = Self {
            temperature,
            top_p,
            max_output_tokens,
            candidate_count,
            stop,
            seed,
        };
        generation.validate()?;
        Ok(generation)
    }

    /// Returns the optional temperature.
    #[must_use]
    pub const fn temperature(&self) -> Option<f64> {
        self.temperature
    }

    /// Returns the optional nucleus sampling probability.
    #[must_use]
    pub const fn top_p(&self) -> Option<f64> {
        self.top_p
    }

    /// Returns the optional maximum output token count.
    #[must_use]
    pub const fn max_output_tokens(&self) -> Option<u64> {
        self.max_output_tokens
    }

    /// Returns the optional requested candidate count.
    #[must_use]
    pub const fn candidate_count(&self) -> Option<u32> {
        self.candidate_count
    }

    /// Borrows ordered stop sequences.
    #[must_use]
    pub fn stop(&self) -> &[String] {
        &self.stop
    }

    /// Returns the optional deterministic seed.
    #[must_use]
    pub const fn seed(&self) -> Option<i64> {
        self.seed
    }

    fn validate(&self) -> Result<(), ContractError> {
        if self.temperature.is_some_and(|value| !value.is_finite()) {
            return Err(ContractError::NonFiniteGenerationControl);
        }
        if self
            .top_p
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err(ContractError::InvalidTopP);
        }
        if self.max_output_tokens == Some(0) || self.candidate_count == Some(0) {
            return Err(ContractError::InvalidPositiveLimit);
        }
        Ok(())
    }
}

/// The desired response family for a completion request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    /// Let the route choose an output family.
    Auto,
    /// Prefer text output.
    Text,
    /// Require structured output.
    Structured,
    /// Prefer tool calls.
    Tools,
    /// Prefer generated media.
    Media,
}

/// A JSON Schema value accepted by the canonical request contract.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SchemaDefinition {
    /// An owned JSON Schema object with deterministic key order.
    Object(JsonObject),
    /// A boolean JSON Schema.
    Boolean(bool),
}

impl fmt::Debug for SchemaDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SchemaDefinition([REDACTED])")
    }
}

/// Requested completion output mode and optional schema constraints.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRequest {
    mode: OutputMode,
    schema_id: Option<String>,
    schema: Option<SchemaDefinition>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "bool")]
    strict: Option<bool>,
    #[serde(default)]
    mime_types: Vec<String>,
}

impl OutputRequest {
    /// Creates an output request with no optional schema controls.
    #[must_use]
    pub const fn new(mode: OutputMode) -> Self {
        Self {
            mode,
            schema_id: None,
            schema: None,
            strict: None,
            mime_types: Vec::new(),
        }
    }

    /// Adds optional schema identity, schema, and strictness.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied schema identity is invalid.
    pub fn with_schema(
        mut self,
        schema_id: Option<String>,
        schema: Option<SchemaDefinition>,
        strict: Option<bool>,
    ) -> Result<Self, ContractError> {
        if let Some(schema_id) = schema_id.as_deref() {
            validate_identifier(schema_id)?;
        }
        self.schema_id = schema_id;
        self.schema = schema;
        self.strict = strict;
        Ok(self)
    }

    /// Adds ordered accepted MIME types.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::EmptyMimeType`] when a MIME type is empty.
    pub fn with_mime_types(mut self, mime_types: Vec<String>) -> Result<Self, ContractError> {
        mime_types
            .iter()
            .try_for_each(|mime_type| validate_mime_type(mime_type))?;
        self.mime_types = mime_types;
        Ok(self)
    }

    /// Returns the desired output mode.
    #[must_use]
    pub const fn mode(&self) -> OutputMode {
        self.mode
    }

    /// Borrows the optional response schema identity.
    #[must_use]
    pub fn schema_id(&self) -> Option<&str> {
        self.schema_id.as_deref()
    }

    /// Borrows the optional response schema.
    #[must_use]
    pub const fn schema(&self) -> Option<&SchemaDefinition> {
        self.schema.as_ref()
    }

    /// Returns optional strict-schema behavior.
    #[must_use]
    pub const fn strict(&self) -> Option<bool> {
        self.strict
    }

    /// Borrows ordered accepted MIME types.
    #[must_use]
    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    fn validate(&self) -> Result<(), ContractError> {
        if let Some(schema_id) = self.schema_id() {
            validate_identifier(schema_id)?;
        }
        self.mime_types
            .iter()
            .try_for_each(|mime_type| validate_mime_type(mime_type))
    }
}

impl fmt::Debug for OutputRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutputRequest")
            .field("mode", &self.mode)
            .field("mime_type_count", &self.mime_types.len())
            .finish_non_exhaustive()
    }
}

/// One provider-neutral tool declaration.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDefinition {
    name: String,
    description: Option<String>,
    capability_id: Option<String>,
    input_schema: SchemaDefinition,
    output_schema: Option<SchemaDefinition>,
}

impl ToolDefinition {
    /// Creates a tool declaration with its required input schema.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the stable tool name is invalid.
    pub fn new(name: String, input_schema: SchemaDefinition) -> Result<Self, ContractError> {
        validate_name(&name)?;
        Ok(Self {
            name,
            description: None,
            capability_id: None,
            input_schema,
            output_schema: None,
        })
    }

    /// Adds optional description, capability identity, and output schema.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied capability identity is invalid.
    pub fn with_details(
        mut self,
        description: Option<String>,
        capability_id: Option<String>,
        output_schema: Option<SchemaDefinition>,
    ) -> Result<Self, ContractError> {
        if let Some(capability_id) = capability_id.as_deref() {
            validate_identifier(capability_id)?;
        }
        self.description = description;
        self.capability_id = capability_id;
        self.output_schema = output_schema;
        Ok(self)
    }

    /// Borrows the stable tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Borrows the optional human-readable description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Borrows the optional application capability identity.
    #[must_use]
    pub fn capability_id(&self) -> Option<&str> {
        self.capability_id.as_deref()
    }

    /// Borrows the required input schema.
    #[must_use]
    pub const fn input_schema(&self) -> &SchemaDefinition {
        &self.input_schema
    }

    /// Borrows the optional output schema.
    #[must_use]
    pub const fn output_schema(&self) -> Option<&SchemaDefinition> {
        self.output_schema.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_name(&self.name)?;
        if let Some(capability_id) = self.capability_id() {
            validate_identifier(capability_id)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ToolDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolDefinition([REDACTED])")
    }
}

/// Required resource and orchestration limits for one request.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestLimits {
    deadline_ms: u64,
    max_model_turns: u32,
    max_tool_calls: u32,
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_cost_microunits: Option<u64>,
}

impl RequestLimits {
    /// Creates required request limits.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when the deadline or model-turn
    /// limit is zero. Tool-call and cost ceilings may be zero.
    pub const fn new(
        deadline_ms: u64,
        max_model_turns: u32,
        max_tool_calls: u32,
    ) -> Result<Self, ContractError> {
        if deadline_ms == 0 || max_model_turns == 0 {
            return Err(ContractError::InvalidPositiveLimit);
        }
        Ok(Self {
            deadline_ms,
            max_model_turns,
            max_tool_calls,
            max_input_bytes: None,
            max_output_bytes: None,
            max_cost_microunits: None,
        })
    }

    /// Adds optional byte and cost ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::InvalidPositiveLimit`] when a supplied byte ceiling is zero.
    pub fn with_optional_limits(
        mut self,
        max_input_bytes: Option<u64>,
        max_output_bytes: Option<u64>,
        max_cost_microunits: Option<u64>,
    ) -> Result<Self, ContractError> {
        if max_input_bytes == Some(0) || max_output_bytes == Some(0) {
            return Err(ContractError::InvalidPositiveLimit);
        }
        self.max_input_bytes = max_input_bytes;
        self.max_output_bytes = max_output_bytes;
        self.max_cost_microunits = max_cost_microunits;
        Ok(self)
    }

    /// Returns the required deadline in milliseconds.
    #[must_use]
    pub const fn deadline_ms(self) -> u64 {
        self.deadline_ms
    }

    /// Returns the maximum number of model turns.
    #[must_use]
    pub const fn max_model_turns(self) -> u32 {
        self.max_model_turns
    }

    /// Returns the maximum number of tool calls.
    #[must_use]
    pub const fn max_tool_calls(self) -> u32 {
        self.max_tool_calls
    }

    /// Returns the optional maximum input bytes.
    #[must_use]
    pub const fn max_input_bytes(self) -> Option<u64> {
        self.max_input_bytes
    }

    /// Returns the optional maximum output bytes.
    #[must_use]
    pub const fn max_output_bytes(self) -> Option<u64> {
        self.max_output_bytes
    }

    /// Returns the optional maximum cost in microunits.
    #[must_use]
    pub const fn max_cost_microunits(self) -> Option<u64> {
        self.max_cost_microunits
    }

    fn validate(self) -> Result<(), ContractError> {
        if self.deadline_ms == 0
            || self.max_model_turns == 0
            || self.max_input_bytes == Some(0)
            || self.max_output_bytes == Some(0)
        {
            return Err(ContractError::InvalidPositiveLimit);
        }
        Ok(())
    }
}

/// The complete provider-neutral canonical LLM request.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRequest {
    schema_version: SchemaVersion,
    request_id: LlmRequestId,
    route: Route,
    messages: Vec<LlmMessage>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "GenerationConfig")]
    generation: Option<GenerationConfig>,
    output: OutputRequest,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<ToolDefinition>")]
    tools: Option<Vec<ToolDefinition>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    tool_policy: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    metadata: Option<JsonObject>,
    limits: RequestLimits,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    data_policy: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    principal_context: Option<JsonObject>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    tenant_context: Option<JsonObject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmRequestWire {
    schema_version: SchemaVersion,
    request_id: LlmRequestId,
    route: Route,
    messages: Vec<LlmMessage>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    generation: Option<GenerationConfig>,
    output: OutputRequest,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    tools: Option<Vec<ToolDefinition>>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    tool_policy: Option<JsonObject>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    metadata: Option<JsonObject>,
    limits: RequestLimits,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    data_policy: Option<JsonObject>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    principal_context: Option<JsonObject>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    tenant_context: Option<JsonObject>,
}

impl<'de> Deserialize<'de> for LlmRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LlmRequestWire::deserialize(deserializer)?;
        let request = Self {
            schema_version: wire.schema_version,
            request_id: wire.request_id,
            route: wire.route,
            messages: wire.messages,
            generation: wire.generation,
            output: wire.output,
            tools: wire.tools,
            tool_policy: wire.tool_policy,
            metadata: wire.metadata,
            limits: wire.limits,
            data_policy: wire.data_policy,
            principal_context: wire.principal_context,
            tenant_context: wire.tenant_context,
        };
        request.validate().map_err(D::Error::custom)?;
        Ok(request)
    }
}

impl LlmRequest {
    /// Creates a request containing every required fixed-schema field.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when any nested required value is invalid.
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        route: Route,
        messages: Vec<LlmMessage>,
        output: OutputRequest,
        limits: RequestLimits,
    ) -> Result<Self, ContractError> {
        let request = Self {
            schema_version: SchemaVersion::CURRENT,
            request_id: request_id.into(),
            route,
            messages,
            generation: None,
            output,
            tools: None,
            tool_policy: None,
            metadata: None,
            limits,
            data_policy: None,
            principal_context: None,
            tenant_context: None,
        };
        request.validate()?;
        Ok(request)
    }

    /// Adds optional generation controls.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the controls are invalid.
    pub fn with_generation(mut self, generation: GenerationConfig) -> Result<Self, ContractError> {
        generation.validate()?;
        self.generation = Some(generation);
        Ok(self)
    }

    /// Adds ordered tool declarations and arbitrary tool policy.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an invalid or duplicate tool name.
    pub fn with_tools(
        mut self,
        tools: Vec<ToolDefinition>,
        tool_policy: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        validate_tools(&tools)?;
        self.tools = Some(tools);
        self.tool_policy = tool_policy;
        Ok(self)
    }

    /// Adds arbitrary deterministic request metadata and policy contexts.
    #[must_use]
    pub fn with_context(
        mut self,
        metadata: Option<JsonObject>,
        data_policy: Option<JsonObject>,
        principal_context: Option<JsonObject>,
        tenant_context: Option<JsonObject>,
    ) -> Self {
        self.metadata = metadata;
        self.data_policy = data_policy;
        self.principal_context = principal_context;
        self.tenant_context = tenant_context;
        self
    }

    /// Returns the fixed schema version.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Borrows the opaque stable request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &LlmRequestId {
        &self.request_id
    }

    /// Borrows route requirements.
    #[must_use]
    pub const fn route(&self) -> &Route {
        &self.route
    }

    /// Borrows ordered request messages.
    #[must_use]
    pub fn messages(&self) -> &[LlmMessage] {
        &self.messages
    }

    /// Borrows optional generation controls.
    #[must_use]
    pub const fn generation(&self) -> Option<&GenerationConfig> {
        self.generation.as_ref()
    }

    /// Borrows output requirements.
    #[must_use]
    pub const fn output(&self) -> &OutputRequest {
        &self.output
    }

    /// Borrows optional ordered tool declarations.
    #[must_use]
    pub fn tools(&self) -> Option<&[ToolDefinition]> {
        self.tools.as_deref()
    }

    /// Borrows optional arbitrary tool policy.
    #[must_use]
    pub const fn tool_policy(&self) -> Option<&JsonObject> {
        self.tool_policy.as_ref()
    }

    /// Borrows optional arbitrary metadata.
    #[must_use]
    pub const fn metadata(&self) -> Option<&JsonObject> {
        self.metadata.as_ref()
    }

    /// Returns required resource limits.
    #[must_use]
    pub const fn limits(&self) -> RequestLimits {
        self.limits
    }

    /// Borrows optional arbitrary data policy.
    #[must_use]
    pub const fn data_policy(&self) -> Option<&JsonObject> {
        self.data_policy.as_ref()
    }

    /// Borrows optional arbitrary principal context.
    #[must_use]
    pub const fn principal_context(&self) -> Option<&JsonObject> {
        self.principal_context.as_ref()
    }

    /// Borrows optional arbitrary tenant context.
    #[must_use]
    pub const fn tenant_context(&self) -> Option<&JsonObject> {
        self.tenant_context.as_ref()
    }

    /// Checks all canonical request invariants recursively.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.route.validate()?;
        self.messages.iter().try_for_each(LlmMessage::validate)?;
        if let Some(generation) = &self.generation {
            generation.validate()?;
        }
        self.output.validate()?;
        if let Some(tools) = &self.tools {
            validate_tools(tools)?;
        }
        self.limits.validate()
    }
}

impl fmt::Debug for LlmRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmRequest")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("message_count", &self.messages.len())
            .field("tool_count", &self.tools.as_ref().map_or(0, Vec::len))
            .finish_non_exhaustive()
    }
}

fn validate_unique_names(
    values: &[String],
    duplicate_error: ContractError,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_name(value)?;
        if !seen.insert(value.as_str()) {
            return Err(duplicate_error);
        }
    }
    Ok(())
}

fn validate_tools(tools: &[ToolDefinition]) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for tool in tools {
        tool.validate()?;
        if !seen.insert(tool.name()) {
            return Err(ContractError::DuplicateToolName);
        }
    }
    Ok(())
}

fn validate_url(value: &str) -> Result<(), ContractError> {
    Url::parse(value)
        .map(|_| ())
        .map_err(|_| ContractError::InvalidReference)
}
