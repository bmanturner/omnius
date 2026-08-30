use std::{collections::BTreeSet, fmt};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};
use serde_json::Value;
use time::OffsetDateTime;

use crate::request::ToolResultStatus;
use crate::value::{
    ContractError, JsonObject, LlmRequestId, RequiredNullable, SchemaVersion, UtcTimestamp,
    deserialize_optional_non_null, validate_identifier, validate_name,
};

/// The presentation format of a text output part.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TextFormat {
    /// Unformatted plaintext.
    Plain,
    /// Markdown text.
    Markdown,
    /// An HTML fragment rather than a complete document.
    HtmlFragment,
}

/// The schema-validation state retained with arbitrary structured output.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StructuredValidation {
    /// The value satisfied the requested schema.
    Valid,
    /// The value did not satisfy the requested schema.
    Invalid,
    /// Schema validation was not requested.
    NotRequested,
}

/// Completion and candidate lifecycle status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionStatus {
    /// The provider completed the output.
    Completed,
    /// The provider returned a usable partial output.
    Partial,
    /// The provider refused the request.
    Refused,
    /// Work was cancelled.
    Cancelled,
    /// Work failed.
    Failed,
}

/// A directly accessible text output part.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextOutputPart {
    id: String,
    text: String,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "TextFormat")]
    format: Option<TextFormat>,
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

impl TextOutputPart {
    /// Creates a stable text output part.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the part identifier is invalid.
    pub fn new(
        id: String,
        text: String,
        format: Option<TextFormat>,
    ) -> Result<Self, ContractError> {
        validate_identifier(&id)?;
        Ok(Self {
            id,
            text,
            format,
            annotations: None,
            provider_metadata: None,
        })
    }

    /// Adds deterministic annotations and provider provenance metadata.
    #[must_use]
    pub fn with_metadata(
        mut self,
        annotations: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Self {
        self.annotations = annotations;
        self.provider_metadata = provider_metadata;
        self
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Borrows plaintext directly, without a provider-specific wrapper.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
    /// Returns the optional presentation format.
    #[must_use]
    pub const fn format(&self) -> Option<TextFormat> {
        self.format
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

    fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.id)
    }
}

/// An arbitrary structured JSON output and its validation state.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuredOutputPart {
    id: String,
    value: Value,
    schema_id: Option<String>,
    validation: StructuredValidation,
    #[serde(default)]
    repair_attempts: u32,
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

impl StructuredOutputPart {
    /// Creates a structured output with an arbitrary JSON value.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when the part identifier is invalid.
    pub fn new(
        id: String,
        value: Value,
        validation: StructuredValidation,
    ) -> Result<Self, ContractError> {
        validate_identifier(&id)?;
        Ok(Self {
            id,
            value,
            schema_id: None,
            validation,
            repair_attempts: 0,
            annotations: None,
            provider_metadata: None,
        })
    }

    /// Adds schema identity and the number of repair attempts.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied schema identifier is invalid.
    pub fn with_validation_details(
        mut self,
        schema_id: Option<String>,
        repair_attempts: u32,
    ) -> Result<Self, ContractError> {
        if let Some(schema_id) = schema_id.as_deref() {
            validate_identifier(schema_id)?;
        }
        self.schema_id = schema_id;
        self.repair_attempts = repair_attempts;
        Ok(self)
    }

    /// Adds deterministic annotations and provider provenance metadata.
    #[must_use]
    pub fn with_metadata(
        mut self,
        annotations: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Self {
        self.annotations = annotations;
        self.provider_metadata = provider_metadata;
        self
    }

    /// Borrows the stable part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Borrows the arbitrary JSON value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }
    /// Borrows the optional schema identity.
    #[must_use]
    pub fn schema_id(&self) -> Option<&str> {
        self.schema_id.as_deref()
    }
    /// Returns the validation state.
    #[must_use]
    pub const fn validation(&self) -> StructuredValidation {
        self.validation
    }
    /// Returns the number of repair attempts.
    #[must_use]
    pub const fn repair_attempts(&self) -> u32 {
        self.repair_attempts
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

    fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.id)?;
        if let Some(schema_id) = self.schema_id() {
            validate_identifier(schema_id)?;
        }
        Ok(())
    }
}

/// A canonical application tool call with stable identity and provenance.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCallOutputPart {
    id: String,
    call_id: String,
    name: String,
    arguments: Value,
    capability_id: Option<String>,
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

impl ToolCallOutputPart {
    /// Creates a stable tool call retaining arbitrary complete JSON arguments.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when an identifier or the tool name is invalid.
    pub fn new(
        id: String,
        call_id: String,
        name: String,
        arguments: Value,
    ) -> Result<Self, ContractError> {
        validate_identifier(&id)?;
        validate_identifier(&call_id)?;
        validate_name(&name)?;
        Ok(Self {
            id,
            call_id,
            name,
            arguments,
            capability_id: None,
            annotations: None,
            provider_metadata: None,
        })
    }

    /// Adds application capability identity and deterministic provider provenance.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied capability identifier is invalid.
    pub fn with_provenance(
        mut self,
        capability_id: Option<String>,
        annotations: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        if let Some(capability_id) = capability_id.as_deref() {
            validate_identifier(capability_id)?;
        }
        self.capability_id = capability_id;
        self.annotations = annotations;
        self.provider_metadata = provider_metadata;
        Ok(self)
    }

    /// Borrows the stable output part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Borrows the stable call identifier.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Borrows the stable tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Borrows complete arbitrary JSON arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }
    /// Borrows the optional application capability identity.
    #[must_use]
    pub fn capability_id(&self) -> Option<&str> {
        self.capability_id.as_deref()
    }
    /// Borrows optional deterministic annotations.
    #[must_use]
    pub const fn annotations(&self) -> Option<&JsonObject> {
        self.annotations.as_ref()
    }
    /// Borrows optional deterministic provider provenance metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.id)?;
        validate_identifier(&self.call_id)?;
        validate_name(&self.name)?;
        if let Some(capability_id) = self.capability_id() {
            validate_identifier(capability_id)?;
        }
        Ok(())
    }
}

/// A recursive canonical tool result with ordered normalized content.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultOutputPart {
    id: String,
    call_id: String,
    status: ToolResultStatus,
    content: Vec<LlmOutputPart>,
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

impl ToolResultOutputPart {
    /// Creates a recursive tool result with ordered content.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when an identifier or nested part is invalid.
    pub fn new(
        id: String,
        call_id: String,
        status: ToolResultStatus,
        content: Vec<LlmOutputPart>,
    ) -> Result<Self, ContractError> {
        let part = Self {
            id,
            call_id,
            status,
            content,
            annotations: None,
            provider_metadata: None,
        };
        part.validate()?;
        Ok(part)
    }

    /// Adds deterministic annotations and provider provenance metadata.
    #[must_use]
    pub fn with_metadata(
        mut self,
        annotations: Option<JsonObject>,
        provider_metadata: Option<JsonObject>,
    ) -> Self {
        self.annotations = annotations;
        self.provider_metadata = provider_metadata;
        self
    }

    /// Borrows the stable output part identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Borrows the stable call identifier shared with its tool call.
    #[must_use]
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
    /// Returns the result status.
    #[must_use]
    pub const fn status(&self) -> ToolResultStatus {
        self.status
    }
    /// Borrows ordered recursive result content.
    #[must_use]
    pub fn content(&self) -> &[LlmOutputPart] {
        &self.content
    }
    /// Borrows optional deterministic annotations.
    #[must_use]
    pub const fn annotations(&self) -> Option<&JsonObject> {
        self.annotations.as_ref()
    }
    /// Borrows optional deterministic provider provenance metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.id)?;
        validate_identifier(&self.call_id)?;
        self.content.iter().try_for_each(LlmOutputPart::validate)
    }
}

/// One ordered canonical output part.
///
/// Additional fixed variants are added by the media and unknown-content layer without
/// changing the four foundational variants owned here.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum LlmOutputPart {
    /// Direct text output.
    Text(TextOutputPart),
    /// Arbitrary structured JSON output.
    Structured(StructuredOutputPart),
    /// A normalized application tool call.
    ToolCall(ToolCallOutputPart),
    /// A recursive normalized tool result.
    ToolResult(ToolResultOutputPart),
}

impl LlmOutputPart {
    /// Borrows the stable identifier common to every output part.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Text(part) => part.id(),
            Self::Structured(part) => part.id(),
            Self::ToolCall(part) => part.id(),
            Self::ToolResult(part) => part.id(),
        }
    }
    /// Returns direct plaintext for a text part without a provider-specific wrapper.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(part) => Some(part.text()),
            _ => None,
        }
    }
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Text(part) => part.validate(),
            Self::Structured(part) => part.validate(),
            Self::ToolCall(part) => part.validate(),
            Self::ToolResult(part) => part.validate(),
        }
    }
}

impl fmt::Debug for LlmOutputPart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Text(_) => "LlmOutputPart::Text([REDACTED])",
            Self::Structured(_) => "LlmOutputPart::Structured([REDACTED])",
            Self::ToolCall(_) => "LlmOutputPart::ToolCall([REDACTED])",
            Self::ToolResult(_) => "LlmOutputPart::ToolResult([REDACTED])",
        })
    }
}

/// One retained provider-returned completion candidate.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    id: Option<String>,
    index: u32,
    status: CompletionStatus,
    stop_reason: Option<String>,
    output: Vec<LlmOutputPart>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
}

impl Candidate {
    /// Creates a candidate with ordered output.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a nested content part is invalid.
    pub fn new(
        index: u32,
        status: CompletionStatus,
        output: Vec<LlmOutputPart>,
    ) -> Result<Self, ContractError> {
        let candidate = Self {
            id: None,
            index,
            status,
            stop_reason: None,
            output,
            provider_metadata: None,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// Adds candidate identity, stop reason, and provider metadata.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for an invalid supplied identity or stop reason.
    pub fn with_details(
        mut self,
        id: Option<String>,
        stop_reason: Option<String>,
        provider_metadata: Option<JsonObject>,
    ) -> Result<Self, ContractError> {
        if let Some(id) = id.as_deref() {
            validate_identifier(id)?;
        }
        if let Some(stop_reason) = stop_reason.as_deref() {
            validate_name(stop_reason)?;
        }
        self.id = id;
        self.stop_reason = stop_reason;
        self.provider_metadata = provider_metadata;
        Ok(self)
    }

    /// Borrows the optional native candidate identifier.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    /// Returns the provider candidate index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }
    /// Returns the candidate status.
    #[must_use]
    pub const fn status(&self) -> CompletionStatus {
        self.status
    }
    /// Borrows the optional stop reason.
    #[must_use]
    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }
    /// Borrows ordered candidate output.
    #[must_use]
    pub fn output(&self) -> &[LlmOutputPart] {
        &self.output
    }
    /// Borrows optional deterministic provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }

    fn validate(&self) -> Result<(), ContractError> {
        if let Some(id) = self.id() {
            validate_identifier(id)?;
        }
        if let Some(stop_reason) = self.stop_reason() {
            validate_name(stop_reason)?;
        }
        self.output.iter().try_for_each(LlmOutputPart::validate)
    }
}

impl fmt::Debug for Candidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Candidate")
            .field("index", &self.index)
            .field("status", &self.status)
            .field("output_parts", &self.output.len())
            .finish_non_exhaustive()
    }
}

/// Comprehensive normalized and provider-specific completion usage.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    #[schemars(with = "Option<u64>")]
    input_tokens: RequiredNullable<u64>,
    #[schemars(with = "Option<u64>")]
    output_tokens: RequiredNullable<u64>,
    cached_input_tokens: Option<u64>,
    cache_read_tokens: Option<u64>,
    cache_write_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    audio_input_tokens: Option<u64>,
    audio_output_tokens: Option<u64>,
    image_input_units: Option<u64>,
    image_output_units: Option<u64>,
    video_input_units: Option<u64>,
    video_output_units: Option<u64>,
    tool_execution_units: Option<u64>,
    estimated_cost_microunits: Option<u64>,
    actual_cost_microunits: Option<u64>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_units: Option<JsonObject>,
}

impl Usage {
    /// Creates usage with the two required nullable token counters.
    #[must_use]
    pub const fn new(input_tokens: Option<u64>, output_tokens: Option<u64>) -> Self {
        Self {
            input_tokens: RequiredNullable::new(input_tokens),
            output_tokens: RequiredNullable::new(output_tokens),
            cached_input_tokens: None,
            cache_read_tokens: None,
            cache_write_tokens: None,
            reasoning_tokens: None,
            audio_input_tokens: None,
            audio_output_tokens: None,
            image_input_units: None,
            image_output_units: None,
            video_input_units: None,
            video_output_units: None,
            tool_execution_units: None,
            estimated_cost_microunits: None,
            actual_cost_microunits: None,
            provider_units: None,
        }
    }

    /// Adds cache, reasoning, and audio token counters.
    #[must_use]
    pub const fn with_token_details(
        mut self,
        cached_input_tokens: Option<u64>,
        cache_read_tokens: Option<u64>,
        cache_write_tokens: Option<u64>,
        reasoning_tokens: Option<u64>,
        audio_input_tokens: Option<u64>,
        audio_output_tokens: Option<u64>,
    ) -> Self {
        self.cached_input_tokens = cached_input_tokens;
        self.cache_read_tokens = cache_read_tokens;
        self.cache_write_tokens = cache_write_tokens;
        self.reasoning_tokens = reasoning_tokens;
        self.audio_input_tokens = audio_input_tokens;
        self.audio_output_tokens = audio_output_tokens;
        self
    }

    /// Adds image, video, and tool execution unit counters.
    #[must_use]
    pub const fn with_execution_units(
        mut self,
        image_input_units: Option<u64>,
        image_output_units: Option<u64>,
        video_input_units: Option<u64>,
        video_output_units: Option<u64>,
        tool_execution_units: Option<u64>,
    ) -> Self {
        self.image_input_units = image_input_units;
        self.image_output_units = image_output_units;
        self.video_input_units = video_input_units;
        self.video_output_units = video_output_units;
        self.tool_execution_units = tool_execution_units;
        self
    }

    /// Adds estimated and actual costs plus namespaced provider units.
    #[must_use]
    pub fn with_costs(
        mut self,
        estimated_cost_microunits: Option<u64>,
        actual_cost_microunits: Option<u64>,
        provider_units: Option<JsonObject>,
    ) -> Self {
        self.estimated_cost_microunits = estimated_cost_microunits;
        self.actual_cost_microunits = actual_cost_microunits;
        self.provider_units = provider_units;
        self
    }

    /// Returns the required nullable input-token counter.
    #[must_use]
    pub fn input_tokens(&self) -> Option<u64> {
        self.input_tokens.as_ref().copied()
    }
    /// Returns the required nullable output-token counter.
    #[must_use]
    pub fn output_tokens(&self) -> Option<u64> {
        self.output_tokens.as_ref().copied()
    }
    /// Returns cached input tokens.
    #[must_use]
    pub const fn cached_input_tokens(&self) -> Option<u64> {
        self.cached_input_tokens
    }
    /// Returns cache-read tokens.
    #[must_use]
    pub const fn cache_read_tokens(&self) -> Option<u64> {
        self.cache_read_tokens
    }
    /// Returns cache-write tokens.
    #[must_use]
    pub const fn cache_write_tokens(&self) -> Option<u64> {
        self.cache_write_tokens
    }
    /// Returns provider-reported reasoning tokens.
    #[must_use]
    pub const fn reasoning_tokens(&self) -> Option<u64> {
        self.reasoning_tokens
    }
    /// Returns audio input tokens.
    #[must_use]
    pub const fn audio_input_tokens(&self) -> Option<u64> {
        self.audio_input_tokens
    }
    /// Returns audio output tokens.
    #[must_use]
    pub const fn audio_output_tokens(&self) -> Option<u64> {
        self.audio_output_tokens
    }
    /// Returns image input units.
    #[must_use]
    pub const fn image_input_units(&self) -> Option<u64> {
        self.image_input_units
    }
    /// Returns image output units.
    #[must_use]
    pub const fn image_output_units(&self) -> Option<u64> {
        self.image_output_units
    }
    /// Returns video input units.
    #[must_use]
    pub const fn video_input_units(&self) -> Option<u64> {
        self.video_input_units
    }
    /// Returns video output units.
    #[must_use]
    pub const fn video_output_units(&self) -> Option<u64> {
        self.video_output_units
    }
    /// Returns tool execution units.
    #[must_use]
    pub const fn tool_execution_units(&self) -> Option<u64> {
        self.tool_execution_units
    }
    /// Returns estimated cost in microunits.
    #[must_use]
    pub const fn estimated_cost_microunits(&self) -> Option<u64> {
        self.estimated_cost_microunits
    }
    /// Returns actual cost in microunits.
    #[must_use]
    pub const fn actual_cost_microunits(&self) -> Option<u64> {
        self.actual_cost_microunits
    }
    /// Borrows namespaced provider-specific units.
    #[must_use]
    pub const fn provider_units(&self) -> Option<&JsonObject> {
        self.provider_units.as_ref()
    }
}

impl fmt::Debug for Usage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Usage")
            .field("input_tokens", &self.input_tokens())
            .field("output_tokens", &self.output_tokens())
            .finish_non_exhaustive()
    }
}

/// A complete canonical completion response.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmResponse {
    schema_version: SchemaVersion,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    stop_reason: Option<String>,
    output: Vec<LlmOutputPart>,
    selected_candidate_index: Option<u32>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<Candidate>")]
    candidates: Option<Vec<Candidate>>,
    usage: Usage,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "Vec<String>")]
    warnings: Option<Vec<String>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_non_null",
        skip_serializing_if = "Option::is_none"
    )]
    #[schemars(with = "JsonObject")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmResponseWire {
    schema_version: SchemaVersion,
    request_id: LlmRequestId,
    response_id: String,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    provider: String,
    model: String,
    status: CompletionStatus,
    stop_reason: Option<String>,
    output: Vec<LlmOutputPart>,
    selected_candidate_index: Option<u32>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    candidates: Option<Vec<Candidate>>,
    usage: Usage,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    warnings: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_non_null")]
    provider_metadata: Option<JsonObject>,
    created_at: UtcTimestamp,
}

impl<'de> Deserialize<'de> for LlmResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LlmResponseWire::deserialize(deserializer)?;
        let response = Self {
            schema_version: wire.schema_version,
            request_id: wire.request_id,
            response_id: wire.response_id,
            provider_response_id: wire.provider_response_id,
            provider_request_id: wire.provider_request_id,
            provider: wire.provider,
            model: wire.model,
            status: wire.status,
            stop_reason: wire.stop_reason,
            output: wire.output,
            selected_candidate_index: wire.selected_candidate_index,
            candidates: wire.candidates,
            usage: wire.usage,
            warnings: wire.warnings,
            provider_metadata: wire.provider_metadata,
            created_at: wire.created_at,
        };
        response.validate().map_err(D::Error::custom)?;
        Ok(response)
    }
}

impl LlmResponse {
    /// Creates a completion response with every required fixed-schema field.
    ///
    /// The creation instant is normalized to UTC.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when an identity, name, stop reason, or nested output part is invalid.
    #[expect(
        clippy::too_many_arguments,
        reason = "the canonical response retains every independent provider identity"
    )]
    pub fn new(
        request_id: impl Into<LlmRequestId>,
        response_id: String,
        provider: String,
        model: String,
        status: CompletionStatus,
        stop_reason: Option<String>,
        output: Vec<LlmOutputPart>,
        usage: Usage,
        created_at: OffsetDateTime,
    ) -> Result<Self, ContractError> {
        let response = Self {
            schema_version: SchemaVersion::CURRENT,
            request_id: request_id.into(),
            response_id,
            provider_response_id: None,
            provider_request_id: None,
            provider,
            model,
            status,
            stop_reason,
            output,
            selected_candidate_index: None,
            candidates: None,
            usage,
            warnings: None,
            provider_metadata: None,
            created_at: UtcTimestamp::new(created_at),
        };
        response.validate()?;
        Ok(response)
    }

    /// Adds provider-native response and transport request identifiers.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] when a supplied identifier is invalid.
    pub fn with_provider_ids(
        mut self,
        provider_response_id: Option<String>,
        provider_request_id: Option<String>,
    ) -> Result<Self, ContractError> {
        if let Some(id) = provider_response_id.as_deref() {
            validate_identifier(id)?;
        }
        if let Some(id) = provider_request_id.as_deref() {
            validate_identifier(id)?;
        }
        self.provider_response_id = provider_response_id;
        self.provider_request_id = provider_request_id;
        Ok(self)
    }

    /// Adds every retained candidate and the selected/default candidate index.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for duplicate indices, a missing selected candidate, or selected output mismatch.
    pub fn with_candidates(
        mut self,
        selected_candidate_index: Option<u32>,
        candidates: Vec<Candidate>,
    ) -> Result<Self, ContractError> {
        self.selected_candidate_index = selected_candidate_index;
        self.candidates = Some(candidates);
        self.validate_candidates()?;
        Ok(self)
    }

    /// Adds ordered warnings and deterministic provider metadata.
    #[must_use]
    pub fn with_metadata(
        mut self,
        warnings: Option<Vec<String>>,
        provider_metadata: Option<JsonObject>,
    ) -> Self {
        self.warnings = warnings;
        self.provider_metadata = provider_metadata;
        self
    }
    /// Returns the fixed schema version.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }
    /// Borrows the original request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &LlmRequestId {
        &self.request_id
    }
    /// Borrows the stable canonical response identifier.
    #[must_use]
    pub fn response_id(&self) -> &str {
        &self.response_id
    }
    /// Borrows the provider-native response identifier.
    #[must_use]
    pub fn provider_response_id(&self) -> Option<&str> {
        self.provider_response_id.as_deref()
    }
    /// Borrows the provider transport request identifier.
    #[must_use]
    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }
    /// Borrows the provider identity.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Borrows the provider model identity.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Returns response status.
    #[must_use]
    pub const fn status(&self) -> CompletionStatus {
        self.status
    }
    /// Borrows the optional stop reason.
    #[must_use]
    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }
    /// Borrows ordered selected/default output.
    #[must_use]
    pub fn output(&self) -> &[LlmOutputPart] {
        &self.output
    }
    /// Iterates directly over plaintext from top-level text output parts.
    pub fn text(&self) -> impl Iterator<Item = &str> {
        self.output.iter().filter_map(LlmOutputPart::as_text)
    }
    /// Returns the optional selected candidate index.
    #[must_use]
    pub const fn selected_candidate_index(&self) -> Option<u32> {
        self.selected_candidate_index
    }
    /// Borrows optional ordered provider candidates.
    #[must_use]
    pub fn candidates(&self) -> Option<&[Candidate]> {
        self.candidates.as_deref()
    }
    /// Borrows comprehensive usage.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }
    /// Borrows optional ordered warnings.
    #[must_use]
    pub fn warnings(&self) -> Option<&[String]> {
        self.warnings.as_deref()
    }
    /// Borrows optional deterministic provider metadata.
    #[must_use]
    pub const fn provider_metadata(&self) -> Option<&JsonObject> {
        self.provider_metadata.as_ref()
    }
    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> UtcTimestamp {
        self.created_at
    }

    /// Checks all canonical response invariants recursively.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ContractError`] for the first invalid invariant.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_identifier(&self.response_id)?;
        if let Some(id) = self.provider_response_id() {
            validate_identifier(id)?;
        }
        if let Some(id) = self.provider_request_id() {
            validate_identifier(id)?;
        }
        validate_name(&self.provider)?;
        validate_name(&self.model)?;
        if let Some(stop_reason) = self.stop_reason() {
            validate_name(stop_reason)?;
        }
        self.output.iter().try_for_each(LlmOutputPart::validate)?;
        self.validate_candidates()
    }

    fn validate_candidates(&self) -> Result<(), ContractError> {
        let Some(candidates) = &self.candidates else {
            return if self.selected_candidate_index.is_some() {
                Err(ContractError::SelectedCandidateMissing)
            } else {
                Ok(())
            };
        };
        let mut indices = BTreeSet::new();
        for candidate in candidates {
            candidate.validate()?;
            if !indices.insert(candidate.index()) {
                return Err(ContractError::DuplicateCandidateIndex);
            }
        }
        if let Some(selected_index) = self.selected_candidate_index {
            let selected = candidates
                .iter()
                .find(|candidate| candidate.index() == selected_index)
                .ok_or(ContractError::SelectedCandidateMissing)?;
            if selected.output() != self.output {
                return Err(ContractError::SelectedOutputMismatch);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for LlmResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmResponse")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field("output_parts", &self.output.len())
            .field(
                "candidate_count",
                &self.candidates.as_ref().map_or(0, Vec::len),
            )
            .finish_non_exhaustive()
    }
}
