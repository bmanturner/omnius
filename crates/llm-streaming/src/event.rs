use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    num::{NonZeroU64, NonZeroUsize},
};

use omnius_llm_core::{
    AudioOutputPart, CitationOutputPart, FileOutputPart, ImageOutputPart, LlmRequestId,
    ReasoningOutputPart, SchemaVersion, StructuredOutputPart, StructuredValidation,
    ToolCallOutputPart, ToolResultOutputPart, Usage, VideoOutputPart,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

/// Fixed request-local ceilings for stream state retained by the assembler.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    max_events: NonZeroU64,
    max_parts: NonZeroUsize,
    max_public_items: NonZeroUsize,
    max_text_bytes: NonZeroUsize,
    max_event_bytes: NonZeroUsize,
}

impl StreamLimits {
    /// Creates positive stream-state ceilings.
    #[must_use]
    pub const fn new(
        max_events: NonZeroU64,
        max_parts: NonZeroUsize,
        max_public_items: NonZeroUsize,
        max_text_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            max_events,
            max_parts,
            max_public_items,
            max_text_bytes,
            max_event_bytes: max_text_bytes,
        }
    }

    /// Returns the maximum event count including the terminal event.
    #[must_use]
    pub const fn max_events(self) -> u64 {
        self.max_events.get()
    }

    /// Returns the maximum distinct part count.
    #[must_use]
    pub const fn max_parts(self) -> usize {
        self.max_parts.get()
    }

    /// Returns the maximum accepted public-content item count.
    #[must_use]
    pub const fn max_public_items(self) -> usize {
        self.max_public_items.get()
    }

    /// Returns the maximum accumulated text bytes across the request.
    #[must_use]
    pub const fn max_text_bytes(self) -> usize {
        self.max_text_bytes.get()
    }

    /// Replaces the serialized byte ceiling for any one stream event.
    #[must_use]
    pub const fn with_max_event_bytes(mut self, max_event_bytes: NonZeroUsize) -> Self {
        self.max_event_bytes = max_event_bytes;
        self
    }

    /// Returns the maximum serialized bytes in any one stream event.
    #[must_use]
    pub const fn max_event_bytes(self) -> usize {
        self.max_event_bytes.get()
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self::new(
            NonZeroU64::new(65_536).unwrap_or(NonZeroU64::MIN),
            NonZeroUsize::new(1_024).unwrap_or(NonZeroUsize::MIN),
            NonZeroUsize::new(4_096).unwrap_or(NonZeroUsize::MIN),
            NonZeroUsize::new(16 * 1_024 * 1_024).unwrap_or(NonZeroUsize::MIN),
        )
        .with_max_event_bytes(NonZeroUsize::new(32 * 1_024 * 1_024).unwrap_or(NonZeroUsize::MIN))
    }
}

/// The canonical kind announced by a part-start event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamPartKind {
    /// Incremental assistant text.
    Text,
    /// One locally validated complete structured value.
    Structured,
    /// One provider tool call.
    ToolCall,
    /// One application tool result.
    ToolResult,
    /// Provider-sanctioned summary, signature, or encrypted reasoning state.
    SafeReasoning,
    /// Image, audio, video, or file output.
    Media,
    /// A citation record.
    Citation,
}

/// An incomplete provider tool-call field.
///
/// This type intentionally has no conversion to `serde_json::Value` or
/// [`ToolCallOutputPart`]. Only the distinct complete event can become executable.
#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", tag = "field", content = "value")]
pub enum StreamToolCallDelta {
    /// A complete provider-emitted tool name field.
    Name(String),
    /// An incomplete JSON argument byte fragment.
    ArgumentsFragment(String),
}

impl fmt::Debug for StreamToolCallDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(value) => formatter
                .debug_struct("Name")
                .field("byte_count", &value.len())
                .finish_non_exhaustive(),
            Self::ArgumentsFragment(value) => formatter
                .debug_struct("ArgumentsFragment")
                .field("byte_count", &value.len())
                .finish_non_exhaustive(),
        }
    }
}

/// A canonical media payload retained without provider-specific wrappers.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "media_type", content = "part")]
pub enum StreamMedia {
    /// Image output.
    Image(ImageOutputPart),
    /// Audio output.
    Audio(AudioOutputPart),
    /// Video output.
    Video(VideoOutputPart),
    /// File output.
    File(FileOutputPart),
}

impl StreamMedia {
    fn id(&self) -> &str {
        match self {
            Self::Image(part) => part.id(),
            Self::Audio(part) => part.id(),
            Self::Video(part) => part.id(),
            Self::File(part) => part.id(),
        }
    }
}

/// A completed locally validated structured part.
///
/// Construction rejects `Invalid` and `NotRequested`, so a stream complete event
/// cannot carry unvalidated structured data.
#[derive(Clone, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ValidatedStructuredComplete(StructuredOutputPart);

impl ValidatedStructuredComplete {
    /// Validates and owns one completed structured part.
    ///
    /// # Errors
    ///
    /// Returns [`StreamInvariantError::StructuredValueNotValidated`] unless the
    /// canonical validation state is `Valid`.
    pub fn try_from_part(part: StructuredOutputPart) -> Result<Self, StreamInvariantError> {
        if part.validation() != StructuredValidation::Valid {
            return Err(StreamInvariantError::StructuredValueNotValidated);
        }
        Ok(Self(part))
    }

    /// Copies a validated completed part from an integration-owned final value.
    ///
    /// # Errors
    ///
    /// Returns [`StreamInvariantError::StructuredValueNotValidated`] if an
    /// implementation violates the trait contract.
    pub fn from_final(
        final_value: &impl ValidatedStructuredFinal,
    ) -> Result<Self, StreamInvariantError> {
        Self::try_from_part(final_value.validated_structured_part().clone())
    }

    /// Borrows the canonical validated structured part.
    #[must_use]
    pub const fn part(&self) -> &StructuredOutputPart {
        &self.0
    }

    /// Consumes the wrapper and returns the canonical part.
    #[must_use]
    pub fn into_part(self) -> StructuredOutputPart {
        self.0
    }
}

impl fmt::Debug for ValidatedStructuredComplete {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedStructuredComplete")
            .field("part_id", &self.0.id())
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for ValidatedStructuredComplete {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let part = StructuredOutputPart::deserialize(deserializer)?;
        Self::try_from_part(part).map_err(D::Error::custom)
    }
}

/// Narrow seam implemented by structured-output runtimes after local validation.
///
/// Implementations must return only a complete [`StructuredOutputPart`] whose
/// validation state is [`StructuredValidation::Valid`]. The streaming boundary
/// checks that postcondition rather than trusting the implementation.
pub trait ValidatedStructuredFinal {
    /// Borrows the locally validated completed structured part.
    fn validated_structured_part(&self) -> &StructuredOutputPart;
}

impl ValidatedStructuredFinal for ValidatedStructuredComplete {
    fn validated_structured_part(&self) -> &StructuredOutputPart {
        self.part()
    }
}

/// Media-independent public content retained at stream termination.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "content_type", content = "content")]
pub enum AcceptedPublicContent {
    /// Accumulated text for one part, including usable interrupted text.
    Text {
        /// Stable text-part identity.
        part_id: String,
        /// Accepted text in provider order.
        text: String,
    },
    /// A complete validated structured value.
    Structured(ValidatedStructuredComplete),
    /// A complete provider tool call and its stream correlation identity.
    ToolCall {
        /// Request-local provider correlation identity.
        correlation_id: String,
        /// Complete canonical tool call.
        part: ToolCallOutputPart,
    },
    /// A complete application tool result.
    ToolResult(ToolResultOutputPart),
    /// Safe provider-sanctioned reasoning state.
    SafeReasoning(ReasoningOutputPart),
    /// Canonical media output.
    Media(StreamMedia),
    /// Canonical citation output.
    Citation(CitationOutputPart),
}

/// Stable warning categories that never retain provider text.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamWarningCode {
    /// A provider extension was intentionally omitted.
    ProviderExtensionOmitted,
    /// Private chain-of-thought content was intentionally omitted.
    PrivateReasoningOmitted,
    /// Safe text coalescing was applied before sequencing.
    TextCoalesced,
    /// Usage is estimated rather than final.
    EstimatedUsage,
}

/// The budget dimension that terminated streaming.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamBudgetDimension {
    /// Model turn count.
    ModelTurns,
    /// Tool call count.
    ToolCalls,
    /// Wall-clock duration.
    WallClock,
    /// Token count.
    Tokens,
    /// Cost ceiling.
    Cost,
    /// Concurrent work.
    Concurrency,
}

/// Redacted failure categories for a terminal failed stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamFailureKind {
    /// Provider protocol normalization failed.
    Protocol,
    /// Provider transport failed.
    Transport,
    /// Internal orchestration failed.
    Internal,
}

/// Redacted causes for a usable partial interruption.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamInterruption {
    /// Provider transport ended after public content was accepted.
    Transport,
    /// Provider protocol failed after public content was accepted.
    Protocol,
    /// The consumer disconnected after public content was accepted.
    ConsumerDisconnected,
    /// An inherited deadline elapsed after public content was accepted.
    Deadline,
}

/// Exactly one explicit terminal state for a canonical stream.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "detail")]
pub enum StreamTerminalState {
    /// The response completed successfully.
    Completed,
    /// The provider refused the request.
    ProviderRefused,
    /// Safety policy refused the request.
    SafetyRefused,
    /// Complete structured data failed local validation.
    InvalidStructuredData,
    /// Tool execution failed with a redacted error.
    ToolExecutionFailed,
    /// One deterministic loop budget was exhausted.
    BudgetExhausted(StreamBudgetDimension),
    /// Cooperative cancellation won.
    Cancelled,
    /// The stream failed before retaining usable partial content.
    Failed(StreamFailureKind),
    /// The stream ended incompletely while retaining accepted public content.
    PartialInterrupted(StreamInterruption),
}

/// Terminal state plus the ordered public-content snapshot accepted before it.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamTerminal {
    state: StreamTerminalState,
    accepted_public_content: Vec<AcceptedPublicContent>,
}

impl StreamTerminal {
    /// Returns the explicit terminal state.
    #[must_use]
    pub const fn state(&self) -> StreamTerminalState {
        self.state
    }

    /// Borrows accepted public content in first-appearance order.
    #[must_use]
    pub fn accepted_public_content(&self) -> &[AcceptedPublicContent] {
        &self.accepted_public_content
    }
}

impl fmt::Debug for StreamTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamTerminal")
            .field("state", &self.state)
            .field("accepted_public_items", &self.accepted_public_content.len())
            .finish()
    }
}

/// Non-terminal input accepted by [`LlmStreamAssembler::emit`].
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
pub enum LlmStreamEventData {
    /// Announces one canonical response identity.
    ResponseStart {
        /// Stable response identity.
        response_id: String,
    },
    /// Announces one stable typed output part.
    PartStart {
        /// Stable part identity.
        part_id: String,
        /// Canonical part kind.
        kind: StreamPartKind,
    },
    /// Emits an incremental text fragment for an open text part.
    TextDelta {
        /// Stable part identity.
        part_id: String,
        /// Nonempty provider-order text fragment.
        text: String,
    },
    /// Emits one locally validated complete structured value.
    StructuredComplete(ValidatedStructuredComplete),
    /// Emits one incomplete tool-call field that is never executable.
    ToolCallDelta {
        /// Stable open tool-call part identity.
        part_id: String,
        /// Request-local correlation identity.
        correlation_id: String,
        /// Typed incomplete field.
        delta: StreamToolCallDelta,
    },
    /// Emits one complete canonical tool call.
    ToolCallComplete {
        /// Request-local correlation identity shared with preceding deltas.
        correlation_id: String,
        /// Complete canonical call.
        part: ToolCallOutputPart,
    },
    /// Emits one complete application tool result.
    ToolResultComplete(ToolResultOutputPart),
    /// Emits one provider-sanctioned safe reasoning representation.
    SafeReasoning(ReasoningOutputPart),
    /// Emits one canonical media value.
    Media(StreamMedia),
    /// Emits one canonical citation.
    Citation(CitationOutputPart),
    /// Replaces the current cumulative usage snapshot.
    Usage(Usage),
    /// Emits a stable content-free warning.
    Warning(StreamWarningCode),
    /// Closes one open part.
    PartComplete {
        /// Stable part identity.
        part_id: String,
    },
}

/// The complete event payload including its single terminal variant.
// Boxing the hot non-terminal variant would add one heap allocation per event.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
pub enum LlmStreamPayload {
    /// A non-terminal ordered stream event.
    Event(LlmStreamEventData),
    /// The sole terminal event.
    Terminal(StreamTerminal),
}
#[derive(Serialize)]
#[serde(rename_all = "snake_case", tag = "event", content = "data")]
enum LlmStreamPayloadRef<'a> {
    Event(&'a LlmStreamEventData),
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct LlmStreamEventRef<'a> {
    schema_version: SchemaVersion,
    request_id: &'a LlmRequestId,
    sequence: u64,
    payload: LlmStreamPayloadRef<'a>,
}

/// One versioned, request-correlated, strictly sequenced canonical stream event.
#[derive(Clone, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmStreamEvent {
    schema_version: SchemaVersion,
    request_id: LlmRequestId,
    sequence: u64,
    payload: LlmStreamPayload,
}

impl LlmStreamEvent {
    /// Returns the fixed canonical schema version.
    #[must_use]
    pub const fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    /// Borrows the request correlation identity.
    #[must_use]
    pub const fn request_id(&self) -> &LlmRequestId {
        &self.request_id
    }

    /// Returns the request-local sequence, beginning at zero.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Borrows the typed payload.
    #[must_use]
    pub const fn payload(&self) -> &LlmStreamPayload {
        &self.payload
    }

    /// Borrows the terminal value only for the terminal event.
    #[must_use]
    pub const fn terminal(&self) -> Option<&StreamTerminal> {
        match &self.payload {
            LlmStreamPayload::Terminal(terminal) => Some(terminal),
            LlmStreamPayload::Event(_) => None,
        }
    }
}

impl fmt::Debug for LlmStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmStreamEvent")
            .field("schema_version", &self.schema_version)
            .field("request_id", &self.request_id)
            .field("sequence", &self.sequence)
            .field(
                "terminal",
                &matches!(&self.payload, LlmStreamPayload::Terminal(_)),
            )
            .finish_non_exhaustive()
    }
}

/// Request-local state machine that is the sole allocator of canonical sequence numbers.
#[derive(Clone)]
pub struct LlmStreamAssembler {
    request_id: LlmRequestId,
    limits: StreamLimits,
    next_sequence: u64,
    response_started: bool,
    terminal: bool,
    parts: BTreeMap<String, PartState>,
    tool_correlations: BTreeMap<String, String>,
    tool_names: BTreeMap<String, String>,
    tool_call_ids: BTreeSet<String>,
    completed_tool_correlations: BTreeSet<String>,
    accepted: Vec<AcceptedPublicContent>,
    text_indices: BTreeMap<String, usize>,
    text_bytes: usize,
    accepted_serialized_bytes: usize,
}

impl LlmStreamAssembler {
    /// Creates an empty request-local state machine.
    #[must_use]
    pub fn new(request_id: LlmRequestId, limits: StreamLimits) -> Self {
        Self {
            request_id,
            limits,
            next_sequence: 0,
            response_started: false,
            terminal: false,
            parts: BTreeMap::new(),
            tool_correlations: BTreeMap::new(),
            tool_names: BTreeMap::new(),
            tool_call_ids: BTreeSet::new(),
            completed_tool_correlations: BTreeSet::new(),
            accepted: Vec::new(),
            text_indices: BTreeMap::new(),
            text_bytes: 0,
            accepted_serialized_bytes: 2,
        }
    }

    /// Validates and sequences one non-terminal event.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`StreamInvariantError`] for lifecycle, part,
    /// correlation, validation, or fixed-bound violations.
    pub fn emit(
        &mut self,
        data: LlmStreamEventData,
    ) -> Result<LlmStreamEvent, StreamInvariantError> {
        if self.terminal {
            return Err(StreamInvariantError::EventAfterTerminal);
        }
        self.ensure_nonterminal_slot()?;
        if !self.nonterminal_event_fits(&data) {
            return Err(StreamInvariantError::EventPayloadLimitExceeded);
        }
        let accepted_serialized_bytes = self.prospective_accepted_bytes(&data)?;
        self.ensure_terminal_snapshot_fits(accepted_serialized_bytes)?;
        self.apply(&data)?;
        self.accepted_serialized_bytes = accepted_serialized_bytes;
        let event = self.event(LlmStreamPayload::Event(data));
        self.advance_sequence()?;
        Ok(event)
    }

    /// Emits the sole terminal event with an assembler-owned public snapshot.
    ///
    /// Non-partial terminal states require every started part to be complete.
    /// Partial interruption deliberately retains any accepted content from open
    /// parts.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`StreamInvariantError`] if the response never
    /// started, a terminal already exists, parts remain open for a non-partial
    /// terminal, no usable content exists for partial interruption, or an event
    /// bound is exhausted.
    pub fn terminate(
        &mut self,
        state: StreamTerminalState,
    ) -> Result<LlmStreamEvent, StreamInvariantError> {
        if self.terminal {
            return Err(StreamInvariantError::DuplicateTerminal);
        }
        self.ensure_event_slot()?;
        if !self.response_started {
            return Err(StreamInvariantError::ResponseNotStarted);
        }
        if matches!(state, StreamTerminalState::PartialInterrupted(_)) {
            if self.accepted.is_empty() {
                return Err(StreamInvariantError::PartialWithoutPublicContent);
            }
        } else if self.parts.values().any(|part| !part.complete) {
            return Err(StreamInvariantError::OpenPartAtTerminal);
        }

        let terminal = StreamTerminal {
            state,
            accepted_public_content: self.accepted.clone(),
        };
        let event = self.event(LlmStreamPayload::Terminal(terminal));
        if !serialized_fits(&event, self.limits.max_event_bytes()) {
            return Err(StreamInvariantError::EventPayloadLimitExceeded);
        }
        self.terminal = true;
        self.advance_sequence()?;
        Ok(event)
    }

    /// Confirms that exactly one terminal event has been emitted.
    ///
    /// # Errors
    ///
    /// Returns [`StreamInvariantError::MissingTerminal`] before termination.
    pub fn finish(&self) -> Result<(), StreamInvariantError> {
        if self.terminal {
            Ok(())
        } else {
            Err(StreamInvariantError::MissingTerminal)
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&mut self, data: &LlmStreamEventData) -> Result<(), StreamInvariantError> {
        if let LlmStreamEventData::ResponseStart { response_id } = data {
            if self.response_started || self.next_sequence != 0 {
                return Err(StreamInvariantError::DuplicateResponseStart);
            }
            validate_id(response_id)?;
            self.response_started = true;
            return Ok(());
        }
        if !self.response_started {
            return Err(StreamInvariantError::ResponseNotStarted);
        }

        match data {
            LlmStreamEventData::ResponseStart { .. } => {
                Err(StreamInvariantError::DuplicateResponseStart)
            }
            LlmStreamEventData::PartStart { part_id, kind } => {
                validate_id(part_id)?;
                if self.parts.contains_key(part_id) {
                    return Err(StreamInvariantError::DuplicatePart);
                }
                if self.parts.len() >= self.limits.max_parts() {
                    return Err(StreamInvariantError::PartLimitExceeded);
                }
                self.parts.insert(
                    part_id.clone(),
                    PartState {
                        kind: *kind,
                        complete: false,
                        value_emitted: false,
                    },
                );
                Ok(())
            }
            LlmStreamEventData::TextDelta { part_id, text } => {
                self.require_open_kind(part_id, StreamPartKind::Text)?;
                if text.is_empty() {
                    return Err(StreamInvariantError::EmptyTextDelta);
                }
                let Some(next_text_bytes) = self.text_bytes.checked_add(text.len()) else {
                    return Err(StreamInvariantError::TextLimitExceeded);
                };
                if next_text_bytes > self.limits.max_text_bytes() {
                    return Err(StreamInvariantError::TextLimitExceeded);
                }
                if let Some(index) = self.text_indices.get(part_id).copied() {
                    let AcceptedPublicContent::Text {
                        text: accumulated, ..
                    } = &mut self.accepted[index]
                    else {
                        return Err(StreamInvariantError::InvalidInternalState);
                    };
                    self.text_bytes = next_text_bytes;
                    accumulated.push_str(text);
                } else {
                    self.ensure_public_item_slot()?;
                    self.text_bytes = next_text_bytes;
                    let index = self.accepted.len();
                    self.accepted.push(AcceptedPublicContent::Text {
                        part_id: part_id.clone(),
                        text: text.clone(),
                    });
                    self.text_indices.insert(part_id.clone(), index);
                }
                Ok(())
            }
            LlmStreamEventData::StructuredComplete(part) => self.complete_public_part(
                part.part().id(),
                StreamPartKind::Structured,
                AcceptedPublicContent::Structured(part.clone()),
            ),
            LlmStreamEventData::ToolCallDelta {
                part_id,
                correlation_id,
                delta,
            } => {
                self.require_pending_value_kind(part_id, StreamPartKind::ToolCall)?;
                if self.completed_tool_correlations.contains(correlation_id) {
                    return Err(StreamInvariantError::DuplicateToolCallIdentity);
                }
                validate_id(correlation_id)?;
                if let StreamToolCallDelta::Name(name) = delta {
                    validate_id(name)?;
                    if self
                        .tool_names
                        .get(correlation_id)
                        .is_some_and(|existing| existing != name)
                    {
                        return Err(StreamInvariantError::CorrelationMismatch);
                    }
                }
                if self
                    .tool_correlations
                    .get(correlation_id)
                    .is_some_and(|existing| existing != part_id)
                {
                    return Err(StreamInvariantError::CorrelationMismatch);
                }
                self.tool_correlations
                    .entry(correlation_id.clone())
                    .or_insert_with(|| part_id.clone());
                if let StreamToolCallDelta::Name(name) = delta {
                    self.tool_names
                        .entry(correlation_id.clone())
                        .or_insert_with(|| name.clone());
                }
                Ok(())
            }
            LlmStreamEventData::ToolCallComplete {
                correlation_id,
                part,
            } => {
                self.require_pending_value_kind(part.id(), StreamPartKind::ToolCall)?;
                validate_id(correlation_id)?;
                if self.completed_tool_correlations.contains(correlation_id)
                    || self.tool_call_ids.contains(part.call_id())
                {
                    return Err(StreamInvariantError::DuplicateToolCallIdentity);
                }
                if self
                    .tool_correlations
                    .get(correlation_id)
                    .is_some_and(|part_id| part_id != part.id())
                    || self
                        .tool_names
                        .get(correlation_id)
                        .is_some_and(|name| name != part.name())
                {
                    return Err(StreamInvariantError::CorrelationMismatch);
                }
                self.ensure_public_item_slot()?;
                self.tool_correlations
                    .entry(correlation_id.clone())
                    .or_insert_with(|| part.id().to_owned());
                self.completed_tool_correlations
                    .insert(correlation_id.clone());
                self.tool_call_ids.insert(part.call_id().to_owned());
                self.accepted.push(AcceptedPublicContent::ToolCall {
                    correlation_id: correlation_id.clone(),
                    part: part.clone(),
                });
                self.mark_value_emitted(part.id())?;
                Ok(())
            }
            LlmStreamEventData::ToolResultComplete(part) => {
                self.require_pending_value_kind(part.id(), StreamPartKind::ToolResult)?;
                if !self.tool_call_ids.contains(part.call_id()) {
                    return Err(StreamInvariantError::UnknownToolCallIdentity);
                }
                self.push_public(AcceptedPublicContent::ToolResult(part.clone()))?;
                self.mark_value_emitted(part.id())
            }
            LlmStreamEventData::SafeReasoning(part) => self.complete_public_part(
                part.id(),
                StreamPartKind::SafeReasoning,
                AcceptedPublicContent::SafeReasoning(part.clone()),
            ),
            LlmStreamEventData::Media(media) => self.complete_public_part(
                media.id(),
                StreamPartKind::Media,
                AcceptedPublicContent::Media(media.clone()),
            ),
            LlmStreamEventData::Citation(part) => self.complete_public_part(
                part.id(),
                StreamPartKind::Citation,
                AcceptedPublicContent::Citation(part.clone()),
            ),
            LlmStreamEventData::Usage(_) | LlmStreamEventData::Warning(_) => Ok(()),
            LlmStreamEventData::PartComplete { part_id } => {
                let Some(part) = self.parts.get_mut(part_id) else {
                    return Err(StreamInvariantError::UnknownPart);
                };
                if part.complete {
                    return Err(StreamInvariantError::DuplicatePartComplete);
                }
                if part.kind != StreamPartKind::Text && !part.value_emitted {
                    return Err(StreamInvariantError::MissingPartValue);
                }
                part.complete = true;
                Ok(())
            }
        }
    }

    fn require_open_kind(
        &self,
        part_id: &str,
        expected: StreamPartKind,
    ) -> Result<(), StreamInvariantError> {
        let Some(part) = self.parts.get(part_id) else {
            return Err(StreamInvariantError::UnknownPart);
        };
        if part.complete {
            return Err(StreamInvariantError::EventAfterPartComplete);
        }
        if part.kind != expected {
            return Err(StreamInvariantError::PartKindMismatch);
        }
        Ok(())
    }
    fn require_pending_value_kind(
        &self,
        part_id: &str,
        expected: StreamPartKind,
    ) -> Result<(), StreamInvariantError> {
        self.require_open_kind(part_id, expected)?;
        if self
            .parts
            .get(part_id)
            .is_some_and(|part| part.value_emitted)
        {
            Err(StreamInvariantError::DuplicatePartValue)
        } else {
            Ok(())
        }
    }

    fn complete_public_part(
        &mut self,
        part_id: &str,
        expected: StreamPartKind,
        content: AcceptedPublicContent,
    ) -> Result<(), StreamInvariantError> {
        self.require_pending_value_kind(part_id, expected)?;
        self.push_public(content)?;
        self.mark_value_emitted(part_id)
    }

    fn mark_value_emitted(&mut self, part_id: &str) -> Result<(), StreamInvariantError> {
        let Some(part) = self.parts.get_mut(part_id) else {
            return Err(StreamInvariantError::InvalidInternalState);
        };
        part.value_emitted = true;
        Ok(())
    }

    fn push_public(&mut self, content: AcceptedPublicContent) -> Result<(), StreamInvariantError> {
        self.ensure_public_item_slot()?;
        self.accepted.push(content);
        Ok(())
    }

    fn ensure_public_item_slot(&self) -> Result<(), StreamInvariantError> {
        if self.accepted.len() >= self.limits.max_public_items() {
            Err(StreamInvariantError::PublicContentLimitExceeded)
        } else {
            Ok(())
        }
    }
    fn ensure_nonterminal_slot(&self) -> Result<(), StreamInvariantError> {
        let terminal_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamInvariantError::EventLimitExceeded)?;
        if terminal_sequence >= self.limits.max_events() {
            Err(StreamInvariantError::EventLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn prospective_accepted_bytes(
        &self,
        data: &LlmStreamEventData,
    ) -> Result<usize, StreamInvariantError> {
        let added = match data {
            LlmStreamEventData::TextDelta { part_id, text } => {
                if self.text_indices.contains_key(part_id) {
                    serialized_size(text)
                        .and_then(|size| size.checked_sub(2))
                        .ok_or(StreamInvariantError::EventPayloadLimitExceeded)?
                } else {
                    let content = AcceptedPublicContent::Text {
                        part_id: part_id.clone(),
                        text: text.clone(),
                    };
                    self.new_public_item_bytes(&content)?
                }
            }
            LlmStreamEventData::StructuredComplete(part) => {
                self.new_public_item_bytes(&AcceptedPublicContent::Structured(part.clone()))?
            }
            LlmStreamEventData::ToolCallComplete {
                correlation_id,
                part,
            } => self.new_public_item_bytes(&AcceptedPublicContent::ToolCall {
                correlation_id: correlation_id.clone(),
                part: part.clone(),
            })?,
            LlmStreamEventData::ToolResultComplete(part) => {
                self.new_public_item_bytes(&AcceptedPublicContent::ToolResult(part.clone()))?
            }
            LlmStreamEventData::SafeReasoning(part) => {
                self.new_public_item_bytes(&AcceptedPublicContent::SafeReasoning(part.clone()))?
            }
            LlmStreamEventData::Media(media) => {
                self.new_public_item_bytes(&AcceptedPublicContent::Media(media.clone()))?
            }
            LlmStreamEventData::Citation(part) => {
                self.new_public_item_bytes(&AcceptedPublicContent::Citation(part.clone()))?
            }
            _ => 0,
        };
        self.accepted_serialized_bytes
            .checked_add(added)
            .ok_or(StreamInvariantError::EventPayloadLimitExceeded)
    }

    fn new_public_item_bytes(
        &self,
        content: &AcceptedPublicContent,
    ) -> Result<usize, StreamInvariantError> {
        let separator = usize::from(!self.accepted.is_empty());
        serialized_size(content)
            .and_then(|size| size.checked_add(separator))
            .ok_or(StreamInvariantError::EventPayloadLimitExceeded)
    }

    fn ensure_terminal_snapshot_fits(
        &self,
        accepted_serialized_bytes: usize,
    ) -> Result<(), StreamInvariantError> {
        let terminal_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamInvariantError::EventLimitExceeded)?;
        let terminal = LlmStreamEvent {
            schema_version: SchemaVersion::CURRENT,
            request_id: self.request_id.clone(),
            sequence: terminal_sequence,
            payload: LlmStreamPayload::Terminal(StreamTerminal {
                // This is the longest currently serialized terminal state and
                // therefore reserves enough space for every actual terminal.
                state: StreamTerminalState::PartialInterrupted(
                    StreamInterruption::ConsumerDisconnected,
                ),
                accepted_public_content: Vec::new(),
            }),
        };
        let empty_terminal_bytes =
            serialized_size(&terminal).ok_or(StreamInvariantError::EventPayloadLimitExceeded)?;
        let terminal_bytes = empty_terminal_bytes
            .checked_add(accepted_serialized_bytes.saturating_sub(2))
            .ok_or(StreamInvariantError::EventPayloadLimitExceeded)?;
        if terminal_bytes > self.limits.max_event_bytes() {
            Err(StreamInvariantError::EventPayloadLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn ensure_event_slot(&self) -> Result<(), StreamInvariantError> {
        if self.next_sequence >= self.limits.max_events() {
            Err(StreamInvariantError::EventLimitExceeded)
        } else {
            Ok(())
        }
    }
    fn nonterminal_event_fits(&self, data: &LlmStreamEventData) -> bool {
        serialized_fits(
            &LlmStreamEventRef {
                schema_version: SchemaVersion::CURRENT,
                request_id: &self.request_id,
                sequence: self.next_sequence,
                payload: LlmStreamPayloadRef::Event(data),
            },
            self.limits.max_event_bytes(),
        )
    }

    fn event(&self, payload: LlmStreamPayload) -> LlmStreamEvent {
        LlmStreamEvent {
            schema_version: SchemaVersion::CURRENT,
            request_id: self.request_id.clone(),
            sequence: self.next_sequence,
            payload,
        }
    }

    fn advance_sequence(&mut self) -> Result<(), StreamInvariantError> {
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(StreamInvariantError::EventLimitExceeded)?;
        Ok(())
    }
}

impl fmt::Debug for LlmStreamAssembler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LlmStreamAssembler")
            .field("request_id", &self.request_id)
            .field("next_sequence", &self.next_sequence)
            .field("response_started", &self.response_started)
            .field("terminal", &self.terminal)
            .field("part_count", &self.parts.len())
            .field("accepted_public_items", &self.accepted.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
struct PartState {
    kind: StreamPartKind,
    complete: bool,
    value_emitted: bool,
}

/// Validates externally decoded events by replaying the canonical state machine.
pub struct LlmStreamValidator {
    assembler: LlmStreamAssembler,
}

impl LlmStreamValidator {
    /// Creates a validator bound to one expected request identity.
    #[must_use]
    pub fn new(request_id: LlmRequestId, limits: StreamLimits) -> Self {
        Self {
            assembler: LlmStreamAssembler::new(request_id, limits),
        }
    }

    /// Validates one event without trusting its sequence or terminal snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`StreamInvariantError`] for version, request, sequence, lifecycle,
    /// correlation, snapshot, or bound violations.
    pub fn accept(&mut self, event: &LlmStreamEvent) -> Result<(), StreamInvariantError> {
        if event.schema_version != SchemaVersion::CURRENT {
            return Err(StreamInvariantError::UnsupportedSchemaVersion);
        }
        if event.request_id != self.assembler.request_id {
            return Err(StreamInvariantError::RequestCorrelationMismatch);
        }
        if event.sequence != self.assembler.next_sequence {
            return Err(StreamInvariantError::NonMonotonicSequence);
        }

        let mut candidate = self.assembler.clone();
        let expected = match &event.payload {
            LlmStreamPayload::Event(data) => candidate.emit(data.clone())?,
            LlmStreamPayload::Terminal(terminal) => candidate.terminate(terminal.state())?,
        };
        if &expected != event {
            return Err(StreamInvariantError::TerminalSnapshotMismatch);
        }
        self.assembler = candidate;
        Ok(())
    }

    /// Confirms exactly one terminal event was accepted.
    ///
    /// # Errors
    ///
    /// Returns [`StreamInvariantError::MissingTerminal`] before termination.
    pub fn finish(&self) -> Result<(), StreamInvariantError> {
        self.assembler.finish()
    }
}

impl fmt::Debug for LlmStreamValidator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("LlmStreamValidator")
            .field(&self.assembler)
            .finish()
    }
}

/// A fixed, content-free stream invariant violation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StreamInvariantError {
    /// The event schema version is unsupported.
    #[error("unsupported stream schema version")]
    UnsupportedSchemaVersion,
    /// An event request identity differs from the request-local stream identity.
    #[error("stream request correlation identity changed")]
    RequestCorrelationMismatch,
    /// An externally supplied sequence was not exactly the expected next value.
    #[error("stream sequence is not strictly monotonic")]
    NonMonotonicSequence,
    /// A non-start event arrived before response start.
    #[error("stream response has not started")]
    ResponseNotStarted,
    /// Response start occurred more than once or outside sequence zero.
    #[error("stream response start is duplicated")]
    DuplicateResponseStart,
    /// A stable stream identity was empty or excessive.
    #[error("stream identity is invalid")]
    InvalidIdentity,
    /// A part identity occurred more than once.
    #[error("stream part identity is duplicated")]
    DuplicatePart,
    /// An event referenced a part that never started.
    #[error("stream event references an unknown part")]
    UnknownPart,
    /// An event payload disagreed with the announced part kind.
    #[error("stream event disagrees with its announced part kind")]
    PartKindMismatch,
    /// A part received content after its completion event.
    #[error("stream part received content after completion")]
    EventAfterPartComplete,
    /// A part completion occurred more than once.
    #[error("stream part completion is duplicated")]
    DuplicatePartComplete,
    /// A typed part closed before emitting its required complete value.
    #[error("stream part completed without its required value")]
    MissingPartValue,
    /// A typed part emitted its complete value more than once.
    #[error("stream part emitted more than one complete value")]
    DuplicatePartValue,
    /// One text delta was empty.
    #[error("stream text delta is empty")]
    EmptyTextDelta,
    /// Structured output was not locally validated as complete and valid.
    #[error("structured stream value is not locally validated")]
    StructuredValueNotValidated,
    /// A tool correlation identity changed part or name.
    #[error("stream tool correlation identity is inconsistent")]
    CorrelationMismatch,
    /// A completed tool-call identity occurred more than once.
    #[error("stream tool call identity is duplicated")]
    DuplicateToolCallIdentity,
    /// A second terminal event was attempted.
    #[error("stream terminal event is duplicated")]
    DuplicateTerminal,
    /// An event was attempted after terminal state.
    #[error("stream event occurred after terminal state")]
    EventAfterTerminal,
    /// A non-partial terminal was attempted with an open part.
    #[error("stream terminal event has an open part")]
    OpenPartAtTerminal,
    /// A partial interruption had no accepted public content to retain.
    #[error("partial stream interruption has no accepted public content")]
    PartialWithoutPublicContent,
    /// The stream ended without a terminal event.
    #[error("stream terminal event is missing")]
    MissingTerminal,
    /// An externally supplied terminal public snapshot was not canonical.
    #[error("stream terminal public snapshot is inconsistent")]
    TerminalSnapshotMismatch,
    /// The fixed event ceiling was exhausted.
    #[error("stream event ceiling was exceeded")]
    EventLimitExceeded,
    /// The fixed part ceiling was exhausted.
    #[error("stream part ceiling was exceeded")]
    PartLimitExceeded,
    /// The fixed accepted-public-content ceiling was exhausted.
    #[error("stream public content ceiling was exceeded")]
    PublicContentLimitExceeded,
    /// The fixed accumulated text byte ceiling was exhausted.
    #[error("stream text byte ceiling was exceeded")]
    TextLimitExceeded,
    /// One event exceeded the configured serialized payload byte ceiling.
    #[error("stream event payload byte ceiling was exceeded")]
    EventPayloadLimitExceeded,
    /// A tool result referenced no completed request-local tool call.
    #[error("stream tool result references an unknown tool call identity")]
    UnknownToolCallIdentity,
    /// An impossible private state inconsistency was detected without panicking.
    #[error("stream state is inconsistent")]
    InvalidInternalState,
}

fn validate_id(value: &str) -> Result<(), StreamInvariantError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(StreamInvariantError::InvalidIdentity)
    } else {
        Ok(())
    }
}

fn serialized_fits(value: &impl Serialize, limit: usize) -> bool {
    let mut writer = BudgetWriter { remaining: limit };
    serde_json::to_writer(&mut writer, value).is_ok()
}
fn serialized_size(value: &impl Serialize) -> Option<usize> {
    let mut writer = CountingWriter { written: 0 };
    serde_json::to_writer(&mut writer, value)
        .ok()
        .map(|()| writer.written)
}

struct CountingWriter {
    written: usize,
}

impl io::Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized stream event size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BudgetWriter {
    remaining: usize,
}

impl io::Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other(
                "serialized stream event exceeds fixed budget",
            ));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
