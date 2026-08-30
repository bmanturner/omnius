use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use futures::Stream;
use serde_json::Value;

use crate::{LlmRequest, LlmResponse, ReasoningRepresentation};

/// Policy controlling whether provider payloads survive the adapter boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RawRetentionPolicy {
    /// Retain no provider payload or structural summary.
    #[default]
    Discard,
    /// Retain only payload shape and serialized byte length.
    Redacted,
    /// Retain the complete parsed payload for explicitly authorized callers.
    Full,
}

/// Observable retained-raw state on a result or error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawRetentionState {
    /// No raw information was retained.
    Discarded,
    /// Only a non-content structural summary was retained.
    Redacted,
    /// The complete payload was retained by explicit policy.
    Full,
}

/// The top-level JSON shape of a redacted payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawPayloadKind {
    /// JSON null.
    Null,
    /// A JSON boolean.
    Boolean,
    /// A JSON number.
    Number,
    /// A JSON string or a non-JSON provider body treated as opaque text.
    String,
    /// A JSON array.
    Array,
    /// A JSON object.
    Object,
}

/// A content-free summary of a provider payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawSummary {
    kind: RawPayloadKind,
    serialized_bytes: u64,
}

impl RawSummary {
    /// Returns the top-level payload shape.
    #[must_use]
    pub const fn kind(self) -> RawPayloadKind {
        self.kind
    }

    /// Returns the payload's serialized byte length.
    #[must_use]
    pub const fn serialized_bytes(self) -> u64 {
        self.serialized_bytes
    }

    fn from_value(value: &Value) -> Self {
        Self {
            kind: payload_kind(value),
            serialized_bytes: serialized_len(value),
        }
    }

    fn from_body(body: &str) -> Self {
        serde_json::from_str(body).map_or(
            Self {
                kind: RawPayloadKind::String,
                serialized_bytes: u64::try_from(body.len()).unwrap_or(u64::MAX),
            },
            |value| Self::from_value(&value),
        )
    }
}

/// Policy-controlled retained raw provider state.
///
/// `Debug` never prints payload content. Complete content is accessible only
/// through the deliberately named [`Self::full_payload`] accessor.
#[derive(Clone, PartialEq)]
pub struct RetainedRaw {
    inner: RetainedRawInner,
}

#[derive(Clone, PartialEq)]
enum RetainedRawInner {
    Discarded,
    Redacted(RawSummary),
    Full(Value),
}

impl RetainedRaw {
    /// Returns an explicitly empty retained-raw value.
    #[must_use]
    pub const fn discarded() -> Self {
        Self {
            inner: RetainedRawInner::Discarded,
        }
    }

    /// Applies a retention policy to one parsed provider payload.
    #[must_use]
    pub fn from_value(policy: RawRetentionPolicy, value: Value) -> Self {
        let inner = match policy {
            RawRetentionPolicy::Discard => RetainedRawInner::Discarded,
            RawRetentionPolicy::Redacted => {
                RetainedRawInner::Redacted(RawSummary::from_value(&value))
            }
            RawRetentionPolicy::Full => RetainedRawInner::Full(value),
        };
        Self { inner }
    }

    /// Applies a retention policy to a provider body.
    ///
    /// Full retention parses JSON bodies and otherwise stores the body as an
    /// opaque JSON string. Redacted retention records only shape and byte length.
    #[must_use]
    pub fn from_body(policy: RawRetentionPolicy, body: &str) -> Self {
        match policy {
            RawRetentionPolicy::Discard => Self::discarded(),
            RawRetentionPolicy::Redacted => Self {
                inner: RetainedRawInner::Redacted(RawSummary::from_body(body)),
            },
            RawRetentionPolicy::Full => Self {
                inner: RetainedRawInner::Full(
                    serde_json::from_str(body).unwrap_or_else(|_| Value::String(body.to_owned())),
                ),
            },
        }
    }

    /// Returns the observable retention state.
    #[must_use]
    pub const fn state(&self) -> RawRetentionState {
        match &self.inner {
            RetainedRawInner::Discarded => RawRetentionState::Discarded,
            RetainedRawInner::Redacted(_) => RawRetentionState::Redacted,
            RetainedRawInner::Full(_) => RawRetentionState::Full,
        }
    }

    /// Returns a content-free summary when redaction was requested.
    #[must_use]
    pub const fn redacted_summary(&self) -> Option<RawSummary> {
        match &self.inner {
            RetainedRawInner::Redacted(summary) => Some(*summary),
            RetainedRawInner::Discarded | RetainedRawInner::Full(_) => None,
        }
    }

    /// Borrows the complete provider payload only when full retention was requested.
    #[must_use]
    pub const fn full_payload(&self) -> Option<&Value> {
        match &self.inner {
            RetainedRawInner::Full(value) => Some(value),
            RetainedRawInner::Discarded | RetainedRawInner::Redacted(_) => None,
        }
    }
}

impl Default for RetainedRaw {
    fn default() -> Self {
        Self::discarded()
    }
}

impl fmt::Debug for RetainedRaw {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedRaw")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

/// Per-call redacted provider normalization diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderCompletionDiagnostics {
    provider: String,
    raw_state: RawRetentionState,
    unmodeled_parts: u32,
    private_reasoning_blocks: u32,
}

impl ProviderCompletionDiagnostics {
    /// Creates diagnostics for a canonical provider completion.
    #[must_use]
    pub const fn new(
        provider: String,
        raw_state: RawRetentionState,
        unmodeled_parts: u32,
        private_reasoning_blocks: u32,
    ) -> Self {
        Self {
            provider,
            raw_state,
            unmodeled_parts,
            private_reasoning_blocks,
        }
    }

    /// Borrows the provider identity that produced the completion.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the terminal raw-retention state.
    #[must_use]
    pub const fn raw_state(&self) -> RawRetentionState {
        self.raw_state
    }

    /// Returns the count of provider content extensions encountered during normalization.
    #[must_use]
    pub const fn unmodeled_parts(&self) -> u32 {
        self.unmodeled_parts
    }

    /// Returns how many private plain-reasoning blocks were deliberately omitted.
    #[must_use]
    pub const fn private_reasoning_blocks(&self) -> u32 {
        self.private_reasoning_blocks
    }
}

impl fmt::Debug for ProviderCompletionDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCompletionDiagnostics")
            .field("provider", &self.provider)
            .field("raw_state", &self.raw_state)
            .field("unmodeled_parts", &self.unmodeled_parts)
            .field("private_reasoning_blocks", &self.private_reasoning_blocks)
            .finish()
    }
}

/// An owned canonical completion and its policy-controlled provider state.
#[derive(Clone, PartialEq)]
pub struct ProviderCompletionResult {
    response: LlmResponse,
    raw: RetainedRaw,
    diagnostics: ProviderCompletionDiagnostics,
}

impl ProviderCompletionResult {
    /// Creates an owned canonical completion result.
    #[must_use]
    pub const fn new(
        response: LlmResponse,
        raw: RetainedRaw,
        diagnostics: ProviderCompletionDiagnostics,
    ) -> Self {
        Self {
            response,
            raw,
            diagnostics,
        }
    }

    /// Borrows the canonical response.
    #[must_use]
    pub const fn response(&self) -> &LlmResponse {
        &self.response
    }

    /// Borrows policy-controlled provider payload state.
    #[must_use]
    pub const fn retained_raw(&self) -> &RetainedRaw {
        &self.raw
    }

    /// Borrows redacted normalization diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &ProviderCompletionDiagnostics {
        &self.diagnostics
    }

    /// Consumes the result into all owned boundary values.
    #[must_use]
    pub fn into_parts(self) -> (LlmResponse, RetainedRaw, ProviderCompletionDiagnostics) {
        (self.response, self.raw, self.diagnostics)
    }
}

impl fmt::Debug for ProviderCompletionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderCompletionResult")
            .field("response", &self.response)
            .field("raw", &self.raw)
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

/// Stable high-level category for provider adapter failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    /// The canonical request asks for semantics the adapter cannot preserve.
    Unsupported,
    /// The provider rejected or failed the request.
    Provider,
    /// The network transport failed before a usable provider response arrived.
    Transport,
    /// The adapter deadline or provider timeout expired.
    Timeout,
    /// The provider throttled the request.
    Throttling,
    /// A safety policy or bounded execution limit rejected the operation.
    Safety,
    /// Configuration, request, response, or schema conversion failed.
    Schema,
}

/// Whether retrying the same operation is safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryClass {
    /// The same operation must not be retried automatically.
    Never,
    /// The same operation may be retried under the caller's deadline and retry budget.
    Safe,
    /// Retry is safe only after the separately reported retry-after duration.
    AfterRetryAfter,
}

/// Canonical semantics that a provider adapter may be unable to preserve faithfully.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedFeature {
    /// A non-assistant message carried a provider message identity.
    MessageIdentity,
    /// A message carried a name that the provider request cannot preserve.
    MessageName,
    /// A message carried provider-neutral metadata.
    MessageMetadata,
    /// A system message had zero or multiple parts and could not retain ordered block boundaries.
    SystemContentShape,
    /// A developer-role message cannot remain distinct from a system message.
    DeveloperMessage,
    /// A tool-role message cannot be reconstructed without provider tool-call provenance.
    ToolMessage,
    /// An image, audio, or video input was requested.
    MediaInput,
    /// A file input was requested.
    FileInput,
    /// A resource-reference input was requested.
    ResourceInput,
    /// A prior tool result lacks the tool name required by the provider request.
    ToolResultInput,
    /// A future canonical input part is unknown to this adapter revision.
    UnknownInputPart,
    /// Nucleus sampling was requested.
    TopP,
    /// More than one response candidate was requested.
    CandidateCount,
    /// Stop sequences were requested.
    StopSequences,
    /// A deterministic provider seed was requested.
    Seed,
    /// Arbitrary tool policy was supplied.
    ToolPolicy,
    /// A tool output schema was supplied.
    ToolOutputSchema,
    /// Structured output or schema controls require local validation.
    StructuredOutputRequiresValidation,
    /// A provider that requires leading system instructions received a later system message.
    SystemMessageOrder,
    /// Output MIME negotiation was requested.
    OutputMimeTypes,
    /// Tool-preferred output mode was requested.
    ToolOutputMode,
    /// Media output mode was requested.
    MediaOutputMode,
    /// Request metadata would be dropped by the provider request.
    RequestMetadata,
    /// Data policy would be dropped by the provider request.
    DataPolicy,
    /// Principal context would be dropped by the provider request.
    PrincipalContext,
    /// Tenant context would be dropped by the provider request.
    TenantContext,
    /// A cost ceiling cannot be enforced by the provider call.
    CostLimit,
    /// Provider-native streaming is unavailable for the exact provider/model revision.
    Streaming,
}

/// A redacted typed provider adapter error.
///
/// The error deliberately does not retain an SDK error value because provider
/// SDK `Display` and `Debug` implementations may contain request or response
/// bodies. Raw error payload is independently governed by [`RawRetentionPolicy`].
pub struct ProviderError {
    kind: ProviderErrorKind,
    provider: String,
    retry: RetryClass,
    retry_after: Option<Duration>,
    status_code: Option<u16>,
    provider_request_id: Option<String>,
    unsupported: Option<UnsupportedFeature>,
    raw: RetainedRaw,
}

impl ProviderError {
    /// Creates a classified error without transport metadata or retained raw state.
    #[must_use]
    pub fn new(provider: String, kind: ProviderErrorKind, retry: RetryClass) -> Self {
        Self {
            kind,
            provider,
            retry,
            retry_after: None,
            status_code: None,
            provider_request_id: None,
            unsupported: None,
            raw: RetainedRaw::discarded(),
        }
    }

    /// Creates a non-retryable unsupported-feature error.
    #[must_use]
    pub fn unsupported(provider: String, unsupported: UnsupportedFeature) -> Self {
        Self {
            unsupported: Some(unsupported),
            ..Self::new(provider, ProviderErrorKind::Unsupported, RetryClass::Never)
        }
    }

    /// Adds provider transport metadata and policy-controlled raw state.
    ///
    /// Empty provider request identifiers are discarded.
    #[must_use]
    pub fn with_transport_metadata(
        mut self,
        status_code: Option<u16>,
        retry_after: Option<Duration>,
        provider_request_id: Option<String>,
        raw: RetainedRaw,
    ) -> Self {
        self.status_code = status_code;
        self.retry_after = retry_after;
        self.provider_request_id = provider_request_id.filter(|value| !value.trim().is_empty());
        self.raw = raw;
        self
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> ProviderErrorKind {
        self.kind
    }

    /// Borrows the provider identity associated with the failed operation.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Returns the retry classification.
    #[must_use]
    pub const fn retry_class(&self) -> RetryClass {
        self.retry
    }

    /// Returns a provider-supplied retry-after duration when valid and captured.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Returns the HTTP status without exposing the provider body.
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    /// Borrows the provider transport request identifier, when captured.
    #[must_use]
    pub fn provider_request_id(&self) -> Option<&str> {
        self.provider_request_id.as_deref()
    }

    /// Returns the unsupported request semantic for an unsupported error.
    #[must_use]
    pub const fn unsupported_feature(&self) -> Option<UnsupportedFeature> {
        self.unsupported
    }

    /// Borrows policy-controlled raw provider error state.
    #[must_use]
    pub const fn retained_raw(&self) -> &RetainedRaw {
        &self.raw
    }
}

impl fmt::Debug for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderError")
            .field("kind", &self.kind)
            .field("provider", &self.provider)
            .field("retry", &self.retry)
            .field("retry_after", &self.retry_after)
            .field("status_code", &self.status_code)
            .field("unsupported", &self.unsupported)
            .field("raw_state", &self.raw.state())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LLM provider operation failed (provider={}, category={:?}",
            self.provider, self.kind
        )?;
        if let Some(status) = self.status_code {
            write!(formatter, ", status={status}")?;
        }
        formatter.write_str(")")
    }
}

impl Error for ProviderError {}

/// One typed fragment of an in-progress provider tool call.
///
/// Argument fragments are deliberately represented as strings rather than
/// [`Value`]. They are incomplete wire fragments and must never be confused
/// with the complete parsed arguments on [`ProviderStreamEvent::ToolCall`].
#[derive(Clone, PartialEq)]
pub enum ProviderToolCallDelta {
    /// The provider-emitted tool name.
    Name(String),
    /// An incomplete JSON argument fragment.
    ArgumentsFragment(String),
}

impl ProviderToolCallDelta {
    /// Borrows the tool name only when this is a name delta.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Name(name) => Some(name),
            Self::ArgumentsFragment(_) => None,
        }
    }

    /// Borrows the incomplete argument fragment only when this is an argument delta.
    #[must_use]
    pub fn arguments_fragment(&self) -> Option<&str> {
        match self {
            Self::ArgumentsFragment(fragment) => Some(fragment),
            Self::Name(_) => None,
        }
    }
}

impl fmt::Debug for ProviderToolCallDelta {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => formatter
                .debug_struct("Name")
                .field("byte_count", &name.len())
                .finish_non_exhaustive(),
            Self::ArgumentsFragment(fragment) => formatter
                .debug_struct("ArgumentsFragment")
                .field("byte_count", &fragment.len())
                .finish_non_exhaustive(),
        }
    }
}

/// Ordered event seam between a provider and stream orchestration.
pub enum ProviderStreamEvent {
    /// One ordered assistant text delta.
    TextDelta {
        /// Monotonic sequence number within this request, starting at zero.
        sequence: u64,
        /// Provider-emitted text fragment.
        text: String,
    },
    /// One fragment of an in-progress tool call.
    ToolCallDelta {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Opaque request-local correlator shared with the completed call.
        correlation_id: String,
        /// Typed name or incomplete argument fragment.
        delta: ProviderToolCallDelta,
    },
    /// One completed provider tool call with complete JSON arguments.
    ToolCall {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Opaque request-local correlator shared with preceding deltas.
        correlation_id: String,
        /// Genuine provider call identifier or deterministic adapter fallback.
        call_id: String,
        /// Complete tool name.
        name: String,
        /// Complete parsed JSON arguments.
        arguments: Value,
        /// Policy-controlled additional provider metadata.
        raw: RetainedRaw,
    },
    /// One safe provider-sanctioned reasoning representation.
    Reasoning {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Opaque request-local reasoning correlator.
        correlation_id: String,
        /// Safe representation category.
        representation: ReasoningRepresentation,
        /// Summary, continuation signature, or encrypted opaque state.
        data: String,
    },
    /// The byte count of an omitted private plain-reasoning delta.
    PrivateReasoningDelta {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Opaque request-local reasoning correlator.
        correlation_id: String,
        /// Number of private bytes deliberately withheld.
        byte_count: u64,
    },
    /// Completion indicator for one omitted private plain-reasoning block.
    PrivateReasoning {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Opaque request-local reasoning correlator.
        correlation_id: String,
        /// Number of private bytes deliberately withheld.
        byte_count: u64,
    },
    /// One unmodeled provider stream item under explicit raw-retention policy.
    UnknownProviderItem {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Stable non-sensitive adapter classification.
        kind: &'static str,
        /// Policy-controlled raw state; its `Debug` implementation is redacted.
        raw: RetainedRaw,
    },
    /// Terminal canonical completion after the provider stream was fully drained.
    Terminal {
        /// Monotonic sequence number within this request.
        sequence: u64,
        /// Owned canonical response and explicit retained-raw state.
        result: Box<ProviderCompletionResult>,
    },
}

impl ProviderStreamEvent {
    /// Returns this event's request-local sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        match self {
            Self::TextDelta { sequence, .. }
            | Self::ToolCallDelta { sequence, .. }
            | Self::ToolCall { sequence, .. }
            | Self::Reasoning { sequence, .. }
            | Self::PrivateReasoningDelta { sequence, .. }
            | Self::PrivateReasoning { sequence, .. }
            | Self::UnknownProviderItem { sequence, .. }
            | Self::Terminal { sequence, .. } => *sequence,
        }
    }

    /// Borrows a text delta only when this is a text event.
    #[must_use]
    pub fn text(&self) -> Option<&str> {
        match self {
            Self::TextDelta { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Borrows a typed tool-call delta only when this is a delta event.
    #[must_use]
    pub const fn tool_call_delta(&self) -> Option<&ProviderToolCallDelta> {
        match self {
            Self::ToolCallDelta { delta, .. } => Some(delta),
            _ => None,
        }
    }

    /// Borrows a stream-local correlator when the event belongs to a tool or reasoning item.
    #[must_use]
    pub fn correlation_id(&self) -> Option<&str> {
        match self {
            Self::ToolCallDelta { correlation_id, .. }
            | Self::ToolCall { correlation_id, .. }
            | Self::Reasoning { correlation_id, .. }
            | Self::PrivateReasoningDelta { correlation_id, .. }
            | Self::PrivateReasoning { correlation_id, .. } => Some(correlation_id),
            Self::TextDelta { .. } | Self::UnknownProviderItem { .. } | Self::Terminal { .. } => {
                None
            }
        }
    }

    /// Borrows complete tool-call fields only when this is a completed call.
    #[must_use]
    pub fn tool_call(&self) -> Option<(&str, &str, &Value)> {
        match self {
            Self::ToolCall {
                call_id,
                name,
                arguments,
                ..
            } => Some((call_id, name, arguments)),
            _ => None,
        }
    }

    /// Borrows safe reasoning data only when this is a safe reasoning event.
    #[must_use]
    pub fn reasoning(&self) -> Option<(ReasoningRepresentation, &str)> {
        match self {
            Self::Reasoning {
                representation,
                data,
                ..
            } => Some((*representation, data)),
            _ => None,
        }
    }

    /// Returns withheld private-reasoning byte count for delta or complete indicators.
    #[must_use]
    pub const fn private_reasoning_byte_count(&self) -> Option<u64> {
        match self {
            Self::PrivateReasoningDelta { byte_count, .. }
            | Self::PrivateReasoning { byte_count, .. } => Some(*byte_count),
            _ => None,
        }
    }

    /// Returns the stable classification only when this is an unknown provider item.
    #[must_use]
    pub const fn unknown_provider_kind(&self) -> Option<&'static str> {
        match self {
            Self::UnknownProviderItem { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Borrows retained provider state only for completed tool or unknown events.
    #[must_use]
    pub const fn retained_raw(&self) -> Option<&RetainedRaw> {
        match self {
            Self::ToolCall { raw, .. } | Self::UnknownProviderItem { raw, .. } => Some(raw),
            _ => None,
        }
    }

    /// Borrows the terminal canonical result only when this is the terminal event.
    #[must_use]
    pub fn terminal(&self) -> Option<&ProviderCompletionResult> {
        match self {
            Self::Terminal { result, .. } => Some(result.as_ref()),
            _ => None,
        }
    }
}

impl fmt::Debug for ProviderStreamEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TextDelta { sequence, text } => formatter
                .debug_struct("TextDelta")
                .field("sequence", sequence)
                .field("byte_count", &text.len())
                .finish_non_exhaustive(),
            Self::ToolCallDelta {
                sequence, delta, ..
            } => formatter
                .debug_struct("ToolCallDelta")
                .field("sequence", sequence)
                .field("delta", delta)
                .finish_non_exhaustive(),
            Self::ToolCall {
                sequence,
                name,
                arguments,
                raw,
                ..
            } => formatter
                .debug_struct("ToolCall")
                .field("sequence", sequence)
                .field("name_bytes", &name.len())
                .field("arguments_bytes", &serialized_len(arguments))
                .field("raw_state", &raw.state())
                .finish_non_exhaustive(),
            Self::Reasoning {
                sequence,
                representation,
                data,
                ..
            } => formatter
                .debug_struct("Reasoning")
                .field("sequence", sequence)
                .field("kind", representation)
                .field("byte_count", &data.len())
                .finish_non_exhaustive(),
            Self::PrivateReasoningDelta {
                sequence,
                byte_count,
                ..
            } => formatter
                .debug_struct("PrivateReasoningDelta")
                .field("sequence", sequence)
                .field("byte_count", byte_count)
                .finish_non_exhaustive(),
            Self::PrivateReasoning {
                sequence,
                byte_count,
                ..
            } => formatter
                .debug_struct("PrivateReasoning")
                .field("sequence", sequence)
                .field("byte_count", byte_count)
                .finish_non_exhaustive(),
            Self::UnknownProviderItem {
                sequence,
                kind,
                raw,
            } => formatter
                .debug_struct("UnknownProviderItem")
                .field("sequence", sequence)
                .field("kind", kind)
                .field("raw_state", &raw.state())
                .finish_non_exhaustive(),
            Self::Terminal { sequence, result } => formatter
                .debug_struct("Terminal")
                .field("sequence", sequence)
                .field("result", result)
                .finish(),
        }
    }
}

/// A boxed, sendable stream of ordered provider events.
pub struct ProviderStream {
    provider: String,
    inner: Pin<Box<dyn Stream<Item = Result<ProviderStreamEvent, ProviderError>> + Send + 'static>>,
}

impl ProviderStream {
    /// Boxes any sendable, owned provider event stream.
    #[must_use]
    pub fn new<S>(provider: String, stream: S) -> Self
    where
        S: Stream<Item = Result<ProviderStreamEvent, ProviderError>> + Send + 'static,
    {
        Self {
            provider,
            inner: Box::pin(stream),
        }
    }

    /// Borrows the identity of the provider backing this stream.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

impl Stream for ProviderStream {
    type Item = Result<ProviderStreamEvent, ProviderError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

impl fmt::Debug for ProviderStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderStream")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// Object-safe provider-neutral LLM execution port.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Executes one owned canonical completion request.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted provider adapter error.
    async fn complete(
        &self,
        request: LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError>;

    /// Opens one owned provider event stream.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted error when request preparation or stream connection fails.
    async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError>;
}

fn payload_kind(value: &Value) -> RawPayloadKind {
    match value {
        Value::Null => RawPayloadKind::Null,
        Value::Bool(_) => RawPayloadKind::Boolean,
        Value::Number(_) => RawPayloadKind::Number,
        Value::String(_) => RawPayloadKind::String,
        Value::Array(_) => RawPayloadKind::Array,
        Value::Object(_) => RawPayloadKind::Object,
    }
}

fn serialized_len<T: serde::Serialize>(value: &T) -> u64 {
    let mut counter = CountingWriter::default();
    if serde_json::to_writer(&mut counter, value).is_err() {
        return u64::MAX;
    }
    counter.bytes
}

#[derive(Default)]
struct CountingWriter {
    bytes: u64,
}

impl io::Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(buffer.len()).unwrap_or(u64::MAX));
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, time::Duration};

    use async_trait::async_trait;
    use futures::{StreamExt, stream};
    use serde_json::json;
    use time::OffsetDateTime;

    use super::{
        LlmProvider, ProviderCompletionDiagnostics, ProviderCompletionResult, ProviderError,
        ProviderErrorKind, ProviderStream, ProviderStreamEvent, ProviderToolCallDelta,
        RawPayloadKind, RawRetentionPolicy, RawRetentionState, RetainedRaw, RetryClass,
        UnsupportedFeature,
    };
    use crate::{
        CompletionStatus, LlmOutputPart, LlmRequest, LlmRequestId, LlmResponse,
        ReasoningRepresentation, TextOutputPart, Usage,
    };

    struct AlwaysUnavailableProvider;

    #[async_trait]
    impl LlmProvider for AlwaysUnavailableProvider {
        async fn complete(
            &self,
            _request: LlmRequest,
        ) -> Result<ProviderCompletionResult, ProviderError> {
            Err(ProviderError::new(
                "test-provider".to_owned(),
                ProviderErrorKind::Provider,
                RetryClass::Never,
            ))
        }

        async fn stream(&self, _request: LlmRequest) -> Result<ProviderStream, ProviderError> {
            Err(ProviderError::new(
                "test-provider".to_owned(),
                ProviderErrorKind::Provider,
                RetryClass::Never,
            ))
        }
    }

    #[test]
    fn provider_port_is_object_safe() {
        fn accept_provider(_provider: &dyn LlmProvider) {}

        accept_provider(&AlwaysUnavailableProvider);
        let _provider: Box<dyn LlmProvider> = Box::new(AlwaysUnavailableProvider);
    }

    #[test]
    fn raw_retention_policy_controls_payload_access() -> Result<(), Box<dyn Error>> {
        let payload = json!({"secret": "raw-secret"});
        let discarded = RetainedRaw::from_value(RawRetentionPolicy::Discard, payload.clone());
        let redacted = RetainedRaw::from_value(RawRetentionPolicy::Redacted, payload.clone());
        let full = RetainedRaw::from_value(RawRetentionPolicy::Full, payload.clone());

        assert_eq!(discarded.state(), RawRetentionState::Discarded);
        assert_eq!(redacted.state(), RawRetentionState::Redacted);
        assert_eq!(full.state(), RawRetentionState::Full);
        assert_eq!(
            redacted.redacted_summary().map(super::RawSummary::kind),
            Some(RawPayloadKind::Object)
        );
        assert!(
            redacted
                .redacted_summary()
                .is_some_and(|summary| summary.serialized_bytes() > 0)
        );
        assert!(discarded.full_payload().is_none());
        assert!(redacted.full_payload().is_none());
        assert_eq!(full.full_payload(), Some(&payload));
        assert!(!format!("{full:?}").contains("raw-secret"));

        let opaque = RetainedRaw::from_body(RawRetentionPolicy::Full, "opaque-secret");
        if opaque.full_payload() != Some(&json!("opaque-secret")) {
            return Err(io::Error::other("opaque full body was not retained deliberately").into());
        }
        Ok(())
    }

    #[test]
    fn debug_and_display_redact_content_raw_model_and_request_metadata()
    -> Result<(), Box<dyn Error>> {
        let result = completion_result()?;
        let result_debug = format!("{result:?}");
        assert!(!result_debug.contains("content-secret"));
        assert!(!result_debug.contains("raw-secret"));
        assert!(!result_debug.contains("model-secret"));
        assert!(!result_debug.contains("provider-request-secret"));

        let event = ProviderStreamEvent::TextDelta {
            sequence: 0,
            text: "delta-secret".to_owned(),
        };
        assert!(!format!("{event:?}").contains("delta-secret"));

        let error = ProviderError::new(
            "test-provider".to_owned(),
            ProviderErrorKind::Throttling,
            RetryClass::AfterRetryAfter,
        )
        .with_transport_metadata(
            Some(429),
            Some(Duration::from_secs(3)),
            Some("provider-request-secret".to_owned()),
            RetainedRaw::from_value(RawRetentionPolicy::Full, json!({"raw": "raw-secret"})),
        );
        let error_debug = format!("{error:?}");
        let error_display = error.to_string();
        assert!(!error_debug.contains("provider-request-secret"));
        assert!(!error_debug.contains("raw-secret"));
        assert!(!error_display.contains("provider-request-secret"));
        assert!(!error_display.contains("raw-secret"));
        Ok(())
    }

    #[test]
    fn provider_error_exposes_typed_metadata_without_debug_leaks() {
        let raw = RetainedRaw::from_body(RawRetentionPolicy::Redacted, r#"{"error":"secret"}"#);
        let error = ProviderError::new(
            "provider-name".to_owned(),
            ProviderErrorKind::Throttling,
            RetryClass::AfterRetryAfter,
        )
        .with_transport_metadata(
            Some(429),
            Some(Duration::from_secs(7)),
            Some("request-secret".to_owned()),
            raw,
        );

        assert_eq!(error.provider(), "provider-name");
        assert_eq!(error.kind(), ProviderErrorKind::Throttling);
        assert_eq!(error.retry_class(), RetryClass::AfterRetryAfter);
        assert_eq!(error.retry_after(), Some(Duration::from_secs(7)));
        assert_eq!(error.status_code(), Some(429));
        assert_eq!(error.provider_request_id(), Some("request-secret"));
        assert_eq!(error.retained_raw().state(), RawRetentionState::Redacted);
        assert_eq!(error.unsupported_feature(), None);

        let unsupported =
            ProviderError::unsupported("provider-name".to_owned(), UnsupportedFeature::MediaInput);
        assert_eq!(unsupported.kind(), ProviderErrorKind::Unsupported);
        assert_eq!(unsupported.retry_class(), RetryClass::Never);
        assert_eq!(
            unsupported.unsupported_feature(),
            Some(UnsupportedFeature::MediaInput)
        );
    }

    #[test]
    fn tool_argument_fragments_remain_incomplete_and_stream_debug_is_redacted() {
        let fragment =
            ProviderToolCallDelta::ArgumentsFragment(r#"{"private":"fragment"#.to_owned());
        assert_eq!(
            fragment.arguments_fragment(),
            Some(r#"{"private":"fragment"#)
        );
        assert!(fragment.name().is_none());

        let delta = ProviderStreamEvent::ToolCallDelta {
            sequence: 4,
            correlation_id: "correlation-secret".to_owned(),
            delta: fragment,
        };
        assert!(delta.tool_call().is_none());
        assert!(delta.tool_call_delta().is_some());
        let delta_debug = format!("{delta:?}");
        assert!(!delta_debug.contains("private"));
        assert!(!delta_debug.contains("fragment"));
        assert!(!delta_debug.contains("correlation-secret"));

        let complete = ProviderStreamEvent::ToolCall {
            sequence: 5,
            correlation_id: "correlation-secret".to_owned(),
            call_id: "call-secret".to_owned(),
            name: "tool-secret".to_owned(),
            arguments: json!({"argument": "argument-secret"}),
            raw: RetainedRaw::from_value(
                RawRetentionPolicy::Full,
                json!({"metadata": "metadata-secret"}),
            ),
        };
        assert_eq!(
            complete.tool_call().map(|(_, _, arguments)| arguments),
            Some(&json!({"argument": "argument-secret"}))
        );
        let complete_debug = format!("{complete:?}");
        for secret in [
            "correlation-secret",
            "call-secret",
            "tool-secret",
            "argument-secret",
            "metadata-secret",
        ] {
            assert!(!complete_debug.contains(secret));
        }

        let reasoning = ProviderStreamEvent::Reasoning {
            sequence: 6,
            correlation_id: "reasoning-correlation-secret".to_owned(),
            representation: ReasoningRepresentation::Signature,
            data: "signature-secret".to_owned(),
        };
        let private = ProviderStreamEvent::PrivateReasoningDelta {
            sequence: 7,
            correlation_id: "reasoning-correlation-secret".to_owned(),
            byte_count: 29,
        };
        assert!(!format!("{reasoning:?}").contains("signature-secret"));
        assert!(!format!("{private:?}").contains("reasoning-correlation-secret"));
    }

    #[test]
    fn stream_events_preserve_sequence_and_typed_accessors() -> Result<(), Box<dyn Error>> {
        let text = ProviderStreamEvent::TextDelta {
            sequence: 0,
            text: "first".to_owned(),
        };
        let unknown = ProviderStreamEvent::UnknownProviderItem {
            sequence: 1,
            kind: "provider-extension",
            raw: RetainedRaw::from_body(RawRetentionPolicy::Redacted, r#"{"value":1}"#),
        };
        let terminal = ProviderStreamEvent::Terminal {
            sequence: 2,
            result: Box::new(completion_result()?),
        };

        assert_eq!(text.sequence(), 0);
        assert_eq!(text.text(), Some("first"));
        assert_eq!(unknown.sequence(), 1);
        assert_eq!(unknown.unknown_provider_kind(), Some("provider-extension"));
        assert_eq!(
            unknown.retained_raw().map(RetainedRaw::state),
            Some(RawRetentionState::Redacted)
        );
        assert_eq!(terminal.sequence(), 2);
        assert!(terminal.terminal().is_some());

        let mut provider_stream = ProviderStream::new(
            "provider-name".to_owned(),
            stream::iter([Ok::<_, ProviderError>(text), Ok(unknown), Ok(terminal)]),
        );
        assert_eq!(provider_stream.provider(), "provider-name");
        let first = futures::executor::block_on(provider_stream.next())
            .ok_or_else(|| io::Error::other("boxed provider stream ended early"))??;
        assert_eq!(first.sequence(), 0);
        Ok(())
    }

    fn completion_result() -> Result<ProviderCompletionResult, Box<dyn Error>> {
        let response = LlmResponse::new(
            LlmRequestId::new("request_01".to_owned())?,
            "response_01".to_owned(),
            "test-provider".to_owned(),
            "model-secret".to_owned(),
            CompletionStatus::Completed,
            Some("stop".to_owned()),
            vec![LlmOutputPart::Text(TextOutputPart::new(
                "part_01".to_owned(),
                "content-secret".to_owned(),
                None,
            )?)],
            Usage::new(Some(1), Some(1)),
            OffsetDateTime::UNIX_EPOCH,
        )?
        .with_provider_ids(None, Some("provider-request-secret".to_owned()))?;
        let raw = RetainedRaw::from_value(RawRetentionPolicy::Full, json!({"raw": "raw-secret"}));
        let diagnostics =
            ProviderCompletionDiagnostics::new("test-provider".to_owned(), raw.state(), 1, 2);
        Ok(ProviderCompletionResult::new(response, raw, diagnostics))
    }
}
