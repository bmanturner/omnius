use std::{fmt, time::Duration};

use metrics::{counter, histogram};
use thiserror::Error;
use tracing::Span;

const MAX_SAFE_NAME_BYTES: usize = 128;
const MAX_CAPTURE_TTL: Duration = Duration::from_hours(24);
const PARTS_PER_MILLION: u32 = 1_000_000;

/// A bounded content-free attribute suitable for configured route, provider, model, tool, and task names.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GenAiAttribute(String);

impl GenAiAttribute {
    /// Validates and owns a portable non-secret attribute.
    ///
    /// # Errors
    ///
    /// Returns [`GenAiTelemetryError::Attribute`] for empty, oversized, or non-portable values.
    pub fn new(value: impl Into<String>) -> Result<Self, GenAiTelemetryError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SAFE_NAME_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-' | b'/')
            })
        {
            return Err(GenAiTelemetryError::Attribute);
        }
        Ok(Self(value))
    }

    /// Borrows the validated value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for GenAiAttribute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GenAiAttribute([bounded])")
    }
}

/// Stable product-neutral `GenAI` operation names.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenAiOperation {
    /// Canonical response generation.
    Generate,
    /// Embedding generation.
    Embed,
    /// Document reranking.
    Rerank,
    /// Audio transcription.
    Transcribe,
    /// Speech synthesis.
    SynthesizeSpeech,
    /// Image or other media generation.
    GenerateMedia,
    /// Classification.
    Classify,
    /// Moderation.
    Moderate,
    /// Tool execution within a model loop.
    ExecuteTool,
}

impl GenAiOperation {
    /// Returns the stable OpenTelemetry-compatible operation name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Generate => "generate_content",
            Self::Embed => "embeddings",
            Self::Rerank => "rerank",
            Self::Transcribe => "transcription",
            Self::SynthesizeSpeech => "speech",
            Self::GenerateMedia => "generate_media",
            Self::Classify => "classification",
            Self::Moderate => "moderation",
            Self::ExecuteTool => "execute_tool",
        }
    }
}

/// Closed terminal outcome used by low-cardinality metrics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenAiOutcome {
    /// The requested operation completed.
    Succeeded,
    /// Provider or safety policy refused the operation.
    Refused,
    /// Cooperative cancellation won.
    Cancelled,
    /// The operation failed before usable completion.
    Failed,
    /// The operation retained explicitly incomplete public output.
    Partial,
}

impl GenAiOutcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Refused => "refused",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::Partial => "partial",
        }
    }
}

/// Closed finish classification aligned with canonical response and stream outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenAiFinishState {
    /// Canonical completion.
    Completed,
    /// Provider refusal.
    ProviderRefused,
    /// Safety-policy refusal.
    SafetyRefused,
    /// Local structured-output validation failure.
    InvalidStructuredData,
    /// Tool execution failure.
    ToolExecutionFailed,
    /// A deterministic loop or quota budget was exhausted.
    BudgetExhausted,
    /// Cooperative cancellation.
    Cancelled,
    /// Failure before usable public content.
    Failed,
    /// Interrupted with explicitly incomplete public content.
    PartialInterrupted,
}

impl GenAiFinishState {
    /// Returns the canonical bounded finish value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::ProviderRefused => "provider_refused",
            Self::SafetyRefused => "safety_refused",
            Self::InvalidStructuredData => "invalid_structured_data",
            Self::ToolExecutionFailed => "tool_execution_failed",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
            Self::PartialInterrupted => "partial_interrupted",
        }
    }
}

/// Content-free stable error category.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenAiErrorClass {
    /// Provider transport failure.
    ProviderTransport,
    /// Provider protocol normalization failure.
    ProviderProtocol,
    /// Route selection or capability failure.
    Routing,
    /// Budget or quota denial.
    Budget,
    /// Tool execution failure.
    Tool,
    /// Media lifecycle or scanning failure.
    Media,
    /// Local validation failure.
    Validation,
    /// Internal orchestration failure.
    Internal,
}

impl GenAiErrorClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ProviderTransport => "provider_transport",
            Self::ProviderProtocol => "provider_protocol",
            Self::Routing => "routing",
            Self::Budget => "budget",
            Self::Tool => "tool",
            Self::Media => "media",
            Self::Validation => "validation",
            Self::Internal => "internal",
        }
    }
}

/// One latency phase measured independently from the end-to-end operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum GenAiLatencyPhase {
    /// Admission, authorization, and policy evaluation.
    Admission,
    /// Route and provider selection.
    Routing,
    /// Time to first provider byte.
    FirstByte,
    /// Provider generation after first byte.
    Generation,
    /// Tool execution.
    Tool,
    /// Final local validation and persistence.
    Finalization,
}

impl GenAiLatencyPhase {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Routing => "routing",
            Self::FirstByte => "first_byte",
            Self::Generation => "generation",
            Self::Tool => "tool",
            Self::Finalization => "finalization",
        }
    }
}

/// Content-free span context. Identifiers are trace-only and never become metric labels.
pub struct GenAiSpanContext<'a> {
    /// Stable operation name.
    pub operation: GenAiOperation,
    /// Configured product route.
    pub route: Option<&'a GenAiAttribute>,
    /// Configured provider name.
    pub provider: Option<&'a GenAiAttribute>,
    /// Configured request model alias.
    pub request_model: Option<&'a GenAiAttribute>,
    /// Normalized provider response model.
    pub response_model: Option<&'a GenAiAttribute>,
    /// Durable task correlation identifier, restricted to this trace.
    pub task_id: Option<&'a GenAiAttribute>,
    /// Configured tool names, restricted to this trace.
    pub tool_names: &'a [GenAiAttribute],
    /// Retry count.
    pub retry_count: u32,
    /// Fallback count.
    pub fallback_count: u32,
}

/// Starts a `GenAI` span containing no prompts, responses, arguments, files, URLs, or credentials.
#[must_use]
pub fn gen_ai_span(context: &GenAiSpanContext<'_>) -> Span {
    tracing::info_span!(
        target: "omnius.gen_ai",
        "gen_ai.operation",
        gen_ai.operation.name = context.operation.as_str(),
        omnius.gen_ai.route = context.route.map(GenAiAttribute::as_str),
        gen_ai.provider.name = context.provider.map(GenAiAttribute::as_str),
        gen_ai.request.model = context.request_model.map(GenAiAttribute::as_str),
        gen_ai.response.model = context.response_model.map(GenAiAttribute::as_str),
        omnius.gen_ai.task.id = context.task_id.map(GenAiAttribute::as_str),
        omnius.gen_ai.tool.names = tracing::field::debug(ToolNames(context.tool_names)),
        omnius.gen_ai.retry.count = context.retry_count,
        omnius.gen_ai.fallback.count = context.fallback_count,
        gen_ai.response.finish_reasons = tracing::field::Empty,
        error.type = tracing::field::Empty,
        gen_ai.usage.input_tokens = tracing::field::Empty,
        gen_ai.usage.output_tokens = tracing::field::Empty,
        omnius.gen_ai.usage.cost_microunits = tracing::field::Empty,
    )
}

struct ToolNames<'a>(&'a [GenAiAttribute]);

impl fmt::Debug for ToolNames<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = formatter.debug_list();
        for value in self.0 {
            list.entry(&value.as_str());
        }
        list.finish()
    }
}

/// Records final content-free fields on a span created by [`gen_ai_span`].
pub fn record_gen_ai_span_outcome(
    span: &Span,
    finish: GenAiFinishState,
    error: Option<GenAiErrorClass>,
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_microunits: Option<u64>,
) {
    span.record("gen_ai.response.finish_reasons", finish.as_str());
    if let Some(error) = error {
        span.record("error.type", error.as_str());
    }
    if let Some(value) = input_tokens {
        span.record("gen_ai.usage.input_tokens", value);
    }
    if let Some(value) = output_tokens {
        span.record("gen_ai.usage.output_tokens", value);
    }
    if let Some(value) = cost_microunits {
        span.record("omnius.gen_ai.usage.cost_microunits", value);
    }
}

/// Records one bounded request observation. No configured names or identifiers become labels.
pub fn record_gen_ai_request(
    operation: GenAiOperation,
    outcome: GenAiOutcome,
    finish: GenAiFinishState,
    duration: Duration,
    retried: bool,
    fallback: bool,
) {
    let retry = if retried { "true" } else { "false" };
    let fallback = if fallback { "true" } else { "false" };
    counter!(
        "omnius_genai_requests_total",
        "operation" => operation.as_str(),
        "outcome" => outcome.as_str(),
        "finish" => finish.as_str(),
        "retried" => retry,
        "fallback" => fallback,
    )
    .increment(1);
    histogram!(
        "omnius_genai_request_duration_seconds",
        "operation" => operation.as_str(),
        "outcome" => outcome.as_str(),
    )
    .record(duration.as_secs_f64());
}

/// Records a phase latency with only closed operation and phase labels.
pub fn record_gen_ai_phase(
    operation: GenAiOperation,
    phase: GenAiLatencyPhase,
    duration: Duration,
) {
    histogram!(
        "omnius_genai_phase_duration_seconds",
        "operation" => operation.as_str(),
        "phase" => phase.as_str(),
    )
    .record(duration.as_secs_f64());
}

/// Records usage totals without tenant, principal, request, job, provider, model, tool, or object labels.
pub fn record_gen_ai_usage(
    operation: GenAiOperation,
    input_tokens: u64,
    output_tokens: u64,
    cost_microunits: u64,
) {
    counter!("omnius_genai_usage_total", "operation" => operation.as_str(), "unit" => "input_token")
        .increment(input_tokens);
    counter!("omnius_genai_usage_total", "operation" => operation.as_str(), "unit" => "output_token")
        .increment(output_tokens);
    counter!("omnius_genai_usage_total", "operation" => operation.as_str(), "unit" => "cost_microunit")
        .increment(cost_microunits);
}

/// Explicit policy governing exceptional encrypted diagnostic content capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticCapturePolicy {
    enabled: bool,
    sample_rate_ppm: u32,
    maximum_ttl: Duration,
    encryption_key_id: Option<GenAiAttribute>,
    redaction_profile: Option<GenAiAttribute>,
}

impl DiagnosticCapturePolicy {
    /// Constructs an enabled, sampled, time-bounded, encrypted, and redacted capture policy.
    ///
    /// # Errors
    ///
    /// Returns [`GenAiTelemetryError::CapturePolicy`] unless every required control is explicit.
    pub fn enabled(
        sample_rate_ppm: u32,
        maximum_ttl: Duration,
        encryption_key_id: GenAiAttribute,
        redaction_profile: GenAiAttribute,
    ) -> Result<Self, GenAiTelemetryError> {
        if sample_rate_ppm == 0
            || sample_rate_ppm > PARTS_PER_MILLION
            || maximum_ttl.is_zero()
            || maximum_ttl > MAX_CAPTURE_TTL
        {
            return Err(GenAiTelemetryError::CapturePolicy);
        }
        Ok(Self {
            enabled: true,
            sample_rate_ppm,
            maximum_ttl,
            encryption_key_id: Some(encryption_key_id),
            redaction_profile: Some(redaction_profile),
        })
    }

    /// Reports whether exceptional capture is explicitly enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the deterministic sampling threshold in parts per million.
    #[must_use]
    pub const fn sample_rate_ppm(&self) -> u32 {
        self.sample_rate_ppm
    }

    /// Returns the maximum encrypted capture lifetime.
    #[must_use]
    pub const fn maximum_ttl(&self) -> Duration {
        self.maximum_ttl
    }

    /// Returns the configured encryption key identifier only for enabled policies.
    #[must_use]
    pub const fn encryption_key_id(&self) -> Option<&GenAiAttribute> {
        self.encryption_key_id.as_ref()
    }

    /// Returns the configured redaction profile only for enabled policies.
    #[must_use]
    pub const fn redaction_profile(&self) -> Option<&GenAiAttribute> {
        self.redaction_profile.as_ref()
    }

    /// Applies deterministic sampling to a caller-provided uniform value below one million.
    #[must_use]
    pub const fn admits_sample(&self, sample: u32) -> bool {
        self.enabled && sample < self.sample_rate_ppm && sample < PARTS_PER_MILLION
    }
}

impl Default for DiagnosticCapturePolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate_ppm: 0,
            maximum_ttl: Duration::ZERO,
            encryption_key_id: None,
            redaction_profile: None,
        }
    }
}

/// Safe `GenAI` telemetry configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GenAiTelemetryError {
    /// A trace-only configured attribute was invalid.
    #[error("invalid GenAI telemetry attribute")]
    Attribute,
    /// Diagnostic capture omitted or exceeded one mandatory control.
    #[error("invalid diagnostic capture policy")]
    CapturePolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_capture_is_disabled_without_explicit_policy() {
        let policy = DiagnosticCapturePolicy::default();

        assert!(!policy.is_enabled());
    }

    #[test]
    fn diagnostic_capture_requires_a_bounded_nonzero_sample() -> Result<(), GenAiTelemetryError> {
        let key = GenAiAttribute::new("kms-key-1")?;
        let profile = GenAiAttribute::new("llm-default")?;

        let result = DiagnosticCapturePolicy::enabled(0, Duration::from_secs(60), key, profile);

        assert_eq!(result, Err(GenAiTelemetryError::CapturePolicy));
        Ok(())
    }

    #[test]
    fn portable_attributes_reject_content_shaped_values() {
        let result = GenAiAttribute::new("prompt text with spaces");

        assert_eq!(result, Err(GenAiTelemetryError::Attribute));
    }
}
