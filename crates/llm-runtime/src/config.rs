use omnius_config::SecretString;
use serde::Deserialize;

/// Strict configuration sections owned by the LLM runtime family.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRuntimeConfig {
    /// Direct Rig provider registrations.
    pub llm_provider_rig: RigProvidersConfig,
    /// Immutable capability, route, and circuit declarations.
    pub llm_routing: RoutingConfig,
    /// Bounded live-stream controls.
    pub llm_streaming: StreamingConfig,
    /// Local structured-output admission and repair controls.
    pub llm_structured_output: StructuredOutputConfig,
}

/// Direct provider registrations. Secrets remain secret strings through construction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RigProvidersConfig {
    /// Candidate-bound provider registrations.
    pub registrations: Vec<RigProviderRegistration>,
}

/// One direct Rig provider registration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RigProviderRegistration {
    /// Globally unique routing candidate identity.
    pub candidate_id: String,
    /// Direct provider family.
    pub provider: DirectProviderConfig,
    /// Exact configured provider model.
    pub model: String,
    /// Exact capability declaration revision.
    pub revision: String,
    /// Provider API key.
    pub api_key: SecretString,
    /// Explicit provider-payload retention policy.
    pub raw_retention: RawRetentionConfig,
}

/// Direct providers constructed by `omnius-llm-provider-rig`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DirectProviderConfig {
    /// `OpenAI` Responses API.
    OpenAi,
    /// Anthropic Messages API.
    Anthropic,
    /// Direct Gemini API.
    Gemini,
    /// `OpenRouter` API.
    OpenRouter,
}

/// Provider payload retention policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RawRetentionConfig {
    /// Retain no provider payload.
    Discard,
    /// Retain only structural summary evidence.
    Redacted,
    /// Retain full payload under explicit application policy.
    Full,
}

/// Strict routing section. Route declarations are deserialized by the application into the
/// validated `omnius-llm-routing` types before runtime construction.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    /// Versioned model capability declarations as JSON-compatible objects.
    pub capabilities: Vec<serde_json::Value>,
    /// Immutable route definitions as JSON-compatible objects.
    pub routes: Vec<serde_json::Value>,
    /// Circuit bounds.
    pub circuit: CircuitConfig,
}

/// Bounded rolling circuit configuration.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CircuitConfig {
    /// Maximum distinct circuit scopes.
    pub max_scopes: usize,
    /// Maximum samples retained per scope.
    pub max_samples_per_scope: usize,
    /// Rolling evidence window in milliseconds.
    pub window_ms: u64,
    /// Health failure threshold.
    pub failure_threshold: usize,
    /// Open interval in milliseconds.
    pub open_duration_ms: u64,
    /// Maximum simultaneous half-open probes.
    pub half_open_max_probes: usize,
}

/// Live-stream state and delivery bounds.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StreamingConfig {
    /// Maximum canonical events including the terminal event.
    pub max_events: u64,
    /// Maximum distinct output parts.
    pub max_parts: usize,
    /// Maximum retained public items.
    pub max_public_items: usize,
    /// Maximum accumulated public text bytes.
    pub max_text_bytes: usize,
    /// Maximum serialized bytes for one event.
    pub max_event_bytes: usize,
    /// Finite delivery channel capacity.
    pub delivery_capacity: usize,
}

/// Structured-output validation, strategy, and repair policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StructuredOutputConfig {
    /// Maximum serialized candidate payload bytes.
    pub max_payload_bytes: usize,
    /// Maximum serialized schema bytes.
    pub max_schema_bytes: usize,
    /// Maximum JSON depth.
    pub max_depth: usize,
    /// Maximum JSON nodes.
    pub max_nodes: usize,
    /// Maximum items in one array.
    pub max_array_items: usize,
    /// Maximum properties in one object.
    pub max_object_properties: usize,
    /// Maximum UTF-8 bytes in one string.
    pub max_string_bytes: usize,
    /// Maximum validation errors retained.
    pub max_errors: usize,
    /// Permit constrained-generation fallback.
    pub allow_constrained_fallback: bool,
    /// Permit prompt-only JSON for non-strict requests.
    pub allow_prompt_json: bool,
    /// Maximum tool-free repair attempts.
    pub max_repair_attempts: u8,
    /// Retention policy for the original invalid value.
    pub invalid_value_retention: RawRetentionConfig,
}
