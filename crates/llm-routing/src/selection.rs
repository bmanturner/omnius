use std::{
    cmp::{Ordering, Reverse},
    collections::BTreeSet,
    fmt,
    sync::Arc,
    time::Instant,
};

use omnius_llm_core::{
    CapabilityRegistryError, LlmInputPart, LlmRequest, ModelCapability, ModelCapabilityAdmission,
    ModelCapabilityRegistry, ModelCapabilityRequirements, OutputMode,
};
use thiserror::Error;

use crate::{
    circuit::{CircuitBreaker, CircuitOutcome, CircuitProbePermit, CircuitScopeKind, CircuitState},
    definition::{CandidateId, RouteCandidate, RouteDefinition},
};

/// Stable, value-free hard-filter rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    /// Configuration disabled the candidate.
    Disabled,
    /// Candidate data residency differs from route policy.
    ResidencyMismatch,
    /// Candidate classification admission is too weak.
    ClassificationUnsupported,
    /// Declared candidate latency exceeds the hard route target.
    LatencyTargetExceeded,
    /// Candidate context capacity is too small.
    ContextCapacityInsufficient,
    /// Candidate output-token capacity is too small.
    OutputTokenCapacityInsufficient,
    /// Candidate input-byte capacity is absent or too small.
    InputByteCapacityInsufficient,
    /// Candidate output-byte capacity is absent or too small.
    OutputByteCapacityInsufficient,
    /// Candidate estimated cost exceeds the effective request/route budget.
    BudgetExceeded,
    /// The canonical request contains an unknown hard capability or ambiguous modality.
    UnsupportedRequestSemantics,
    /// The exact provider/model/revision has no evidence-backed declaration.
    CapabilityDeclarationMissing,
    /// One or more hard capabilities are absent.
    RequiredCapabilityUnavailable,
    /// The exact declaration is unavailable in the candidate region.
    CapabilityRegionUnavailable,
    /// Registry token limits do not satisfy the request.
    CapabilityLimitsInsufficient,
    /// One scope-specific circuit is open.
    CircuitUnavailable(CircuitScopeKind),
}

/// Ordered rejection evidence for one configured candidate position.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateRejection {
    candidate_position: u16,
    reasons: Arc<[RejectionReason]>,
}

impl CandidateRejection {
    /// Returns the stable candidate position in the exact route revision.
    #[must_use]
    pub const fn candidate_position(&self) -> u16 {
        self.candidate_position
    }

    /// Returns deterministic ordered hard-filter reasons.
    #[must_use]
    pub fn reasons(&self) -> &[RejectionReason] {
        &self.reasons
    }
}

/// Selected candidate and capability evidence revision.
pub struct SelectedCandidate {
    candidate_position: u16,
    candidate_id: CandidateId,
    capability_registry_revision: String,
    unmet_preferred_count: usize,
    probe_permit: CircuitProbePermit,
}

impl SelectedCandidate {
    /// Returns the candidate configuration position.
    #[must_use]
    pub const fn candidate_position(&self) -> u16 {
        self.candidate_position
    }

    /// Returns the selected stable candidate identity for dispatch lookup.
    #[must_use]
    pub const fn candidate_id(&self) -> &CandidateId {
        &self.candidate_id
    }

    /// Returns the capability registry revision that admitted the exact target.
    #[must_use]
    pub fn capability_registry_revision(&self) -> &str {
        &self.capability_registry_revision
    }

    /// Returns the count of unmet soft preferences used only during ranking.
    #[must_use]
    pub const fn unmet_preferred_count(&self) -> usize {
        self.unmet_preferred_count
    }

    /// Returns whether dispatch owns at least one half-open recovery probe.
    #[must_use]
    pub fn has_half_open_probe(&self) -> bool {
        self.probe_permit.is_required()
    }

    /// Completes every owned half-open recovery probe with the dispatch outcome.
    pub fn complete_probe(&mut self, observed_at: Instant, outcome: CircuitOutcome) {
        self.probe_permit.complete(observed_at, outcome);
    }

    /// Releases every owned half-open recovery probe without recording an outcome.
    pub fn release_probe(&mut self) {
        self.probe_permit.release();
    }
}

impl fmt::Debug for SelectedCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectedCandidate")
            .field("candidate_position", &self.candidate_position)
            .field("candidate_id", &"[REDACTED]")
            .field(
                "capability_registry_revision",
                &self.capability_registry_revision,
            )
            .field("unmet_preferred_count", &self.unmet_preferred_count)
            .field("has_half_open_probe", &self.has_half_open_probe())
            .finish_non_exhaustive()
    }
}

/// Complete deterministic routing report, including every hard-filtered candidate.
#[derive(Debug)]
pub struct SelectionReport {
    selected: Option<SelectedCandidate>,
    rejections: Arc<[CandidateRejection]>,
}

impl SelectionReport {
    /// Returns the selected candidate, or `None` when hard filtering removed every candidate.
    #[must_use]
    pub const fn selected(&self) -> Option<&SelectedCandidate> {
        self.selected.as_ref()
    }

    /// Consumes the report and returns the selected candidate with its owned probe reservation.
    #[must_use]
    pub fn into_selected(self) -> Option<SelectedCandidate> {
        self.selected
    }

    /// Returns ordered redacted rejection evidence.
    #[must_use]
    pub fn rejections(&self) -> &[CandidateRejection] {
        &self.rejections
    }
}

/// Selects from one immutable route revision.
///
/// Every candidate is completely hard-filtered before the first ranking comparison. Soft
/// capabilities affect only the ranking key. Final ties resolve by candidate configuration order.
///
/// # Errors
///
/// Returns [`SelectionError`] when the canonical request names a different route or does not pin
/// the exact route revision.
pub fn select_candidate(
    route: &RouteDefinition,
    request: &LlmRequest,
    registry: &ModelCapabilityRegistry,
    circuits: &CircuitBreaker,
    now: Instant,
) -> Result<SelectionReport, SelectionError> {
    validate_request_route(route, request)?;
    let requirements = RequestRequirements::for_request(route, request);
    let mut eligible = Vec::with_capacity(route.candidates().len());
    let mut rejections = Vec::new();

    for (position, candidate) in route.candidates().iter().enumerate() {
        let Ok(position) = u16::try_from(position) else {
            unreachable!("validated route candidate positions fit in u16")
        };
        let evaluation = evaluate_candidate(
            route,
            candidate,
            &requirements,
            registry,
            Some((circuits, now)),
        );
        if evaluation.reasons.is_empty() {
            if let Some(admission) = evaluation.admission {
                eligible.push(EligibleCandidate {
                    position,
                    candidate,
                    admission,
                    unknown_preferred_count: requirements.unknown_preferred_count,
                    health_penalty: evaluation.health_penalty,
                });
            }
        } else {
            rejections.push(CandidateRejection {
                candidate_position: position,
                reasons: evaluation.reasons.into(),
            });
        }
    }

    eligible.sort_by(compare_eligible);
    let mut selected = None;
    for eligible in eligible {
        if let Some(probe_permit) =
            circuits.try_acquire_candidate(eligible.candidate.circuit_scopes(), now)
        {
            selected = Some(SelectedCandidate {
                candidate_position: eligible.position,
                candidate_id: eligible.candidate.id().clone(),
                capability_registry_revision: eligible.admission.registry_revision().to_owned(),
                unmet_preferred_count: eligible
                    .admission
                    .unmet_preferred()
                    .len()
                    .saturating_add(eligible.unknown_preferred_count),
                probe_permit,
            });
            break;
        }
        let unavailable_kind = eligible
            .candidate
            .circuit_scopes()
            .iter()
            .zip(circuits.candidate_states(eligible.candidate.circuit_scopes(), now))
            .find_map(|(scope, state)| (state != CircuitState::Closed).then_some(scope.kind()))
            .unwrap_or(CircuitScopeKind::Provider);
        rejections.push(CandidateRejection {
            candidate_position: eligible.position,
            reasons: Arc::from([RejectionReason::CircuitUnavailable(unavailable_kind)]),
        });
    }
    rejections.sort_by_key(CandidateRejection::candidate_position);

    Ok(SelectionReport {
        selected,
        rejections: rejections.into(),
    })
}

pub(crate) fn validate_request_route(
    route: &RouteDefinition,
    request: &LlmRequest,
) -> Result<(), SelectionError> {
    if request.route().id() != route.id().as_str() {
        return Err(SelectionError::RouteIdentityMismatch);
    }
    let Some(revision) = request.route().revision() else {
        return Err(SelectionError::RouteRevisionRequired);
    };
    if revision != route.revision().get() {
        return Err(SelectionError::RouteRevisionMismatch);
    }
    Ok(())
}

pub(crate) fn admit_candidate_without_circuit(
    route: &RouteDefinition,
    request: &LlmRequest,
    candidate: &RouteCandidate,
    registry: &ModelCapabilityRegistry,
) -> Result<ModelCapabilityAdmission, CandidateAdmissionError> {
    let requirements = RequestRequirements::for_request(route, request);
    let evaluation = evaluate_candidate(route, candidate, &requirements, registry, None);
    if evaluation.reasons.is_empty() {
        evaluation
            .admission
            .ok_or(CandidateAdmissionError::Ineligible)
    } else {
        Err(CandidateAdmissionError::Ineligible)
    }
}

pub(crate) fn candidate_available_for_readiness(
    route: &RouteDefinition,
    candidate: &RouteCandidate,
    registry: &ModelCapabilityRegistry,
    circuits: &CircuitBreaker,
    now: Instant,
) -> bool {
    if circuits
        .candidate_states(candidate.circuit_scopes(), now)
        .iter()
        .any(|state| *state != CircuitState::Closed)
    {
        return false;
    }
    let requirements = RequestRequirements::for_route(route);
    evaluate_candidate(route, candidate, &requirements, registry, None)
        .reasons
        .is_empty()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CandidateAdmissionError {
    Ineligible,
}

struct RequestRequirements {
    required_capabilities: BTreeSet<ModelCapability>,
    preferred_capabilities: BTreeSet<ModelCapability>,
    unknown_required: bool,
    unknown_preferred_count: usize,
    strict_structured_output: bool,
    minimum_context_tokens: u64,
    required_output_tokens: u64,
    required_input_bytes: Option<u64>,
    required_output_bytes: Option<u64>,
    max_cost_microunits: Option<u64>,
}

impl RequestRequirements {
    fn for_route(route: &RouteDefinition) -> Self {
        let limits = route.policy().limits();
        let mut required_capabilities = route.policy().required_capabilities().clone();
        required_capabilities.insert(ModelCapability::TextInput);
        Self {
            required_capabilities,
            preferred_capabilities: route.policy().preferred_capabilities().clone(),
            unknown_required: false,
            unknown_preferred_count: 0,
            strict_structured_output: false,
            minimum_context_tokens: limits.minimum_context_tokens(),
            required_output_tokens: limits.required_output_tokens(),
            required_input_bytes: limits.max_input_bytes(),
            required_output_bytes: limits.max_output_bytes(),
            max_cost_microunits: limits.max_cost_microunits(),
        }
    }

    fn for_request(route: &RouteDefinition, request: &LlmRequest) -> Self {
        let mut requirements = Self::for_route(route);
        for capability in request.route().required_capabilities() {
            if let Some(capability) = parse_capability(capability) {
                requirements.required_capabilities.insert(capability);
            } else {
                requirements.unknown_required = true;
            }
        }
        for capability in request.route().preferred_capabilities() {
            if let Some(capability) = parse_capability(capability) {
                requirements.preferred_capabilities.insert(capability);
            } else {
                requirements.unknown_preferred_count += 1;
            }
        }
        derive_request_semantics(request, &mut requirements);
        {
            let RequestRequirements {
                required_capabilities,
                preferred_capabilities,
                ..
            } = &mut requirements;
            preferred_capabilities.retain(|capability| !required_capabilities.contains(capability));
        }

        if let Some(output_tokens) = request
            .generation()
            .and_then(omnius_llm_core::GenerationConfig::max_output_tokens)
        {
            requirements.required_output_tokens =
                requirements.required_output_tokens.max(output_tokens);
        }
        let request_limits = request.limits();
        requirements.required_input_bytes = max_optional(
            requirements.required_input_bytes,
            request_limits.max_input_bytes(),
        );
        requirements.required_output_bytes = max_optional(
            requirements.required_output_bytes,
            request_limits.max_output_bytes(),
        );
        requirements.max_cost_microunits = min_optional(
            requirements.max_cost_microunits,
            request_limits.max_cost_microunits(),
        );
        requirements
    }
}

struct CandidateEvaluation {
    reasons: Vec<RejectionReason>,
    admission: Option<ModelCapabilityAdmission>,
    health_penalty: u8,
}

#[allow(clippy::too_many_lines)]
fn evaluate_candidate(
    route: &RouteDefinition,
    candidate: &RouteCandidate,
    requirements: &RequestRequirements,
    registry: &ModelCapabilityRegistry,
    circuit_context: Option<(&CircuitBreaker, Instant)>,
) -> CandidateEvaluation {
    let mut reasons = Vec::new();
    if !candidate.is_enabled() {
        reasons.push(RejectionReason::Disabled);
    }
    if candidate.boundary().residency() != route.policy().residency() {
        reasons.push(RejectionReason::ResidencyMismatch);
    }
    if candidate.boundary().max_classification() < route.policy().data_classification() {
        reasons.push(RejectionReason::ClassificationUnsupported);
    }
    if candidate.rank().expected_latency() > route.policy().latency_target() {
        reasons.push(RejectionReason::LatencyTargetExceeded);
    }
    if candidate.limits().max_context_tokens() < requirements.minimum_context_tokens {
        reasons.push(RejectionReason::ContextCapacityInsufficient);
    }
    if candidate.limits().max_output_tokens() < requirements.required_output_tokens {
        reasons.push(RejectionReason::OutputTokenCapacityInsufficient);
    }
    if !capacity_satisfies(
        candidate.limits().max_input_bytes(),
        requirements.required_input_bytes,
    ) {
        reasons.push(RejectionReason::InputByteCapacityInsufficient);
    }
    if !capacity_satisfies(
        candidate.limits().max_output_bytes(),
        requirements.required_output_bytes,
    ) {
        reasons.push(RejectionReason::OutputByteCapacityInsufficient);
    }
    if requirements
        .max_cost_microunits
        .is_some_and(|ceiling| candidate.rank().estimated_cost_microunits() > ceiling)
    {
        reasons.push(RejectionReason::BudgetExceeded);
    }
    if requirements.unknown_required {
        reasons.push(RejectionReason::UnsupportedRequestSemantics);
    }

    let mut required_capabilities = requirements.required_capabilities.clone();
    let strict_alternative_missing = if requirements.strict_structured_output {
        registry.get(candidate.target()).is_some_and(|declaration| {
            if declaration.supports(ModelCapability::StrictJsonSchema) {
                required_capabilities.insert(ModelCapability::StrictJsonSchema);
                false
            } else if declaration.supports(ModelCapability::StrictToolOutput) {
                required_capabilities.insert(ModelCapability::StrictToolOutput);
                false
            } else {
                true
            }
        })
    } else {
        false
    };
    let mut preferred_capabilities = requirements.preferred_capabilities.clone();
    preferred_capabilities.retain(|capability| !required_capabilities.contains(capability));
    let core_requirements = ModelCapabilityRequirements::new(
        required_capabilities,
        preferred_capabilities,
        Some(candidate.region().as_str().to_owned()),
        Some(requirements.minimum_context_tokens),
        Some(requirements.required_output_tokens),
    );
    let admission = if let Ok(core_requirements) = core_requirements {
        match registry.admit_exact(candidate.target(), &core_requirements) {
            Ok(admission) => Some(admission),
            Err(error) => {
                reasons.push(registry_rejection(&error));
                None
            }
        }
    } else {
        reasons.push(RejectionReason::UnsupportedRequestSemantics);
        None
    };
    if strict_alternative_missing
        && !reasons.contains(&RejectionReason::RequiredCapabilityUnavailable)
    {
        reasons.push(RejectionReason::RequiredCapabilityUnavailable);
    }

    let mut health_penalty = 0_u8;
    if let Some((circuits, now)) = circuit_context {
        for (scope, state) in candidate
            .circuit_scopes()
            .iter()
            .zip(circuits.candidate_states(candidate.circuit_scopes(), now))
        {
            match state {
                CircuitState::Closed => {}
                CircuitState::HalfOpen => health_penalty = health_penalty.saturating_add(1),
                CircuitState::Open => {
                    reasons.push(RejectionReason::CircuitUnavailable(scope.kind()));
                }
            }
        }
    }

    CandidateEvaluation {
        reasons,
        admission,
        health_penalty,
    }
}

struct EligibleCandidate<'a> {
    position: u16,
    candidate: &'a RouteCandidate,
    admission: ModelCapabilityAdmission,
    unknown_preferred_count: usize,
    health_penalty: u8,
}

fn compare_eligible(left: &EligibleCandidate<'_>, right: &EligibleCandidate<'_>) -> Ordering {
    ranking_key(left).cmp(&ranking_key(right))
}

fn ranking_key(
    candidate: &EligibleCandidate<'_>,
) -> (usize, u8, Reverse<u16>, std::time::Duration, u64, u16) {
    (
        candidate
            .admission
            .unmet_preferred()
            .len()
            .saturating_add(candidate.unknown_preferred_count),
        candidate.health_penalty,
        Reverse(candidate.candidate.rank().quality_tier()),
        candidate.candidate.rank().expected_latency(),
        candidate.candidate.rank().estimated_cost_microunits(),
        candidate.position,
    )
}

fn derive_request_semantics(request: &LlmRequest, requirements: &mut RequestRequirements) {
    requirements
        .required_capabilities
        .insert(ModelCapability::TextInput);
    for part in request
        .messages()
        .iter()
        .flat_map(omnius_llm_core::LlmMessage::content)
    {
        match part {
            LlmInputPart::Text(_) | LlmInputPart::Structured(_) => {}
            LlmInputPart::Image(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::ImageInput);
            }
            LlmInputPart::Audio(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::AudioInput);
            }
            LlmInputPart::Video(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::VideoInput);
            }
            LlmInputPart::File(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::FileInput);
            }
            LlmInputPart::Resource(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::ResourceInput);
            }
            LlmInputPart::ToolResult(_) => {
                requirements
                    .required_capabilities
                    .insert(ModelCapability::Tools);
            }
            _ => requirements.unknown_required = true,
        }
    }
    if request.tools().is_some_and(|tools| !tools.is_empty()) || request.tool_policy().is_some() {
        requirements
            .required_capabilities
            .insert(ModelCapability::Tools);
    }
    match request.output().mode() {
        OutputMode::Auto => {}
        OutputMode::Text => {
            requirements
                .required_capabilities
                .insert(ModelCapability::TextOutput);
        }
        OutputMode::Structured if request.output().strict() == Some(true) => {
            requirements.strict_structured_output = true;
        }
        OutputMode::Structured => {
            requirements
                .required_capabilities
                .insert(ModelCapability::StructuredOutput);
        }
        OutputMode::Tools => {
            requirements
                .required_capabilities
                .insert(ModelCapability::Tools);
        }
        OutputMode::Media => derive_media_output(request, requirements),
    }
}

fn derive_media_output(request: &LlmRequest, requirements: &mut RequestRequirements) {
    if request.output().mime_types().is_empty() {
        let route_declares_media = requirements.required_capabilities.iter().any(|capability| {
            matches!(
                capability,
                ModelCapability::ImageOutput
                    | ModelCapability::AudioOutput
                    | ModelCapability::VideoOutput
                    | ModelCapability::FileOutput
                    | ModelCapability::ResourceOutput
            )
        });
        requirements.unknown_required |= !route_declares_media;
        return;
    }
    for mime_type in request.output().mime_types() {
        let capability = if mime_type.starts_with("image/") {
            ModelCapability::ImageOutput
        } else if mime_type.starts_with("audio/") {
            ModelCapability::AudioOutput
        } else if mime_type.starts_with("video/") {
            ModelCapability::VideoOutput
        } else {
            ModelCapability::FileOutput
        };
        requirements.required_capabilities.insert(capability);
    }
}

fn registry_rejection(error: &CapabilityRegistryError) -> RejectionReason {
    match error {
        CapabilityRegistryError::UnknownModelRevision
        | CapabilityRegistryError::InvalidDeclaration
        | CapabilityRegistryError::InvalidRequirements
        | CapabilityRegistryError::DuplicateDeclaration => {
            RejectionReason::CapabilityDeclarationMissing
        }
        CapabilityRegistryError::UnsupportedRequirements { .. } => {
            RejectionReason::RequiredCapabilityUnavailable
        }
        CapabilityRegistryError::RegionUnavailable => RejectionReason::CapabilityRegionUnavailable,
        CapabilityRegistryError::InsufficientLimits => {
            RejectionReason::CapabilityLimitsInsufficient
        }
    }
}

fn parse_capability(value: &str) -> Option<ModelCapability> {
    Some(match value {
        "text_input" => ModelCapability::TextInput,
        "image_input" => ModelCapability::ImageInput,
        "audio_input" => ModelCapability::AudioInput,
        "video_input" => ModelCapability::VideoInput,
        "file_input" => ModelCapability::FileInput,
        "resource_input" => ModelCapability::ResourceInput,
        "text_output" => ModelCapability::TextOutput,
        "structured_output" => ModelCapability::StructuredOutput,
        "image_output" => ModelCapability::ImageOutput,
        "audio_output" => ModelCapability::AudioOutput,
        "video_output" => ModelCapability::VideoOutput,
        "file_output" => ModelCapability::FileOutput,
        "resource_output" => ModelCapability::ResourceOutput,
        "annotation_output" => ModelCapability::AnnotationOutput,
        "execution_step_output" => ModelCapability::ExecutionStepOutput,
        "strict_json_schema" => ModelCapability::StrictJsonSchema,
        "strict_tool_output" => ModelCapability::StrictToolOutput,
        "tools" => ModelCapability::Tools,
        "parallel_tool_calls" => ModelCapability::ParallelToolCalls,
        "streaming" => ModelCapability::Streaming,
        "resumable_conversations" => ModelCapability::ResumableConversations,
        "citations" => ModelCapability::Citations,
        "grounding" => ModelCapability::Grounding,
        "token_scores" => ModelCapability::TokenScores,
        "safety_metadata" => ModelCapability::SafetyMetadata,
        "search_results" => ModelCapability::SearchResults,
        "provider_executed_steps" => ModelCapability::ProviderExecutedSteps,
        "reasoning_summaries" => ModelCapability::ReasoningSummaries,
        "opaque_reasoning_state" => ModelCapability::OpaqueReasoningState,
        "embeddings" => ModelCapability::Embeddings,
        "reranking" => ModelCapability::Reranking,
        "transcription" => ModelCapability::Transcription,
        "speech_generation" => ModelCapability::SpeechGeneration,
        "image_generation" => ModelCapability::ImageGeneration,
        "video_generation" => ModelCapability::VideoGeneration,
        "prompt_caching" => ModelCapability::PromptCaching,
        "cache_controls" => ModelCapability::CacheControls,
        _ => return None,
    })
}

const fn capacity_satisfies(available: Option<u64>, required: Option<u64>) -> bool {
    match (available, required) {
        (_, None) => true,
        (Some(available), Some(required)) => available >= required,
        (None, Some(_)) => false,
    }
}

const fn max_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left > right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

const fn min_optional(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if left < right { left } else { right }),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Value-free canonical request/route mismatch.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SelectionError {
    /// The request names a different logical route.
    #[error("request route identity does not match")]
    RouteIdentityMismatch,
    /// Routing requires the request to pin a route revision.
    #[error("request route revision is required")]
    RouteRevisionRequired,
    /// The request names a different route revision.
    #[error("request route revision does not match")]
    RouteRevisionMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        candidate, circuit_breaker, registry, route_definition, strict_structured_request,
        text_request,
    };

    #[test]
    fn hard_filtering_should_run_before_ranking() {
        let candidates = vec![
            candidate(
                "bad-residency",
                "provider-a",
                "model-a",
                "other-residency",
                100,
                true,
            ),
            candidate("eligible", "provider-b", "model-b", "eu-only", 1, true),
        ];
        let route = route_definition(candidates, BTreeSet::new(), BTreeSet::new(), Vec::new());
        let registry = registry([
            (
                "provider-a",
                "model-a",
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
            (
                "provider-b",
                "model-b",
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
        ]);
        let report = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuit_breaker(),
            Instant::now(),
        )
        .expect("route should match");

        assert_eq!(
            report.selected().map(SelectedCandidate::candidate_position),
            Some(1)
        );
        assert_eq!(
            report.rejections()[0].reasons(),
            &[RejectionReason::ResidencyMismatch]
        );
    }

    #[test]
    fn preferred_capability_should_rank_without_filtering() {
        let candidates = vec![
            candidate(
                "without-preference",
                "provider-a",
                "model-a",
                "eu-only",
                100,
                true,
            ),
            candidate(
                "with-preference",
                "provider-b",
                "model-b",
                "eu-only",
                1,
                true,
            ),
        ];
        let route = route_definition(
            candidates,
            BTreeSet::new(),
            BTreeSet::from([ModelCapability::Citations]),
            Vec::new(),
        );
        let registry = registry([
            (
                "provider-a",
                "model-a",
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
            (
                "provider-b",
                "model-b",
                [
                    ModelCapability::TextInput,
                    ModelCapability::TextOutput,
                    ModelCapability::Citations,
                ]
                .as_slice(),
            ),
        ]);
        let report = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuit_breaker(),
            Instant::now(),
        )
        .expect("route should match");

        assert_eq!(
            report.selected().map(SelectedCandidate::candidate_position),
            Some(1)
        );
        assert!(report.rejections().is_empty());
    }

    #[test]
    fn strict_structured_request_should_accept_strict_tool_alternative_but_not_tools_alone() {
        let candidates = vec![
            candidate("tools-only", "provider-a", "model-a", "eu-only", 100, true),
            candidate("strict-tool", "provider-b", "model-b", "eu-only", 1, true),
        ];
        let route = route_definition(candidates, BTreeSet::new(), BTreeSet::new(), Vec::new());
        let registry = registry([
            (
                "provider-a",
                "model-a",
                [ModelCapability::TextInput, ModelCapability::Tools].as_slice(),
            ),
            (
                "provider-b",
                "model-b",
                [
                    ModelCapability::TextInput,
                    ModelCapability::StrictToolOutput,
                ]
                .as_slice(),
            ),
        ]);
        let report = select_candidate(
            &route,
            &strict_structured_request("route-a", 7),
            &registry,
            &circuit_breaker(),
            Instant::now(),
        )
        .expect("route should match");

        assert_eq!(
            report.selected().map(SelectedCandidate::candidate_position),
            Some(1)
        );
        assert_eq!(
            report.rejections()[0].reasons(),
            &[RejectionReason::RequiredCapabilityUnavailable]
        );
    }

    #[test]
    fn strict_tool_output_capability_name_should_decode_exactly() {
        assert_eq!(
            parse_capability("strict_tool_output"),
            Some(ModelCapability::StrictToolOutput)
        );
    }

    #[test]
    fn exact_ranking_tie_should_use_configuration_order() {
        let candidates = vec![
            candidate("first", "provider-a", "model-a", "eu-only", 10, true),
            candidate("second", "provider-b", "model-b", "eu-only", 10, true),
        ];
        let route = route_definition(candidates, BTreeSet::new(), BTreeSet::new(), Vec::new());
        let registry = registry([
            (
                "provider-a",
                "model-a",
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
            (
                "provider-b",
                "model-b",
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
        ]);
        let report = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuit_breaker(),
            Instant::now(),
        )
        .expect("route should match");

        assert_eq!(
            report.selected().map(SelectedCandidate::candidate_position),
            Some(0)
        );
    }

    #[test]
    fn rejection_evidence_and_debug_should_be_ordered_and_redacted() {
        let candidates = vec![candidate(
            "secret-candidate",
            "secret-provider",
            "secret-model",
            "other-residency",
            10,
            false,
        )];
        let route = route_definition(candidates, BTreeSet::new(), BTreeSet::new(), Vec::new());
        let registry = registry([(
            "secret-provider",
            "secret-model",
            [ModelCapability::TextInput].as_slice(),
        )]);
        let report = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuit_breaker(),
            Instant::now(),
        )
        .expect("route should match");

        assert_eq!(
            report.rejections()[0].reasons(),
            &[
                RejectionReason::Disabled,
                RejectionReason::ResidencyMismatch,
                RejectionReason::RequiredCapabilityUnavailable,
            ]
        );
        let rendered = format!("{report:?}");
        assert!(!rendered.contains("secret-candidate"));
        assert!(!rendered.contains("secret-provider"));
        assert!(!rendered.contains("secret-model"));
    }
    #[test]
    fn selected_candidate_should_own_and_release_half_open_probe() {
        let candidate = candidate("recovery", "provider-a", "model-a", "eu-only", 10, true);
        let provider_scope = candidate.circuit_scopes()[0].clone();
        let route = route_definition(
            vec![candidate],
            BTreeSet::new(),
            BTreeSet::new(),
            Vec::new(),
        );
        let registry = registry([(
            "provider-a",
            "model-a",
            [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
        )]);
        let circuits = circuit_breaker();
        let started = Instant::now();
        for _ in 0..5 {
            circuits
                .record(provider_scope.clone(), started, CircuitOutcome::Timeout)
                .expect("scope should fit");
        }
        let recovery = started + std::time::Duration::from_secs(30);

        let first = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuits,
            recovery,
        )
        .expect("route should match");
        assert!(
            first
                .selected()
                .is_some_and(SelectedCandidate::has_half_open_probe)
        );
        let blocked = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuits,
            recovery,
        )
        .expect("route should match");
        assert!(blocked.selected().is_none());
        drop(first);

        let mut recovered = select_candidate(
            &route,
            &text_request("route-a", 7),
            &registry,
            &circuits,
            recovery,
        )
        .expect("route should match")
        .into_selected()
        .expect("released recovery probe should be selectable");
        recovered.complete_probe(recovery, CircuitOutcome::Success);
        assert_eq!(
            circuits.state(&provider_scope, recovery),
            CircuitState::Closed
        );
    }
}
