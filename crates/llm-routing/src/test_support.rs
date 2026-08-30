use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, LlmInputPart, LlmMessage, LlmRequest,
    LlmRequestId, MessageRole, ModelCapability, ModelCapabilityDeclaration, ModelCapabilityKey,
    ModelCapabilityRegistry, OutputMode, OutputRequest, RequestLimits, Route, SchemaDefinition,
    ToolDefinition,
};

use crate::{
    circuit::{CircuitBreaker, CircuitPolicy},
    definition::{
        CandidateId, CandidateLimits, CandidateRank, DataClassification, EndpointId,
        ObservabilityName, Region, Residency, RouteCandidate, RouteDefinition, RouteId,
        RouteLimits, RoutePolicy, RouteRevision, SafetyPolicyRevision, SemanticBoundary,
    },
    fallback::{FallbackPolicy, FallbackRule},
    hedge::HedgePolicy,
    retry::{DeadlinePolicy, RetryPolicy},
};

pub(crate) fn candidate(
    id: &str,
    provider: &str,
    model: &str,
    residency: &str,
    quality_tier: u16,
    enabled: bool,
) -> RouteCandidate {
    let target = ModelCapabilityKey::new(provider, model, "v1")
        .expect("test model identity should be valid");
    RouteCandidate::new(
        CandidateId::new(id).expect("test candidate identity should be valid"),
        target,
        EndpointId::new("primary-endpoint").expect("test endpoint should be valid"),
        Region::new("eu-west-1").expect("test region should be valid"),
        SemanticBoundary::new(
            Residency::new(residency).expect("test residency should be valid"),
            DataClassification::Confidential,
            SafetyPolicyRevision::new("safety-v1").expect("test safety revision should be valid"),
        ),
        CandidateLimits::new(8_192, 1_024, Some(2_000_000), Some(2_000_000))
            .expect("test candidate limits should be valid"),
        CandidateRank::new(quality_tier, Duration::from_millis(100), 10)
            .expect("test candidate rank should be valid"),
        enabled,
    )
    .expect("test candidate should be valid")
}

pub(crate) fn route_definition(
    candidates: Vec<RouteCandidate>,
    required: BTreeSet<ModelCapability>,
    preferred: BTreeSet<ModelCapability>,
    fallback_rules: Vec<FallbackRule>,
) -> RouteDefinition {
    let deadlines = DeadlinePolicy::new(
        Duration::from_millis(100),
        Duration::from_millis(500),
        Duration::from_secs(1),
        Duration::from_secs(10),
        Duration::from_secs(2),
    )
    .expect("test deadlines should be valid");
    let retry = RetryPolicy::new(
        3,
        Duration::from_millis(50),
        Duration::from_secs(1),
        5_000,
        deadlines,
    )
    .expect("test retry policy should be valid");
    let limits = RouteLimits::new(4_096, 512, Some(1_000_000), Some(1_000_000), Some(100))
        .expect("test route limits should be valid");
    let policy = RoutePolicy::new(
        true,
        required,
        preferred,
        Residency::new("eu-only").expect("test residency should be valid"),
        DataClassification::Confidential,
        Duration::from_secs(1),
        limits,
        retry,
        FallbackPolicy::new(fallback_rules).expect("test fallback policy should be valid"),
        HedgePolicy::default(),
    )
    .expect("test route policy should be valid");
    RouteDefinition::new(
        RouteId::new("route-a").expect("test route identity should be valid"),
        RouteRevision::new(7).expect("test route revision should be valid"),
        ObservabilityName::new("route-a-observable")
            .expect("test observability name should be valid"),
        policy,
        candidates,
    )
    .expect("test route definition should be valid")
}

pub(crate) fn registry<const N: usize>(
    declarations: [(&str, &str, &[ModelCapability]); N],
) -> ModelCapabilityRegistry {
    let declarations = declarations
        .into_iter()
        .map(|(provider, model, capabilities)| {
            let evidence = capabilities
                .iter()
                .copied()
                .map(|capability| {
                    (
                        capability,
                        CapabilityEvidence::new(
                            CapabilityEvidenceSource::Configured,
                            "evidence-v1",
                        )
                        .expect("test evidence should be valid"),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            ModelCapabilityDeclaration::new(
                ModelCapabilityKey::new(provider, model, "v1")
                    .expect("test model identity should be valid"),
                "registry-v1",
                evidence,
                BTreeSet::from(["eu-west-1".to_owned()]),
                Some(8_192),
                Some(1_024),
            )
            .expect("test declaration should be valid")
        });
    ModelCapabilityRegistry::new(declarations).expect("test registry should be valid")
}

pub(crate) fn text_request(route_id: &str, revision: u64) -> LlmRequest {
    let route = Route::new(route_id.to_owned(), Some(revision), Vec::new(), Vec::new())
        .expect("test core route should be valid");
    let message = LlmMessage::new(
        MessageRole::User,
        vec![LlmInputPart::text("sensitive prompt".to_owned())],
    )
    .expect("test message should be valid");
    let request_id =
        LlmRequestId::new("request-a".to_owned()).expect("test request id should be valid");
    LlmRequest::new(
        request_id,
        route,
        vec![message],
        OutputRequest::new(OutputMode::Text),
        RequestLimits::new(10_000, 1, 4).expect("test request limits should be valid"),
    )
    .expect("test request should be valid")
}

pub(crate) fn strict_structured_request(route_id: &str, revision: u64) -> LlmRequest {
    let route = Route::new(route_id.to_owned(), Some(revision), Vec::new(), Vec::new())
        .expect("test core route should be valid");
    let message = LlmMessage::new(
        MessageRole::User,
        vec![LlmInputPart::text("sensitive prompt".to_owned())],
    )
    .expect("test message should be valid");
    let output = OutputRequest::new(OutputMode::Structured)
        .with_schema(None, Some(SchemaDefinition::Boolean(true)), Some(true))
        .expect("test structured output should be valid");
    let request_id =
        LlmRequestId::new("request-a".to_owned()).expect("test request id should be valid");
    LlmRequest::new(
        request_id,
        route,
        vec![message],
        output,
        RequestLimits::new(10_000, 1, 4).expect("test request limits should be valid"),
    )
    .expect("test request should be valid")
}

pub(crate) fn request_with_tools(route_id: &str, revision: u64) -> LlmRequest {
    let tool = ToolDefinition::new(
        "write-side-effect".to_owned(),
        SchemaDefinition::Boolean(true),
    )
    .expect("test tool should be valid");
    text_request(route_id, revision)
        .with_tools(vec![tool], None)
        .expect("test request tools should be valid")
}

pub(crate) fn circuit_breaker() -> CircuitBreaker {
    CircuitBreaker::new(CircuitPolicy::default())
}
