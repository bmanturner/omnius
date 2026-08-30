//! Provider-neutral immutable LLM routing, reliability, fallback, circuit, and readiness policy.
//!
//! Provider adapters remain responsible for protocol translation and typed provider errors. This
//! crate consumes canonical requests and evidence-backed model declarations without importing any
//! provider SDK.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::expect_used))]

mod circuit;
mod definition;
mod fallback;
mod hedge;
mod readiness;
mod retry;
mod selection;

#[cfg(test)]
mod test_support;

pub use circuit::{
    CircuitBreaker, CircuitError, CircuitEvidenceSummary, CircuitOutcome, CircuitPolicy,
    CircuitProbePermit, CircuitScope, CircuitScopeKind, CircuitState, FailureIsolation,
};
pub use definition::{
    CandidateId, CandidateLimits, CandidateRank, DataClassification, EndpointId, ObservabilityName,
    Region, Residency, RouteBuildError, RouteCandidate, RouteDefinition, RouteId, RouteLimits,
    RoutePolicy, RouteRevision, SafetyPolicyRevision, SemanticBoundary,
};
pub use fallback::{
    FallbackPolicy, FallbackPolicyError, FallbackProof, FallbackProofError, FallbackReason,
    FallbackRule, prove_fallback,
};
pub use hedge::{
    HedgeAdmission, HedgeBillingPolicy, HedgePolicy, HedgePolicyError, HedgeRejectionReason,
    LoserCancellationPolicy, admit_hedge,
};
pub use readiness::{
    RequiredRouteReadiness, RequiredRouteReadinessEvaluator, required_route_health_check,
};
pub use retry::{
    DeadlinePolicy, JitterSample, RetryContext, RetryDecision, RetryPolicy, RetryPolicyError,
    RetryStopReason, decide_retry,
};
pub use selection::{
    CandidateRejection, RejectionReason, SelectedCandidate, SelectionError, SelectionReport,
    select_candidate,
};
