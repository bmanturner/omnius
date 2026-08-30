use std::{collections::BTreeSet, fmt, num::NonZeroU64, sync::Arc, time::Duration};

use omnius_llm_core::{ModelCapability, ModelCapabilityKey};
use thiserror::Error;

use crate::{
    circuit::CircuitScope, fallback::FallbackPolicy, hedge::HedgePolicy, retry::RetryPolicy,
};

const MAX_ID_BYTES: usize = 128;
const MAX_CANDIDATES: usize = 65_535;

macro_rules! bounded_identifier {
    ($(#[$metadata:meta])* $name:ident) => {
        $(#[$metadata])*
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Creates a bounded routing identifier.
            ///
            /// # Errors
            ///
            /// Returns [`RouteBuildError::InvalidIdentifier`] when the identifier is empty,
            /// oversized, or contains unsupported characters.
            pub fn new(value: impl Into<String>) -> Result<Self, RouteBuildError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Borrows the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

bounded_identifier!(
    /// Stable logical route identity requested by application code.
    RouteId
);
bounded_identifier!(
    /// Stable identity of one configured route candidate.
    CandidateId
);
bounded_identifier!(
    /// Redacted observability identity for one logical route.
    ObservabilityName
);
bounded_identifier!(
    /// Provider-neutral configured endpoint identity.
    EndpointId
);
bounded_identifier!(
    /// Provider region used for capability and circuit isolation.
    Region
);
bounded_identifier!(
    /// Required data-residency boundary.
    Residency
);
bounded_identifier!(
    /// Immutable safety policy revision applied by a candidate.
    SafetyPolicyRevision
);

/// Positive immutable route configuration revision.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub struct RouteRevision(NonZeroU64);

impl RouteRevision {
    /// Creates a positive route revision.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::InvalidRevision`] for zero.
    pub const fn new(value: u64) -> Result<Self, RouteBuildError> {
        match NonZeroU64::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(RouteBuildError::InvalidRevision),
        }
    }

    /// Returns the positive numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

impl fmt::Debug for RouteRevision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("RouteRevision")
            .field(&self.get())
            .finish()
    }
}

/// Ordered data classification handled by a route candidate.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum DataClassification {
    /// Public data.
    Public,
    /// Internal non-public data.
    Internal,
    /// Confidential data.
    Confidential,
    /// Most restricted supported data class.
    Restricted,
}

/// Exact data and safety guarantees attached to one candidate.
#[derive(Clone, Eq, PartialEq)]
pub struct SemanticBoundary {
    residency: Residency,
    max_classification: DataClassification,
    safety_policy_revision: SafetyPolicyRevision,
}

impl SemanticBoundary {
    /// Creates exact candidate semantic guarantees.
    #[must_use]
    pub const fn new(
        residency: Residency,
        max_classification: DataClassification,
        safety_policy_revision: SafetyPolicyRevision,
    ) -> Self {
        Self {
            residency,
            max_classification,
            safety_policy_revision,
        }
    }

    /// Returns the candidate data residency.
    #[must_use]
    pub const fn residency(&self) -> &Residency {
        &self.residency
    }

    /// Returns the highest admitted data classification.
    #[must_use]
    pub const fn max_classification(&self) -> DataClassification {
        self.max_classification
    }

    /// Returns the exact safety policy revision.
    #[must_use]
    pub const fn safety_policy_revision(&self) -> &SafetyPolicyRevision {
        &self.safety_policy_revision
    }
}

impl fmt::Debug for SemanticBoundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SemanticBoundary")
            .field("residency", &"[REDACTED]")
            .field("max_classification", &self.max_classification)
            .field("safety_policy_revision", &"[REDACTED]")
            .finish()
    }
}

/// Hard capacities guaranteed by one configured candidate.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateLimits {
    max_context_tokens: u64,
    max_output_tokens: u64,
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
}

impl CandidateLimits {
    /// Creates exact candidate capacities.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::InvalidLimit`] for any declared zero capacity.
    pub const fn new(
        max_context_tokens: u64,
        max_output_tokens: u64,
        max_input_bytes: Option<u64>,
        max_output_bytes: Option<u64>,
    ) -> Result<Self, RouteBuildError> {
        if max_context_tokens == 0
            || max_output_tokens == 0
            || matches!(max_input_bytes, Some(0))
            || matches!(max_output_bytes, Some(0))
        {
            return Err(RouteBuildError::InvalidLimit);
        }
        Ok(Self {
            max_context_tokens,
            max_output_tokens,
            max_input_bytes,
            max_output_bytes,
        })
    }

    /// Returns the maximum supported context tokens.
    #[must_use]
    pub const fn max_context_tokens(self) -> u64 {
        self.max_context_tokens
    }

    /// Returns the maximum supported output tokens.
    #[must_use]
    pub const fn max_output_tokens(self) -> u64 {
        self.max_output_tokens
    }

    /// Returns the maximum input bytes when explicitly bounded.
    #[must_use]
    pub const fn max_input_bytes(self) -> Option<u64> {
        self.max_input_bytes
    }

    /// Returns the maximum output bytes when explicitly bounded.
    #[must_use]
    pub const fn max_output_bytes(self) -> Option<u64> {
        self.max_output_bytes
    }

    /// Reports whether every source capacity is preserved or increased.
    #[must_use]
    pub fn covers(self, source: Self) -> bool {
        self.max_context_tokens >= source.max_context_tokens
            && self.max_output_tokens >= source.max_output_tokens
            && optional_capacity_covers(self.max_input_bytes, source.max_input_bytes)
            && optional_capacity_covers(self.max_output_bytes, source.max_output_bytes)
    }
}

/// Explicit deterministic candidate ranking inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateRank {
    quality_tier: u16,
    expected_latency: Duration,
    estimated_cost_microunits: u64,
}

impl CandidateRank {
    /// Creates explicit stable ranking inputs.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::InvalidLimit`] when expected latency is zero.
    pub const fn new(
        quality_tier: u16,
        expected_latency: Duration,
        estimated_cost_microunits: u64,
    ) -> Result<Self, RouteBuildError> {
        if expected_latency.is_zero() {
            return Err(RouteBuildError::InvalidLimit);
        }
        Ok(Self {
            quality_tier,
            expected_latency,
            estimated_cost_microunits,
        })
    }

    /// Returns the explicit quality tier; larger values rank first.
    #[must_use]
    pub const fn quality_tier(self) -> u16 {
        self.quality_tier
    }

    /// Returns declared expected latency; smaller values rank first.
    #[must_use]
    pub const fn expected_latency(self) -> Duration {
        self.expected_latency
    }

    /// Returns estimated cost; smaller values rank first.
    #[must_use]
    pub const fn estimated_cost_microunits(self) -> u64 {
        self.estimated_cost_microunits
    }
}

/// One immutable allowed provider/model candidate.
#[derive(Clone)]
pub struct RouteCandidate {
    id: CandidateId,
    target: ModelCapabilityKey,
    endpoint: EndpointId,
    region: Region,
    boundary: SemanticBoundary,
    limits: CandidateLimits,
    rank: CandidateRank,
    enabled: bool,
    circuit_scopes: [CircuitScope; 4],
}

impl RouteCandidate {
    /// Creates one provider-neutral candidate declaration.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::InvalidCircuitScope`] if a core model identity cannot form a
    /// bounded circuit key.
    #[expect(
        clippy::too_many_arguments,
        reason = "candidate declarations keep independent hard-policy fields explicit"
    )]
    pub fn new(
        id: CandidateId,
        target: ModelCapabilityKey,
        endpoint: EndpointId,
        region: Region,
        boundary: SemanticBoundary,
        limits: CandidateLimits,
        rank: CandidateRank,
        enabled: bool,
    ) -> Result<Self, RouteBuildError> {
        let circuit_scopes = CircuitScope::for_candidate(&target, &endpoint, &region)
            .map_err(|_| RouteBuildError::InvalidCircuitScope)?;
        Ok(Self {
            id,
            target,
            endpoint,
            region,
            boundary,
            limits,
            rank,
            enabled,
            circuit_scopes,
        })
    }

    /// Returns the configured candidate identity.
    #[must_use]
    pub const fn id(&self) -> &CandidateId {
        &self.id
    }

    /// Returns the exact provider/model/revision registry key.
    #[must_use]
    pub const fn target(&self) -> &ModelCapabilityKey {
        &self.target
    }

    /// Returns the configured endpoint identity.
    #[must_use]
    pub const fn endpoint(&self) -> &EndpointId {
        &self.endpoint
    }

    /// Returns the provider region.
    #[must_use]
    pub const fn region(&self) -> &Region {
        &self.region
    }

    /// Returns exact residency, classification, and safety guarantees.
    #[must_use]
    pub const fn boundary(&self) -> &SemanticBoundary {
        &self.boundary
    }

    /// Returns candidate hard capacities.
    #[must_use]
    pub const fn limits(&self) -> CandidateLimits {
        self.limits
    }

    /// Returns explicit deterministic ranking inputs.
    #[must_use]
    pub const fn rank(&self) -> CandidateRank {
        self.rank
    }

    /// Reports whether configuration currently enables this candidate.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns provider, endpoint, region, and exact-model circuit keys in that order.
    #[must_use]
    pub const fn circuit_scopes(&self) -> &[CircuitScope; 4] {
        &self.circuit_scopes
    }
}

impl fmt::Debug for RouteCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteCandidate")
            .field("identity", &"[REDACTED]")
            .field("target", &"[REDACTED]")
            .field("endpoint", &"[REDACTED]")
            .field("region", &"[REDACTED]")
            .field("boundary", &self.boundary)
            .field("limits", &self.limits)
            .field("rank", &self.rank)
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}

/// Route-owned hard limits and budget ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteLimits {
    minimum_context_tokens: u64,
    required_output_tokens: u64,
    max_input_bytes: Option<u64>,
    max_output_bytes: Option<u64>,
    max_cost_microunits: Option<u64>,
}

impl RouteLimits {
    /// Creates route capacity requirements and optional budget.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::InvalidLimit`] for a zero token or byte requirement. A zero cost
    /// ceiling is valid and intentionally excludes every non-free candidate.
    pub const fn new(
        minimum_context_tokens: u64,
        required_output_tokens: u64,
        max_input_bytes: Option<u64>,
        max_output_bytes: Option<u64>,
        max_cost_microunits: Option<u64>,
    ) -> Result<Self, RouteBuildError> {
        if minimum_context_tokens == 0
            || required_output_tokens == 0
            || matches!(max_input_bytes, Some(0))
            || matches!(max_output_bytes, Some(0))
        {
            return Err(RouteBuildError::InvalidLimit);
        }
        Ok(Self {
            minimum_context_tokens,
            required_output_tokens,
            max_input_bytes,
            max_output_bytes,
            max_cost_microunits,
        })
    }

    /// Returns the minimum context capacity.
    #[must_use]
    pub const fn minimum_context_tokens(self) -> u64 {
        self.minimum_context_tokens
    }

    /// Returns the required output token capacity.
    #[must_use]
    pub const fn required_output_tokens(self) -> u64 {
        self.required_output_tokens
    }

    /// Returns the optional input byte requirement.
    #[must_use]
    pub const fn max_input_bytes(self) -> Option<u64> {
        self.max_input_bytes
    }

    /// Returns the optional output byte requirement.
    #[must_use]
    pub const fn max_output_bytes(self) -> Option<u64> {
        self.max_output_bytes
    }

    /// Returns the optional estimated cost ceiling.
    #[must_use]
    pub const fn max_cost_microunits(self) -> Option<u64> {
        self.max_cost_microunits
    }
}

/// Immutable logical-route policy shared by every candidate.
#[derive(Clone)]
pub struct RoutePolicy {
    required_route: bool,
    required_capabilities: BTreeSet<ModelCapability>,
    preferred_capabilities: BTreeSet<ModelCapability>,
    residency: Residency,
    data_classification: DataClassification,
    latency_target: Duration,
    limits: RouteLimits,
    retry: RetryPolicy,
    fallback: FallbackPolicy,
    hedge: HedgePolicy,
}

impl RoutePolicy {
    /// Creates hard route policy and reliability controls.
    ///
    /// # Errors
    ///
    /// Returns [`RouteBuildError::OverlappingCapabilities`] when a capability is both hard and
    /// preferred, or [`RouteBuildError::InvalidLimit`] for zero latency.
    #[expect(
        clippy::too_many_arguments,
        reason = "route policy construction must make every immutable policy dimension explicit"
    )]
    pub fn new(
        required_route: bool,
        required_capabilities: BTreeSet<ModelCapability>,
        preferred_capabilities: BTreeSet<ModelCapability>,
        residency: Residency,
        data_classification: DataClassification,
        latency_target: Duration,
        limits: RouteLimits,
        retry: RetryPolicy,
        fallback: FallbackPolicy,
        hedge: HedgePolicy,
    ) -> Result<Self, RouteBuildError> {
        if !required_capabilities.is_disjoint(&preferred_capabilities) {
            return Err(RouteBuildError::OverlappingCapabilities);
        }
        if latency_target.is_zero() {
            return Err(RouteBuildError::InvalidLimit);
        }
        Ok(Self {
            required_route,
            required_capabilities,
            preferred_capabilities,
            residency,
            data_classification,
            latency_target,
            limits,
            retry,
            fallback,
            hedge,
        })
    }

    /// Reports whether this route is process-readiness-critical.
    #[must_use]
    pub const fn is_required_route(&self) -> bool {
        self.required_route
    }

    /// Returns hard route capabilities.
    #[must_use]
    pub const fn required_capabilities(&self) -> &BTreeSet<ModelCapability> {
        &self.required_capabilities
    }

    /// Returns soft capabilities used only during ranking.
    #[must_use]
    pub const fn preferred_capabilities(&self) -> &BTreeSet<ModelCapability> {
        &self.preferred_capabilities
    }

    /// Returns the hard residency boundary.
    #[must_use]
    pub const fn residency(&self) -> &Residency {
        &self.residency
    }

    /// Returns the request data classification.
    #[must_use]
    pub const fn data_classification(&self) -> DataClassification {
        self.data_classification
    }

    /// Returns the hard latency target.
    #[must_use]
    pub const fn latency_target(&self) -> Duration {
        self.latency_target
    }

    /// Returns route capacities and budget.
    #[must_use]
    pub const fn limits(&self) -> RouteLimits {
        self.limits
    }

    /// Returns timeout and retry policy.
    #[must_use]
    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    /// Returns declared fallback edges.
    #[must_use]
    pub const fn fallback(&self) -> &FallbackPolicy {
        &self.fallback
    }

    /// Returns the default-off hedge policy.
    #[must_use]
    pub const fn hedge(&self) -> HedgePolicy {
        self.hedge
    }
}

impl fmt::Debug for RoutePolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RoutePolicy")
            .field("required_route", &self.required_route)
            .field(
                "required_capability_count",
                &self.required_capabilities.len(),
            )
            .field(
                "preferred_capability_count",
                &self.preferred_capabilities.len(),
            )
            .field("residency", &"[REDACTED]")
            .field("data_classification", &self.data_classification)
            .field("latency_target", &self.latency_target)
            .field("limits", &self.limits)
            .field("retry", &self.retry)
            .field("fallback_rule_count", &self.fallback.rules().len())
            .field("hedge", &self.hedge)
            .finish()
    }
}

/// Immutable exact revision of a logical LLM route.
#[derive(Clone)]
pub struct RouteDefinition {
    id: RouteId,
    revision: RouteRevision,
    observability_name: ObservabilityName,
    policy: RoutePolicy,
    candidates: Arc<[RouteCandidate]>,
}

impl RouteDefinition {
    /// Creates an immutable route revision and validates its candidate/fallback graph.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`RouteBuildError`] for empty/duplicate candidates, excessive
    /// candidate count, or fallback edges outside this exact revision.
    pub fn new(
        id: RouteId,
        revision: RouteRevision,
        observability_name: ObservabilityName,
        policy: RoutePolicy,
        candidates: Vec<RouteCandidate>,
    ) -> Result<Self, RouteBuildError> {
        if candidates.is_empty() {
            return Err(RouteBuildError::EmptyCandidates);
        }
        if candidates.len() > MAX_CANDIDATES {
            return Err(RouteBuildError::TooManyCandidates);
        }
        let mut ids = BTreeSet::new();
        if candidates
            .iter()
            .any(|candidate| !ids.insert(candidate.id().clone()))
        {
            return Err(RouteBuildError::DuplicateCandidate);
        }
        if policy
            .fallback()
            .rules()
            .iter()
            .any(|rule| !ids.contains(rule.from()) || !ids.contains(rule.to()))
        {
            return Err(RouteBuildError::UnknownFallbackCandidate);
        }
        Ok(Self {
            id,
            revision,
            observability_name,
            policy,
            candidates: candidates.into(),
        })
    }

    /// Returns the stable route identity.
    #[must_use]
    pub const fn id(&self) -> &RouteId {
        &self.id
    }

    /// Returns the exact positive configuration revision.
    #[must_use]
    pub const fn revision(&self) -> RouteRevision {
        self.revision
    }

    /// Returns the redacted observability name.
    #[must_use]
    pub const fn observability_name(&self) -> &ObservabilityName {
        &self.observability_name
    }

    /// Returns route policy.
    #[must_use]
    pub const fn policy(&self) -> &RoutePolicy {
        &self.policy
    }

    /// Returns ordered candidates. Configuration order is the final stable ranking tie-breaker.
    #[must_use]
    pub fn candidates(&self) -> &[RouteCandidate] {
        &self.candidates
    }

    /// Returns one candidate by its stable configured identity.
    #[must_use]
    pub fn candidate(&self, id: &CandidateId) -> Option<&RouteCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.id() == id)
    }

    /// Returns declared fallback policy.
    #[must_use]
    pub const fn fallback_policy(&self) -> &FallbackPolicy {
        self.policy.fallback()
    }
}

impl fmt::Debug for RouteDefinition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RouteDefinition")
            .field("identity", &"[REDACTED]")
            .field("revision", &self.revision)
            .field("observability_name", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("candidate_count", &self.candidates.len())
            .finish_non_exhaustive()
    }
}

/// Value-free route definition validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RouteBuildError {
    /// A routing identifier is empty, oversized, or contains unsupported characters.
    #[error("routing identifier is invalid")]
    InvalidIdentifier,
    /// Route revision zero is invalid.
    #[error("route revision is invalid")]
    InvalidRevision,
    /// A token, byte, latency, or capacity bound is invalid.
    #[error("route limit is invalid")]
    InvalidLimit,
    /// A capability cannot be both hard-required and preferred.
    #[error("route capabilities overlap")]
    OverlappingCapabilities,
    /// A route must contain at least one candidate.
    #[error("route candidates are empty")]
    EmptyCandidates,
    /// Candidate count exceeds the bounded evidence index.
    #[error("route has too many candidates")]
    TooManyCandidates,
    /// Candidate identities must be unique within a revision.
    #[error("route candidate is duplicated")]
    DuplicateCandidate,
    /// A fallback edge names a candidate outside the exact route revision.
    #[error("fallback candidate is unknown")]
    UnknownFallbackCandidate,
    /// A core model identity cannot form a safe bounded circuit scope.
    #[error("route circuit scope is invalid")]
    InvalidCircuitScope,
}

fn validate_identifier(value: &str) -> Result<(), RouteBuildError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RouteBuildError::InvalidIdentifier);
    }
    Ok(())
}

const fn optional_capacity_covers(target: Option<u64>, source: Option<u64>) -> bool {
    match (target, source) {
        (_, None) => true,
        (Some(target), Some(source)) => target >= source,
        (None, Some(_)) => false,
    }
}
