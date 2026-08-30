use std::{fmt, sync::Arc};

use omnius_llm_core::{LlmRequest, ModelCapabilityRegistry};
use thiserror::Error;

use crate::{
    definition::{CandidateId, RouteDefinition, RouteRevision},
    selection::{admit_candidate_without_circuit, validate_request_route},
};

/// Stable operator-safe reason an explicitly compatible fallback was selected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FallbackReason {
    /// The primary provider or endpoint is unavailable.
    ProviderUnavailable,
    /// Retry policy exhausted the primary attempt budget.
    RetryExhausted,
    /// The primary is unlikely to complete inside the full deadline.
    DeadlineRisk,
    /// Scope-specific evidence opened a primary circuit.
    CircuitOpen,
}

/// One explicitly declared directed fallback edge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FallbackRule {
    from: CandidateId,
    to: CandidateId,
}

impl FallbackRule {
    /// Creates a directed fallback edge.
    ///
    /// # Errors
    ///
    /// Returns [`FallbackPolicyError::SelfFallback`] when both candidates are equal.
    pub fn new(from: CandidateId, to: CandidateId) -> Result<Self, FallbackPolicyError> {
        if from == to {
            return Err(FallbackPolicyError::SelfFallback);
        }
        Ok(Self { from, to })
    }

    /// Returns the primary candidate identity.
    #[must_use]
    pub const fn from(&self) -> &CandidateId {
        &self.from
    }

    /// Returns the fallback candidate identity.
    #[must_use]
    pub const fn to(&self) -> &CandidateId {
        &self.to
    }
}

/// Immutable declared fallback graph. Empty policy disables fallback.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FallbackPolicy {
    rules: Arc<[FallbackRule]>,
}

impl FallbackPolicy {
    /// Returns a policy with no permitted fallback edges.
    #[must_use]
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Creates a policy from unique directed edges.
    ///
    /// # Errors
    ///
    /// Returns [`FallbackPolicyError::DuplicateRule`] for a repeated edge.
    pub fn new(rules: Vec<FallbackRule>) -> Result<Self, FallbackPolicyError> {
        for (position, rule) in rules.iter().enumerate() {
            if rules[..position].contains(rule) {
                return Err(FallbackPolicyError::DuplicateRule);
            }
        }
        Ok(Self {
            rules: rules.into(),
        })
    }

    /// Borrows ordered declared fallback edges.
    #[must_use]
    pub fn rules(&self) -> &[FallbackRule] {
        &self.rules
    }

    /// Reports whether one exact directed edge is declared.
    #[must_use]
    pub fn allows(&self, from: &CandidateId, to: &CandidateId) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.from() == from && rule.to() == to)
    }
}

/// Immutable evidence that a declared fallback preserves route semantics.
#[derive(Clone, Eq, PartialEq)]
pub struct FallbackProof {
    route_revision: RouteRevision,
    from: CandidateId,
    to: CandidateId,
    reason: FallbackReason,
    capability_registry_revision: String,
}

impl FallbackProof {
    /// Returns the exact route revision under which compatibility was proven.
    #[must_use]
    pub const fn route_revision(&self) -> RouteRevision {
        self.route_revision
    }

    /// Returns the primary candidate identity.
    #[must_use]
    pub const fn from(&self) -> &CandidateId {
        &self.from
    }

    /// Returns the compatible fallback candidate identity.
    #[must_use]
    pub const fn to(&self) -> &CandidateId {
        &self.to
    }

    /// Returns the stable fallback reason.
    #[must_use]
    pub const fn reason(&self) -> FallbackReason {
        self.reason
    }

    /// Returns the capability registry revision used for the proof.
    #[must_use]
    pub fn capability_registry_revision(&self) -> &str {
        &self.capability_registry_revision
    }
}

impl fmt::Debug for FallbackProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FallbackProof")
            .field("route_revision", &self.route_revision)
            .field("from", &"[REDACTED]")
            .field("to", &"[REDACTED]")
            .field("reason", &self.reason)
            .field(
                "capability_registry_revision",
                &self.capability_registry_revision,
            )
            .finish()
    }
}

/// Proves one caller-permitted fallback without weakening semantic guarantees.
///
/// The target must be an enabled, hard-policy-compliant route candidate with an exact capability
/// declaration. Its residency and safety revision must equal the primary, its classification
/// boundary cannot be weaker, and every declared capacity must be at least as strong.
///
/// # Errors
///
/// Returns a value-free [`FallbackProofError`] when the edge is undeclared, caller-prohibited, or
/// any semantic guarantee would be weakened.
pub fn prove_fallback(
    route: &RouteDefinition,
    request: &LlmRequest,
    registry: &ModelCapabilityRegistry,
    from: &CandidateId,
    to: &CandidateId,
    reason: FallbackReason,
    caller_allows_fallback: bool,
) -> Result<FallbackProof, FallbackProofError> {
    validate_request_route(route, request).map_err(|_| FallbackProofError::RouteMismatch)?;
    if !caller_allows_fallback {
        return Err(FallbackProofError::CallerProhibited);
    }
    if !route.fallback_policy().allows(from, to) {
        return Err(FallbackProofError::UndeclaredFallback);
    }
    let primary = route
        .candidate(from)
        .ok_or(FallbackProofError::UnknownCandidate)?;
    let fallback = route
        .candidate(to)
        .ok_or(FallbackProofError::UnknownCandidate)?;
    let primary_boundary = primary.boundary();
    let fallback_boundary = fallback.boundary();
    if primary_boundary.residency() != fallback_boundary.residency()
        || primary_boundary.safety_policy_revision() != fallback_boundary.safety_policy_revision()
        || fallback_boundary.max_classification() < primary_boundary.max_classification()
        || !fallback.limits().covers(primary.limits())
    {
        return Err(FallbackProofError::SemanticDowngrade);
    }
    let admission = admit_candidate_without_circuit(route, request, fallback, registry)
        .map_err(|_| FallbackProofError::CandidateIneligible)?;
    Ok(FallbackProof {
        route_revision: route.revision(),
        from: from.clone(),
        to: to.clone(),
        reason,
        capability_registry_revision: admission.registry_revision().to_owned(),
    })
}

/// Value-free fallback graph validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FallbackPolicyError {
    /// A candidate cannot fallback to itself.
    #[error("fallback edge must target a different candidate")]
    SelfFallback,
    /// The same directed edge was declared more than once.
    #[error("fallback edge is duplicated")]
    DuplicateRule,
}

/// Value-free fallback compatibility failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FallbackProofError {
    /// The caller prohibited fallback for this operation.
    #[error("fallback is prohibited by the caller")]
    CallerProhibited,
    /// The route does not declare the requested directed edge.
    #[error("fallback edge is not declared")]
    UndeclaredFallback,
    /// A named candidate is absent from the exact route revision.
    #[error("fallback candidate is unknown")]
    UnknownCandidate,
    /// The canonical request does not name this exact route revision.
    #[error("fallback route revision does not match")]
    RouteMismatch,
    /// The target weakens a residency, classification, safety, or capacity guarantee.
    #[error("fallback would weaken semantic guarantees")]
    SemanticDowngrade,
    /// The target fails current hard policy or capability admission.
    #[error("fallback candidate is ineligible")]
    CandidateIneligible,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use omnius_llm_core::ModelCapability;

    use super::*;
    use crate::test_support::{candidate, registry, route_definition, text_request};

    #[test]
    fn declared_compatible_fallback_should_record_exact_revision_and_reason() {
        let from = CandidateId::new("primary").expect("test candidate id should be valid");
        let to = CandidateId::new("fallback").expect("test candidate id should be valid");
        let rule = FallbackRule::new(from.clone(), to.clone())
            .expect("test fallback rule should be valid");
        let route = route_definition(
            vec![
                candidate("primary", "provider-a", "model-a", "eu-only", 10, true),
                candidate("fallback", "provider-b", "model-b", "eu-only", 9, true),
            ],
            BTreeSet::new(),
            BTreeSet::new(),
            vec![rule],
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
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
        ]);

        let proof = prove_fallback(
            &route,
            &text_request("route-a", 7),
            &registry,
            &from,
            &to,
            FallbackReason::CircuitOpen,
            true,
        )
        .expect("declared equivalent fallback should be admitted");

        assert_eq!(proof.route_revision().get(), 7);
        assert_eq!(proof.reason(), FallbackReason::CircuitOpen);
        assert_eq!(proof.capability_registry_revision(), "registry-v1");
    }

    #[test]
    fn fallback_should_reject_changed_data_boundary() {
        let from = CandidateId::new("primary").expect("test candidate id should be valid");
        let to = CandidateId::new("fallback").expect("test candidate id should be valid");
        let rule = FallbackRule::new(from.clone(), to.clone())
            .expect("test fallback rule should be valid");
        let route = route_definition(
            vec![
                candidate("primary", "provider-a", "model-a", "eu-only", 10, true),
                candidate(
                    "fallback",
                    "provider-b",
                    "model-b",
                    "other-residency",
                    9,
                    true,
                ),
            ],
            BTreeSet::new(),
            BTreeSet::new(),
            vec![rule],
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
                [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
            ),
        ]);

        assert_eq!(
            prove_fallback(
                &route,
                &text_request("route-a", 7),
                &registry,
                &from,
                &to,
                FallbackReason::ProviderUnavailable,
                true,
            ),
            Err(FallbackProofError::SemanticDowngrade)
        );
    }

    #[test]
    fn fallback_proof_debug_should_redact_candidate_identities() {
        let from = CandidateId::new("secret-primary").expect("test candidate id should be valid");
        let to = CandidateId::new("secret-fallback").expect("test candidate id should be valid");
        let proof = FallbackProof {
            route_revision: RouteRevision::new(7).expect("test revision should be valid"),
            from,
            to,
            reason: FallbackReason::RetryExhausted,
            capability_registry_revision: "registry-v1".to_owned(),
        };
        let rendered = format!("{proof:?}");

        assert!(!rendered.contains("secret-primary"));
        assert!(!rendered.contains("secret-fallback"));
    }
}
