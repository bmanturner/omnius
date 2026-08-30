use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use omnius_core::ErrorCode;
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_llm_core::ModelCapabilityRegistry;
use omnius_runtime::Criticality;

use crate::{
    circuit::CircuitBreaker, definition::RouteDefinition,
    selection::candidate_available_for_readiness,
};

const HEALTH_CHECK_NAME: &str = "required-route-availability";
const MODULE_NAME: &str = "llm-routing";
const UNAVAILABLE_CODE: &str = "LLM_REQUIRED_ROUTE_UNAVAILABLE";

/// Value-free required-route availability result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequiredRouteReadiness {
    required_route_count: usize,
    unavailable_route_count: usize,
}

impl RequiredRouteReadiness {
    /// Reports whether every required route retains a healthy compliant candidate.
    #[must_use]
    pub const fn is_ready(self) -> bool {
        self.unavailable_route_count == 0
    }

    /// Returns configured required-route count without exposing route identities.
    #[must_use]
    pub const fn required_route_count(self) -> usize {
        self.required_route_count
    }

    /// Returns unavailable required-route count without exposing route identities.
    #[must_use]
    pub const fn unavailable_route_count(self) -> usize {
        self.unavailable_route_count
    }
}

/// Immutable required-route readiness evaluator over shared circuit evidence.
#[derive(Clone)]
pub struct RequiredRouteReadinessEvaluator {
    routes: Arc<[RouteDefinition]>,
    registry: Arc<ModelCapabilityRegistry>,
    circuits: CircuitBreaker,
}

impl RequiredRouteReadinessEvaluator {
    /// Creates an evaluator over immutable route and capability snapshots.
    #[must_use]
    pub fn new(
        routes: Vec<RouteDefinition>,
        registry: Arc<ModelCapabilityRegistry>,
        circuits: CircuitBreaker,
    ) -> Self {
        Self {
            routes: routes.into(),
            registry,
            circuits,
        }
    }

    /// Evaluates every required route at a caller-supplied monotonic time.
    #[must_use]
    pub fn evaluate_at(&self, now: Instant) -> RequiredRouteReadiness {
        let mut required_route_count = 0;
        let mut unavailable_route_count = 0;
        for route in self
            .routes
            .iter()
            .filter(|route| route.policy().is_required_route())
        {
            required_route_count += 1;
            let available = route.candidates().iter().any(|candidate| {
                candidate_available_for_readiness(
                    route,
                    candidate,
                    &self.registry,
                    &self.circuits,
                    now,
                )
            });
            unavailable_route_count += usize::from(!available);
        }
        RequiredRouteReadiness {
            required_route_count,
            unavailable_route_count,
        }
    }
}

impl fmt::Debug for RequiredRouteReadinessEvaluator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequiredRouteReadinessEvaluator")
            .field("route_count", &self.routes.len())
            .field("registry", &"[REDACTED]")
            .field("circuits", &self.circuits)
            .finish_non_exhaustive()
    }
}

/// Creates the required cached health check consumed by process readiness.
///
/// The check returns one stable value-free code when any required route has no enabled,
/// hard-policy-compliant, capability-admitted candidate with closed circuit scopes.
#[must_use]
pub fn required_route_health_check(
    evaluator: RequiredRouteReadinessEvaluator,
    timeout: Duration,
) -> HealthCheckSpec {
    HealthCheckSpec::new(
        HEALTH_CHECK_NAME,
        MODULE_NAME,
        Criticality::Required,
        timeout,
        move || {
            let evaluator = evaluator.clone();
            async move {
                if evaluator.evaluate_at(Instant::now()).is_ready() {
                    Ok(())
                } else {
                    Err(CheckFailure::new(unavailable_code()))
                }
            }
        },
    )
}

fn unavailable_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(UNAVAILABLE_CODE) else {
        unreachable!("static LLM routing health code must be valid")
    };
    code
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use omnius_llm_core::ModelCapability;

    use super::*;
    use crate::{
        circuit::{CircuitOutcome, CircuitPolicy, CircuitScope},
        test_support::{candidate, registry, route_definition},
    };

    #[test]
    fn required_route_should_fail_readiness_and_recover_after_success() {
        let route = route_definition(
            vec![candidate(
                "candidate-a",
                "provider-a",
                "model-a",
                "eu-only",
                10,
                true,
            )],
            BTreeSet::from([ModelCapability::TextInput, ModelCapability::TextOutput]),
            BTreeSet::new(),
            Vec::new(),
        );
        let registry = Arc::new(registry([(
            "provider-a",
            "model-a",
            [ModelCapability::TextInput, ModelCapability::TextOutput].as_slice(),
        )]));
        let policy =
            CircuitPolicy::new(8, 4, Duration::from_secs(10), 1, Duration::from_secs(5), 1)
                .expect("test circuit policy should be valid");
        let circuits = CircuitBreaker::new(policy);
        let evaluator = RequiredRouteReadinessEvaluator::new(
            vec![route],
            Arc::clone(&registry),
            circuits.clone(),
        );
        let scope =
            CircuitScope::model("provider-a", "model-a", "v1").expect("test scope should be valid");
        let now = Instant::now();
        circuits
            .record(scope.clone(), now, CircuitOutcome::ProviderFailure)
            .expect("scope should fit");

        assert!(!evaluator.evaluate_at(now).is_ready());

        let recovery = now + Duration::from_secs(6);
        let mut permit = circuits
            .try_acquire(&scope, recovery)
            .expect("one recovery probe should be available");
        permit.complete(recovery, CircuitOutcome::Success);

        assert!(evaluator.evaluate_at(recovery).is_ready());
    }
}
