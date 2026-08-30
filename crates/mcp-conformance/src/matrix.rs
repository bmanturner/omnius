use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence::{AcceptanceId, CaseEvidence, EvidenceBounds, Transport};

/// Deterministic synthetic contract exercised against both transport adapters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticScenario {
    /// Basic framing, revision, and response bound behavior.
    TransportRoundTrip,
    /// MCP Apps metadata, sandbox, and untrusted message behavior.
    Apps,
    /// Elicitation/MRTR binding, single-use state, and retention behavior.
    ElicitationMrtr,
    /// Task owner binding, cancellation, and terminal result behavior.
    Tasks,
    /// Subscription isolation, revocation, and slow-consumer behavior.
    Subscriptions,
    /// Attempted cross-tenant authorization bypass.
    CrossTenantBypass,
    /// Attempted principal substitution.
    PrincipalBypass,
    /// Attempted capability escalation.
    CapabilityBypass,
    /// Finite concurrent request load.
    BoundedLoad,
    /// Finite repeated-operation soak.
    BoundedSoak,
    /// Deadline and cancellation propagation.
    Cancellation,
    /// Bounded queue and slow-consumer handling.
    Backpressure,
    /// Redacted bounded provider failure.
    ProviderFailure,
    /// Prompt instruction injection.
    PromptInjection,
    /// Secret exfiltration attempt.
    Exfiltration,
    /// Tampered MRTR state.
    ForgedState,
    /// Local-file, loopback, and traversal resource URI attempts.
    MaliciousUri,
    /// Issuer, audience, and tenant token confusion.
    TokenConfusion,
}

impl SyntheticScenario {
    /// All scenarios in canonical order.
    pub const ALL: [Self; 18] = [
        Self::TransportRoundTrip,
        Self::Apps,
        Self::ElicitationMrtr,
        Self::Tasks,
        Self::Subscriptions,
        Self::CrossTenantBypass,
        Self::PrincipalBypass,
        Self::CapabilityBypass,
        Self::BoundedLoad,
        Self::BoundedSoak,
        Self::Cancellation,
        Self::Backpressure,
        Self::ProviderFailure,
        Self::PromptInjection,
        Self::Exfiltration,
        Self::ForgedState,
        Self::MaliciousUri,
        Self::TokenConfusion,
    ];

    /// Stable identifier segment.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::TransportRoundTrip => "transport_round_trip",
            Self::Apps => "apps",
            Self::ElicitationMrtr => "elicitation_mrtr",
            Self::Tasks => "tasks",
            Self::Subscriptions => "subscriptions",
            Self::CrossTenantBypass => "cross_tenant_bypass",
            Self::PrincipalBypass => "principal_bypass",
            Self::CapabilityBypass => "capability_bypass",
            Self::BoundedLoad => "bounded_load",
            Self::BoundedSoak => "bounded_soak",
            Self::Cancellation => "cancellation",
            Self::Backpressure => "backpressure",
            Self::ProviderFailure => "provider_failure",
            Self::PromptInjection => "prompt_injection",
            Self::Exfiltration => "exfiltration",
            Self::ForgedState => "forged_state",
            Self::MaliciousUri => "malicious_uri",
            Self::TokenConfusion => "token_confusion",
        }
    }

    /// Stable matrix category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::TransportRoundTrip => "transport",
            Self::Apps => "apps",
            Self::ElicitationMrtr => "elicitation_mrtr",
            Self::Tasks => "tasks",
            Self::Subscriptions => "subscriptions",
            Self::CrossTenantBypass | Self::PrincipalBypass | Self::CapabilityBypass => {
                "authorization"
            }
            Self::BoundedLoad
            | Self::BoundedSoak
            | Self::Cancellation
            | Self::Backpressure
            | Self::ProviderFailure => "resilience",
            Self::PromptInjection
            | Self::Exfiltration
            | Self::ForgedState
            | Self::MaliciousUri
            | Self::TokenConfusion => "adversarial",
        }
    }

    /// Acceptance criteria supported by the case.
    #[must_use]
    pub fn acceptance_ids(self) -> Vec<AcceptanceId> {
        match self {
            Self::CrossTenantBypass | Self::PrincipalBypass | Self::CapabilityBypass => {
                vec![AcceptanceId::AcAi109]
            }
            Self::BoundedLoad
            | Self::BoundedSoak
            | Self::Cancellation
            | Self::Backpressure
            | Self::ProviderFailure => vec![AcceptanceId::AcAi110],
            Self::PromptInjection
            | Self::Exfiltration
            | Self::ForgedState
            | Self::MaliciousUri
            | Self::TokenConfusion => vec![AcceptanceId::AcAi112],
            Self::TransportRoundTrip
            | Self::Apps
            | Self::ElicitationMrtr
            | Self::Tasks
            | Self::Subscriptions => vec![AcceptanceId::AcAi105],
        }
    }

    /// Complete observable check identifiers for this scenario.
    #[must_use]
    pub const fn expected_checks(self) -> &'static [&'static str] {
        match self {
            Self::TransportRoundTrip => &[
                "wire_request_decoded",
                "revision_preserved",
                "response_bounded",
            ],
            Self::Apps => &[
                "app_metadata_bound",
                "sandbox_denies_untrusted_origin",
                "message_treated_as_untrusted_data",
            ],
            Self::ElicitationMrtr => &[
                "state_bound_to_subject",
                "state_consumed_once",
                "sensitive_answer_not_retained",
            ],
            Self::Tasks => &[
                "task_owner_bound",
                "cancel_idempotent",
                "terminal_result_bounded",
            ],
            Self::Subscriptions => &[
                "subscription_tenant_bound",
                "revocation_stops_delivery",
                "slow_consumer_bounded",
            ],
            Self::CrossTenantBypass | Self::PrincipalBypass | Self::CapabilityBypass => &[
                "request_denied",
                "catalog_not_disclosed",
                "side_effects_zero",
            ],
            Self::BoundedLoad => &[
                "request_count_bounded",
                "concurrency_bounded",
                "responses_bounded",
            ],
            Self::BoundedSoak => &[
                "iterations_bounded",
                "retained_bytes_bounded",
                "stable_state",
            ],
            Self::Cancellation => &[
                "deadline_enforced",
                "work_cancelled",
                "late_result_discarded",
            ],
            Self::Backpressure => &[
                "queue_bounded",
                "slow_consumer_disconnected",
                "retained_bytes_bounded",
            ],
            Self::ProviderFailure => &["failure_redacted", "deadline_enforced", "no_retry_storm"],
            Self::PromptInjection => &[
                "instructions_not_executed",
                "payload_treated_as_data",
                "side_effects_zero",
            ],
            Self::Exfiltration => &[
                "secret_not_disclosed",
                "unauthorized_field_omitted",
                "diagnostic_redacted",
            ],
            Self::ForgedState => &[
                "signature_rejected",
                "subject_binding_enforced",
                "side_effects_zero",
            ],
            Self::MaliciousUri => &[
                "local_scheme_rejected",
                "loopback_host_rejected",
                "traversal_rejected",
            ],
            Self::TokenConfusion => &["issuer_bound", "audience_bound", "tenant_claim_bound"],
        }
    }
}

/// One canonical transport/scenario matrix row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCase {
    /// Stable case identifier.
    pub case_id: String,
    /// Transport adapter exercised.
    pub transport: Transport,
    /// Synthetic scenario.
    pub scenario: SyntheticScenario,
    /// Acceptance criteria supported by the row.
    pub acceptance_ids: Vec<AcceptanceId>,
    /// Complete observable assertion identifiers.
    pub expected_checks: Vec<String>,
}

impl MatrixCase {
    fn new(transport: Transport, scenario: SyntheticScenario) -> Self {
        let transport_id = transport.id();
        let scenario_id = scenario.id();
        Self {
            case_id: format!("{transport_id}.{scenario_id}"),
            transport,
            scenario,
            acceptance_ids: scenario.acceptance_ids(),
            expected_checks: scenario
                .expected_checks()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        }
    }
}

/// Canonical deterministic matrix and its finite execution bounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticMatrix {
    /// Bounds enforced by the runner.
    pub bounds: EvidenceBounds,
    /// Canonically generated matrix rows.
    pub cases: Vec<MatrixCase>,
}

impl SyntheticMatrix {
    /// Generates every scenario once for Streamable HTTP and once for stdio.
    ///
    /// # Errors
    ///
    /// Returns [`MatrixError::InvalidBounds`] when `bounds` cannot support a finite canonical
    /// matrix, or another matrix error if the generated matrix violates its invariants.
    pub fn canonical(bounds: EvidenceBounds) -> Result<Self, MatrixError> {
        bounds.validate().map_err(|_| MatrixError::InvalidBounds)?;
        let cases = canonical_cases();
        let matrix = Self { bounds, cases };
        matrix.validate()?;
        Ok(matrix)
    }

    /// Verifies complete two-transport coverage, uniqueness, and stable row contents.
    ///
    /// # Errors
    ///
    /// Returns an error when execution bounds are invalid, the matrix exceeds its case limit,
    /// coverage is incomplete or duplicated, or a row differs from its canonical contents.
    pub fn validate(&self) -> Result<(), MatrixError> {
        self.bounds
            .validate()
            .map_err(|_| MatrixError::InvalidBounds)?;
        if self.cases.len() > self.bounds.max_cases {
            return Err(MatrixError::TooManyCases);
        }
        let expected: BTreeSet<_> = [Transport::StreamableHttp, Transport::Stdio]
            .into_iter()
            .flat_map(|transport| {
                SyntheticScenario::ALL
                    .into_iter()
                    .map(move |scenario| (transport, scenario))
            })
            .collect();
        let actual: BTreeSet<_> = self
            .cases
            .iter()
            .map(|case| (case.transport, case.scenario))
            .collect();
        if actual != expected || actual.len() != self.cases.len() {
            return Err(MatrixError::IncompleteCoverage);
        }
        for case in &self.cases {
            let canonical = MatrixCase::new(case.transport, case.scenario);
            if *case != canonical {
                return Err(MatrixError::NonCanonicalCase(case.case_id.clone()));
            }
        }
        Ok(())
    }

    pub(crate) fn evidence_matches(&self, evidence: &[CaseEvidence]) -> bool {
        evidence.len() == self.cases.len()
            && self.cases.iter().all(|matrix_case| {
                evidence
                    .iter()
                    .find(|case| case.case_id == matrix_case.case_id)
                    .is_some_and(|case| {
                        let check_ids: BTreeSet<_> = case
                            .checks
                            .iter()
                            .map(|check| check.check_id.as_str())
                            .collect();
                        let expected_checks: BTreeSet<_> = matrix_case
                            .expected_checks
                            .iter()
                            .map(String::as_str)
                            .collect();
                        case.transport == Some(matrix_case.transport)
                            && case.category == matrix_case.scenario.category()
                            && case.acceptance_ids == matrix_case.acceptance_ids
                            && case.checks.len() == matrix_case.expected_checks.len()
                            && check_ids == expected_checks
                    })
            })
    }
}

impl Default for SyntheticMatrix {
    fn default() -> Self {
        Self {
            bounds: EvidenceBounds::default(),
            cases: canonical_cases(),
        }
    }
}

fn canonical_cases() -> Vec<MatrixCase> {
    [Transport::StreamableHttp, Transport::Stdio]
        .into_iter()
        .flat_map(|transport| {
            SyntheticScenario::ALL
                .into_iter()
                .map(move |scenario| MatrixCase::new(transport, scenario))
        })
        .collect()
}

/// Synthetic matrix construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MatrixError {
    /// Execution bounds were invalid.
    #[error("invalid matrix execution bounds")]
    InvalidBounds,
    /// Matrix exceeded the declared maximum case count.
    #[error("matrix exceeds maximum case count")]
    TooManyCases,
    /// A transport/scenario pair was duplicated or missing.
    #[error("matrix must contain every scenario exactly once per transport")]
    IncompleteCoverage,
    /// A case's identifiers or expected checks differed from the canonical definition.
    #[error("non-canonical matrix case: {0}")]
    NonCanonicalCase(String),
}
