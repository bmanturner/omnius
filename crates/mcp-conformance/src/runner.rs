use std::{collections::BTreeMap, time::Duration};

use async_trait::async_trait;
use futures::{StreamExt, stream};
use thiserror::Error;
use tokio::time::{Instant, timeout};

use crate::{
    evidence::{
        CaseEvidence, CaseEvidenceDraft, CheckOutcome, EvidenceCheck, EvidenceError,
        EvidenceReport, EvidenceSuiteKind,
    },
    matrix::{MatrixCase, MatrixError, SyntheticMatrix},
    official::MCP_REQUIREMENTS_REVISION,
    redaction::RedactedDiagnostic,
};

/// Per-case limits supplied to every adapter invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecutionBudget {
    /// Fixed deterministic seed.
    pub seed: u64,
    /// Hard wall-clock deadline enforced by the runner.
    pub deadline: Duration,
    /// Maximum retained bytes admitted for the case.
    pub max_retained_bytes: usize,
    /// Maximum retained diagnostics admitted for the case.
    pub max_diagnostics: usize,
    /// Maximum bytes admitted in one diagnostic.
    pub max_diagnostic_bytes: usize,
}

/// Checked adapter observation. Construction requires an outcome for every expected check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntheticObservation {
    checks: Vec<EvidenceCheck>,
    diagnostics: Vec<RedactedDiagnostic>,
    retained_bytes: usize,
}

impl SyntheticObservation {
    pub(crate) fn into_parts(self) -> (Vec<EvidenceCheck>, Vec<RedactedDiagnostic>, usize) {
        (self.checks, self.diagnostics, self.retained_bytes)
    }
}

/// Builder that prevents missing or invented check identifiers.
pub struct ObservationBuilder<'a> {
    case: &'a MatrixCase,
    budget: ExecutionBudget,
    outcomes: BTreeMap<String, CheckOutcome>,
    diagnostics: Vec<RedactedDiagnostic>,
    retained_bytes: usize,
}

impl<'a> ObservationBuilder<'a> {
    /// Starts a checked observation for one canonical matrix row.
    #[must_use]
    pub fn new(case: &'a MatrixCase, budget: ExecutionBudget) -> Self {
        Self {
            case,
            budget,
            outcomes: BTreeMap::new(),
            diagnostics: Vec::new(),
            retained_bytes: 0,
        }
    }

    /// Records a satisfied check.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::UnknownCheck`] when `check_id` is not expected by this case,
    /// or [`ObservationError::DuplicateCheck`] when it already has an outcome.
    pub fn satisfied(&mut self, check_id: &str) -> Result<(), ObservationError> {
        self.record(check_id, CheckOutcome::Satisfied)
    }

    /// Records a failed check with a redacted bounded diagnostic.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::UnknownCheck`] when `check_id` is not expected by this case,
    /// or [`ObservationError::DuplicateCheck`] when it already has an outcome.
    pub fn failed(
        &mut self,
        check_id: &str,
        code: &str,
        message: &str,
    ) -> Result<(), ObservationError> {
        let diagnostic = RedactedDiagnostic::new(code, message, self.budget.max_diagnostic_bytes);
        self.record(check_id, CheckOutcome::Failed { diagnostic })
    }

    /// Records a check that could not be exercised. It will derive a skipped case, never a pass.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::UnknownCheck`] when `check_id` is not expected by this case,
    /// or [`ObservationError::DuplicateCheck`] when it already has an outcome.
    pub fn not_run(
        &mut self,
        check_id: &str,
        code: &str,
        reason: &str,
    ) -> Result<(), ObservationError> {
        let reason = RedactedDiagnostic::new(code, reason, self.budget.max_diagnostic_bytes);
        self.record(check_id, CheckOutcome::NotRun { reason })
    }

    /// Adds a bounded redacted supplemental diagnostic.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::TooManyDiagnostics`] when the case diagnostic limit has
    /// already been reached.
    pub fn diagnostic(&mut self, code: &str, message: &str) -> Result<(), ObservationError> {
        if self.diagnostics.len() >= self.budget.max_diagnostics {
            return Err(ObservationError::TooManyDiagnostics);
        }
        self.diagnostics.push(RedactedDiagnostic::new(
            code,
            message,
            self.budget.max_diagnostic_bytes,
        ));
        Ok(())
    }

    /// Records bytes intentionally retained as evidence, not transient processing bytes.
    pub fn retain_bytes(&mut self, retained_bytes: usize) {
        self.retained_bytes = retained_bytes;
    }

    /// Completes the observation only when every canonical check has exactly one outcome.
    ///
    /// # Errors
    ///
    /// Returns [`ObservationError::MissingChecks`] when an expected check has no outcome.
    pub fn finish(self) -> Result<SyntheticObservation, ObservationError> {
        let Self {
            case,
            budget: _,
            mut outcomes,
            diagnostics,
            retained_bytes,
        } = self;
        if outcomes.len() != case.expected_checks.len()
            || case
                .expected_checks
                .iter()
                .any(|check_id| !outcomes.contains_key(check_id))
        {
            return Err(ObservationError::MissingChecks);
        }
        let mut checks = Vec::with_capacity(case.expected_checks.len());
        for check_id in &case.expected_checks {
            let Some(outcome) = outcomes.remove(check_id) else {
                return Err(ObservationError::MissingChecks);
            };
            checks.push(EvidenceCheck {
                check_id: check_id.clone(),
                outcome,
            });
        }
        Ok(SyntheticObservation {
            checks,
            diagnostics,
            retained_bytes,
        })
    }

    fn record(&mut self, check_id: &str, outcome: CheckOutcome) -> Result<(), ObservationError> {
        if !self
            .case
            .expected_checks
            .iter()
            .any(|expected| expected == check_id)
        {
            return Err(ObservationError::UnknownCheck(check_id.to_owned()));
        }
        if self.outcomes.insert(check_id.to_owned(), outcome).is_some() {
            return Err(ObservationError::DuplicateCheck(check_id.to_owned()));
        }
        Ok(())
    }
}

/// Deterministic black-box adapter driven by the project-owned synthetic matrix.
#[async_trait]
pub trait SyntheticAdapter: Send + Sync {
    /// Exercises one case within the supplied finite budget.
    async fn exercise(
        &self,
        case: &MatrixCase,
        budget: ExecutionBudget,
    ) -> Result<SyntheticObservation, AdapterFailure>;
}

/// Bounded adapter failure safe to retain as evidence.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("synthetic adapter failed: {diagnostic:?}")]
pub struct AdapterFailure {
    diagnostic: RedactedDiagnostic,
}

impl AdapterFailure {
    /// Creates a redacted adapter failure.
    #[must_use]
    pub fn new(code: &str, message: &str, max_diagnostic_bytes: usize) -> Self {
        Self {
            diagnostic: RedactedDiagnostic::new(code, message, max_diagnostic_bytes),
        }
    }
}

/// Executes a canonical matrix with hard per-case deadlines and bounded concurrency.
#[derive(Clone, Debug, Default)]
pub struct MatrixRunner;

impl MatrixRunner {
    /// Runs the matrix and returns sorted, validated, machine-readable evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the matrix is invalid, execution exceeds the total deadline, an
    /// adapter result cannot be converted to case evidence, or the final evidence is invalid.
    pub async fn run<A: SyntheticAdapter>(
        &self,
        matrix: &SyntheticMatrix,
        adapter: &A,
    ) -> Result<EvidenceReport, RunnerError> {
        matrix.validate()?;
        let bounds = matrix.bounds.clone();
        let max_concurrency = bounds.max_concurrency;
        let total_deadline = Duration::from_millis(bounds.total_deadline_ms);
        let execution = stream::iter(matrix.cases.iter().cloned())
            .map(|case| {
                let bounds = bounds.clone();
                async move { run_case(adapter, case, &bounds).await }
            })
            .buffer_unordered(max_concurrency)
            .collect::<Vec<_>>();
        let cases = timeout(total_deadline, execution)
            .await
            .map_err(|_| RunnerError::TotalDeadlineExceeded)?
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        EvidenceReport::new(
            EvidenceSuiteKind::SyntheticOffline,
            "synthetic-contract-matrix",
            MCP_REQUIREMENTS_REVISION,
            None,
            bounds,
            cases,
        )
        .map_err(RunnerError::Evidence)
    }
}

async fn run_case<A: SyntheticAdapter>(
    adapter: &A,
    case: MatrixCase,
    bounds: &crate::evidence::EvidenceBounds,
) -> Result<CaseEvidence, RunnerError> {
    let deadline = Duration::from_millis(bounds.case_deadline_ms);
    let budget = ExecutionBudget {
        seed: bounds.seed,
        deadline,
        max_retained_bytes: bounds.max_retained_bytes_per_case,
        max_diagnostics: bounds.max_diagnostics_per_case,
        max_diagnostic_bytes: bounds.max_diagnostic_bytes,
    };
    let started = Instant::now();
    let result = timeout(deadline, adapter.exercise(&case, budget)).await;
    let duration_ms = u64::try_from(started.elapsed().as_millis())
        .unwrap_or(u64::MAX)
        .min(bounds.case_deadline_ms);

    let (mut checks, mut diagnostics, retained_bytes) = match result {
        Ok(Ok(observation)) => observation.into_parts(),
        Ok(Err(failure)) => failure_observation(&case, failure.diagnostic, bounds),
        Err(_) => failure_observation(
            &case,
            RedactedDiagnostic::new(
                "case_deadline_exceeded",
                "synthetic adapter exceeded its hard case deadline",
                bounds.max_diagnostic_bytes,
            ),
            bounds,
        ),
    };

    let retained_bytes = if retained_bytes > bounds.max_retained_bytes_per_case {
        if let Some(first) = checks.first_mut() {
            first.outcome = CheckOutcome::Failed {
                diagnostic: RedactedDiagnostic::new(
                    "retention_bound_exceeded",
                    "adapter reported evidence retention beyond the configured bound",
                    bounds.max_diagnostic_bytes,
                ),
            };
        }
        bounds.max_retained_bytes_per_case
    } else {
        retained_bytes
    };
    diagnostics.truncate(bounds.max_diagnostics_per_case);

    CaseEvidence::from_checks(CaseEvidenceDraft {
        case_id: case.case_id,
        acceptance_ids: case.acceptance_ids,
        transport: Some(case.transport),
        category: case.scenario.category().to_owned(),
        deadline_ms: bounds.case_deadline_ms,
        duration_ms,
        retained_bytes,
        checks,
        diagnostics,
    })
    .map_err(RunnerError::Evidence)
}

fn failure_observation(
    case: &MatrixCase,
    diagnostic: RedactedDiagnostic,
    bounds: &crate::evidence::EvidenceBounds,
) -> (Vec<EvidenceCheck>, Vec<RedactedDiagnostic>, usize) {
    let checks = case
        .expected_checks
        .iter()
        .enumerate()
        .map(|(index, check_id)| EvidenceCheck {
            check_id: check_id.clone(),
            outcome: if index == 0 {
                CheckOutcome::Failed {
                    diagnostic: diagnostic.clone(),
                }
            } else {
                CheckOutcome::NotRun {
                    reason: RedactedDiagnostic::new(
                        "adapter_failed_before_check",
                        "adapter failure prevented this check from running",
                        bounds.max_diagnostic_bytes,
                    ),
                }
            },
        })
        .collect();
    (checks, vec![diagnostic], 0)
}

/// Observation construction failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ObservationError {
    /// Adapter tried to report an assertion not defined by the matrix.
    #[error("unknown matrix check: {0}")]
    UnknownCheck(String),
    /// Adapter tried to report an assertion more than once.
    #[error("duplicate matrix check: {0}")]
    DuplicateCheck(String),
    /// Adapter omitted at least one defined assertion.
    #[error("adapter did not report every expected matrix check")]
    MissingChecks,
    /// Adapter exceeded the supplemental diagnostic count.
    #[error("adapter exceeded the diagnostic count bound")]
    TooManyDiagnostics,
}

/// Matrix execution failure.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// Matrix was incomplete or non-canonical.
    #[error(transparent)]
    Matrix(#[from] MatrixError),
    /// Evidence construction or validation failed.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
    /// The complete matrix exceeded its declared total deadline.
    #[error("synthetic matrix exceeded its total deadline")]
    TotalDeadlineExceeded,
}
