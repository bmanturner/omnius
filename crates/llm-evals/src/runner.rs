use std::time::Duration;

use futures::{StreamExt, stream};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;
use tokio::time::{Instant, timeout};

use crate::{
    AssertionReport, CandidateRole, CaseExecutionRequest, CaseExecutor, CaseOutcome, CaseReport,
    DatasetBounds, DatasetError, DeterministicAssertion, DiagnosticCode, EvalCase,
    EvalExecutionResult, EvalInvocation, EvalUsage, EvaluationDataset, EvaluationReport,
    EvaluationResultRepository, ExecutionReport, JudgeCandidate, JudgeLabel, JudgeMethodology,
    JudgeReport, JudgeRequest, JudgeResult, ModelJudge, RUNNER_VERSION, RedactedDiagnostic,
    RejectedJudgeReport, ReportTotals, ResultRepositoryError,
    hashing::{hash_serializable, sha256_bytes},
};

/// Policy controlling bounded retention of already-redacted diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticRetention {
    /// Retain no diagnostics.
    Discard,
    /// Retain a bounded number of diagnostics whose source lengths are also bounded.
    Redacted {
        /// Maximum case diagnostics retained in deterministic case order.
        max_diagnostics: usize,
        /// Maximum sensitive source length represented by a retained digest.
        max_source_bytes: u64,
    },
}

impl DiagnosticRetention {
    fn validate(self) -> Result<(), RunError> {
        match self {
            Self::Discard => Ok(()),
            Self::Redacted {
                max_diagnostics,
                max_source_bytes,
            } if max_diagnostics > 0 && max_source_bytes > 0 => Ok(()),
            Self::Redacted { .. } => Err(RunError::InvalidLimits),
        }
    }
}

/// Total dataset and execution resource limits for a runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunnerLimits {
    dataset: DatasetBounds,
    max_concurrency: usize,
    max_case_deadline_ms: u64,
    total_cost_ceiling_microunits: u64,
    diagnostic_retention: DiagnosticRetention,
}

impl RunnerLimits {
    /// Creates positive runner limits and a diagnostic retention policy.
    ///
    /// # Errors
    ///
    /// Returns [`RunError::InvalidLimits`] when a run limit is zero or the retention policy is invalid.
    pub fn new(
        dataset: DatasetBounds,
        max_concurrency: usize,
        max_case_deadline_ms: u64,
        total_cost_ceiling_microunits: u64,
        diagnostic_retention: DiagnosticRetention,
    ) -> Result<Self, RunError> {
        diagnostic_retention.validate()?;
        if max_concurrency == 0 || max_case_deadline_ms == 0 || total_cost_ceiling_microunits == 0 {
            return Err(RunError::InvalidLimits);
        }
        Ok(Self {
            dataset,
            max_concurrency,
            max_case_deadline_ms,
            total_cost_ceiling_microunits,
            diagnostic_retention,
        })
    }

    /// Returns dataset admission limits.
    #[must_use]
    pub const fn dataset(self) -> DatasetBounds {
        self.dataset
    }

    /// Returns maximum simultaneously-polled cases.
    #[must_use]
    pub const fn max_concurrency(self) -> usize {
        self.max_concurrency
    }

    /// Returns the maximum admitted case deadline.
    #[must_use]
    pub const fn max_case_deadline_ms(self) -> u64 {
        self.max_case_deadline_ms
    }

    /// Returns the total pre-reserved run cost ceiling.
    #[must_use]
    pub const fn total_cost_ceiling_microunits(self) -> u64 {
        self.total_cost_ceiling_microunits
    }

    /// Returns diagnostic retention policy.
    #[must_use]
    pub const fn diagnostic_retention(self) -> DiagnosticRetention {
        self.diagnostic_retention
    }
}

/// A runner admission, resource, encoding, or persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RunError {
    /// A runner resource or retention limit was zero.
    #[error("evaluation runner limits must be positive")]
    InvalidLimits,
    /// Dataset admission failed.
    #[error(transparent)]
    Dataset(#[from] DatasetError),
    /// A case requested more time than the runner allows.
    #[error("evaluation case exceeds the runner deadline limit")]
    DeadlineLimitExceeded,
    /// Reserved case ceilings exceeded the total run cost budget.
    #[error("evaluation dataset exceeds the total run cost ceiling")]
    CostBudgetExceeded,
    /// A usage or report counter overflowed.
    #[error("evaluation accounting overflowed")]
    AccountingOverflow,
    /// Durable report persistence failed.
    #[error(transparent)]
    Repository(#[from] ResultRepositoryError),
}

/// Seed-derived candidate ordering that never reads or retains candidate content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlindedOrder {
    /// Primary is A and comparison is B.
    PrimaryFirst,
    /// Comparison is A and primary is B.
    ComparisonFirst,
}

impl BlindedOrder {
    /// Derives stable order from seed, dataset digest, and case identifier only.
    #[must_use]
    pub fn derive(seed: u64, dataset_sha256: &str, case_id: &str) -> Self {
        let mut material = Vec::with_capacity(dataset_sha256.len() + case_id.len() + 32);
        material.extend_from_slice(&seed.to_be_bytes());
        material.extend_from_slice(
            &u64::try_from(dataset_sha256.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        material.extend_from_slice(dataset_sha256.as_bytes());
        material.extend_from_slice(
            &u64::try_from(case_id.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        material.extend_from_slice(case_id.as_bytes());
        let digest = sha256_bytes(&material);
        if digest.as_bytes().first().is_some_and(|byte| *byte & 1 == 0) {
            Self::PrimaryFirst
        } else {
            Self::ComparisonFirst
        }
    }
}

/// Deterministic bounded orchestrator for execution, assertions, optional judging, and persistence.
pub struct EvaluationRunner<'a> {
    executor: &'a dyn CaseExecutor,
    judge: Option<&'a dyn ModelJudge>,
    repository: &'a dyn EvaluationResultRepository,
    limits: RunnerLimits,
}

impl<'a> EvaluationRunner<'a> {
    /// Creates a runner around async application-owned ports.
    #[must_use]
    pub const fn new(
        executor: &'a dyn CaseExecutor,
        judge: Option<&'a dyn ModelJudge>,
        repository: &'a dyn EvaluationResultRepository,
        limits: RunnerLimits,
    ) -> Self {
        Self {
            executor,
            judge,
            repository,
            limits,
        }
    }

    /// Runs an admitted dataset and atomically persists its content-free report.
    ///
    /// Cases are concurrently polled under the configured bound while report order
    /// remains dataset order. The sum of per-case cost ceilings is reserved before
    /// any executor call.
    ///
    /// # Errors
    ///
    /// Returns [`RunError`] when admission, accounting, encoding, or persistence fails.
    pub async fn run(&self, dataset: &EvaluationDataset) -> Result<EvaluationReport, RunError> {
        dataset.validate(self.limits.dataset)?;
        let mut reserved_cost = 0_u64;
        for case in dataset.cases() {
            if case.deadline_ms() > self.limits.max_case_deadline_ms {
                return Err(RunError::DeadlineLimitExceeded);
            }
            reserved_cost = reserved_cost
                .checked_add(case.cost_ceiling_microunits())
                .ok_or(RunError::AccountingOverflow)?;
            if reserved_cost > self.limits.total_cost_ceiling_microunits {
                return Err(RunError::CostBudgetExceeded);
            }
        }

        let dataset_sha256 = dataset.sha256()?;
        let mut cases = stream::iter(dataset.cases())
            .map(|case| self.run_case(dataset, &dataset_sha256, case))
            .buffered(self.limits.max_concurrency)
            .collect::<Vec<_>>()
            .await;
        retain_diagnostics(&mut cases, self.limits.diagnostic_retention);

        let totals = ReportTotals::from_cases(&cases).ok_or(RunError::AccountingOverflow)?;
        let executor_evidence_sha256 = self.executor.evidence_sha256();
        let judge_evidence_sha256 = self.judge.and_then(ModelJudge::evidence_sha256);
        let reproducibility_sha256 = hash_serializable(&ReproducibilityMaterial {
            runner_version: RUNNER_VERSION,
            dataset_sha256: &dataset_sha256,
            executor_evidence_sha256,
            judge_evidence_sha256,
            cases: &cases,
        })?;
        let report = EvaluationReport::new(
            dataset.dataset_id().to_owned(),
            dataset.dataset_version().to_owned(),
            dataset_sha256,
            executor_evidence_sha256.map(str::to_owned),
            judge_evidence_sha256.map(str::to_owned),
            reproducibility_sha256,
            cases,
            totals,
        );
        self.repository.store(&report).await?;
        Ok(report)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the contiguous case pipeline makes accounting and policy precedence auditable"
    )]
    async fn run_case(
        &self,
        dataset: &EvaluationDataset,
        dataset_sha256: &str,
        case: &EvalCase,
    ) -> CaseReport {
        let started = Instant::now();
        let deadline = Duration::from_millis(case.deadline_ms());
        let mut execution_reports = Vec::with_capacity(2);
        let mut usage = EvalUsage::default();

        let primary = match self
            .execute_candidate(
                dataset,
                case,
                CandidateRole::Primary,
                case.primary(),
                deadline,
                started,
                case.cost_ceiling_microunits(),
            )
            .await
        {
            CandidateStep::Completed(result, report) => {
                usage = result.usage();
                execution_reports.push(report);
                result
            }
            CandidateStep::Failed(failure) => {
                return case_failure_from_candidate(
                    case,
                    execution_reports,
                    Vec::new(),
                    usage,
                    failure,
                );
            }
            CandidateStep::TimedOut(exposure) => {
                return case_timeout(
                    case,
                    execution_reports,
                    add_timeout_exposure(usage, exposure),
                );
            }
        };
        if usage.cost_microunits() > case.cost_ceiling_microunits() {
            return case_failure(
                case,
                execution_reports,
                Vec::new(),
                usage,
                RedactedDiagnostic::new(DiagnosticCode::CaseCostExceeded),
            );
        }

        let comparison = if let Some(invocation) = case.comparison() {
            let remaining_cost = case
                .cost_ceiling_microunits()
                .saturating_sub(usage.cost_microunits());
            if remaining_cost == 0 {
                return case_failure(
                    case,
                    execution_reports,
                    Vec::new(),
                    usage,
                    RedactedDiagnostic::new(DiagnosticCode::ComparisonBudgetExhausted),
                );
            }
            match self
                .execute_candidate(
                    dataset,
                    case,
                    CandidateRole::Comparison,
                    invocation,
                    deadline,
                    started,
                    remaining_cost,
                )
                .await
            {
                CandidateStep::Completed(result, report) => {
                    let Some(combined) = usage.checked_add(result.usage()) else {
                        return case_failure(
                            case,
                            execution_reports,
                            Vec::new(),
                            usage,
                            RedactedDiagnostic::new(DiagnosticCode::UsageOverflow),
                        );
                    };
                    usage = combined;
                    execution_reports.push(report);
                    if usage.cost_microunits() > case.cost_ceiling_microunits() {
                        return case_failure(
                            case,
                            execution_reports,
                            Vec::new(),
                            usage,
                            RedactedDiagnostic::new(DiagnosticCode::CaseCostExceeded),
                        );
                    }
                    Some(result)
                }
                CandidateStep::Failed(failure) => {
                    return case_failure_from_candidate(
                        case,
                        execution_reports,
                        Vec::new(),
                        usage,
                        failure,
                    );
                }
                CandidateStep::TimedOut(exposure) => {
                    return case_timeout(
                        case,
                        execution_reports,
                        add_timeout_exposure(usage, exposure),
                    );
                }
            }
        } else {
            None
        };

        let assertions = match evaluate_assertions(case, &primary, comparison.as_deref()) {
            Ok(assertions) => assertions,
            Err(diagnostic) => {
                return case_failure(case, execution_reports, Vec::new(), usage, diagnostic);
            }
        };
        if assertions.iter().any(|assertion| !assertion.passed()) {
            return case_failure(
                case,
                execution_reports,
                assertions,
                usage,
                RedactedDiagnostic::new(DiagnosticCode::DeterministicAssertionFailed),
            );
        }

        let Some(methodology) = case.judge() else {
            return CaseReport::new(
                case.id().to_owned(),
                CaseOutcome::Passed,
                execution_reports,
                assertions,
                None,
                usage,
                None,
            );
        };
        let Some(calibration) = methodology.calibration() else {
            return case_failure(
                case,
                execution_reports,
                assertions,
                usage,
                RedactedDiagnostic::new(DiagnosticCode::JudgeEvidenceInvalid),
            );
        };
        let Some(judge) = self.judge else {
            return case_failure(
                case,
                execution_reports,
                assertions,
                usage,
                RedactedDiagnostic::new(DiagnosticCode::JudgeUnavailable),
            );
        };

        let (first, second, blinded, order_sha256) = judge_candidates(
            dataset_sha256,
            case.id(),
            methodology,
            &primary,
            comparison.as_deref(),
        );
        let remaining_cost = case
            .cost_ceiling_microunits()
            .saturating_sub(usage.cost_microunits());
        if remaining_cost == 0 {
            return case_failure(
                case,
                execution_reports,
                assertions,
                usage,
                RedactedDiagnostic::new(DiagnosticCode::JudgeBudgetExhausted),
            );
        }
        let judge_request = JudgeRequest::new(
            dataset.dataset_id(),
            dataset.dataset_version(),
            case.id(),
            methodology,
            first,
            second,
            remaining_cost,
        );
        let Some(remaining) = deadline.checked_sub(started.elapsed()) else {
            return case_timeout(case, execution_reports, usage);
        };
        let judge_result = match timeout(remaining, judge.judge(judge_request)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let (charged_usage, diagnostic) = match usage.checked_add(error.usage()) {
                    Some(combined)
                        if combined.cost_microunits() > case.cost_ceiling_microunits() =>
                    {
                        (
                            combined,
                            RedactedDiagnostic::new(DiagnosticCode::CaseCostExceeded),
                        )
                    }
                    Some(combined) => (combined, error.diagnostic().clone()),
                    None => (
                        EvalUsage::new(Some(u64::MAX), Some(u64::MAX), u64::MAX),
                        RedactedDiagnostic::new(DiagnosticCode::UsageOverflow),
                    ),
                };
                return case_failure(
                    case,
                    execution_reports,
                    assertions,
                    charged_usage,
                    diagnostic,
                );
            }
            Err(_) => {
                return case_timeout(
                    case,
                    execution_reports,
                    add_timeout_exposure(usage, remaining_cost),
                );
            }
        };
        let Some(combined) = usage.checked_add(judge_result.usage()) else {
            return rejected_judge_failure(
                case,
                execution_reports,
                assertions,
                EvalUsage::new(Some(u64::MAX), Some(u64::MAX), u64::MAX),
                methodology,
                calibration,
                &judge_result,
                blinded,
                order_sha256,
                RedactedDiagnostic::new(DiagnosticCode::UsageOverflow),
            );
        };
        usage = combined;
        if usage.cost_microunits() > case.cost_ceiling_microunits() {
            return rejected_judge_failure(
                case,
                execution_reports,
                assertions,
                usage,
                methodology,
                calibration,
                &judge_result,
                blinded,
                order_sha256,
                RedactedDiagnostic::new(DiagnosticCode::CaseCostExceeded),
            );
        }
        if judge_result.evidence() != methodology.judge()
            || judge_result.score_microunits() > 1_000_000
        {
            return rejected_judge_failure(
                case,
                execution_reports,
                assertions,
                usage,
                methodology,
                calibration,
                &judge_result,
                blinded,
                order_sha256,
                RedactedDiagnostic::new(DiagnosticCode::JudgeEvidenceInvalid),
            );
        }
        let Some(minimum_score) = case.tolerances().minimum_judge_score_microunits() else {
            return rejected_judge_failure(
                case,
                execution_reports,
                assertions,
                usage,
                methodology,
                calibration,
                &judge_result,
                blinded,
                order_sha256,
                RedactedDiagnostic::new(DiagnosticCode::JudgeToleranceMissing),
            );
        };
        let judge_passed = judge_result.score_microunits() >= minimum_score;
        let judge_report = JudgeReport::new(
            methodology,
            calibration.clone(),
            judge_result.evidence().clone(),
            judge_result.score_microunits(),
            judge_passed,
            blinded,
            order_sha256,
            judge_result.usage(),
        );
        CaseReport::new(
            case.id().to_owned(),
            if judge_passed {
                CaseOutcome::Passed
            } else {
                CaseOutcome::Failed
            },
            execution_reports,
            assertions,
            Some(judge_report),
            usage,
            (!judge_passed)
                .then(|| RedactedDiagnostic::new(DiagnosticCode::JudgeScoreBelowTolerance)),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the executor boundary carries every independent resource and identity control"
    )]
    async fn execute_candidate(
        &self,
        dataset: &EvaluationDataset,
        case: &EvalCase,
        role: CandidateRole,
        invocation: &EvalInvocation,
        deadline: Duration,
        started: Instant,
        cost_ceiling_microunits: u64,
    ) -> CandidateStep {
        let Some(remaining) = deadline.checked_sub(started.elapsed()) else {
            return CandidateStep::TimedOut(0);
        };
        let request = CaseExecutionRequest::new(
            dataset.dataset_id(),
            dataset.dataset_version(),
            case.id(),
            role,
            invocation,
            case.deadline_ms(),
            cost_ceiling_microunits,
        );
        let result = match timeout(remaining, self.executor.execute(request)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                return CandidateStep::Failed(CandidateFailure {
                    diagnostic: error.diagnostic().clone(),
                    usage: error.usage(),
                    report: None,
                });
            }
            Err(_) => return CandidateStep::TimedOut(cost_ceiling_microunits),
        };
        let Ok(input_sha256) = hash_serializable(invocation.input()) else {
            return CandidateStep::Failed(CandidateFailure {
                diagnostic: RedactedDiagnostic::new(DiagnosticCode::InputHashFailed),
                usage: result.usage(),
                report: None,
            });
        };
        let Ok(response_sha256) = hash_serializable(result.response()) else {
            return CandidateStep::Failed(CandidateFailure {
                diagnostic: RedactedDiagnostic::new(DiagnosticCode::ResponseHashFailed),
                usage: result.usage(),
                report: None,
            });
        };
        let report = ExecutionReport::new(
            role,
            result.evidence().clone(),
            input_sha256,
            response_sha256,
            result.usage(),
        );
        if result.evidence() != invocation.target()
            || result.response().provider() != result.evidence().provider()
            || result.response().model() != result.evidence().model()
        {
            return CandidateStep::Failed(CandidateFailure {
                diagnostic: RedactedDiagnostic::new(DiagnosticCode::ExecutionRevisionMismatch),
                usage: result.usage(),
                report: Some(report),
            });
        }
        CandidateStep::Completed(Box::new(result), report)
    }
}

#[derive(Serialize)]
struct ReproducibilityMaterial<'a> {
    runner_version: &'static str,
    dataset_sha256: &'a str,
    executor_evidence_sha256: Option<&'a str>,
    judge_evidence_sha256: Option<&'a str>,
    cases: &'a [CaseReport],
}

struct CandidateFailure {
    diagnostic: RedactedDiagnostic,
    usage: EvalUsage,
    report: Option<ExecutionReport>,
}

enum CandidateStep {
    Completed(Box<EvalExecutionResult>, ExecutionReport),
    Failed(CandidateFailure),
    TimedOut(u64),
}

fn evaluate_assertions(
    case: &EvalCase,
    primary: &EvalExecutionResult,
    comparison: Option<&EvalExecutionResult>,
) -> Result<Vec<AssertionReport>, RedactedDiagnostic> {
    let primary_json = serde_json::to_value(primary.response())
        .map_err(|_| RedactedDiagnostic::new(DiagnosticCode::ResponseProjectionFailed))?;
    let comparison_json = comparison
        .map(|result| serde_json::to_value(result.response()))
        .transpose()
        .map_err(|_| RedactedDiagnostic::new(DiagnosticCode::ResponseProjectionFailed))?;
    let primary_sha256 = hash_serializable(primary.response())
        .map_err(|_| RedactedDiagnostic::new(DiagnosticCode::ResponseHashFailed))?;
    let comparison_sha256 = comparison
        .map(|result| hash_serializable(result.response()))
        .transpose()
        .map_err(|_| RedactedDiagnostic::new(DiagnosticCode::ResponseHashFailed))?;

    Ok(case
        .expected()
        .iter()
        .map(|assertion| {
            let (json, digest) = match assertion.target() {
                CandidateRole::Primary => (&primary_json, Some(primary_sha256.as_str())),
                CandidateRole::Comparison => (
                    comparison_json.as_ref().unwrap_or(&Value::Null),
                    comparison_sha256.as_deref(),
                ),
            };
            let passed = assertion_passes(
                assertion,
                json,
                digest,
                case.tolerances().absolute_numeric_microunits(),
            );
            AssertionReport::new(assertion.id().to_owned(), assertion.target(), passed)
        })
        .collect())
}

fn assertion_passes(
    assertion: &DeterministicAssertion,
    response: &Value,
    response_sha256: Option<&str>,
    numeric_tolerance: u64,
) -> bool {
    match assertion {
        DeterministicAssertion::ResponseSha256 {
            expected_sha256, ..
        } => response_sha256 == Some(expected_sha256),
        DeterministicAssertion::JsonPointerPresent { pointer, .. } => {
            response.pointer(pointer).is_some()
        }
        DeterministicAssertion::JsonPointerEquals {
            pointer, expected, ..
        } => response.pointer(pointer) == Some(expected),
        DeterministicAssertion::JsonNumberMicrounitsWithin {
            pointer,
            expected_microunits,
            ..
        } => response
            .pointer(pointer)
            .and_then(Value::as_i64)
            .is_some_and(|actual| actual.abs_diff(*expected_microunits) <= numeric_tolerance),
    }
}

fn judge_candidates<'a>(
    dataset_sha256: &str,
    case_id: &str,
    methodology: &JudgeMethodology,
    primary: &'a EvalExecutionResult,
    comparison: Option<&'a EvalExecutionResult>,
) -> (JudgeCandidate<'a>, Option<JudgeCandidate<'a>>, bool, String) {
    let order = methodology
        .blind_seed()
        .map_or(BlindedOrder::PrimaryFirst, |seed| {
            BlindedOrder::derive(seed, dataset_sha256, case_id)
        });
    let blinded = methodology.blind_seed().is_some() && comparison.is_some();
    let (first, second) = match (order, comparison) {
        (BlindedOrder::ComparisonFirst, Some(comparison)) => (
            JudgeCandidate::new(JudgeLabel::A, comparison.response()),
            Some(JudgeCandidate::new(JudgeLabel::B, primary.response())),
        ),
        (_, Some(comparison)) => (
            JudgeCandidate::new(JudgeLabel::A, primary.response()),
            Some(JudgeCandidate::new(JudgeLabel::B, comparison.response())),
        ),
        (_, None) => (JudgeCandidate::new(JudgeLabel::A, primary.response()), None),
    };
    let seed = methodology.blind_seed().unwrap_or_default();
    let marker = match (order, comparison.is_some()) {
        (BlindedOrder::PrimaryFirst, true) => b"primary_first".as_slice(),
        (BlindedOrder::ComparisonFirst, true) => b"comparison_first".as_slice(),
        (_, false) => b"single".as_slice(),
    };
    let mut material = Vec::with_capacity(dataset_sha256.len() + case_id.len() + marker.len() + 40);
    material.extend_from_slice(&seed.to_be_bytes());
    material.extend_from_slice(
        &u64::try_from(dataset_sha256.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(dataset_sha256.as_bytes());
    material.extend_from_slice(
        &u64::try_from(case_id.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(case_id.as_bytes());
    material.extend_from_slice(
        &u64::try_from(marker.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    material.extend_from_slice(marker);
    (first, second, blinded, sha256_bytes(&material))
}

fn case_failure_from_candidate(
    case: &EvalCase,
    mut executions: Vec<ExecutionReport>,
    assertions: Vec<AssertionReport>,
    usage: EvalUsage,
    failure: CandidateFailure,
) -> CaseReport {
    if let Some(report) = failure.report {
        executions.push(report);
    }
    let (usage, diagnostic) = match usage.checked_add(failure.usage) {
        Some(combined) if combined.cost_microunits() > case.cost_ceiling_microunits() => (
            combined,
            RedactedDiagnostic::new(DiagnosticCode::CaseCostExceeded),
        ),
        Some(combined) => (combined, failure.diagnostic),
        None => (
            EvalUsage::new(Some(u64::MAX), Some(u64::MAX), u64::MAX),
            RedactedDiagnostic::new(DiagnosticCode::UsageOverflow),
        ),
    };
    case_failure(case, executions, assertions, usage, diagnostic)
}

#[expect(
    clippy::too_many_arguments,
    reason = "rejected judge reports preserve every independent reproducibility field"
)]
fn rejected_judge_failure(
    case: &EvalCase,
    executions: Vec<ExecutionReport>,
    assertions: Vec<AssertionReport>,
    usage: EvalUsage,
    methodology: &JudgeMethodology,
    calibration: &crate::JudgeCalibration,
    result: &JudgeResult,
    blinded: bool,
    order_sha256: String,
    diagnostic: RedactedDiagnostic,
) -> CaseReport {
    let valid_score = (result.score_microunits() <= 1_000_000).then_some(result.score_microunits());
    let rejected = RejectedJudgeReport::new(
        methodology,
        calibration.clone(),
        result.evidence().clone(),
        valid_score,
        blinded,
        order_sha256,
        result.usage(),
        diagnostic.clone(),
    );
    case_failure(case, executions, assertions, usage, diagnostic).with_rejected_judge(rejected)
}

fn case_failure(
    case: &EvalCase,
    executions: Vec<ExecutionReport>,
    assertions: Vec<AssertionReport>,
    usage: EvalUsage,
    diagnostic: RedactedDiagnostic,
) -> CaseReport {
    CaseReport::new(
        case.id().to_owned(),
        CaseOutcome::Failed,
        executions,
        assertions,
        None,
        usage,
        Some(diagnostic),
    )
}

fn add_timeout_exposure(usage: EvalUsage, cost_exposure_microunits: u64) -> EvalUsage {
    usage
        .checked_add(EvalUsage::new(None, None, cost_exposure_microunits))
        .unwrap_or_else(|| EvalUsage::new(Some(u64::MAX), Some(u64::MAX), u64::MAX))
}

fn case_timeout(case: &EvalCase, executions: Vec<ExecutionReport>, usage: EvalUsage) -> CaseReport {
    CaseReport::new(
        case.id().to_owned(),
        CaseOutcome::TimedOut,
        executions,
        Vec::new(),
        None,
        usage,
        Some(RedactedDiagnostic::new(DiagnosticCode::DeadlineExceeded)),
    )
}

fn retain_diagnostics(cases: &mut [CaseReport], policy: DiagnosticRetention) {
    match policy {
        DiagnosticRetention::Discard => {
            cases.iter_mut().for_each(CaseReport::discard_diagnostic);
        }
        DiagnosticRetention::Redacted {
            max_diagnostics,
            max_source_bytes,
        } => {
            let mut retained = 0_usize;
            for case in cases {
                let retain = case.diagnostic().is_some_and(|diagnostic| {
                    retained < max_diagnostics
                        && diagnostic
                            .source_bytes()
                            .is_none_or(|bytes| bytes <= max_source_bytes)
                });
                if retain {
                    retained += 1;
                } else {
                    case.discard_diagnostic();
                }
            }
        }
    }
}
