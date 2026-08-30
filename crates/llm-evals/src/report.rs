use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CandidateRole, DiagnosticCode, EvalUsage, ExecutionTarget, JudgeCalibration, JudgeMethodology,
    RedactedDiagnostic,
    hashing::{canonical_json, hash_serializable, is_sha256},
};

/// The only evaluation report wire schema emitted by this crate.
pub const REPORT_SCHEMA_VERSION: &str = "1.0.0";
/// The deterministic runner implementation revision.
pub const RUNNER_VERSION: &str = "1.0.0";

/// Resource limits applied while admitting a serialized evaluation report.
///
/// Limits are caller-selected ceilings; the fixed report schema can impose
/// stricter limits, such as two ordered candidate executions per case.
#[allow(
    clippy::struct_field_names,
    reason = "resource ceilings remain unambiguous when consistently named as maxima"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReportBounds {
    max_bytes: usize,
    max_cases: usize,
    max_executions_per_case: usize,
    max_assertions_per_case: usize,
    max_route_capabilities: usize,
    max_identifier_bytes: usize,
    max_diagnostic_source_bytes: u64,
}

impl ReportBounds {
    /// Creates positive report admission limits.
    ///
    /// # Errors
    ///
    /// Returns [`ReportAdmissionError::InvalidBounds`] when any limit is zero.
    pub const fn new(
        max_bytes: usize,
        max_cases: usize,
        max_executions_per_case: usize,
        max_assertions_per_case: usize,
        max_route_capabilities: usize,
        max_identifier_bytes: usize,
        max_diagnostic_source_bytes: u64,
    ) -> Result<Self, ReportAdmissionError> {
        if max_bytes == 0
            || max_cases == 0
            || max_executions_per_case == 0
            || max_assertions_per_case == 0
            || max_route_capabilities == 0
            || max_identifier_bytes == 0
            || max_diagnostic_source_bytes == 0
        {
            return Err(ReportAdmissionError::InvalidBounds);
        }
        Ok(Self {
            max_bytes,
            max_cases,
            max_executions_per_case,
            max_assertions_per_case,
            max_route_capabilities,
            max_identifier_bytes,
            max_diagnostic_source_bytes,
        })
    }

    /// Returns the maximum encoded report size.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// Returns the maximum number of cases.
    #[must_use]
    pub const fn max_cases(self) -> usize {
        self.max_cases
    }

    /// Returns the maximum candidate execution records in one case.
    #[must_use]
    pub const fn max_executions_per_case(self) -> usize {
        self.max_executions_per_case
    }

    /// Returns the maximum deterministic assertion records in one case.
    #[must_use]
    pub const fn max_assertions_per_case(self) -> usize {
        self.max_assertions_per_case
    }

    /// Returns the maximum entries in each route capability list.
    #[must_use]
    pub const fn max_route_capabilities(self) -> usize {
        self.max_route_capabilities
    }

    /// Returns the maximum byte length of a stable identifier.
    #[must_use]
    pub const fn max_identifier_bytes(self) -> usize {
        self.max_identifier_bytes
    }

    /// Returns the maximum sensitive source length represented by a diagnostic.
    #[must_use]
    pub const fn max_diagnostic_source_bytes(self) -> u64 {
        self.max_diagnostic_source_bytes
    }
}

/// A content-free evaluation report admission failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReportAdmissionError {
    /// A configured resource limit was zero.
    #[error("evaluation report bounds must be positive")]
    InvalidBounds,
    /// The source or canonical report exceeded its encoded byte limit.
    #[error("evaluation report exceeds its byte limit")]
    TooManyBytes,
    /// The report contained no cases or exceeded its case limit.
    #[error("evaluation report case count is outside its admitted bounds")]
    CaseCount,
    /// A case exceeded its candidate execution record limit.
    #[error("evaluation report contains too many execution records")]
    ExecutionCount,
    /// A case exceeded its deterministic assertion record limit.
    #[error("evaluation report contains too many assertion records")]
    AssertionCount,
    /// An execution target exceeded its route capability limit.
    #[error("evaluation report contains too many route capabilities")]
    CapabilityCount,
    /// A diagnostic represented a source larger than the admitted limit.
    #[error("evaluation report diagnostic source length exceeds its limit")]
    DiagnosticSourceBytes,
    /// The report wire schema version is unsupported.
    #[error("unsupported evaluation report schema version")]
    UnsupportedSchemaVersion,
    /// The deterministic runner version is unsupported.
    #[error("unsupported evaluation report runner version")]
    UnsupportedRunnerVersion,
    /// A stable identifier or version was invalid.
    #[error("evaluation report contains an invalid stable identifier")]
    InvalidIdentifier,
    /// A required SHA-256 digest was not lowercase hexadecimal.
    #[error("evaluation report contains an invalid SHA-256 digest")]
    InvalidDigest,
    /// The caller-supplied trusted report digest was not lowercase hexadecimal.
    #[error("trusted evaluation report SHA-256 digest is invalid")]
    InvalidTrustedDigest,
    /// Canonical report bytes differed from the caller's trusted digest.
    #[error("evaluation report differs from its trusted SHA-256 digest")]
    TrustedDigestMismatch,
    /// An execution target lacked exact, bounded route or model evidence.
    #[error("evaluation report contains an invalid execution target")]
    InvalidExecutionTarget,
    /// JSON decoding failed without exposing source content.
    #[error("evaluation report JSON is invalid")]
    InvalidJson,
    /// A case outcome was inconsistent with its retained evidence.
    #[error("evaluation report case evidence is inconsistent")]
    InconsistentCase,
    /// Model-judge evidence was invalid or internally inconsistent.
    #[error("evaluation report judge evidence is invalid")]
    InvalidJudgeEvidence,
    /// Aggregate counters differed from the admitted cases.
    #[error("evaluation report totals are inconsistent")]
    InconsistentTotals,
    /// Aggregate usage or outcome accounting overflowed.
    #[error("evaluation report accounting overflowed")]
    AccountingOverflow,
    /// The reproducibility digest differed from canonical report evidence.
    #[error("evaluation report reproducibility digest is inconsistent")]
    ReproducibilityMismatch,
    /// Canonical encoding failed without exposing report content.
    #[error("evaluation report could not be encoded")]
    Serialization,
}

/// Final outcome for one evaluation case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseOutcome {
    /// Every deterministic assertion and admitted judge threshold passed.
    Passed,
    /// Execution, evidence, assertions, cost, or judging failed.
    Failed,
    /// The enclosing case deadline elapsed and cancelled remaining work.
    TimedOut,
}

/// Content-free result of one deterministic assertion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionReport {
    id: String,
    target: CandidateRole,
    passed: bool,
}

impl AssertionReport {
    pub(crate) fn new(id: String, target: CandidateRole, passed: bool) -> Self {
        Self { id, target, passed }
    }

    /// Borrows the assertion identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the evaluated candidate.
    #[must_use]
    pub const fn target(&self) -> CandidateRole {
        self.target
    }

    /// Returns whether the deterministic property passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }
}

/// Content-free reproducibility evidence for one candidate execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExecutionReport {
    role: CandidateRole,
    evidence: ExecutionTarget,
    input_sha256: String,
    response_sha256: String,
    usage: EvalUsage,
}

impl ExecutionReport {
    pub(crate) fn new(
        role: CandidateRole,
        evidence: ExecutionTarget,
        input_sha256: String,
        response_sha256: String,
        usage: EvalUsage,
    ) -> Self {
        Self {
            role,
            evidence,
            input_sha256,
            response_sha256,
            usage,
        }
    }

    /// Returns the candidate role.
    #[must_use]
    pub const fn role(&self) -> CandidateRole {
        self.role
    }

    /// Borrows exact observed revision evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionTarget {
        &self.evidence
    }

    /// Borrows the request or prompt-reference digest.
    #[must_use]
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }

    /// Borrows the canonical response digest.
    #[must_use]
    pub fn response_sha256(&self) -> &str {
        &self.response_sha256
    }

    /// Returns normalized usage and cost.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}

/// Content-free evidence emitted after calibrated model judging.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JudgeReport {
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    calibration: JudgeCalibration,
    evidence: ExecutionTarget,
    score_microunits: u64,
    passed: bool,
    blinded: bool,
    order_sha256: String,
    usage: EvalUsage,
}

impl JudgeReport {
    #[expect(
        clippy::too_many_arguments,
        reason = "the report retains every independent reproducibility field"
    )]
    pub(crate) fn new(
        methodology: &JudgeMethodology,
        calibration: JudgeCalibration,
        evidence: ExecutionTarget,
        score_microunits: u64,
        passed: bool,
        blinded: bool,
        order_sha256: String,
        usage: EvalUsage,
    ) -> Self {
        Self {
            methodology_id: methodology.methodology_id().to_owned(),
            methodology_version: methodology.methodology_version().to_owned(),
            rubric_sha256: methodology.rubric_sha256().to_owned(),
            calibration,
            evidence,
            score_microunits,
            passed,
            blinded,
            order_sha256,
            usage,
        }
    }

    /// Borrows the methodology identifier.
    #[must_use]
    pub fn methodology_id(&self) -> &str {
        &self.methodology_id
    }

    /// Borrows the methodology version.
    #[must_use]
    pub fn methodology_version(&self) -> &str {
        &self.methodology_version
    }

    /// Borrows the rubric digest.
    #[must_use]
    pub fn rubric_sha256(&self) -> &str {
        &self.rubric_sha256
    }

    /// Borrows content-addressed judge calibration evidence.
    #[must_use]
    pub const fn calibration(&self) -> &JudgeCalibration {
        &self.calibration
    }

    /// Borrows exact observed judge revision evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionTarget {
        &self.evidence
    }

    /// Returns the million-point judge score.
    #[must_use]
    pub const fn score_microunits(&self) -> u64 {
        self.score_microunits
    }

    /// Returns whether the score met the dataset tolerance.
    #[must_use]
    pub const fn passed(&self) -> bool {
        self.passed
    }

    /// Returns whether pair order was seed-blinded.
    #[must_use]
    pub const fn blinded(&self) -> bool {
        self.blinded
    }

    /// Borrows the content-free deterministic pair-order digest.
    #[must_use]
    pub fn order_sha256(&self) -> &str {
        &self.order_sha256
    }

    /// Returns normalized judge usage and cost.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}
/// Content-free evidence for a charged judge result rejected by runner policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RejectedJudgeReport {
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    calibration: JudgeCalibration,
    evidence: ExecutionTarget,
    score_microunits: Option<u64>,
    blinded: bool,
    order_sha256: String,
    usage: EvalUsage,
    diagnostic: Option<RedactedDiagnostic>,
}

impl RejectedJudgeReport {
    #[expect(
        clippy::too_many_arguments,
        reason = "rejected judge evidence retains every independent reproducibility field"
    )]
    pub(crate) fn new(
        methodology: &JudgeMethodology,
        calibration: JudgeCalibration,
        evidence: ExecutionTarget,
        score_microunits: Option<u64>,
        blinded: bool,
        order_sha256: String,
        usage: EvalUsage,
        diagnostic: RedactedDiagnostic,
    ) -> Self {
        Self {
            methodology_id: methodology.methodology_id().to_owned(),
            methodology_version: methodology.methodology_version().to_owned(),
            rubric_sha256: methodology.rubric_sha256().to_owned(),
            calibration,
            evidence,
            score_microunits,
            blinded,
            order_sha256,
            usage,
            diagnostic: Some(diagnostic),
        }
    }

    /// Borrows exact observed judge revision evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionTarget {
        &self.evidence
    }

    /// Returns the score only when it was inside the admitted million-point scale.
    #[must_use]
    pub const fn score_microunits(&self) -> Option<u64> {
        self.score_microunits
    }

    /// Returns usage charged for the rejected result.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }

    /// Borrows the policy-retained rejection diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&RedactedDiagnostic> {
        self.diagnostic.as_ref()
    }

    fn discard_diagnostic(&mut self) {
        self.diagnostic = None;
    }
}

/// Content-free result and reproducibility evidence for one case.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseReport {
    case_id: String,
    outcome: CaseOutcome,
    executions: Vec<ExecutionReport>,
    assertions: Vec<AssertionReport>,
    judge: Option<JudgeReport>,
    rejected_judge: Option<RejectedJudgeReport>,
    usage: EvalUsage,
    unattributed_usage: EvalUsage,
    diagnostic: Option<RedactedDiagnostic>,
}

impl CaseReport {
    pub(crate) fn new(
        case_id: String,
        outcome: CaseOutcome,
        executions: Vec<ExecutionReport>,
        assertions: Vec<AssertionReport>,
        judge: Option<JudgeReport>,
        usage: EvalUsage,
        diagnostic: Option<RedactedDiagnostic>,
    ) -> Self {
        let unattributed_usage =
            compute_unattributed_usage(usage, &executions, judge.as_ref(), None);
        Self {
            case_id,
            outcome,
            executions,
            assertions,
            judge,
            rejected_judge: None,
            usage,
            unattributed_usage,
            diagnostic,
        }
    }

    /// Borrows the case identifier.
    #[must_use]
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Returns the final outcome.
    #[must_use]
    pub const fn outcome(&self) -> CaseOutcome {
        self.outcome
    }

    /// Borrows ordered candidate execution evidence.
    #[must_use]
    pub fn executions(&self) -> &[ExecutionReport] {
        &self.executions
    }

    /// Borrows deterministic assertion results in dataset order.
    #[must_use]
    pub fn assertions(&self) -> &[AssertionReport] {
        &self.assertions
    }

    /// Borrows admitted model-judge evidence when judging ran.
    #[must_use]
    pub const fn judge(&self) -> Option<&JudgeReport> {
        self.judge.as_ref()
    }
    /// Borrows evidence for a charged judge result rejected by runner policy.
    #[must_use]
    pub const fn rejected_judge(&self) -> Option<&RejectedJudgeReport> {
        self.rejected_judge.as_ref()
    }

    /// Returns aggregate candidate and judge usage.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
    /// Returns charged usage not represented by a completed execution or judge result.
    #[must_use]
    pub const fn unattributed_usage(&self) -> EvalUsage {
        self.unattributed_usage
    }

    /// Borrows a policy-retained redacted diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&RedactedDiagnostic> {
        self.diagnostic.as_ref()
    }

    pub(crate) fn discard_diagnostic(&mut self) {
        self.diagnostic = None;
        if let Some(rejected) = &mut self.rejected_judge {
            rejected.discard_diagnostic();
        }
    }

    pub(crate) fn with_rejected_judge(mut self, rejected_judge: RejectedJudgeReport) -> Self {
        self.rejected_judge = Some(rejected_judge);
        self.unattributed_usage = compute_unattributed_usage(
            self.usage,
            &self.executions,
            self.judge.as_ref(),
            self.rejected_judge.as_ref(),
        );
        self
    }
}
fn compute_unattributed_usage(
    total: EvalUsage,
    executions: &[ExecutionReport],
    judge: Option<&JudgeReport>,
    rejected_judge: Option<&RejectedJudgeReport>,
) -> EvalUsage {
    let mut attributed = EvalUsage::default();
    for execution in executions {
        attributed = saturating_usage_add(attributed, execution.usage);
    }
    if let Some(judge) = judge {
        attributed = saturating_usage_add(attributed, judge.usage);
    }
    if let Some(rejected) = rejected_judge {
        attributed = saturating_usage_add(attributed, rejected.usage);
    }
    usage_difference(total, attributed)
}

fn saturating_usage_add(left: EvalUsage, right: EvalUsage) -> EvalUsage {
    EvalUsage::new(
        saturating_counter_add(left.input_tokens(), right.input_tokens()),
        saturating_counter_add(left.output_tokens(), right.output_tokens()),
        left.cost_microunits()
            .saturating_add(right.cost_microunits()),
    )
}

const fn saturating_counter_add(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.saturating_add(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

fn usage_difference(total: EvalUsage, attributed: EvalUsage) -> EvalUsage {
    EvalUsage::new(
        counter_difference(total.input_tokens(), attributed.input_tokens()),
        counter_difference(total.output_tokens(), attributed.output_tokens()),
        total
            .cost_microunits()
            .saturating_sub(attributed.cost_microunits()),
    )
}

const fn counter_difference(total: Option<u64>, attributed: Option<u64>) -> Option<u64> {
    match (total, attributed) {
        (Some(total), Some(attributed)) => Some(total.saturating_sub(attributed)),
        (Some(total), None) => Some(total),
        (None, Some(_) | None) => None,
    }
}

/// Aggregate evaluation report counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReportTotals {
    passed: u64,
    failed: u64,
    timed_out: u64,
    usage: EvalUsage,
}

impl ReportTotals {
    pub(crate) fn from_cases(cases: &[CaseReport]) -> Option<Self> {
        let mut totals = Self::default();
        for case in cases {
            match case.outcome {
                CaseOutcome::Passed => totals.passed = totals.passed.checked_add(1)?,
                CaseOutcome::Failed => totals.failed = totals.failed.checked_add(1)?,
                CaseOutcome::TimedOut => totals.timed_out = totals.timed_out.checked_add(1)?,
            }
            totals.usage = totals.usage.checked_add(case.usage)?;
        }
        Some(totals)
    }

    /// Returns passed cases.
    #[must_use]
    pub const fn passed(self) -> u64 {
        self.passed
    }

    /// Returns failed cases.
    #[must_use]
    pub const fn failed(self) -> u64 {
        self.failed
    }

    /// Returns timed-out cases.
    #[must_use]
    pub const fn timed_out(self) -> u64 {
        self.timed_out
    }

    /// Returns aggregate usage and cost.
    #[must_use]
    pub const fn usage(self) -> EvalUsage {
        self.usage
    }
}

/// A deterministic evaluation report that contains hashes and redacted diagnostics, never prompts or responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvaluationReport {
    schema_version: String,
    runner_version: String,
    dataset_id: String,
    dataset_version: String,
    dataset_sha256: String,
    executor_evidence_sha256: Option<String>,
    judge_evidence_sha256: Option<String>,
    reproducibility_sha256: String,
    cases: Vec<CaseReport>,
    totals: ReportTotals,
}

impl EvaluationReport {
    #[expect(
        clippy::too_many_arguments,
        reason = "the report root records independent version and reproducibility evidence"
    )]
    pub(crate) fn new(
        dataset_id: String,
        dataset_version: String,
        dataset_sha256: String,
        executor_evidence_sha256: Option<String>,
        judge_evidence_sha256: Option<String>,
        reproducibility_sha256: String,
        cases: Vec<CaseReport>,
        totals: ReportTotals,
    ) -> Self {
        Self {
            schema_version: REPORT_SCHEMA_VERSION.to_owned(),
            runner_version: RUNNER_VERSION.to_owned(),
            dataset_id,
            dataset_version,
            dataset_sha256,
            executor_evidence_sha256,
            judge_evidence_sha256,
            reproducibility_sha256,
            cases,
            totals,
        }
    }

    /// Parses and admits a bounded evaluation report against a trusted digest.
    ///
    /// The source buffer is not retained. Admission verifies the canonical report
    /// against `trusted_sha256`, then validates all evidence, aggregate counters,
    /// and the reproducibility digest. The trusted digest must come from a channel
    /// independent of `bytes`.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`ReportAdmissionError`] when JSON decoding,
    /// trusted digest verification, resource bounds, report evidence, accounting,
    /// or canonical hashing fails.
    pub fn from_json(
        bytes: &[u8],
        trusted_sha256: &str,
        bounds: ReportBounds,
    ) -> Result<Self, ReportAdmissionError> {
        if bytes.len() > bounds.max_bytes {
            return Err(ReportAdmissionError::TooManyBytes);
        }
        if !is_sha256(trusted_sha256) {
            return Err(ReportAdmissionError::InvalidTrustedDigest);
        }
        let wire: EvaluationReportWire =
            serde_json::from_slice(bytes).map_err(|_| ReportAdmissionError::InvalidJson)?;
        let canonical_sha256 =
            hash_serializable(&wire).map_err(|_| ReportAdmissionError::Serialization)?;
        if !constant_time_digest_eq(&canonical_sha256, trusted_sha256) {
            return Err(ReportAdmissionError::TrustedDigestMismatch);
        }
        wire.validate(bounds)?;
        Ok(Self::from(wire))
    }

    /// Computes the canonical SHA-256 digest to persist through a trusted channel.
    ///
    /// # Errors
    ///
    /// Returns [`ReportAdmissionError::Serialization`] when canonical encoding fails.
    pub fn canonical_sha256(&self) -> Result<String, ReportAdmissionError> {
        hash_serializable(self).map_err(|_| ReportAdmissionError::Serialization)
    }

    /// Returns the report wire schema version.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Returns the deterministic runner implementation revision.
    #[must_use]
    pub fn runner_version(&self) -> &str {
        &self.runner_version
    }

    /// Borrows the dataset identifier.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Borrows the dataset version.
    #[must_use]
    pub fn dataset_version(&self) -> &str {
        &self.dataset_version
    }

    /// Borrows the admitted canonical dataset digest.
    #[must_use]
    pub fn dataset_sha256(&self) -> &str {
        &self.dataset_sha256
    }
    /// Borrows the trusted canonical executor evidence digest when supplied.
    #[must_use]
    pub fn executor_evidence_sha256(&self) -> Option<&str> {
        self.executor_evidence_sha256.as_deref()
    }

    /// Borrows the trusted canonical judge evidence digest when supplied.
    #[must_use]
    pub fn judge_evidence_sha256(&self) -> Option<&str> {
        self.judge_evidence_sha256.as_deref()
    }

    /// Borrows the digest of ordered content-free case evidence.
    #[must_use]
    pub fn reproducibility_sha256(&self) -> &str {
        &self.reproducibility_sha256
    }

    /// Borrows per-case reports in dataset order.
    #[must_use]
    pub fn cases(&self) -> &[CaseReport] {
        &self.cases
    }

    /// Returns aggregate outcomes, usage, and cost.
    #[must_use]
    pub const fn totals(&self) -> ReportTotals {
        self.totals
    }
}

const MAX_STABLE_IDENTIFIER_BYTES: usize = 160;

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum CaseOutcomeWire {
    Passed,
    Failed,
    TimedOut,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AssertionReportWire {
    id: String,
    target: CandidateRole,
    passed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionReportWire {
    role: CandidateRole,
    evidence: ExecutionTarget,
    input_sha256: String,
    response_sha256: String,
    usage: EvalUsage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JudgeReportWire {
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    calibration: JudgeCalibration,
    evidence: ExecutionTarget,
    score_microunits: u64,
    passed: bool,
    blinded: bool,
    order_sha256: String,
    usage: EvalUsage,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RejectedJudgeReportWire {
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    calibration: JudgeCalibration,
    evidence: ExecutionTarget,
    score_microunits: Option<u64>,
    blinded: bool,
    order_sha256: String,
    usage: EvalUsage,
    diagnostic: Option<RedactedDiagnostic>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseReportWire {
    case_id: String,
    outcome: CaseOutcomeWire,
    executions: Vec<ExecutionReportWire>,
    assertions: Vec<AssertionReportWire>,
    judge: Option<JudgeReportWire>,
    rejected_judge: Option<RejectedJudgeReportWire>,
    usage: EvalUsage,
    unattributed_usage: EvalUsage,
    diagnostic: Option<RedactedDiagnostic>,
}

#[derive(Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ReportTotalsWire {
    passed: u64,
    failed: u64,
    timed_out: u64,
    usage: EvalUsage,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvaluationReportWire {
    schema_version: String,
    runner_version: String,
    dataset_id: String,
    dataset_version: String,
    dataset_sha256: String,
    executor_evidence_sha256: Option<String>,
    judge_evidence_sha256: Option<String>,
    reproducibility_sha256: String,
    cases: Vec<CaseReportWire>,
    totals: ReportTotalsWire,
}

#[derive(Serialize)]
struct ReproducibilityMaterial<'a> {
    runner_version: &'a str,
    dataset_sha256: &'a str,
    executor_evidence_sha256: Option<&'a str>,
    judge_evidence_sha256: Option<&'a str>,
    cases: &'a [CaseReportWire],
}

impl EvaluationReportWire {
    fn validate(&self, bounds: ReportBounds) -> Result<(), ReportAdmissionError> {
        if self.schema_version != REPORT_SCHEMA_VERSION {
            return Err(ReportAdmissionError::UnsupportedSchemaVersion);
        }
        if self.runner_version != RUNNER_VERSION {
            return Err(ReportAdmissionError::UnsupportedRunnerVersion);
        }
        validate_identifier(&self.dataset_id, bounds)?;
        validate_identifier(&self.dataset_version, bounds)?;
        validate_digest(&self.dataset_sha256)?;
        if let Some(digest) = &self.executor_evidence_sha256 {
            validate_digest(digest)?;
        }
        if let Some(digest) = &self.judge_evidence_sha256 {
            validate_digest(digest)?;
        }
        validate_digest(&self.reproducibility_sha256)?;
        if self.cases.is_empty() || self.cases.len() > bounds.max_cases {
            return Err(ReportAdmissionError::CaseCount);
        }
        for (index, case) in self.cases.iter().enumerate() {
            validate_case(case, bounds)?;
            if self.cases[..index]
                .iter()
                .any(|previous| previous.case_id == case.case_id)
            {
                return Err(ReportAdmissionError::InconsistentCase);
            }
        }
        let totals = ReportTotalsWire::from_cases(&self.cases)
            .ok_or(ReportAdmissionError::AccountingOverflow)?;
        if totals != self.totals {
            return Err(ReportAdmissionError::InconsistentTotals);
        }
        let reproducibility_sha256 = hash_serializable(&ReproducibilityMaterial {
            runner_version: &self.runner_version,
            dataset_sha256: &self.dataset_sha256,
            executor_evidence_sha256: self.executor_evidence_sha256.as_deref(),
            judge_evidence_sha256: self.judge_evidence_sha256.as_deref(),
            cases: &self.cases,
        })
        .map_err(|_| ReportAdmissionError::Serialization)?;
        if reproducibility_sha256 != self.reproducibility_sha256 {
            return Err(ReportAdmissionError::ReproducibilityMismatch);
        }
        let canonical = canonical_json(self).map_err(|_| ReportAdmissionError::Serialization)?;
        if canonical.len() > bounds.max_bytes {
            return Err(ReportAdmissionError::TooManyBytes);
        }
        Ok(())
    }
}

impl ReportTotalsWire {
    fn from_cases(cases: &[CaseReportWire]) -> Option<Self> {
        let mut totals = Self::default();
        for case in cases {
            match case.outcome {
                CaseOutcomeWire::Passed => totals.passed = totals.passed.checked_add(1)?,
                CaseOutcomeWire::Failed => totals.failed = totals.failed.checked_add(1)?,
                CaseOutcomeWire::TimedOut => {
                    totals.timed_out = totals.timed_out.checked_add(1)?;
                }
            }
            totals.usage = totals.usage.checked_add(case.usage)?;
        }
        Some(totals)
    }
}

impl From<CaseOutcomeWire> for CaseOutcome {
    fn from(wire: CaseOutcomeWire) -> Self {
        match wire {
            CaseOutcomeWire::Passed => Self::Passed,
            CaseOutcomeWire::Failed => Self::Failed,
            CaseOutcomeWire::TimedOut => Self::TimedOut,
        }
    }
}

impl From<AssertionReportWire> for AssertionReport {
    fn from(wire: AssertionReportWire) -> Self {
        Self {
            id: wire.id,
            target: wire.target,
            passed: wire.passed,
        }
    }
}

impl From<ExecutionReportWire> for ExecutionReport {
    fn from(wire: ExecutionReportWire) -> Self {
        Self {
            role: wire.role,
            evidence: wire.evidence,
            input_sha256: wire.input_sha256,
            response_sha256: wire.response_sha256,
            usage: wire.usage,
        }
    }
}

impl From<JudgeReportWire> for JudgeReport {
    fn from(wire: JudgeReportWire) -> Self {
        Self {
            methodology_id: wire.methodology_id,
            methodology_version: wire.methodology_version,
            rubric_sha256: wire.rubric_sha256,
            calibration: wire.calibration,
            evidence: wire.evidence,
            score_microunits: wire.score_microunits,
            passed: wire.passed,
            blinded: wire.blinded,
            order_sha256: wire.order_sha256,
            usage: wire.usage,
        }
    }
}
impl From<RejectedJudgeReportWire> for RejectedJudgeReport {
    fn from(wire: RejectedJudgeReportWire) -> Self {
        Self {
            methodology_id: wire.methodology_id,
            methodology_version: wire.methodology_version,
            rubric_sha256: wire.rubric_sha256,
            calibration: wire.calibration,
            evidence: wire.evidence,
            score_microunits: wire.score_microunits,
            blinded: wire.blinded,
            order_sha256: wire.order_sha256,
            usage: wire.usage,
            diagnostic: wire.diagnostic,
        }
    }
}

impl From<CaseReportWire> for CaseReport {
    fn from(wire: CaseReportWire) -> Self {
        Self {
            case_id: wire.case_id,
            outcome: wire.outcome.into(),
            executions: wire.executions.into_iter().map(Into::into).collect(),
            assertions: wire.assertions.into_iter().map(Into::into).collect(),
            judge: wire.judge.map(Into::into),
            rejected_judge: wire.rejected_judge.map(Into::into),
            usage: wire.usage,
            unattributed_usage: wire.unattributed_usage,
            diagnostic: wire.diagnostic,
        }
    }
}

impl From<ReportTotalsWire> for ReportTotals {
    fn from(wire: ReportTotalsWire) -> Self {
        Self {
            passed: wire.passed,
            failed: wire.failed,
            timed_out: wire.timed_out,
            usage: wire.usage,
        }
    }
}

impl From<EvaluationReportWire> for EvaluationReport {
    fn from(wire: EvaluationReportWire) -> Self {
        Self {
            schema_version: wire.schema_version,
            runner_version: wire.runner_version,
            dataset_id: wire.dataset_id,
            dataset_version: wire.dataset_version,
            dataset_sha256: wire.dataset_sha256,
            executor_evidence_sha256: wire.executor_evidence_sha256,
            judge_evidence_sha256: wire.judge_evidence_sha256,
            reproducibility_sha256: wire.reproducibility_sha256,
            cases: wire.cases.into_iter().map(Into::into).collect(),
            totals: wire.totals.into(),
        }
    }
}

fn validate_case(case: &CaseReportWire, bounds: ReportBounds) -> Result<(), ReportAdmissionError> {
    validate_identifier(&case.case_id, bounds)?;
    if case.executions.len() > bounds.max_executions_per_case {
        return Err(ReportAdmissionError::ExecutionCount);
    }
    if case.assertions.len() > bounds.max_assertions_per_case {
        return Err(ReportAdmissionError::AssertionCount);
    }
    for execution in &case.executions {
        validate_execution(execution, bounds)?;
    }
    match case.executions.as_slice() {
        [] => {}
        [primary] if primary.role == CandidateRole::Primary => {}
        [primary, comparison]
            if primary.role == CandidateRole::Primary
                && comparison.role == CandidateRole::Comparison => {}
        _ => return Err(ReportAdmissionError::InconsistentCase),
    }
    for assertion in &case.assertions {
        validate_identifier(&assertion.id, bounds)?;
        if !case
            .executions
            .iter()
            .any(|execution| execution.role == assertion.target)
        {
            return Err(ReportAdmissionError::InconsistentCase);
        }
    }
    let mut accounted_usage = case.unattributed_usage;
    for execution in &case.executions {
        accounted_usage = saturating_usage_add(accounted_usage, execution.usage);
    }
    if case.judge.is_some() && case.rejected_judge.is_some() {
        return Err(ReportAdmissionError::InvalidJudgeEvidence);
    }
    if let Some(judge) = &case.judge {
        validate_judge(judge, bounds)?;
        if judge.blinded
            && !case
                .executions
                .iter()
                .any(|execution| execution.role == CandidateRole::Comparison)
        {
            return Err(ReportAdmissionError::InvalidJudgeEvidence);
        }
        accounted_usage = saturating_usage_add(accounted_usage, judge.usage);
    } else if let Some(rejected) = &case.rejected_judge {
        validate_rejected_judge(rejected, bounds)?;
        if rejected.blinded
            && !case
                .executions
                .iter()
                .any(|execution| execution.role == CandidateRole::Comparison)
        {
            return Err(ReportAdmissionError::InvalidJudgeEvidence);
        }
        accounted_usage = saturating_usage_add(accounted_usage, rejected.usage);
    }
    if accounted_usage != case.usage {
        return Err(ReportAdmissionError::InconsistentCase);
    }
    validate_diagnostic(case.diagnostic.as_ref(), bounds)?;
    validate_case_consistency(case)
}

fn validate_execution(
    execution: &ExecutionReportWire,
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    validate_target(&execution.evidence, bounds)?;
    validate_digest(&execution.input_sha256)?;
    validate_digest(&execution.response_sha256)
}

fn validate_judge(
    judge: &JudgeReportWire,
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    validate_identifier(&judge.methodology_id, bounds)?;
    validate_identifier(&judge.methodology_version, bounds)?;
    validate_digest(&judge.rubric_sha256)?;
    validate_identifier(judge.calibration.dataset_id(), bounds)?;
    validate_identifier(judge.calibration.dataset_version(), bounds)?;
    validate_digest(judge.calibration.evidence_sha256())?;
    validate_target(&judge.evidence, bounds)?;
    validate_digest(&judge.order_sha256)?;
    if judge.score_microunits > 1_000_000 {
        return Err(ReportAdmissionError::InvalidJudgeEvidence);
    }
    Ok(())
}
fn validate_rejected_judge(
    rejected: &RejectedJudgeReportWire,
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    validate_identifier(&rejected.methodology_id, bounds)?;
    validate_identifier(&rejected.methodology_version, bounds)?;
    validate_digest(&rejected.rubric_sha256)?;
    validate_identifier(rejected.calibration.dataset_id(), bounds)?;
    validate_identifier(rejected.calibration.dataset_version(), bounds)?;
    validate_digest(rejected.calibration.evidence_sha256())?;
    validate_target(&rejected.evidence, bounds)?;
    validate_digest(&rejected.order_sha256)?;
    validate_diagnostic(rejected.diagnostic.as_ref(), bounds)?;
    if rejected
        .score_microunits
        .is_some_and(|score| score > 1_000_000)
    {
        return Err(ReportAdmissionError::InvalidJudgeEvidence);
    }
    Ok(())
}

fn validate_target(
    target: &ExecutionTarget,
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    let route = target.route();
    if !matches!(route.revision(), Some(revision) if revision > 0) {
        return Err(ReportAdmissionError::InvalidExecutionTarget);
    }
    validate_identifier(route.id(), bounds)?;
    validate_capabilities(route.required_capabilities(), bounds)?;
    validate_capabilities(route.preferred_capabilities(), bounds)?;
    validate_identifier(target.provider(), bounds)?;
    validate_identifier(target.model(), bounds)?;
    validate_identifier(target.model_revision(), bounds)
}

fn validate_capabilities(
    capabilities: &[String],
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    if capabilities.len() > bounds.max_route_capabilities {
        return Err(ReportAdmissionError::CapabilityCount);
    }
    for (index, capability) in capabilities.iter().enumerate() {
        validate_identifier(capability, bounds)?;
        if capabilities[..index].contains(capability) {
            return Err(ReportAdmissionError::InvalidExecutionTarget);
        }
    }
    Ok(())
}

fn validate_diagnostic(
    diagnostic: Option<&RedactedDiagnostic>,
    bounds: ReportBounds,
) -> Result<(), ReportAdmissionError> {
    let Some(diagnostic) = diagnostic else {
        return Ok(());
    };
    if diagnostic
        .source_bytes()
        .is_some_and(|source_bytes| source_bytes > bounds.max_diagnostic_source_bytes)
    {
        return Err(ReportAdmissionError::DiagnosticSourceBytes);
    }
    if let Some(digest) = diagnostic.source_sha256() {
        validate_digest(digest)?;
    }
    Ok(())
}

fn validate_case_consistency(case: &CaseReportWire) -> Result<(), ReportAdmissionError> {
    let assertions_passed =
        !case.assertions.is_empty() && case.assertions.iter().all(|assertion| assertion.passed);
    let assertion_failed = case.assertions.iter().any(|assertion| !assertion.passed);
    match case.outcome {
        CaseOutcomeWire::Passed
            if case.executions.is_empty()
                || !assertions_passed
                || case.judge.as_ref().is_some_and(|judge| !judge.passed)
                || case.rejected_judge.is_some()
                || case.diagnostic.is_some() =>
        {
            return Err(ReportAdmissionError::InconsistentCase);
        }
        CaseOutcomeWire::Failed => {
            if let Some(judge) = &case.judge
                && (judge.passed || !assertions_passed)
            {
                return Err(ReportAdmissionError::InconsistentCase);
            }
            if let Some(rejected) = &case.rejected_judge
                && (!assertions_passed || case.diagnostic.as_ref() != rejected.diagnostic.as_ref())
            {
                return Err(ReportAdmissionError::InconsistentCase);
            }
        }
        CaseOutcomeWire::TimedOut
            if !case.assertions.is_empty()
                || case.judge.is_some()
                || case.rejected_judge.is_some() =>
        {
            return Err(ReportAdmissionError::InconsistentCase);
        }
        _ => {}
    }
    if let Some(diagnostic) = &case.diagnostic {
        match diagnostic.code() {
            DiagnosticCode::DeadlineExceeded if case.outcome != CaseOutcomeWire::TimedOut => {
                return Err(ReportAdmissionError::InconsistentCase);
            }
            DiagnosticCode::JudgeScoreBelowTolerance
                if case.outcome != CaseOutcomeWire::Failed
                    || case.judge.as_ref().is_none_or(|judge| judge.passed) =>
            {
                return Err(ReportAdmissionError::InconsistentCase);
            }
            DiagnosticCode::DeterministicAssertionFailed
                if case.outcome != CaseOutcomeWire::Failed
                    || case.judge.is_some()
                    || case.rejected_judge.is_some()
                    || !assertion_failed =>
            {
                return Err(ReportAdmissionError::InconsistentCase);
            }
            DiagnosticCode::DeadlineExceeded
            | DiagnosticCode::JudgeScoreBelowTolerance
            | DiagnosticCode::DeterministicAssertionFailed => {}
            _ if case.outcome != CaseOutcomeWire::Failed || case.judge.is_some() => {
                return Err(ReportAdmissionError::InconsistentCase);
            }
            _ => {}
        }
        if assertion_failed && diagnostic.code() != DiagnosticCode::DeterministicAssertionFailed {
            return Err(ReportAdmissionError::InconsistentCase);
        }
    }
    Ok(())
}

fn validate_identifier(value: &str, bounds: ReportBounds) -> Result<(), ReportAdmissionError> {
    if value.is_empty()
        || value.len() > bounds.max_identifier_bytes.min(MAX_STABLE_IDENTIFIER_BYTES)
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
    {
        return Err(ReportAdmissionError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ReportAdmissionError> {
    if !is_sha256(value) {
        return Err(ReportAdmissionError::InvalidDigest);
    }
    Ok(())
}

fn constant_time_digest_eq(actual: &str, expected: &str) -> bool {
    actual
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (actual, expected)| {
            difference | (actual ^ expected)
        })
        == 0
}
