use std::fmt;

use async_trait::async_trait;
use omnius_llm_core::LlmResponse;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

use crate::{
    CandidateRole, EvalInvocation, EvaluationReport, ExecutionTarget, JudgeMethodology,
    hashing::sha256_bytes,
};

/// Closed diagnostic taxonomy preventing caller-supplied content from entering reports.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCode {
    /// Candidate execution failed.
    ExecutionFailed,
    /// A prompt reference could not be resolved.
    InputResolutionFailed,
    /// A provider rejected or failed a request.
    ProviderFailed,
    /// Provider transport failed.
    TransportFailed,
    /// Model judging failed.
    JudgeFailed,
    /// Report persistence failed.
    RepositoryFailed,
    /// Observed execution revision evidence differed from the dataset.
    ExecutionRevisionMismatch,
    /// Request or prompt-reference hashing failed.
    InputHashFailed,
    /// Canonical response hashing failed.
    ResponseHashFailed,
    /// Canonical response projection for assertions failed.
    ResponseProjectionFailed,
    /// Actual case cost exceeded its ceiling.
    CaseCostExceeded,
    /// No budget remained for a required comparison.
    ComparisonBudgetExhausted,
    /// No budget remained for an admitted judge.
    JudgeBudgetExhausted,
    /// Usage or cost accounting overflowed.
    UsageOverflow,
    /// At least one deterministic assertion failed.
    DeterministicAssertionFailed,
    /// The dataset required a judge but no judge port was configured.
    JudgeUnavailable,
    /// Judge score or exact execution evidence was invalid.
    JudgeEvidenceInvalid,
    /// An admitted judge was missing its score tolerance.
    JudgeToleranceMissing,
    /// Judge score did not meet the dataset tolerance.
    JudgeScoreBelowTolerance,
    /// The enclosing case deadline elapsed.
    DeadlineExceeded,
}

/// A bounded content-free diagnostic suitable for report retention.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct RedactedDiagnostic {
    code: DiagnosticCode,
    source_bytes: Option<u64>,
    source_sha256: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactedDiagnosticWire {
    code: DiagnosticCode,
    source_bytes: Option<u64>,
    source_sha256: Option<String>,
}

impl RedactedDiagnostic {
    /// Creates a content-free diagnostic code.
    #[must_use]
    pub const fn new(code: DiagnosticCode) -> Self {
        Self {
            code,
            source_bytes: None,
            source_sha256: None,
        }
    }

    /// Hashes sensitive diagnostic bytes instead of retaining their content.
    #[must_use]
    pub fn from_sensitive(code: DiagnosticCode, sensitive: &[u8]) -> Self {
        Self {
            code,
            source_bytes: Some(u64::try_from(sensitive.len()).unwrap_or(u64::MAX)),
            source_sha256: Some(sha256_bytes(sensitive)),
        }
    }

    /// Returns the stable diagnostic category.
    #[must_use]
    pub const fn code(&self) -> DiagnosticCode {
        self.code
    }

    /// Returns the measured sensitive source length when one was supplied.
    #[must_use]
    pub const fn source_bytes(&self) -> Option<u64> {
        self.source_bytes
    }

    /// Borrows the sensitive source digest when one was supplied.
    #[must_use]
    pub fn source_sha256(&self) -> Option<&str> {
        self.source_sha256.as_deref()
    }
}

impl<'de> Deserialize<'de> for RedactedDiagnostic {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RedactedDiagnosticWire::deserialize(deserializer)?;
        let source_fields_match = matches!(
            (&wire.source_bytes, &wire.source_sha256),
            (None, None) | (Some(_), Some(_))
        );
        if !source_fields_match
            || wire
                .source_sha256
                .as_deref()
                .is_some_and(|digest| !crate::hashing::is_sha256(digest))
        {
            return Err(D::Error::custom("invalid redacted diagnostic evidence"));
        }
        Ok(Self {
            code: wire.code,
            source_bytes: wire.source_bytes,
            source_sha256: wire.source_sha256,
        })
    }
}

impl fmt::Debug for RedactedDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedDiagnostic")
            .field("code", &self.code)
            .field("source_bytes", &self.source_bytes)
            .field("source_sha256", &self.source_sha256)
            .finish()
    }
}

/// Normalized usage and billable cost returned by an executor or judge.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalUsage {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_microunits: u64,
}

impl EvalUsage {
    /// Creates normalized usage with an exact billable cost.
    #[must_use]
    pub const fn new(
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
        cost_microunits: u64,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cost_microunits,
        }
    }

    /// Returns normalized input tokens when reported.
    #[must_use]
    pub const fn input_tokens(self) -> Option<u64> {
        self.input_tokens
    }

    /// Returns normalized output tokens when reported.
    #[must_use]
    pub const fn output_tokens(self) -> Option<u64> {
        self.output_tokens
    }

    /// Returns exact charged microunits.
    #[must_use]
    pub const fn cost_microunits(self) -> u64 {
        self.cost_microunits
    }

    /// Checked component-wise addition for aggregate evaluation accounting.
    ///
    /// Present token counters are summed while an absent observation contributes
    /// no counter. Returns `None` when any known counter or exact cost overflows.
    #[must_use]
    pub fn checked_add(self, other: Self) -> Option<Self> {
        Some(Self {
            input_tokens: checked_add_options(self.input_tokens, other.input_tokens)?,
            output_tokens: checked_add_options(self.output_tokens, other.output_tokens)?,
            cost_microunits: self.cost_microunits.checked_add(other.cost_microunits)?,
        })
    }
}

/// An executor result retaining content only until assertions and judging finish.
#[derive(Clone, PartialEq)]
pub struct EvalExecutionResult {
    response: LlmResponse,
    evidence: ExecutionTarget,
    usage: EvalUsage,
}

impl EvalExecutionResult {
    /// Creates an execution result with exact observed revision evidence.
    #[must_use]
    pub const fn new(response: LlmResponse, evidence: ExecutionTarget, usage: EvalUsage) -> Self {
        Self {
            response,
            evidence,
            usage,
        }
    }

    /// Borrows the canonical response.
    #[must_use]
    pub const fn response(&self) -> &LlmResponse {
        &self.response
    }

    /// Borrows exact observed route, provider, model, and revision evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionTarget {
        &self.evidence
    }

    /// Returns normalized usage and cost.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}

impl fmt::Debug for EvalExecutionResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvalExecutionResult")
            .field("evidence", &self.evidence)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// A borrowed, bounded case execution request.
pub struct CaseExecutionRequest<'a> {
    dataset_id: &'a str,
    dataset_version: &'a str,
    case_id: &'a str,
    role: CandidateRole,
    invocation: &'a EvalInvocation,
    deadline_ms: u64,
    cost_ceiling_microunits: u64,
}

impl<'a> CaseExecutionRequest<'a> {
    pub(crate) const fn new(
        dataset_id: &'a str,
        dataset_version: &'a str,
        case_id: &'a str,
        role: CandidateRole,
        invocation: &'a EvalInvocation,
        deadline_ms: u64,
        cost_ceiling_microunits: u64,
    ) -> Self {
        Self {
            dataset_id,
            dataset_version,
            case_id,
            role,
            invocation,
            deadline_ms,
            cost_ceiling_microunits,
        }
    }

    /// Borrows the dataset identifier.
    #[must_use]
    pub const fn dataset_id(&self) -> &str {
        self.dataset_id
    }

    /// Borrows the dataset version.
    #[must_use]
    pub const fn dataset_version(&self) -> &str {
        self.dataset_version
    }

    /// Borrows the case identifier.
    #[must_use]
    pub const fn case_id(&self) -> &str {
        self.case_id
    }

    /// Returns the candidate role.
    #[must_use]
    pub const fn role(&self) -> CandidateRole {
        self.role
    }

    /// Borrows the invocation input and exact target.
    #[must_use]
    pub const fn invocation(&self) -> &EvalInvocation {
        self.invocation
    }

    /// Returns the enclosing case deadline.
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Returns the remaining candidate and judge cost allowance.
    #[must_use]
    pub const fn cost_ceiling_microunits(&self) -> u64 {
        self.cost_ceiling_microunits
    }
}

impl fmt::Debug for CaseExecutionRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaseExecutionRequest")
            .field("dataset_id", &self.dataset_id)
            .field("dataset_version", &self.dataset_version)
            .field("case_id", &self.case_id)
            .field("role", &self.role)
            .field("deadline_ms", &self.deadline_ms)
            .field("cost_ceiling_microunits", &self.cost_ceiling_microunits)
            .finish_non_exhaustive()
    }
}

/// A content-free executor failure with any usage already charged by the provider.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("evaluation case execution failed")]
pub struct CaseExecutorError {
    diagnostic: RedactedDiagnostic,
    usage: EvalUsage,
}

impl CaseExecutorError {
    /// Creates a failure from an already-redacted diagnostic and charged usage.
    #[must_use]
    pub const fn new(diagnostic: RedactedDiagnostic, usage: EvalUsage) -> Self {
        Self { diagnostic, usage }
    }

    /// Borrows the redacted diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &RedactedDiagnostic {
        &self.diagnostic
    }

    /// Returns usage charged before execution failed.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}

/// Async port that resolves and executes one evaluation candidate.
#[async_trait]
pub trait CaseExecutor: Send + Sync {
    /// Borrows a trusted canonical evidence digest when this executor is cassette-backed.
    fn evidence_sha256(&self) -> Option<&str>;

    /// Executes one candidate under the supplied enclosing deadline.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`CaseExecutorError`] for execution failures.
    async fn execute(
        &self,
        request: CaseExecutionRequest<'_>,
    ) -> Result<EvalExecutionResult, CaseExecutorError>;
}

/// The label exposed to a model judge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JudgeLabel {
    /// Candidate A.
    A,
    /// Candidate B.
    B,
}

/// One content-bearing candidate exposed only through the judge port.
pub struct JudgeCandidate<'a> {
    label: JudgeLabel,
    response: &'a LlmResponse,
}

impl<'a> JudgeCandidate<'a> {
    pub(crate) const fn new(label: JudgeLabel, response: &'a LlmResponse) -> Self {
        Self { label, response }
    }

    /// Returns the blinded candidate label.
    #[must_use]
    pub const fn label(&self) -> JudgeLabel {
        self.label
    }

    /// Borrows candidate content for evaluation by the admitted judge.
    #[must_use]
    pub const fn response(&self) -> &LlmResponse {
        self.response
    }
}

impl fmt::Debug for JudgeCandidate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JudgeCandidate")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// A calibrated judge request with one or two optionally blinded candidates.
pub struct JudgeRequest<'a> {
    dataset_id: &'a str,
    dataset_version: &'a str,
    case_id: &'a str,
    methodology: &'a JudgeMethodology,
    first: JudgeCandidate<'a>,
    second: Option<JudgeCandidate<'a>>,
    cost_ceiling_microunits: u64,
}

impl<'a> JudgeRequest<'a> {
    pub(crate) const fn new(
        dataset_id: &'a str,
        dataset_version: &'a str,
        case_id: &'a str,
        methodology: &'a JudgeMethodology,
        first: JudgeCandidate<'a>,
        second: Option<JudgeCandidate<'a>>,
        cost_ceiling_microunits: u64,
    ) -> Self {
        Self {
            dataset_id,
            dataset_version,
            case_id,
            methodology,
            first,
            second,
            cost_ceiling_microunits,
        }
    }

    /// Borrows the dataset identifier.
    #[must_use]
    pub const fn dataset_id(&self) -> &str {
        self.dataset_id
    }

    /// Borrows the dataset version.
    #[must_use]
    pub const fn dataset_version(&self) -> &str {
        self.dataset_version
    }

    /// Borrows the case identifier.
    #[must_use]
    pub const fn case_id(&self) -> &str {
        self.case_id
    }

    /// Borrows the admitted calibrated methodology.
    #[must_use]
    pub const fn methodology(&self) -> &JudgeMethodology {
        self.methodology
    }

    /// Borrows candidate A.
    #[must_use]
    pub const fn first(&self) -> &JudgeCandidate<'a> {
        &self.first
    }

    /// Borrows candidate B when this is a pair comparison.
    #[must_use]
    pub const fn second(&self) -> Option<&JudgeCandidate<'a>> {
        self.second.as_ref()
    }

    /// Returns the remaining judge cost allowance.
    #[must_use]
    pub const fn cost_ceiling_microunits(&self) -> u64 {
        self.cost_ceiling_microunits
    }
}

impl fmt::Debug for JudgeRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JudgeRequest")
            .field("dataset_id", &self.dataset_id)
            .field("dataset_version", &self.dataset_version)
            .field("case_id", &self.case_id)
            .field("methodology_id", &self.methodology.methodology_id())
            .field(
                "methodology_version",
                &self.methodology.methodology_version(),
            )
            .field("first", &self.first)
            .field("second", &self.second)
            .field("cost_ceiling_microunits", &self.cost_ceiling_microunits)
            .finish()
    }
}

/// A model-judge result with exact observed judge revision evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JudgeResult {
    score_microunits: u64,
    evidence: ExecutionTarget,
    usage: EvalUsage,
}

impl JudgeResult {
    /// Creates a judge result on a million-point score scale.
    #[must_use]
    pub const fn new(score_microunits: u64, evidence: ExecutionTarget, usage: EvalUsage) -> Self {
        Self {
            score_microunits,
            evidence,
            usage,
        }
    }

    /// Returns the judge score.
    #[must_use]
    pub const fn score_microunits(&self) -> u64 {
        self.score_microunits
    }

    /// Borrows exact observed judge revision evidence.
    #[must_use]
    pub const fn evidence(&self) -> &ExecutionTarget {
        &self.evidence
    }

    /// Returns judge usage and cost.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}

/// A content-free model-judge failure with any usage already charged by the provider.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("evaluation model judge failed")]
pub struct ModelJudgeError {
    diagnostic: RedactedDiagnostic,
    usage: EvalUsage,
}

impl ModelJudgeError {
    /// Creates a judge failure from an already-redacted diagnostic and charged usage.
    #[must_use]
    pub const fn new(diagnostic: RedactedDiagnostic, usage: EvalUsage) -> Self {
        Self { diagnostic, usage }
    }

    /// Borrows the redacted diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &RedactedDiagnostic {
        &self.diagnostic
    }

    /// Returns usage charged before judging failed.
    #[must_use]
    pub const fn usage(&self) -> EvalUsage {
        self.usage
    }
}

/// Optional async port for calibrated model grading.
#[async_trait]
pub trait ModelJudge: Send + Sync {
    /// Borrows a trusted canonical evidence digest when this judge is cassette-backed.
    fn evidence_sha256(&self) -> Option<&str>;

    /// Grades one admitted request.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`ModelJudgeError`] for judge failures.
    async fn judge(&self, request: JudgeRequest<'_>) -> Result<JudgeResult, ModelJudgeError>;
}

/// A content-free report persistence failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("evaluation report persistence failed")]
pub struct ResultRepositoryError {
    diagnostic: RedactedDiagnostic,
}

impl ResultRepositoryError {
    /// Creates a persistence failure from an already-redacted diagnostic.
    #[must_use]
    pub const fn new(diagnostic: RedactedDiagnostic) -> Self {
        Self { diagnostic }
    }

    /// Borrows the redacted diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &RedactedDiagnostic {
        &self.diagnostic
    }
}

/// Async repository port for durable evaluation report ownership.
#[async_trait]
pub trait EvaluationResultRepository: Send + Sync {
    /// Persists one complete content-free evaluation report atomically.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`ResultRepositoryError`] if persistence fails.
    async fn store(&self, report: &EvaluationReport) -> Result<(), ResultRepositoryError>;
}

#[allow(
    clippy::option_option,
    reason = "the outer option represents overflow while the inner option represents provider omission"
)]
fn checked_add_options(left: Option<u64>, right: Option<u64>) -> Option<Option<u64>> {
    match (left, right) {
        (Some(left), Some(right)) => left.checked_add(right).map(Some),
        (Some(value), None) | (None, Some(value)) => Some(Some(value)),
        (None, None) => Some(None),
    }
}
