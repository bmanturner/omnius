//! Versioned, bounded LLM evaluation datasets and deterministic report orchestration.
//!
//! Dataset content is available only to the executor and optional calibrated judge.
//! Durable reports retain exact revision evidence, usage, cost, hashes, and bounded
//! redacted diagnostics without prompts or response content.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod dataset;
mod hashing;
mod offline;
mod ports;
mod report;
mod runner;

pub use dataset::{
    CandidateRole, DATASET_SCHEMA_VERSION, DatasetBounds, DatasetError, DeterministicAssertion,
    EvalCase, EvalInvocation, EvalTolerances, EvaluationDataset, EvaluationInput, ExecutionTarget,
    JudgeCalibration, JudgeMethodology, PromptRevisionReference,
};
pub use offline::{
    OfflineCaseExecutor, OfflineFixtureError, OfflineFixtureLimits, OfflineModelJudge,
    OfflinePayloadKind, OfflineRawMetadata, offline_response_sha256,
};
pub use ports::{
    CaseExecutionRequest, CaseExecutor, CaseExecutorError, DiagnosticCode, EvalExecutionResult,
    EvalUsage, EvaluationResultRepository, JudgeCandidate, JudgeLabel, JudgeRequest, JudgeResult,
    ModelJudge, ModelJudgeError, RedactedDiagnostic, ResultRepositoryError,
};
pub use report::{
    AssertionReport, CaseOutcome, CaseReport, EvaluationReport, ExecutionReport, JudgeReport,
    REPORT_SCHEMA_VERSION, RUNNER_VERSION, RejectedJudgeReport, ReportAdmissionError, ReportBounds,
    ReportTotals,
};
pub use runner::{BlindedOrder, DiagnosticRetention, EvaluationRunner, RunError, RunnerLimits};
