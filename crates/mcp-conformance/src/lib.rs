//! Pinned official-tool planning and bounded deterministic offline MCP conformance evidence.
//!
//! Official, Inspector, and project-owned synthetic coverage exercise authenticated Streamable
//! HTTP and require explicit execution capability for external tools.

#![forbid(unsafe_code)]

mod artifact;
mod evidence;
mod execution;
mod matrix;
mod official;
mod redaction;
mod reference;
mod runner;

pub use artifact::{ArtifactError, ArtifactStore, DEFAULT_ARTIFACT_DIRECTORY, SafeRelativePath};
pub use evidence::{
    AcceptanceId, CaseEvidence, CaseEvidenceDraft, CheckOutcome, EVIDENCE_SCHEMA_VERSION,
    EvidenceBounds, EvidenceCheck, EvidenceError, EvidenceReport, EvidenceStatus,
    EvidenceSuiteKind, EvidenceSummary, EvidenceToolchain, Transport,
};
pub use execution::{
    ExecutionError, ExternalExecutionBounds, OfficialExecutionOptIn, OfficialExecutor,
    skipped_official_evidence,
};
pub use matrix::{MatrixCase, MatrixError, SyntheticMatrix, SyntheticScenario};
pub use official::{
    CONFORMANCE_PACKAGE, CONFORMANCE_VERSION, CommandPlan, HttpEndpoint, INSPECTOR_PACKAGE,
    INSPECTOR_VERSION, InspectorConfig, InspectorMethod, InspectorPlan, InspectorServerConfig,
    MCP_REQUIREMENTS_REVISION, MINIMUM_NODE_VERSION, NodeVersion, OfficialConformancePlan,
    OfficialTarget, PinnedTool, PlanError,
};
pub use redaction::{DEFAULT_DIAGNOSTIC_BYTES, RedactedDiagnostic, redact_diagnostic};
pub use reference::{ReferenceSyntheticAdapter, TargetSyntheticAdapter, execute_fixture_target};
pub use runner::{
    AdapterFailure, ExecutionBudget, MatrixRunner, ObservationBuilder, ObservationError,
    RunnerError, SyntheticAdapter, SyntheticObservation,
};
