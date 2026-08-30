use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    matrix::SyntheticMatrix,
    official::{MCP_REQUIREMENTS_REVISION, MINIMUM_NODE_VERSION, NodeVersion, PinnedTool},
    redaction::{DEFAULT_DIAGNOSTIC_BYTES, RedactedDiagnostic},
};

/// Machine-readable evidence schema revision.
pub const EVIDENCE_SCHEMA_VERSION: &str = "mcp-conformance-evidence/v1";
const ABSOLUTE_MAX_REPORT_BYTES: usize = 16 * 1_024 * 1_024;
const HEX: &[u8; 16] = b"0123456789abcdef";
/// Fixed offline seed used by the default matrix.
pub const DEFAULT_SYNTHETIC_SEED: u64 = 0x4d43_5032_3032_3630;

/// Acceptance criterion owned by this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AcceptanceId {
    /// Official conformance coverage.
    #[serde(rename = "AC-AI-105")]
    AcAi105,
    /// Inspector smoke coverage.
    #[serde(rename = "AC-AI-106")]
    AcAi106,
    /// Cross-transport authorization coverage.
    #[serde(rename = "AC-AI-109")]
    AcAi109,
    /// Bounded load and failure coverage.
    #[serde(rename = "AC-AI-110")]
    AcAi110,
    /// Adversarial security coverage.
    #[serde(rename = "AC-AI-112")]
    AcAi112,
}

/// Transport boundary exercised by a synthetic case.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// MCP Streamable HTTP adapter.
    StreamableHttp,
    /// MCP newline-framed stdio adapter.
    Stdio,
}

impl Transport {
    /// Stable case identifier segment.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::StreamableHttp => "streamable_http",
            Self::Stdio => "stdio",
        }
    }
}

/// Evidence suite provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSuiteKind {
    /// Pinned external official runner.
    OfficialConformance,
    /// Pinned external Inspector smoke.
    InspectorSmoke,
    /// Project-owned deterministic offline suite.
    SyntheticOffline,
}

/// One observable assertion outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    /// The observable invariant held.
    Satisfied,
    /// The invariant was exercised and failed.
    Failed {
        /// Content-free failure detail retained under evidence bounds.
        diagnostic: RedactedDiagnostic,
    },
    /// The invariant was not exercised.
    NotRun {
        /// Content-free reason the invariant was not exercised.
        reason: RedactedDiagnostic,
    },
}

/// Derived case status. Callers cannot legitimately turn `NotRun` into `Passed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EvidenceStatus {
    /// Every check was exercised and satisfied.
    Passed,
    /// At least one exercised check failed.
    Failed,
    /// At least one check was not exercised and none failed.
    SkippedWithReason {
        /// Content-free reason at least one check was not exercised.
        reason: RedactedDiagnostic,
    },
}

/// Named assertion recorded by a case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceCheck {
    /// Stable assertion identifier.
    pub check_id: String,
    /// Observable outcome.
    pub outcome: CheckOutcome,
}

/// Exact external tool provenance retained with official or Inspector evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceToolchain {
    /// Pinned official tool.
    pub tool: PinnedTool,
    /// Exact package name.
    pub package: String,
    /// Exact package version.
    pub version: String,
    /// Discovered Node version; absent only when execution was honestly skipped.
    pub node_version: Option<NodeVersion>,
}

impl EvidenceToolchain {
    /// Captures the exact admitted package and optional discovered Node runtime.
    #[must_use]
    pub fn pinned(tool: PinnedTool, node_version: Option<NodeVersion>) -> Self {
        Self {
            tool,
            package: tool.package().to_owned(),
            version: tool.version().to_owned(),
            node_version,
        }
    }
}
/// Bounds retained in every report so a consumer can verify execution limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBounds {
    /// Fixed deterministic seed.
    pub seed: u64,
    /// Per-case wall-clock deadline.
    pub case_deadline_ms: u64,
    /// Whole matrix deadline budget.
    pub total_deadline_ms: u64,
    /// Maximum concurrently active cases.
    pub max_concurrency: usize,
    /// Maximum cases in one report.
    pub max_cases: usize,
    /// Maximum bytes retained for one case.
    pub max_retained_bytes_per_case: usize,
    /// Maximum retained bytes summed across the report.
    pub max_retained_bytes_total: usize,
    /// Maximum diagnostics retained for one case.
    pub max_diagnostics_per_case: usize,
    /// Maximum message bytes retained for one diagnostic.
    pub max_diagnostic_bytes: usize,
    /// Maximum serialized report bytes.
    pub max_report_bytes: usize,
}

impl Default for EvidenceBounds {
    fn default() -> Self {
        Self {
            seed: DEFAULT_SYNTHETIC_SEED,
            case_deadline_ms: 1_000,
            total_deadline_ms: 20_000,
            max_concurrency: 4,
            max_cases: 64,
            max_retained_bytes_per_case: 4_096,
            max_retained_bytes_total: 256 * 1_024,
            max_diagnostics_per_case: 4,
            max_diagnostic_bytes: DEFAULT_DIAGNOSTIC_BYTES,
            max_report_bytes: 512 * 1_024,
        }
    }
}

impl EvidenceBounds {
    /// Rejects zero, internally inconsistent, or unreasonably large harness limits.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::InvalidBounds`] when a limit is out of range or the total deadline
    /// cannot accommodate the configured cases at the configured concurrency.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.case_deadline_ms == 0
            || self.case_deadline_ms > 30 * 60 * 1_000
            || self.total_deadline_ms < self.case_deadline_ms
            || self.total_deadline_ms > 30 * 60 * 1_000
            || !(1..=64).contains(&self.max_concurrency)
            || !(1..=1_024).contains(&self.max_cases)
            || !(1..=1_024 * 1_024).contains(&self.max_retained_bytes_per_case)
            || self.max_retained_bytes_total < self.max_retained_bytes_per_case
            || self.max_retained_bytes_total > 16 * 1_024 * 1_024
            || !(1..=32).contains(&self.max_diagnostics_per_case)
            || !(32..=16_384).contains(&self.max_diagnostic_bytes)
            || self.max_report_bytes < 1_024
            || self.max_report_bytes > 16 * 1_024 * 1_024
        {
            return Err(EvidenceError::InvalidBounds);
        }
        let minimum_runtime = self.case_deadline_ms.saturating_mul(
            u64::try_from(self.max_cases.div_ceil(self.max_concurrency)).unwrap_or(u64::MAX),
        );
        if self.total_deadline_ms < minimum_runtime {
            return Err(EvidenceError::InvalidBounds);
        }
        Ok(())
    }
}

/// Evidence for one deterministic matrix row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseEvidence {
    /// Stable matrix case identifier.
    pub case_id: String,
    /// Acceptance criteria covered by the case.
    pub acceptance_ids: Vec<AcceptanceId>,
    /// Transport boundary, when applicable.
    pub transport: Option<Transport>,
    /// Stable case class.
    pub category: String,
    /// Derived status.
    pub status: EvidenceStatus,
    /// Case wall-clock deadline.
    pub deadline_ms: u64,
    /// Bounded observed duration.
    pub duration_ms: u64,
    /// Bounded bytes intentionally retained by the adapter.
    pub retained_bytes: usize,
    /// Complete named assertions.
    pub checks: Vec<EvidenceCheck>,
    /// Additional bounded redacted diagnostics.
    pub diagnostics: Vec<RedactedDiagnostic>,
}
/// Inputs for a case whose status will be derived from observable checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseEvidenceDraft {
    /// Stable matrix case identifier.
    pub case_id: String,
    /// Acceptance criteria covered by the case.
    pub acceptance_ids: Vec<AcceptanceId>,
    /// Transport boundary, when applicable.
    pub transport: Option<Transport>,
    /// Stable case class.
    pub category: String,
    /// Case wall-clock deadline.
    pub deadline_ms: u64,
    /// Bounded observed duration.
    pub duration_ms: u64,
    /// Bounded bytes intentionally retained by the adapter.
    pub retained_bytes: usize,
    /// Complete named assertions.
    pub checks: Vec<EvidenceCheck>,
    /// Additional bounded redacted diagnostics.
    pub diagnostics: Vec<RedactedDiagnostic>,
}

impl CaseEvidence {
    /// Constructs case evidence and derives status from the check outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::EmptyChecks`] when `draft` does not contain an observable check.
    pub fn from_checks(draft: CaseEvidenceDraft) -> Result<Self, EvidenceError> {
        let status = derive_status(&draft.checks)?;
        Ok(Self {
            case_id: draft.case_id,
            acceptance_ids: draft.acceptance_ids,
            transport: draft.transport,
            category: draft.category,
            status,
            deadline_ms: draft.deadline_ms,
            duration_ms: draft.duration_ms,
            retained_bytes: draft.retained_bytes,
            checks: draft.checks,
            diagnostics: draft.diagnostics,
        })
    }

    fn validate(&self, bounds: &EvidenceBounds) -> Result<(), EvidenceError> {
        if self.case_id.is_empty()
            || self.case_id.len() > 160
            || !self.case_id.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
            })
            || self.category.is_empty()
            || self.acceptance_ids.is_empty()
            || self.deadline_ms == 0
            || self.deadline_ms > bounds.case_deadline_ms
            || self.duration_ms > self.deadline_ms
            || self.retained_bytes > bounds.max_retained_bytes_per_case
            || self.diagnostics.len() > bounds.max_diagnostics_per_case
        {
            return Err(EvidenceError::InvalidCase(self.case_id.clone()));
        }

        let acceptance_set: BTreeSet<_> = self.acceptance_ids.iter().copied().collect();
        if acceptance_set.len() != self.acceptance_ids.len()
            || self
                .diagnostics
                .iter()
                .any(|diagnostic| !diagnostic.validate(bounds.max_diagnostic_bytes))
        {
            return Err(EvidenceError::InvalidCase(self.case_id.clone()));
        }

        let check_ids: BTreeSet<_> = self
            .checks
            .iter()
            .map(|check| check.check_id.as_str())
            .collect();
        if self.checks.is_empty()
            || self.checks.len() > 64
            || check_ids.len() != self.checks.len()
            || self.checks.iter().any(|check| {
                check.check_id.is_empty()
                    || check.check_id.len() > 96
                    || !check.check_id.chars().all(|character| {
                        character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                    })
                    || match &check.outcome {
                        CheckOutcome::Satisfied => false,
                        CheckOutcome::Failed { diagnostic }
                        | CheckOutcome::NotRun { reason: diagnostic } => {
                            !diagnostic.validate(bounds.max_diagnostic_bytes)
                        }
                    }
            })
            || self.status != derive_status(&self.checks)?
        {
            return Err(EvidenceError::DishonestStatus(self.case_id.clone()));
        }
        Ok(())
    }
}

/// Aggregate evidence counts. Skips never contribute to passes or a passing gate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// Exercised passing cases.
    pub passed: usize,
    /// Exercised failing cases.
    pub failed: usize,
    /// Cases not fully exercised.
    pub skipped: usize,
    /// True only when every case passed.
    pub gate_passed: bool,
}

/// Complete bounded machine-readable harness evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReport {
    /// Evidence schema revision.
    pub schema_version: String,
    /// Provenance of the suite.
    pub suite_kind: EvidenceSuiteKind,
    /// Stable suite identifier.
    pub suite_id: String,
    /// MCP requirements revision.
    pub requirements_revision: String,
    /// Exact external package and Node provenance; absent for synthetic evidence.
    pub toolchain: Option<EvidenceToolchain>,
    /// Enforced finite bounds and seed.
    pub bounds: EvidenceBounds,
    /// Sorted case evidence.
    pub cases: Vec<CaseEvidence>,
    /// Derived aggregate counts.
    pub summary: EvidenceSummary,
}

impl EvidenceReport {
    /// Constructs, sorts, summarizes, and validates a report.
    ///
    /// # Errors
    ///
    /// Returns an error when the bounds, suite metadata, toolchain provenance, case evidence,
    /// derived statuses, summary, redaction, or encoded size are invalid.
    pub fn new(
        suite_kind: EvidenceSuiteKind,
        suite_id: impl Into<String>,
        requirements_revision: impl Into<String>,
        toolchain: Option<EvidenceToolchain>,
        bounds: EvidenceBounds,
        mut cases: Vec<CaseEvidence>,
    ) -> Result<Self, EvidenceError> {
        cases.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        let summary = summarize(&cases);
        let report = Self {
            schema_version: EVIDENCE_SCHEMA_VERSION.to_owned(),
            suite_kind,
            suite_id: suite_id.into(),
            requirements_revision: requirements_revision.into(),
            toolchain,
            bounds,
            cases,
            summary,
        };
        report.validate()?;
        Ok(report)
    }

    /// Parses JSON and verifies it against an independently supplied trusted digest.
    ///
    /// `trusted_sha256` must be persisted through a channel independent of `bytes`. Admission
    /// then rejects inconsistent, dishonest, unredacted, incomplete, or oversized evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when the trusted digest is invalid or mismatched, the input exceeds the
    /// absolute report size, decoding fails, or report validation fails.
    pub fn from_json(bytes: &[u8], trusted_sha256: &str) -> Result<Self, EvidenceError> {
        if bytes.len() > ABSOLUTE_MAX_REPORT_BYTES {
            return Err(EvidenceError::ReportTooLarge {
                actual: bytes.len(),
                maximum: ABSOLUTE_MAX_REPORT_BYTES,
            });
        }
        if !is_sha256(trusted_sha256) {
            return Err(EvidenceError::InvalidTrustedDigest);
        }
        let report: Self = serde_json::from_slice(bytes).map_err(EvidenceError::Deserialize)?;
        report.validate()?;
        let actual_sha256 = report.canonical_sha256()?;
        if !constant_time_digest_eq(&actual_sha256, trusted_sha256) {
            return Err(EvidenceError::TrustedDigestMismatch);
        }
        Ok(report)
    }

    /// Computes the canonical SHA-256 digest to persist through a trusted channel.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::Serialize`] when canonical report encoding fails.
    pub fn canonical_sha256(&self) -> Result<String, EvidenceError> {
        self.validate()?;
        let canonical = serde_json::to_vec(self).map_err(EvidenceError::Serialize)?;
        let digest = Sha256::digest(canonical);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(encoded)
    }

    /// Produces deterministic pretty JSON after full validation.
    ///
    /// # Errors
    ///
    /// Returns an error when the report is invalid, serialization fails, or the encoded report
    /// exceeds its configured size limit.
    pub fn to_json_pretty(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate()?;
        let bytes = serde_json::to_vec_pretty(self).map_err(EvidenceError::Serialize)?;
        if bytes.len() > self.bounds.max_report_bytes {
            return Err(EvidenceError::ReportTooLarge {
                actual: bytes.len(),
                maximum: self.bounds.max_report_bytes,
            });
        }
        Ok(bytes)
    }

    /// Validates all report structure, bounds, redaction, summaries, and status derivation.
    ///
    /// # Errors
    ///
    /// Returns an error when any bound, schema field, suite provenance, case, derived status,
    /// summary, redaction constraint, or encoded size invariant is violated.
    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.bounds.validate()?;
        if self.schema_version != EVIDENCE_SCHEMA_VERSION
            || self.suite_id.is_empty()
            || self.suite_id.len() > 160
            || self.requirements_revision != MCP_REQUIREMENTS_REVISION
            || self.cases.is_empty()
            || self.cases.len() > self.bounds.max_cases
            || !toolchain_valid(self.suite_kind, self.toolchain.as_ref(), &self.cases)
            || !suite_evidence_valid(self)
        {
            return Err(EvidenceError::InvalidReport);
        }
        let mut previous: Option<&str> = None;
        let mut retained_total = 0usize;
        for case in &self.cases {
            case.validate(&self.bounds)?;
            if expected_acceptance(self.suite_kind, &case.category)
                .is_none_or(|expected| case.acceptance_ids.as_slice() != [expected])
            {
                return Err(EvidenceError::InvalidCase(case.case_id.clone()));
            }
            if previous.is_some_and(|prior| prior >= case.case_id.as_str()) {
                return Err(EvidenceError::DuplicateOrUnsortedCase);
            }
            previous = Some(&case.case_id);
            retained_total = retained_total
                .checked_add(case.retained_bytes)
                .ok_or(EvidenceError::InvalidReport)?;
        }
        if retained_total > self.bounds.max_retained_bytes_total
            || self.summary != summarize(&self.cases)
        {
            return Err(EvidenceError::DishonestSummary);
        }
        let encoded = serde_json::to_vec(self).map_err(EvidenceError::Serialize)?;
        if encoded.len() > self.bounds.max_report_bytes {
            return Err(EvidenceError::ReportTooLarge {
                actual: encoded.len(),
                maximum: self.bounds.max_report_bytes,
            });
        }
        Ok(())
    }
}

fn suite_evidence_valid(report: &EvidenceReport) -> bool {
    match report.suite_kind {
        EvidenceSuiteKind::SyntheticOffline => {
            report.suite_id == "synthetic-contract-matrix"
                && SyntheticMatrix::canonical(report.bounds.clone())
                    .is_ok_and(|matrix| matrix.evidence_matches(&report.cases))
        }
        EvidenceSuiteKind::OfficialConformance => {
            let Some(case) = report.cases.first().filter(|_| report.cases.len() == 1) else {
                return false;
            };
            let (suite_id, case_id, category, transport) =
                if report.suite_id == "official-conformance-server" {
                    (
                        "official-conformance-server",
                        "official_conformance.streamable_http",
                        "official_conformance",
                        Transport::StreamableHttp,
                    )
                } else if report.suite_id == "official-conformance-via-test-only-stdio-bridge" {
                    (
                        "official-conformance-via-test-only-stdio-bridge",
                        "official_conformance.test_only_stdio_bridge",
                        "official_conformance_via_test_only_stdio_bridge",
                        Transport::Stdio,
                    )
                } else {
                    return false;
                };
            report.suite_id == suite_id
                && (case.case_id == case_id
                    || case.case_id.strip_suffix(".not_executed") == Some(case_id))
                && case.category == category
                && case.transport == Some(transport)
                && check_ids_match(
                    case,
                    &[
                        "package_pin_valid",
                        "node_supported",
                        "requirements_revision_pinned",
                        "official_process_exit_zero",
                    ],
                )
        }
        EvidenceSuiteKind::InspectorSmoke => {
            let Some(case) = report.cases.first().filter(|_| report.cases.len() == 1) else {
                return false;
            };
            let expected = match report.suite_id.as_str() {
                "inspector-smoke-streamable-http" => {
                    ("inspector_smoke.streamable_http", Transport::StreamableHttp)
                }
                "inspector-smoke-stdio" => ("inspector_smoke.stdio", Transport::Stdio),
                _ => return false,
            };
            case.case_id == expected.0
                && case.category == "inspector_smoke"
                && case.transport == Some(expected.1)
                && check_ids_match(
                    case,
                    &[
                        "package_pin_valid",
                        "node_supported",
                        "target_plan_valid",
                        "inspector_process_exit_zero",
                        "inspector_json_output_valid",
                    ],
                )
        }
    }
}

fn check_ids_match(case: &CaseEvidence, expected: &[&str]) -> bool {
    let actual: BTreeSet<_> = case
        .checks
        .iter()
        .map(|check| check.check_id.as_str())
        .collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    case.checks.len() == expected.len() && actual == expected
}

fn toolchain_valid(
    suite_kind: EvidenceSuiteKind,
    toolchain: Option<&EvidenceToolchain>,
    cases: &[CaseEvidence],
) -> bool {
    if suite_kind == EvidenceSuiteKind::SyntheticOffline {
        return toolchain.is_none();
    }
    let Some(toolchain) = toolchain else {
        return false;
    };
    let expected_tool = match suite_kind {
        EvidenceSuiteKind::OfficialConformance => PinnedTool::Conformance,
        EvidenceSuiteKind::InspectorSmoke => PinnedTool::Inspector,
        EvidenceSuiteKind::SyntheticOffline => return false,
    };
    let executed = cases
        .iter()
        .any(|case| !matches!(&case.status, EvidenceStatus::SkippedWithReason { .. }));
    toolchain.tool == expected_tool
        && toolchain.package == expected_tool.package()
        && toolchain.version == expected_tool.version()
        && toolchain
            .node_version
            .is_none_or(|version| version >= MINIMUM_NODE_VERSION)
        && (!executed || toolchain.node_version.is_some())
}

fn expected_acceptance(suite_kind: EvidenceSuiteKind, category: &str) -> Option<AcceptanceId> {
    match suite_kind {
        EvidenceSuiteKind::OfficialConformance
            if matches!(
                category,
                "official_conformance" | "official_conformance_via_test_only_stdio_bridge"
            ) =>
        {
            Some(AcceptanceId::AcAi105)
        }
        EvidenceSuiteKind::InspectorSmoke if category == "inspector_smoke" => {
            Some(AcceptanceId::AcAi106)
        }
        EvidenceSuiteKind::SyntheticOffline => match category {
            "transport" | "apps" | "elicitation_mrtr" | "tasks" | "subscriptions" => {
                Some(AcceptanceId::AcAi105)
            }
            "authorization" => Some(AcceptanceId::AcAi109),
            "resilience" => Some(AcceptanceId::AcAi110),
            "adversarial" => Some(AcceptanceId::AcAi112),
            _ => None,
        },
        EvidenceSuiteKind::OfficialConformance | EvidenceSuiteKind::InspectorSmoke => None,
    }
}

fn derive_status(checks: &[EvidenceCheck]) -> Result<EvidenceStatus, EvidenceError> {
    if checks.is_empty() {
        return Err(EvidenceError::EmptyChecks);
    }
    if checks
        .iter()
        .any(|check| matches!(&check.outcome, CheckOutcome::Failed { .. }))
    {
        return Ok(EvidenceStatus::Failed);
    }
    if let Some(reason) = checks.iter().find_map(|check| match &check.outcome {
        CheckOutcome::NotRun { reason } => Some(reason.clone()),
        CheckOutcome::Satisfied | CheckOutcome::Failed { .. } => None,
    }) {
        return Ok(EvidenceStatus::SkippedWithReason { reason });
    }
    Ok(EvidenceStatus::Passed)
}

fn summarize(cases: &[CaseEvidence]) -> EvidenceSummary {
    let mut passed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    for case in cases {
        match &case.status {
            EvidenceStatus::Passed => passed += 1,
            EvidenceStatus::Failed => failed += 1,
            EvidenceStatus::SkippedWithReason { .. } => skipped += 1,
        }
    }
    EvidenceSummary {
        passed,
        failed,
        skipped,
        gate_passed: failed == 0 && skipped == 0 && !cases.is_empty(),
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

/// Invalid or dishonest evidence.
#[derive(Debug, Error)]
pub enum EvidenceError {
    /// Bounds were zero, inconsistent, or unreasonably large.
    #[error("invalid evidence bounds")]
    InvalidBounds,
    /// Report-level schema or identity fields were invalid.
    #[error("invalid evidence report")]
    InvalidReport,
    /// A case violated its declared bound or identifier contract.
    #[error("invalid evidence case: {0}")]
    InvalidCase(String),
    /// A case status did not match its check outcomes.
    #[error("case status does not match observable outcomes: {0}")]
    DishonestStatus(String),
    /// Aggregate counts did not match case status.
    #[error("evidence summary does not match cases")]
    DishonestSummary,
    /// Case identifiers were duplicated or not canonically sorted.
    #[error("case identifiers must be unique and sorted")]
    DuplicateOrUnsortedCase,
    /// A case did not record an observable assertion.
    #[error("case evidence must contain checks")]
    EmptyChecks,
    /// Evidence JSON decoding failed.
    #[error("failed to decode evidence JSON")]
    Deserialize(#[source] serde_json::Error),
    /// The caller's trusted evidence digest was not lowercase SHA-256.
    #[error("trusted evidence SHA-256 digest is invalid")]
    InvalidTrustedDigest,
    /// Canonical evidence differed from its independently supplied trusted digest.
    #[error("evidence differs from its trusted SHA-256 digest")]
    TrustedDigestMismatch,
    /// Evidence JSON encoding failed.
    #[error("failed to encode evidence JSON")]
    Serialize(#[source] serde_json::Error),
    /// Serialized evidence exceeded its declared bound.
    #[error("evidence report was {actual} bytes, maximum is {maximum}")]
    ReportTooLarge {
        /// Actual serialized byte count.
        actual: usize,
        /// Maximum serialized byte count.
        maximum: usize,
    },
}
