use std::fmt;

use async_trait::async_trait;
use omnius_llm_core::LlmResponse;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::{Value, value::RawValue};
use thiserror::Error;

use crate::{
    CandidateRole, CaseExecutionRequest, CaseExecutor, CaseExecutorError, DiagnosticCode,
    EvalExecutionResult, EvalUsage, EvaluationInput, ExecutionTarget, JudgeLabel, JudgeRequest,
    JudgeResult, ModelJudge, ModelJudgeError, RedactedDiagnostic,
    hashing::{canonical_json, hash_serializable, is_sha256},
};

/// Positive resource ceilings applied while loading an offline fixture.
#[allow(
    clippy::struct_field_names,
    reason = "resource ceilings are clearest when every field is named as a maximum"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfflineFixtureLimits {
    max_entries: usize,
    max_fixture_bytes: usize,
    max_safe_metadata_bytes: usize,
}

impl OfflineFixtureLimits {
    /// Creates positive offline-fixture ceilings.
    ///
    /// # Errors
    ///
    /// Returns [`OfflineFixtureError::InvalidBounds`] when any ceiling is zero.
    pub const fn new(
        max_entries: usize,
        max_fixture_bytes: usize,
        max_safe_metadata_bytes: usize,
    ) -> Result<Self, OfflineFixtureError> {
        if max_entries == 0 || max_fixture_bytes == 0 || max_safe_metadata_bytes == 0 {
            return Err(OfflineFixtureError::InvalidBounds);
        }
        Ok(Self {
            max_entries,
            max_fixture_bytes,
            max_safe_metadata_bytes,
        })
    }

    /// Returns the admitted entry count.
    #[must_use]
    pub const fn max_entries(self) -> usize {
        self.max_entries
    }

    /// Returns the admitted encoded fixture size.
    #[must_use]
    pub const fn max_fixture_bytes(self) -> usize {
        self.max_fixture_bytes
    }

    /// Returns the encoded safe-metadata ceiling for one entry.
    #[must_use]
    pub const fn max_safe_metadata_bytes(self) -> usize {
        self.max_safe_metadata_bytes
    }
}

/// A content-free offline fixture admission failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OfflineFixtureError {
    /// At least one fixture ceiling was zero.
    #[error("offline fixture bounds must be positive")]
    InvalidBounds,
    /// The expected canonical fixture digest was not lowercase SHA-256.
    #[error("offline fixture expected digest is invalid")]
    InvalidExpectedDigest,
    /// The fixture did not match its expected canonical digest.
    #[error("offline fixture digest does not match")]
    DigestMismatch,
    /// The encoded fixture exceeded its byte ceiling.
    #[error("offline fixture exceeds its byte ceiling")]
    TooManyBytes,
    /// The fixture had no entries or exceeded its entry ceiling.
    #[error("offline fixture entry count is outside its admitted bounds")]
    EntryCount,
    /// JSON decoding or canonical contract decoding failed.
    #[error("offline fixture JSON is invalid")]
    InvalidJson,
    /// More than one entry owned the same immutable lookup identity.
    #[error("offline fixture contains a duplicate lookup identity")]
    DuplicateEntry,
    /// Safe raw metadata exceeded its encoded byte ceiling.
    #[error("offline fixture safe metadata exceeds its byte ceiling")]
    MetadataTooLarge,
    /// Safe raw metadata contained a non-digest provider request identity.
    #[error("offline fixture safe metadata is invalid")]
    InvalidMetadata,
}

/// The top-level shape of a provider payload without retaining its content.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflinePayloadKind {
    /// JSON null.
    Null,
    /// A JSON boolean.
    Boolean,
    /// A JSON number.
    Number,
    /// A JSON string or opaque non-JSON body.
    String,
    /// A JSON array.
    Array,
    /// A JSON object.
    Object,
}

/// Bounded, content-free raw provider metadata retained by a cassette entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineRawMetadata {
    status_code: Option<u16>,
    payload_kind: Option<OfflinePayloadKind>,
    serialized_bytes: Option<u64>,
    provider_request_id_sha256: Option<String>,
}

impl OfflineRawMetadata {
    /// Returns the provider HTTP status when captured.
    #[must_use]
    pub const fn status_code(&self) -> Option<u16> {
        self.status_code
    }

    /// Returns the content-free top-level payload shape when captured.
    #[must_use]
    pub const fn payload_kind(&self) -> Option<OfflinePayloadKind> {
        self.payload_kind
    }

    /// Returns the measured serialized provider payload size when captured.
    #[must_use]
    pub const fn serialized_bytes(&self) -> Option<u64> {
        self.serialized_bytes
    }

    /// Borrows the hashed provider request identity when captured.
    #[must_use]
    pub fn provider_request_id_sha256(&self) -> Option<&str> {
        self.provider_request_id_sha256.as_deref()
    }

    fn validate(&self, max_bytes: usize) -> Result<(), OfflineFixtureError> {
        if self
            .provider_request_id_sha256
            .as_deref()
            .is_some_and(|digest| !is_sha256(digest))
        {
            return Err(OfflineFixtureError::InvalidMetadata);
        }
        let encoded = canonical_json(self).map_err(|_| OfflineFixtureError::InvalidJson)?;
        if encoded.len() > max_bytes {
            return Err(OfflineFixtureError::MetadataTooLarge);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorCassetteWire {
    schema_version: String,
    cassette_id: String,
    entries: Vec<ExecutorEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorEntryWire {
    dataset_id: String,
    dataset_version: String,
    case_id: String,
    role: CandidateRole,
    input: EvaluationInput,
    target: ExecutionTarget,
    safe_raw_metadata: OfflineRawMetadata,
    outcome: ExecutorOutcomeWire,
}

#[derive(Clone)]
enum ExecutorOutcomeWire {
    Success {
        response: Box<LlmResponse>,
        usage: EvalUsage,
    },
    Failure {
        diagnostic: RedactedDiagnostic,
        usage: EvalUsage,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutorOutcomeWireRaw {
    kind: String,
    response: Option<Box<RawValue>>,
    diagnostic: Option<RedactedDiagnostic>,
    usage: EvalUsage,
}

impl<'de> Deserialize<'de> for ExecutorOutcomeWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = ExecutorOutcomeWireRaw::deserialize(deserializer)?;
        match (raw.kind.as_str(), raw.response.as_deref(), raw.diagnostic) {
            ("success", Some(response), None) => Ok(Self::Success {
                response: Box::new(serde_json::from_str(response.get()).map_err(D::Error::custom)?),
                usage: raw.usage,
            }),
            ("failure", None, Some(diagnostic)) => Ok(Self::Failure {
                diagnostic,
                usage: raw.usage,
            }),
            _ => Err(D::Error::custom("invalid executor outcome")),
        }
    }
}

/// Deterministic, bounded, cassette-backed [`CaseExecutor`] for offline evaluation.
///
/// Lookup includes dataset, case, candidate role, exact input, route, provider,
/// model, and immutable model revision. Construction requires a trusted canonical
/// digest; execution has no transport or network handle.
pub struct OfflineCaseExecutor {
    cassette_id: String,
    canonical_sha256: String,
    entries: Vec<ExecutorEntryWire>,
}

impl OfflineCaseExecutor {
    /// Loads a bounded executor cassette from JSON with a trusted canonical digest.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`OfflineFixtureError`] for an invalid expected
    /// digest or malformed, mismatched, duplicate, excessive, or unsafe fixture data.
    pub fn from_json(
        bytes: &[u8],
        expected_canonical_sha256: &str,
        limits: OfflineFixtureLimits,
    ) -> Result<Self, OfflineFixtureError> {
        validate_expected_digest(expected_canonical_sha256)?;
        if bytes.len() > limits.max_fixture_bytes {
            return Err(OfflineFixtureError::TooManyBytes);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| OfflineFixtureError::InvalidJson)?;
        validate_value_entry_count(&value, limits.max_entries)?;
        let canonical_sha256 = verified_canonical_digest(&value, expected_canonical_sha256)?;
        let wire: ExecutorCassetteWire =
            serde_json::from_slice(bytes).map_err(|_| OfflineFixtureError::InvalidJson)?;
        if wire.schema_version != "1.0.0" || !valid_identifier(&wire.cassette_id) {
            return Err(OfflineFixtureError::InvalidJson);
        }
        for (index, entry) in wire.entries.iter().enumerate() {
            if !entry.identifiers_are_valid() || !entry.success_is_consistent() {
                return Err(OfflineFixtureError::InvalidJson);
            }
            entry
                .safe_raw_metadata
                .validate(limits.max_safe_metadata_bytes)?;
            if wire.entries[..index]
                .iter()
                .any(|prior| prior.same_lookup(entry))
            {
                return Err(OfflineFixtureError::DuplicateEntry);
            }
        }
        Ok(Self {
            cassette_id: wire.cassette_id,
            canonical_sha256,
            entries: wire.entries,
        })
    }

    /// Borrows the stable cassette revision identifier.
    #[must_use]
    pub fn cassette_id(&self) -> &str {
        &self.cassette_id
    }

    /// Borrows the verified canonical cassette SHA-256 digest.
    #[must_use]
    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    /// Returns the admitted cassette entry count.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Borrows safe raw metadata for one immutable lookup identity.
    #[must_use]
    pub fn safe_raw_metadata(
        &self,
        dataset_id: &str,
        dataset_version: &str,
        case_id: &str,
        role: CandidateRole,
    ) -> Option<&OfflineRawMetadata> {
        self.entries
            .iter()
            .find(|entry| entry.matches_lookup(dataset_id, dataset_version, case_id, role))
            .map(|entry| &entry.safe_raw_metadata)
    }
}

impl fmt::Debug for OfflineCaseExecutor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineCaseExecutor")
            .field("cassette_id", &self.cassette_id)
            .field("canonical_sha256", &self.canonical_sha256)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl ExecutorEntryWire {
    fn identifiers_are_valid(&self) -> bool {
        valid_identifier(&self.dataset_id)
            && valid_identifier(&self.dataset_version)
            && valid_identifier(&self.case_id)
            && target_is_exact(&self.target)
            && input_is_exact(&self.input, &self.target)
    }
    fn success_is_consistent(&self) -> bool {
        match &self.outcome {
            ExecutorOutcomeWire::Success { response, usage } => {
                response.provider() == self.target.provider()
                    && response.model() == self.target.model()
                    && response.usage().input_tokens() == usage.input_tokens()
                    && response.usage().output_tokens() == usage.output_tokens()
            }
            ExecutorOutcomeWire::Failure { .. } => true,
        }
    }

    fn matches_lookup(
        &self,
        dataset_id: &str,
        dataset_version: &str,
        case_id: &str,
        role: CandidateRole,
    ) -> bool {
        self.dataset_id == dataset_id
            && self.dataset_version == dataset_version
            && self.case_id == case_id
            && self.role == role
    }

    fn same_lookup(&self, other: &Self) -> bool {
        self.matches_lookup(
            &other.dataset_id,
            &other.dataset_version,
            &other.case_id,
            other.role,
        )
    }
}

#[async_trait]
impl CaseExecutor for OfflineCaseExecutor {
    fn evidence_sha256(&self) -> Option<&str> {
        Some(&self.canonical_sha256)
    }

    async fn execute(
        &self,
        request: CaseExecutionRequest<'_>,
    ) -> Result<EvalExecutionResult, CaseExecutorError> {
        let Some(entry) = self.entries.iter().find(|entry| {
            entry.matches_lookup(
                request.dataset_id(),
                request.dataset_version(),
                request.case_id(),
                request.role(),
            )
        }) else {
            return Err(CaseExecutorError::new(
                RedactedDiagnostic::new(DiagnosticCode::InputResolutionFailed),
                EvalUsage::default(),
            ));
        };
        if &entry.input != request.invocation().input()
            || &entry.target != request.invocation().target()
        {
            return Err(CaseExecutorError::new(
                RedactedDiagnostic::new(DiagnosticCode::ExecutionRevisionMismatch),
                EvalUsage::default(),
            ));
        }
        match &entry.outcome {
            ExecutorOutcomeWire::Success { response, usage } => Ok(EvalExecutionResult::new(
                response.as_ref().clone(),
                entry.target.clone(),
                *usage,
            )),
            ExecutorOutcomeWire::Failure { diagnostic, usage } => {
                Err(CaseExecutorError::new(diagnostic.clone(), *usage))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeCassetteWire {
    schema_version: String,
    cassette_id: String,
    entries: Vec<JudgeEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeEntryWire {
    dataset_id: String,
    dataset_version: String,
    case_id: String,
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    calibration_dataset_id: String,
    calibration_dataset_version: String,
    calibration_evidence_sha256: String,
    first: JudgeCandidateWire,
    second: Option<JudgeCandidateWire>,
    outcome: JudgeOutcomeWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JudgeCandidateWire {
    label: OfflineJudgeLabel,
    response: LlmResponse,
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum OfflineJudgeLabel {
    A,
    B,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum JudgeOutcomeWire {
    Success {
        score_microunits: u64,
        evidence: ExecutionTarget,
        usage: EvalUsage,
    },
    Failure {
        diagnostic: RedactedDiagnostic,
        usage: EvalUsage,
    },
}

/// Deterministic calibrated [`ModelJudge`] backed by fixed offline outcomes.
pub struct OfflineModelJudge {
    cassette_id: String,
    canonical_sha256: String,
    entries: Vec<JudgeEntryWire>,
}

impl OfflineModelJudge {
    /// Loads bounded, fixed judge outcomes from JSON with a trusted canonical digest.
    ///
    /// # Errors
    ///
    /// Returns a content-free [`OfflineFixtureError`] for an invalid expected
    /// digest or malformed, mismatched, duplicate, excessive, or unversioned fixture data.
    pub fn from_json(
        bytes: &[u8],
        expected_canonical_sha256: &str,
        limits: OfflineFixtureLimits,
    ) -> Result<Self, OfflineFixtureError> {
        validate_expected_digest(expected_canonical_sha256)?;
        if bytes.len() > limits.max_fixture_bytes {
            return Err(OfflineFixtureError::TooManyBytes);
        }
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| OfflineFixtureError::InvalidJson)?;
        validate_value_entry_count(&value, limits.max_entries)?;
        let canonical_sha256 = verified_canonical_digest(&value, expected_canonical_sha256)?;
        let wire: JudgeCassetteWire =
            serde_json::from_slice(bytes).map_err(|_| OfflineFixtureError::InvalidJson)?;
        if wire.schema_version != "1.0.0" || !valid_identifier(&wire.cassette_id) {
            return Err(OfflineFixtureError::InvalidJson);
        }
        for (index, entry) in wire.entries.iter().enumerate() {
            if !entry.is_valid() {
                return Err(OfflineFixtureError::InvalidJson);
            }
            if wire.entries[..index]
                .iter()
                .any(|prior| prior.same_lookup(entry))
            {
                return Err(OfflineFixtureError::DuplicateEntry);
            }
        }
        Ok(Self {
            cassette_id: wire.cassette_id,
            canonical_sha256,
            entries: wire.entries,
        })
    }

    /// Borrows the stable fixed-judge cassette revision identifier.
    #[must_use]
    pub fn cassette_id(&self) -> &str {
        &self.cassette_id
    }

    /// Borrows the verified canonical judge cassette SHA-256 digest.
    #[must_use]
    pub fn canonical_sha256(&self) -> &str {
        &self.canonical_sha256
    }

    /// Returns the admitted judge entry count.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl fmt::Debug for OfflineModelJudge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineModelJudge")
            .field("cassette_id", &self.cassette_id)
            .field("canonical_sha256", &self.canonical_sha256)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

impl JudgeEntryWire {
    fn is_valid(&self) -> bool {
        valid_identifier(&self.dataset_id)
            && valid_identifier(&self.dataset_version)
            && valid_identifier(&self.case_id)
            && valid_identifier(&self.methodology_id)
            && valid_identifier(&self.methodology_version)
            && valid_identifier(&self.calibration_dataset_id)
            && valid_identifier(&self.calibration_dataset_version)
            && is_sha256(&self.rubric_sha256)
            && is_sha256(&self.calibration_evidence_sha256)
            && match &self.outcome {
                JudgeOutcomeWire::Success {
                    score_microunits,
                    evidence,
                    ..
                } => *score_microunits <= 1_000_000 && target_is_exact(evidence),
                JudgeOutcomeWire::Failure { .. } => true,
            }
    }

    fn same_lookup(&self, other: &Self) -> bool {
        self.dataset_id == other.dataset_id
            && self.dataset_version == other.dataset_version
            && self.case_id == other.case_id
            && self.methodology_id == other.methodology_id
            && self.methodology_version == other.methodology_version
    }

    fn matches_request(&self, request: &JudgeRequest<'_>) -> bool {
        let methodology = request.methodology();
        self.dataset_id == request.dataset_id()
            && self.dataset_version == request.dataset_version()
            && self.case_id == request.case_id()
            && self.methodology_id == methodology.methodology_id()
            && self.methodology_version == methodology.methodology_version()
            && self.rubric_sha256 == methodology.rubric_sha256()
            && methodology.calibration().is_some_and(|calibration| {
                calibration.dataset_id() == self.calibration_dataset_id
                    && calibration.dataset_version() == self.calibration_dataset_version
                    && calibration.evidence_sha256() == self.calibration_evidence_sha256
            })
            && self.first.matches(request.first())
            && match (&self.second, request.second()) {
                (Some(expected), Some(actual)) => expected.matches(actual),
                (None, None) => true,
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl JudgeCandidateWire {
    fn matches(&self, candidate: &crate::JudgeCandidate<'_>) -> bool {
        self.label.matches(candidate.label()) && &self.response == candidate.response()
    }
}

impl OfflineJudgeLabel {
    const fn matches(self, label: JudgeLabel) -> bool {
        matches!(
            (self, label),
            (Self::A, JudgeLabel::A) | (Self::B, JudgeLabel::B)
        )
    }
}

#[async_trait]
impl ModelJudge for OfflineModelJudge {
    fn evidence_sha256(&self) -> Option<&str> {
        Some(&self.canonical_sha256)
    }

    async fn judge(&self, request: JudgeRequest<'_>) -> Result<JudgeResult, ModelJudgeError> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|entry| entry.matches_request(&request))
        else {
            return Err(ModelJudgeError::new(
                RedactedDiagnostic::new(DiagnosticCode::JudgeEvidenceInvalid),
                EvalUsage::default(),
            ));
        };
        match &entry.outcome {
            JudgeOutcomeWire::Success {
                score_microunits,
                evidence,
                usage,
            } => Ok(JudgeResult::new(
                *score_microunits,
                evidence.clone(),
                *usage,
            )),
            JudgeOutcomeWire::Failure { diagnostic, usage } => {
                Err(ModelJudgeError::new(diagnostic.clone(), *usage))
            }
        }
    }
}

/// Returns the canonical SHA-256 digest used by offline judge response fixtures.
///
/// # Errors
///
/// Returns [`crate::DatasetError::Serialization`] when the canonical response
/// cannot be encoded.
pub fn offline_response_sha256(response: &LlmResponse) -> Result<String, crate::DatasetError> {
    hash_serializable(response)
}

fn input_is_exact(input: &EvaluationInput, target: &ExecutionTarget) -> bool {
    match input {
        EvaluationInput::CanonicalRequest { request } => request.route() == target.route(),
        EvaluationInput::PromptReference { prompt } => {
            valid_identifier(prompt.prompt_id())
                && prompt.revision() > 0
                && is_sha256(prompt.content_sha256())
        }
    }
}

fn target_is_exact(target: &ExecutionTarget) -> bool {
    valid_identifier(target.route().id())
        && target
            .route()
            .revision()
            .is_some_and(|revision| revision > 0)
        && valid_identifier(target.provider())
        && valid_identifier(target.model())
        && valid_identifier(target.model_revision())
}

fn validate_value_entry_count(
    value: &Value,
    max_entries: usize,
) -> Result<(), OfflineFixtureError> {
    let entries = value
        .get("entries")
        .and_then(Value::as_array)
        .ok_or(OfflineFixtureError::InvalidJson)?;
    if entries.is_empty() || entries.len() > max_entries {
        Err(OfflineFixtureError::EntryCount)
    } else {
        Ok(())
    }
}

fn validate_expected_digest(expected: &str) -> Result<(), OfflineFixtureError> {
    if is_sha256(expected) {
        Ok(())
    } else {
        Err(OfflineFixtureError::InvalidExpectedDigest)
    }
}

fn verified_canonical_digest<T: Serialize>(
    value: &T,
    expected: &str,
) -> Result<String, OfflineFixtureError> {
    let actual = hash_serializable(value).map_err(|_| OfflineFixtureError::InvalidJson)?;
    if constant_time_eq(actual.as_bytes(), expected.as_bytes()) {
        Ok(actual)
    } else {
        Err(OfflineFixtureError::DigestMismatch)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for (&left, &right) in left.iter().zip(right) {
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.chars().any(char::is_control)
        && value.trim() == value
}
