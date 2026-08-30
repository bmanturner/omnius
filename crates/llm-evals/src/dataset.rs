use std::fmt;

use omnius_llm_core::{LlmRequest, Route};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;

use crate::hashing::{canonical_json, hash_serializable, is_sha256};

/// The only dataset wire schema understood by this crate.
pub const DATASET_SCHEMA_VERSION: &str = "1.0.0";

/// Resource limits applied before an evaluation dataset is admitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatasetBounds {
    max_cases: usize,
    max_bytes: usize,
}

impl DatasetBounds {
    /// Creates positive dataset limits.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::InvalidBounds`] when either limit is zero.
    pub const fn new(max_cases: usize, max_bytes: usize) -> Result<Self, DatasetError> {
        if max_cases == 0 || max_bytes == 0 {
            return Err(DatasetError::InvalidBounds);
        }
        Ok(Self {
            max_cases,
            max_bytes,
        })
    }

    /// Returns the maximum number of cases.
    #[must_use]
    pub const fn max_cases(self) -> usize {
        self.max_cases
    }

    /// Returns the maximum encoded dataset size.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }
}

/// A dataset construction, admission, or deterministic encoding failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DatasetError {
    /// A configured resource limit was zero.
    #[error("evaluation dataset bounds must be positive")]
    InvalidBounds,
    /// The encoded dataset exceeded its byte limit.
    #[error("evaluation dataset exceeds its byte limit")]
    TooManyBytes,
    /// The dataset contained no cases or exceeded its case limit.
    #[error("evaluation dataset case count is outside its admitted bounds")]
    CaseCount,
    /// The wire schema version is unsupported.
    #[error("unsupported evaluation dataset schema version")]
    UnsupportedSchemaVersion,
    /// A stable identifier or version was invalid.
    #[error("evaluation dataset contains an invalid stable identifier")]
    InvalidIdentifier,
    /// A required SHA-256 digest was not lowercase hexadecimal.
    #[error("evaluation dataset contains an invalid SHA-256 digest")]
    InvalidDigest,
    /// A route did not name an exact positive revision.
    #[error("evaluation target must name an exact route revision")]
    InexactRouteRevision,
    /// A canonical request route differed from its execution target.
    #[error("canonical request route does not match its execution target")]
    RequestRouteMismatch,
    /// A case identifier occurred more than once.
    #[error("evaluation case identifiers must be unique")]
    DuplicateCase,
    /// A case did not contain at least one deterministic assertion.
    #[error("evaluation cases require deterministic assertions")]
    MissingDeterministicAssertion,
    /// A comparison assertion or blind requested a missing comparison candidate.
    #[error("evaluation comparison configuration requires a comparison candidate")]
    MissingComparison,
    /// A model judge did not include valid calibration evidence.
    #[error("model judge methodology is not calibrated")]
    UncalibratedJudge,
    /// Judge threshold configuration did not match judge admission.
    #[error("evaluation judge tolerance does not match judge configuration")]
    InvalidJudgeTolerance,
    /// A case deadline or cost ceiling was zero.
    #[error("evaluation case deadline and cost ceiling must be positive")]
    InvalidCaseLimit,
    /// A JSON pointer assertion was malformed.
    #[error("evaluation assertion contains an invalid JSON pointer")]
    InvalidJsonPointer,
    /// JSON decoding failed without exposing dataset content.
    #[error("evaluation dataset JSON is invalid")]
    InvalidJson,
    /// Deterministic JSON encoding failed without exposing dataset content.
    #[error("evaluation dataset could not be encoded")]
    Serialization,
}

/// Identifies which candidate a deterministic assertion evaluates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRole {
    /// The case's primary candidate.
    Primary,
    /// The optional comparison candidate.
    Comparison,
}

/// A content-addressed prompt revision used instead of embedding prompt content.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromptRevisionReference {
    prompt_id: String,
    revision: u64,
    content_sha256: String,
}

impl PromptRevisionReference {
    /// Creates a prompt reference pinned to its revision and content digest.
    #[must_use]
    pub fn new(prompt_id: String, revision: u64, content_sha256: String) -> Self {
        Self {
            prompt_id,
            revision,
            content_sha256,
        }
    }

    /// Borrows the stable prompt identifier.
    #[must_use]
    pub fn prompt_id(&self) -> &str {
        &self.prompt_id
    }

    /// Returns the exact prompt revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Borrows the prompt content digest.
    #[must_use]
    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    fn validate(&self) -> Result<(), DatasetError> {
        validate_identifier(&self.prompt_id)?;
        if self.revision == 0 {
            return Err(DatasetError::InvalidIdentifier);
        }
        validate_digest(&self.content_sha256)
    }
}

impl fmt::Debug for PromptRevisionReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PromptRevisionReference")
            .field("prompt_id", &self.prompt_id)
            .field("revision", &self.revision)
            .field("content_sha256", &self.content_sha256)
            .finish()
    }
}

/// The content-bearing canonical request or content-addressed prompt used by a case.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvaluationInput {
    /// A complete provider-neutral request.
    CanonicalRequest {
        /// The canonical request passed to the executor.
        request: Box<LlmRequest>,
    },
    /// A prompt revision resolved by the executor.
    PromptReference {
        /// The content-addressed prompt revision.
        prompt: PromptRevisionReference,
    },
}

impl EvaluationInput {
    /// Wraps a canonical request without copying it.
    #[must_use]
    pub fn canonical_request(request: LlmRequest) -> Self {
        Self::CanonicalRequest {
            request: Box::new(request),
        }
    }

    /// Wraps a content-addressed prompt reference.
    #[must_use]
    pub const fn prompt_reference(prompt: PromptRevisionReference) -> Self {
        Self::PromptReference { prompt }
    }

    fn validate(&self) -> Result<(), DatasetError> {
        match self {
            Self::CanonicalRequest { .. } => Ok(()),
            Self::PromptReference { prompt } => prompt.validate(),
        }
    }
}

impl fmt::Debug for EvaluationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::CanonicalRequest { .. } => "canonical_request",
            Self::PromptReference { .. } => "prompt_reference",
        };
        formatter
            .debug_struct("EvaluationInput")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// An exact route, provider, model, and provider model revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionTarget {
    route: Route,
    provider: String,
    model: String,
    model_revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionTargetWire {
    route: Route,
    provider: String,
    model: String,
    model_revision: String,
}

impl<'de> Deserialize<'de> for ExecutionTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ExecutionTargetWire::deserialize(deserializer)?;
        Self::new(wire.route, wire.provider, wire.model, wire.model_revision)
            .map_err(D::Error::custom)
    }
}

impl ExecutionTarget {
    /// Creates exact, bounded execution revision evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError`] when the route is not exact or an identifier,
    /// capability set, provider, model, or revision is invalid.
    pub fn new(
        route: Route,
        provider: String,
        model: String,
        model_revision: String,
    ) -> Result<Self, DatasetError> {
        let target = Self {
            route,
            provider,
            model,
            model_revision,
        };
        target.validate()?;
        Ok(target)
    }

    /// Borrows the exact route.
    #[must_use]
    pub const fn route(&self) -> &Route {
        &self.route
    }

    /// Borrows the provider identifier.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Borrows the provider model identifier.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Borrows the immutable provider model revision.
    #[must_use]
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }

    pub(crate) fn validate(&self) -> Result<(), DatasetError> {
        if !matches!(self.route.revision(), Some(revision) if revision > 0) {
            return Err(DatasetError::InexactRouteRevision);
        }
        validate_identifier(self.route.id())?;
        validate_capabilities(self.route.required_capabilities())?;
        validate_capabilities(self.route.preferred_capabilities())?;
        validate_identifier(&self.provider)?;
        validate_identifier(&self.model)?;
        validate_identifier(&self.model_revision)
    }
}

/// One candidate invocation pinned to its input and exact execution target.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalInvocation {
    input: EvaluationInput,
    target: ExecutionTarget,
}

impl EvalInvocation {
    /// Creates one evaluation invocation.
    #[must_use]
    pub const fn new(input: EvaluationInput, target: ExecutionTarget) -> Self {
        Self { input, target }
    }

    /// Borrows the request or prompt reference.
    #[must_use]
    pub const fn input(&self) -> &EvaluationInput {
        &self.input
    }

    /// Borrows the exact execution target.
    #[must_use]
    pub const fn target(&self) -> &ExecutionTarget {
        &self.target
    }

    fn validate(&self) -> Result<(), DatasetError> {
        self.input.validate()?;
        self.target.validate()?;
        if let EvaluationInput::CanonicalRequest { request } = &self.input
            && request.route() != &self.target.route
        {
            return Err(DatasetError::RequestRouteMismatch);
        }
        Ok(())
    }
}

/// A deterministic, content-inspecting property checked before any model judge.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeterministicAssertion {
    /// Requires the canonical serialized response to have an exact SHA-256 digest.
    ResponseSha256 {
        /// Stable assertion identifier used in content-free reports.
        id: String,
        /// Candidate evaluated by the assertion.
        target: CandidateRole,
        /// Expected lowercase SHA-256 digest.
        expected_sha256: String,
    },
    /// Requires a canonical response JSON pointer to exist.
    JsonPointerPresent {
        /// Stable assertion identifier used in content-free reports.
        id: String,
        /// Candidate evaluated by the assertion.
        target: CandidateRole,
        /// RFC 6901 JSON pointer; an empty pointer denotes the root.
        pointer: String,
    },
    /// Requires a canonical response JSON pointer to equal an expected value.
    JsonPointerEquals {
        /// Stable assertion identifier used in content-free reports.
        id: String,
        /// Candidate evaluated by the assertion.
        target: CandidateRole,
        /// RFC 6901 JSON pointer; an empty pointer denotes the root.
        pointer: String,
        /// Expected canonical JSON value retained only in the dataset.
        expected: Value,
    },
    /// Requires an integer microunit value to remain within the case tolerance.
    JsonNumberMicrounitsWithin {
        /// Stable assertion identifier used in content-free reports.
        id: String,
        /// Candidate evaluated by the assertion.
        target: CandidateRole,
        /// RFC 6901 JSON pointer to an integer microunit value.
        pointer: String,
        /// Expected signed microunit value.
        expected_microunits: i64,
    },
}

impl DeterministicAssertion {
    /// Borrows the stable content-free assertion identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::ResponseSha256 { id, .. }
            | Self::JsonPointerPresent { id, .. }
            | Self::JsonPointerEquals { id, .. }
            | Self::JsonNumberMicrounitsWithin { id, .. } => id,
        }
    }

    /// Returns the candidate evaluated by this assertion.
    #[must_use]
    pub const fn target(&self) -> CandidateRole {
        match self {
            Self::ResponseSha256 { target, .. }
            | Self::JsonPointerPresent { target, .. }
            | Self::JsonPointerEquals { target, .. }
            | Self::JsonNumberMicrounitsWithin { target, .. } => *target,
        }
    }

    fn validate(&self) -> Result<(), DatasetError> {
        validate_identifier(self.id())?;
        match self {
            Self::ResponseSha256 {
                expected_sha256, ..
            } => validate_digest(expected_sha256),
            Self::JsonPointerPresent { pointer, .. }
            | Self::JsonPointerEquals { pointer, .. }
            | Self::JsonNumberMicrounitsWithin { pointer, .. } => validate_json_pointer(pointer),
        }
    }
}

/// Numeric and model-judge tolerances recorded with every case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalTolerances {
    absolute_numeric_microunits: u64,
    minimum_judge_score_microunits: Option<u64>,
}

impl EvalTolerances {
    /// Creates explicit deterministic and optional judge tolerances.
    #[must_use]
    pub const fn new(
        absolute_numeric_microunits: u64,
        minimum_judge_score_microunits: Option<u64>,
    ) -> Self {
        Self {
            absolute_numeric_microunits,
            minimum_judge_score_microunits,
        }
    }

    /// Returns the permitted absolute numeric delta.
    #[must_use]
    pub const fn absolute_numeric_microunits(self) -> u64 {
        self.absolute_numeric_microunits
    }

    /// Returns the optional minimum model-judge score on a million-point scale.
    #[must_use]
    pub const fn minimum_judge_score_microunits(self) -> Option<u64> {
        self.minimum_judge_score_microunits
    }

    fn validate(self) -> Result<(), DatasetError> {
        if self
            .minimum_judge_score_microunits
            .is_some_and(|score| score > 1_000_000)
        {
            return Err(DatasetError::InvalidJudgeTolerance);
        }
        Ok(())
    }
}

/// Content-addressed evidence that a judge methodology was calibrated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeCalibration {
    dataset_id: String,
    dataset_version: String,
    evidence_sha256: String,
}

impl JudgeCalibration {
    /// Creates calibration evidence tied to a versioned benchmark dataset.
    #[must_use]
    pub fn new(dataset_id: String, dataset_version: String, evidence_sha256: String) -> Self {
        Self {
            dataset_id,
            dataset_version,
            evidence_sha256,
        }
    }

    /// Borrows the calibration dataset identifier.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Borrows the calibration dataset version.
    #[must_use]
    pub fn dataset_version(&self) -> &str {
        &self.dataset_version
    }

    /// Borrows the calibration evidence digest.
    #[must_use]
    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    fn validate(&self) -> Result<(), DatasetError> {
        validate_identifier(&self.dataset_id)?;
        validate_identifier(&self.dataset_version)?;
        validate_digest(&self.evidence_sha256)
    }
}

/// A calibrated, versioned model-judge methodology.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeMethodology {
    methodology_id: String,
    methodology_version: String,
    rubric_sha256: String,
    judge: ExecutionTarget,
    calibration: Option<JudgeCalibration>,
    blind_seed: Option<u64>,
}

impl JudgeMethodology {
    /// Creates judge admission data; dataset validation rejects missing calibration.
    #[must_use]
    pub fn new(
        methodology_id: String,
        methodology_version: String,
        rubric_sha256: String,
        judge: ExecutionTarget,
        calibration: Option<JudgeCalibration>,
        blind_seed: Option<u64>,
    ) -> Self {
        Self {
            methodology_id,
            methodology_version,
            rubric_sha256,
            judge,
            calibration,
            blind_seed,
        }
    }

    /// Borrows the methodology identifier.
    #[must_use]
    pub fn methodology_id(&self) -> &str {
        &self.methodology_id
    }

    /// Borrows the exact methodology version.
    #[must_use]
    pub fn methodology_version(&self) -> &str {
        &self.methodology_version
    }

    /// Borrows the content-addressed rubric digest.
    #[must_use]
    pub fn rubric_sha256(&self) -> &str {
        &self.rubric_sha256
    }

    /// Borrows the exact judge execution target.
    #[must_use]
    pub const fn judge(&self) -> &ExecutionTarget {
        &self.judge
    }

    /// Borrows calibration evidence when supplied.
    #[must_use]
    pub const fn calibration(&self) -> Option<&JudgeCalibration> {
        self.calibration.as_ref()
    }

    /// Returns the optional deterministic pair-blinding seed.
    #[must_use]
    pub const fn blind_seed(&self) -> Option<u64> {
        self.blind_seed
    }

    fn validate(&self) -> Result<(), DatasetError> {
        validate_identifier(&self.methodology_id)?;
        validate_identifier(&self.methodology_version)?;
        validate_digest(&self.rubric_sha256)?;
        self.judge.validate()?;
        self.calibration
            .as_ref()
            .ok_or(DatasetError::UncalibratedJudge)?
            .validate()
    }
}

/// One bounded evaluation case.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCase {
    id: String,
    primary: EvalInvocation,
    comparison: Option<EvalInvocation>,
    expected: Vec<DeterministicAssertion>,
    judge: Option<JudgeMethodology>,
    tolerances: EvalTolerances,
    deadline_ms: u64,
    cost_ceiling_microunits: u64,
}

impl EvalCase {
    /// Creates a case. Admission occurs when it is placed in a dataset.
    #[expect(
        clippy::too_many_arguments,
        reason = "the record deliberately retains every independent evaluation control"
    )]
    #[must_use]
    pub fn new(
        id: String,
        primary: EvalInvocation,
        comparison: Option<EvalInvocation>,
        expected: Vec<DeterministicAssertion>,
        judge: Option<JudgeMethodology>,
        tolerances: EvalTolerances,
        deadline_ms: u64,
        cost_ceiling_microunits: u64,
    ) -> Self {
        Self {
            id,
            primary,
            comparison,
            expected,
            judge,
            tolerances,
            deadline_ms,
            cost_ceiling_microunits,
        }
    }

    /// Borrows the case identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Borrows the primary invocation.
    #[must_use]
    pub const fn primary(&self) -> &EvalInvocation {
        &self.primary
    }

    /// Borrows the optional comparison invocation.
    #[must_use]
    pub const fn comparison(&self) -> Option<&EvalInvocation> {
        self.comparison.as_ref()
    }

    /// Borrows ordered deterministic assertions.
    #[must_use]
    pub fn expected(&self) -> &[DeterministicAssertion] {
        &self.expected
    }

    /// Borrows the optional admitted model judge.
    #[must_use]
    pub const fn judge(&self) -> Option<&JudgeMethodology> {
        self.judge.as_ref()
    }

    /// Returns explicit tolerances.
    #[must_use]
    pub const fn tolerances(&self) -> EvalTolerances {
        self.tolerances
    }

    /// Returns the case deadline in milliseconds.
    #[must_use]
    pub const fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    /// Returns the total candidate cost ceiling in microunits.
    #[must_use]
    pub const fn cost_ceiling_microunits(&self) -> u64 {
        self.cost_ceiling_microunits
    }

    fn validate(&self) -> Result<(), DatasetError> {
        validate_identifier(&self.id)?;
        self.primary.validate()?;
        if let Some(comparison) = &self.comparison {
            comparison.validate()?;
        }
        if self.expected.is_empty() {
            return Err(DatasetError::MissingDeterministicAssertion);
        }
        for assertion in &self.expected {
            assertion.validate()?;
            if assertion.target() == CandidateRole::Comparison && self.comparison.is_none() {
                return Err(DatasetError::MissingComparison);
            }
        }
        self.tolerances.validate()?;
        match (&self.judge, self.tolerances.minimum_judge_score_microunits) {
            (Some(judge), Some(_)) => {
                judge.validate()?;
                if judge.blind_seed.is_some() && self.comparison.is_none() {
                    return Err(DatasetError::MissingComparison);
                }
            }
            (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(DatasetError::InvalidJudgeTolerance);
            }
        }
        if self.deadline_ms == 0 || self.cost_ceiling_microunits == 0 {
            return Err(DatasetError::InvalidCaseLimit);
        }
        Ok(())
    }
}

/// A versioned, bounded deterministic evaluation dataset.
#[derive(Clone, PartialEq, Serialize)]
pub struct EvaluationDataset {
    schema_version: String,
    dataset_id: String,
    dataset_version: String,
    cases: Vec<EvalCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DatasetWire {
    schema_version: String,
    dataset_id: String,
    dataset_version: String,
    cases: Vec<EvalCase>,
}

impl EvaluationDataset {
    /// Creates and admits a dataset under explicit byte and case bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`DatasetError`] for invalid records or exceeded bounds.
    pub fn new(
        dataset_id: String,
        dataset_version: String,
        cases: Vec<EvalCase>,
        bounds: DatasetBounds,
    ) -> Result<Self, DatasetError> {
        let dataset = Self {
            schema_version: DATASET_SCHEMA_VERSION.to_owned(),
            dataset_id,
            dataset_version,
            cases,
        };
        dataset.validate(bounds)?;
        Ok(dataset)
    }

    /// Parses and admits a dataset without retaining the source buffer.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`DatasetError`] for malformed JSON, invalid records, or bounds.
    pub fn from_json(bytes: &[u8], bounds: DatasetBounds) -> Result<Self, DatasetError> {
        if bytes.len() > bounds.max_bytes {
            return Err(DatasetError::TooManyBytes);
        }
        let wire: DatasetWire =
            serde_json::from_slice(bytes).map_err(|_| DatasetError::InvalidJson)?;
        let dataset = Self {
            schema_version: wire.schema_version,
            dataset_id: wire.dataset_id,
            dataset_version: wire.dataset_version,
            cases: wire.cases,
        };
        dataset.validate(bounds)?;
        Ok(dataset)
    }

    /// Returns the fixed dataset schema version.
    #[must_use]
    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    /// Borrows the stable dataset identifier.
    #[must_use]
    pub fn dataset_id(&self) -> &str {
        &self.dataset_id
    }

    /// Borrows the immutable dataset revision.
    #[must_use]
    pub fn dataset_version(&self) -> &str {
        &self.dataset_version
    }

    /// Borrows cases in deterministic report order.
    #[must_use]
    pub fn cases(&self) -> &[EvalCase] {
        &self.cases
    }

    /// Encodes the dataset deterministically.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] if a nested JSON value cannot be encoded.
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, DatasetError> {
        canonical_json(self)
    }

    /// Computes the deterministic digest of the canonical dataset encoding.
    ///
    /// # Errors
    ///
    /// Returns [`DatasetError::Serialization`] if canonical encoding fails.
    pub fn sha256(&self) -> Result<String, DatasetError> {
        hash_serializable(self)
    }

    pub(crate) fn validate(&self, bounds: DatasetBounds) -> Result<(), DatasetError> {
        if self.schema_version != DATASET_SCHEMA_VERSION {
            return Err(DatasetError::UnsupportedSchemaVersion);
        }
        validate_identifier(&self.dataset_id)?;
        validate_identifier(&self.dataset_version)?;
        if self.cases.is_empty() || self.cases.len() > bounds.max_cases {
            return Err(DatasetError::CaseCount);
        }
        for (index, case) in self.cases.iter().enumerate() {
            case.validate()?;
            if self.cases[..index]
                .iter()
                .any(|previous| previous.id == case.id)
            {
                return Err(DatasetError::DuplicateCase);
            }
        }
        if self.to_canonical_json()?.len() > bounds.max_bytes {
            return Err(DatasetError::TooManyBytes);
        }
        Ok(())
    }
}

fn validate_identifier(value: &str) -> Result<(), DatasetError> {
    if value.is_empty()
        || value.len() > 160
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/' | b'@' | b'+')
        })
    {
        return Err(DatasetError::InvalidIdentifier);
    }
    Ok(())
}

fn validate_capabilities(capabilities: &[String]) -> Result<(), DatasetError> {
    if capabilities.len() > 64 {
        return Err(DatasetError::InvalidIdentifier);
    }
    for (index, capability) in capabilities.iter().enumerate() {
        validate_identifier(capability)?;
        if capabilities[..index].contains(capability) {
            return Err(DatasetError::InvalidIdentifier);
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), DatasetError> {
    if is_sha256(value) {
        Ok(())
    } else {
        Err(DatasetError::InvalidDigest)
    }
}

fn validate_json_pointer(pointer: &str) -> Result<(), DatasetError> {
    if pointer.len() > 512 || (!pointer.is_empty() && !pointer.starts_with('/')) {
        return Err(DatasetError::InvalidJsonPointer);
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~' && !matches!(bytes.next(), Some(b'0' | b'1')) {
            return Err(DatasetError::InvalidJsonPointer);
        }
    }
    Ok(())
}
