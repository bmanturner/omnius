//! Bounded validation adapters for untrusted transport payloads.
//!
//! This crate owns boundary validation only. Domain invariants remain in domain and application
//! code, while database constraints remain authoritative for persisted invariants. Raw values and
//! third-party validation messages never enter the public error surface.

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use garde::{Validate, error::Kind as GardePathKind};
use jsonschema::error::ValidationErrorKind;
use rsk_http::{FieldError as ProblemFieldError, ProblemBuildError};
use serde_json::Value;
use thiserror::Error;

/// Default maximum JSON request size: 2 MiB.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Default maximum JSON Schema document size: 256 KiB.
pub const DEFAULT_MAX_SCHEMA_BYTES: usize = 256 * 1024;
/// Maximum number of safe field failures accepted by the Problem Details contract.
pub const MAX_VALIDATION_ERRORS: usize = 100;
/// Client-safe detail for a boundary validation failure.
pub const SAFE_VALIDATION_DETAIL: &str = "request validation failed";

const MAX_PATH_SEGMENTS: usize = 32;
const MAX_PATH_BYTES: usize = 512;
const MAX_PATH_SEGMENT_BYTES: usize = 128;
const MAX_CONFIGURED_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
const MAX_CONFIGURED_SCHEMA_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONFIGURED_DEPTH: usize = 64;
const MAX_CONFIGURED_NODES: usize = 200_000;
const MAX_CONFIGURED_ARRAY_ITEMS: usize = 100_000;
const MAX_CONFIGURED_OBJECT_PROPERTIES: usize = 10_000;
const MAX_CONFIGURED_STRING_BYTES: usize = 4 * 1024 * 1024;

/// One typed JSON location component.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PathSegment {
    /// A JSON object property.
    Property(String),
    /// A JSON array index.
    Index(usize),
}

/// A bounded typed path that renders as an RFC 6901 JSON Pointer.
#[derive(Clone, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct FieldPath {
    segments: Vec<PathSegment>,
}

impl FieldPath {
    /// Returns the root path.
    #[must_use]
    pub const fn root() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Parses an RFC 6901 pointer without guessing whether numeric components are array indexes.
    ///
    /// Parsed components are properties. Adapters that have the JSON instance retain typed array
    /// indexes automatically.
    ///
    /// # Errors
    ///
    /// Returns [`FieldPathError`] for malformed escapes or a path exceeding the safety bounds.
    pub fn try_from_json_pointer(pointer: &str) -> Result<Self, FieldPathError> {
        if pointer.is_empty() {
            return Ok(Self::root());
        }
        let Some(segments) = pointer.strip_prefix('/') else {
            return Err(FieldPathError::InvalidPointer);
        };
        let mut path = Self::root();
        for segment in segments.split('/') {
            path.try_push_property(decode_pointer_segment(segment)?)?;
        }
        Ok(path)
    }

    /// Returns the typed path components.
    #[must_use]
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// Appends a bounded property component.
    ///
    /// # Errors
    ///
    /// Returns [`FieldPathError`] when the component or complete pointer is too large.
    pub fn try_push_property(&mut self, property: impl Into<String>) -> Result<(), FieldPathError> {
        let property = property.into();
        if property.len() > MAX_PATH_SEGMENT_BYTES {
            return Err(FieldPathError::SegmentTooLong);
        }
        self.try_push(PathSegment::Property(property))
    }

    /// Appends an array index.
    ///
    /// # Errors
    ///
    /// Returns [`FieldPathError`] when the complete pointer is too large.
    pub fn try_push_index(&mut self, index: usize) -> Result<(), FieldPathError> {
        self.try_push(PathSegment::Index(index))
    }

    /// Renders the canonical RFC 6901 JSON Pointer.
    #[must_use]
    pub fn to_json_pointer(&self) -> String {
        let mut pointer = String::with_capacity(self.encoded_len());
        for segment in &self.segments {
            pointer.push('/');
            match segment {
                PathSegment::Property(property) => write_escaped_segment(&mut pointer, property),
                PathSegment::Index(index) => pointer.push_str(&index.to_string()),
            }
        }
        pointer
    }

    fn try_push(&mut self, segment: PathSegment) -> Result<(), FieldPathError> {
        if self.segments.len() >= MAX_PATH_SEGMENTS {
            return Err(FieldPathError::TooDeep);
        }
        self.segments.push(segment);
        if self.encoded_len() > MAX_PATH_BYTES {
            let _ = self.segments.pop();
            return Err(FieldPathError::TooLong);
        }
        Ok(())
    }

    fn encoded_len(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| {
                1 + match segment {
                    PathSegment::Property(property) => property
                        .bytes()
                        .map(|byte| if matches!(byte, b'~' | b'/') { 2 } else { 1 })
                        .sum::<usize>(),
                    PathSegment::Index(index) => {
                        usize::try_from(index.checked_ilog10().unwrap_or(0)).unwrap_or(0) + 1
                    }
                }
            })
            .sum()
    }
}

/// Invalid or excessive field path.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FieldPathError {
    /// The input was not an RFC 6901 pointer.
    #[error("invalid validation field pointer")]
    InvalidPointer,
    /// A pointer escape was malformed.
    #[error("invalid validation field pointer escape")]
    InvalidEscape,
    /// One property component exceeded 128 bytes.
    #[error("validation field path component exceeds 128 bytes")]
    SegmentTooLong,
    /// The path exceeded 32 components.
    #[error("validation field path exceeds 32 components")]
    TooDeep,
    /// The rendered pointer exceeded 512 bytes.
    #[error("validation field pointer exceeds 512 bytes")]
    TooLong,
}

/// Stable, value-free boundary validation categories.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ValidationCode {
    /// A required field is absent.
    Required,
    /// A value has the wrong JSON or DTO type.
    InvalidType,
    /// A value does not satisfy a declared format.
    InvalidFormat,
    /// A numeric value is outside its declared range.
    OutOfRange,
    /// A string, collection, or object has an invalid length.
    InvalidLength,
    /// An undeclared object property was supplied.
    UnexpectedField,
    /// A value does not match a declared pattern.
    PatternMismatch,
    /// A boundary rule failed without a more specific safe category.
    Invalid,
}

impl ValidationCode {
    const fn wire_code(self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::InvalidType => "invalid_type",
            Self::InvalidFormat => "invalid_format",
            Self::OutOfRange => "out_of_range",
            Self::InvalidLength => "invalid_length",
            Self::UnexpectedField => "unexpected_field",
            Self::PatternMismatch => "pattern_mismatch",
            Self::Invalid => "invalid",
        }
    }

    const fn safe_message(self) -> &'static str {
        match self {
            Self::Required => "field is required",
            Self::InvalidType => "value has an invalid type",
            Self::InvalidFormat => "value has an invalid format",
            Self::OutOfRange => "value is outside the permitted range",
            Self::InvalidLength => "value has an invalid length",
            Self::UnexpectedField => "field is not permitted",
            Self::PatternMismatch => "value does not match the permitted pattern",
            Self::Invalid => "value does not satisfy boundary constraints",
        }
    }
}

/// One typed, value-free validation failure.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ValidationIssue {
    path: FieldPath,
    code: ValidationCode,
}

impl ValidationIssue {
    /// Creates a safe issue from a typed path and closed error category.
    #[must_use]
    pub const fn new(path: FieldPath, code: ValidationCode) -> Self {
        Self { path, code }
    }

    /// Returns the typed failure path.
    #[must_use]
    pub const fn path(&self) -> &FieldPath {
        &self.path
    }

    /// Returns the stable error category.
    #[must_use]
    pub const fn code(&self) -> ValidationCode {
        self.code
    }

    /// Returns a static message that never contains the rejected value.
    #[must_use]
    pub const fn safe_message(&self) -> &'static str {
        self.code.safe_message()
    }
}

/// A deterministic, bounded aggregate of boundary validation failures.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("boundary validation failed")]
pub struct ValidationErrors {
    issues: Vec<ValidationIssue>,
    truncated: bool,
}

impl ValidationErrors {
    /// Creates an aggregate from one or more already-safe issues.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationErrorsBuildError`] for an empty or oversized aggregate.
    pub fn try_new(issues: Vec<ValidationIssue>) -> Result<Self, ValidationErrorsBuildError> {
        if issues.is_empty() {
            return Err(ValidationErrorsBuildError::Empty);
        }
        if issues.len() > MAX_VALIDATION_ERRORS {
            return Err(ValidationErrorsBuildError::TooMany);
        }
        Ok(Self::bounded(issues, false))
    }

    /// Creates an aggregate containing one issue.
    #[must_use]
    pub fn one(issue: ValidationIssue) -> Self {
        Self::bounded(vec![issue], false)
    }

    /// Returns sorted, duplicate-free issues.
    #[must_use]
    pub fn issues(&self) -> &[ValidationIssue] {
        &self.issues
    }

    /// Reports whether additional provider failures were omitted at the public bound.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Converts into existing RFC 9457 field errors without third-party messages or values.
    ///
    /// # Errors
    ///
    /// Returns [`ProblemBuildError`] only if the downstream Problem Details contract changes in a
    /// way incompatible with this crate's bounded pointer and code invariants.
    pub fn to_problem_field_errors(&self) -> Result<Vec<ProblemFieldError>, ProblemBuildError> {
        self.issues
            .iter()
            .map(|issue| {
                ProblemFieldError::try_new(
                    issue.path.to_json_pointer(),
                    issue.code.wire_code(),
                    issue.safe_message(),
                )
            })
            .collect()
    }

    fn bounded(mut issues: Vec<ValidationIssue>, mut truncated: bool) -> Self {
        issues.sort_unstable();
        issues.dedup();
        if issues.len() > MAX_VALIDATION_ERRORS {
            issues.truncate(MAX_VALIDATION_ERRORS);
            truncated = true;
        }
        Self { issues, truncated }
    }
}

/// Invalid validation error aggregate.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValidationErrorsBuildError {
    /// Successful validation must be represented by `Ok`, not an empty error.
    #[error("validation error aggregate must not be empty")]
    Empty,
    /// The public aggregate exceeded the Problem Details bound.
    #[error("validation error aggregate exceeds 100 issues")]
    TooMany,
}

/// Validates and consumes a transport DTO with its default garde context.
///
/// # Errors
///
/// Returns only typed, value-free [`ValidationErrors`]. Garde's free-form messages are discarded.
pub fn validate_garde<T>(value: T) -> Result<garde::Valid<T>, ValidationErrors>
where
    T: Validate,
    T::Context: Default,
{
    garde::Unvalidated::new(value)
        .validate()
        .map_err(validation_errors_from_garde)
}

/// Validates and consumes a transport DTO with an explicit garde context.
///
/// # Errors
///
/// Returns only typed, value-free [`ValidationErrors`]. Garde's free-form messages are discarded.
pub fn validate_garde_with<T>(
    value: T,
    context: &T::Context,
) -> Result<garde::Valid<T>, ValidationErrors>
where
    T: Validate,
{
    garde::Unvalidated::new(value)
        .validate_with(context)
        .map_err(validation_errors_from_garde)
}

/// Borrowing seam for boundary validators used by transport adapters.
pub trait BoundaryValidator<T>: Clone + Send + Sync + 'static {
    /// Validates without retaining or recording the supplied value.
    ///
    /// # Errors
    ///
    /// Returns typed, value-free boundary failures.
    fn validate(&self, value: &T) -> Result<(), ValidationErrors>;
}

/// Production borrowing adapter for garde-derived transport DTOs.
#[derive(Clone, Copy, Debug, Default)]
pub struct GardeBoundaryValidator;

impl<T> BoundaryValidator<T> for GardeBoundaryValidator
where
    T: Validate,
    T::Context: Default,
{
    fn validate(&self, value: &T) -> Result<(), ValidationErrors> {
        value.validate().map_err(validation_errors_from_garde)
    }
}

/// Deterministic fake validator that records only a call count, never inspected values.
#[derive(Clone, Debug)]
pub struct FakeBoundaryValidator {
    outcome: Arc<Mutex<Result<(), ValidationErrors>>>,
    calls: Arc<AtomicUsize>,
}

impl FakeBoundaryValidator {
    /// Creates a fake with a deterministic fallback outcome.
    #[must_use]
    pub fn new(outcome: Result<(), ValidationErrors>) -> Self {
        Self {
            outcome: Arc::new(Mutex::new(outcome)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Replaces the outcome returned to later calls.
    ///
    /// # Errors
    ///
    /// Returns [`FakeValidationError`] if the fake state is unavailable.
    pub fn set_outcome(
        &self,
        outcome: Result<(), ValidationErrors>,
    ) -> Result<(), FakeValidationError> {
        let mut current = self
            .outcome
            .lock()
            .map_err(|_| FakeValidationError::State)?;
        *current = outcome;
        Ok(())
    }

    /// Returns the number of validation calls without retaining input values.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl<T> BoundaryValidator<T> for FakeBoundaryValidator {
    fn validate(&self, _value: &T) -> Result<(), ValidationErrors> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        self.outcome.lock().map_or_else(
            |_| {
                Err(ValidationErrors::one(ValidationIssue::new(
                    FieldPath::root(),
                    ValidationCode::Invalid,
                )))
            },
            |outcome| outcome.clone(),
        )
    }
}

/// Failure to access deterministic fake state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FakeValidationError {
    /// The fake's synchronization state was poisoned.
    #[error("fake boundary validator state is unavailable")]
    State,
}

/// Bounds applied before and after JSON decoding and during schema validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JsonValidationLimits {
    /// Maximum serialized payload bytes.
    pub max_payload_bytes: usize,
    /// Maximum serialized schema bytes.
    pub max_schema_bytes: usize,
    /// Maximum object/array nesting depth, where the root has depth zero.
    pub max_depth: usize,
    /// Maximum total JSON nodes.
    pub max_nodes: usize,
    /// Maximum items in any one array.
    pub max_array_items: usize,
    /// Maximum properties in any one object.
    pub max_object_properties: usize,
    /// Maximum UTF-8 bytes in any one string or property name.
    pub max_string_bytes: usize,
    /// Maximum validation issues returned to the caller.
    pub max_errors: usize,
}

impl Default for JsonValidationLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_schema_bytes: DEFAULT_MAX_SCHEMA_BYTES,
            max_depth: 32,
            max_nodes: 100_000,
            max_array_items: 10_000,
            max_object_properties: 1_000,
            max_string_bytes: 1024 * 1024,
            max_errors: MAX_VALIDATION_ERRORS,
        }
    }
}

impl JsonValidationLimits {
    /// Validates every non-zero configured safety bound against a hard ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`JsonLimitError`] if any configured bound is zero or excessive.
    pub fn validate(self) -> Result<Self, JsonLimitError> {
        let valid = self.max_payload_bytes > 0
            && self.max_payload_bytes <= MAX_CONFIGURED_PAYLOAD_BYTES
            && self.max_schema_bytes > 0
            && self.max_schema_bytes <= MAX_CONFIGURED_SCHEMA_BYTES
            && self.max_depth > 0
            && self.max_depth <= MAX_CONFIGURED_DEPTH
            && self.max_nodes > 0
            && self.max_nodes <= MAX_CONFIGURED_NODES
            && self.max_array_items > 0
            && self.max_array_items <= MAX_CONFIGURED_ARRAY_ITEMS
            && self.max_object_properties > 0
            && self.max_object_properties <= MAX_CONFIGURED_OBJECT_PROPERTIES
            && self.max_string_bytes > 0
            && self.max_string_bytes <= MAX_CONFIGURED_STRING_BYTES
            && self.max_errors > 0
            && self.max_errors <= MAX_VALIDATION_ERRORS;
        if valid { Ok(self) } else { Err(JsonLimitError) }
    }
}

/// Invalid JSON safety bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("JSON validation limits are invalid")]
pub struct JsonLimitError;

/// Bounded JSON structure failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JsonStructureError {
    /// Nesting exceeded the configured depth.
    #[error("JSON nesting exceeds the configured limit")]
    TooDeep,
    /// Total nodes exceeded the configured bound.
    #[error("JSON node count exceeds the configured limit")]
    TooManyNodes,
    /// One array exceeded its item bound.
    #[error("JSON array exceeds the configured item limit")]
    ArrayTooLong,
    /// One object exceeded its property bound.
    #[error("JSON object exceeds the configured property limit")]
    ObjectTooLarge,
    /// One string or property name exceeded its byte bound.
    #[error("JSON string exceeds the configured byte limit")]
    StringTooLong,
}

/// Safe JSON Schema compilation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SchemaAdapterError {
    /// Safety bounds were invalid.
    #[error(transparent)]
    InvalidLimits(#[from] JsonLimitError),
    /// The serialized schema exceeded its byte bound.
    #[error("JSON Schema exceeds the configured byte limit")]
    TooLarge,
    /// The schema was not valid JSON.
    #[error("JSON Schema is malformed")]
    Malformed,
    /// The schema structure exceeded a configured bound.
    #[error(transparent)]
    Structure(#[from] JsonStructureError),
    /// Network or file reference resolution is forbidden at this boundary.
    #[error("JSON Schema contains a non-local reference")]
    NonLocalReference,
    /// The document was not a valid JSON Schema 2020-12 schema.
    #[error("JSON Schema is invalid")]
    InvalidSchema,
}

/// Safe bounded-payload validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum JsonPayloadError {
    /// The serialized payload exceeded its byte bound.
    #[error("JSON payload exceeds the configured byte limit")]
    TooLarge,
    /// The payload was not valid JSON.
    #[error("JSON payload is malformed")]
    Malformed,
    /// The decoded structure exceeded a configured bound.
    #[error(transparent)]
    Structure(#[from] JsonStructureError),
    /// The bounded payload did not satisfy the compiled schema.
    #[error(transparent)]
    Validation(#[from] ValidationErrors),
}

/// A JSON value that passed byte, structure, and schema validation.
pub struct ValidatedJson(Value);

impl ValidatedJson {
    /// Returns the validated value by reference.
    #[must_use]
    pub const fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consumes the wrapper and returns the validated value.
    #[must_use]
    pub fn into_inner(self) -> Value {
        self.0
    }
}

impl fmt::Debug for ValidatedJson {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedJson([REDACTED])")
    }
}

/// Reusable, local-only JSON Schema 2020-12 boundary adapter.
#[derive(Clone)]
pub struct JsonSchemaAdapter {
    validator: jsonschema::Validator,
    limits: JsonValidationLimits,
    reject_all_root_properties: bool,
}

impl JsonSchemaAdapter {
    /// Compiles one bounded JSON Schema with local references and format checks enabled.
    ///
    /// Network and file retrieval are not enabled. Explicit non-local `$ref` and `$dynamicRef`
    /// values are rejected before compilation.
    ///
    /// # Errors
    ///
    /// Returns [`SchemaAdapterError`] without retaining or rendering schema contents.
    pub fn compile(
        schema_bytes: &[u8],
        limits: JsonValidationLimits,
    ) -> Result<Self, SchemaAdapterError> {
        let limits = limits.validate()?;
        if schema_bytes.len() > limits.max_schema_bytes {
            return Err(SchemaAdapterError::TooLarge);
        }
        let schema: Value =
            serde_json::from_slice(schema_bytes).map_err(|_| SchemaAdapterError::Malformed)?;
        validate_json_shape(&schema, limits)?;
        reject_non_local_references(&schema)?;
        let reject_all_root_properties = schema.as_object().is_some_and(|object| {
            object.get("additionalProperties") == Some(&Value::Bool(false))
                && !object.contains_key("properties")
                && !object.contains_key("patternProperties")
        });
        let validator = jsonschema::draft202012::options()
            .should_validate_formats(true)
            .build(&schema)
            .map_err(|_| SchemaAdapterError::InvalidSchema)?;
        Ok(Self {
            validator,
            limits,
            reject_all_root_properties,
        })
    }

    /// Parses and validates one bounded JSON payload.
    ///
    /// The serialized byte bound is enforced before decoding. Structure bounds are enforced before
    /// schema evaluation, and returned issues are sorted, deduplicated, and capped.
    ///
    /// # Errors
    ///
    /// Returns [`JsonPayloadError`] without retaining or rendering payload values.
    pub fn validate_bytes(&self, payload: &[u8]) -> Result<ValidatedJson, JsonPayloadError> {
        if payload.len() > self.limits.max_payload_bytes {
            return Err(JsonPayloadError::TooLarge);
        }
        let value = serde_json::from_slice(payload).map_err(|_| JsonPayloadError::Malformed)?;
        validate_json_shape(&value, self.limits)?;
        self.validate_value(&value)?;
        Ok(ValidatedJson(value))
    }

    /// Returns the immutable safety limits used by this adapter.
    #[must_use]
    pub const fn limits(&self) -> JsonValidationLimits {
        self.limits
    }

    fn validate_value(&self, value: &Value) -> Result<(), ValidationErrors> {
        if self.reject_all_root_properties
            && let Some(object) = value.as_object()
            && !object.is_empty()
        {
            let mut properties = object.keys().map(String::as_str).collect::<Vec<_>>();
            properties.sort_unstable();
            let truncated = properties.len() > self.limits.max_errors;
            let issues = properties
                .into_iter()
                .take(self.limits.max_errors)
                .map(|property| {
                    let mut path = FieldPath::root();
                    if path.try_push_property(property).is_err() {
                        path = FieldPath::root();
                    }
                    ValidationIssue::new(path, ValidationCode::UnexpectedField)
                })
                .collect();
            return Err(ValidationErrors::bounded(issues, truncated));
        }
        let mut issues = Vec::new();
        let mut truncated = false;
        for error in self.validator.iter_errors(value) {
            if issues.len() == self.limits.max_errors
                || append_schema_error_issues(&error, value, &mut issues, self.limits.max_errors)
            {
                truncated = true;
                break;
            }
        }
        if issues.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::bounded(issues, truncated))
        }
    }
}

impl fmt::Debug for JsonSchemaAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonSchemaAdapter")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

fn validation_errors_from_garde(report: garde::Report) -> ValidationErrors {
    let mut issues = Vec::new();
    let mut truncated = false;
    for (path, _error) in report.into_inner() {
        if issues.len() == MAX_VALIDATION_ERRORS {
            truncated = true;
            break;
        }
        issues.push(ValidationIssue::new(
            field_path_from_garde(&path),
            ValidationCode::Invalid,
        ));
    }
    if issues.is_empty() {
        issues.push(ValidationIssue::new(
            FieldPath::root(),
            ValidationCode::Invalid,
        ));
    }
    ValidationErrors::bounded(issues, truncated)
}

fn field_path_from_garde(path: &garde::Path) -> FieldPath {
    let mut converted = FieldPath::root();
    for (kind, component) in path.__iter().rev() {
        let result = match kind {
            GardePathKind::None => Ok(()),
            GardePathKind::Key => converted.try_push_property(component.as_str()),
            GardePathKind::Index => component
                .as_str()
                .parse::<usize>()
                .map_err(|_| FieldPathError::InvalidPointer)
                .and_then(|index| converted.try_push_index(index)),
        };
        if result.is_err() {
            return FieldPath::root();
        }
    }
    converted
}

fn append_schema_error_issues(
    error: &jsonschema::ValidationError<'_>,
    instance: &Value,
    issues: &mut Vec<ValidationIssue>,
    max_errors: usize,
) -> bool {
    let (ValidationErrorKind::AdditionalProperties { unexpected }
    | ValidationErrorKind::UnevaluatedProperties { unexpected }) = error.kind()
    else {
        issues.push(issue_from_schema_error(error, instance));
        return false;
    };
    let base = field_path_from_instance_pointer(error.instance_path().as_str(), instance);
    let mut properties: Vec<&str> = unexpected.iter().map(String::as_str).collect();
    properties.sort_unstable();
    for property in properties {
        if issues.len() == max_errors {
            return true;
        }
        let mut path = base.clone();
        if path.try_push_property(property).is_err() {
            path = base.clone();
        }
        issues.push(ValidationIssue::new(path, ValidationCode::UnexpectedField));
    }
    false
}

fn issue_from_schema_error(
    error: &jsonschema::ValidationError<'_>,
    instance: &Value,
) -> ValidationIssue {
    let mut path = field_path_from_instance_pointer(error.instance_path().as_str(), instance);
    let code = match error.kind() {
        ValidationErrorKind::Required { property } => {
            if let Some(property) = property.as_str() {
                let _ = path.try_push_property(property);
            }
            ValidationCode::Required
        }
        ValidationErrorKind::AdditionalItems { .. }
        | ValidationErrorKind::AdditionalProperties { .. }
        | ValidationErrorKind::UnevaluatedItems { .. }
        | ValidationErrorKind::UnevaluatedProperties { .. } => ValidationCode::UnexpectedField,
        ValidationErrorKind::Type { .. } => ValidationCode::InvalidType,
        ValidationErrorKind::Format { .. }
        | ValidationErrorKind::ContentEncoding { .. }
        | ValidationErrorKind::ContentMediaType { .. }
        | ValidationErrorKind::FromUtf8 { .. } => ValidationCode::InvalidFormat,
        ValidationErrorKind::ExclusiveMaximum { .. }
        | ValidationErrorKind::ExclusiveMinimum { .. }
        | ValidationErrorKind::Maximum { .. }
        | ValidationErrorKind::Minimum { .. }
        | ValidationErrorKind::MultipleOf { .. } => ValidationCode::OutOfRange,
        ValidationErrorKind::MaxItems { .. }
        | ValidationErrorKind::MaxLength { .. }
        | ValidationErrorKind::MaxProperties { .. }
        | ValidationErrorKind::MinItems { .. }
        | ValidationErrorKind::MinLength { .. }
        | ValidationErrorKind::MinProperties { .. } => ValidationCode::InvalidLength,
        ValidationErrorKind::BacktrackLimitExceeded { .. }
        | ValidationErrorKind::RegexEngineFailure { .. }
        | ValidationErrorKind::Pattern { .. } => ValidationCode::PatternMismatch,
        ValidationErrorKind::AnyOf { .. }
        | ValidationErrorKind::Constant { .. }
        | ValidationErrorKind::Contains
        | ValidationErrorKind::Custom { .. }
        | ValidationErrorKind::Enum { .. }
        | ValidationErrorKind::FalseSchema
        | ValidationErrorKind::Not { .. }
        | ValidationErrorKind::OneOfMultipleValid { .. }
        | ValidationErrorKind::OneOfNotValid { .. }
        | ValidationErrorKind::PropertyNames { .. }
        | ValidationErrorKind::UniqueItems
        | ValidationErrorKind::Referencing(_) => ValidationCode::Invalid,
    };
    ValidationIssue::new(path, code)
}

fn field_path_from_instance_pointer(pointer: &str, instance: &Value) -> FieldPath {
    let Some(segments) = pointer.strip_prefix('/') else {
        return FieldPath::root();
    };
    if pointer.is_empty() {
        return FieldPath::root();
    }
    let mut path = FieldPath::root();
    let mut current = Some(instance);
    for encoded in segments.split('/') {
        let Ok(segment) = decode_pointer_segment(encoded) else {
            return FieldPath::root();
        };
        let result = match current {
            Some(Value::Array(items)) => segment
                .parse::<usize>()
                .map_err(|_| FieldPathError::InvalidPointer)
                .and_then(|index| {
                    current = items.get(index);
                    path.try_push_index(index)
                }),
            Some(Value::Object(properties)) => {
                current = properties.get(&segment);
                path.try_push_property(segment)
            }
            _ => {
                current = None;
                path.try_push_property(segment)
            }
        };
        if result.is_err() {
            return FieldPath::root();
        }
    }
    path
}

fn decode_pointer_segment(segment: &str) -> Result<String, FieldPathError> {
    if !segment.contains('~') {
        return Ok(segment.to_owned());
    }
    let mut decoded = String::with_capacity(segment.len());
    let mut remaining = segment;
    while let Some(index) = remaining.find('~') {
        let (before, escape) = remaining.split_at(index);
        decoded.push_str(before);
        let Some(suffix) = escape.get(1..) else {
            return Err(FieldPathError::InvalidEscape);
        };
        match suffix.as_bytes().first() {
            Some(b'0') => decoded.push('~'),
            Some(b'1') => decoded.push('/'),
            _ => return Err(FieldPathError::InvalidEscape),
        }
        remaining = suffix.get(1..).ok_or(FieldPathError::InvalidEscape)?;
    }
    decoded.push_str(remaining);
    Ok(decoded)
}

fn write_escaped_segment(pointer: &mut String, segment: &str) {
    for character in segment.chars() {
        match character {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            _ => pointer.push(character),
        }
    }
}

fn validate_json_shape(
    root: &Value,
    limits: JsonValidationLimits,
) -> Result<(), JsonStructureError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > limits.max_depth {
            return Err(JsonStructureError::TooDeep);
        }
        nodes = nodes.saturating_add(1);
        if nodes > limits.max_nodes {
            return Err(JsonStructureError::TooManyNodes);
        }
        match value {
            Value::String(value) if value.len() > limits.max_string_bytes => {
                return Err(JsonStructureError::StringTooLong);
            }
            Value::Array(values) => {
                if values.len() > limits.max_array_items {
                    return Err(JsonStructureError::ArrayTooLong);
                }
                let retained = nodes.saturating_add(stack.len());
                if values.len() > limits.max_nodes.saturating_sub(retained) {
                    return Err(JsonStructureError::TooManyNodes);
                }
                for child in values {
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            Value::Object(values) => {
                if values.len() > limits.max_object_properties {
                    return Err(JsonStructureError::ObjectTooLarge);
                }
                let retained = nodes.saturating_add(stack.len());
                if values.len() > limits.max_nodes.saturating_sub(retained) {
                    return Err(JsonStructureError::TooManyNodes);
                }
                for (property, child) in values {
                    if property.len() > limits.max_string_bytes {
                        return Err(JsonStructureError::StringTooLong);
                    }
                    stack.push((child, depth.saturating_add(1)));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn reject_non_local_references(schema: &Value) -> Result<(), SchemaAdapterError> {
    let mut stack = vec![schema];
    while let Some(value) = stack.pop() {
        match value {
            Value::Array(values) => stack.extend(values),
            Value::Object(values) => {
                for (property, child) in values {
                    if matches!(property.as_str(), "$ref" | "$dynamicRef")
                        && child
                            .as_str()
                            .is_some_and(|reference| !reference.starts_with('#'))
                    {
                        return Err(SchemaAdapterError::NonLocalReference);
                    }
                    stack.push(child);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}
