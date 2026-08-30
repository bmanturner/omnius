//! Deterministic `OpenAPI` 3.1 policy validation and locally served catalog routes.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderValue, header},
    routing::get,
};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use utoipa::openapi::OpenApi as OpenApiDocument;
use utoipa_swagger_ui::{Config as SwaggerConfig, SwaggerUi};

/// Route serving the deterministic `OpenAPI` document.
pub const OPENAPI_DOCUMENT_PATH: &str = "/openapi.json";
/// Root route serving the locally embedded Swagger UI.
pub const OPENAPI_DOCS_PATH: &str = "/docs";
/// Default maximum serialized document size: four MiB.
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Hard upper bound for a serialized `OpenAPI` document: sixteen MiB.
pub const MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;

const MAX_REFERENCE_DEPTH: usize = 16;
const OPERATION_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

const MAX_DIFF_TRAVERSAL_DEPTH: usize = 64;
const MAX_DIFF_VISITED_NODES: usize = 250_000;

/// Runtime policy for exposing the public API catalog.
///
/// The JSON document and interactive documentation routes are independent: a
/// deployment may expose either route, both routes, or neither route.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OpenApiConfig {
    /// Whether `GET /openapi.json` is installed.
    pub document_route_enabled: bool,
    /// Whether the embedded Swagger UI under `/docs` is installed.
    pub docs_route_enabled: bool,
    /// Maximum accepted size of the canonical serialized document.
    pub max_document_bytes: usize,
}

impl Default for OpenApiConfig {
    fn default() -> Self {
        Self {
            document_route_enabled: true,
            docs_route_enabled: true,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
        }
    }
}

impl OpenApiConfig {
    /// Validates the fixed document-size bound.
    ///
    /// # Errors
    ///
    /// Returns [`OpenApiError::InvalidDocumentSizeLimit`] when the configured
    /// limit is zero or exceeds [`MAX_DOCUMENT_BYTES`].
    pub fn validate(self) -> Result<Self, OpenApiError> {
        if self.max_document_bytes == 0 || self.max_document_bytes > MAX_DOCUMENT_BYTES {
            return Err(OpenApiError::InvalidDocumentSizeLimit);
        }
        Ok(self)
    }
}

/// Safe, value-free `OpenAPI` construction or policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OpenApiError {
    /// The configured document-size limit is outside its fixed bounds.
    #[error("OpenAPI document size limit is outside the supported bounds")]
    InvalidDocumentSizeLimit,
    /// The generated document could not be represented as JSON.
    #[error("OpenAPI document serialization failed")]
    SerializationFailed,
    /// The document is not an `OpenAPI` 3.1 document.
    #[error("OpenAPI document must use version 3.1")]
    UnsupportedVersion,
    /// The document has no public operations to describe.
    #[error("OpenAPI document has no public operations")]
    NoOperations,
    /// At least one operation has no non-empty operation identifier.
    #[error("OpenAPI operation is missing operationId")]
    MissingOperationId,
    /// More than one operation uses the same operation identifier.
    #[error("OpenAPI operationId values must be globally unique")]
    DuplicateOperationId,
    /// At least one operation has no declared response.
    #[error("OpenAPI operation is missing responses")]
    MissingResponses,
    /// At least one operation has no RFC 9457 media-type error response.
    #[error("OpenAPI operation is missing an application/problem+json error response")]
    MissingProblemDetailsResponse,
    /// At least one operation does not state its security policy.
    #[error("OpenAPI operation is missing explicit security")]
    MissingSecurity,
    /// A local `OpenAPI` reference is malformed, missing, or too deeply nested.
    #[error("OpenAPI document contains an invalid reference")]
    InvalidReference,
    /// An operation refers to a security scheme absent from components.
    #[error("OpenAPI operation refers to an undefined security scheme")]
    UndefinedSecurityScheme,
    /// The canonical JSON exceeds the configured size limit.
    #[error("OpenAPI document exceeds the configured size limit")]
    DocumentTooLarge,
    /// The generated operations differ from the composition root's public route registry.
    #[error("OpenAPI operations do not match the public route registry")]
    OperationCoverageMismatch,
}

/// One browser-consumable HTTP operation owned by the composition root.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ExpectedOperation {
    /// Lowercase HTTP method.
    pub method: &'static str,
    /// Canonical `OpenAPI` path template.
    pub path: &'static str,
    /// Stable public operation identifier.
    pub operation_id: &'static str,
    /// Capability-ownership tag.
    pub tag: &'static str,
}

impl ExpectedOperation {
    /// Creates one static operation descriptor.
    #[must_use]
    pub const fn new(
        method: &'static str,
        path: &'static str,
        operation_id: &'static str,
        tag: &'static str,
    ) -> Self {
        Self {
            method,
            path,
            operation_id,
            tag,
        }
    }
}

/// A stable category of structural `OpenAPI` compatibility failure.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum BreakingChangeKind {
    /// A public path no longer exists.
    PathRemoved,
    /// An operation method no longer exists at a retained path.
    MethodRemoved,
    /// A request body no longer accepts a media type.
    RequestMediaTypeRemoved,
    /// An operation no longer declares a response status.
    ResponseStatusRemoved,
    /// A retained response status no longer produces a media type.
    ResponseMediaTypeRemoved,
    /// An operation no longer accepts a parameter.
    ParameterRemoved,
    /// A parameter is new and required, or changed from optional to required.
    ParameterNowRequired,
    /// A request body changed from optional or absent to required.
    RequestBodyNowRequired,
    /// A retained schema no longer declares a property.
    SchemaPropertyRemoved,
    /// A schema property changed from optional or absent to required.
    SchemaPropertyNowRequired,
    /// A schema's declared JSON type set changed.
    SchemaTypeChanged,
    /// A schema's format declaration was added, removed, or changed.
    SchemaFormatChanged,
    /// A schema enum accepts fewer values than before.
    EnumNarrowed,
    /// A schema validation constraint accepts fewer values than before.
    SchemaConstraintNarrowed,
    /// An operation accepts fewer security alternatives than before.
    SecurityRequirementsStrengthened,
}

impl fmt::Display for BreakingChangeKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::PathRemoved => "path removed",
            Self::MethodRemoved => "method removed",
            Self::RequestMediaTypeRemoved => "request media type removed",
            Self::ResponseStatusRemoved => "response status removed",
            Self::ResponseMediaTypeRemoved => "response media type removed",
            Self::ParameterRemoved => "parameter removed",
            Self::ParameterNowRequired => "parameter is now required",
            Self::RequestBodyNowRequired => "request body is now required",
            Self::SchemaPropertyRemoved => "schema property removed",
            Self::SchemaPropertyNowRequired => "schema property is now required",
            Self::SchemaTypeChanged => "schema type changed",
            Self::SchemaFormatChanged => "schema format changed",
            Self::EnumNarrowed => "schema enum narrowed",
            Self::SchemaConstraintNarrowed => "schema constraint narrowed",
            Self::SecurityRequirementsStrengthened => "security requirements strengthened",
        };
        formatter.write_str(description)
    }
}

/// A value-free structural compatibility finding.
///
/// `location` is a JSON Pointer into the compared operation or schema. It may
/// identify API names such as paths and properties, but findings never contain
/// examples, defaults, enum members, or other schema values.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BreakingChange {
    kind: BreakingChangeKind,
    location: String,
    operation_id: Option<String>,
}

impl BreakingChange {
    /// Returns the stable compatibility category.
    #[must_use]
    pub const fn kind(&self) -> BreakingChangeKind {
        self.kind
    }

    /// Returns the JSON Pointer identifying the affected structure.
    #[must_use]
    pub fn location(&self) -> &str {
        &self.location
    }

    /// Returns the baseline operation identifier for operation findings.
    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }
}

impl fmt::Display for BreakingChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} at {}", self.kind, self.location)?;
        if let Some(operation_id) = &self.operation_id {
            write!(formatter, " (operationId: {operation_id})")?;
        }
        Ok(())
    }
}

/// Safe, value-free failure to load or compare two `OpenAPI` documents.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OpenApiDiffError {
    /// The baseline bytes are not a structurally valid `OpenAPI` document.
    #[error("baseline OpenAPI document is malformed")]
    BaselineMalformed,
    /// The candidate bytes are not a structurally valid `OpenAPI` document.
    #[error("candidate OpenAPI document is malformed")]
    CandidateMalformed,
    /// The baseline exceeds the fixed comparison input limit.
    #[error("baseline OpenAPI document exceeds the comparison size limit")]
    BaselineDocumentTooLarge,
    /// The candidate exceeds the fixed comparison input limit.
    #[error("candidate OpenAPI document exceeds the comparison size limit")]
    CandidateDocumentTooLarge,
    /// The baseline violates catalog policy.
    #[error("baseline OpenAPI document violates catalog policy: {0}")]
    BaselinePolicy(#[source] OpenApiError),
    /// The candidate violates catalog policy.
    #[error("candidate OpenAPI document violates catalog policy: {0}")]
    CandidatePolicy(#[source] OpenApiError),
    /// The documents exceed the fixed structural traversal bounds.
    #[error("OpenAPI comparison exceeds structural traversal limits")]
    TraversalLimitExceeded,
}

/// A policy-validated `OpenAPI` document and its canonical JSON representation.
#[derive(Clone)]
pub struct OpenApiCatalog {
    json: Bytes,
    config: OpenApiConfig,
}

impl fmt::Debug for OpenApiCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenApiCatalog")
            .field("config", &self.config)
            .field("json_bytes", &self.json.len())
            .finish()
    }
}

impl OpenApiCatalog {
    /// Validates and serializes a generated `utoipa` document once.
    ///
    /// # Errors
    ///
    /// Returns [`OpenApiError`] when configuration bounds, `OpenAPI` policy,
    /// JSON serialization, or the configured document-size limit are violated.
    pub fn try_new(
        document: &OpenApiDocument,
        config: OpenApiConfig,
    ) -> Result<Self, OpenApiError> {
        let value =
            serde_json::to_value(document).map_err(|_| OpenApiError::SerializationFailed)?;
        Self::try_from_value(value, config)
    }

    /// Validates and serializes a JSON `OpenAPI` document.
    ///
    /// This entry point permits composition roots to add schemas generated by
    /// non-`utoipa` contract owners without translating those contracts into a
    /// second Rust wire model.
    ///
    /// # Errors
    ///
    /// Returns [`OpenApiError`] when the JSON document violates catalog policy,
    /// cannot be serialized, or exceeds the configured size limit.
    pub fn try_from_value(document: Value, config: OpenApiConfig) -> Result<Self, OpenApiError> {
        let config = config.validate()?;
        let json = prepare_value(document)?;
        if json.len() > config.max_document_bytes {
            return Err(OpenApiError::DocumentTooLarge);
        }
        let document_size = u32::try_from(json.len()).unwrap_or(u32::MAX);
        metrics::counter!("omnius_openapi_builds_total").increment(1);
        metrics::histogram!("omnius_openapi_document_size_bytes").record(document_size);
        Ok(Self {
            json: Bytes::from(json),
            config,
        })
    }

    /// Generates a document with `T::openapi()`, then validates and serializes it.
    ///
    /// # Errors
    ///
    /// Returns [`OpenApiError`] under the same conditions as [`Self::try_new`].
    pub fn from_generator<T: utoipa::OpenApi>(config: OpenApiConfig) -> Result<Self, OpenApiError> {
        Self::try_new(&T::openapi(), config)
    }

    /// Returns the stable canonical JSON bytes used by the document route.
    #[must_use]
    pub fn json_bytes(&self) -> &[u8] {
        &self.json
    }

    /// Builds the enabled catalog routes.
    ///
    /// Swagger UI assets are compiled into the binary by the dependency's
    /// `vendored` feature. Serving the docs performs no runtime network fetch.
    pub fn router(&self) -> Router {
        let mut router = Router::new();

        if self.config.document_route_enabled {
            router = router.merge(document_router(OPENAPI_DOCUMENT_PATH, self.json.clone()));
        }

        if self.config.docs_route_enabled {
            const DOCS_DOCUMENT_PATH: &str = "/docs/openapi.json";
            let docs: Router = SwaggerUi::new(OPENAPI_DOCS_PATH)
                .config(SwaggerConfig::from(DOCS_DOCUMENT_PATH).validator_url("none"))
                .into();
            router = router
                .merge(document_router(DOCS_DOCUMENT_PATH, self.json.clone()))
                .merge(docs);
        }

        router
    }
}

fn document_router(path: &'static str, json: Bytes) -> Router {
    Router::new().route(
        path,
        get(move || {
            let json = json.clone();
            async move {
                (
                    [
                        (
                            header::CONTENT_TYPE,
                            HeaderValue::from_static("application/json"),
                        ),
                        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                    ],
                    json,
                )
            }
        }),
    )
}

/// Validates every operation in a generated `OpenAPI` document.
///
/// Explicit empty security arrays are accepted because they are `OpenAPI`'s
/// operation-level declaration that a route is intentionally anonymous.
///
/// # Errors
///
/// Returns the first value-free [`OpenApiError`] policy violation.
pub fn validate_document(document: &OpenApiDocument) -> Result<(), OpenApiError> {
    let value = serde_json::to_value(document).map_err(|_| OpenApiError::SerializationFailed)?;
    validate_json_value(&value)
}

/// Validates an `OpenAPI` JSON value without first translating its schemas into
/// `utoipa` model types.
///
/// # Errors
///
/// Returns the first value-free [`OpenApiError`] policy violation.
pub fn validate_json_value(document: &Value) -> Result<(), OpenApiError> {
    validate_value(document)
}

/// Verifies that the canonical contract exactly covers the composition root's
/// browser-consumable route registry.
///
/// Operator-only documentation and diagnostic routes are intentionally absent
/// from `expected`; every operation present in the contract must otherwise
/// match a route, stable operation ID, and capability tag.
///
/// # Errors
///
/// Returns [`OpenApiError::OperationCoverageMismatch`] for missing, extra, or
/// mismatched operations and the normal policy errors for an invalid document.
pub fn validate_operation_coverage(
    document: &OpenApiDocument,
    expected: &[ExpectedOperation],
) -> Result<(), OpenApiError> {
    let root = serde_json::to_value(document).map_err(|_| OpenApiError::SerializationFailed)?;
    validate_operation_coverage_value(&root, expected)
}

/// Verifies route coverage directly against an `OpenAPI` JSON value.
///
/// # Errors
///
/// Returns [`OpenApiError::OperationCoverageMismatch`] for missing, extra, or
/// mismatched operations and the normal policy errors for an invalid document.
pub fn validate_operation_coverage_value(
    root: &Value,
    expected: &[ExpectedOperation],
) -> Result<(), OpenApiError> {
    validate_json_value(root)?;
    let paths = root
        .get("paths")
        .and_then(Value::as_object)
        .ok_or(OpenApiError::OperationCoverageMismatch)?;
    let mut actual = BTreeMap::new();
    for (path, path_item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        let path_item = resolve_reference(path_item, root)?;
        let path_item = path_item
            .as_object()
            .ok_or(OpenApiError::OperationCoverageMismatch)?;
        for method in OPERATION_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .ok_or(OpenApiError::OperationCoverageMismatch)?;
            let tag = operation
                .get("tags")
                .and_then(Value::as_array)
                .and_then(|tags| tags.first())
                .and_then(Value::as_str)
                .ok_or(OpenApiError::OperationCoverageMismatch)?;
            actual.insert((path.as_str(), *method), (operation_id, tag));
        }
    }

    let mut declared = BTreeMap::new();
    for operation in expected {
        if !OPERATION_METHODS.contains(&operation.method)
            || operation.path.is_empty()
            || operation.operation_id.is_empty()
            || operation.tag.is_empty()
            || declared
                .insert(
                    (operation.path, operation.method),
                    (operation.operation_id, operation.tag),
                )
                .is_some()
        {
            return Err(OpenApiError::OperationCoverageMismatch);
        }
    }
    if actual != declared {
        return Err(OpenApiError::OperationCoverageMismatch);
    }
    Ok(())
}

/// Produces canonical, key-sorted JSON after validating document policy.
///
/// # Errors
///
/// Returns [`OpenApiError`] if policy validation or serialization fails.
pub fn deterministic_json(document: &OpenApiDocument) -> Result<Vec<u8>, OpenApiError> {
    let value = serde_json::to_value(document).map_err(|_| OpenApiError::SerializationFailed)?;
    deterministic_json_value(value)
}

/// Produces canonical, key-sorted JSON for an `OpenAPI` JSON value.
///
/// # Errors
///
/// Returns [`OpenApiError`] if policy validation or serialization fails.
pub fn deterministic_json_value(document: Value) -> Result<Vec<u8>, OpenApiError> {
    prepare_value(document)
}

fn prepare_value(mut value: Value) -> Result<Vec<u8>, OpenApiError> {
    validate_value(&value)?;
    canonicalize(&mut value);
    serde_json::to_vec(&value).map_err(|_| OpenApiError::SerializationFailed)
}

fn validate_value(root: &Value) -> Result<(), OpenApiError> {
    let supported_version = root
        .get("openapi")
        .and_then(Value::as_str)
        .is_some_and(is_openapi_31);
    if !supported_version {
        return Err(OpenApiError::UnsupportedVersion);
    }

    let mut operation_ids = BTreeSet::new();
    let Some(paths) = root.get("paths").and_then(Value::as_object) else {
        return Err(OpenApiError::NoOperations);
    };

    for (path, path_item) in paths {
        if path.starts_with("x-") {
            continue;
        }
        let path_item = resolve_reference(path_item, root)?;
        let Some(path_item) = path_item.as_object() else {
            return Err(OpenApiError::InvalidReference);
        };
        for method in OPERATION_METHODS {
            let Some(operation) = path_item.get(*method) else {
                continue;
            };
            let operation_id = validate_operation(operation, root)?;
            if !operation_ids.insert(operation_id) {
                return Err(OpenApiError::DuplicateOperationId);
            }
        }
    }

    if operation_ids.is_empty() {
        return Err(OpenApiError::NoOperations);
    }
    Ok(())
}

fn validate_operation<'a>(operation: &'a Value, root: &Value) -> Result<&'a str, OpenApiError> {
    let Some(operation_id) = operation
        .get("operationId")
        .and_then(Value::as_str)
        .filter(|operation_id| !operation_id.trim().is_empty())
    else {
        return Err(OpenApiError::MissingOperationId);
    };

    let Some(responses) = operation.get("responses").and_then(Value::as_object) else {
        return Err(OpenApiError::MissingResponses);
    };
    if responses.is_empty() {
        return Err(OpenApiError::MissingResponses);
    }
    let mut has_problem_details = false;
    for (status, response) in responses {
        if is_error_response_status(status) && response_has_problem_details(response, root)? {
            has_problem_details = true;
            break;
        }
    }
    if !has_problem_details {
        return Err(OpenApiError::MissingProblemDetailsResponse);
    }

    validate_security(operation, root)?;
    Ok(operation_id)
}

fn validate_security(operation: &Value, root: &Value) -> Result<(), OpenApiError> {
    let Some(security) = operation.get("security").and_then(Value::as_array) else {
        return Err(OpenApiError::MissingSecurity);
    };
    let defined_schemes = root
        .pointer("/components/securitySchemes")
        .and_then(Value::as_object);

    for requirement in security {
        let Some(requirement) = requirement.as_object() else {
            return Err(OpenApiError::UndefinedSecurityScheme);
        };
        for scheme in requirement.keys() {
            if !defined_schemes.is_some_and(|defined| defined.contains_key(scheme)) {
                return Err(OpenApiError::UndefinedSecurityScheme);
            }
        }
    }
    Ok(())
}

fn response_has_problem_details(response: &Value, root: &Value) -> Result<bool, OpenApiError> {
    const REQUIRED_PROPERTIES: &[&str] = &["type", "title", "status", "code", "request_id"];

    let response = resolve_reference(response, root)?;
    let Some(schema) = response
        .get("content")
        .and_then(Value::as_object)
        .and_then(|content| content.get("application/problem+json"))
        .and_then(|media| media.get("schema"))
    else {
        return Ok(false);
    };
    let schema = resolve_reference(schema, root)?;
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return Ok(false);
    };
    let Some(required) = schema.get("required").and_then(Value::as_array) else {
        return Ok(false);
    };

    Ok(schema.get("type").and_then(Value::as_str) == Some("object")
        && REQUIRED_PROPERTIES
            .iter()
            .all(|property| properties.contains_key(*property))
        && REQUIRED_PROPERTIES.iter().all(|property| {
            required
                .iter()
                .any(|required| required.as_str() == Some(*property))
        }))
}

fn resolve_reference<'a>(value: &'a Value, root: &'a Value) -> Result<&'a Value, OpenApiError> {
    let mut resolved = value;
    for _ in 0..MAX_REFERENCE_DEPTH {
        let Some(reference) = resolved.get("$ref") else {
            return Ok(resolved);
        };
        let reference = reference.as_str().ok_or(OpenApiError::InvalidReference)?;
        let pointer = reference
            .strip_prefix('#')
            .ok_or(OpenApiError::InvalidReference)?;
        resolved = root
            .pointer(pointer)
            .ok_or(OpenApiError::InvalidReference)?;
    }
    Err(OpenApiError::InvalidReference)
}

fn is_openapi_31(version: &str) -> bool {
    version
        .strip_prefix("3.1.")
        .is_some_and(|patch| !patch.is_empty() && patch.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_error_response_status(status: &str) -> bool {
    if status == "default" {
        return true;
    }
    let bytes = status.as_bytes();
    bytes.len() == 3
        && matches!(bytes[0], b'4' | b'5')
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'X')
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(object) => {
            let mut entries: Vec<_> = std::mem::take(object).into_iter().collect();
            entries.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
            for (key, mut value) in entries {
                canonicalize(&mut value);
                object.insert(key, value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Compares two policy-valid `OpenAPI` byte documents for structural breaking changes.
///
/// Findings are sorted and deduplicated. Diagnostics contain only structural
/// locations and baseline operation identifiers; schema values are never
/// copied into a finding or an error.
///
/// # Errors
///
/// Returns [`OpenApiDiffError`] if either input is malformed, violates catalog
/// policy, exceeds the fixed input limit, or exceeds structural traversal
/// bounds.
pub fn breaking_changes(
    baseline: &[u8],
    candidate: &[u8],
) -> Result<Vec<BreakingChange>, OpenApiDiffError> {
    let baseline = load_diff_document(baseline, DiffSide::Baseline)?;
    let candidate = load_diff_document(candidate, DiffSide::Candidate)?;
    let mut context = DiffContext::new(&baseline, &candidate);
    context.compare_documents()?;
    Ok(context.changes.into_iter().collect())
}

#[derive(Clone, Copy)]
enum DiffSide {
    Baseline,
    Candidate,
}

impl DiffSide {
    const fn malformed(self) -> OpenApiDiffError {
        match self {
            Self::Baseline => OpenApiDiffError::BaselineMalformed,
            Self::Candidate => OpenApiDiffError::CandidateMalformed,
        }
    }

    const fn too_large(self) -> OpenApiDiffError {
        match self {
            Self::Baseline => OpenApiDiffError::BaselineDocumentTooLarge,
            Self::Candidate => OpenApiDiffError::CandidateDocumentTooLarge,
        }
    }

    const fn policy(self, error: OpenApiError) -> OpenApiDiffError {
        match self {
            Self::Baseline => OpenApiDiffError::BaselinePolicy(error),
            Self::Candidate => OpenApiDiffError::CandidatePolicy(error),
        }
    }
}

fn load_diff_document(bytes: &[u8], side: DiffSide) -> Result<Value, OpenApiDiffError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(side.too_large());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| side.malformed())?;
    validate_value(&value).map_err(|error| side.policy(error))?;
    validate_diff_tree(&value, side)?;
    Ok(value)
}

fn validate_diff_tree(root: &Value, side: DiffSide) -> Result<(), OpenApiDiffError> {
    let mut stack = vec![(root, 0_usize)];
    let mut visited = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        if depth > MAX_DIFF_TRAVERSAL_DEPTH || visited >= MAX_DIFF_VISITED_NODES {
            return Err(OpenApiDiffError::TraversalLimitExceeded);
        }
        visited += 1;
        if value.get("$ref").is_some() {
            resolve_reference(value, root).map_err(|error| side.policy(error))?;
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

struct DiffContext<'a> {
    baseline: &'a Value,
    candidate: &'a Value,
    changes: BTreeSet<BreakingChange>,
    compared_schema_references: BTreeSet<(String, String)>,
    visited_nodes: usize,
}

impl<'a> DiffContext<'a> {
    fn new(baseline: &'a Value, candidate: &'a Value) -> Self {
        Self {
            baseline,
            candidate,
            changes: BTreeSet::new(),
            compared_schema_references: BTreeSet::new(),
            visited_nodes: 0,
        }
    }

    fn compare_documents(&mut self) -> Result<(), OpenApiDiffError> {
        self.compare_component_schemas()?;
        let baseline_paths = self
            .baseline
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(OpenApiDiffError::TraversalLimitExceeded)?;
        let candidate_paths = self
            .candidate
            .get("paths")
            .and_then(Value::as_object)
            .ok_or(OpenApiDiffError::TraversalLimitExceeded)?;

        for (path, baseline_path_item) in baseline_paths {
            if path.starts_with("x-") {
                continue;
            }
            self.consume_node(1)?;
            let path_location = child_pointer("/paths", path);
            let Some(candidate_path_item) = candidate_paths.get(path) else {
                self.record(BreakingChangeKind::PathRemoved, path_location, None);
                continue;
            };
            let baseline_path_item = resolve_compared_reference(baseline_path_item, self.baseline)?;
            let candidate_path_item =
                resolve_compared_reference(candidate_path_item, self.candidate)?;

            for method in OPERATION_METHODS {
                let Some(baseline_operation) = baseline_path_item.get(*method) else {
                    continue;
                };
                self.consume_node(2)?;
                let operation_location = child_pointer(&path_location, method);
                let operation_id = baseline_operation
                    .get("operationId")
                    .and_then(Value::as_str);
                let Some(candidate_operation) = candidate_path_item.get(*method) else {
                    self.record(
                        BreakingChangeKind::MethodRemoved,
                        operation_location,
                        operation_id,
                    );
                    continue;
                };
                self.compare_operation(
                    baseline_path_item,
                    baseline_operation,
                    candidate_path_item,
                    candidate_operation,
                    &operation_location,
                    operation_id,
                )?;
            }
        }
        Ok(())
    }

    fn compare_component_schemas(&mut self) -> Result<(), OpenApiDiffError> {
        let Some(baseline_schemas) = self
            .baseline
            .pointer("/components/schemas")
            .and_then(Value::as_object)
        else {
            return Ok(());
        };
        let candidate_schemas = self
            .candidate
            .pointer("/components/schemas")
            .and_then(Value::as_object);

        for (name, baseline_schema) in baseline_schemas {
            let Some(candidate_schema) = candidate_schemas.and_then(|schemas| schemas.get(name))
            else {
                continue;
            };
            let location = child_pointer("/components/schemas", name);
            let reference = format!("#{location}");
            if !self
                .compared_schema_references
                .insert((reference.clone(), reference))
            {
                continue;
            }
            self.compare_schema(baseline_schema, candidate_schema, &location, 1)?;
        }
        Ok(())
    }

    fn compare_operation(
        &mut self,
        baseline_path_item: &'a Value,
        baseline_operation: &'a Value,
        candidate_path_item: &'a Value,
        candidate_operation: &'a Value,
        location: &str,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        self.compare_parameters(
            baseline_path_item,
            baseline_operation,
            candidate_path_item,
            candidate_operation,
            location,
            operation_id,
        )?;
        self.compare_request_body(
            baseline_operation,
            candidate_operation,
            location,
            operation_id,
        )?;
        self.compare_responses(
            baseline_operation,
            candidate_operation,
            location,
            operation_id,
        )?;
        self.compare_security(
            baseline_operation,
            candidate_operation,
            location,
            operation_id,
        );
        Ok(())
    }

    fn compare_parameters(
        &mut self,
        baseline_path_item: &'a Value,
        baseline_operation: &'a Value,
        candidate_path_item: &'a Value,
        candidate_operation: &'a Value,
        location: &str,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        let baseline_parameters =
            collect_effective_parameters(baseline_path_item, baseline_operation, self.baseline)?;
        let candidate_parameters =
            collect_effective_parameters(candidate_path_item, candidate_operation, self.candidate)?;

        for (&(parameter_in, name), baseline_parameter) in &baseline_parameters {
            self.consume_node(3)?;
            let parameter_location = parameter_location(location, parameter_in, name);
            let Some(candidate_parameter) = candidate_parameters.get(&(parameter_in, name)) else {
                self.record(
                    BreakingChangeKind::ParameterRemoved,
                    parameter_location,
                    operation_id,
                );
                continue;
            };
            if !is_required(baseline_parameter) && is_required(candidate_parameter) {
                self.record(
                    BreakingChangeKind::ParameterNowRequired,
                    parameter_location.clone(),
                    operation_id,
                );
            }
            self.compare_parameter_schema(
                baseline_parameter,
                candidate_parameter,
                &parameter_location,
                operation_id,
            )?;
        }

        for (&(parameter_in, name), candidate_parameter) in &candidate_parameters {
            if !baseline_parameters.contains_key(&(parameter_in, name))
                && is_required(candidate_parameter)
            {
                self.record(
                    BreakingChangeKind::ParameterNowRequired,
                    parameter_location(location, parameter_in, name),
                    operation_id,
                );
            }
        }
        Ok(())
    }

    fn compare_parameter_schema(
        &mut self,
        baseline_parameter: &'a Value,
        candidate_parameter: &'a Value,
        location: &str,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        if let (Some(baseline_schema), Some(candidate_schema)) = (
            baseline_parameter.get("schema"),
            candidate_parameter.get("schema"),
        ) {
            return self.compare_schema(
                baseline_schema,
                candidate_schema,
                &child_pointer(location, "schema"),
                4,
            );
        }

        let baseline_content = baseline_parameter.get("content").and_then(Value::as_object);
        let candidate_content = candidate_parameter
            .get("content")
            .and_then(Value::as_object);
        if let (Some(baseline_content), Some(candidate_content)) =
            (baseline_content, candidate_content)
        {
            for (media_type, baseline_media) in baseline_content {
                let Some(candidate_media) = candidate_content.get(media_type) else {
                    continue;
                };
                self.compare_media_schema(
                    baseline_media,
                    candidate_media,
                    &child_pointer(&child_pointer(location, "content"), media_type),
                    operation_id,
                )?;
            }
        }
        Ok(())
    }

    fn compare_request_body(
        &mut self,
        baseline_operation: &'a Value,
        candidate_operation: &'a Value,
        location: &str,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        let baseline_body = baseline_operation
            .get("requestBody")
            .map(|body| resolve_compared_reference(body, self.baseline))
            .transpose()?;
        let candidate_body = candidate_operation
            .get("requestBody")
            .map(|body| resolve_compared_reference(body, self.candidate))
            .transpose()?;
        let body_location = child_pointer(location, "requestBody");

        if candidate_body.is_some_and(is_required) && !baseline_body.is_some_and(is_required) {
            self.record(
                BreakingChangeKind::RequestBodyNowRequired,
                body_location.clone(),
                operation_id,
            );
        }

        let Some(baseline_body) = baseline_body else {
            return Ok(());
        };
        let baseline_content = baseline_body.get("content").and_then(Value::as_object);
        let candidate_content = candidate_body
            .and_then(|body| body.get("content"))
            .and_then(Value::as_object);
        self.compare_content(
            baseline_content,
            candidate_content,
            &body_location,
            BreakingChangeKind::RequestMediaTypeRemoved,
            operation_id,
        )
    }

    fn compare_responses(
        &mut self,
        baseline_operation: &'a Value,
        candidate_operation: &'a Value,
        location: &str,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        let baseline_responses = baseline_operation
            .get("responses")
            .and_then(Value::as_object)
            .ok_or(OpenApiDiffError::TraversalLimitExceeded)?;
        let candidate_responses = candidate_operation
            .get("responses")
            .and_then(Value::as_object)
            .ok_or(OpenApiDiffError::TraversalLimitExceeded)?;
        let responses_location = child_pointer(location, "responses");

        for (status, baseline_response) in baseline_responses {
            self.consume_node(3)?;
            let status_location = child_pointer(&responses_location, status);
            let Some(candidate_response) = candidate_responses.get(status) else {
                self.record(
                    BreakingChangeKind::ResponseStatusRemoved,
                    status_location,
                    operation_id,
                );
                continue;
            };
            let baseline_response = resolve_compared_reference(baseline_response, self.baseline)?;
            let candidate_response =
                resolve_compared_reference(candidate_response, self.candidate)?;
            self.compare_content(
                baseline_response.get("content").and_then(Value::as_object),
                candidate_response.get("content").and_then(Value::as_object),
                &status_location,
                BreakingChangeKind::ResponseMediaTypeRemoved,
                operation_id,
            )?;
        }
        Ok(())
    }

    fn compare_content(
        &mut self,
        baseline_content: Option<&'a serde_json::Map<String, Value>>,
        candidate_content: Option<&'a serde_json::Map<String, Value>>,
        location: &str,
        removed_kind: BreakingChangeKind,
        operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        let Some(baseline_content) = baseline_content else {
            return Ok(());
        };
        let content_location = child_pointer(location, "content");
        for (media_type, baseline_media) in baseline_content {
            self.consume_node(4)?;
            let media_location = child_pointer(&content_location, media_type);
            let Some(candidate_media) =
                candidate_content.and_then(|content| content.get(media_type))
            else {
                self.record(removed_kind, media_location, operation_id);
                continue;
            };
            self.compare_media_schema(
                baseline_media,
                candidate_media,
                &media_location,
                operation_id,
            )?;
        }
        Ok(())
    }

    fn compare_media_schema(
        &mut self,
        baseline_media: &'a Value,
        candidate_media: &'a Value,
        location: &str,
        _operation_id: Option<&str>,
    ) -> Result<(), OpenApiDiffError> {
        if let (Some(baseline_schema), Some(candidate_schema)) =
            (baseline_media.get("schema"), candidate_media.get("schema"))
        {
            self.compare_schema(
                baseline_schema,
                candidate_schema,
                &child_pointer(location, "schema"),
                5,
            )?;
        }
        Ok(())
    }

    fn compare_security(
        &mut self,
        baseline_operation: &Value,
        candidate_operation: &Value,
        location: &str,
        operation_id: Option<&str>,
    ) {
        let baseline = baseline_operation.get("security").and_then(Value::as_array);
        let candidate = candidate_operation
            .get("security")
            .and_then(Value::as_array);
        if let (Some(baseline), Some(candidate)) = (baseline, candidate)
            && security_is_stricter(baseline, candidate)
        {
            self.record(
                BreakingChangeKind::SecurityRequirementsStrengthened,
                child_pointer(location, "security"),
                operation_id,
            );
        }
    }

    fn compare_schema(
        &mut self,
        baseline_schema: &'a Value,
        candidate_schema: &'a Value,
        location: &str,
        depth: usize,
    ) -> Result<(), OpenApiDiffError> {
        self.consume_node(depth)?;
        let baseline_reference = baseline_schema.get("$ref").and_then(Value::as_str);
        let candidate_reference = candidate_schema.get("$ref").and_then(Value::as_str);
        if baseline_reference.is_some() || candidate_reference.is_some() {
            let references = (
                baseline_reference.unwrap_or(location).to_owned(),
                candidate_reference.unwrap_or(location).to_owned(),
            );
            if !self.compared_schema_references.insert(references) {
                return Ok(());
            }
            let baseline_schema = resolve_compared_reference(baseline_schema, self.baseline)?;
            let candidate_schema = resolve_compared_reference(candidate_schema, self.candidate)?;
            return self.compare_schema(baseline_schema, candidate_schema, location, depth + 1);
        }

        if schema_type_changed(baseline_schema, candidate_schema) {
            self.record(
                BreakingChangeKind::SchemaTypeChanged,
                child_pointer(location, "type"),
                None,
            );
        }
        if schema_format_changed(baseline_schema, candidate_schema) {
            self.record(
                BreakingChangeKind::SchemaFormatChanged,
                child_pointer(location, "format"),
                None,
            );
        }
        if schema_enum_narrowed(baseline_schema, candidate_schema) {
            self.record(
                BreakingChangeKind::EnumNarrowed,
                child_pointer(location, "enum"),
                None,
            );
        }
        self.compare_schema_constraints(baseline_schema, candidate_schema, location);

        self.compare_schema_properties(baseline_schema, candidate_schema, location, depth)?;
        self.compare_nested_schemas(baseline_schema, candidate_schema, location, depth)
    }

    fn compare_schema_constraints(
        &mut self,
        baseline_schema: &Value,
        candidate_schema: &Value,
        location: &str,
    ) {
        const LOWER_BOUNDS: &[&str] = &[
            "exclusiveMinimum",
            "minContains",
            "minItems",
            "minLength",
            "minProperties",
            "minimum",
        ];
        const UPPER_BOUNDS: &[&str] = &[
            "exclusiveMaximum",
            "maxContains",
            "maxItems",
            "maxLength",
            "maxProperties",
            "maximum",
        ];

        for keyword in LOWER_BOUNDS {
            if numeric_constraint_narrowed(
                baseline_schema,
                candidate_schema,
                keyword,
                BoundDirection::HigherIsNarrower,
            ) {
                self.record(
                    BreakingChangeKind::SchemaConstraintNarrowed,
                    child_pointer(location, keyword),
                    None,
                );
            }
        }
        for keyword in UPPER_BOUNDS {
            if numeric_constraint_narrowed(
                baseline_schema,
                candidate_schema,
                keyword,
                BoundDirection::LowerIsNarrower,
            ) {
                self.record(
                    BreakingChangeKind::SchemaConstraintNarrowed,
                    child_pointer(location, keyword),
                    None,
                );
            }
        }
        if string_constraint_narrowed(baseline_schema, candidate_schema, "pattern") {
            self.record(
                BreakingChangeKind::SchemaConstraintNarrowed,
                child_pointer(location, "pattern"),
                None,
            );
        }
        if candidate_schema.get("uniqueItems").and_then(Value::as_bool) == Some(true)
            && baseline_schema.get("uniqueItems").and_then(Value::as_bool) != Some(true)
        {
            self.record(
                BreakingChangeKind::SchemaConstraintNarrowed,
                child_pointer(location, "uniqueItems"),
                None,
            );
        }
    }

    fn compare_schema_properties(
        &mut self,
        baseline_schema: &'a Value,
        candidate_schema: &'a Value,
        location: &str,
        depth: usize,
    ) -> Result<(), OpenApiDiffError> {
        let baseline_properties = baseline_schema.get("properties").and_then(Value::as_object);
        let candidate_properties = candidate_schema
            .get("properties")
            .and_then(Value::as_object);
        let properties_location = child_pointer(location, "properties");

        if let Some(baseline_properties) = baseline_properties {
            for (property, baseline_property) in baseline_properties {
                let property_location = child_pointer(&properties_location, property);
                let Some(candidate_property) =
                    candidate_properties.and_then(|properties| properties.get(property))
                else {
                    self.record(
                        BreakingChangeKind::SchemaPropertyRemoved,
                        property_location,
                        None,
                    );
                    continue;
                };
                self.compare_schema(
                    baseline_property,
                    candidate_property,
                    &property_location,
                    depth + 1,
                )?;
            }
        }

        let baseline_required = required_properties(baseline_schema);
        for property in required_properties(candidate_schema) {
            if !baseline_required.contains(property) {
                self.record(
                    BreakingChangeKind::SchemaPropertyNowRequired,
                    child_pointer(&properties_location, property),
                    None,
                );
            }
        }
        Ok(())
    }

    fn compare_nested_schemas(
        &mut self,
        baseline_schema: &'a Value,
        candidate_schema: &'a Value,
        location: &str,
        depth: usize,
    ) -> Result<(), OpenApiDiffError> {
        const SINGLE_SCHEMAS: &[&str] = &[
            "additionalProperties",
            "contains",
            "else",
            "if",
            "items",
            "not",
            "propertyNames",
            "then",
            "unevaluatedProperties",
        ];
        const SCHEMA_ARRAYS: &[&str] = &["allOf", "anyOf", "oneOf", "prefixItems"];
        const SCHEMA_MAPS: &[&str] = &["$defs", "dependentSchemas", "patternProperties"];

        for key in SINGLE_SCHEMAS {
            if let (Some(baseline_nested), Some(candidate_nested)) =
                (baseline_schema.get(*key), candidate_schema.get(*key))
                && baseline_nested.is_object()
                && candidate_nested.is_object()
            {
                self.compare_schema(
                    baseline_nested,
                    candidate_nested,
                    &child_pointer(location, key),
                    depth + 1,
                )?;
            }
        }
        for key in SCHEMA_ARRAYS {
            let baseline_values = baseline_schema.get(*key).and_then(Value::as_array);
            let candidate_values = candidate_schema.get(*key).and_then(Value::as_array);
            if let (Some(baseline_values), Some(candidate_values)) =
                (baseline_values, candidate_values)
            {
                let array_location = child_pointer(location, key);
                for (index, (baseline_nested, candidate_nested)) in
                    baseline_values.iter().zip(candidate_values).enumerate()
                {
                    self.compare_schema(
                        baseline_nested,
                        candidate_nested,
                        &child_pointer(&array_location, &index.to_string()),
                        depth + 1,
                    )?;
                }
            }
        }
        for key in SCHEMA_MAPS {
            let baseline_values = baseline_schema.get(*key).and_then(Value::as_object);
            let candidate_values = candidate_schema.get(*key).and_then(Value::as_object);
            if let (Some(baseline_values), Some(candidate_values)) =
                (baseline_values, candidate_values)
            {
                let map_location = child_pointer(location, key);
                for (name, baseline_nested) in baseline_values {
                    let Some(candidate_nested) = candidate_values.get(name) else {
                        continue;
                    };
                    self.compare_schema(
                        baseline_nested,
                        candidate_nested,
                        &child_pointer(&map_location, name),
                        depth + 1,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn consume_node(&mut self, depth: usize) -> Result<(), OpenApiDiffError> {
        if depth > MAX_DIFF_TRAVERSAL_DEPTH || self.visited_nodes >= MAX_DIFF_VISITED_NODES {
            return Err(OpenApiDiffError::TraversalLimitExceeded);
        }
        self.visited_nodes += 1;
        Ok(())
    }

    fn record(&mut self, kind: BreakingChangeKind, location: String, operation_id: Option<&str>) {
        self.changes.insert(BreakingChange {
            kind,
            location,
            operation_id: operation_id.map(str::to_owned),
        });
    }
}

fn resolve_compared_reference<'a>(
    value: &'a Value,
    root: &'a Value,
) -> Result<&'a Value, OpenApiDiffError> {
    resolve_reference(value, root).map_err(|_| OpenApiDiffError::TraversalLimitExceeded)
}

fn collect_effective_parameters<'a>(
    path_item: &'a Value,
    operation: &'a Value,
    root: &'a Value,
) -> Result<BTreeMap<(&'a str, &'a str), &'a Value>, OpenApiDiffError> {
    let mut parameters = BTreeMap::new();
    extend_parameters(&mut parameters, path_item, root)?;
    extend_parameters(&mut parameters, operation, root)?;
    Ok(parameters)
}

fn extend_parameters<'a>(
    parameters: &mut BTreeMap<(&'a str, &'a str), &'a Value>,
    owner: &'a Value,
    root: &'a Value,
) -> Result<(), OpenApiDiffError> {
    let Some(declared) = owner.get("parameters").and_then(Value::as_array) else {
        return Ok(());
    };
    for parameter in declared {
        let parameter = resolve_compared_reference(parameter, root)?;
        let Some(name) = parameter.get("name").and_then(Value::as_str) else {
            continue;
        };
        let Some(parameter_in) = parameter.get("in").and_then(Value::as_str) else {
            continue;
        };
        parameters.insert((parameter_in, name), parameter);
    }
    Ok(())
}

fn parameter_location(operation: &str, parameter_in: &str, name: &str) -> String {
    child_pointer(
        &child_pointer(&child_pointer(operation, "parameters"), parameter_in),
        name,
    )
}

fn is_required(value: &Value) -> bool {
    value
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn required_properties(schema: &Value) -> BTreeSet<&str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect()
}

#[derive(Clone, Copy)]
enum BoundDirection {
    HigherIsNarrower,
    LowerIsNarrower,
}

fn numeric_constraint_narrowed(
    baseline: &Value,
    candidate: &Value,
    keyword: &str,
    direction: BoundDirection,
) -> bool {
    let candidate = candidate.get(keyword);
    let Some(candidate) = candidate else {
        return false;
    };
    let Some(baseline) = baseline.get(keyword) else {
        return candidate.is_number();
    };
    if baseline == candidate {
        return false;
    }
    let (Some(baseline), Some(candidate)) = (baseline.as_f64(), candidate.as_f64()) else {
        return true;
    };
    match direction {
        BoundDirection::HigherIsNarrower => candidate > baseline,
        BoundDirection::LowerIsNarrower => candidate < baseline,
    }
}

fn string_constraint_narrowed(baseline: &Value, candidate: &Value, keyword: &str) -> bool {
    let Some(candidate) = candidate.get(keyword).and_then(Value::as_str) else {
        return false;
    };
    baseline.get(keyword).and_then(Value::as_str) != Some(candidate)
}

fn schema_types(schema: &Value) -> Option<BTreeSet<&str>> {
    match schema.get("type") {
        Some(Value::String(schema_type)) => Some(BTreeSet::from([schema_type.as_str()])),
        Some(Value::Array(schema_types)) => {
            Some(schema_types.iter().filter_map(Value::as_str).collect())
        }
        None | Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_)) => None,
    }
}

fn schema_type_changed(baseline: &Value, candidate: &Value) -> bool {
    schema_types(baseline) != schema_types(candidate)
}

fn schema_format_changed(baseline: &Value, candidate: &Value) -> bool {
    baseline.get("format").and_then(Value::as_str)
        != candidate.get("format").and_then(Value::as_str)
}

fn schema_enum_narrowed(baseline: &Value, candidate: &Value) -> bool {
    let baseline = baseline.get("enum").and_then(Value::as_array);
    let candidate = candidate.get("enum").and_then(Value::as_array);
    match (baseline, candidate) {
        (_, None) => false,
        (None, Some(_)) => true,
        (Some(baseline), Some(candidate)) => {
            let candidate: HashSet<_> = candidate.iter().collect();
            baseline.iter().any(|value| !candidate.contains(value))
        }
    }
}

fn security_is_stricter(baseline: &[Value], candidate: &[Value]) -> bool {
    if candidate.is_empty() {
        return false;
    }
    if baseline.is_empty() {
        return !candidate.iter().any(security_requirement_is_anonymous);
    }
    baseline.iter().any(|baseline_requirement| {
        !candidate.iter().any(|candidate_requirement| {
            security_requirement_no_stricter(candidate_requirement, baseline_requirement)
        })
    })
}

fn security_requirement_is_anonymous(requirement: &Value) -> bool {
    requirement
        .as_object()
        .is_some_and(serde_json::Map::is_empty)
}

fn security_requirement_no_stricter(candidate: &Value, baseline: &Value) -> bool {
    let (Some(candidate), Some(baseline)) = (candidate.as_object(), baseline.as_object()) else {
        return false;
    };
    candidate.iter().all(|(scheme, candidate_scopes)| {
        let Some(baseline_scopes) = baseline.get(scheme).and_then(Value::as_array) else {
            return false;
        };
        let Some(candidate_scopes) = candidate_scopes.as_array() else {
            return false;
        };
        candidate_scopes
            .iter()
            .all(|scope| baseline_scopes.contains(scope))
    })
}

fn child_pointer(parent: &str, segment: &str) -> String {
    let mut pointer = String::with_capacity(parent.len() + segment.len() + 1);
    pointer.push_str(parent);
    pointer.push('/');
    for character in segment.chars() {
        match character {
            '~' => pointer.push_str("~0"),
            '/' => pointer.push_str("~1"),
            _ => pointer.push(character),
        }
    }
    pointer
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "test setup and request failures must stop the test immediately"
)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt as _;
    use utoipa::OpenApi as _;

    use super::*;

    #[expect(dead_code, reason = "utoipa consumes the function metadata")]
    #[utoipa::path(
        get,
        path = "/widgets",
        operation_id = "listWidgets",
        tag = "widgets",
        security(("bearer_auth" = [])),
        responses(
            (status = 200, description = "widgets", body = [String]),
            (
                status = 400,
                description = "invalid request",
                body = ProblemDetailsFixture,
                content_type = "application/problem+json"
            )
        )
    )]
    fn list_widgets() {}

    #[derive(serde::Serialize, utoipa::ToSchema)]
    struct ProblemDetailsFixture {
        r#type: String,
        title: String,
        status: u16,
        code: String,
        request_id: String,
    }

    struct SecurityAddon;

    impl utoipa::Modify for SecurityAddon {
        fn modify(&self, openapi: &mut OpenApiDocument) {
            use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

            let components = openapi.components.get_or_insert_default();
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(HttpBuilder::new().scheme(HttpAuthScheme::Bearer).build()),
            );
        }
    }

    #[derive(utoipa::OpenApi)]
    #[openapi(
        paths(list_widgets),
        components(schemas(ProblemDetailsFixture)),
        modifiers(&SecurityAddon)
    )]
    struct ValidApi;

    fn mutated_document(
        mutator: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> OpenApiDocument {
        let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        let operation = value
            .pointer_mut("/paths/~1widgets/get")
            .and_then(Value::as_object_mut)
            .expect("generated GET operation");
        mutator(operation);
        serde_json::from_value(value).expect("mutated document remains structurally valid")
    }

    fn diff_document() -> Value {
        serde_json::to_value(ValidApi::openapi()).expect("valid diff document")
    }

    fn operation_mut(document: &mut Value) -> &mut serde_json::Map<String, Value> {
        document
            .pointer_mut("/paths/~1widgets/get")
            .and_then(Value::as_object_mut)
            .expect("generated GET operation")
    }

    fn problem_schema_mut(document: &mut Value) -> &mut serde_json::Map<String, Value> {
        document
            .pointer_mut("/components/schemas/ProblemDetailsFixture")
            .and_then(Value::as_object_mut)
            .expect("generated problem schema")
    }

    fn diff_bytes(document: &Value) -> Vec<u8> {
        serde_json::to_vec(document).expect("diff fixture serialization")
    }

    fn compare_values(
        baseline: &Value,
        candidate: &Value,
    ) -> Result<Vec<BreakingChange>, OpenApiDiffError> {
        breaking_changes(&diff_bytes(baseline), &diff_bytes(candidate))
    }

    fn change_kinds(changes: &[BreakingChange]) -> Vec<BreakingChangeKind> {
        changes.iter().map(BreakingChange::kind).collect()
    }

    fn add_request_body(operation: &mut serde_json::Map<String, Value>, required: bool) {
        operation.insert(
            "requestBody".to_owned(),
            json!({
                "required": required,
                "content": {
                    "application/json": {"schema": {"type": "string"}},
                    "application/xml": {"schema": {"type": "string"}}
                }
            }),
        );
    }

    fn add_schema_property(document: &mut Value, name: &str, schema: Value) {
        problem_schema_mut(document)
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .expect("problem properties")
            .insert(name.to_owned(), schema);
    }

    #[test]
    fn breaking_changes_reports_removed_path() {
        let mut baseline = diff_document();
        let mut added_path = baseline
            .pointer("/paths/~1widgets")
            .cloned()
            .expect("widget path");
        added_path["get"]["operationId"] = json!("listGadgets");
        baseline
            .get_mut("paths")
            .and_then(Value::as_object_mut)
            .expect("paths")
            .insert("/gadgets".to_owned(), added_path);
        let mut candidate = baseline.clone();
        candidate
            .get_mut("paths")
            .and_then(Value::as_object_mut)
            .expect("paths")
            .remove("/gadgets");

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::PathRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_method() {
        let mut baseline = diff_document();
        let mut post = baseline
            .pointer("/paths/~1widgets/get")
            .cloned()
            .expect("GET operation");
        post["operationId"] = json!("createWidget");
        baseline
            .pointer_mut("/paths/~1widgets")
            .and_then(Value::as_object_mut)
            .expect("widget path")
            .insert("post".to_owned(), post);
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::MethodRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_request_media_type() {
        let mut baseline = diff_document();
        add_request_body(operation_mut(&mut baseline), false);
        let mut candidate = baseline.clone();
        operation_mut(&mut candidate)["requestBody"]["content"]
            .as_object_mut()
            .expect("request content")
            .remove("application/xml");

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::RequestMediaTypeRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_response_status() {
        let mut baseline = diff_document();
        let success = operation_mut(&mut baseline)["responses"]["200"].clone();
        operation_mut(&mut baseline)["responses"]
            .as_object_mut()
            .expect("responses")
            .insert("201".to_owned(), success);
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::ResponseStatusRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_response_media_type() {
        let mut baseline = diff_document();
        let json_media =
            operation_mut(&mut baseline)["responses"]["200"]["content"]["application/json"].clone();
        operation_mut(&mut baseline)["responses"]["200"]["content"]
            .as_object_mut()
            .expect("response content")
            .insert("application/xml".to_owned(), json_media);
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::ResponseMediaTypeRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_parameter() {
        let mut baseline = diff_document();
        operation_mut(&mut baseline).insert(
            "parameters".to_owned(),
            json!([{
                "name": "filter",
                "in": "query",
                "required": false,
                "schema": {"type": "string"}
            }]),
        );
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::ParameterRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_new_required_parameter() {
        let baseline = diff_document();
        let mut candidate = diff_document();
        operation_mut(&mut candidate).insert(
            "parameters".to_owned(),
            json!([{
                "name": "filter",
                "in": "query",
                "required": true,
                "schema": {"type": "string"}
            }]),
        );

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::ParameterNowRequired]
        );
    }

    #[test]
    fn breaking_changes_reports_request_body_becoming_required() {
        let mut baseline = diff_document();
        add_request_body(operation_mut(&mut baseline), false);
        let mut candidate = baseline.clone();
        operation_mut(&mut candidate)["requestBody"]["required"] = json!(true);

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::RequestBodyNowRequired]
        );
    }

    #[test]
    fn breaking_changes_reports_removed_schema_property() {
        let mut baseline = diff_document();
        add_schema_property(&mut baseline, "nickname", json!({"type": "string"}));
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::SchemaPropertyRemoved]
        );
    }

    #[test]
    fn breaking_changes_reports_schema_property_becoming_required() {
        let mut baseline = diff_document();
        add_schema_property(&mut baseline, "nickname", json!({"type": "string"}));
        let mut candidate = baseline.clone();
        problem_schema_mut(&mut candidate)
            .get_mut("required")
            .and_then(Value::as_array_mut)
            .expect("required properties")
            .push(json!("nickname"));

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::SchemaPropertyNowRequired]
        );
    }

    #[test]
    fn breaking_changes_reports_schema_type_narrowing() {
        let mut baseline = diff_document();
        add_schema_property(
            &mut baseline,
            "nickname",
            json!({"type": ["string", "null"]}),
        );
        let mut candidate = baseline.clone();
        problem_schema_mut(&mut candidate)["properties"]["nickname"]["type"] = json!("string");

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::SchemaTypeChanged]
        );
    }

    #[test]
    fn breaking_changes_reports_schema_format_change() {
        let mut baseline = diff_document();
        add_schema_property(
            &mut baseline,
            "external_id",
            json!({"type": "string", "format": "uuid"}),
        );
        let mut candidate = baseline.clone();
        problem_schema_mut(&mut candidate)["properties"]["external_id"]["format"] =
            json!("date-time");

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::SchemaFormatChanged]
        );
    }

    #[test]
    fn breaking_changes_reports_tightened_schema_constraints() {
        let cases = [
            ("minLength", Some(json!(1)), json!(2)),
            ("maxLength", Some(json!(100)), json!(50)),
            ("pattern", Some(json!("^.*$")), json!("^[a-z]+$")),
            ("minimum", Some(json!(0)), json!(1)),
            ("maximum", Some(json!(100)), json!(99)),
            ("minItems", Some(json!(0)), json!(1)),
            ("maxItems", Some(json!(100)), json!(50)),
            ("minProperties", None, json!(1)),
            ("uniqueItems", Some(json!(false)), json!(true)),
        ];

        for (keyword, baseline_constraint, candidate_constraint) in cases {
            let mut schema = match keyword {
                "minItems" | "maxItems" | "uniqueItems" => {
                    json!({"type": "array", "items": {"type": "string"}})
                }
                "minProperties" => json!({"type": "object"}),
                "minimum" | "maximum" => json!({"type": "number"}),
                _ => json!({"type": "string"}),
            };
            if let Some(constraint) = baseline_constraint {
                schema[keyword] = constraint;
            }
            let mut baseline = diff_document();
            add_schema_property(&mut baseline, "constrained", schema);
            let mut candidate = baseline.clone();
            problem_schema_mut(&mut candidate)["properties"]["constrained"][keyword] =
                candidate_constraint;

            let changes = compare_values(&baseline, &candidate).expect("valid comparison");

            assert_eq!(
                change_kinds(&changes),
                vec![BreakingChangeKind::SchemaConstraintNarrowed],
                "constraint {keyword} was not classified as narrowing"
            );
            assert!(
                changes[0].location().ends_with(&format!("/{keyword}")),
                "constraint finding did not identify {keyword}"
            );
        }
    }

    #[test]
    fn breaking_changes_accepts_relaxed_schema_constraints() {
        let mut baseline = diff_document();
        add_schema_property(
            &mut baseline,
            "constrained",
            json!({
                "type": "string",
                "minLength": 2,
                "maxLength": 50,
                "pattern": "^[a-z]+$",
                "uniqueItems": true
            }),
        );
        let mut candidate = baseline.clone();
        let schema = &mut problem_schema_mut(&mut candidate)["properties"]["constrained"];
        schema["minLength"] = json!(1);
        schema["maxLength"] = json!(100);
        schema
            .as_object_mut()
            .expect("constraint schema")
            .remove("pattern");
        schema["uniqueItems"] = json!(false);

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert!(changes.is_empty());
    }

    #[test]
    fn breaking_changes_are_sorted_deduplicated_deterministic_and_value_free() {
        let mut baseline = diff_document();
        add_schema_property(
            &mut baseline,
            "choice",
            json!({
                "type": ["string", "null"],
                "enum": ["SAFE_CHOICE", "DO_NOT_ECHO_SECRET_CHOICE"],
                "default": "DO_NOT_ECHO_SECRET_DEFAULT",
                "example": "DO_NOT_ECHO_SECRET_EXAMPLE"
            }),
        );
        let mut candidate = baseline.clone();
        problem_schema_mut(&mut candidate)["properties"]["choice"]["enum"] = json!(["SAFE_CHOICE"]);
        problem_schema_mut(&mut candidate)["properties"]["choice"]["format"] = json!("uuid");
        problem_schema_mut(&mut candidate)["properties"]["choice"]["type"] = json!("string");
        let required = problem_schema_mut(&mut candidate)
            .get_mut("required")
            .and_then(Value::as_array_mut)
            .expect("required properties");
        required.push(json!("choice"));
        required.push(json!("choice"));

        let first = compare_values(&baseline, &candidate).expect("first comparison");
        let second = compare_values(&baseline, &candidate).expect("second comparison");
        let diagnostics = format!("{first:?}");

        assert!(
            first == second
                && change_kinds(&first)
                    == vec![
                        BreakingChangeKind::SchemaPropertyNowRequired,
                        BreakingChangeKind::SchemaTypeChanged,
                        BreakingChangeKind::SchemaFormatChanged,
                        BreakingChangeKind::EnumNarrowed,
                    ]
                && first.windows(2).all(|pair| pair[0] < pair[1])
                && !diagnostics.contains("DO_NOT_ECHO")
        );
    }

    #[test]
    fn breaking_changes_reports_stricter_security() {
        let mut baseline = diff_document();
        operation_mut(&mut baseline).insert("security".to_owned(), json!([]));
        let candidate = diff_document();

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            change_kinds(&changes),
            vec![BreakingChangeKind::SecurityRequirementsStrengthened]
        );
    }

    #[test]
    fn breaking_changes_accepts_additive_contract_changes() {
        let mut baseline = diff_document();
        add_request_body(operation_mut(&mut baseline), false);
        add_schema_property(
            &mut baseline,
            "choice",
            json!({"type": "string", "enum": ["one"]}),
        );
        let mut candidate = baseline.clone();
        add_schema_property(&mut candidate, "optional_note", json!({"type": "string"}));
        problem_schema_mut(&mut candidate)["properties"]["choice"]["enum"] = json!(["one", "two"]);
        operation_mut(&mut candidate)
            .entry("parameters")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .expect("parameters")
            .push(json!({
                "name": "filter",
                "in": "query",
                "required": false,
                "schema": {"type": "string"}
            }));
        let success = operation_mut(&mut candidate)["responses"]["200"].clone();
        operation_mut(&mut candidate)["responses"]
            .as_object_mut()
            .expect("responses")
            .insert("201".to_owned(), success);
        operation_mut(&mut candidate)
            .insert("security".to_owned(), json!([{"bearer_auth": []}, {}]));

        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert!(changes.is_empty(), "unexpected changes: {changes:?}");
    }

    #[test]
    fn breaking_changes_accepts_json_schema_union_types() {
        let mut contract = diff_document();
        add_schema_property(
            &mut contract,
            "nullable_note",
            json!({"type": ["string", "null"]}),
        );
        let contract = diff_bytes(&contract);

        let changes =
            breaking_changes(&contract, &contract).expect("OpenAPI 3.1 union type is comparable");

        assert!(changes.is_empty());
    }

    #[test]
    fn breaking_changes_returns_value_free_malformed_error() {
        let candidate = diff_bytes(&diff_document());
        let error = breaking_changes(b"{\"secret\":\"DO_NOT_ECHO\"", &candidate)
            .expect_err("malformed baseline");

        assert!(
            error == OpenApiDiffError::BaselineMalformed
                && !format!("{error:?}").contains("DO_NOT_ECHO")
        );
    }

    #[test]
    fn breaking_changes_returns_value_free_policy_error() {
        let baseline = diff_document();
        let mut candidate = diff_document();
        operation_mut(&mut candidate).remove("security");
        operation_mut(&mut candidate).insert(
            "description".to_owned(),
            json!("DO_NOT_ECHO_SECRET_DESCRIPTION"),
        );

        let error = compare_values(&baseline, &candidate).expect_err("policy-invalid candidate");

        assert!(
            error == OpenApiDiffError::CandidatePolicy(OpenApiError::MissingSecurity)
                && !format!("{error:?}").contains("DO_NOT_ECHO")
        );
    }

    #[test]
    fn breaking_change_display_is_actionable_and_value_free() {
        let mut baseline = diff_document();
        let mut post = baseline
            .pointer("/paths/~1widgets/get")
            .cloned()
            .expect("GET operation");
        post["operationId"] = json!("createWidget");
        baseline
            .pointer_mut("/paths/~1widgets")
            .and_then(Value::as_object_mut)
            .expect("widget path")
            .insert("post".to_owned(), post);
        let candidate = diff_document();
        let changes = compare_values(&baseline, &candidate).expect("valid comparison");

        assert_eq!(
            changes[0].to_string(),
            "method removed at /paths/~1widgets/post (operationId: createWidget)"
        );
    }

    #[test]
    fn breaking_changes_rejects_documents_exceeding_traversal_depth() {
        let mut baseline = diff_document();
        let mut nested = json!({"type": "string"});
        for _ in 0..=MAX_DIFF_TRAVERSAL_DEPTH {
            nested = json!({"type": "array", "items": nested});
        }
        add_schema_property(&mut baseline, "deep", nested);
        let candidate = baseline.clone();

        let error = compare_values(&baseline, &candidate).expect_err("bounded traversal");

        assert_eq!(error, OpenApiDiffError::TraversalLimitExceeded);
    }

    #[test]
    fn validate_document_accepts_complete_generated_contract() {
        let result = validate_document(&ValidApi::openapi());

        assert!(result.is_ok(), "unexpected policy failure: {result:?}");
    }

    #[test]
    fn json_value_catalog_preserves_external_contract_schemas_deterministically() {
        let mut document = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        document
            .pointer_mut("/components/schemas")
            .and_then(Value::as_object_mut)
            .expect("generated schemas")
            .insert(
                "CanonicalExternalContract".to_owned(),
                json!({
                    "type": "object",
                    "properties": {"state": {"type": "string"}},
                    "required": ["state"]
                }),
            );

        let first = deterministic_json_value(document.clone()).expect("canonical external schema");
        let second = deterministic_json_value(document.clone()).expect("deterministic schema");
        let catalog = OpenApiCatalog::try_from_value(document, OpenApiConfig::default())
            .expect("value catalog");

        assert!(first == second && first == catalog.json_bytes());
    }

    #[test]
    fn json_value_coverage_uses_the_same_closed_route_registry() {
        let mut document = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        let expected = [ExpectedOperation::new(
            "get",
            "/widgets",
            "listWidgets",
            "widgets",
        )];
        document
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("generated paths")
            .insert("x-catalog".to_owned(), json!("metadata"));

        assert!(validate_operation_coverage_value(&document, &expected).is_ok());
    }

    #[test]
    fn validate_document_ignores_paths_extensions() {
        let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        value
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("generated paths")
            .insert("x-catalog".to_owned(), json!("metadata"));
        let result = validate_value(&value);

        assert!(result.is_ok(), "unexpected policy failure: {result:?}");
    }

    #[test]
    fn validate_document_rejects_missing_operation_id() {
        let document = mutated_document(|operation| {
            operation.remove("operationId");
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingOperationId)
        );
    }

    #[test]
    fn validate_document_rejects_missing_responses() {
        let document = mutated_document(|operation| {
            operation.insert("responses".to_owned(), json!({}));
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingResponses)
        );
    }

    #[test]
    fn validate_document_rejects_missing_problem_details_error_response() {
        let document = mutated_document(|operation| {
            operation.insert(
                "responses".to_owned(),
                json!({"200": {"description": "widgets"}}),
            );
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingProblemDetailsResponse)
        );
    }

    #[test]
    fn validate_document_rejects_problem_media_with_string_schema() {
        let document = mutated_document(|operation| {
            let media = operation
                .get_mut("responses")
                .and_then(|responses| responses.get_mut("400"))
                .and_then(|response| response.get_mut("content"))
                .and_then(|content| content.get_mut("application/problem+json"))
                .and_then(Value::as_object_mut)
                .expect("generated problem media");
            media.insert("schema".to_owned(), json!({"type": "string"}));
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingProblemDetailsResponse)
        );
    }

    #[test]
    fn validate_document_rejects_problem_media_without_schema() {
        let document = mutated_document(|operation| {
            let media = operation
                .get_mut("responses")
                .and_then(|responses| responses.get_mut("400"))
                .and_then(|response| response.get_mut("content"))
                .and_then(|content| content.get_mut("application/problem+json"))
                .and_then(Value::as_object_mut)
                .expect("generated problem media");
            media.remove("schema");
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingProblemDetailsResponse)
        );
    }

    #[test]
    fn validate_document_rejects_empty_operation_id() {
        let document = mutated_document(|operation| {
            operation.insert("operationId".to_owned(), json!(" "));
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingOperationId)
        );
    }

    #[test]
    fn validate_document_rejects_missing_explicit_security() {
        let document = mutated_document(|operation| {
            operation.remove("security");
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::MissingSecurity)
        );
    }

    #[test]
    fn validate_document_accepts_explicit_anonymous_security() {
        let document = mutated_document(|operation| {
            operation.insert("security".to_owned(), json!([]));
        });
        let result = validate_document(&document);

        assert!(result.is_ok(), "unexpected policy failure: {result:?}");
    }

    #[test]
    fn validate_document_rejects_duplicate_operation_id() {
        let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        let duplicate = value
            .pointer("/paths/~1widgets/get")
            .cloned()
            .expect("generated GET operation");
        value
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("generated paths")
            .insert("/other".to_owned(), json!({"get": duplicate}));
        let document = serde_json::from_value(value).expect("duplicate document is structural");

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::DuplicateOperationId)
        );
    }

    #[test]
    fn validate_document_rejects_undefined_security_scheme() {
        let document = mutated_document(|operation| {
            operation.insert("security".to_owned(), json!([{"missing_scheme": []}]));
        });

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::UndefinedSecurityScheme)
        );
    }

    #[test]
    fn validate_document_rejects_document_without_operations() {
        let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        value["paths"] = json!({});
        let document = serde_json::from_value(value).expect("empty paths document is structural");

        assert_eq!(
            validate_document(&document),
            Err(OpenApiError::NoOperations)
        );
    }

    #[test]
    fn validate_document_rejects_unresolved_path_item_reference() {
        let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
        value
            .pointer_mut("/paths")
            .and_then(Value::as_object_mut)
            .expect("generated paths")
            .insert(
                "/referenced".to_owned(),
                json!({"$ref": "#/components/pathItems/missing"}),
            );
        assert_eq!(validate_value(&value), Err(OpenApiError::InvalidReference));
    }

    #[test]
    fn operation_coverage_requires_exact_route_id_and_capability_tag() {
        let document = ValidApi::openapi();
        let expected = [ExpectedOperation::new(
            "get",
            "/widgets",
            "listWidgets",
            "widgets",
        )];

        assert_eq!(validate_operation_coverage(&document, &expected), Ok(()));
        assert_eq!(
            validate_operation_coverage(
                &document,
                &[ExpectedOperation::new(
                    "get",
                    "/widgets",
                    "renamedWidgets",
                    "widgets",
                )],
            ),
            Err(OpenApiError::OperationCoverageMismatch)
        );
        assert_eq!(
            validate_operation_coverage(&document, &[]),
            Err(OpenApiError::OperationCoverageMismatch)
        );
    }

    #[test]
    fn deterministic_json_returns_identical_bytes_across_generations() {
        let first = deterministic_json(&ValidApi::openapi()).expect("first generation");
        let second = deterministic_json(&ValidApi::openapi()).expect("second generation");

        assert_eq!(first, second);
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let result = serde_json::from_value::<OpenApiConfig>(json!({"unknown": true}));

        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_zero_document_size_limit() {
        let result = OpenApiConfig {
            max_document_bytes: 0,
            ..OpenApiConfig::default()
        }
        .validate();

        assert_eq!(result, Err(OpenApiError::InvalidDocumentSizeLimit));
    }

    #[test]
    fn config_rejects_document_size_limit_above_hard_maximum() {
        let result = OpenApiConfig {
            max_document_bytes: MAX_DOCUMENT_BYTES + 1,
            ..OpenApiConfig::default()
        }
        .validate();

        assert_eq!(result, Err(OpenApiError::InvalidDocumentSizeLimit));
    }

    #[test]
    fn catalog_rejects_document_exceeding_configured_limit() {
        let result = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            max_document_bytes: 1,
            ..OpenApiConfig::default()
        });

        assert!(matches!(result, Err(OpenApiError::DocumentTooLarge)));
    }

    #[tokio::test]
    async fn router_omits_disabled_document_route_while_docs_remain_enabled() {
        let catalog = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            document_route_enabled: false,
            docs_route_enabled: true,
            ..OpenApiConfig::default()
        })
        .expect("valid catalog");
        let response = catalog
            .router()
            .oneshot(
                Request::builder()
                    .uri(OPENAPI_DOCUMENT_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_serves_docs_when_document_route_is_disabled() {
        let catalog = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            document_route_enabled: false,
            docs_route_enabled: true,
            ..OpenApiConfig::default()
        })
        .expect("valid catalog");
        let response = catalog
            .router()
            .oneshot(
                Request::builder()
                    .uri(format!("{OPENAPI_DOCS_PATH}/swagger-ui.css"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn docs_only_router_serves_its_canonical_backing_document() {
        let catalog = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            document_route_enabled: false,
            docs_route_enabled: true,
            ..OpenApiConfig::default()
        })
        .expect("valid catalog");
        let expected = catalog.json_bytes().to_owned();
        let response = catalog
            .router()
            .oneshot(
                Request::builder()
                    .uri("/docs/openapi.json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), DEFAULT_MAX_DOCUMENT_BYTES)
            .await
            .expect("document body");

        assert_eq!(body.as_ref(), expected);
    }

    #[tokio::test]
    async fn router_serves_canonical_document_when_docs_are_disabled() {
        let catalog = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            document_route_enabled: true,
            docs_route_enabled: false,
            ..OpenApiConfig::default()
        })
        .expect("valid catalog");
        let expected = catalog.json_bytes().to_owned();
        let response = catalog
            .router()
            .oneshot(
                Request::builder()
                    .uri(OPENAPI_DOCUMENT_PATH)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let body = axum::body::to_bytes(response.into_body(), DEFAULT_MAX_DOCUMENT_BYTES)
            .await
            .expect("document body");

        assert_eq!(body.as_ref(), expected);
    }

    #[tokio::test]
    async fn router_omits_disabled_docs_route_while_document_remains_enabled() {
        let catalog = OpenApiCatalog::from_generator::<ValidApi>(OpenApiConfig {
            document_route_enabled: true,
            docs_route_enabled: false,
            ..OpenApiConfig::default()
        })
        .expect("valid catalog");
        let response = catalog
            .router()
            .oneshot(
                Request::builder()
                    .uri(format!("{OPENAPI_DOCS_PATH}/swagger-ui.css"))
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
