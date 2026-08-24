//! Deterministic `OpenAPI` 3.1 policy validation and locally served catalog routes.

use std::{collections::BTreeSet, fmt};

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
        let config = config.validate()?;
        let json = prepare_document(document)?;
        if json.len() > config.max_document_bytes {
            return Err(OpenApiError::DocumentTooLarge);
        }
        let document_size = u32::try_from(json.len()).unwrap_or(u32::MAX);
        metrics::counter!("rsk_openapi_builds_total").increment(1);
        metrics::histogram!("rsk_openapi_document_size_bytes").record(document_size);
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
    validate_value(&value)
}

/// Produces canonical, key-sorted JSON after validating document policy.
///
/// # Errors
///
/// Returns [`OpenApiError`] if policy validation or serialization fails.
pub fn deterministic_json(document: &OpenApiDocument) -> Result<Vec<u8>, OpenApiError> {
    prepare_document(document)
}

fn prepare_document(document: &OpenApiDocument) -> Result<Vec<u8>, OpenApiError> {
    let mut value =
        serde_json::to_value(document).map_err(|_| OpenApiError::SerializationFailed)?;
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

    #[test]
    fn validate_document_accepts_complete_generated_contract() {
        let result = validate_document(&ValidApi::openapi());

        assert!(result.is_ok(), "unexpected policy failure: {result:?}");
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
