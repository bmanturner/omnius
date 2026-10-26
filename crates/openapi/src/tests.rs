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

fn mutated_document(mutator: impl FnOnce(&mut serde_json::Map<String, Value>)) -> OpenApiDocument {
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
    problem_schema_mut(&mut candidate)["properties"]["external_id"]["format"] = json!("date-time");

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
    operation_mut(&mut candidate).insert("security".to_owned(), json!([{"bearer_auth": []}, {}]));

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
    let catalog =
        OpenApiCatalog::try_from_value(document, OpenApiConfig::default()).expect("value catalog");

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
fn validate_document_accepts_document_without_operations() {
    let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
    value["paths"] = json!({});
    let document = serde_json::from_value(value).expect("empty paths document is structural");

    assert_eq!(validate_document(&document), Ok(()));
}

#[test]
fn validate_value_requires_paths_object() {
    let mut value = serde_json::to_value(ValidApi::openapi()).expect("valid document JSON");
    value.as_object_mut().expect("root object").remove("paths");

    assert_eq!(validate_value(&value), Err(OpenApiError::NoOperations));
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
fn expected_operation_reexport_is_the_http_owned_type() {
    let operation: omnius_http::ExpectedOperation =
        ExpectedOperation::new("get", "/widgets", "listWidgets", "widgets");

    assert_eq!(operation.operation_id, "listWidgets");
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
