//! Contract tests for bounded transport validation.

use std::error::Error;

use garde::Validate;
use rsk_validation::{
    BoundaryValidator, FakeBoundaryValidator, FieldPath, GardeBoundaryValidator, JsonPayloadError,
    JsonSchemaAdapter, JsonStructureError, JsonValidationLimits, SchemaAdapterError,
    ValidationCode, ValidationErrors, ValidationIssue, validate_garde,
};
use serde::Deserialize;

#[derive(Deserialize, Validate)]
#[serde(deny_unknown_fields)]
struct LoginPayload {
    #[garde(ascii, length(min = 3, max = 32))]
    username: String,
    #[garde(length(min = 12, max = 128))]
    password: String,
}

#[test]
fn garde_adapter_returns_sorted_problem_safe_field_errors() -> Result<(), Box<dyn Error>> {
    let payload = LoginPayload {
        username: "x".to_owned(),
        password: "secret".to_owned(),
    };

    let errors = validate_garde(payload)
        .err()
        .ok_or_else(|| std::io::Error::other("invalid payload unexpectedly accepted"))?;
    let wire = serde_json::to_string(&errors.to_problem_field_errors()?)?;

    assert_eq!(
        wire,
        concat!(
            "[{\"pointer\":\"/password\",\"code\":\"invalid\",",
            "\"message\":\"value does not satisfy boundary constraints\"},",
            "{\"pointer\":\"/username\",\"code\":\"invalid\",",
            "\"message\":\"value does not satisfy boundary constraints\"}]"
        )
    );
    Ok(())
}

#[test]
fn garde_adapter_never_echoes_rejected_values() -> Result<(), Box<dyn Error>> {
    let payload = LoginPayload {
        username: "private-user-name-that-is-far-too-long".to_owned(),
        password: "s3cr3t".to_owned(),
    };
    let errors = validate_garde(payload)
        .err()
        .ok_or_else(|| std::io::Error::other("invalid payload unexpectedly accepted"))?;

    let wire = serde_json::to_string(&errors.to_problem_field_errors()?)?;

    assert!(!wire.contains("private-user-name-that-is-far-too-long") && !wire.contains("s3cr3t"));
    Ok(())
}

#[test]
fn typed_paths_escape_json_pointer_components() -> Result<(), Box<dyn Error>> {
    let mut path = FieldPath::root();
    path.try_push_property("items/by~id")?;
    path.try_push_index(7)?;

    assert_eq!(path.to_json_pointer(), "/items~1by~0id/7");
    Ok(())
}

#[test]
fn schema_adapter_rejects_non_local_references() {
    let result = JsonSchemaAdapter::compile(
        br#"{"$ref":"https://schemas.example.invalid/private.json"}"#,
        JsonValidationLimits::default(),
    );

    assert!(matches!(result, Err(SchemaAdapterError::NonLocalReference)));
}

#[test]
fn schema_adapter_enforces_payload_byte_bound_before_decoding() -> Result<(), Box<dyn Error>> {
    let limits = JsonValidationLimits {
        max_payload_bytes: 3,
        ..JsonValidationLimits::default()
    };
    let adapter = JsonSchemaAdapter::compile(b"true", limits)?;

    assert!(matches!(
        adapter.validate_bytes(br#"{"a":1}"#),
        Err(JsonPayloadError::TooLarge)
    ));
    Ok(())
}

#[test]
fn schema_adapter_enforces_node_bound_before_queueing_children() -> Result<(), Box<dyn Error>> {
    let limits = JsonValidationLimits {
        max_nodes: 1,
        ..JsonValidationLimits::default()
    };
    let adapter = JsonSchemaAdapter::compile(b"true", limits)?;

    assert!(matches!(
        adapter.validate_bytes(b"[1,2]"),
        Err(JsonPayloadError::Structure(
            JsonStructureError::TooManyNodes
        ))
    ));
    Ok(())
}

#[test]
fn schema_adapter_addresses_each_unexpected_property() -> Result<(), Box<dyn Error>> {
    let adapter = JsonSchemaAdapter::compile(
        br#"{"type":"object","additionalProperties":false}"#,
        JsonValidationLimits::default(),
    )?;
    let error = adapter
        .validate_bytes(br#"{"zeta":1,"alpha":2}"#)
        .err()
        .ok_or_else(|| std::io::Error::other("unexpected properties were accepted"))?;
    let JsonPayloadError::Validation(errors) = error else {
        return Err(std::io::Error::other("unexpected bounded payload error").into());
    };

    let wire = serde_json::to_string(&errors.to_problem_field_errors()?)?;

    assert!(
        wire.contains("\"/alpha\"") && wire.contains("\"/zeta\""),
        "unexpected property paths: {wire}"
    );
    Ok(())
}

#[test]
fn schema_adapter_returns_value_free_typed_failures() -> Result<(), Box<dyn Error>> {
    let schema = br#"
    {
      "type": "object",
      "additionalProperties": false,
      "required": ["password"],
      "properties": {
        "password": {"type": "string", "minLength": 16},
        "attempts": {"type": "integer", "maximum": 3}
      }
    }
    "#;
    let adapter = JsonSchemaAdapter::compile(schema, JsonValidationLimits::default())?;
    let error = adapter
        .validate_bytes(br#"{"password":"do-not-echo","attempts":9}"#)
        .err()
        .ok_or_else(|| std::io::Error::other("invalid payload unexpectedly accepted"))?;
    let JsonPayloadError::Validation(errors) = error else {
        return Err(std::io::Error::other("unexpected bounded payload error").into());
    };

    let wire = serde_json::to_string(&errors.to_problem_field_errors()?)?;

    assert!(!wire.contains("do-not-echo") && wire.contains("out_of_range"));
    Ok(())
}

#[test]
fn fake_validator_records_only_call_count() {
    let issue = ValidationIssue::new(FieldPath::root(), ValidationCode::Invalid);
    let fake = FakeBoundaryValidator::new(Err(ValidationErrors::one(issue)));
    let sensitive = String::from("never-retained-secret");

    let result = fake.validate(&sensitive);

    assert!(result.is_err() && fake.call_count() == 1);
}

#[test]
fn garde_borrowing_port_matches_consuming_adapter() {
    let validator = GardeBoundaryValidator;
    let payload = LoginPayload {
        username: "x".to_owned(),
        password: "short".to_owned(),
    };

    assert!(validator.validate(&payload).is_err());
}
