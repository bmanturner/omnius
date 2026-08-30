//! Serialization, schema, declaration, and redaction contracts.

use std::{collections::BTreeMap, error::Error};

use omnius_agent_capability_registry::{
    CapabilityDocument, CapabilityId, DeclarationError, JSON_SCHEMA_DRAFT_2020_12, ObjectSchema,
    ValueError,
};
use serde_json::{Value, json};

const FIXED_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/agent-capability.example.yaml");

#[test]
fn fixed_yaml_example_round_trips_canonically() -> Result<(), Box<dyn Error>> {
    let document: CapabilityDocument = serde_yaml::from_str(FIXED_EXAMPLE)?;
    document.validate()?;

    let encoded = serde_yaml::to_string(&document)?;
    let decoded: CapabilityDocument = serde_yaml::from_str(&encoded)?;

    assert_eq!(decoded, document);
    assert_eq!(document.id.as_str(), "records.search");
    assert!(!encoded.contains("deprecated:"));
    Ok(())
}

#[test]
fn schemars_emits_draft_2020_12_object_schema() -> Result<(), Box<dyn Error>> {
    let schema = schemars::schema_for!(ObjectSchema);
    let value = serde_json::to_value(schema)?;

    assert_eq!(
        value.get("$schema"),
        Some(&json!(JSON_SCHEMA_DRAFT_2020_12))
    );
    assert_eq!(value.get("type"), Some(&json!("object")));
    assert_eq!(value.get("additionalProperties"), Some(&json!(true)));
    Ok(())
}

#[test]
fn bounded_types_have_deterministic_string_serde_and_schema() -> Result<(), Box<dyn Error>> {
    let identifier: CapabilityId = "records.search".parse()?;
    let serialized = serde_json::to_value(&identifier)?;
    let schema = serde_json::to_value(schemars::schema_for!(CapabilityId))?;

    assert_eq!(serialized, json!("records.search"));
    assert_eq!(schema.get("type"), Some(&json!("string")));
    assert_eq!(schema.get("pattern"), Some(&json!("^[a-z][a-z0-9.-]*$")));
    Ok(())
}

#[test]
fn schema_fields_reject_non_objects_without_echoing_values() {
    let supplied = "private-schema-material";
    let encoded = format!(
        "{{\"id\":\"records.search\",\"version\":\"1.0.0\",\"title\":\"Search\",\"kind\":\"query\",\"input_schema\":\"{supplied}\",\"output_schema\":{{}},\"permissions\":[],\"side_effect\":\"none\",\"confirmation\":\"never\",\"idempotency\":\"not-applicable\",\"tenant_modes\":[\"tenant\"],\"exposures\":[]}}"
    );

    let error = serde_json::from_str::<CapabilityDocument>(&encoded)
        .err()
        .map(|error| format!("{error:?} {error}"))
        .unwrap_or_default();

    assert!(!error.contains(supplied));
}

#[test]
fn declaration_rejects_duplicates_and_unsafe_policy_combinations() -> Result<(), Box<dyn Error>> {
    let mut duplicate: CapabilityDocument = serde_yaml::from_str(FIXED_EXAMPLE)?;
    duplicate.permissions.push("records.read".parse()?);
    let duplicate_error = duplicate.validate();

    let mut unsafe_query: CapabilityDocument = serde_yaml::from_str(FIXED_EXAMPLE)?;
    unsafe_query.side_effect = omnius_agent_capability_registry::SideEffect::Mutating;
    unsafe_query.confirmation = omnius_agent_capability_registry::ConfirmationPolicy::Always;
    unsafe_query.idempotency = omnius_agent_capability_registry::IdempotencyPolicy::Required;
    let unsafe_error = unsafe_query.validate();

    assert_eq!(duplicate_error, Err(DeclarationError::DuplicateListItem));
    assert_eq!(unsafe_error, Err(DeclarationError::UnsafePolicyCombination));
    Ok(())
}

#[test]
fn declaration_and_owned_value_bounds_fail_closed() -> Result<(), Box<dyn Error>> {
    let title = omnius_agent_capability_registry::CapabilityTitle::new(
        "x".repeat(omnius_agent_capability_registry::MAX_TITLE_BYTES + 1),
    );

    let mut excessive_permissions: CapabilityDocument = serde_yaml::from_str(FIXED_EXAMPLE)?;
    excessive_permissions.permissions = (0..=omnius_agent_capability_registry::MAX_PERMISSIONS)
        .map(|index| format!("permission.{index:03}").parse())
        .collect::<Result<Vec<_>, _>>()?;

    let mut nested = json!(true);
    for _ in 0..omnius_agent_capability_registry::MAX_SCHEMA_DEPTH {
        nested = json!({"nested": nested});
    }
    let mut schema = BTreeMap::new();
    schema.insert("nested".to_owned(), nested);
    let mut excessive_depth: CapabilityDocument = serde_yaml::from_str(FIXED_EXAMPLE)?;
    excessive_depth.input_schema = ObjectSchema::new(schema);

    assert!(matches!(title, Err(ValueError::TooLong)));
    assert_eq!(
        excessive_permissions.validate(),
        Err(DeclarationError::TooManyPermissions)
    );
    assert_eq!(
        excessive_depth.validate(),
        Err(DeclarationError::SchemaTooDeep)
    );
    Ok(())
}

#[test]
fn malformed_owned_value_errors_are_value_free() {
    let supplied = "SENSITIVE INVALID IDENTIFIER";
    let error = supplied.parse::<CapabilityId>();
    let rendered = error
        .err()
        .map(|error| format!("{error:?} {error}"))
        .unwrap_or_default();

    assert!(!rendered.contains(supplied));
    assert!(matches!(
        supplied.parse::<CapabilityId>(),
        Err(ValueError::InvalidCharacter)
    ));
}

#[test]
fn w3c_trace_values_validate_bounds_and_duplicate_members() -> Result<(), Box<dyn Error>> {
    let parent: omnius_agent_capability_registry::TraceParent =
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?;
    let state: omnius_agent_capability_registry::TraceState =
        "vendor=value,1tenant@system=opaque".parse()?;
    let duplicate =
        "vendor=first,vendor=second".parse::<omnius_agent_capability_registry::TraceState>();

    assert_eq!(parent.as_str().len(), 55);
    assert_eq!(state.as_str(), "vendor=value,1tenant@system=opaque");
    assert!(matches!(duplicate, Err(ValueError::InvalidFormat)));
    Ok(())
}

#[test]
fn object_schema_value_conversion_rejects_arrays() {
    let error = ObjectSchema::try_from(Value::Array(Vec::new()));

    assert!(error.is_err());
}
