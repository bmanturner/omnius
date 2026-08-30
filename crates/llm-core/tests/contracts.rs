//! Contract coverage against the fixed canonical LLM schemas and examples.

use std::{collections::BTreeMap, error::Error};

use omnius_core::RequestId;
use omnius_llm_core::{
    BinarySource, Candidate, CompletionStatus, ContractError, LlmInputPart, LlmOutputPart,
    LlmRequest, LlmRequestId, LlmResponse, StructuredInputPart, StructuredOutputPart,
    StructuredValidation, TextFormat, TextOutputPart, ToolCallOutputPart, ToolResultOutputPart,
    ToolResultStatus, Usage,
};
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const REQUEST_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/llm-request.example.json");
const REQUEST_SCHEMA: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-request.schema.json");
const RESPONSE_SCHEMA: &str = include_str!(
    "../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-response.schema.json"
);
const CONTENT_SCHEMA: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-content.schema.json");
const CONTENT_SCHEMA_ID: &str = "https://example.invalid/omnius/ai/llm-content.schema.json";

#[test]
fn canonical_request_validates_and_round_trips_against_fixed_schema() -> Result<(), Box<dyn Error>>
{
    let request: LlmRequest = serde_json::from_str(REQUEST_EXAMPLE)?;
    request.validate()?;

    let encoded = serde_json::to_value(&request)?;
    let schema: Value = serde_json::from_str(REQUEST_SCHEMA)?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?;
    assert!(validator.is_valid(&encoded));

    let decoded: LlmRequest = serde_json::from_value(encoded)?;
    assert_eq!(decoded, request);
    Ok(())
}

#[test]
fn core_request_id_converts_to_the_opaque_wire_identity() {
    let core_id = RequestId::new();
    let wire_id = LlmRequestId::from(core_id);

    assert_eq!(wire_id.as_str(), core_id.to_string());
}

#[test]
fn schema_version_rejects_every_other_value() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["schema_version"] = json!("1.0.1");

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn unknown_top_level_request_field_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["future_optional_field"] = json!({"safe": true});

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn duplicate_route_capability_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["route"]["required_capabilities"] = json!(["text-input", "text-input"]);

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn duplicate_tool_name_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["tools"] = json!([
        {"name": "records.search", "input_schema": true},
        {"name": "records.search", "input_schema": {"type": "object"}}
    ]);

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn positive_request_limits_fail_closed() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["limits"]["deadline_ms"] = json!(0);

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn invalid_top_p_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["generation"]["top_p"] = json!(1.01);

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn every_fixed_input_discriminator_round_trips_in_order() -> Result<(), Box<dyn Error>> {
    let value = json!([
        {"kind": "text", "text": "hello"},
        {"kind": "structured", "value": [null, true, 7, "x"]},
        {"kind": "image", "mime_type": "image/png", "source": {"type": "object", "object_key": "objects/image"}},
        {"kind": "audio", "mime_type": "audio/wav", "source": {"type": "url", "url": "https://example.invalid/audio.wav"}},
        {"kind": "video", "mime_type": "video/mp4", "source": {"type": "inline", "data_base64": "AA=="}},
        {"kind": "file", "mime_type": "application/pdf", "source": {"type": "object", "object_key": "objects/file"}, "filename": "record.pdf"},
        {"kind": "resource", "uri": "record://rec_1", "mime_type": "application/json"},
        {"kind": "tool_result", "call_id": "call_1", "status": "success", "content": [{"arbitrary": [1, 2]}]}
    ]);

    let parts: Vec<LlmInputPart> = serde_json::from_value(value.clone())?;
    assert_eq!(serde_json::to_value(parts)?, value);
    Ok(())
}

#[test]
fn plaintext_is_directly_accessible_without_provider_wrapper() -> Result<(), Box<dyn Error>> {
    let part = LlmOutputPart::Text(TextOutputPart::new(
        "part_text".to_owned(),
        "direct text".to_owned(),
        Some(TextFormat::Plain),
    )?);

    assert_eq!(part.as_text(), Some("direct text"));
    Ok(())
}

#[test]
fn mixed_foundational_output_order_survives_json_round_trip() -> Result<(), Box<dyn Error>> {
    let parts = foundational_output()?;
    let encoded = serde_json::to_value(&parts)?;
    let schema: Value = serde_json::from_str(CONTENT_SCHEMA)?;
    let validator = jsonschema::draft202012::options().build(&schema)?;
    assert!(
        encoded
            .as_array()
            .is_some_and(|values| values.iter().all(|value| validator.is_valid(value)))
    );
    let decoded: Vec<LlmOutputPart> = serde_json::from_value(encoded)?;

    assert_eq!(decoded, parts);
    Ok(())
}

#[test]
fn arbitrary_structured_json_and_validation_state_survive() -> Result<(), Box<dyn Error>> {
    let arbitrary = json!([null, true, 42, "record", {"nested": [1, 2, 3]}]);
    let part = StructuredOutputPart::new(
        "part_structured".to_owned(),
        arbitrary.clone(),
        StructuredValidation::Invalid,
    )?
    .with_validation_details(Some("record.output@2".to_owned()), 3)?;
    let encoded = serde_json::to_value(&part)?;
    let decoded: StructuredOutputPart = serde_json::from_value(encoded)?;

    assert_eq!(
        (
            decoded.value(),
            decoded.validation(),
            decoded.repair_attempts()
        ),
        (&arbitrary, StructuredValidation::Invalid, 3)
    );
    Ok(())
}

#[test]
fn tool_identity_arguments_capability_and_provenance_survive() -> Result<(), Box<dyn Error>> {
    let arguments = json!({"query": "bounded", "filters": ["a", "b"]});
    let provider_metadata = BTreeMap::from([
        ("provider_call_id".to_owned(), json!("native_call_7")),
        (
            "provenance".to_owned(),
            json!({"source": "responses-api", "turn": 2}),
        ),
    ]);
    let part = ToolCallOutputPart::new(
        "part_call".to_owned(),
        "call_7".to_owned(),
        "records.search".to_owned(),
        arguments.clone(),
    )?
    .with_provenance(
        Some("records.search@1".to_owned()),
        None,
        Some(provider_metadata.clone()),
    )?;
    let decoded: ToolCallOutputPart = serde_json::from_value(serde_json::to_value(part)?)?;

    assert_eq!(
        (
            decoded.id(),
            decoded.call_id(),
            decoded.name(),
            decoded.arguments(),
            decoded.capability_id(),
            decoded.provider_metadata(),
        ),
        (
            "part_call",
            "call_7",
            "records.search",
            &arguments,
            Some("records.search@1"),
            Some(&provider_metadata),
        )
    );
    Ok(())
}

#[test]
fn candidates_usage_and_native_identities_survive() -> Result<(), Box<dyn Error>> {
    let output = foundational_output()?;
    let candidate = Candidate::new(0, CompletionStatus::Completed, output.clone())?.with_details(
        Some("candidate_0".to_owned()),
        Some("complete".to_owned()),
        Some(BTreeMap::from([("native_index".to_owned(), json!(4))])),
    )?;
    let provider_units = BTreeMap::from([
        ("billable_character_units".to_owned(), json!(31)),
        ("service_tier_units".to_owned(), json!({"priority": 1})),
    ]);
    let usage = Usage::new(Some(120), Some(45))
        .with_token_details(Some(4), Some(3), Some(2), Some(10), Some(5), Some(6))
        .with_execution_units(Some(7), Some(8), Some(9), Some(10), Some(11))
        .with_costs(Some(2_300), Some(2_250), Some(provider_units.clone()));
    let created_at = OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339)?;
    let response = LlmResponse::new(
        LlmRequestId::new("req_01".to_owned())?,
        "resp_01".to_owned(),
        "openai".to_owned(),
        "configured-model-id".to_owned(),
        CompletionStatus::Completed,
        Some("complete".to_owned()),
        output,
        usage,
        created_at,
    )?
    .with_provider_ids(
        Some("provider_resp_01".to_owned()),
        Some("provider_req_01".to_owned()),
    )?
    .with_candidates(Some(0), vec![candidate])?;
    let decoded: LlmResponse = serde_json::from_value(serde_json::to_value(&response)?)?;

    assert_eq!(decoded, response);
    assert_eq!(
        (
            decoded.response_id(),
            decoded.provider_response_id(),
            decoded.provider_request_id(),
            decoded.provider(),
            decoded.model(),
        ),
        (
            "resp_01",
            Some("provider_resp_01"),
            Some("provider_req_01"),
            "openai",
            "configured-model-id",
        )
    );
    assert_eq!(
        (
            decoded.usage().input_tokens(),
            decoded.usage().output_tokens(),
            decoded.usage().cached_input_tokens(),
            decoded.usage().cache_read_tokens(),
            decoded.usage().cache_write_tokens(),
            decoded.usage().reasoning_tokens(),
            decoded.usage().audio_input_tokens(),
            decoded.usage().audio_output_tokens(),
        ),
        (
            Some(120),
            Some(45),
            Some(4),
            Some(3),
            Some(2),
            Some(10),
            Some(5),
            Some(6),
        )
    );
    assert_eq!(
        (
            decoded.usage().image_input_units(),
            decoded.usage().image_output_units(),
            decoded.usage().video_input_units(),
            decoded.usage().video_output_units(),
            decoded.usage().tool_execution_units(),
            decoded.usage().estimated_cost_microunits(),
            decoded.usage().actual_cost_microunits(),
        ),
        (
            Some(7),
            Some(8),
            Some(9),
            Some(10),
            Some(11),
            Some(2_300),
            Some(2_250),
        )
    );
    assert_eq!(decoded.usage().provider_units(), Some(&provider_units));
    Ok(())
}

#[test]
fn duplicate_candidate_indices_fail_closed() -> Result<(), Box<dyn Error>> {
    let output = vec![LlmOutputPart::Text(TextOutputPart::new(
        "part_1".to_owned(),
        "answer".to_owned(),
        None,
    )?)];
    let first = Candidate::new(0, CompletionStatus::Completed, output.clone())?;
    let duplicate = Candidate::new(0, CompletionStatus::Completed, output.clone())?;
    let response = base_response(output)?;

    assert_eq!(
        response.with_candidates(Some(0), vec![first, duplicate]),
        Err(ContractError::DuplicateCandidateIndex)
    );
    Ok(())
}

#[test]
fn selected_candidate_output_mismatch_fails_closed() -> Result<(), Box<dyn Error>> {
    let selected_output = vec![LlmOutputPart::Text(TextOutputPart::new(
        "selected".to_owned(),
        "selected answer".to_owned(),
        None,
    )?)];
    let response_output = vec![LlmOutputPart::Text(TextOutputPart::new(
        "default".to_owned(),
        "different answer".to_owned(),
        None,
    )?)];
    let candidate = Candidate::new(1, CompletionStatus::Completed, selected_output)?;
    let response = base_response(response_output)?;

    assert_eq!(
        response.with_candidates(Some(1), vec![candidate]),
        Err(ContractError::SelectedOutputMismatch)
    );
    Ok(())
}

#[test]
fn arbitrary_json_numbers_above_u64_round_trip_exactly() -> Result<(), Box<dyn Error>> {
    const INTEGER: &str = "18446744073709551616";
    let input: StructuredInputPart = serde_json::from_str(r#"{"value":18446744073709551616}"#)?;
    let output: StructuredOutputPart = serde_json::from_str(
        r#"{"id":"part_precision","value":18446744073709551616,"validation":"valid"}"#,
    )?;

    assert_eq!(
        (input.value().to_string(), output.value().to_string()),
        (INTEGER.to_owned(), INTEGER.to_owned())
    );
    Ok(())
}

#[test]
fn identities_and_names_above_old_limits_are_accepted() -> Result<(), Box<dyn Error>> {
    let request_id = LlmRequestId::new("r".repeat(257))?;
    let output = TextOutputPart::new("p".repeat(513), String::new(), None)?;
    let tool = ToolCallOutputPart::new(
        "part_call".to_owned(),
        "call_1".to_owned(),
        "n".repeat(257),
        Value::Null,
    )?;

    assert_eq!(
        (
            request_id.as_str().len(),
            output.id().len(),
            tool.name().len()
        ),
        (257, 513, 257)
    );
    Ok(())
}

#[test]
fn non_absolute_url_constructor_is_rejected() {
    assert_eq!(
        BinarySource::url("relative/binary".to_owned()),
        Err(ContractError::InvalidReference)
    );
}

#[test]
fn malformed_url_in_deserialized_request_is_rejected() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    value["messages"][1]["content"][1]["source"] = json!({"type": "url", "url": "http://[::1"});

    assert!(serde_json::from_value::<LlmRequest>(value).is_err());
    Ok(())
}

#[test]
fn request_non_null_optionals_reject_explicit_null() -> Result<(), Box<dyn Error>> {
    let value: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    let mut nested = value.clone();
    nested["messages"][0]["metadata"] = Value::Null;
    let mut envelope = value;
    envelope["metadata"] = Value::Null;

    assert!(
        serde_json::from_value::<LlmRequest>(nested).is_err()
            && serde_json::from_value::<LlmRequest>(envelope).is_err()
    );
    Ok(())
}

#[test]
fn response_non_null_optionals_reject_explicit_null() -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_value(base_response(foundational_output()?)?)?;
    let mut nested = value.clone();
    nested["output"][0]["annotations"] = Value::Null;
    let mut envelope = value;
    envelope["warnings"] = Value::Null;

    assert!(
        serde_json::from_value::<LlmResponse>(nested).is_err()
            && serde_json::from_value::<LlmResponse>(envelope).is_err()
    );
    Ok(())
}

#[test]
fn generated_request_schema_preserves_absent_only_non_null_optionals_and_uri_format()
-> Result<(), Box<dyn Error>> {
    let schema = serde_json::to_value(schemars::schema_for!(LlmRequest))?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?;
    let mut absent: Value = serde_json::from_str(REQUEST_EXAMPLE)?;
    let _ = absent
        .as_object_mut()
        .and_then(|object| object.remove("metadata"));
    let _ = absent["messages"][0]
        .as_object_mut()
        .and_then(|object| object.remove("metadata"));
    let _ = absent["output"]
        .as_object_mut()
        .and_then(|object| object.remove("strict"));
    let mut explicit_null = absent.clone();
    explicit_null["metadata"] = Value::Null;
    let mut malformed_uri = absent.clone();
    malformed_uri["messages"][1]["content"][1]["source"] =
        json!({"type": "url", "url": "relative/binary"});

    assert_eq!(
        (
            validator.is_valid(&absent),
            validator.is_valid(&explicit_null),
            validator.is_valid(&malformed_uri)
        ),
        (true, false, false)
    );
    Ok(())
}

#[test]
fn generated_response_schema_preserves_absent_only_non_null_optionals() -> Result<(), Box<dyn Error>>
{
    let schema = serde_json::to_value(schemars::schema_for!(LlmResponse))?;
    let validator = jsonschema::draft202012::options().build(&schema)?;
    let absent = serde_json::to_value(base_response(foundational_output()?)?)?;
    let mut envelope_null = absent.clone();
    envelope_null["warnings"] = Value::Null;
    let mut nested_null = absent.clone();
    nested_null["output"][0]["annotations"] = Value::Null;

    assert_eq!(
        (
            validator.is_valid(&absent),
            validator.is_valid(&envelope_null),
            validator.is_valid(&nested_null)
        ),
        (true, false, false)
    );
    Ok(())
}

#[test]
fn foundational_response_validates_against_fixed_schema_with_content_resource()
-> Result<(), Box<dyn Error>> {
    let response = base_response(foundational_output()?)?;
    let encoded = serde_json::to_value(response)?;
    let schema: Value = serde_json::from_str(RESPONSE_SCHEMA)?;
    let content_schema: Value = serde_json::from_str(CONTENT_SCHEMA)?;
    let registry = jsonschema::Registry::new()
        .add(CONTENT_SCHEMA_ID, content_schema)?
        .prepare()?;
    let validator = jsonschema::draft202012::options()
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(&schema)?;

    assert!(validator.is_valid(&encoded));
    Ok(())
}

fn foundational_output() -> Result<Vec<LlmOutputPart>, ContractError> {
    let text = LlmOutputPart::Text(TextOutputPart::new(
        "part_text".to_owned(),
        "Two records matched.".to_owned(),
        Some(TextFormat::Markdown),
    )?);
    let structured = LlmOutputPart::Structured(
        StructuredOutputPart::new(
            "part_structured".to_owned(),
            json!({"records": [{"id": "rec_1"}], "complete": true}),
            StructuredValidation::Valid,
        )?
        .with_validation_details(Some("records.search.output@1".to_owned()), 0)?,
    );
    let tool_call = LlmOutputPart::ToolCall(
        ToolCallOutputPart::new(
            "part_call".to_owned(),
            "call_1".to_owned(),
            "records.search".to_owned(),
            json!({"query": "authorized"}),
        )?
        .with_provenance(
            Some("records.search@1".to_owned()),
            None,
            Some(BTreeMap::from([(
                "native_call_id".to_owned(),
                json!("native_1"),
            )])),
        )?,
    );
    let nested_text = LlmOutputPart::Text(TextOutputPart::new(
        "result_text".to_owned(),
        "tool complete".to_owned(),
        Some(TextFormat::Plain),
    )?);
    let tool_result = LlmOutputPart::ToolResult(ToolResultOutputPart::new(
        "part_result".to_owned(),
        "call_1".to_owned(),
        ToolResultStatus::Success,
        vec![nested_text],
    )?);

    Ok(vec![text, structured, tool_call, tool_result])
}

fn base_response(output: Vec<LlmOutputPart>) -> Result<LlmResponse, Box<dyn Error>> {
    let created_at = OffsetDateTime::parse("2026-08-24T12:00:00Z", &Rfc3339)?;
    Ok(LlmResponse::new(
        LlmRequestId::new("req_01".to_owned())?,
        "resp_01".to_owned(),
        "provider".to_owned(),
        "model".to_owned(),
        CompletionStatus::Completed,
        None,
        output,
        Usage::new(Some(1), Some(1)),
        created_at,
    )?)
}
