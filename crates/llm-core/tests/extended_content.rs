//! Extended canonical content coverage against the fixed schema and example.

use std::{error::Error, io};

use omnius_llm_core::{
    AnnotationOutputPart, AnnotationType, AudioOutputPart, BinarySource, CitationOutputPart,
    ContentLimits, ContractError, ExecutionOperation, ExecutionStatus, ExecutionStepOutputPart,
    FileOutputPart, ImageOutputPart, JsonObject, LlmOutputPart, LlmResponse, ReasoningOutputPart,
    ReasoningRepresentation, RefusalOutputPart, ResourceOutputPart, SafetyDisposition,
    SafetyOutputPart, UnknownOutputPart, VideoOutputPart,
};
use serde_json::{Value, json};

const CONTENT_SCHEMA: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-content.schema.json");
const RESPONSE_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/llm-response.example.json");
const LARGE_INTEGER: &str = "18446744073709551616";

#[test]
fn canonical_response_example_retains_ordered_extended_content() -> Result<(), Box<dyn Error>> {
    let response: LlmResponse = serde_json::from_str(RESPONSE_EXAMPLE)?;
    let kinds: Vec<_> = response.output().iter().map(output_kind).collect();

    assert_eq!(
        kinds,
        [
            "text",
            "structured",
            "citation",
            "image",
            "annotation",
            "execution_step",
            "resource",
            "safety",
            "video",
            "reasoning",
            "unknown",
        ]
    );
    Ok(())
}

#[test]
fn all_sixteen_output_kinds_validate_and_retain_order_and_content() -> Result<(), Box<dyn Error>> {
    let source = all_output_json()?;
    let schema: Value = serde_json::from_str(CONTENT_SCHEMA)?;
    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)?;
    let parts: Vec<LlmOutputPart> = serde_json::from_value(source)?;
    let encoded = serde_json::to_value(&parts)?;
    let round_tripped: Vec<LlmOutputPart> = serde_json::from_value(encoded.clone())?;
    let kinds: Vec<_> = parts.iter().map(output_kind).collect();
    let every_part_is_valid = encoded
        .as_array()
        .is_some_and(|values| values.iter().all(|value| validator.is_valid(value)));
    let unknown_integer = parts.iter().find_map(|part| match part {
        LlmOutputPart::Unknown(part) => Some(part.payload().to_string()),
        _ => None,
    });

    assert_eq!(
        (
            kinds,
            every_part_is_valid,
            round_tripped == parts,
            unknown_integer.as_deref(),
        ),
        (
            vec![
                "text",
                "structured",
                "tool_call",
                "tool_result",
                "citation",
                "refusal",
                "image",
                "audio",
                "video",
                "file",
                "resource",
                "annotation",
                "execution_step",
                "safety",
                "reasoning",
                "unknown",
            ],
            true,
            true,
            Some(LARGE_INTEGER),
        )
    );
    Ok(())
}

#[test]
fn citation_and_refusal_remain_typed() -> Result<(), Box<dyn Error>> {
    let parts: Vec<LlmOutputPart> = serde_json::from_value(all_output_json()?)?;
    let citation = parts.iter().find_map(|part| match part {
        LlmOutputPart::Citation(part) => Some(part),
        _ => None,
    });
    let refusal = parts.iter().find_map(|part| match part {
        LlmOutputPart::Refusal(part) => Some(part),
        _ => None,
    });

    assert_eq!(
        (
            citation.and_then(CitationOutputPart::part_id),
            citation.and_then(|part| part.source().get("uri")),
            refusal.map(RefusalOutputPart::category),
            refusal.and_then(RefusalOutputPart::retryable),
        ),
        (
            Some("p2"),
            Some(&json!("record://rec_1")),
            Some("policy"),
            Some(false),
        )
    );
    Ok(())
}

#[test]
fn inline_url_and_object_media_sources_are_bounded() -> Result<(), Box<dyn Error>> {
    let inline = ImageOutputPart::new(
        "i".to_owned(),
        "image/png".to_owned(),
        BinarySource::inline("QUJDRA==".to_owned())?,
    )?;
    let url = AudioOutputPart::new(
        "a".to_owned(),
        "audio/wav".to_owned(),
        BinarySource::url("https://example.invalid/audio.wav".to_owned())?,
    )?;
    let object = VideoOutputPart::new(
        "v".to_owned(),
        "video/mp4".to_owned(),
        BinarySource::object("objects/video.mp4".to_owned())?,
    )?;
    let inline_limit = ContentLimits::default().with_max_inline_binary_bytes(3)?;
    let string_limit = ContentLimits::default().with_max_string_bytes(12)?;

    assert_eq!(
        (
            inline.validate(&ContentLimits::default()),
            url.validate(&ContentLimits::default()),
            object.validate(&ContentLimits::default()),
            inline.validate(&inline_limit),
            url.validate(&string_limit),
            object.validate(&string_limit),
        ),
        (
            Ok(()),
            Ok(()),
            Ok(()),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
        )
    );
    Ok(())
}

#[test]
fn invalid_dimensions_rates_hash_offsets_and_urls_fail_closed() -> Result<(), Box<dyn Error>> {
    let image = ImageOutputPart::new(
        "i".to_owned(),
        "image/png".to_owned(),
        BinarySource::object("image".to_owned())?,
    )?;
    let audio = AudioOutputPart::new(
        "a".to_owned(),
        "audio/wav".to_owned(),
        BinarySource::object("audio".to_owned())?,
    )?;
    let video = VideoOutputPart::new(
        "v".to_owned(),
        "video/mp4".to_owned(),
        BinarySource::object("video".to_owned())?,
    )?;
    let file = FileOutputPart::new(
        "f".to_owned(),
        "application/octet-stream".to_owned(),
        BinarySource::object("file".to_owned())?,
    )?;
    let citation = CitationOutputPart::new("c".to_owned(), JsonObject::default())?;

    assert_eq!(
        (
            image.with_dimensions(Some(0), Some(1)),
            audio.with_media_details(None, Some(0), None),
            video.with_media_details(None, Some(1), Some(1), Some(0.0)),
            file.with_file_details(None, Some("A".repeat(64)), None),
            citation.with_location(Some("p".to_owned()), Some(10), Some(9)),
            BinarySource::url("relative/media".to_owned()),
            ResourceOutputPart::new("r".to_owned(), "relative/resource".to_owned()),
        ),
        (
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidReference),
            Err(ContractError::InvalidReference),
        )
    );
    Ok(())
}

#[test]
fn timestamp_formats_and_execution_order_fail_closed() -> Result<(), Box<dyn Error>> {
    let invalid_format = serde_json::from_value::<ExecutionStepOutputPart>(json!({
        "id": "e",
        "step_id": "s",
        "operation": "web-search",
        "status": "completed",
        "started_at": "not-a-timestamp"
    }));
    let invalid_order = serde_json::from_value::<ExecutionStepOutputPart>(json!({
        "id": "e",
        "step_id": "s",
        "operation": "web-search",
        "status": "completed",
        "started_at": "2026-08-24T12:00:00Z",
        "completed_at": "2026-08-24T11:59:59Z"
    }))?;

    assert!(invalid_format.is_err() && invalid_order.validate(&ContentLimits::default()).is_err());
    Ok(())
}

#[test]
fn every_configured_content_limit_fails_closed() -> Result<(), Box<dyn Error>> {
    let string_part = ReasoningOutputPart::new(
        "p".to_owned(),
        ReasoningRepresentation::Summary,
        "xx".to_owned(),
    )?;
    let json_part = UnknownOutputPart::new("p".to_owned(), "k".to_owned(), json!("1234567890"))?;
    let inline_part = ImageOutputPart::new(
        "p".to_owned(),
        "image/png".to_owned(),
        BinarySource::inline("QUJDRA==".to_owned())?,
    )?;
    let container_part = UnknownOutputPart::new("p".to_owned(), "k".to_owned(), json!([1, 2]))?;
    let node_part = UnknownOutputPart::new("p".to_owned(), "k".to_owned(), json!([1]))?;
    let depth_part = UnknownOutputPart::new("p".to_owned(), "k".to_owned(), json!({"n": 1}))?;

    assert_eq!(
        (
            string_part.validate(&ContentLimits::default().with_max_string_bytes(1)?),
            json_part.validate(&ContentLimits::default().with_max_json_bytes(11)?),
            inline_part.validate(&ContentLimits::default().with_max_inline_binary_bytes(3)?),
            container_part.validate(&ContentLimits::default().with_max_collection_items(1)?),
            node_part.validate(&ContentLimits::default().with_max_json_nodes(1)?),
            depth_part.validate(&ContentLimits::default().with_max_nesting_depth(1)?),
        ),
        (
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
            Err(ContractError::InvalidContent),
        )
    );
    Ok(())
}

#[test]
fn reasoning_representations_exclude_private_chain_of_thought() {
    let value = json!({
        "id": "reasoning",
        "representation": "chain-of-thought",
        "data": "private"
    });

    assert!(serde_json::from_value::<ReasoningOutputPart>(value).is_err());
}

#[test]
fn optional_non_null_metadata_and_unknown_fields_fail_closed() {
    let null_metadata = json!({
        "id": "reasoning",
        "representation": "summary",
        "data": "safe",
        "annotations": null
    });
    let unknown_field = json!({
        "id": "reasoning",
        "representation": "summary",
        "data": "safe",
        "future": true
    });

    assert!(
        serde_json::from_value::<ReasoningOutputPart>(null_metadata).is_err()
            && serde_json::from_value::<ReasoningOutputPart>(unknown_field).is_err()
    );
}

#[test]
fn debug_and_errors_do_not_disclose_reasoning_or_unknown_payloads() -> Result<(), Box<dyn Error>> {
    const SECRET: &str = "private-reasoning-secret";
    let reasoning = ReasoningOutputPart::new(
        "r".to_owned(),
        ReasoningRepresentation::OpaqueEncrypted,
        SECRET.to_owned(),
    )?;
    let unknown = UnknownOutputPart::new(
        "u".to_owned(),
        "vendor.secret".to_owned(),
        json!({"secret": SECRET}),
    )?;
    let error = reasoning
        .validate(&ContentLimits::default().with_max_string_bytes(8)?)
        .err()
        .ok_or_else(|| io::Error::other("reasoning data unexpectedly satisfied the limit"))?;
    let unknown_error = unknown
        .validate(&ContentLimits::default().with_max_json_bytes(8)?)
        .err()
        .ok_or_else(|| io::Error::other("unknown payload unexpectedly satisfied the limit"))?;
    let rendered =
        format!("{reasoning:?} {unknown:?} {error:?} {error} {unknown_error:?} {unknown_error}");

    assert!(!rendered.contains(SECRET));
    Ok(())
}

#[test]
fn typed_enum_wire_values_match_the_fixed_schema() -> Result<(), Box<dyn Error>> {
    let annotation =
        AnnotationOutputPart::new("a".to_owned(), AnnotationType::LogProbability, Value::Null)?;
    let execution = ExecutionStepOutputPart::new(
        "e".to_owned(),
        "s".to_owned(),
        ExecutionOperation::ComputerUse,
        ExecutionStatus::Running,
    )?;
    let safety = SafetyOutputPart::new("s".to_owned(), SafetyDisposition::ReviewRequired)?;

    assert_eq!(
        (
            serde_json::to_value(annotation)?["annotation_type"].clone(),
            serde_json::to_value(execution)?["operation"].clone(),
            serde_json::to_value(safety)?["disposition"].clone(),
        ),
        (
            json!("log-probability"),
            json!("computer-use"),
            json!("review-required"),
        )
    );
    Ok(())
}

fn output_kind(part: &LlmOutputPart) -> &'static str {
    match part {
        LlmOutputPart::Text(_) => "text",
        LlmOutputPart::Structured(_) => "structured",
        LlmOutputPart::ToolCall(_) => "tool_call",
        LlmOutputPart::ToolResult(_) => "tool_result",
        LlmOutputPart::Citation(_) => "citation",
        LlmOutputPart::Refusal(_) => "refusal",
        LlmOutputPart::Image(_) => "image",
        LlmOutputPart::Audio(_) => "audio",
        LlmOutputPart::Video(_) => "video",
        LlmOutputPart::File(_) => "file",
        LlmOutputPart::Resource(_) => "resource",
        LlmOutputPart::Annotation(_) => "annotation",
        LlmOutputPart::ExecutionStep(_) => "execution_step",
        LlmOutputPart::Safety(_) => "safety",
        LlmOutputPart::Reasoning(_) => "reasoning",
        LlmOutputPart::Unknown(_) => "unknown",
        _ => "future",
    }
}

fn all_output_json() -> Result<Value, serde_json::Error> {
    serde_json::from_str(&format!(
        r#"[
          {{"id":"p1","kind":"text","text":"answer","format":"plain"}},
          {{"id":"p2","kind":"structured","value":{{"answer":42}},"validation":"valid"}},
          {{"id":"p3","kind":"tool_call","call_id":"call_1","name":"records.search","arguments":{{"query":"bounded"}}}},
          {{"id":"p4","kind":"tool_result","call_id":"call_1","status":"success","content":[{{"id":"p4.1","kind":"text","text":"one match"}}]}},
          {{"id":"p5","kind":"citation","source":{{"uri":"record://rec_1","title":"Example"}},"part_id":"p2","start":0,"end":6}},
          {{"id":"p6","kind":"refusal","category":"policy","message":"not permitted","retryable":false}},
          {{"id":"p7","kind":"image","mime_type":"image/png","source":{{"type":"inline","data_base64":"AA=="}},"width":1,"height":1}},
          {{"id":"p8","kind":"audio","mime_type":"audio/wav","source":{{"type":"url","url":"https://example.invalid/audio.wav"}},"duration_ms":0,"sample_rate_hz":16000,"transcript":"audio"}},
          {{"id":"p9","kind":"video","mime_type":"video/mp4","source":{{"type":"object","object_key":"objects/video.mp4"}},"duration_ms":1,"width":1,"height":1,"frame_rate":24.0}},
          {{"id":"p10","kind":"file","filename":"data.json","mime_type":"application/json","source":{{"type":"object","object_key":"objects/data.json"}},"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":0}},
          {{"id":"p11","kind":"resource","uri":"provider-file://file_1","name":"data.json","mime_type":"application/json","source":null,"expires_at":null,"resource_metadata":{{"provider_file_id":"file_1"}}}},
          {{"id":"p12","kind":"annotation","annotation_type":"grounding","data":{{"confidence":0.9}},"part_id":"p2","start":null,"end":null}},
          {{"id":"p13","kind":"execution_step","step_id":"step_1","operation":"web-search","status":"completed","input":{{"query":"bounded"}},"output":{{"count":1}},"error":null,"started_at":"2026-08-24T11:59:58Z","completed_at":"2026-08-24T11:59:59Z"}},
          {{"id":"p14","kind":"safety","disposition":"allowed","category":null,"message":null,"scores":{{}},"policy_id":"default@1"}},
          {{"id":"p15","kind":"reasoning","representation":"summary","data":"safe provider summary"}},
          {{"id":"p16","kind":"unknown","provider_kind":"vendor.future","payload":{LARGE_INTEGER}}}
        ]"#
    ))
}
