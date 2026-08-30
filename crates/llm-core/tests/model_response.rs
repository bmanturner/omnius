//! Specialized model-operation response coverage against the fixed canonical schema.

use std::error::Error;

use omnius_llm_core::{
    BinaryEmbedding, BinaryEmbeddingEncoding, ClassificationLabel, ClassificationResponse,
    ContentLimits, EmbeddingItem, EmbeddingResponse, EmbeddingValue, GeneratedAssetKind,
    GenerationSeed, MediaGenerationResponse, ModelOperation, ModelResponse, RerankResponse,
    RerankResult, SpeechResponse, SpeechTimingKind, SpeechTimingMark, TranscriptWord,
    TranscriptionResponse,
};
use serde_json::{Value, json};

const MODEL_SCHEMA: &str = include_str!(
    "../../../specs/machine/extensions/llm-mcp-suite/schemas/model-response.schema.json"
);
const RESPONSE_SCHEMA: &str = include_str!(
    "../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-response.schema.json"
);
const CONTENT_SCHEMA: &str =
    include_str!("../../../specs/machine/extensions/llm-mcp-suite/schemas/llm-content.schema.json");
const RESPONSE_SCHEMA_ID: &str = "https://example.invalid/omnius/ai/llm-response.schema.json";
const CONTENT_SCHEMA_ID: &str = "https://example.invalid/omnius/ai/llm-content.schema.json";
const EMBEDDING_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/embedding-response.example.json");
const RERANK_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/rerank-response.example.json");
const TRANSCRIPTION_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/transcription-response.example.json");
const SPEECH_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/speech-response.example.json");
const MEDIA_GENERATION_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/media-generation-response.example.json");
const CLASSIFICATION_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/classification-response.example.json");
const COMPLETION_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/llm-response.example.json");

#[test]
fn specialized_examples_round_trip_against_fixed_model_schema() -> Result<(), Box<dyn Error>> {
    let schema: Value = serde_json::from_str(MODEL_SCHEMA)?;
    let response_schema: Value = serde_json::from_str(RESPONSE_SCHEMA)?;
    let content_schema: Value = serde_json::from_str(CONTENT_SCHEMA)?;
    let registry = jsonschema::Registry::new()
        .add(RESPONSE_SCHEMA_ID, response_schema)?
        .add(CONTENT_SCHEMA_ID, content_schema)?
        .prepare()?;
    let validator = jsonschema::draft202012::options()
        .with_registry(&registry)
        .should_validate_formats(true)
        .build(&schema)?;

    for example in [
        EMBEDDING_EXAMPLE,
        RERANK_EXAMPLE,
        TRANSCRIPTION_EXAMPLE,
        SPEECH_EXAMPLE,
        MEDIA_GENERATION_EXAMPLE,
        CLASSIFICATION_EXAMPLE,
    ] {
        let original: Value = serde_json::from_str(example)?;
        let response: ModelResponse = serde_json::from_value(original.clone())?;
        let encoded = serde_json::to_value(&response)?;

        assert_eq!(encoded, original);
        assert!(validator.is_valid(&encoded));
        let decoded: ModelResponse = serde_json::from_value(encoded)?;
        assert_eq!(decoded, response);
    }
    Ok(())
}

#[test]
fn specialized_branches_expose_every_nested_family_without_text_coercion()
-> Result<(), Box<dyn Error>> {
    let embeddings: ModelResponse = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    let embeddings = embeddings
        .as_embeddings()
        .ok_or("expected embeddings response")?;
    assert_eq!(embeddings.operation(), ModelOperation::Embeddings);
    assert_eq!(embeddings.items()[0].input_id(), Some("doc_01"));
    let EmbeddingValue::Dense(dense) = embeddings.items()[0].embedding() else {
        return Err("expected dense embedding".into());
    };
    assert_eq!(dense.values(), &[0.12, -0.04, 0.9]);
    let EmbeddingValue::Sparse(sparse) = embeddings.items()[1].embedding() else {
        return Err("expected sparse embedding".into());
    };
    assert_eq!(sparse.indices(), &[3, 11]);
    assert_eq!(sparse.dimensions(), 1024);

    let rerank: ModelResponse = serde_json::from_str(RERANK_EXAMPLE)?;
    let rerank = rerank.as_rerank().ok_or("expected reranking response")?;
    assert_eq!(rerank.results()[0].document_index(), 2);
    assert_eq!(rerank.results()[0].rank(), 1);
    assert_eq!(
        rerank.results()[0]
            .document()
            .and_then(|document| document.get("title")),
        Some(&json!("Most relevant"))
    );
    assert_eq!(rerank.results()[0].explanation(), None);

    let transcription: ModelResponse = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    let transcription = transcription
        .as_transcription()
        .ok_or("expected transcription response")?;
    assert_eq!(transcription.language(), Some("en-US"));
    assert_eq!(transcription.segments()[0].speaker(), Some("speaker_1"));
    assert_eq!(
        transcription.segments()[0]
            .words()
            .and_then(|words| words.first())
            .map(TranscriptWord::text),
        Some("Hello")
    );

    let speech: ModelResponse = serde_json::from_str(SPEECH_EXAMPLE)?;
    let speech = speech.as_speech().ok_or("expected speech response")?;
    assert_eq!(speech.audio().voice(), Some("configured-voice"));
    assert_eq!(
        speech
            .audio()
            .timing_marks()
            .and_then(|marks| marks.get(1))
            .map(SpeechTimingMark::kind),
        Some(SpeechTimingKind::Viseme)
    );

    let media: ModelResponse = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    let media = media
        .as_media_generation()
        .ok_or("expected media-generation response")?;
    assert_eq!(media.generation_id(), Some("generation_01"));
    assert_eq!(media.assets()[0].kind(), GeneratedAssetKind::Image);
    assert_eq!(
        media.assets()[0].safety().map(<[ClassificationLabel]>::len),
        Some(1)
    );
    assert_eq!(
        media.assets()[0]
            .provenance()
            .and_then(|provenance| provenance.get("watermark")),
        Some(&json!("provider"))
    );
    assert!(matches!(
        media.assets()[0].seed(),
        Some(GenerationSeed::Integer(_))
    ));
    assert!(matches!(
        media.assets()[1].seed(),
        Some(GenerationSeed::String(_))
    ));

    let classification: ModelResponse = serde_json::from_str(CLASSIFICATION_EXAMPLE)?;
    let classification = classification
        .as_classification()
        .ok_or("expected classification response")?;
    assert_eq!(classification.policy_id(), Some("moderation-default@1"));
    assert_eq!(classification.results()[0].labels()[0].label(), "violence");
    assert_eq!(
        classification.results()[0].labels()[0].disposition(),
        Some("allowed")
    );
    assert_eq!(
        classification.results()[0].overall_disposition(),
        Some("allowed")
    );
    Ok(())
}

#[test]
fn namespaced_metadata_and_arbitrary_precision_json_are_retained() -> Result<(), Box<dyn Error>> {
    let mut value: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    value["provider_metadata"] = serde_json::from_str(
        r#"{"example-provider:trace":{"exact":184467440737095516170123456789}}"#,
    )?;
    value["items"][0]["provider_metadata"] = json!({"example-provider:vector_revision": "rev_7"});

    let response: ModelResponse = serde_json::from_value(value.clone())?;
    let embeddings = response
        .as_embeddings()
        .ok_or("expected embeddings response")?;
    assert_eq!(
        embeddings
            .provider_metadata()
            .and_then(|metadata| metadata.get("example-provider:trace"))
            .and_then(|trace| trace.get("exact"))
            .map(Value::to_string)
            .as_deref(),
        Some("184467440737095516170123456789")
    );
    assert_eq!(
        embeddings.items()[0]
            .provider_metadata()
            .and_then(|metadata| metadata.get("example-provider:vector_revision")),
        Some(&json!("rev_7"))
    );
    assert_eq!(serde_json::to_value(response)?, value);
    Ok(())
}

#[test]
fn fixed_objects_reject_unknown_fields_and_absent_only_nulls() -> Result<(), Box<dyn Error>> {
    let mut unknown_envelope: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    unknown_envelope["provider_blob"] = json!(true);
    assert!(serde_json::from_value::<ModelResponse>(unknown_envelope).is_err());

    let mut unknown_nested: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    unknown_nested["items"][0]["embedding"]["provider_blob"] = json!(true);
    assert!(serde_json::from_value::<ModelResponse>(unknown_nested).is_err());

    let mut null_warnings: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    null_warnings["warnings"] = Value::Null;
    assert!(serde_json::from_value::<ModelResponse>(null_warnings).is_err());

    let mut null_metadata: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    null_metadata["items"][0]["provider_metadata"] = Value::Null;
    assert!(serde_json::from_value::<ModelResponse>(null_metadata).is_err());

    let mut null_provider_units: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    null_provider_units["usage"]["provider_units"] = Value::Null;
    assert!(serde_json::from_value::<ModelResponse>(null_provider_units).is_err());
    Ok(())
}

#[test]
fn vector_invariants_cover_dense_sparse_binary_and_multi_vector_representations()
-> Result<(), Box<dyn Error>> {
    let mut dense_dimensions: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    dense_dimensions["items"][0]["embedding"]["dimensions"] = json!(4);
    assert!(serde_json::from_value::<ModelResponse>(dense_dimensions).is_err());

    let mut sparse_alignment: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    sparse_alignment["items"][1]["embedding"]["indices"] = json!([3, 3]);
    assert!(serde_json::from_value::<ModelResponse>(sparse_alignment).is_err());

    let binary = BinaryEmbedding::new("AQID".to_owned(), BinaryEmbeddingEncoding::Uint8, 3)?;
    assert_eq!(binary.dimensions(), 3);
    assert!(
        BinaryEmbedding::new("AQID".to_owned(), BinaryEmbeddingEncoding::Float32Le, 3).is_err()
    );

    let mut multi_vector: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    multi_vector["items"][0]["embedding"] = json!({
        "kind": "multi-vector",
        "vectors": [{"name": "query", "values": [0.1, 0.2], "dimensions": 2}]
    });
    let response: ModelResponse = serde_json::from_value(multi_vector)?;
    let embedding = response
        .as_embeddings()
        .and_then(|response| response.items().first())
        .map(EmbeddingItem::embedding)
        .ok_or("expected embedding")?;
    assert!(matches!(embedding, EmbeddingValue::MultiVector(_)));
    Ok(())
}

#[test]
fn ordering_confidence_asset_and_score_invariants_are_enforced() -> Result<(), Box<dyn Error>> {
    let mut duplicate_embedding_index: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    duplicate_embedding_index["items"][1]["index"] = json!(0);
    assert!(serde_json::from_value::<ModelResponse>(duplicate_embedding_index).is_err());

    let mut duplicate_rank: Value = serde_json::from_str(RERANK_EXAMPLE)?;
    let duplicate = duplicate_rank["results"][0].clone();
    duplicate_rank["results"]
        .as_array_mut()
        .ok_or("results array")?
        .push(duplicate);
    assert!(serde_json::from_value::<ModelResponse>(duplicate_rank).is_err());
    assert!(RerankResult::new(0, 1, f64::INFINITY).is_err());

    let mut reversed_word: Value = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    reversed_word["segments"][0]["words"][0]["end_ms"] = json!(0);
    reversed_word["segments"][0]["words"][0]["start_ms"] = json!(1);
    assert!(serde_json::from_value::<ModelResponse>(reversed_word).is_err());

    let mut invalid_confidence: Value = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    invalid_confidence["segments"][0]["confidence"] = json!(1.01);
    assert!(serde_json::from_value::<ModelResponse>(invalid_confidence).is_err());

    let mut reversed_mark: Value = serde_json::from_str(SPEECH_EXAMPLE)?;
    reversed_mark["audio"]["timing_marks"][0]["end_ms"] = json!(10);
    reversed_mark["audio"]["timing_marks"][0]["start_ms"] = json!(11);
    assert!(serde_json::from_value::<ModelResponse>(reversed_mark).is_err());

    let mut no_assets: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    no_assets["assets"] = json!([]);
    assert!(serde_json::from_value::<ModelResponse>(no_assets).is_err());

    let mut invalid_digest: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    invalid_digest["assets"][0]["sha256"] = json!("ABC");
    assert!(serde_json::from_value::<ModelResponse>(invalid_digest).is_err());

    let mut invalid_source: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    invalid_source["assets"][0]["source"] = json!({"type": "inline", "data_base64": "%%%"});
    assert!(serde_json::from_value::<ModelResponse>(invalid_source).is_err());

    assert!(ClassificationLabel::new("unsafe".to_owned(), f64::INFINITY).is_err());
    Ok(())
}

#[test]
fn completion_response_parses_through_the_union_without_a_specialized_discriminator()
-> Result<(), Box<dyn Error>> {
    let response: ModelResponse = serde_json::from_str(COMPLETION_EXAMPLE)?;
    assert_eq!(response.operation(), None);
    assert!(response.as_completion().is_some());
    assert_eq!(response.provider(), "openai");
    assert_eq!(
        serde_json::to_value(&response)?,
        serde_json::from_str::<Value>(COMPLETION_EXAMPLE)?
    );
    Ok(())
}

#[test]
fn direct_specialized_deserialization_enforces_operations_and_nested_invariants()
-> Result<(), Box<dyn Error>> {
    let mut embeddings: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    embeddings["operation"] = json!("speech");
    assert!(serde_json::from_value::<EmbeddingResponse>(embeddings).is_err());

    let mut rerank: Value = serde_json::from_str(RERANK_EXAMPLE)?;
    rerank["operation"] = json!("embeddings");
    assert!(serde_json::from_value::<RerankResponse>(rerank).is_err());

    let mut transcription: Value = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    transcription["operation"] = json!("classification");
    assert!(serde_json::from_value::<TranscriptionResponse>(transcription).is_err());

    let mut speech: Value = serde_json::from_str(SPEECH_EXAMPLE)?;
    speech["operation"] = json!("rerank");
    assert!(serde_json::from_value::<SpeechResponse>(speech).is_err());

    let mut media: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    media["operation"] = json!("transcription");
    assert!(serde_json::from_value::<MediaGenerationResponse>(media).is_err());

    let mut classification: Value = serde_json::from_str(CLASSIFICATION_EXAMPLE)?;
    classification["operation"] = json!("media_generation");
    assert!(serde_json::from_value::<ClassificationResponse>(classification).is_err());

    let mut invalid_embeddings: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    invalid_embeddings["items"][0]["embedding"]["dimensions"] = json!(99);
    assert!(serde_json::from_value::<EmbeddingResponse>(invalid_embeddings).is_err());

    let mut invalid_rerank: Value = serde_json::from_str(RERANK_EXAMPLE)?;
    invalid_rerank["results"][1]["rank"] = json!(1);
    assert!(serde_json::from_value::<RerankResponse>(invalid_rerank).is_err());

    let mut invalid_transcription: Value = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    invalid_transcription["segments"][0]["confidence"] = json!(2);
    assert!(serde_json::from_value::<TranscriptionResponse>(invalid_transcription).is_err());

    let mut invalid_speech: Value = serde_json::from_str(SPEECH_EXAMPLE)?;
    invalid_speech["audio"]["timing_marks"][0]["start_ms"] = json!(400);
    invalid_speech["audio"]["timing_marks"][0]["end_ms"] = json!(300);
    assert!(serde_json::from_value::<SpeechResponse>(invalid_speech).is_err());

    let mut invalid_media: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    invalid_media["assets"] = json!([]);
    assert!(serde_json::from_value::<MediaGenerationResponse>(invalid_media).is_err());

    let mut invalid_classification: Value = serde_json::from_str(CLASSIFICATION_EXAMPLE)?;
    let duplicate = invalid_classification["results"][0].clone();
    invalid_classification["results"]
        .as_array_mut()
        .ok_or("classification results array")?
        .push(duplicate);
    assert!(serde_json::from_value::<ClassificationResponse>(invalid_classification).is_err());
    Ok(())
}

#[test]
fn generated_specialized_schemas_pin_each_operation_discriminator() -> Result<(), Box<dyn Error>> {
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(EmbeddingResponse))?,
        EMBEDDING_EXAMPLE,
        "speech",
    )?;
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(RerankResponse))?,
        RERANK_EXAMPLE,
        "embeddings",
    )?;
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(TranscriptionResponse))?,
        TRANSCRIPTION_EXAMPLE,
        "classification",
    )?;
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(SpeechResponse))?,
        SPEECH_EXAMPLE,
        "rerank",
    )?;
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(MediaGenerationResponse))?,
        MEDIA_GENERATION_EXAMPLE,
        "transcription",
    )?;
    assert_generated_schema_rejects_operation(
        &serde_json::to_value(schemars::schema_for!(ClassificationResponse))?,
        CLASSIFICATION_EXAMPLE,
        "media_generation",
    )?;
    Ok(())
}

#[test]
fn explicit_content_limits_cover_every_specialized_serialization_dimension()
-> Result<(), Box<dyn Error>> {
    let embeddings: ModelResponse = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    assert!(
        embeddings
            .validate_with_limits(&ContentLimits::default().with_max_string_bytes(1)?)
            .is_err()
    );
    assert!(
        embeddings
            .validate_with_limits(&ContentLimits::default().with_max_json_bytes(1)?)
            .is_err()
    );
    assert!(
        embeddings
            .validate_with_limits(&ContentLimits::default().with_max_collection_items(1)?)
            .is_err()
    );
    assert!(
        embeddings
            .validate_with_limits(&ContentLimits::default().with_max_nesting_depth(1)?)
            .is_err()
    );

    let mut node_heavy: Value = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    node_heavy["provider_metadata"] = json!({"provider:nested": {"value": 1}});
    let node_heavy: ModelResponse = serde_json::from_value(node_heavy)?;
    assert!(
        node_heavy
            .validate_with_limits(&ContentLimits::default().with_max_json_nodes(1)?)
            .is_err()
    );

    let mut inline_media: Value = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    inline_media["assets"][0]["source"] = json!({"type": "inline", "data_base64": "AQID"});
    let inline_media: ModelResponse = serde_json::from_value(inline_media)?;
    assert!(
        inline_media
            .validate_with_limits(&ContentLimits::default().with_max_inline_binary_bytes(2)?,)
            .is_err()
    );
    Ok(())
}

#[test]
fn specialized_debug_output_is_redacted_to_status_and_counts() -> Result<(), Box<dyn Error>> {
    let embeddings: EmbeddingResponse = serde_json::from_str(EMBEDDING_EXAMPLE)?;
    let rerank: RerankResponse = serde_json::from_str(RERANK_EXAMPLE)?;
    let transcription: TranscriptionResponse = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    let speech: SpeechResponse = serde_json::from_str(SPEECH_EXAMPLE)?;
    let media: MediaGenerationResponse = serde_json::from_str(MEDIA_GENERATION_EXAMPLE)?;
    let classification: ClassificationResponse = serde_json::from_str(CLASSIFICATION_EXAMPLE)?;

    let outputs = [
        format!("{embeddings:?}"),
        format!("{rerank:?}"),
        format!("{transcription:?}"),
        format!("{speech:?}"),
        format!("{media:?}"),
        format!("{classification:?}"),
    ];
    for output in &outputs {
        assert!(output.contains("operation"));
        assert!(output.contains("status"));
        assert!(!output.contains("configured-model"));
        assert!(!output.contains("example-provider"));
        assert!(!output.contains("Hello from speaker one"));
        assert!(!output.contains("Most relevant"));
        assert!(!output.contains("image.png"));
        assert!(!output.contains("violence"));
    }

    let union: ModelResponse = serde_json::from_str(TRANSCRIPTION_EXAMPLE)?;
    let union_debug = format!("{union:?}");
    assert!(union_debug.contains("segment_count"));
    assert!(!union_debug.contains("speaker_1"));
    assert!(!union_debug.contains("Hello from speaker one"));
    Ok(())
}

fn assert_generated_schema_rejects_operation(
    schema: &Value,
    example: &str,
    wrong_operation: &str,
) -> Result<(), Box<dyn Error>> {
    let validator = jsonschema::draft202012::options().build(schema)?;
    let mut value: Value = serde_json::from_str(example)?;
    assert!(validator.is_valid(&value));
    value["operation"] = json!(wrong_operation);
    assert!(!validator.is_valid(&value));
    Ok(())
}
