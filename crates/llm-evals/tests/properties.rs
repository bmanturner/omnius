//! Property and boundary tests for schemas, streams, and resource limits.
#![allow(
    clippy::expect_used,
    reason = "fixed property-test setup uses expect to keep generated counterexamples focused"
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    num::{NonZeroU64, NonZeroUsize},
    time::Duration,
};

use async_trait::async_trait;
use omnius_llm_core::{
    CapabilityEvidence, ContentLimits, LlmOutputPart, LlmRequestId, ModelCapabilityDeclaration,
    ModelCapabilityKey, OutputMode, OutputRequest, ProviderError, ProviderErrorKind,
    ProviderStreamEvent, ProviderToolCallDelta, RawPayloadKind, RawRetentionPolicy,
    RawRetentionState, RetainedRaw, RetryClass, Route, SchemaDefinition, StructuredOutputPart,
    StructuredValidation, TextFormat, TextOutputPart, ToolCallOutputPart,
};
use omnius_llm_evals::{
    CandidateRole, DatasetBounds, DatasetError, DeterministicAssertion, EvalCase, EvalInvocation,
    EvalTolerances, EvalUsage, EvaluationDataset, EvaluationInput, ExecutionTarget,
    PromptRevisionReference,
};
use omnius_llm_provider_rig::{CatalogProvider, DirectProvider, RIG_COMPATIBILITY_VERSION};
use omnius_llm_streaming::{
    AcceptedPublicContent, ConsumerOwnership, DeliveryError, LlmStreamAssembler, LlmStreamEvent,
    LlmStreamEventData, LlmStreamValidator, StreamInterruption, StreamInvariantError, StreamLimits,
    StreamPartKind, StreamTerminalState, StreamToolCallDelta, bounded_stream,
};
use omnius_llm_structured_output::{
    CandidateInvalidKind, FallbackPermission, PreparedStructuredOutput, RepairCandidate,
    RepairPolicy, RepairRequest, StrategyPolicy, StructuredOutputError, StructuredOutputRepairPort,
};
use omnius_llm_tool_runtime::{CompleteToolCall, CompleteToolCallError};
use omnius_validation::JsonValidationLimits;
use proptest::prelude::*;
use proptest::test_runner::RngSeed;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const DIGEST_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const ADVERSARIAL_REGRESSIONS: &[u8] =
    include_bytes!("../fixtures/adversarial/v1/regressions.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegressionCorpus {
    schema_version: String,
    arbitrary_json_roots: Vec<Value>,
    truncated_tool_fragments: Vec<String>,
    stream_text: String,
    stream_chunk_plans: Vec<Vec<usize>>,
    usage_overflow_cases: Vec<UsageOverflowWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageOverflowWire {
    left: (Option<u64>, Option<u64>, u64),
    right: (Option<u64>, Option<u64>, u64),
}

fn arb_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i32>().prop_map(|value| Value::Number(value.into())),
        "[a-zA-Z0-9 _-]{0,24}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,8}", inner, 0..6)
                .prop_map(|object| { Value::Object(object.into_iter().collect()) }),
        ]
    })
}

fn route() -> Route {
    Route::new("property.route".to_owned(), Some(3), Vec::new(), Vec::new())
        .expect("fixed route must satisfy the public contract")
}

fn invocation() -> EvalInvocation {
    EvalInvocation::new(
        EvaluationInput::prompt_reference(PromptRevisionReference::new(
            "property.prompt".to_owned(),
            1,
            DIGEST_A.to_owned(),
        )),
        ExecutionTarget::new(
            route(),
            "openai".to_owned(),
            "property-model".to_owned(),
            "immutable-revision".to_owned(),
        )
        .expect("fixed execution target"),
    )
}

fn dataset_with_expected(expected: Value) -> EvaluationDataset {
    EvaluationDataset::new(
        "property.dataset".to_owned(),
        "1.0.0".to_owned(),
        vec![EvalCase::new(
            "arbitrary-root".to_owned(),
            invocation(),
            None,
            vec![DeterministicAssertion::JsonPointerEquals {
                id: "root.equals".to_owned(),
                target: CandidateRole::Primary,
                pointer: "/output/0/value".to_owned(),
                expected,
            }],
            None,
            EvalTolerances::new(0, None),
            1_000,
            1_000,
        )],
        DatasetBounds::new(4, 256 * 1024).expect("positive property bounds"),
    )
    .expect("bounded property dataset must be admitted")
}

fn option_counter() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![Just(None), (0_u64..1_000_000).prop_map(Some)]
}

fn stream_limits() -> StreamLimits {
    StreamLimits::new(
        NonZeroU64::new(256).expect("nonzero event limit"),
        NonZeroUsize::new(32).expect("nonzero part limit"),
        NonZeroUsize::new(32).expect("nonzero public item limit"),
        NonZeroUsize::new(4_096).expect("nonzero text limit"),
    )
    .with_max_event_bytes(NonZeroUsize::new(16_384).expect("nonzero event byte limit"))
}

fn text_stream(
    text: &str,
    chunk_sizes: &[usize],
) -> Result<(Vec<LlmStreamEvent>, Vec<AcceptedPublicContent>), Box<dyn Error>> {
    let request_id = LlmRequestId::new("request-property".to_owned())?;
    let mut assembler = LlmStreamAssembler::new(request_id.clone(), stream_limits());
    let mut events = vec![assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-property".to_owned(),
    })?];
    events.push(assembler.emit(LlmStreamEventData::PartStart {
        part_id: "text-part".to_owned(),
        kind: StreamPartKind::Text,
    })?);
    let mut offset = 0;
    let mut chunk_index = 0;
    while offset < text.len() {
        let requested = chunk_sizes[chunk_index % chunk_sizes.len()];
        let end = offset.saturating_add(requested).min(text.len());
        events.push(assembler.emit(LlmStreamEventData::TextDelta {
            part_id: "text-part".to_owned(),
            text: text[offset..end].to_owned(),
        })?);
        offset = end;
        chunk_index += 1;
    }
    events.push(assembler.emit(LlmStreamEventData::PartComplete {
        part_id: "text-part".to_owned(),
    })?);
    events.push(assembler.terminate(StreamTerminalState::Completed)?);
    assembler.finish()?;

    let mut validator = LlmStreamValidator::new(request_id, stream_limits());
    for (sequence, event) in events.iter().enumerate() {
        if event.sequence() != u64::try_from(sequence)? {
            return Err("stream sequence changed".into());
        }
        validator.accept(event)?;
    }
    validator.finish()?;
    let snapshot = events
        .last()
        .and_then(LlmStreamEvent::terminal)
        .ok_or("missing terminal snapshot")?
        .accepted_public_content()
        .to_vec();
    Ok((events, snapshot))
}

fn declaration() -> ModelCapabilityDeclaration {
    ModelCapabilityDeclaration::new(
        ModelCapabilityKey::new(
            "fixture-provider",
            "fixture-model",
            "fixture-model-revision",
        )
        .expect("fixed model key"),
        "fixture-registry-revision",
        BTreeMap::<_, CapabilityEvidence>::new(),
        BTreeSet::new(),
        None,
        None,
    )
    .expect("fixed capability declaration")
}

fn prepared_schema(schema: Value, limits: JsonValidationLimits) -> PreparedStructuredOutput {
    let schema: SchemaDefinition =
        serde_json::from_value(schema).expect("fixture schema is canonical");
    let output = OutputRequest::new(OutputMode::Structured)
        .with_schema(Some("root.schema.v1".to_owned()), Some(schema), Some(false))
        .expect("fixed structured request");
    PreparedStructuredOutput::prepare(
        &output,
        &declaration(),
        StrategyPolicy::new(FallbackPermission::Allow, FallbackPermission::Deny),
        limits,
    )
    .expect("bounded fixture schema must prepare")
}

fn prepared_true_schema(limits: JsonValidationLimits) -> PreparedStructuredOutput {
    prepared_schema(Value::Bool(true), limits)
}

struct UnexpectedRepair;

#[async_trait]
impl StructuredOutputRepairPort for UnexpectedRepair {
    async fn repair(&self, _request: RepairRequest<'_>) -> Result<RepairCandidate, ProviderError> {
        Err(ProviderError::new(
            "fixture-provider".to_owned(),
            ProviderErrorKind::Provider,
            RetryClass::Never,
        ))
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_shrink_iters: 4_096,
        rng_seed: RngSeed::Fixed(0x5eed_0177_cafe_babe),
        .. ProptestConfig::default()
    })]

    #[test]
    fn dataset_hash_is_independent_of_object_insertion_order(
        values in prop::collection::btree_map("[a-z]{1,8}", any::<i32>(), 0..12)
    ) {
        let mut forward = Map::new();
        for (key, value) in &values {
            forward.insert(key.clone(), Value::Number((*value).into()));
        }
        let mut reverse = Map::new();
        for (key, value) in values.iter().rev() {
            reverse.insert(key.clone(), Value::Number((*value).into()));
        }
        let forward_dataset = dataset_with_expected(Value::Object(forward));
        let reverse_dataset = dataset_with_expected(Value::Object(reverse));

        prop_assert_eq!(forward_dataset.sha256(), reverse_dataset.sha256());
        prop_assert_eq!(
            forward_dataset.to_canonical_json(),
            reverse_dataset.to_canonical_json()
        );
    }

    #[test]
    fn dataset_canonical_encode_parse_is_stable_for_arbitrary_json_roots(value in arb_json()) {
        let dataset = dataset_with_expected(value);
        let encoded = dataset
            .to_canonical_json()
            .expect("generated canonical dataset must encode");
        let decoded = EvaluationDataset::from_json(
            &encoded,
            DatasetBounds::new(4, 256 * 1024).expect("positive property bounds"),
        )
        .expect("canonical dataset must parse");

        prop_assert_eq!(decoded.to_canonical_json(), Ok(encoded));
        prop_assert_eq!(decoded.sha256(), dataset.sha256());
    }

    #[test]
    fn dataset_byte_boundary_is_exact_and_rejection_never_echoes_content(
        secret in "sensitive_[A-Z]{8,32}"
    ) {
        let dataset = dataset_with_expected(Value::String(secret.clone()));
        let encoded = dataset
            .to_canonical_json()
            .expect("generated canonical dataset must encode");
        let exact = DatasetBounds::new(4, encoded.len()).expect("positive exact bound");
        let below = DatasetBounds::new(4, encoded.len() - 1).expect("positive lower bound");
        let admitted = EvaluationDataset::from_json(&encoded, exact);
        let rejected = EvaluationDataset::from_json(&encoded, below);
        let rendered = rejected
            .as_ref()
            .err()
            .map(|error| format!("{error:?}{error}"))
            .expect("lower bound must reject");

        prop_assert!(admitted.is_ok());
        prop_assert!(matches!(rejected, Err(DatasetError::TooManyBytes)));
        prop_assert!(!rendered.contains(&secret));
    }

    #[test]
    fn canonical_output_part_round_trips_arbitrary_structured_roots(value in arb_json()) {
        let part = LlmOutputPart::Structured(
            StructuredOutputPart::new(
                "structured-part".to_owned(),
                value.clone(),
                StructuredValidation::Valid,
            )
            .expect("fixed part identity"),
        );
        let encoded = serde_json::to_vec(&part).expect("canonical part must encode");
        let decoded: LlmOutputPart =
            serde_json::from_slice(&encoded).expect("canonical part must parse");
        let decoded_value = match &decoded {
            LlmOutputPart::Structured(part) => part.value(),
            _ => panic!("structured variant changed during round trip"),
        };

        prop_assert_eq!(decoded_value, &value);
        let reencoded = serde_json::to_vec(&decoded).expect("decoded part must re-encode");
        prop_assert_eq!(reencoded, encoded);
    }

    #[test]
    fn canonical_content_limits_reject_exact_overflow_without_echoing_content(
        text in "SENSITIVE_[A-Z]{0,48}"
    ) {
        let part = LlmOutputPart::Text(
            TextOutputPart::new(
                "text-part".to_owned(),
                text.clone(),
                Some(TextFormat::Plain),
            )
            .expect("fixed text part"),
        );
        let limits = ContentLimits::default()
            .with_max_string_bytes(16)
            .expect("positive string limit");
        let result = part.validate_with_limits(&limits);

        prop_assert_eq!(result.is_ok(), text.len() <= 16);
        if let Err(error) = result {
            let rendered = format!("{error:?}{error}");
            prop_assert!(!rendered.contains(&text) || text.is_empty());
        }
    }

    #[test]
    fn usage_checked_add_is_commutative_associative_and_has_zero_identity(
        ai in option_counter(), ao in option_counter(), ac in 0_u64..1_000_000,
        bi in option_counter(), bo in option_counter(), bc in 0_u64..1_000_000,
        ci in option_counter(), co in option_counter(), cc in 0_u64..1_000_000,
    ) {
        let a = EvalUsage::new(ai, ao, ac);
        let b = EvalUsage::new(bi, bo, bc);
        let c = EvalUsage::new(ci, co, cc);
        let zero = EvalUsage::default();

        prop_assert_eq!(a.checked_add(b), b.checked_add(a));
        prop_assert_eq!(a.checked_add(zero), Some(a));
        prop_assert_eq!(
            a.checked_add(b).and_then(|sum| sum.checked_add(c)),
            b.checked_add(c).and_then(|sum| a.checked_add(sum))
        );
    }

    #[test]
    fn text_stream_terminal_snapshot_is_independent_of_chunk_boundaries(
        text in "[a-zA-Z0-9 ]{1,96}",
        first_chunks in prop::collection::vec(1_usize..12, 1..12),
        second_chunks in prop::collection::vec(1_usize..12, 1..12),
    ) {
        let (_, first) = text_stream(&text, &first_chunks).expect("first bounded stream");
        let (_, second) = text_stream(&text, &second_chunks).expect("second bounded stream");

        prop_assert!(first == second);
        let Some(AcceptedPublicContent::Text {
            text: accumulated, ..
        }) = first.first()
        else {
            panic!("text stream lost its accepted text");
        };
        prop_assert_eq!(accumulated, &text);
    }

    #[test]
    fn duplicate_and_unknown_stream_parts_are_rejected_deterministically(
        part_id in "[a-z]{1,32}",
        unknown_id in "[A-Z]{1,32}"
    ) {
        let mut assembler = LlmStreamAssembler::new(
            LlmRequestId::new("request-duplicates".to_owned()).expect("fixed request identity"),
            stream_limits(),
        );
        assembler.emit(LlmStreamEventData::ResponseStart {
            response_id: "response-duplicates".to_owned(),
        }).expect("response start");
        let start = LlmStreamEventData::PartStart {
            part_id: part_id.clone(),
            kind: StreamPartKind::Text,
        };
        assembler.emit(start.clone()).expect("first part start");

        prop_assert_eq!(assembler.emit(start), Err(StreamInvariantError::DuplicatePart));
        prop_assert_eq!(
            assembler.emit(LlmStreamEventData::TextDelta {
                part_id: unknown_id,
                text: "x".to_owned(),
            }),
            Err(StreamInvariantError::UnknownPart)
        );
    }

    #[test]
    fn stream_text_limit_accepts_exact_boundary_and_rejects_one_byte_over(
        byte_count in 1_usize..65
    ) {
        let limits = StreamLimits::new(
            NonZeroU64::new(16).expect("nonzero event limit"),
            NonZeroUsize::new(2).expect("nonzero part limit"),
            NonZeroUsize::new(2).expect("nonzero public item limit"),
            NonZeroUsize::new(32).expect("nonzero text limit"),
        )
        .with_max_event_bytes(NonZeroUsize::new(4_096).expect("nonzero event byte limit"));
        let mut assembler = LlmStreamAssembler::new(
            LlmRequestId::new("request-text-boundary".to_owned()).expect("fixed request identity"),
            limits,
        );
        assembler.emit(LlmStreamEventData::ResponseStart {
            response_id: "response-text-boundary".to_owned(),
        }).expect("response start");
        assembler.emit(LlmStreamEventData::PartStart {
            part_id: "text-boundary".to_owned(),
            kind: StreamPartKind::Text,
        }).expect("text part start");
        let result = assembler.emit(LlmStreamEventData::TextDelta {
            part_id: "text-boundary".to_owned(),
            text: "x".repeat(byte_count),
        });

        if byte_count <= 32 {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(result, Err(StreamInvariantError::TextLimitExceeded));
        }
    }

    #[test]
    fn truncated_tool_json_deltas_never_become_executable(
        fragment in "\"sensitive_[a-z]{8,32}"
    ) {
        let event = ProviderStreamEvent::ToolCallDelta {
            sequence: 0,
            correlation_id: "correlation-1".to_owned(),
            delta: ProviderToolCallDelta::ArgumentsFragment(fragment.clone()),
        };
        let rendered = format!("{:?}", event.tool_call_delta().expect("delta event"));

        prop_assert!(matches!(
            CompleteToolCall::try_from(event),
            Err(CompleteToolCallError::NotComplete)
        ));
        prop_assert!(!rendered.contains(&fragment));
    }

    #[test]
    fn complete_tool_call_identity_boundaries_are_exact_and_content_free(
        call_bytes in 0_usize..300,
        correlation_bytes in 0_usize..300,
    ) {
        let call_id = "c".repeat(call_bytes);
        let correlation_id = "r".repeat(correlation_bytes);
        let result = CompleteToolCall::try_from(ProviderStreamEvent::ToolCall {
            sequence: 0,
            correlation_id,
            call_id,
            name: "lookup_fixture".to_owned(),
            arguments: json!({}),
            raw: RetainedRaw::discarded(),
        });
        let expected = (1..=256).contains(&call_bytes)
            && (1..=256).contains(&correlation_bytes);

        prop_assert_eq!(result.is_ok(), expected);
        if let Err(error) = result {
            prop_assert_eq!(error, CompleteToolCallError::InvalidIdentity);
        }
    }

    #[test]
    fn complete_tool_calls_preserve_arbitrary_json_and_reject_duplicate_stream_identity(
        arguments in arb_json()
    ) {
        let part = ToolCallOutputPart::new(
            "tool-part".to_owned(),
            "call-1".to_owned(),
            "lookup_fixture".to_owned(),
            arguments.clone(),
        ).expect("fixed complete tool call");
        let complete = CompleteToolCall::from_output_part("correlation-1".to_owned(), &part)
            .expect("complete canonical call must be executable");
        let mut assembler = LlmStreamAssembler::new(
            LlmRequestId::new("request-tools".to_owned()).expect("fixed request identity"),
            stream_limits(),
        );
        assembler.emit(LlmStreamEventData::ResponseStart {
            response_id: "response-tools".to_owned(),
        }).expect("response start");
        assembler.emit(LlmStreamEventData::PartStart {
            part_id: "tool-part".to_owned(),
            kind: StreamPartKind::ToolCall,
        }).expect("tool part start");
        assembler.emit(LlmStreamEventData::ToolCallDelta {
            part_id: "tool-part".to_owned(),
            correlation_id: "correlation-1".to_owned(),
            delta: StreamToolCallDelta::ArgumentsFragment("{\"incomplete\":".to_owned()),
        }).expect("incomplete delta remains non-executable");
        let completed_event = LlmStreamEventData::ToolCallComplete {
            correlation_id: "correlation-1".to_owned(),
            part: part.clone(),
        };
        assembler.emit(completed_event).expect("first complete tool call");
        assembler.emit(LlmStreamEventData::PartStart {
            part_id: "tool-part-2".to_owned(),
            kind: StreamPartKind::ToolCall,
        }).expect("second tool part start");
        let duplicate_identity = ToolCallOutputPart::new(
            "tool-part-2".to_owned(),
            "call-2".to_owned(),
            "lookup_fixture".to_owned(),
            arguments.clone(),
        ).expect("fixed duplicate-identity tool call");

        prop_assert_eq!(complete.arguments(), &arguments);
        prop_assert_eq!(
            assembler.emit(LlmStreamEventData::ToolCallComplete {
                correlation_id: "correlation-1".to_owned(),
                part: duplicate_identity,
            }),
            Err(StreamInvariantError::DuplicateToolCallIdentity)
        );
    }

    #[test]
    fn structured_output_locally_validates_arbitrary_json_roots(value in arb_json()) {
        let prepared = prepared_true_schema(JsonValidationLimits::default());
        let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)
            .expect("zero repair budget is bounded");
        let validated = futures::executor::block_on(prepared.validate_and_repair(
            "structured-arbitrary-root".to_owned(),
            value.clone(),
            policy,
            &UnexpectedRepair,
        ))
        .expect("bounded arbitrary root must satisfy the boolean schema");

        prop_assert_eq!(validated.part().value(), &value);
        prop_assert_eq!(validated.part().validation(), StructuredValidation::Valid);
    }

    #[test]
    fn structured_output_accepts_all_json_roots_and_enforces_nesting(depth in 0_usize..9) {
        let mut value = json!(0);
        for _ in 0..depth {
            value = Value::Array(vec![value]);
        }
        let limits = JsonValidationLimits {
            max_depth: 3,
            max_nodes: 64,
            max_array_items: 8,
            max_object_properties: 8,
            max_string_bytes: 64,
            max_payload_bytes: 1_024,
            max_schema_bytes: 1_024,
            max_errors: 4,
        };
        let prepared = prepared_true_schema(limits);
        let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)
            .expect("zero repair budget is bounded");
        let result = futures::executor::block_on(prepared.validate_and_repair(
            "structured-root".to_owned(),
            value,
            policy,
            &UnexpectedRepair,
        ));

        if depth <= limits.max_depth {
            prop_assert!(result.is_ok());
        } else {
            let invalid_kind = match result {
                Err(StructuredOutputError::Invalid(invalid)) => invalid.last_invalid_kind(),
                _ => panic!("excessive nesting did not produce bounded invalid output"),
            };
            prop_assert_eq!(invalid_kind, CandidateInvalidKind::StructureLimit);
        }
    }

    #[test]
    fn public_provider_error_normalization_is_deterministic_and_content_free(
        provider_index in 0_usize..DirectProvider::ALL.len(),
        secret in "sensitive_[A-Za-z]{8,32}"
    ) {
        let provider = DirectProvider::ALL[provider_index];
        let raw = RetainedRaw::from_value(
            RawRetentionPolicy::Full,
            json!({"sensitive": secret.clone()}),
        );
        let error = ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Throttling,
            RetryClass::AfterRetryAfter,
        )
        .with_transport_metadata(
            Some(429),
            Some(Duration::from_millis(250)),
            Some(secret.clone()),
            raw,
        );
        let rendered = format!("{error:?}{error}");

        prop_assert_eq!(
            (
                error.provider(),
                error.kind(),
                error.retry_class(),
                error.status_code(),
                error.retry_after(),
                provider.catalog_provider().direct(),
            ),
            (
                provider.as_str(),
                ProviderErrorKind::Throttling,
                RetryClass::AfterRetryAfter,
                Some(429),
                Some(Duration::from_millis(250)),
                Some(provider),
            )
        );
        prop_assert!(!rendered.contains(&secret));
    }
}

#[test]
fn composed_schema_preserves_object_array_and_scalar_roots() -> Result<(), Box<dyn Error>> {
    let prepared = prepared_schema(
        json!({
            "oneOf": [
                {"type": "null"},
                {"type": "boolean"},
                {"type": "integer"},
                {"type": "string"},
                {"type": "array", "items": true},
                {"type": "object", "additionalProperties": true}
            ]
        }),
        JsonValidationLimits::default(),
    );
    let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)?;
    let candidates = [
        Value::Null,
        json!(true),
        json!(7),
        json!("seven"),
        json!([1, 2]),
        json!({"value": 7}),
    ];
    let values = candidates
        .into_iter()
        .enumerate()
        .map(|(index, candidate)| {
            futures::executor::block_on(prepared.validate_and_repair(
                format!("composed-root-{index}"),
                candidate,
                policy,
                &UnexpectedRepair,
            ))
            .map(|validated| validated.part().value().clone())
        })
        .collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        values,
        vec![
            Value::Null,
            json!(true),
            json!(7),
            json!("seven"),
            json!([1, 2]),
            json!({"value": 7}),
        ]
    );
    Ok(())
}
#[test]
fn fixed_adversarial_regression_corpus_replays_every_minimal_counterexample()
-> Result<(), Box<dyn Error>> {
    let corpus: RegressionCorpus = serde_json::from_slice(ADVERSARIAL_REGRESSIONS)?;
    let decoded_roots = corpus
        .arbitrary_json_roots
        .iter()
        .map(|value| {
            let part = LlmOutputPart::Structured(StructuredOutputPart::new(
                "regression-root".to_owned(),
                value.clone(),
                StructuredValidation::Valid,
            )?);
            let encoded = serde_json::to_vec(&part)?;
            let decoded: LlmOutputPart = serde_json::from_slice(&encoded)?;
            match decoded {
                LlmOutputPart::Structured(part) => Ok(part.value().clone()),
                _ => Err::<Value, Box<dyn Error>>("structured regression changed variant".into()),
            }
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let fragments_are_inert = corpus.truncated_tool_fragments.iter().all(|fragment| {
        matches!(
            CompleteToolCall::try_from(ProviderStreamEvent::ToolCallDelta {
                sequence: 0,
                correlation_id: "regression-correlation".to_owned(),
                delta: ProviderToolCallDelta::ArgumentsFragment(fragment.clone()),
            }),
            Err(CompleteToolCallError::NotComplete)
        )
    });
    let snapshots = corpus
        .stream_chunk_plans
        .iter()
        .map(|plan| text_stream(&corpus.stream_text, plan).map(|(_, snapshot)| snapshot))
        .collect::<Result<Vec<_>, _>>()?;
    let usage_overflows = corpus.usage_overflow_cases.iter().all(|case| {
        EvalUsage::new(case.left.0, case.left.1, case.left.2)
            .checked_add(EvalUsage::new(case.right.0, case.right.1, case.right.2))
            .is_none()
    });

    assert!(
        corpus.schema_version == "1.0.0"
            && decoded_roots == corpus.arbitrary_json_roots
            && fragments_are_inert
            && snapshots.windows(2).all(|pair| pair[0] == pair[1])
            && usage_overflows
    );
    Ok(())
}

#[test]
fn usage_checked_add_rejects_every_overflow_branch() {
    let token_overflow =
        EvalUsage::new(Some(u64::MAX), None, 0).checked_add(EvalUsage::new(Some(1), None, 0));
    let output_overflow =
        EvalUsage::new(None, Some(u64::MAX), 0).checked_add(EvalUsage::new(None, Some(1), 0));
    let cost_overflow =
        EvalUsage::new(None, None, u64::MAX).checked_add(EvalUsage::new(None, None, 1));

    assert_eq!(
        (token_overflow, output_overflow, cost_overflow),
        (None, None, None)
    );
}

#[test]
fn rig_provider_catalog_public_contract_is_complete_and_versioned() {
    let direct = DirectProvider::ALL.map(|provider| {
        (
            provider.as_str(),
            provider.catalog_provider().adapter_module(),
        )
    });
    let catalog = CatalogProvider::ALL.map(CatalogProvider::as_str);

    assert_eq!(
        (direct, catalog, RIG_COMPATIBILITY_VERSION),
        (
            [
                ("openai", "llm-provider-rig"),
                ("anthropic", "llm-provider-rig"),
                ("gemini", "llm-provider-rig"),
                ("openrouter", "llm-provider-rig"),
            ],
            [
                "openai",
                "anthropic",
                "gemini",
                "openrouter",
                "bedrock",
                "vertex"
            ],
            "0.42.0",
        )
    );
}

#[tokio::test]
async fn bounded_delivery_applies_capacity_and_pre_cancelled_failure_without_waiting()
-> Result<(), Box<dyn Error>> {
    let mut assembler = LlmStreamAssembler::new(
        LlmRequestId::new("request-delivery".to_owned())?,
        stream_limits(),
    );
    let event = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-delivery".to_owned(),
    })?;
    let cancellation = CancellationToken::new();
    let far_future = OffsetDateTime::UNIX_EPOCH + time::Duration::days(365 * 200);
    let (sender, mut receiver) = bounded_stream(
        NonZeroUsize::MIN,
        far_future,
        cancellation.clone(),
        ConsumerOwnership::Interactive,
    );
    sender.send(event.clone()).await?;
    let full_capacity = sender.remaining_capacity();
    let delivered_event = receiver.recv().await?;
    cancellation.cancel();
    let cancelled = sender.send(event).await;

    assert_eq!(
        (full_capacity, delivered_event.is_some(), cancelled),
        (0, true, Err(DeliveryError::Cancelled))
    );
    Ok(())
}
#[test]
fn unknown_provider_stream_items_retain_only_content_free_bounded_metadata() {
    let secret = "sensitive_unknown_provider_payload";
    let event = ProviderStreamEvent::UnknownProviderItem {
        sequence: 7,
        kind: "fixture_extension",
        raw: RetainedRaw::from_value(
            RawRetentionPolicy::Redacted,
            json!({"secret": secret, "items": [1, 2, 3]}),
        ),
    };
    let raw = event.retained_raw().expect("unknown item raw state");
    let summary = raw.redacted_summary().expect("redacted raw summary");
    let rendered = format!("{event:?}");

    assert_eq!(
        (
            event.sequence(),
            event.unknown_provider_kind(),
            raw.state(),
            raw.full_payload(),
            summary.kind(),
            summary.serialized_bytes() > 0,
            rendered.contains(secret),
        ),
        (
            7,
            Some("fixture_extension"),
            RawRetentionState::Redacted,
            None,
            RawPayloadKind::Object,
            true,
            false,
        )
    );
}

#[test]
fn partial_interruption_requires_public_content_and_retains_usable_prefix()
-> Result<(), Box<dyn Error>> {
    let mut empty = LlmStreamAssembler::new(
        LlmRequestId::new("request-empty-partial".to_owned())?,
        stream_limits(),
    );
    empty.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-empty-partial".to_owned(),
    })?;
    let empty_result = empty.terminate(StreamTerminalState::PartialInterrupted(
        StreamInterruption::Transport,
    ));
    let (_, snapshot) = text_stream("usable-prefix", &[1, 3, 2])?;

    assert!(matches!(
        empty_result,
        Err(StreamInvariantError::PartialWithoutPublicContent)
    ));
    assert!(
        snapshot
            == vec![AcceptedPublicContent::Text {
                part_id: "text-part".to_owned(),
                text: "usable-prefix".to_owned(),
            }]
    );
    Ok(())
}
