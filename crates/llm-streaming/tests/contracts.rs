//! Behavioral contracts for canonical bounded LLM streams.

use std::num::NonZeroUsize;

use omnius_llm_core::{
    LlmRequestId, StructuredOutputPart, StructuredValidation, ToolCallOutputPart,
    ToolResultOutputPart, ToolResultStatus,
};
use omnius_llm_streaming::{
    AcceptedPublicContent, BoundedTextCoalescer, ConsumerOwnership, DeliveryError,
    LlmStreamAssembler, LlmStreamEventData, LlmStreamPayload, LlmStreamValidator,
    StreamInterruption, StreamInvariantError, StreamLimits, StreamPartKind, StreamTerminalState,
    StreamToolCallDelta, ValidatedStructuredComplete, bounded_stream,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

fn request_id() -> Result<LlmRequestId, Box<dyn std::error::Error>> {
    Ok(LlmRequestId::new("request-157".to_owned())?)
}

fn started_text_stream() -> Result<LlmStreamAssembler, Box<dyn std::error::Error>> {
    let mut stream = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    stream.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?;
    stream.emit(LlmStreamEventData::PartStart {
        part_id: "part-1".to_owned(),
        kind: StreamPartKind::Text,
    })?;
    Ok(stream)
}

#[test]
fn assembler_allocates_strict_sequence_and_rejects_post_terminal_events()
-> Result<(), Box<dyn std::error::Error>> {
    let mut stream = started_text_stream()?;
    let text = stream.emit(LlmStreamEventData::TextDelta {
        part_id: "part-1".to_owned(),
        text: "hello".to_owned(),
    })?;
    stream.emit(LlmStreamEventData::PartComplete {
        part_id: "part-1".to_owned(),
    })?;
    let terminal = stream.terminate(StreamTerminalState::Completed)?;

    assert_eq!(
        (text.sequence(), terminal.sequence(), stream.finish()),
        (2, 4, Ok(()))
    );
    assert_eq!(
        stream.emit(LlmStreamEventData::Warning(
            omnius_llm_streaming::StreamWarningCode::EstimatedUsage,
        )),
        Err(StreamInvariantError::EventAfterTerminal)
    );
    assert_eq!(
        stream.terminate(StreamTerminalState::Completed),
        Err(StreamInvariantError::DuplicateTerminal)
    );
    Ok(())
}

#[test]
fn validator_rejects_a_skipped_sequence() -> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let start = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?;
    let mut encoded = serde_json::to_value(start)?;
    encoded["sequence"] = json!(1);
    let altered = serde_json::from_value(encoded)?;
    let mut validator = LlmStreamValidator::new(request_id()?, StreamLimits::default());

    assert_eq!(
        validator.accept(&altered),
        Err(StreamInvariantError::NonMonotonicSequence)
    );
    Ok(())
}

#[test]
fn validator_accepts_only_the_complete_ordered_terminal_stream()
-> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let events = [
        assembler.emit(LlmStreamEventData::ResponseStart {
            response_id: "response-ordered".to_owned(),
        })?,
        assembler.emit(LlmStreamEventData::PartStart {
            part_id: "part-ordered".to_owned(),
            kind: StreamPartKind::Text,
        })?,
        assembler.emit(LlmStreamEventData::TextDelta {
            part_id: "part-ordered".to_owned(),
            text: "ordered".to_owned(),
        })?,
        assembler.emit(LlmStreamEventData::PartComplete {
            part_id: "part-ordered".to_owned(),
        })?,
        assembler.terminate(StreamTerminalState::Completed)?,
    ];
    let mut validator = LlmStreamValidator::new(request_id()?, StreamLimits::default());
    for event in &events {
        validator.accept(event)?;
    }

    assert_eq!(validator.finish(), Ok(()));
    Ok(())
}

#[test]
fn validator_rejects_forged_terminal_snapshot_without_committing_terminal_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = started_text_stream()?;
    let text = assembler.emit(LlmStreamEventData::TextDelta {
        part_id: "part-1".to_owned(),
        text: "retained".to_owned(),
    })?;
    let terminal = assembler.terminate(StreamTerminalState::PartialInterrupted(
        StreamInterruption::Protocol,
    ))?;
    let mut validator = LlmStreamValidator::new(request_id()?, StreamLimits::default());
    let mut prefix = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let start = prefix.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?;
    let part = prefix.emit(LlmStreamEventData::PartStart {
        part_id: "part-1".to_owned(),
        kind: StreamPartKind::Text,
    })?;
    validator.accept(&start)?;
    validator.accept(&part)?;
    validator.accept(&text)?;

    let mut encoded = serde_json::to_value(&terminal)?;
    encoded["payload"]["data"]["accepted_public_content"] = json!([]);
    let forged = serde_json::from_value(encoded)?;
    assert_eq!(
        (validator.accept(&forged), validator.finish(),),
        (
            Err(StreamInvariantError::TerminalSnapshotMismatch),
            Err(StreamInvariantError::MissingTerminal),
        )
    );
    validator.accept(&terminal)?;
    assert_eq!(validator.finish(), Ok(()));
    Ok(())
}

#[test]
fn partial_interruption_retains_already_accepted_public_text()
-> Result<(), Box<dyn std::error::Error>> {
    let mut stream = started_text_stream()?;
    stream.emit(LlmStreamEventData::TextDelta {
        part_id: "part-1".to_owned(),
        text: "usable partial".to_owned(),
    })?;
    let terminal = stream.terminate(StreamTerminalState::PartialInterrupted(
        StreamInterruption::Transport,
    ))?;
    let Some(terminal) = terminal.terminal() else {
        return Err("missing terminal payload".into());
    };

    assert!(matches!(
        terminal.accepted_public_content(),
        [AcceptedPublicContent::Text { part_id, text }]
            if part_id == "part-1" && text == "usable partial"
    ));
    Ok(())
}

#[test]
fn structured_complete_rejects_non_validated_part() -> Result<(), Box<dyn std::error::Error>> {
    let part = StructuredOutputPart::new(
        "structured-1".to_owned(),
        json!({"answer": 42}),
        StructuredValidation::Invalid,
    )?;

    assert_eq!(
        ValidatedStructuredComplete::try_from_part(part),
        Err(StreamInvariantError::StructuredValueNotValidated)
    );
    Ok(())
}

#[test]
fn partial_structured_json_cannot_form_a_complete_structured_output_part() {
    let attempted = serde_json::from_str::<Value>(r#"{"answer":"#).map(|value| {
        StructuredOutputPart::new(
            "structured-partial".to_owned(),
            value,
            StructuredValidation::Valid,
        )
    });

    assert!(attempted.is_err());
}
#[test]
fn typed_parts_require_exactly_one_complete_value() -> Result<(), Box<dyn std::error::Error>> {
    let complete = ValidatedStructuredComplete::try_from_part(StructuredOutputPart::new(
        "structured-part".to_owned(),
        json!({"answer": 42}),
        StructuredValidation::Valid,
    )?)?;
    let mut stream = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    stream.emit(LlmStreamEventData::ResponseStart {
        response_id: "structured-response".to_owned(),
    })?;
    stream.emit(LlmStreamEventData::PartStart {
        part_id: "structured-part".to_owned(),
        kind: StreamPartKind::Structured,
    })?;
    stream.emit(LlmStreamEventData::StructuredComplete(complete.clone()))?;
    assert_eq!(
        stream
            .emit(LlmStreamEventData::StructuredComplete(complete))
            .err(),
        Some(StreamInvariantError::DuplicatePartValue)
    );

    let mut missing = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    missing.emit(LlmStreamEventData::ResponseStart {
        response_id: "missing-response".to_owned(),
    })?;
    missing.emit(LlmStreamEventData::PartStart {
        part_id: "missing-part".to_owned(),
        kind: StreamPartKind::Structured,
    })?;
    assert_eq!(
        missing
            .emit(LlmStreamEventData::PartComplete {
                part_id: "missing-part".to_owned(),
            })
            .err(),
        Some(StreamInvariantError::MissingPartValue)
    );
    Ok(())
}

#[tokio::test]
async fn full_bounded_channel_unblocks_on_inherited_cancellation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let event = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?;
    let cancellation = CancellationToken::new();
    let (sender, _receiver) = bounded_stream(
        NonZeroUsize::MIN,
        OffsetDateTime::now_utc() + time::Duration::minutes(1),
        cancellation.clone(),
        ConsumerOwnership::Interactive,
    );
    sender.send(event.clone()).await?;
    let cancel = tokio::spawn(async move {
        tokio::task::yield_now().await;
        cancellation.cancel();
    });

    let result = sender.send(event).await;
    cancel.await?;
    assert_eq!(result, Err(DeliveryError::Cancelled));
    Ok(())
}

#[tokio::test]
async fn elapsed_absolute_deadline_cancels_delivery() -> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let event = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?;
    let cancellation = CancellationToken::new();
    let (sender, _receiver) = bounded_stream(
        NonZeroUsize::MIN,
        OffsetDateTime::now_utc() - time::Duration::milliseconds(1),
        cancellation.clone(),
        ConsumerOwnership::Interactive,
    );

    assert_eq!(
        (sender.send(event).await, cancellation.is_cancelled()),
        (Err(DeliveryError::DeadlineExceeded), true)
    );
    Ok(())
}

#[test]
fn consumer_disconnect_cancels_only_interactive_ownership() {
    let interactive = CancellationToken::new();
    let (_, receiver) = bounded_stream(
        NonZeroUsize::MIN,
        OffsetDateTime::now_utc() + time::Duration::minutes(1),
        interactive.clone(),
        ConsumerOwnership::Interactive,
    );
    drop(receiver);

    let durable = CancellationToken::new();
    let (_, receiver) = bounded_stream(
        NonZeroUsize::MIN,
        OffsetDateTime::now_utc() + time::Duration::minutes(1),
        durable.clone(),
        ConsumerOwnership::DurableJob,
    );
    drop(receiver);

    assert_eq!(
        (interactive.is_cancelled(), durable.is_cancelled()),
        (true, false)
    );
}

#[tokio::test]
async fn dropping_interactive_receiver_after_terminal_does_not_cancel_completed_work()
-> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let start = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "completed-response".to_owned(),
    })?;
    let terminal = assembler.terminate(StreamTerminalState::Completed)?;
    let cancellation = CancellationToken::new();
    let (sender, mut receiver) = bounded_stream(
        NonZeroUsize::new(2).ok_or("zero capacity")?,
        OffsetDateTime::now_utc() + time::Duration::minutes(1),
        cancellation.clone(),
        ConsumerOwnership::Interactive,
    );
    sender.send(start).await?;
    sender.send(terminal).await?;
    let _ = receiver.recv().await?;
    let _ = receiver.recv().await?;
    drop(receiver);

    assert!(!cancellation.is_cancelled());
    Ok(())
}
#[tokio::test]
async fn receiver_closes_logically_after_terminal_even_with_queued_events()
-> Result<(), Box<dyn std::error::Error>> {
    let mut assembler = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let start = assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "terminal-response".to_owned(),
    })?;
    let terminal = assembler.terminate(StreamTerminalState::Completed)?;
    let mut other = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    let queued_after_terminal = other.emit(LlmStreamEventData::ResponseStart {
        response_id: "must-not-deliver".to_owned(),
    })?;
    let (sender, mut receiver) = bounded_stream(
        NonZeroUsize::new(3).ok_or("zero capacity")?,
        OffsetDateTime::now_utc() + time::Duration::minutes(1),
        CancellationToken::new(),
        ConsumerOwnership::DurableJob,
    );
    sender.send(start).await?;
    sender.send(terminal).await?;
    sender.send(queued_after_terminal).await?;

    assert!(receiver.recv().await?.is_some());
    assert!(receiver.recv().await?.is_some());
    assert!(receiver.recv().await?.is_none());
    Ok(())
}

#[test]
fn completed_tool_correlation_rejects_late_fragments_and_unknown_results()
-> Result<(), Box<dyn std::error::Error>> {
    let mut stream = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    stream.emit(LlmStreamEventData::ResponseStart {
        response_id: "tool-response".to_owned(),
    })?;
    stream.emit(LlmStreamEventData::PartStart {
        part_id: "tool-part".to_owned(),
        kind: StreamPartKind::ToolCall,
    })?;
    stream.emit(LlmStreamEventData::ToolCallComplete {
        correlation_id: "tool-correlation".to_owned(),
        part: ToolCallOutputPart::new(
            "tool-part".to_owned(),
            "call-1".to_owned(),
            "widgets.update".to_owned(),
            json!({"value": 1}),
        )?,
    })?;
    let late_delta = stream.emit(LlmStreamEventData::ToolCallDelta {
        part_id: "tool-part".to_owned(),
        correlation_id: "tool-correlation".to_owned(),
        delta: StreamToolCallDelta::ArgumentsFragment("}".to_owned()),
    });

    let mut unknown_result = LlmStreamAssembler::new(request_id()?, StreamLimits::default());
    unknown_result.emit(LlmStreamEventData::ResponseStart {
        response_id: "result-response".to_owned(),
    })?;
    unknown_result.emit(LlmStreamEventData::PartStart {
        part_id: "result-part".to_owned(),
        kind: StreamPartKind::ToolResult,
    })?;
    let result = unknown_result.emit(LlmStreamEventData::ToolResultComplete(
        ToolResultOutputPart::new(
            "result-part".to_owned(),
            "never-called".to_owned(),
            ToolResultStatus::Success,
            Vec::new(),
        )?,
    ));

    assert_eq!(
        (late_delta.err(), result.err(),),
        (
            Some(StreamInvariantError::DuplicatePartValue),
            Some(StreamInvariantError::UnknownToolCallIdentity),
        )
    );
    Ok(())
}

#[test]
fn serialized_event_payload_limit_rejects_one_oversized_public_value()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = StreamLimits::default()
        .with_max_event_bytes(NonZeroUsize::new(128).ok_or("zero event limit")?);
    let mut stream = LlmStreamAssembler::new(request_id()?, limits);

    assert_eq!(
        stream
            .emit(LlmStreamEventData::ResponseStart {
                response_id: "x".repeat(256),
            })
            .err(),
        Some(StreamInvariantError::EventPayloadLimitExceeded)
    );
    Ok(())
}
#[test]
fn full_event_envelope_and_terminal_snapshot_share_the_byte_ceiling()
-> Result<(), Box<dyn std::error::Error>> {
    let start = LlmStreamEventData::ResponseStart {
        response_id: "response".to_owned(),
    };
    let payload_bytes = serde_json::to_vec(&start)?.len();
    let limits = StreamLimits::default()
        .with_max_event_bytes(NonZeroUsize::new(payload_bytes).ok_or("zero serialized payload")?);
    let mut envelope_limited = LlmStreamAssembler::new(request_id()?, limits);
    assert_eq!(
        envelope_limited.emit(start).err(),
        Some(StreamInvariantError::EventPayloadLimitExceeded)
    );

    let limits = StreamLimits::default()
        .with_max_event_bytes(NonZeroUsize::new(512).ok_or("zero event limit")?);
    let mut stream = LlmStreamAssembler::new(request_id()?, limits);
    stream.emit(LlmStreamEventData::ResponseStart {
        response_id: "response".to_owned(),
    })?;
    stream.emit(LlmStreamEventData::PartStart {
        part_id: "part".to_owned(),
        kind: StreamPartKind::Text,
    })?;
    let mut rejected = false;
    for _ in 0..100 {
        match stream.emit(LlmStreamEventData::TextDelta {
            part_id: "part".to_owned(),
            text: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_owned(),
        }) {
            Ok(_) => {}
            Err(StreamInvariantError::EventPayloadLimitExceeded) => {
                rejected = true;
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    assert!(rejected);
    let terminal = stream.terminate(StreamTerminalState::PartialInterrupted(
        StreamInterruption::Transport,
    ))?;
    assert!(serde_json::to_vec(&terminal)?.len() <= limits.max_event_bytes());
    Ok(())
}

#[test]
fn text_coalescing_never_exceeds_its_byte_ceiling() -> Result<(), Box<dyn std::error::Error>> {
    let mut coalescer = BoundedTextCoalescer::new(NonZeroUsize::new(5).ok_or("zero")?);
    assert_eq!(coalescer.push("abc")?, None);
    assert_eq!(coalescer.push("de")?, None);
    assert_eq!(coalescer.push("f")?, Some("abcde".to_owned()));
    assert_eq!(coalescer.flush(), Some("f".to_owned()));
    assert_eq!(coalescer.buffered_bytes(), 0);
    Ok(())
}

#[test]
fn terminal_payload_is_the_only_terminal_algebra_variant() -> Result<(), Box<dyn std::error::Error>>
{
    let mut stream = started_text_stream()?;
    stream.emit(LlmStreamEventData::TextDelta {
        part_id: "part-1".to_owned(),
        text: "partial".to_owned(),
    })?;
    let terminal = stream.terminate(StreamTerminalState::PartialInterrupted(
        StreamInterruption::Protocol,
    ))?;

    assert!(matches!(terminal.payload(), LlmStreamPayload::Terminal(_)));
    Ok(())
}
