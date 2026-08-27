//! Strict bounded realtime protocol wire contracts.

use std::error::Error;

use omnius_realtime_core::{
    AcceptedOutput, COMMAND_REJECTED_MESSAGE_TYPE, ControlOutput, EventOutput, InboundCommand,
    MAX_CURSOR_BYTES, MAX_ENVELOPE_BYTES, MAX_TOPIC_BYTES, MessageId, MessageType, ObjectPayload,
    OutboundMessage, PING_MESSAGE_TYPE, PingCommand, ProtocolEnvelope, ProtocolError,
    RejectedOutput, RejectionCode, RevocationReason, SUBSCRIBE_MESSAGE_TYPE,
    SUBSCRIPTION_CREATED_MESSAGE_TYPE, SUBSCRIPTION_REVOKED_MESSAGE_TYPE, SubscribeCommand,
    SubscriptionId, Topic,
};
use serde_json::{Value, json};

const MESSAGE: &str = "01890f2a-0000-7000-8000-000000000001";
const CORRELATION: &str = "01890f2a-0000-7000-8000-000000000002";
const SUBSCRIPTION: &str = "01890f2a-0000-7000-8000-000000000003";

#[test]
fn ping_round_trip_preserves_exact_five_field_envelope() -> Result<(), Box<dyn Error>> {
    let id: MessageId = MESSAGE.parse()?;
    let command = InboundCommand::Ping {
        id,
        correlation_id: None,
        command: PingCommand::new(),
    };

    let encoded = command.to_envelope()?.encode()?;
    assert_eq!(
        String::from_utf8(encoded.clone())?,
        format!(
            r#"{{"v":1,"id":"{MESSAGE}","type":"{PING_MESSAGE_TYPE}","correlation_id":null,"payload":{{}}}}"#
        )
    );
    assert_eq!(InboundCommand::parse(&encoded)?, command);
    Ok(())
}

#[test]
fn subscribe_round_trip_preserves_bounded_typed_payload() -> Result<(), Box<dyn Error>> {
    let command = InboundCommand::Subscribe {
        id: MESSAGE.parse()?,
        correlation_id: Some(CORRELATION.parse()?),
        command: SubscribeCommand::new(
            SUBSCRIPTION.parse()?,
            Topic::new("tenant-events/orders")?,
            Some("opaque-1".parse()?),
        ),
    };

    let encoded = command.to_envelope()?.encode()?;
    let decoded: Value = serde_json::from_slice(&encoded)?;
    assert_eq!(
        decoded,
        json!({
            "v": 1,
            "id": MESSAGE,
            "type": SUBSCRIBE_MESSAGE_TYPE,
            "correlation_id": CORRELATION,
            "payload": {
                "subscription_id": SUBSCRIPTION,
                "topic": "tenant-events/orders",
                "cursor": "opaque-1"
            }
        })
    );
    assert_eq!(InboundCommand::parse(&encoded)?, command);
    Ok(())
}

#[test]
fn envelope_rejects_missing_and_unknown_fields() {
    let missing_correlation = format!(r#"{{"v":1,"id":"{MESSAGE}","type":"ping","payload":{{}}}}"#);
    let unknown_field = format!(
        r#"{{"v":1,"id":"{MESSAGE}","type":"ping","correlation_id":null,"payload":{{}},"extra":true}}"#
    );

    assert_eq!(
        ProtocolEnvelope::parse(missing_correlation.as_bytes()),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        ProtocolEnvelope::parse(unknown_field.as_bytes()),
        Err(ProtocolError::InvalidEnvelope)
    );
}

#[test]
fn envelope_and_nested_payload_reject_duplicate_object_keys() {
    let duplicate_envelope_id = format!(
        r#"{{"v":1,"id":"{MESSAGE}","id":"{CORRELATION}","type":"ping","correlation_id":null,"payload":{{}}}}"#
    );
    let duplicate_topic = format!(
        r#"{{"v":1,"id":"{MESSAGE}","type":"subscription.create","correlation_id":null,"payload":{{"subscription_id":"{SUBSCRIPTION}","topic":"orders","topic":"private"}}}}"#
    );
    let duplicate_nested_key = format!(
        r#"{{"v":1,"id":"{MESSAGE}","type":"event.example","correlation_id":null,"payload":{{"data":{{"value":1,"value":2}}}}}}"#
    );

    assert_eq!(
        ProtocolEnvelope::parse(duplicate_envelope_id.as_bytes()),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        InboundCommand::parse(duplicate_topic.as_bytes()),
        Err(ProtocolError::InvalidEnvelope)
    );
    assert_eq!(
        ProtocolEnvelope::parse(duplicate_nested_key.as_bytes()),
        Err(ProtocolError::InvalidEnvelope)
    );
}

#[test]
fn envelope_rejects_unsupported_version_non_object_payload_and_unknown_command() {
    let unsupported =
        format!(r#"{{"v":2,"id":"{MESSAGE}","type":"ping","correlation_id":null,"payload":{{}}}}"#);
    let scalar_payload =
        format!(r#"{{"v":1,"id":"{MESSAGE}","type":"ping","correlation_id":null,"payload":true}}"#);
    let unknown = format!(
        r#"{{"v":1,"id":"{MESSAGE}","type":"other.command","correlation_id":null,"payload":{{}}}}"#
    );

    assert_eq!(
        InboundCommand::parse(unsupported.as_bytes()),
        Err(ProtocolError::UnsupportedVersion)
    );
    assert_eq!(
        InboundCommand::parse(scalar_payload.as_bytes()),
        Err(ProtocolError::InvalidPayload)
    );
    assert_eq!(
        InboundCommand::parse(unknown.as_bytes()),
        Err(ProtocolError::UnknownCommand)
    );
}

#[test]
fn identifiers_must_be_canonical_uuid_v7_values() {
    let non_v7 = "550e8400-e29b-41d4-a716-446655440000";
    let non_canonical = MESSAGE.to_ascii_uppercase();
    let non_v7_envelope =
        format!(r#"{{"v":1,"id":"{non_v7}","type":"ping","correlation_id":null,"payload":{{}}}}"#);
    let non_canonical_envelope = format!(
        r#"{{"v":1,"id":"{non_canonical}","type":"ping","correlation_id":null,"payload":{{}}}}"#
    );

    assert_eq!(
        InboundCommand::parse(non_v7_envelope.as_bytes()),
        Err(ProtocolError::InvalidIdentifier)
    );
    assert_eq!(
        InboundCommand::parse(non_canonical_envelope.as_bytes()),
        Err(ProtocolError::InvalidIdentifier)
    );
}

#[test]
fn input_size_is_rejected_before_json_decoding() {
    let oversized = vec![b'x'; MAX_ENVELOPE_BYTES + 1];
    assert_eq!(
        ProtocolEnvelope::parse(&oversized),
        Err(ProtocolError::EnvelopeTooLarge)
    );
}

#[test]
fn topic_cursor_and_payload_fields_enforce_fixed_bounds() -> Result<(), Box<dyn Error>> {
    let oversized_topic = "a".repeat(MAX_TOPIC_BYTES + 1);
    let topic_command = serde_json::to_vec(&json!({
        "v": 1,
        "id": MESSAGE,
        "type": SUBSCRIBE_MESSAGE_TYPE,
        "correlation_id": null,
        "payload": {
            "subscription_id": SUBSCRIPTION,
            "topic": oversized_topic
        }
    }))?;
    let oversized_cursor = "c".repeat(MAX_CURSOR_BYTES + 1);
    let cursor_command = serde_json::to_vec(&json!({
        "v": 1,
        "id": MESSAGE,
        "type": SUBSCRIBE_MESSAGE_TYPE,
        "correlation_id": null,
        "payload": {
            "subscription_id": SUBSCRIPTION,
            "topic": "orders",
            "cursor": oversized_cursor
        }
    }))?;
    let extra_payload_field = format!(
        r#"{{"v":1,"id":"{MESSAGE}","type":"ping","correlation_id":null,"payload":{{"trace":"not-allowed"}}}}"#
    );

    assert_eq!(
        InboundCommand::parse(&topic_command),
        Err(ProtocolError::InvalidPayload)
    );
    assert_eq!(
        InboundCommand::parse(&cursor_command),
        Err(ProtocolError::InvalidPayload)
    );
    assert_eq!(
        InboundCommand::parse(extra_payload_field.as_bytes()),
        Err(ProtocolError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn protocol_and_rejection_errors_are_stable_and_redacted() -> Result<(), Box<dyn Error>> {
    let secret = "secret-topic/customer@example.test";
    let malformed = format!("{{not-json:{secret}}}");
    let error = ProtocolEnvelope::parse(malformed.as_bytes()).err();
    assert_eq!(error, Some(ProtocolError::InvalidEnvelope));
    assert!(
        !error
            .map_or(String::new(), |value| value.to_string())
            .contains(secret)
    );

    let rejection = OutboundMessage::Rejected(RejectedOutput::new(
        MESSAGE.parse()?,
        RejectionCode::Unauthorized,
    ))
    .into_envelope()?;
    assert_eq!(
        rejection.message_type().as_str(),
        COMMAND_REJECTED_MESSAGE_TYPE
    );
    assert_eq!(
        rejection.payload().as_map(),
        ObjectPayload::new(
            json!({
                "code": "unauthorized",
                "message": "command is not authorized"
            })
            .as_object()
            .cloned()
            .ok_or("expected object")?
        )?
        .as_map()
    );
    Ok(())
}

#[test]
fn subscription_identifier_payload_rejects_non_v7_uuid() -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_vec(&json!({
        "v": 1,
        "id": MESSAGE,
        "type": SUBSCRIBE_MESSAGE_TYPE,
        "correlation_id": null,
        "payload": {
            "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
            "topic": "orders"
        }
    }))?;
    assert_eq!(
        InboundCommand::parse(&encoded),
        Err(ProtocolError::InvalidPayload)
    );
    Ok(())
}

#[test]
fn command_constructors_accept_only_validated_subscription_ids() -> Result<(), Box<dyn Error>> {
    let subscription: SubscriptionId = SUBSCRIPTION.parse()?;
    let command = SubscribeCommand::new(subscription, Topic::new("orders")?, None);
    assert_eq!(command.subscription_id(), subscription);
    Ok(())
}

#[test]
fn accepted_event_and_control_outputs_use_structured_v1_envelopes() -> Result<(), Box<dyn Error>> {
    let command_id: MessageId = MESSAGE.parse()?;
    let subscription_id: SubscriptionId = SUBSCRIPTION.parse()?;
    let topic = Topic::new("orders")?;

    let accepted = OutboundMessage::Accepted(AcceptedOutput::subscription_created(
        command_id,
        subscription_id,
        topic.clone(),
    ))
    .into_envelope()?;
    assert_eq!(
        accepted.message_type().as_str(),
        SUBSCRIPTION_CREATED_MESSAGE_TYPE
    );
    assert_eq!(accepted.correlation_id(), Some(command_id));
    assert_eq!(
        accepted.payload().as_map().get("subscription_id"),
        Some(&Value::String(SUBSCRIPTION.into()))
    );

    let control = OutboundMessage::Control(ControlOutput::subscription_revoked(
        subscription_id,
        RevocationReason::AuthorizationChanged,
    ))
    .into_envelope()?;
    assert_eq!(
        control.message_type().as_str(),
        SUBSCRIPTION_REVOKED_MESSAGE_TYPE
    );
    assert_eq!(control.correlation_id(), None);

    let data = ObjectPayload::new(
        json!({ "status": "paid" })
            .as_object()
            .cloned()
            .ok_or("expected event object")?,
    )?;
    let event = OutboundMessage::Event(EventOutput::new(
        MessageType::new("order.changed")?,
        Some(command_id),
        subscription_id,
        topic,
        Some("opaque-event-cursor".parse()?),
        data,
    ))
    .into_envelope()?;
    let encoded = event.encode()?;
    let decoded = ProtocolEnvelope::parse(&encoded)?;
    assert_eq!(decoded.message_type().as_str(), "order.changed");
    assert_eq!(decoded.correlation_id(), Some(command_id));
    assert_eq!(
        decoded.payload().as_map().get("data"),
        Some(&json!({ "status": "paid" }))
    );
    Ok(())
}
