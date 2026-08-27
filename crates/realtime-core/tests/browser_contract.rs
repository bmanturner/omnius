//! Authoritative browser-message registry contracts.

use std::collections::BTreeSet;

use omnius_realtime_core::{
    BrowserCorrelation, BrowserMessageDirection, BrowserMessageIdentity, BrowserPayload,
    COMMAND_REJECTED_MESSAGE_TYPE, PING_MESSAGE_TYPE, PONG_MESSAGE_TYPE, PROTOCOL_VERSION,
    SUBSCRIBE_MESSAGE_TYPE, SUBSCRIPTION_CREATED_MESSAGE_TYPE, SUBSCRIPTION_DELETED_MESSAGE_TYPE,
    SUBSCRIPTION_REVOKED_MESSAGE_TYPE, UNSUBSCRIBE_MESSAGE_TYPE, browser_message_contracts,
};

#[test]
fn static_registry_covers_transport_and_sse_control_messages_once() {
    let actual = browser_message_contracts()
        .iter()
        .filter_map(|contract| contract.identity().static_name())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        SUBSCRIBE_MESSAGE_TYPE,
        UNSUBSCRIBE_MESSAGE_TYPE,
        PING_MESSAGE_TYPE,
        SUBSCRIPTION_CREATED_MESSAGE_TYPE,
        SUBSCRIPTION_DELETED_MESSAGE_TYPE,
        COMMAND_REJECTED_MESSAGE_TYPE,
        PONG_MESSAGE_TYPE,
        SUBSCRIPTION_REVOKED_MESSAGE_TYPE,
        "reconnect",
    ]);

    assert_eq!(actual, expected);
}

#[test]
fn domain_event_family_is_server_emitted_on_both_browser_transports() {
    let domain_event = browser_message_contracts()
        .iter()
        .find(|contract| contract.identity() == BrowserMessageIdentity::DomainEventV1);

    assert!(matches!(
        domain_event,
        Some(contract)
            if contract.component_name() == "BrowserDomainEventV1"
                && contract.version() == PROTOCOL_VERSION
                && contract.direction() == BrowserMessageDirection::ServerToClient
                && contract.correlation() == BrowserCorrelation::Nullable
                && contract.payload() == BrowserPayload::DomainEvent
                && contract.websocket()
                && contract.sse()
    ));
}

#[test]
fn sse_reconnect_hint_is_text_only_and_not_a_websocket_envelope() {
    let reconnect = browser_message_contracts()
        .iter()
        .find(|contract| contract.component_name() == "SseReconnectV1");

    assert!(matches!(
        reconnect,
        Some(contract)
            if contract.identity() == BrowserMessageIdentity::Static("reconnect")
                && contract.direction() == BrowserMessageDirection::ServerToClient
                && contract.payload() == BrowserPayload::SseReconnect
                && !contract.websocket()
                && contract.sse()
    ));
}

#[test]
fn registry_component_names_are_unique() {
    let names = browser_message_contracts()
        .iter()
        .map(omnius_realtime_core::BrowserMessageContract::component_name)
        .collect::<BTreeSet<_>>();

    assert_eq!(names.len(), browser_message_contracts().len());
}
