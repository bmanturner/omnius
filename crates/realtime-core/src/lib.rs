//! Transport-neutral realtime protocol, bounded registry, and authorization boundary.
//!
//! Transport adapters authenticate and register a canonical principal, activate the connection,
//! parse commands with [`InboundCommand::parse`], and pass them to [`RealtimeService::handle`].
//! Topic names and cursors are routing data only: [`CommandAuthorizationResolver`] supplies the
//! authoritative action, resource facts, and authorization context for every command.
//!
//! This crate intentionally owns no WebSocket/SSE lifecycle, fan-out provider, replay store,
//! outbound queue, backpressure policy, or drain loop.

#![forbid(unsafe_code)]

mod protocol;
mod registry;
mod service;

pub use protocol::{
    AcceptedKind, AcceptedOutput, COMMAND_REJECTED_MESSAGE_TYPE, ConnectionId, ControlOutput,
    EventOutput, InboundCommand, MAX_CURSOR_BYTES, MAX_ENVELOPE_BYTES, MAX_MESSAGE_TYPE_BYTES,
    MAX_PAYLOAD_BYTES, MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_NODES, MAX_TOPIC_BYTES, MessageId,
    MessageType, ObjectPayload, OpaqueCursor, OutboundMessage, PING_MESSAGE_TYPE,
    PONG_MESSAGE_TYPE, PROTOCOL_VERSION, PayloadError, PingCommand, PortableStringError,
    ProtocolEnvelope, ProtocolError, RejectedOutput, RejectionCode, RevocationReason,
    SUBSCRIBE_MESSAGE_TYPE, SUBSCRIPTION_CREATED_MESSAGE_TYPE, SUBSCRIPTION_DELETED_MESSAGE_TYPE,
    SUBSCRIPTION_REVOKED_MESSAGE_TYPE, SubscribeCommand, SubscriptionId, Topic,
    UNSUBSCRIBE_MESSAGE_TYPE, UnsubscribeCommand, WireIdError,
};
pub use registry::{
    ConnectionRegistry, ConnectionSnapshot, ConnectionState, ControlIntent, MAX_CONNECTIONS,
    MAX_SUBSCRIPTIONS, MAX_SUBSCRIPTIONS_PER_CONNECTION, RegistryConfig, RegistryConfigError,
    RegistryError, SubscriptionSnapshot, SubscriptionState,
};
pub use service::{
    AuthorizationCommand, CommandAuthorizationResolver, PING_ACTION, RealtimeService,
    ResolvedAuthorization, SUBSCRIBE_ACTION, UNSUBSCRIBE_ACTION,
};
