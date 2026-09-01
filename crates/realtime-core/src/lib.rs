//! Transport-neutral realtime protocol, bounded registry, delivery, and fan-out routing.
//!
//! Transport adapters authenticate and register a canonical principal, activate the connection,
//! parse commands with [`InboundCommand::parse`], and pass them to [`RealtimeService::handle`].
//! Topic names and cursors are routing data only: [`CommandAuthorizationResolver`] supplies the
//! authoritative action, resource facts, and authorization context for every command.
//! Provider adapters exchange [`CanonicalFanoutEvent`] records through [`FanoutWireCodec`], while
//! [`FanoutRouter`] refreshes authorization and emits transport-neutral bounded intents.
//!
//! This crate owns connection-scoped bounded delivery and drain policy, but no WebSocket/SSE
//! lifecycle, provider connection, replay store, or transport write.

#![forbid(unsafe_code)]

mod browser_contract;
mod delivery;
mod fanout;
mod protocol;
mod registry;
mod runtime;
mod service;

pub use browser_contract::{
    BrowserCorrelation, BrowserMessageContract, BrowserMessageDirection, BrowserMessageIdentity,
    BrowserPayload, browser_message_contracts,
};
pub use delivery::{
    ConnectionDeliveryHub, ConnectionDeliveryReceiver, ConnectionDeliverySink,
    DEFAULT_DELIVERY_BYTES_PER_CONNECTION, DEFAULT_DELIVERY_DRAIN_TIMEOUT,
    DEFAULT_DELIVERY_MESSAGES_PER_CONNECTION, DEFAULT_DELIVERY_TOTAL_BYTES, DeliveryDrainOutcome,
    DeliveryError, DeliveryMessage, DeliveryMetricsSnapshot, DeliveryPriority, DeliveryQueueConfig,
    DeliveryQueueConfigError, DeliveryReservation, DeliveryStatus, DeliveryTerminal,
    MAX_DELIVERY_BYTES_PER_CONNECTION, MAX_DELIVERY_DRAIN_TIMEOUT,
    MAX_DELIVERY_MESSAGES_PER_CONNECTION, MAX_DELIVERY_TOTAL_BYTES, QueuedDelivery,
    SlowConsumerPolicy,
};
pub use fanout::{
    CanonicalFanoutEvent, FANOUT_WIRE_VERSION, FanoutAuthorizer, FanoutCodecError,
    FanoutDeliveryIntent, FanoutIntentPriority, FanoutIntentReservation, FanoutIntentSink,
    FanoutReservationContext, FanoutRouteError, FanoutRouter, FanoutRouterConfig,
    FanoutRouterConfigError, FanoutTarget, FanoutWireCodec, FanoutWireMode,
    MAX_FANOUT_AUTHORIZATION_CONCURRENCY, MAX_FANOUT_AUTHORIZATION_TIMEOUT, MAX_FANOUT_EVENT_BYTES,
    MAX_FANOUT_IN_FLIGHT, MAX_FANOUT_RESERVED_BYTES, MAX_FANOUT_ROUTE_TIMEOUT,
};
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
    RegistryError, SubscriptionSnapshot, SubscriptionState, TopicSubscriptionCursor,
};
pub use runtime::{RealtimeRuntime, RealtimeShutdownReport};
pub use service::{
    AuthorizationCommand, CommandAuthorizationResolver, PING_ACTION, RealtimeService,
    ResolvedAuthorization, SUBSCRIBE_ACTION, UNSUBSCRIBE_ACTION,
};
