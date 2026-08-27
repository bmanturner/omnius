use super::protocol::{
    COMMAND_REJECTED_MESSAGE_TYPE, PING_MESSAGE_TYPE, PONG_MESSAGE_TYPE, PROTOCOL_VERSION,
    SUBSCRIBE_MESSAGE_TYPE, SUBSCRIPTION_CREATED_MESSAGE_TYPE, SUBSCRIPTION_DELETED_MESSAGE_TYPE,
    SUBSCRIPTION_REVOKED_MESSAGE_TYPE, UNSUBSCRIBE_MESSAGE_TYPE,
};

/// The browser-visible identity represented by an `AsyncAPI` message component.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrowserMessageIdentity {
    /// One reserved transport command or control message with an exact wire discriminator.
    Static(&'static str),
    /// The generic module-owned version-1 domain-event family carried by [`crate::EventOutput`].
    DomainEventV1,
}

impl BrowserMessageIdentity {
    /// Returns the exact wire discriminator for a static transport message.
    #[must_use]
    pub const fn static_name(self) -> Option<&'static str> {
        match self {
            Self::Static(name) => Some(name),
            Self::DomainEventV1 => None,
        }
    }
}

/// The direction of a browser-facing message relative to the service.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrowserMessageDirection {
    /// The browser sends the message and the service receives it.
    ClientToServer,
    /// The service sends the message and the browser receives it.
    ServerToClient,
}

/// The exact `correlation_id` constraint for a version-1 envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrowserCorrelation {
    /// The field is required and accepts either a canonical `UUIDv7` or `null`.
    Nullable,
    /// The field is required and must be a canonical `UUIDv7`.
    Required,
    /// The field is required and must be `null` for a server-initiated message.
    Null,
}

/// The typed payload shape selected by a browser-message declaration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BrowserPayload {
    /// `subscription.create` payload containing subscription, topic, and optional cursor fields.
    SubscriptionCreate,
    /// `subscription.delete` payload containing a subscription identifier.
    SubscriptionDelete,
    /// Empty payload used by `ping` and `pong`.
    Empty,
    /// `subscription.created` payload containing subscription and topic fields.
    SubscriptionCreated,
    /// `subscription.deleted` payload containing a subscription identifier.
    SubscriptionDeleted,
    /// Redacted `command.rejected` code and fixed public message payload.
    CommandRejected,
    /// `subscription.revoked` payload containing subscription and reason fields.
    SubscriptionRevoked,
    /// Generic module-owned domain event payload containing routing and bounded data fields.
    DomainEvent,
    /// SSE-only terminal reconnect hint encoded as a named text event.
    SseReconnect,
}

/// One authoritative browser-facing realtime message declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrowserMessageContract {
    component_name: &'static str,
    identity: BrowserMessageIdentity,
    version: u16,
    direction: BrowserMessageDirection,
    correlation: BrowserCorrelation,
    payload: BrowserPayload,
    websocket: bool,
    sse: bool,
}

impl BrowserMessageContract {
    const fn new(
        component_name: &'static str,
        identity: BrowserMessageIdentity,
        direction: BrowserMessageDirection,
        correlation: BrowserCorrelation,
        payload: BrowserPayload,
        websocket: bool,
        sse: bool,
    ) -> Self {
        Self {
            component_name,
            identity,
            version: PROTOCOL_VERSION,
            direction,
            correlation,
            payload,
            websocket,
            sse,
        }
    }

    /// Returns the stable `AsyncAPI` component name.
    #[must_use]
    pub const fn component_name(&self) -> &'static str {
        self.component_name
    }

    /// Returns the wire identity represented by this declaration.
    #[must_use]
    pub const fn identity(&self) -> BrowserMessageIdentity {
        self.identity
    }

    /// Returns the exact protocol version carried in the envelope.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the message direction relative to the service.
    #[must_use]
    pub const fn direction(&self) -> BrowserMessageDirection {
        self.direction
    }

    /// Returns the exact correlation-field requirement.
    #[must_use]
    pub const fn correlation(&self) -> BrowserCorrelation {
        self.correlation
    }

    /// Returns the typed payload shape.
    #[must_use]
    pub const fn payload(&self) -> BrowserPayload {
        self.payload
    }

    /// Returns whether the message is carried by the browser WebSocket transport.
    #[must_use]
    pub const fn websocket(&self) -> bool {
        self.websocket
    }

    /// Returns whether the message can be emitted by the browser SSE transport.
    #[must_use]
    pub const fn sse(&self) -> bool {
        self.sse
    }
}

const BROWSER_MESSAGE_CONTRACTS: [BrowserMessageContract; 10] = [
    BrowserMessageContract::new(
        "SubscriptionCreateV1",
        BrowserMessageIdentity::Static(SUBSCRIBE_MESSAGE_TYPE),
        BrowserMessageDirection::ClientToServer,
        BrowserCorrelation::Nullable,
        BrowserPayload::SubscriptionCreate,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "SubscriptionDeleteV1",
        BrowserMessageIdentity::Static(UNSUBSCRIBE_MESSAGE_TYPE),
        BrowserMessageDirection::ClientToServer,
        BrowserCorrelation::Nullable,
        BrowserPayload::SubscriptionDelete,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "PingV1",
        BrowserMessageIdentity::Static(PING_MESSAGE_TYPE),
        BrowserMessageDirection::ClientToServer,
        BrowserCorrelation::Nullable,
        BrowserPayload::Empty,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "SubscriptionCreatedV1",
        BrowserMessageIdentity::Static(SUBSCRIPTION_CREATED_MESSAGE_TYPE),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Required,
        BrowserPayload::SubscriptionCreated,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "SubscriptionDeletedV1",
        BrowserMessageIdentity::Static(SUBSCRIPTION_DELETED_MESSAGE_TYPE),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Required,
        BrowserPayload::SubscriptionDeleted,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "CommandRejectedV1",
        BrowserMessageIdentity::Static(COMMAND_REJECTED_MESSAGE_TYPE),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Required,
        BrowserPayload::CommandRejected,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "PongV1",
        BrowserMessageIdentity::Static(PONG_MESSAGE_TYPE),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Required,
        BrowserPayload::Empty,
        true,
        false,
    ),
    BrowserMessageContract::new(
        "SubscriptionRevokedV1",
        BrowserMessageIdentity::Static(SUBSCRIPTION_REVOKED_MESSAGE_TYPE),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Null,
        BrowserPayload::SubscriptionRevoked,
        true,
        true,
    ),
    BrowserMessageContract::new(
        "BrowserDomainEventV1",
        BrowserMessageIdentity::DomainEventV1,
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Nullable,
        BrowserPayload::DomainEvent,
        true,
        true,
    ),
    BrowserMessageContract::new(
        "SseReconnectV1",
        BrowserMessageIdentity::Static("reconnect"),
        BrowserMessageDirection::ServerToClient,
        BrowserCorrelation::Null,
        BrowserPayload::SseReconnect,
        false,
        true,
    ),
];

/// Returns the complete authoritative browser-message registry in stable order.
#[must_use]
pub const fn browser_message_contracts() -> &'static [BrowserMessageContract] {
    &BROWSER_MESSAGE_CONTRACTS
}
