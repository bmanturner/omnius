use rsk_auth_core::Principal;
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationService, Decision, Resource,
};

use crate::{
    protocol::{
        AcceptedOutput, InboundCommand, OutboundMessage, PingCommand, RejectedOutput,
        RejectionCode, SubscribeCommand, UnsubscribeCommand,
    },
    registry::{
        ConnectionRegistry, ConnectionSnapshot, ConnectionState, RegistryError,
        SubscriptionSnapshot,
    },
};

/// Declared application action for `subscription.create`.
pub const SUBSCRIBE_ACTION: &str = "realtime.subscription.create";
/// Declared application action for `subscription.delete`.
pub const UNSUBSCRIBE_ACTION: &str = "realtime.subscription.delete";
/// Declared application action for `ping`.
pub const PING_ACTION: &str = "realtime.ping";

/// One validated command presented to an authoritative authorization resolver.
#[derive(Clone, Copy, Debug)]
pub enum AuthorizationCommand<'a> {
    /// A validated request to create a subscription.
    Subscribe(&'a SubscribeCommand),
    /// A validated request to remove a subscription.
    Unsubscribe {
        /// The validated command payload.
        command: &'a UnsubscribeCommand,
        /// The existing connection-owned subscription when one exists.
        ///
        /// A resolver must use this record—not topic text or caller-supplied facts—to describe an
        /// existing subscription resource. `None` allows authorization to remain fail-closed for
        /// identifiers that are missing or belong to another connection.
        existing: Option<&'a SubscriptionSnapshot>,
    },
    /// A validated heartbeat command.
    Ping(&'a PingCommand),
}

impl AuthorizationCommand<'_> {
    /// Returns the canonical declared action required for this command.
    #[must_use]
    pub const fn declared_action(self) -> &'static str {
        match self {
            Self::Subscribe(_) => SUBSCRIBE_ACTION,
            Self::Unsubscribe { .. } => UNSUBSCRIBE_ACTION,
            Self::Ping(_) => PING_ACTION,
        }
    }
}

/// Owned authoritative facts for one application-service authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedAuthorization {
    action: Action,
    resource: Resource,
    context: AuthorizationContext,
}

impl ResolvedAuthorization {
    /// Creates a complete authorization resolution.
    #[must_use]
    pub const fn new(action: Action, resource: Resource, context: AuthorizationContext) -> Self {
        Self {
            action,
            resource,
            context,
        }
    }

    /// Returns the declared application action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    /// Returns authoritative resource facts.
    #[must_use]
    pub const fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Returns authoritative request context.
    #[must_use]
    pub const fn context(&self) -> &AuthorizationContext {
        &self.context
    }
}

/// Resolves validated realtime commands to authoritative authorization facts.
///
/// Implementations belong at the application-service boundary. They must load resource and tenant
/// facts from authoritative state; topic names and cursor text are never authorization evidence.
pub trait CommandAuthorizationResolver {
    /// A fact-resolution failure. The service redacts this error and rejects without mutation.
    type Error;

    /// Resolves the declared action, protected resource, and current authorization context.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error when authoritative facts cannot be established.
    fn resolve(
        &self,
        principal: &Principal,
        command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error>;
}

/// The transport-independent realtime application service.
///
/// Every active-connection command crosses the same resolver and [`AuthorizationService`]
/// boundary before mutation. Denial, evaluator failure, resolution failure, or mismatched
/// authoritative facts produces a stable rejection and no registry mutation.
pub struct RealtimeService<P, R> {
    registry: ConnectionRegistry,
    authorization: AuthorizationService<P>,
    resolver: R,
}

impl<P, R> RealtimeService<P, R>
where
    P: AuthorizationProvider,
    R: CommandAuthorizationResolver,
{
    /// Creates an authorized realtime application service.
    #[must_use]
    pub const fn new(
        registry: ConnectionRegistry,
        authorization: AuthorizationService<P>,
        resolver: R,
    ) -> Self {
        Self {
            registry,
            authorization,
            resolver,
        }
    }

    /// Returns the shared bounded registry.
    #[must_use]
    pub const fn registry(&self) -> &ConnectionRegistry {
        &self.registry
    }

    /// Validates connection state, resolves authoritative facts, authorizes, and handles a command.
    ///
    /// The returned output is transport-neutral and safe to encode for an adapter. Authorization
    /// denials and provider errors intentionally share the same public rejection category.
    #[must_use]
    pub fn handle(
        &self,
        connection_id: crate::protocol::ConnectionId,
        command: InboundCommand,
    ) -> OutboundMessage {
        let command_id = command.id();
        let connection = match self.active_connection(connection_id) {
            Ok(connection) => connection,
            Err(code) => {
                return OutboundMessage::Rejected(RejectedOutput::new(command_id, code));
            }
        };

        match command {
            InboundCommand::Subscribe { command, .. } => {
                self.handle_subscribe(&connection, command_id, &command)
            }
            InboundCommand::Unsubscribe { command, .. } => {
                self.handle_unsubscribe(&connection, command_id, command)
            }
            InboundCommand::Ping { command, .. } => {
                self.handle_ping(&connection, command_id, command)
            }
        }
    }

    fn active_connection(
        &self,
        connection_id: crate::protocol::ConnectionId,
    ) -> Result<ConnectionSnapshot, RejectionCode> {
        match self.registry.connection(connection_id) {
            Ok(Some(connection)) if connection.state() == ConnectionState::Active => Ok(connection),
            Ok(Some(_) | None) => Err(RejectionCode::ConnectionNotActive),
            Err(_) => Err(RejectionCode::Unavailable),
        }
    }

    fn resolve_and_authorize(
        &self,
        principal: &Principal,
        command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, RejectionCode> {
        let expected_action = command.declared_action();
        let resolved = self
            .resolver
            .resolve(principal, command)
            .map_err(|_| RejectionCode::Unauthorized)?;
        let decision = self.authorization.authorize(
            principal,
            resolved.action(),
            resolved.resource(),
            resolved.context(),
        );
        if decision != Decision::Allow || resolved.action().as_str() != expected_action {
            return Err(RejectionCode::Unauthorized);
        }
        Ok(resolved)
    }

    fn handle_subscribe(
        &self,
        connection: &ConnectionSnapshot,
        command_id: crate::protocol::MessageId,
        command: &SubscribeCommand,
    ) -> OutboundMessage {
        let resolved = match self.resolve_and_authorize(
            connection.principal(),
            AuthorizationCommand::Subscribe(command),
        ) {
            Ok(resolved) => resolved,
            Err(code) => {
                return OutboundMessage::Rejected(RejectedOutput::new(command_id, code));
            }
        };
        let Some(tenant_id) = resolved.resource().tenant_id else {
            return OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                RejectionCode::Unauthorized,
            ));
        };
        let subscription_id = command.subscription_id();
        let topic = command.topic().clone();
        match self.registry.add_subscription(
            connection.id(),
            subscription_id,
            tenant_id,
            topic.clone(),
            command.cursor().cloned(),
        ) {
            Ok(_) => OutboundMessage::Accepted(AcceptedOutput::subscription_created(
                command_id,
                subscription_id,
                topic,
            )),
            Err(error) => OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                rejection_for_registry(error),
            )),
        }
    }

    fn handle_unsubscribe(
        &self,
        connection: &ConnectionSnapshot,
        command_id: crate::protocol::MessageId,
        command: UnsubscribeCommand,
    ) -> OutboundMessage {
        let subscription_id = command.subscription_id();
        let Ok(existing) = self
            .registry
            .subscription_for_connection(connection.id(), subscription_id)
        else {
            return OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                RejectionCode::Unavailable,
            ));
        };
        let resolved = match self.resolve_and_authorize(
            connection.principal(),
            AuthorizationCommand::Unsubscribe {
                command: &command,
                existing: existing.as_ref(),
            },
        ) {
            Ok(resolved) => resolved,
            Err(code) => {
                return OutboundMessage::Rejected(RejectedOutput::new(command_id, code));
            }
        };
        let Some(existing) = existing else {
            return OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                RejectionCode::NotFound,
            ));
        };
        if resolved.resource().tenant_id != Some(existing.tenant_id())
            || resolved.resource().owner_id != Some(existing.subject_id())
        {
            return OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                RejectionCode::Unauthorized,
            ));
        }

        match self
            .registry
            .remove_subscription_if_current(connection.id(), &existing)
        {
            Ok(_) => OutboundMessage::Accepted(AcceptedOutput::subscription_deleted(
                command_id,
                subscription_id,
            )),
            Err(error) => OutboundMessage::Rejected(RejectedOutput::new(
                command_id,
                rejection_for_registry(error),
            )),
        }
    }

    fn handle_ping(
        &self,
        connection: &ConnectionSnapshot,
        command_id: crate::protocol::MessageId,
        command: PingCommand,
    ) -> OutboundMessage {
        match self
            .resolve_and_authorize(connection.principal(), AuthorizationCommand::Ping(&command))
        {
            Ok(_) => OutboundMessage::Control(crate::protocol::ControlOutput::pong(command_id)),
            Err(code) => OutboundMessage::Rejected(RejectedOutput::new(command_id, code)),
        }
    }
}

const fn rejection_for_registry(error: RegistryError) -> RejectionCode {
    match error {
        RegistryError::ConnectionCapacity
        | RegistryError::SubscriptionCapacity
        | RegistryError::PerConnectionSubscriptionCapacity => RejectionCode::CapacityExceeded,
        RegistryError::DuplicateSubscription | RegistryError::SubscriptionConflict => {
            RejectionCode::Conflict
        }
        RegistryError::ConnectionNotFound | RegistryError::InvalidState => {
            RejectionCode::ConnectionNotActive
        }
        RegistryError::SubscriptionNotFound => RejectionCode::NotFound,
        RegistryError::TenantMismatch => RejectionCode::Unauthorized,
        RegistryError::Unavailable => RejectionCode::Unavailable,
    }
}
