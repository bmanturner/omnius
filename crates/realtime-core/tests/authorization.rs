//! Realtime command authorization and zero-mutation denial contracts.

use std::{
    convert::Infallible,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationRequest,
    AuthorizationService, BasicPolicy, Decision, DenyReason, Grant, PolicyMatrix, PolicyRule,
    Resource, ResourceKind,
};
use omnius_realtime_core::{
    AcceptedKind, AuthorizationCommand, CommandAuthorizationResolver, ConnectionRegistry,
    InboundCommand, MessageId, OutboundMessage, PING_ACTION, PingCommand, RealtimeService,
    RegistryConfig, RejectionCode, ResolvedAuthorization, SUBSCRIBE_ACTION, SubscribeCommand,
    SubscriptionId, Topic, UNSUBSCRIBE_ACTION, UnsubscribeCommand,
};
use time::OffsetDateTime;
use uuid::Uuid;

const SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const OTHER_TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);

fn principal() -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::from_uuid(SUBJECT)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(TENANT)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn active_registry() -> Result<(ConnectionRegistry, omnius_realtime_core::ConnectionId), Box<dyn Error>>
{
    let registry = ConnectionRegistry::new(RegistryConfig::new(4, 16, 8)?);
    let connection = registry.register(principal()?)?;
    registry.activate(connection.id())?;
    Ok((registry, connection.id()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SeenAuthorization {
    action: String,
    tenant_id: Option<TenantId>,
    owner_id: Option<SubjectId>,
}

#[derive(Clone, Copy)]
enum ProviderMode {
    Allow,
    Deny,
    Fail,
}

#[derive(Clone, Copy, Debug)]
struct ProviderFailure;

impl fmt::Display for ProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("provider failed")
    }
}

impl Error for ProviderFailure {}

#[derive(Clone)]
struct RecordingProvider {
    mode: ProviderMode,
    seen: Arc<Mutex<Vec<SeenAuthorization>>>,
}

impl RecordingProvider {
    fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn seen(&self) -> Vec<SeenAuthorization> {
        match self.seen.lock() {
            Ok(seen) => seen.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl AuthorizationProvider for RecordingProvider {
    type Error = ProviderFailure;

    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        self.seen
            .lock()
            .map_err(|_| ProviderFailure)?
            .push(SeenAuthorization {
                action: request.action.as_str().into(),
                tenant_id: request.resource.tenant_id,
                owner_id: request.resource.owner_id,
            });
        match self.mode {
            ProviderMode::Allow => Ok(Decision::Allow),
            ProviderMode::Deny => Ok(Decision::Deny(DenyReason::NotEntitled)),
            ProviderMode::Fail => Err(ProviderFailure),
        }
    }
}

#[derive(Clone)]
struct TestResolver {
    subscribe_action: Action,
    unsubscribe_action: Action,
    ping_action: Action,
    subscription_kind: ResourceKind,
    connection_kind: ResourceKind,
    resource_tenant: Option<TenantId>,
    context: AuthorizationContext,
}

impl TestResolver {
    fn new(
        resource_tenant: Option<TenantId>,
        memberships: Vec<TenantId>,
    ) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            subscribe_action: Action::new(SUBSCRIBE_ACTION)?,
            unsubscribe_action: Action::new(UNSUBSCRIBE_ACTION)?,
            ping_action: Action::new(PING_ACTION)?,
            subscription_kind: ResourceKind::new("realtime_subscription")?,
            connection_kind: ResourceKind::new("realtime_connection")?,
            resource_tenant,
            context: AuthorizationContext::new(Vec::new(), memberships, Vec::new(), Vec::new())?,
        })
    }

    fn resource_for(
        kind: ResourceKind,
        owner_id: SubjectId,
        tenant_id: Option<TenantId>,
    ) -> Resource {
        let resource = Resource::new(kind).owned_by(owner_id);
        match tenant_id {
            Some(tenant_id) => resource.in_tenant(tenant_id),
            None => resource,
        }
    }
}

impl CommandAuthorizationResolver for TestResolver {
    type Error = Infallible;

    fn resolve(
        &self,
        principal: &Principal,
        command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        let resolved = match command {
            AuthorizationCommand::Subscribe(_) => ResolvedAuthorization::new(
                self.subscribe_action.clone(),
                Self::resource_for(
                    self.subscription_kind.clone(),
                    principal.subject_id,
                    self.resource_tenant,
                ),
                self.context.clone(),
            ),
            AuthorizationCommand::Unsubscribe { existing, .. } => {
                let (owner_id, tenant_id) = existing.map_or(
                    (principal.subject_id, self.resource_tenant),
                    |subscription| (subscription.subject_id(), Some(subscription.tenant_id())),
                );
                ResolvedAuthorization::new(
                    self.unsubscribe_action.clone(),
                    Self::resource_for(self.subscription_kind.clone(), owner_id, tenant_id),
                    self.context.clone(),
                )
            }
            AuthorizationCommand::Ping(_) => ResolvedAuthorization::new(
                self.ping_action.clone(),
                Self::resource_for(
                    self.connection_kind.clone(),
                    principal.subject_id,
                    self.resource_tenant,
                ),
                self.context.clone(),
            ),
        };
        Ok(resolved)
    }
}

fn subscribe(subscription_id: SubscriptionId) -> Result<InboundCommand, Box<dyn Error>> {
    Ok(InboundCommand::Subscribe {
        id: MessageId::new(),
        correlation_id: None,
        command: SubscribeCommand::new(subscription_id, Topic::new("orders/private")?, None),
    })
}

fn unsubscribe(subscription_id: SubscriptionId) -> InboundCommand {
    InboundCommand::Unsubscribe {
        id: MessageId::new(),
        correlation_id: None,
        command: UnsubscribeCommand::new(subscription_id),
    }
}

fn ping() -> InboundCommand {
    InboundCommand::Ping {
        id: MessageId::new(),
        correlation_id: None,
        command: PingCommand::new(),
    }
}

fn rejection_code(output: &OutboundMessage) -> Option<RejectionCode> {
    match output {
        OutboundMessage::Rejected(rejection) => Some(rejection.code()),
        _ => None,
    }
}

#[test]
fn every_supported_command_uses_declared_action_and_authoritative_resource()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_uuid(TENANT)?;
    let (registry, connection_id) = active_registry()?;
    let provider = RecordingProvider::new(ProviderMode::Allow);
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(Some(tenant), vec![tenant])?,
    );
    let subscription_id = SubscriptionId::new();

    let created = service.handle(connection_id, subscribe(subscription_id)?);
    assert!(matches!(
        &created,
        OutboundMessage::Accepted(accepted)
            if matches!(accepted.kind(), AcceptedKind::SubscriptionCreated { subscription_id: id, .. } if *id == subscription_id)
    ));
    assert_eq!(registry.subscription_count()?, 1);

    let deleted = service.handle(connection_id, unsubscribe(subscription_id));
    assert!(matches!(
        &deleted,
        OutboundMessage::Accepted(accepted)
            if matches!(accepted.kind(), AcceptedKind::SubscriptionDeleted { subscription_id: id } if *id == subscription_id)
    ));
    assert_eq!(registry.subscription_count()?, 0);

    let pong = service.handle(connection_id, ping());
    assert!(matches!(pong, OutboundMessage::Control(_)));

    let seen = provider.seen();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].action, SUBSCRIBE_ACTION);
    assert_eq!(seen[1].action, UNSUBSCRIBE_ACTION);
    assert_eq!(seen[2].action, PING_ACTION);
    assert_eq!(seen[0].tenant_id, Some(tenant));
    assert_eq!(seen[1].tenant_id, Some(tenant));
    assert_eq!(seen[1].owner_id, Some(SubjectId::from_uuid(SUBJECT)?));
    Ok(())
}

#[test]
fn allowed_duplicate_subscribe_authorizes_twice_but_mutates_once() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_uuid(TENANT)?;
    let (registry, connection_id) = active_registry()?;
    let provider = RecordingProvider::new(ProviderMode::Allow);
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(Some(tenant), vec![tenant])?,
    );
    let subscription_id = SubscriptionId::new();
    let command = subscribe(subscription_id)?;

    assert!(matches!(
        service.handle(connection_id, command.clone()),
        OutboundMessage::Accepted(_)
    ));
    assert_eq!(
        rejection_code(&service.handle(connection_id, command)),
        Some(RejectionCode::Conflict)
    );
    assert_eq!(registry.subscription_count()?, 1);
    assert_eq!(provider.seen().len(), 2);
    Ok(())
}

#[test]
fn deny_and_evaluator_failure_return_same_stable_rejection_without_mutation()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_uuid(TENANT)?;
    for mode in [ProviderMode::Deny, ProviderMode::Fail] {
        let (registry, connection_id) = active_registry()?;
        let service = RealtimeService::new(
            registry.clone(),
            AuthorizationService::new(RecordingProvider::new(mode)),
            TestResolver::new(Some(tenant), vec![tenant])?,
        );
        let output = service.handle(connection_id, subscribe(SubscriptionId::new())?);
        assert_eq!(rejection_code(&output), Some(RejectionCode::Unauthorized));
        assert_eq!(registry.subscription_count()?, 0);
    }
    Ok(())
}

#[test]
fn denied_unsubscribe_and_ping_are_rejected_without_state_change() -> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_uuid(TENANT)?;
    let (registry, connection_id) = active_registry()?;
    let subscription_id = SubscriptionId::new();
    registry.add_subscription(
        connection_id,
        subscription_id,
        tenant,
        Topic::new("orders/private")?,
        None,
    )?;
    let provider = RecordingProvider::new(ProviderMode::Deny);
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(Some(tenant), vec![tenant])?,
    );

    let unsubscribe_output = service.handle(connection_id, unsubscribe(subscription_id));
    let ping_output = service.handle(connection_id, ping());
    assert_eq!(
        rejection_code(&unsubscribe_output),
        Some(RejectionCode::Unauthorized)
    );
    assert_eq!(
        rejection_code(&ping_output),
        Some(RejectionCode::Unauthorized)
    );
    assert_eq!(registry.subscription_count()?, 1);
    assert_eq!(
        provider
            .seen()
            .into_iter()
            .map(|request| request.action)
            .collect::<Vec<_>>(),
        vec![UNSUBSCRIBE_ACTION.to_owned(), PING_ACTION.to_owned()]
    );
    Ok(())
}

struct FailingResolver;

impl CommandAuthorizationResolver for FailingResolver {
    type Error = &'static str;

    fn resolve(
        &self,
        _principal: &Principal,
        _command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        Err("authoritative facts unavailable")
    }
}

#[test]
fn resolver_failure_is_redacted_and_does_not_mutate() -> Result<(), Box<dyn Error>> {
    let (registry, connection_id) = active_registry()?;
    let provider = RecordingProvider::new(ProviderMode::Allow);
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        FailingResolver,
    );

    let output = service.handle(connection_id, subscribe(SubscriptionId::new())?);
    assert_eq!(rejection_code(&output), Some(RejectionCode::Unauthorized));
    assert_eq!(registry.subscription_count()?, 0);
    assert!(provider.seen().is_empty());
    Ok(())
}

#[test]
fn nonexistent_unsubscribe_is_authorized_before_not_found_rejection() -> Result<(), Box<dyn Error>>
{
    let tenant = TenantId::from_uuid(TENANT)?;
    let (registry, connection_id) = active_registry()?;
    let provider = RecordingProvider::new(ProviderMode::Allow);
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(Some(tenant), vec![tenant])?,
    );

    let output = service.handle(connection_id, unsubscribe(SubscriptionId::new()));
    assert_eq!(rejection_code(&output), Some(RejectionCode::NotFound));
    assert_eq!(provider.seen().len(), 1);
    assert_eq!(provider.seen()[0].action, UNSUBSCRIBE_ACTION);
    assert_eq!(registry.subscription_count()?, 0);
    Ok(())
}

#[derive(Clone)]
struct DecisionRecorder {
    policy: BasicPolicy,
    decisions: Arc<Mutex<Vec<Decision>>>,
}

impl DecisionRecorder {
    fn new(policy: BasicPolicy) -> Self {
        Self {
            policy,
            decisions: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn decisions(&self) -> Vec<Decision> {
        match self.decisions.lock() {
            Ok(decisions) => decisions.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl AuthorizationProvider for DecisionRecorder {
    type Error = Infallible;

    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        let decision = self.policy.evaluate(request)?;
        if let Ok(mut decisions) = self.decisions.lock() {
            decisions.push(decision);
        }
        Ok(decision)
    }
}

fn membership_policy() -> Result<BasicPolicy, Box<dyn Error>> {
    let subscription_kind = ResourceKind::new("realtime_subscription")?;
    let connection_kind = ResourceKind::new("realtime_connection")?;
    let rules = vec![
        PolicyRule::new(
            Action::new(SUBSCRIBE_ACTION)?,
            subscription_kind.clone(),
            vec![Grant::Owner],
        )?
        .requiring_tenant_membership(),
        PolicyRule::new(
            Action::new(UNSUBSCRIBE_ACTION)?,
            subscription_kind,
            vec![Grant::Owner],
        )?
        .requiring_tenant_membership(),
        PolicyRule::new(
            Action::new(PING_ACTION)?,
            connection_kind,
            vec![Grant::Owner],
        )?
        .requiring_tenant_membership(),
    ];
    Ok(BasicPolicy::new(PolicyMatrix::new(rules)?))
}

#[test]
fn cross_tenant_missing_membership_and_missing_facts_deny_without_mutation()
-> Result<(), Box<dyn Error>> {
    let tenant = TenantId::from_uuid(TENANT)?;
    let other_tenant = TenantId::from_uuid(OTHER_TENANT)?;
    let cases = [
        (
            Some(other_tenant),
            vec![other_tenant],
            DenyReason::TenantMismatch,
        ),
        (Some(tenant), Vec::new(), DenyReason::NotTenantMember),
        (None, vec![tenant], DenyReason::MissingTenantContext),
    ];

    for (resource_tenant, memberships, expected_reason) in cases {
        let (registry, connection_id) = active_registry()?;
        let provider = DecisionRecorder::new(membership_policy()?);
        let service = RealtimeService::new(
            registry.clone(),
            AuthorizationService::new(provider.clone()),
            TestResolver::new(resource_tenant, memberships)?,
        );
        let output = service.handle(connection_id, subscribe(SubscriptionId::new())?);
        assert_eq!(rejection_code(&output), Some(RejectionCode::Unauthorized));
        assert_eq!(provider.decisions(), vec![Decision::Deny(expected_reason)]);
        assert_eq!(registry.subscription_count()?, 0);
    }
    Ok(())
}

#[test]
fn inactive_connection_rejects_before_resolution_or_mutation() -> Result<(), Box<dyn Error>> {
    let registry = ConnectionRegistry::new(RegistryConfig::new(1, 1, 1)?);
    let connection = registry.register(principal()?)?;
    let provider = RecordingProvider::new(ProviderMode::Allow);
    let tenant = TenantId::from_uuid(TENANT)?;
    let service = RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(Some(tenant), vec![tenant])?,
    );

    let output = service.handle(connection.id(), ping());
    assert_eq!(
        rejection_code(&output),
        Some(RejectionCode::ConnectionNotActive)
    );
    assert!(provider.seen().is_empty());
    assert_eq!(registry.subscription_count()?, 0);
    Ok(())
}
