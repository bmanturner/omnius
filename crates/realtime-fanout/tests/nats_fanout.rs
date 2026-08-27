//! Real Core NATS composition contracts for canonical authorized multi-instance fan-out.

mod support;

use std::{
    convert::Infallible,
    error::Error,
    future::{Future, ready},
    io,
    sync::Arc,
    time::Duration,
};

use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_events_nats::{
    NatsAuthConfig, NatsConnectionConfig, NatsCoreFanout, NatsCoreFanoutConfig,
    NatsCoreFanoutLifecycle, NatsCoreFanoutStatus,
};
use omnius_realtime_core::{
    CanonicalFanoutEvent, ConnectionDeliveryHub, ConnectionRegistry, DeliveryQueueConfig,
    FanoutAuthorizer, FanoutDeliveryIntent, FanoutRouter, FanoutRouterConfig, MessageId,
    MessageType, ObjectPayload, ProtocolEnvelope, QueuedDelivery, RegistryConfig, SubscriptionId,
    SubscriptionSnapshot, Topic,
};
use omnius_realtime_fanout::{NatsFanoutIngress, NatsFanoutPublisher};
use omnius_runtime::{Supervisor, SupervisorHandle};
use omnius_test_support::NatsCoreFanoutRoleFixture;
use support::CollectingSink;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

const SUBJECT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const SUBJECT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
const TENANT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const TENANT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);
const SOURCE_ID: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0021);

#[derive(Clone, Copy)]
struct Allow;

impl FanoutAuthorizer for Allow {
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        _subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        ready(Ok(true))
    }
}

fn principal(subject: Uuid, tenant: Uuid) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::from_uuid(subject)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(tenant)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn add_subscription(
    registry: &ConnectionRegistry,
    subject: Uuid,
    tenant: Uuid,
    topic: &Topic,
) -> Result<SubscriptionId, Box<dyn Error>> {
    let tenant_id = TenantId::from_uuid(tenant)?;
    let connection = registry.register(principal(subject, tenant)?)?;
    registry.activate(connection.id())?;
    let subscription_id = SubscriptionId::new();
    registry.add_subscription(
        connection.id(),
        subscription_id,
        tenant_id,
        topic.clone(),
        None,
    )?;
    Ok(subscription_id)
}

fn connection_config(url: &SecretString) -> Result<NatsConnectionConfig, Box<dyn Error>> {
    let mut parsed = Url::parse(url.expose_secret())?;
    let username = parsed.username().to_owned();
    let password = parsed
        .password()
        .ok_or_else(|| io::Error::other("fixture URL has no password"))?
        .to_owned();
    parsed
        .set_username("")
        .map_err(|()| io::Error::other("fixture URL username could not be removed"))?;
    parsed
        .set_password(None)
        .map_err(|()| io::Error::other("fixture URL password could not be removed"))?;
    let mut config = NatsConnectionConfig::new(
        SecretString::from(parsed.to_string()),
        NatsAuthConfig::UserPassword {
            username: SecretString::from(username),
            password: SecretString::from(password),
        },
    );
    config.tls_required = false;
    config.operation_timeout = Duration::from_secs(2);
    config.connection_timeout = Duration::from_secs(2);
    Ok(config)
}

fn provider_config(subject: &str) -> NatsCoreFanoutConfig {
    let mut config = NatsCoreFanoutConfig::new(subject.to_owned());
    config.ingress_capacity = 8;
    config.max_message_bytes = 16 * 1024;
    config.shutdown_timeout = Duration::from_secs(1);
    config.restart.initial_backoff = Duration::from_millis(20);
    config.restart.max_backoff = Duration::from_millis(50);
    config.restart.jitter_percent = 0;
    config
}

fn start(task: omnius_runtime::TaskSpec) -> Result<SupervisorHandle, Box<dyn Error>> {
    let mut supervisor = Supervisor::new();
    supervisor.register(task)?;
    Ok(supervisor.start()?)
}

async fn wait_stopped(status: &mut NatsCoreFanoutStatus) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while status.lifecycle() != NatsCoreFanoutLifecycle::Stopped {
            status.changed().await?;
        }
        Ok::<_, omnius_events_nats::NatsCoreFanoutStatusError>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn canonical_event_reaches_both_ready_instances_without_replay_or_tenant_crossover()
-> Result<(), Box<dyn Error>> {
    let fixture = NatsCoreFanoutRoleFixture::start().await?;
    let connection = connection_config(fixture.runtime_url())?;
    let first = NatsCoreFanout::connect(
        &connection,
        provider_config(fixture.subject()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let second = NatsCoreFanout::connect(
        &connection,
        provider_config(fixture.subject()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let (provider_publisher, mut first_receiver, mut first_status, first_task) = first.into_parts();
    let (_, mut second_receiver, mut second_status, second_task) = second.into_parts();
    let publisher = NatsFanoutPublisher::new(provider_publisher);

    let topic = Topic::new("orders/changed")?;
    let tenant_one = TenantId::from_uuid(TENANT_ONE)?;
    let source_id = MessageId::from_uuid(SOURCE_ID)?;
    let event = CanonicalFanoutEvent::new(
        source_id,
        tenant_one,
        topic.clone(),
        MessageType::new("order.changed")?,
        None,
        ObjectPayload::empty(),
    );

    publisher.publish(&event).await?;
    assert!(first_receiver.try_recv().is_err());
    assert!(second_receiver.try_recv().is_err());

    let first_registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(4, 8, 4)?));
    let second_registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(4, 8, 4)?));
    let first_subscription = add_subscription(&first_registry, SUBJECT_ONE, TENANT_ONE, &topic)?;
    let second_subscription = add_subscription(&second_registry, SUBJECT_ONE, TENANT_ONE, &topic)?;
    let foreign_subscription = add_subscription(&second_registry, SUBJECT_TWO, TENANT_TWO, &topic)?;
    let first_ingress = NatsFanoutIngress::new(FanoutRouter::new(
        Arc::clone(&first_registry),
        Allow,
        FanoutRouterConfig::default(),
    ));
    let second_ingress = NatsFanoutIngress::new(FanoutRouter::new(
        Arc::clone(&second_registry),
        Allow,
        FanoutRouterConfig::default(),
    ));
    let first_connection = first_registry
        .subscription(first_subscription)?
        .ok_or_else(|| io::Error::other("first subscription missing"))?
        .connection_id();
    let first_hub =
        ConnectionDeliveryHub::new(Arc::clone(&first_registry), DeliveryQueueConfig::default());
    let mut first_delivery = first_hub.open_connection(first_connection)?;
    let second_sink = CollectingSink::default();

    let first_handle = start(first_task)?;
    let second_handle = start(second_task)?;
    tokio::time::timeout(Duration::from_secs(3), first_status.wait_until_ready()).await??;
    tokio::time::timeout(Duration::from_secs(3), second_status.wait_until_ready()).await??;
    assert!(first_receiver.try_recv().is_err());
    assert!(second_receiver.try_recv().is_err());

    publisher.publish(&event).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        first_ingress.recv_and_route(&mut first_receiver, &first_hub),
    )
    .await?
    .ok_or_else(|| io::Error::other("first Core NATS intake stopped"))??;
    tokio::time::timeout(
        Duration::from_secs(2),
        second_ingress.recv_and_route(&mut second_receiver, &second_sink),
    )
    .await?
    .ok_or_else(|| io::Error::other("second Core NATS intake stopped"))??;
    let first_delivery = first_delivery
        .recv()
        .await
        .ok_or_else(|| io::Error::other("first instance delivery queue closed"))?;
    let second_intents = second_sink.intents();

    let QueuedDelivery::Message(first_message) = first_delivery else {
        return Err(io::Error::other("first instance did not deliver one event").into());
    };
    let [FanoutDeliveryIntent::Target(second_target)] = second_intents.as_slice() else {
        return Err(io::Error::other("second instance did not produce one target").into());
    };
    assert_eq!(
        ProtocolEnvelope::parse(first_message.encoded())?
            .payload()
            .as_map()
            .get("subscription_id"),
        Some(&serde_json::Value::String(first_subscription.to_string()))
    );
    assert_eq!(second_target.subscription_id(), second_subscription);
    assert_ne!(second_target.subscription_id(), foreign_subscription);
    assert_eq!(
        ProtocolEnvelope::parse(first_message.encoded())?.id(),
        source_id
    );
    assert_eq!(
        ProtocolEnvelope::parse(second_target.encoded_event())?.id(),
        source_id
    );

    assert!(first_handle.shutdown().await.forced.is_empty());
    assert!(second_handle.shutdown().await.forced.is_empty());
    wait_stopped(&mut first_status).await?;
    wait_stopped(&mut second_status).await?;
    drop(publisher);
    fixture.cleanup().await?;
    Ok(())
}
