//! Real Redis composition contracts for canonical authorized multi-instance fan-out.

mod support;

use std::{
    convert::Infallible,
    error::Error,
    future::{Future, ready},
    io,
    sync::Arc,
    time::Duration,
};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_config::DeploymentEnvironment;
use rsk_events_redis_ephemeral::{
    RedisEphemeralConfig, RedisEphemeralEvents, RedisEphemeralListenerStatus,
    RedisEphemeralRestartConfig,
};
use rsk_realtime_core::{
    CanonicalFanoutEvent, ConnectionRegistry, FanoutAuthorizer, FanoutDeliveryIntent, FanoutRouter,
    FanoutRouterConfig, MessageId, MessageType, ObjectPayload, ProtocolEnvelope, RegistryConfig,
    SubscriptionId, SubscriptionSnapshot, Topic,
};
use rsk_realtime_fanout::{RedisFanoutIngress, RedisFanoutPublisher};
use rsk_redis_core::{RedisConfig, RedisCore, RedisReconnectConfig};
use rsk_runtime::{Supervisor, SupervisorHandle};
use rsk_test_support::RedisFixture;
use support::CollectingSink;
use time::OffsetDateTime;
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

fn redis_config(fixture: &RedisFixture) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(2),
        startup_timeout: Duration::from_secs(5),
        command_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(1),
        client_name: "rsk-realtime-fanout-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v1".to_owned(),
        max_value_bytes: 1024 * 1024,
        reconnect: RedisReconnectConfig::default(),
    }
}

fn provider_config() -> RedisEphemeralConfig {
    RedisEphemeralConfig {
        enabled: true,
        channels: vec!["realtime".to_owned()],
        delivery_capacity: 8,
        max_message_bytes: 16 * 1024,
        operation_timeout: Duration::from_millis(300),
        read_poll_timeout: Duration::from_millis(20),
        shutdown_timeout: Duration::from_secs(1),
        restart: RedisEphemeralRestartConfig {
            max_restarts: 4,
            initial_backoff: Duration::from_millis(20),
            max_backoff: Duration::from_millis(50),
            jitter_percent: 0,
        },
    }
}

fn start(task: rsk_runtime::TaskSpec) -> Result<SupervisorHandle, Box<dyn Error>> {
    let mut supervisor = Supervisor::new();
    supervisor.register(task)?;
    Ok(supervisor.start()?)
}

async fn wait_ready(status: &mut RedisEphemeralListenerStatus) -> Result<(), Box<dyn Error>> {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !status.is_ready() {
            status
                .changed()
                .await
                .ok_or_else(|| io::Error::other("Redis listener status closed before readiness"))?;
        }
        Ok::<_, io::Error>(())
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn canonical_event_reaches_both_ready_instances_without_replay_or_tenant_crossover()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = RedisCore::connect(&redis_config(&fixture), DeploymentEnvironment::Test)
        .await?
        .ok_or_else(|| io::Error::other("enabled Redis unexpectedly disabled"))?;
    let first = RedisEphemeralEvents::new(&provider_config(), Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled Redis fan-out unexpectedly disabled"))?;
    let second = RedisEphemeralEvents::new(&provider_config(), Some(redis.clone()))?
        .ok_or_else(|| io::Error::other("enabled Redis fan-out unexpectedly disabled"))?;
    let mut first_status = first.listener_status();
    let mut second_status = second.listener_status();
    let (provider_publisher, mut first_receiver, first_task) = first.into_parts();
    let (_, mut second_receiver, second_task) = second.into_parts();
    let publisher = RedisFanoutPublisher::new(provider_publisher, "realtime");

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
    let first_ingress = RedisFanoutIngress::new(
        FanoutRouter::new(
            Arc::clone(&first_registry),
            Allow,
            FanoutRouterConfig::default(),
        ),
        "realtime",
    );
    let second_ingress = RedisFanoutIngress::new(
        FanoutRouter::new(
            Arc::clone(&second_registry),
            Allow,
            FanoutRouterConfig::default(),
        ),
        "realtime",
    );
    let first_sink = CollectingSink::default();
    let second_sink = CollectingSink::default();

    let first_handle = start(first_task)?;
    let second_handle = start(second_task)?;
    wait_ready(&mut first_status).await?;
    wait_ready(&mut second_status).await?;
    assert!(first_receiver.try_recv().is_err());
    assert!(second_receiver.try_recv().is_err());

    publisher.publish(&event).await?;
    tokio::time::timeout(
        Duration::from_secs(2),
        first_ingress.recv_and_route(&mut first_receiver, &first_sink),
    )
    .await?
    .ok_or_else(|| io::Error::other("first Redis intake stopped"))??;
    tokio::time::timeout(
        Duration::from_secs(2),
        second_ingress.recv_and_route(&mut second_receiver, &second_sink),
    )
    .await?
    .ok_or_else(|| io::Error::other("second Redis intake stopped"))??;
    let first_intents = first_sink.intents();
    let second_intents = second_sink.intents();

    let [FanoutDeliveryIntent::Target(first_target)] = first_intents.as_slice() else {
        return Err(io::Error::other("first instance did not produce one target").into());
    };
    let [FanoutDeliveryIntent::Target(second_target)] = second_intents.as_slice() else {
        return Err(io::Error::other("second instance did not produce one target").into());
    };
    assert_eq!(first_target.subscription_id(), first_subscription);
    assert_eq!(second_target.subscription_id(), second_subscription);
    assert_ne!(second_target.subscription_id(), foreign_subscription);
    assert_eq!(
        ProtocolEnvelope::parse(first_target.encoded_event())?.id(),
        source_id
    );
    assert_eq!(
        ProtocolEnvelope::parse(second_target.encoded_event())?.id(),
        source_id
    );

    assert!(first_handle.shutdown().await.forced.is_empty());
    assert!(second_handle.shutdown().await.forced.is_empty());
    drop(publisher);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}
