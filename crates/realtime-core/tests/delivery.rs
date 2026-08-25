//! Connection-owned count-and-byte delivery, generation, priority, and drain contracts.

use std::{
    error::Error,
    future::{Future, ready},
    sync::Arc,
    time::Duration,
};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_realtime_core::{
    CanonicalFanoutEvent, ConnectionDeliveryHub, ConnectionId, ConnectionRegistry, ControlOutput,
    DeliveryError, DeliveryPriority, DeliveryQueueConfig, DeliveryTerminal, FanoutAuthorizer,
    FanoutDeliveryIntent, FanoutIntentPriority, FanoutIntentReservation, FanoutIntentSink,
    FanoutRouter, FanoutRouterConfig, MAX_ENVELOPE_BYTES, MessageId, MessageType, ObjectPayload,
    OutboundMessage, ProtocolEnvelope, QueuedDelivery, RegistryConfig, RevocationReason,
    SubscriptionId, Topic,
};
use time::OffsetDateTime;
use uuid::Uuid;

const SUBJECT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const SUBJECT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const SUBSCRIPTION: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0021);

fn principal(subject: Uuid) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        SubjectId::from_uuid(subject)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(TENANT)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn active_connection(
    registry: &ConnectionRegistry,
    subject: Uuid,
) -> Result<ConnectionId, Box<dyn Error>> {
    let connection = registry.register(principal(subject)?)?;
    Ok(registry.activate(connection.id())?.id())
}

fn hub(
    max_connections: usize,
    max_messages: usize,
    drain_timeout: Duration,
) -> Result<(Arc<ConnectionRegistry>, ConnectionDeliveryHub), Box<dyn Error>> {
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(
        max_connections,
        16,
        8,
    )?));
    let bytes_per_connection = max_messages * MAX_ENVELOPE_BYTES;
    let config = DeliveryQueueConfig::new(
        max_messages,
        bytes_per_connection,
        max_connections * bytes_per_connection,
        drain_timeout,
    )?;
    let delivery = ConnectionDeliveryHub::new(Arc::clone(&registry), config)?;
    Ok((registry, delivery))
}

fn pong(correlation_id: MessageId) -> OutboundMessage {
    OutboundMessage::Control(ControlOutput::pong(correlation_id))
}

#[test]
fn reservation_drop_releases_exact_count_and_byte_capacity() -> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 2, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let _receiver = hub.open_connection(connection_id)?;
    let reservation =
        hub.sink()
            .reserve_message(connection_id, DeliveryPriority::Normal, MAX_ENVELOPE_BYTES)?;

    let reserved = hub.status();
    assert_eq!(
        (reserved.reserved_messages, reserved.reserved_bytes),
        (1, MAX_ENVELOPE_BYTES)
    );
    drop(reservation);
    let released = hub.status();
    assert_eq!(
        (released.reserved_messages, released.reserved_bytes),
        (0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn high_priority_control_is_received_before_normal_data() -> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 2, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    let normal_id = MessageId::new();
    let high_id = MessageId::new();
    hub.enqueue(connection_id, DeliveryPriority::Normal, pong(normal_id))?;
    hub.enqueue(connection_id, DeliveryPriority::High, pong(high_id))?;

    let Some(QueuedDelivery::Message(first)) = receiver.recv().await else {
        return Err("expected a queued control".into());
    };
    let envelope = ProtocolEnvelope::parse(first.encoded())?;
    assert_eq!(envelope.correlation_id(), Some(high_id));
    Ok(())
}

#[tokio::test]
async fn high_priority_control_evicts_oldest_normal_message_when_queue_is_full()
-> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 1, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    hub.enqueue(
        connection_id,
        DeliveryPriority::Normal,
        pong(MessageId::new()),
    )?;
    let high_id = MessageId::new();
    hub.enqueue(connection_id, DeliveryPriority::High, pong(high_id))?;

    let Some(QueuedDelivery::Message(delivery)) = receiver.recv().await else {
        return Err("expected high-priority control".into());
    };
    assert_eq!(
        ProtocolEnvelope::parse(delivery.encoded())?.correlation_id(),
        Some(high_id)
    );
    assert_eq!(hub.metrics().priority_purged, 1);
    assert_eq!(hub.metrics().slow_consumer_disconnects, 0);
    Ok(())
}

#[tokio::test]
async fn full_queue_disconnects_only_slow_target_while_fast_target_continues()
-> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(2, 1, Duration::from_secs(1))?;
    let slow = active_connection(&registry, SUBJECT_ONE)?;
    let fast = active_connection(&registry, SUBJECT_TWO)?;
    let mut slow_receiver = hub.open_connection(slow)?;
    let mut fast_receiver = hub.open_connection(fast)?;
    hub.enqueue(slow, DeliveryPriority::Normal, pong(MessageId::new()))?;
    assert!(
        hub.enqueue(slow, DeliveryPriority::Normal, pong(MessageId::new()))
            .is_err()
    );
    let fast_id = MessageId::new();
    hub.enqueue(fast, DeliveryPriority::Normal, pong(fast_id))?;

    assert_eq!(
        slow_receiver.recv().await,
        Some(QueuedDelivery::Terminal(DeliveryTerminal::SlowConsumer))
    );
    let Some(QueuedDelivery::Message(fast_message)) = fast_receiver.recv().await else {
        return Err("expected fast delivery".into());
    };
    assert_eq!(
        ProtocolEnvelope::parse(fast_message.encoded())?.correlation_id(),
        Some(fast_id)
    );
    Ok(())
}

struct Allow;

impl FanoutAuthorizer for Allow {
    type Error = ();

    fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        _subscription: &'a rsk_realtime_core::SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        ready(Ok(true))
    }
}

fn fanout_event() -> Result<CanonicalFanoutEvent, Box<dyn Error>> {
    Ok(CanonicalFanoutEvent::new(
        MessageId::new(),
        TenantId::from_uuid(TENANT)?,
        Topic::new("orders")?,
        MessageType::new("order.changed")?,
        None,
        ObjectPayload::empty(),
    ))
}

fn subscribed(
    registry: &ConnectionRegistry,
    connection_id: ConnectionId,
) -> Result<SubscriptionId, Box<dyn Error>> {
    let subscription_id = SubscriptionId::from_uuid(SUBSCRIPTION)?;
    registry.add_subscription(
        connection_id,
        subscription_id,
        TenantId::from_uuid(TENANT)?,
        Topic::new("orders")?,
        None,
    )?;
    Ok(subscription_id)
}

#[tokio::test]
async fn fanout_full_target_does_not_abort_delivery_to_fast_target() -> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(2, 1, Duration::from_secs(1))?;
    let slow = active_connection(&registry, SUBJECT_ONE)?;
    let fast = active_connection(&registry, SUBJECT_TWO)?;
    let mut slow_receiver = hub.open_connection(slow)?;
    let mut fast_receiver = hub.open_connection(fast)?;
    let topic = Topic::new("orders")?;
    registry.add_subscription(
        slow,
        SubscriptionId::from_uuid(SUBSCRIPTION)?,
        TenantId::from_uuid(TENANT)?,
        topic.clone(),
        None,
    )?;
    registry.add_subscription(
        fast,
        SubscriptionId::new(),
        TenantId::from_uuid(TENANT)?,
        topic,
        None,
    )?;
    hub.enqueue(slow, DeliveryPriority::Normal, pong(MessageId::new()))?;
    let router = FanoutRouter::new(Arc::clone(&registry), Allow, FanoutRouterConfig::default());
    router.route(&fanout_event()?, &hub).await?;

    assert_eq!(
        slow_receiver.recv().await,
        Some(QueuedDelivery::Terminal(DeliveryTerminal::SlowConsumer))
    );
    assert!(matches!(
        fast_receiver.recv().await,
        Some(QueuedDelivery::Message(_))
    ));
    Ok(())
}
#[tokio::test]
async fn deterministic_many_slow_and_fast_clients_remain_within_fixed_accounting()
-> Result<(), Box<dyn Error>> {
    const PAIRS: usize = 32;
    let (registry, hub) = hub(PAIRS * 2, 1, Duration::from_secs(1))?;
    let mut slow_receivers = Vec::with_capacity(PAIRS);
    let mut fast_receivers = Vec::with_capacity(PAIRS);
    for index in 0..PAIRS {
        let slow_subject =
            Uuid::from_u128(0x0189_0f2a_0000_7000_8100_0000_0000_0000 + (index as u128 * 2));
        let fast_subject =
            Uuid::from_u128(0x0189_0f2a_0000_7000_8100_0000_0000_0001 + (index as u128 * 2));
        let slow = active_connection(&registry, slow_subject)?;
        let fast = active_connection(&registry, fast_subject)?;
        slow_receivers.push(hub.open_connection(slow)?);
        fast_receivers.push(hub.open_connection(fast)?);
        hub.enqueue(slow, DeliveryPriority::Normal, pong(MessageId::new()))?;
        assert!(
            hub.enqueue(slow, DeliveryPriority::Normal, pong(MessageId::new()))
                .is_err()
        );
        hub.enqueue(fast, DeliveryPriority::Normal, pong(MessageId::new()))?;
    }

    let peak = hub.status();
    assert_eq!(peak.queued_messages, PAIRS);
    assert!(peak.queued_bytes <= PAIRS * MAX_ENVELOPE_BYTES);
    for receiver in &mut slow_receivers {
        assert_eq!(
            receiver.recv().await,
            Some(QueuedDelivery::Terminal(DeliveryTerminal::SlowConsumer))
        );
    }
    for receiver in &mut fast_receivers {
        assert!(matches!(
            receiver.recv().await,
            Some(QueuedDelivery::Message(_))
        ));
    }
    let drained = hub.status();
    assert_eq!(
        (
            drained.queued_messages,
            drained.queued_bytes,
            drained.reserved_messages,
            drained.reserved_bytes
        ),
        (0, 0, 0, 0)
    );
    assert_eq!(hub.metrics().slow_consumer_disconnects, PAIRS as u64);
    Ok(())
}

#[tokio::test]
async fn receiver_drops_event_whose_generation_was_revoked_after_admission()
-> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 2, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    let subscription_id = subscribed(&registry, connection_id)?;
    let router = FanoutRouter::new(Arc::clone(&registry), Allow, FanoutRouterConfig::default());
    router.route(&fanout_event()?, &hub).await?;
    let _ =
        registry.revoke_subscription(subscription_id, RevocationReason::AuthorizationChanged)?;

    assert!(
        tokio::time::timeout(Duration::from_millis(10), receiver.recv())
            .await
            .is_err()
    );
    assert_eq!(hub.metrics().stale_generation_dropped, 1);
    Ok(())
}

#[tokio::test]
async fn revocation_purges_matching_generation_and_control_is_delivered_first()
-> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 2, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    let subscription_id = subscribed(&registry, connection_id)?;
    let router = FanoutRouter::new(Arc::clone(&registry), Allow, FanoutRouterConfig::default());
    router.route(&fanout_event()?, &hub).await?;
    let intent =
        registry.revoke_subscription(subscription_id, RevocationReason::AuthorizationChanged)?;
    let reservation = hub
        .reserve_for(
            connection_id,
            FanoutIntentPriority::High,
            MAX_ENVELOPE_BYTES,
        )
        .await?;
    reservation
        .admit(FanoutDeliveryIntent::Control(intent))
        .await?;

    let Some(QueuedDelivery::Message(control)) = receiver.recv().await else {
        return Err("expected revocation control".into());
    };
    assert_eq!(
        ProtocolEnvelope::parse(control.encoded())?
            .message_type()
            .as_str(),
        "subscription.revoked"
    );
    assert_eq!(hub.metrics().revocation_purged, 1);
    Ok(())
}

#[tokio::test]
async fn drain_closes_intake_drops_at_deadline_and_wakes_transport() -> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 1, Duration::from_millis(10))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    hub.enqueue(
        connection_id,
        DeliveryPriority::Normal,
        pong(MessageId::new()),
    )?;

    let outcome = hub.drain().await;
    assert!(outcome.deadline_expired);
    assert_eq!(outcome.dropped_messages, 1);
    assert!(!hub.is_accepting());
    assert_eq!(
        receiver.recv().await,
        Some(QueuedDelivery::Terminal(DeliveryTerminal::Draining))
    );
    assert_eq!(registry.connection_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn pre_drain_reservation_linearizes_command_admission() -> Result<(), Box<dyn Error>> {
    let (registry, hub) = hub(1, 1, Duration::from_secs(1))?;
    let connection_id = active_connection(&registry, SUBJECT_ONE)?;
    let mut receiver = hub.open_connection(connection_id)?;
    let reservation =
        hub.sink()
            .reserve_message(connection_id, DeliveryPriority::High, MAX_ENVELOPE_BYTES)?;

    hub.begin_drain();
    assert!(matches!(
        hub.sink()
            .reserve_message(connection_id, DeliveryPriority::High, MAX_ENVELOPE_BYTES,),
        Err(DeliveryError::IntakeClosed)
    ));
    reservation.admit_message(pong(MessageId::new()))?;
    assert!(matches!(
        receiver.recv().await,
        Some(QueuedDelivery::Message(_))
    ));
    let _ = hub.force_close();
    Ok(())
}
