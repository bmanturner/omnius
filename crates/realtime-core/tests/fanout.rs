//! Provider-neutral fan-out codec and authorization-routing contracts.

use std::{
    collections::VecDeque,
    error::Error,
    future::{Future, pending, ready},
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_realtime_core::{
    CanonicalFanoutEvent, ConnectionRegistry, ControlOutput, FANOUT_WIRE_VERSION, FanoutAuthorizer,
    FanoutCodecError, FanoutDeliveryIntent, FanoutIntentReservation, FanoutIntentSink,
    FanoutRouteError, FanoutRouter, FanoutRouterConfig, FanoutRouterConfigError, FanoutWireCodec,
    MAX_CURSOR_BYTES, MAX_ENVELOPE_BYTES, MAX_FANOUT_AUTHORIZATION_CONCURRENCY,
    MAX_FANOUT_AUTHORIZATION_TIMEOUT, MAX_FANOUT_EVENT_BYTES, MAX_FANOUT_IN_FLIGHT,
    MAX_FANOUT_RESERVED_BYTES, MAX_FANOUT_ROUTE_TIMEOUT, MAX_MESSAGE_TYPE_BYTES, MAX_PAYLOAD_BYTES,
    MAX_PAYLOAD_DEPTH, MAX_PAYLOAD_NODES, MAX_TOPIC_BYTES, MessageId, MessageType, ObjectPayload,
    ProtocolEnvelope, RegistryConfig, RevocationReason, SubscriptionId, SubscriptionSnapshot,
    SubscriptionState, Topic,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

const SOURCE: &str = "01890f2a-0000-7000-8000-000000000001";
const CORRELATION: &str = "01890f2a-0000-7000-8000-000000000002";
const SUBSCRIPTION_ONE: &str = "01890f2a-0000-7000-8000-000000000003";
const SUBSCRIPTION_TWO: &str = "01890f2a-0000-7000-8000-000000000004";
const SUBJECT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const SUBJECT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);
const TENANT_ONE: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0021);
const TENANT_TWO: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0022);
const TENANT_ONE_TEXT: &str = "01890f2a-0000-7000-8000-000000000021";

fn object(value: Value) -> Result<ObjectPayload, Box<dyn Error>> {
    let Value::Object(value) = value else {
        return Err("expected object".into());
    };
    Ok(ObjectPayload::new(value)?)
}

fn event_record(
    source_id: &str,
    tenant_id: &str,
    topic: &str,
    event_type: &str,
    correlation_id: &str,
    cursor: &str,
    data: &str,
) -> Vec<u8> {
    format!(
        r#"{{"v":{FANOUT_WIRE_VERSION},"source_id":"{source_id}","tenant_id":"{tenant_id}","topic":"{topic}","type":"{event_type}","correlation_id":{correlation_id},"cursor":{cursor},"data":{data}}}"#,
    )
    .into_bytes()
}

#[test]
fn codec_round_trip_is_exact_canonical_and_preserves_source_id() -> Result<(), Box<dyn Error>> {
    let source_id: MessageId = SOURCE.parse()?;
    let correlation_id: MessageId = CORRELATION.parse()?;
    let event = CanonicalFanoutEvent::new(
        source_id,
        TenantId::from_uuid(TENANT_ONE)?,
        Topic::new("orders/changed")?,
        MessageType::new("order.changed")?,
        Some(correlation_id),
        object(json!({"status": "paid", "count": 2}))?,
    );
    let codec = FanoutWireCodec::ephemeral();

    let encoded = codec.encode(&event)?;
    assert_eq!(
        String::from_utf8(encoded.clone())?,
        format!(
            r#"{{"v":1,"source_id":"{SOURCE}","tenant_id":"{TENANT_ONE_TEXT}","topic":"orders/changed","type":"order.changed","correlation_id":"{CORRELATION}","cursor":null,"data":{{"count":2,"status":"paid"}}}}"#
        )
    );
    assert_eq!(codec.decode(&encoded)?, event);
    assert_eq!(codec.decode(&encoded)?.source_id(), source_id);
    Ok(())
}

#[test]
fn replay_cursor_requires_replay_construction_and_codec_mode() -> Result<(), Box<dyn Error>> {
    let event = CanonicalFanoutEvent::replayed(
        SOURCE.parse()?,
        TenantId::from_uuid(TENANT_ONE)?,
        Topic::new("orders")?,
        MessageType::new("order.changed")?,
        None,
        "replay-42".parse()?,
        ObjectPayload::empty(),
    );
    let replay = FanoutWireCodec::replay();
    let encoded = replay.encode(&event)?;

    assert_eq!(replay.decode(&encoded)?, event);
    assert_eq!(
        FanoutWireCodec::ephemeral().encode(&event),
        Err(FanoutCodecError::CursorNotAllowed)
    );
    assert_eq!(
        FanoutWireCodec::ephemeral().decode(&encoded),
        Err(FanoutCodecError::CursorNotAllowed)
    );
    Ok(())
}

#[test]
fn codec_rejects_total_bound_unknown_duplicate_missing_and_noncanonical_fields() {
    let oversized = vec![b'x'; MAX_FANOUT_EVENT_BYTES + 1];
    let unknown = format!(
        r#"{{"v":1,"source_id":"{SOURCE}","tenant_id":"{TENANT_ONE_TEXT}","topic":"orders","type":"order.changed","correlation_id":null,"cursor":null,"data":{{}},"extra":true}}"#
    );
    let duplicate = format!(
        r#"{{"v":1,"source_id":"{SOURCE}","source_id":"{CORRELATION}","tenant_id":"{TENANT_ONE_TEXT}","topic":"orders","type":"order.changed","correlation_id":null,"cursor":null,"data":{{}}}}"#
    );
    let missing_cursor = format!(
        r#"{{"v":1,"source_id":"{SOURCE}","tenant_id":"{TENANT_ONE_TEXT}","topic":"orders","type":"order.changed","correlation_id":null,"data":{{}}}}"#
    );
    let noncanonical = format!(
        r#"{{ "v":1,"source_id":"{SOURCE}","tenant_id":"{TENANT_ONE_TEXT}","topic":"orders","type":"order.changed","correlation_id":null,"cursor":null,"data":{{}}}}"#
    );
    let codec = FanoutWireCodec::ephemeral();

    assert_eq!(
        codec.decode(&oversized),
        Err(FanoutCodecError::EventTooLarge)
    );
    assert_eq!(
        codec.decode(unknown.as_bytes()),
        Err(FanoutCodecError::InvalidEnvelope)
    );
    assert_eq!(
        codec.decode(duplicate.as_bytes()),
        Err(FanoutCodecError::InvalidEnvelope)
    );
    assert_eq!(
        codec.decode(missing_cursor.as_bytes()),
        Err(FanoutCodecError::InvalidEnvelope)
    );
    assert_eq!(
        codec.decode(noncanonical.as_bytes()),
        Err(FanoutCodecError::NonCanonical)
    );
}

#[test]
fn codec_rejects_identifier_topic_type_and_cursor_string_violations() {
    let codec = FanoutWireCodec::replay();
    let invalid_source = event_record(
        "00000000-0000-4000-8000-000000000000",
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        "{}",
    );
    let invalid_tenant = event_record(
        SOURCE,
        "00000000-0000-4000-8000-000000000000",
        "orders",
        "order.changed",
        "null",
        "null",
        "{}",
    );
    let invalid_correlation = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        r#""not-a-uuid""#,
        "null",
        "{}",
    );
    let long_topic = "t".repeat(MAX_TOPIC_BYTES + 1);
    let invalid_topic = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        &long_topic,
        "order.changed",
        "null",
        "null",
        "{}",
    );
    let long_type = "t".repeat(MAX_MESSAGE_TYPE_BYTES + 1);
    let invalid_type = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        &long_type,
        "null",
        "null",
        "{}",
    );
    let long_cursor = format!(r#""{}""#, "c".repeat(MAX_CURSOR_BYTES + 1));
    let invalid_cursor = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        &long_cursor,
        "{}",
    );

    assert_eq!(
        codec.decode(&invalid_source),
        Err(FanoutCodecError::InvalidSourceId)
    );
    assert_eq!(
        codec.decode(&invalid_tenant),
        Err(FanoutCodecError::InvalidTenantId)
    );
    assert_eq!(
        codec.decode(&invalid_correlation),
        Err(FanoutCodecError::InvalidCorrelationId)
    );
    assert_eq!(
        codec.decode(&invalid_topic),
        Err(FanoutCodecError::InvalidTopic)
    );
    assert_eq!(
        codec.decode(&invalid_type),
        Err(FanoutCodecError::InvalidEventType)
    );
    assert_eq!(
        codec.decode(&invalid_cursor),
        Err(FanoutCodecError::InvalidCursor)
    );
}

#[test]
fn codec_rejects_non_object_duplicate_deep_numerous_and_large_data() {
    let codec = FanoutWireCodec::replay();
    let scalar = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        "[]",
    );
    let duplicate = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        r#"{"secret":1,"secret":2}"#,
    );
    let nested = format!(
        r#"{{"items":{}null{}}}"#,
        "[".repeat(MAX_PAYLOAD_DEPTH),
        "]".repeat(MAX_PAYLOAD_DEPTH)
    );
    let too_deep = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        &nested,
    );
    let nodes = std::iter::repeat_n("null", MAX_PAYLOAD_NODES)
        .collect::<Vec<_>>()
        .join(",");
    let numerous = format!(r#"{{"items":[{nodes}]}}"#);
    let too_many_nodes = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        &numerous,
    );
    let large_string = "x".repeat(MAX_PAYLOAD_BYTES / 2);
    let large_data = format!(r#"{{"value":"{large_string}"}}"#);
    let data_out_of_bounds = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        "orders",
        "order.changed",
        "null",
        "null",
        &large_data,
    );

    assert_eq!(codec.decode(&scalar), Err(FanoutCodecError::InvalidData));
    assert_eq!(
        codec.decode(&duplicate),
        Err(FanoutCodecError::InvalidEnvelope)
    );
    assert_eq!(
        codec.decode(&too_deep),
        Err(FanoutCodecError::DataOutOfBounds)
    );
    assert_eq!(
        codec.decode(&too_many_nodes),
        Err(FanoutCodecError::DataOutOfBounds)
    );
    assert_eq!(
        codec.decode(&data_out_of_bounds),
        Err(FanoutCodecError::DataOutOfBounds)
    );
}

#[test]
fn codec_errors_and_event_debug_never_render_rejected_values() -> Result<(), Box<dyn Error>> {
    let secret_topic = "secret-tenant/private-topic";
    let raw = event_record(
        SOURCE,
        TENANT_ONE_TEXT,
        secret_topic,
        "invalid type",
        "null",
        "null",
        r#"{"secret-data":"do-not-log"}"#,
    );
    let error = FanoutWireCodec::ephemeral()
        .decode(&raw)
        .err()
        .ok_or("expected invalid type")?;
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(secret_topic));
    assert!(!rendered.contains(TENANT_ONE_TEXT));
    assert!(!rendered.contains("do-not-log"));
    assert!(!rendered.contains(&String::from_utf8(raw)?));

    let event = CanonicalFanoutEvent::new(
        SOURCE.parse()?,
        TenantId::from_uuid(TENANT_ONE)?,
        Topic::new(secret_topic)?,
        MessageType::new("order.changed")?,
        None,
        object(json!({"secret-data": "do-not-log"}))?,
    );
    let event_debug = format!("{event:?}");
    assert!(!event_debug.contains(secret_topic));
    assert!(!event_debug.contains(TENANT_ONE_TEXT));
    assert!(!event_debug.contains("do-not-log"));
    Ok(())
}

#[derive(Clone, Copy)]
enum AuthorizationResult {
    Allow,
    Deny,
    Error,
}

struct FixedAuthorizer(AuthorizationResult);

impl FanoutAuthorizer for FixedAuthorizer {
    type Error = ();

    fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        _subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        ready(match self.0 {
            AuthorizationResult::Allow => Ok(true),
            AuthorizationResult::Deny => Ok(false),
            AuthorizationResult::Error => Err(()),
        })
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

fn registry_with_subscription(
    subject: Uuid,
    tenant: Uuid,
    subscription_id: SubscriptionId,
    topic: &str,
) -> Result<(Arc<ConnectionRegistry>, SubscriptionSnapshot), Box<dyn Error>> {
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(4, 8, 4)?));
    let connection = registry.register(principal(subject, tenant)?)?;
    registry.activate(connection.id())?;
    let subscription = registry.add_subscription(
        connection.id(),
        subscription_id,
        TenantId::from_uuid(tenant)?,
        Topic::new(topic)?,
        None,
    )?;
    Ok((registry, subscription))
}

fn configured(
    authorization_timeout: Duration,
    route_timeout: Duration,
    authorization_concurrency: usize,
    max_in_flight: usize,
) -> Result<FanoutRouterConfig, FanoutRouterConfigError> {
    FanoutRouterConfig::new(
        authorization_timeout,
        route_timeout,
        authorization_concurrency,
        max_in_flight,
        max_in_flight.saturating_mul(MAX_ENVELOPE_BYTES),
    )
}

fn empty_event(tenant: Uuid, topic: &str) -> Result<CanonicalFanoutEvent, Box<dyn Error>> {
    Ok(CanonicalFanoutEvent::new(
        SOURCE.parse()?,
        TenantId::from_uuid(tenant)?,
        Topic::new(topic)?,
        MessageType::new("order.changed")?,
        None,
        ObjectPayload::empty(),
    ))
}

struct SinkState {
    intents: Mutex<VecDeque<FanoutDeliveryIntent>>,
    retain_limit: usize,
    max_reservations: usize,
    max_reserved_bytes: usize,
    reservations: AtomicUsize,
    peak_reservations: AtomicUsize,
    reserved_bytes: AtomicUsize,
    peak_reserved_bytes: AtomicUsize,
    admitted: AtomicUsize,
    target_admitted_while_reserved: AtomicBool,
}

struct BoundedSink {
    state: Arc<SinkState>,
}

impl BoundedSink {
    fn new(retain_limit: usize, max_reservations: usize, max_reserved_bytes: usize) -> Self {
        Self {
            state: Arc::new(SinkState {
                intents: Mutex::new(VecDeque::with_capacity(retain_limit)),
                retain_limit,
                max_reservations,
                max_reserved_bytes,
                reservations: AtomicUsize::new(0),
                peak_reservations: AtomicUsize::new(0),
                reserved_bytes: AtomicUsize::new(0),
                peak_reserved_bytes: AtomicUsize::new(0),
                admitted: AtomicUsize::new(0),
                target_admitted_while_reserved: AtomicBool::new(false),
            }),
        }
    }

    fn snapshot(&self) -> Result<Vec<FanoutDeliveryIntent>, io::Error> {
        let intents = self
            .state
            .intents
            .lock()
            .map_err(|_| io::Error::other("test sink lock poisoned"))?;
        Ok(intents.iter().cloned().collect())
    }

    fn retained_len(&self) -> Result<usize, io::Error> {
        self.state
            .intents
            .lock()
            .map(|intents| intents.len())
            .map_err(|_| io::Error::other("test sink lock poisoned"))
    }

    fn admitted(&self) -> usize {
        self.state.admitted.load(Ordering::SeqCst)
    }

    fn peak_reservations(&self) -> usize {
        self.state.peak_reservations.load(Ordering::SeqCst)
    }

    fn peak_reserved_bytes(&self) -> usize {
        self.state.peak_reserved_bytes.load(Ordering::SeqCst)
    }

    fn target_admitted_while_reserved(&self) -> bool {
        self.state
            .target_admitted_while_reserved
            .load(Ordering::SeqCst)
    }
}

struct BoundedReservation {
    state: Arc<SinkState>,
    bytes: usize,
}

impl Drop for BoundedReservation {
    fn drop(&mut self) {
        let _ = self.state.reservations.fetch_sub(1, Ordering::SeqCst);
        let _ = self
            .state
            .reserved_bytes
            .fetch_sub(self.bytes, Ordering::SeqCst);
    }
}

impl FanoutIntentReservation for BoundedReservation {
    type Error = ();

    async fn admit(self, intent: FanoutDeliveryIntent) -> Result<(), Self::Error> {
        tokio::task::yield_now().await;
        if matches!(intent, FanoutDeliveryIntent::Target(_))
            && self.state.reservations.load(Ordering::SeqCst) > 0
        {
            self.state
                .target_admitted_while_reserved
                .store(true, Ordering::SeqCst);
        }
        let _ = self.state.admitted.fetch_add(1, Ordering::SeqCst);
        let mut intents = self.state.intents.lock().map_err(|_| ())?;
        if intents.len() < self.state.retain_limit {
            intents.push_back(intent);
        }
        Ok(())
    }
}

impl FanoutIntentSink for BoundedSink {
    type Error = ();
    type Reservation = BoundedReservation;

    fn reserve(
        &self,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        let reservations = self.state.reservations.fetch_add(1, Ordering::SeqCst);
        if reservations >= self.state.max_reservations {
            let _ = self.state.reservations.fetch_sub(1, Ordering::SeqCst);
            return ready(Err(()));
        }
        let reserved_bytes = self
            .state
            .reserved_bytes
            .fetch_add(maximum_encoded_bytes, Ordering::SeqCst);
        let Some(total_reserved_bytes) = reserved_bytes.checked_add(maximum_encoded_bytes) else {
            let _ = self
                .state
                .reserved_bytes
                .fetch_sub(maximum_encoded_bytes, Ordering::SeqCst);
            let _ = self.state.reservations.fetch_sub(1, Ordering::SeqCst);
            return ready(Err(()));
        };
        if total_reserved_bytes > self.state.max_reserved_bytes {
            let _ = self
                .state
                .reserved_bytes
                .fetch_sub(maximum_encoded_bytes, Ordering::SeqCst);
            let _ = self.state.reservations.fetch_sub(1, Ordering::SeqCst);
            return ready(Err(()));
        }
        let _ = self
            .state
            .peak_reservations
            .fetch_max(reservations.saturating_add(1), Ordering::SeqCst);
        let _ = self
            .state
            .peak_reserved_bytes
            .fetch_max(total_reserved_bytes, Ordering::SeqCst);
        ready(Ok(BoundedReservation {
            state: Arc::clone(&self.state),
            bytes: maximum_encoded_bytes,
        }))
    }
}

struct NeverReservation;

impl FanoutIntentReservation for NeverReservation {
    type Error = ();

    fn admit(
        self,
        _intent: FanoutDeliveryIntent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready(Ok(()))
    }
}

struct NeverSink;

impl FanoutIntentSink for NeverSink {
    type Error = ();
    type Reservation = NeverReservation;

    fn reserve(
        &self,
        _maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        pending()
    }
}

#[test]
fn router_configuration_rejects_zero_excessive_and_inconsistent_limits() {
    assert_eq!(
        FanoutRouterConfig::new(
            Duration::ZERO,
            Duration::from_secs(1),
            1,
            1,
            MAX_ENVELOPE_BYTES,
        ),
        Err(FanoutRouterConfigError::ZeroLimit)
    );
    assert_eq!(
        FanoutRouterConfig::new(
            MAX_FANOUT_AUTHORIZATION_TIMEOUT + Duration::from_millis(1),
            MAX_FANOUT_ROUTE_TIMEOUT,
            1,
            1,
            MAX_ENVELOPE_BYTES,
        ),
        Err(FanoutRouterConfigError::ExceedsHardLimit)
    );
    assert_eq!(
        configured(Duration::from_secs(2), Duration::from_secs(1), 1, 1,),
        Err(FanoutRouterConfigError::AuthorizationTimeoutExceedsRouteTimeout)
    );
    assert_eq!(
        configured(Duration::from_secs(1), Duration::from_secs(1), 2, 1),
        Err(FanoutRouterConfigError::AuthorizationConcurrencyExceedsInFlight)
    );
    assert_eq!(
        FanoutRouterConfig::new(
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
            MAX_FANOUT_IN_FLIGHT,
            MAX_FANOUT_RESERVED_BYTES.saturating_sub(1),
        ),
        Err(FanoutRouterConfigError::InsufficientReservationCapacity)
    );
    assert_eq!(
        configured(
            Duration::from_secs(1),
            Duration::from_secs(1),
            MAX_FANOUT_AUTHORIZATION_CONCURRENCY.saturating_add(1),
            MAX_FANOUT_IN_FLIGHT,
        ),
        Err(FanoutRouterConfigError::ExceedsHardLimit)
    );
}

#[tokio::test]
async fn router_isolates_tenants_and_allowed_target_preserves_generation_and_event()
-> Result<(), Box<dyn Error>> {
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(2, 4, 2)?));
    let topic = Topic::new("orders/changed")?;
    let first = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    let second = registry.register(principal(SUBJECT_TWO, TENANT_TWO)?)?;
    registry.activate(first.id())?;
    registry.activate(second.id())?;
    let first_subscription = registry.add_subscription(
        first.id(),
        SUBSCRIPTION_ONE.parse()?,
        TenantId::from_uuid(TENANT_ONE)?,
        topic.clone(),
        None,
    )?;
    registry.add_subscription(
        second.id(),
        SUBSCRIPTION_TWO.parse()?,
        TenantId::from_uuid(TENANT_TWO)?,
        topic.clone(),
        None,
    )?;
    let source_id = SOURCE.parse()?;
    let event = CanonicalFanoutEvent::new(
        source_id,
        TenantId::from_uuid(TENANT_ONE)?,
        topic,
        MessageType::new("order.changed")?,
        Some(CORRELATION.parse()?),
        object(json!({"status": "paid"}))?,
    );
    let router = FanoutRouter::new(
        Arc::clone(&registry),
        FixedAuthorizer(AuthorizationResult::Allow),
        FanoutRouterConfig::default(),
    );
    let sink = BoundedSink::new(1, 16, 16 * MAX_ENVELOPE_BYTES);

    router.route(&event, &sink).await?;
    let intents = sink.snapshot()?;
    let [FanoutDeliveryIntent::Target(target)] = intents.as_slice() else {
        return Err("expected one target".into());
    };
    assert_eq!(target.connection_id(), first.id());
    assert_eq!(target.subscription_id(), first_subscription.id());
    assert_eq!(
        target.subscription_generation(),
        first_subscription.generation()
    );
    let envelope = ProtocolEnvelope::parse(target.encoded_event())?;
    assert_eq!(envelope.id(), source_id);
    assert_eq!(envelope.message_type().as_str(), "order.changed");
    assert_eq!(envelope.correlation_id(), Some(CORRELATION.parse()?));
    assert_eq!(
        envelope
            .payload()
            .as_map()
            .get("subscription_id")
            .and_then(Value::as_str),
        Some(SUBSCRIPTION_ONE)
    );
    assert_eq!(
        envelope
            .payload()
            .as_map()
            .get("topic")
            .and_then(Value::as_str),
        Some(first_subscription.topic().as_str())
    );
    assert_eq!(
        envelope
            .payload()
            .as_map()
            .get("data")
            .and_then(Value::as_object),
        Some(event.data().as_map())
    );
    Ok(())
}

#[tokio::test]
async fn sink_reservation_precedes_event_allocation_and_encoding() -> Result<(), Box<dyn Error>> {
    let subscription_id = SubscriptionId::new();
    let (registry, _) =
        registry_with_subscription(SUBJECT_ONE, TENANT_ONE, subscription_id, "orders")?;
    let event = CanonicalFanoutEvent::new(
        SOURCE.parse()?,
        TenantId::from_uuid(TENANT_ONE)?,
        Topic::new("orders")?,
        MessageType::new("order.changed")?,
        None,
        object(json!({"items": vec![Value::Null; MAX_PAYLOAD_NODES - 2]}))?,
    );
    let router = FanoutRouter::new(
        registry,
        FixedAuthorizer(AuthorizationResult::Allow),
        FanoutRouterConfig::default(),
    );
    let sink = BoundedSink::new(1, 16, 16 * MAX_ENVELOPE_BYTES);

    assert_eq!(
        router.route(&event, &sink).await,
        Err(FanoutRouteError::Encoding)
    );
    assert_eq!(sink.peak_reservations(), 1);
    assert!(!sink.target_admitted_while_reserved());
    Ok(())
}

#[tokio::test]
async fn denial_and_authorizer_error_revoke_and_emit_control_only() -> Result<(), Box<dyn Error>> {
    for result in [AuthorizationResult::Deny, AuthorizationResult::Error] {
        let subscription_id = SubscriptionId::new();
        let (registry, subscription) =
            registry_with_subscription(SUBJECT_ONE, TENANT_ONE, subscription_id, "orders")?;
        let router = FanoutRouter::new(
            Arc::clone(&registry),
            FixedAuthorizer(result),
            FanoutRouterConfig::default(),
        );
        let sink = BoundedSink::new(1, 16, 16 * MAX_ENVELOPE_BYTES);

        router
            .route(&empty_event(TENANT_ONE, "orders")?, &sink)
            .await?;
        let intents = sink.snapshot()?;
        let [FanoutDeliveryIntent::Control(intent)] = intents.as_slice() else {
            return Err("expected one control intent".into());
        };
        assert_eq!(intent.connection_id(), subscription.connection_id());
        assert!(matches!(
            intent.output(),
            ControlOutput::SubscriptionRevoked {
                subscription_id: revoked,
                reason: RevocationReason::AuthorizationChanged,
                ..
            } if *revoked == subscription_id
        ));
        assert_eq!(
            registry
                .subscription(subscription_id)?
                .map(|value| value.state()),
            Some(SubscriptionState::Revoked)
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Mutation {
    Revoke,
    Replace,
    Close,
}

struct MutatingAuthorizer {
    registry: Arc<ConnectionRegistry>,
    mutation: Mutation,
}

impl FanoutAuthorizer for MutatingAuthorizer {
    type Error = ();

    fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        match self.mutation {
            Mutation::Revoke => {
                let _ = self
                    .registry
                    .revoke_subscription(subscription.id(), RevocationReason::AuthorizationChanged);
            }
            Mutation::Replace => {
                let _ = self
                    .registry
                    .remove_subscription(subscription.connection_id(), subscription.id());
                let _ = self.registry.add_subscription(
                    subscription.connection_id(),
                    subscription.id(),
                    subscription.tenant_id(),
                    subscription.topic().clone(),
                    None,
                );
            }
            Mutation::Close => {
                let _ = self.registry.begin_close(subscription.connection_id());
            }
        }
        ready(Ok(true))
    }
}

#[tokio::test]
async fn revoked_replaced_generation_and_inactive_connection_emit_no_target()
-> Result<(), Box<dyn Error>> {
    for mutation in [Mutation::Revoke, Mutation::Replace, Mutation::Close] {
        let (registry, _) =
            registry_with_subscription(SUBJECT_ONE, TENANT_ONE, SubscriptionId::new(), "orders")?;
        let router = FanoutRouter::new(
            Arc::clone(&registry),
            MutatingAuthorizer { registry, mutation },
            FanoutRouterConfig::default(),
        );
        let sink = BoundedSink::new(1, 16, 16 * MAX_ENVELOPE_BYTES);

        router
            .route(&empty_event(TENANT_ONE, "orders")?, &sink)
            .await?;
        assert_eq!(sink.admitted(), 0);
    }
    Ok(())
}

struct ReplacingDenyAuthorizer {
    registry: Arc<ConnectionRegistry>,
}

impl FanoutAuthorizer for ReplacingDenyAuthorizer {
    type Error = ();

    fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        let _ = self
            .registry
            .remove_subscription(subscription.connection_id(), subscription.id());
        let _ = self.registry.add_subscription(
            subscription.connection_id(),
            subscription.id(),
            subscription.tenant_id(),
            subscription.topic().clone(),
            None,
        );
        ready(Ok(false))
    }
}

#[tokio::test]
async fn stale_denial_does_not_revoke_replacement_or_emit_control() -> Result<(), Box<dyn Error>> {
    let subscription_id = SubscriptionId::new();
    let (registry, original) =
        registry_with_subscription(SUBJECT_ONE, TENANT_ONE, subscription_id, "orders")?;
    let router = FanoutRouter::new(
        Arc::clone(&registry),
        ReplacingDenyAuthorizer {
            registry: Arc::clone(&registry),
        },
        FanoutRouterConfig::default(),
    );
    let sink = BoundedSink::new(1, 16, 16 * MAX_ENVELOPE_BYTES);

    router
        .route(&empty_event(TENANT_ONE, "orders")?, &sink)
        .await?;
    assert_eq!(sink.admitted(), 0);
    let replacement = registry
        .subscription(subscription_id)?
        .ok_or("replacement should remain")?;
    assert_ne!(replacement.generation(), original.generation());
    assert_eq!(replacement.state(), SubscriptionState::Active);
    Ok(())
}

struct SelectivePendingAuthorizer {
    pending_subscription: SubscriptionId,
}

impl FanoutAuthorizer for SelectivePendingAuthorizer {
    type Error = ();

    async fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> Result<bool, Self::Error> {
        if subscription.id() == self.pending_subscription {
            pending::<()>().await;
        }
        Ok(true)
    }
}

#[tokio::test]
async fn authorization_timeout_revokes_exact_subscription_and_later_fast_target_continues()
-> Result<(), Box<dyn Error>> {
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(1, 2, 2)?));
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let tenant = TenantId::from_uuid(TENANT_ONE)?;
    let topic = Topic::new("orders")?;
    let slow_id = SUBSCRIPTION_ONE.parse()?;
    let fast_id = SUBSCRIPTION_TWO.parse()?;
    let slow = registry.add_subscription(connection.id(), slow_id, tenant, topic.clone(), None)?;
    registry.add_subscription(connection.id(), fast_id, tenant, topic, None)?;
    let config = configured(Duration::from_millis(10), Duration::from_millis(100), 2, 2)?;
    let router = FanoutRouter::new(
        Arc::clone(&registry),
        SelectivePendingAuthorizer {
            pending_subscription: slow_id,
        },
        config,
    );
    let sink = BoundedSink::new(2, 2, 2 * MAX_ENVELOPE_BYTES);

    tokio::time::timeout(
        Duration::from_millis(200),
        router.route(&empty_event(TENANT_ONE, "orders")?, &sink),
    )
    .await??;
    let intents = sink.snapshot()?;
    assert!(intents.iter().any(|intent| matches!(
        intent,
        FanoutDeliveryIntent::Target(target) if target.subscription_id() == fast_id
    )));
    assert!(intents.iter().any(|intent| matches!(
        intent,
        FanoutDeliveryIntent::Control(control)
            if matches!(
                control.output(),
                ControlOutput::SubscriptionRevoked {
                    subscription_id,
                    reason: RevocationReason::AuthorizationChanged,
                    ..
                } if *subscription_id == slow_id
            )
    )));
    assert_eq!(
        registry
            .subscription(slow_id)?
            .map(|value| (value.generation(), value.state())),
        Some((slow.generation(), SubscriptionState::Revoked))
    );
    Ok(())
}

struct ReplacingPendingAuthorizer {
    registry: Arc<ConnectionRegistry>,
}

impl FanoutAuthorizer for ReplacingPendingAuthorizer {
    type Error = ();

    async fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> Result<bool, Self::Error> {
        let _ = self
            .registry
            .remove_subscription(subscription.connection_id(), subscription.id());
        let _ = self.registry.add_subscription(
            subscription.connection_id(),
            subscription.id(),
            subscription.tenant_id(),
            subscription.topic().clone(),
            None,
        );
        pending::<()>().await;
        Ok(true)
    }
}

#[tokio::test]
async fn authorization_timeout_never_revokes_or_controls_a_replacement_generation()
-> Result<(), Box<dyn Error>> {
    let subscription_id = SubscriptionId::new();
    let (registry, original) =
        registry_with_subscription(SUBJECT_ONE, TENANT_ONE, subscription_id, "orders")?;
    let router = FanoutRouter::new(
        Arc::clone(&registry),
        ReplacingPendingAuthorizer {
            registry: Arc::clone(&registry),
        },
        configured(Duration::from_millis(10), Duration::from_millis(100), 1, 1)?,
    );
    let sink = BoundedSink::new(1, 1, MAX_ENVELOPE_BYTES);

    router
        .route(&empty_event(TENANT_ONE, "orders")?, &sink)
        .await?;
    assert_eq!(sink.admitted(), 0);
    let replacement = registry
        .subscription(subscription_id)?
        .ok_or("replacement should remain")?;
    assert_ne!(replacement.generation(), original.generation());
    assert_eq!(replacement.state(), SubscriptionState::Active);
    Ok(())
}

struct ConcurrencyAuthorizer {
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

impl FanoutAuthorizer for ConcurrencyAuthorizer {
    type Error = ();

    async fn authorize<'a>(
        &'a self,
        _event: &'a CanonicalFanoutEvent,
        _subscription: &'a SubscriptionSnapshot,
    ) -> Result<bool, Self::Error> {
        let active = self.active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        let _ = self.peak.fetch_max(active, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let _ = self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(true)
    }
}

#[tokio::test]
async fn authorization_concurrency_never_exceeds_the_validated_bound() -> Result<(), Box<dyn Error>>
{
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(1, 8, 8)?));
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let tenant = TenantId::from_uuid(TENANT_ONE)?;
    let topic = Topic::new("orders")?;
    for _ in 0..8 {
        registry.add_subscription(
            connection.id(),
            SubscriptionId::new(),
            tenant,
            topic.clone(),
            None,
        )?;
    }
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let router = FanoutRouter::new(
        registry,
        ConcurrencyAuthorizer {
            active,
            peak: Arc::clone(&peak),
        },
        configured(Duration::from_secs(1), Duration::from_secs(2), 3, 3)?,
    );
    let sink = BoundedSink::new(1, 3, 3 * MAX_ENVELOPE_BYTES);

    router
        .route(&empty_event(TENANT_ONE, "orders")?, &sink)
        .await?;
    assert_eq!(peak.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn whole_route_deadline_bounds_a_never_resolving_sink() -> Result<(), Box<dyn Error>> {
    let (registry, _) =
        registry_with_subscription(SUBJECT_ONE, TENANT_ONE, SubscriptionId::new(), "orders")?;
    let router = FanoutRouter::new(
        registry,
        FixedAuthorizer(AuthorizationResult::Allow),
        configured(Duration::from_millis(10), Duration::from_millis(20), 1, 1)?,
    );

    assert_eq!(
        tokio::time::timeout(
            Duration::from_millis(200),
            router.route(&empty_event(TENANT_ONE, "orders")?, &NeverSink),
        )
        .await?,
        Err(FanoutRouteError::DeadlineExceeded)
    );
    Ok(())
}

#[tokio::test]
async fn high_cardinality_max_payload_keeps_fixed_in_flight_and_retained_bounds()
-> Result<(), Box<dyn Error>> {
    const SUBSCRIPTIONS: usize = 64;
    const IN_FLIGHT: usize = 4;
    let registry = Arc::new(ConnectionRegistry::new(RegistryConfig::new(
        1,
        SUBSCRIPTIONS,
        SUBSCRIPTIONS,
    )?));
    let connection = registry.register(principal(SUBJECT_ONE, TENANT_ONE)?)?;
    registry.activate(connection.id())?;
    let tenant = TenantId::from_uuid(TENANT_ONE)?;
    let topic = Topic::new("orders")?;
    for _ in 0..SUBSCRIPTIONS {
        registry.add_subscription(
            connection.id(),
            SubscriptionId::new(),
            tenant,
            topic.clone(),
            None,
        )?;
    }
    let event = CanonicalFanoutEvent::new(
        SOURCE.parse()?,
        tenant,
        topic,
        MessageType::new("order.changed")?,
        None,
        object(json!({
            "blob": "x".repeat((MAX_PAYLOAD_BYTES / 6).saturating_sub(256))
        }))?,
    );
    let router = FanoutRouter::new(
        registry,
        FixedAuthorizer(AuthorizationResult::Allow),
        configured(
            Duration::from_secs(1),
            Duration::from_secs(10),
            IN_FLIGHT,
            IN_FLIGHT,
        )?,
    );
    let sink = BoundedSink::new(1, IN_FLIGHT, IN_FLIGHT * MAX_ENVELOPE_BYTES);

    router.route(&event, &sink).await?;
    assert_eq!(sink.admitted(), SUBSCRIPTIONS);
    assert!(sink.peak_reservations() <= IN_FLIGHT);
    assert!(sink.peak_reserved_bytes() <= IN_FLIGHT * MAX_ENVELOPE_BYTES);
    assert!(sink.retained_len()? <= 1);
    assert!(sink.target_admitted_while_reserved());
    Ok(())
}
