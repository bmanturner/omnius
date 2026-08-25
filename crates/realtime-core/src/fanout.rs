use std::{fmt, future::Future, sync::Arc, time::Duration};

use futures::{StreamExt, stream::FuturesUnordered};
use rsk_auth_core::TenantId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::time::{Instant, sleep_until, timeout};
use uuid::Uuid;

use crate::{
    protocol::{
        EventOutput, MAX_ENVELOPE_BYTES, MessageId, MessageType, ObjectPayload, OpaqueCursor,
        OutboundMessage, PROTOCOL_VERSION, RequiredNullable, StrictValue, SubscriptionId, Topic,
    },
    registry::{ConnectionRegistry, ControlIntent, RegistryError, SubscriptionSnapshot},
};

/// The exact version of the provider-neutral fan-out wire record.
pub const FANOUT_WIRE_VERSION: u16 = PROTOCOL_VERSION;
/// Maximum encoded size of one provider-neutral fan-out record.
pub const MAX_FANOUT_EVENT_BYTES: usize = 16 * 1024;
/// Hard ceiling for one refreshed authorization decision.
pub const MAX_FANOUT_AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard ceiling for routing one canonical event.
pub const MAX_FANOUT_ROUTE_TIMEOUT: Duration = Duration::from_mins(5);
/// Hard ceiling for simultaneously polled authorization decisions.
pub const MAX_FANOUT_AUTHORIZATION_CONCURRENCY: usize = 256;
/// Hard ceiling for all authorization and sink-admission work retained by one route.
pub const MAX_FANOUT_IN_FLIGHT: usize = 256;
/// Hard ceiling for aggregate sink reservations retained by one route.
pub const MAX_FANOUT_RESERVED_BYTES: usize = MAX_FANOUT_IN_FLIGHT * MAX_ENVELOPE_BYTES;

/// Invalid fan-out router limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FanoutRouterConfigError {
    /// Every timeout and capacity must be greater than zero.
    #[error("realtime fan-out router limits must be non-zero")]
    ZeroLimit,
    /// A configured value exceeded its compile-time hard ceiling.
    #[error("realtime fan-out router limit exceeds its hard bound")]
    ExceedsHardLimit,
    /// A decision timeout cannot extend beyond the whole route.
    #[error("realtime fan-out authorization timeout exceeds the route timeout")]
    AuthorizationTimeoutExceedsRouteTimeout,
    /// Authorization concurrency cannot exceed the aggregate in-flight capacity.
    #[error("realtime fan-out authorization concurrency exceeds aggregate capacity")]
    AuthorizationConcurrencyExceedsInFlight,
    /// The aggregate byte reservation cannot cover every configured in-flight admission.
    #[error("realtime fan-out reservation capacity is inconsistent")]
    InsufficientReservationCapacity,
}

/// Validated time and retained-work limits for a [`FanoutRouter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FanoutRouterConfig {
    authorization_timeout: Duration,
    route_timeout: Duration,
    authorization_concurrency: usize,
    max_in_flight: usize,
    max_reserved_bytes: usize,
}

impl FanoutRouterConfig {
    /// Validates every router limit against fixed hard ceilings and aggregate bounds.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`FanoutRouterConfigError`] for a zero, excessive, or inconsistent
    /// limit.
    pub fn new(
        authorization_timeout: Duration,
        route_timeout: Duration,
        authorization_concurrency: usize,
        max_in_flight: usize,
        max_reserved_bytes: usize,
    ) -> Result<Self, FanoutRouterConfigError> {
        if authorization_timeout.is_zero()
            || route_timeout.is_zero()
            || authorization_concurrency == 0
            || max_in_flight == 0
            || max_reserved_bytes == 0
        {
            return Err(FanoutRouterConfigError::ZeroLimit);
        }
        if authorization_timeout > MAX_FANOUT_AUTHORIZATION_TIMEOUT
            || route_timeout > MAX_FANOUT_ROUTE_TIMEOUT
            || authorization_concurrency > MAX_FANOUT_AUTHORIZATION_CONCURRENCY
            || max_in_flight > MAX_FANOUT_IN_FLIGHT
            || max_reserved_bytes > MAX_FANOUT_RESERVED_BYTES
        {
            return Err(FanoutRouterConfigError::ExceedsHardLimit);
        }
        if authorization_timeout > route_timeout {
            return Err(FanoutRouterConfigError::AuthorizationTimeoutExceedsRouteTimeout);
        }
        if authorization_concurrency > max_in_flight {
            return Err(FanoutRouterConfigError::AuthorizationConcurrencyExceedsInFlight);
        }
        if max_in_flight
            .checked_mul(MAX_ENVELOPE_BYTES)
            .is_none_or(|required| required > max_reserved_bytes)
        {
            return Err(FanoutRouterConfigError::InsufficientReservationCapacity);
        }
        Ok(Self {
            authorization_timeout,
            route_timeout,
            authorization_concurrency,
            max_in_flight,
            max_reserved_bytes,
        })
    }

    /// Returns the deadline applied independently to each authorization decision.
    #[must_use]
    pub const fn authorization_timeout(self) -> Duration {
        self.authorization_timeout
    }

    /// Returns the deadline for the whole route, including sink admission.
    #[must_use]
    pub const fn route_timeout(self) -> Duration {
        self.route_timeout
    }

    /// Returns the maximum number of simultaneously polled authorization decisions.
    #[must_use]
    pub const fn authorization_concurrency(self) -> usize {
        self.authorization_concurrency
    }

    /// Returns the maximum aggregate authorization and admission work retained by one route.
    #[must_use]
    pub const fn max_in_flight(self) -> usize {
        self.max_in_flight
    }

    /// Returns the maximum aggregate bytes promised to outstanding sink reservations.
    #[must_use]
    pub const fn max_reserved_bytes(self) -> usize {
        self.max_reserved_bytes
    }
}

impl Default for FanoutRouterConfig {
    fn default() -> Self {
        Self {
            authorization_timeout: Duration::from_secs(2),
            route_timeout: Duration::from_secs(30),
            authorization_concurrency: 16,
            max_in_flight: 16,
            max_reserved_bytes: 16 * MAX_ENVELOPE_BYTES,
        }
    }
}

/// A validated provider-neutral application event.
///
/// The tenant and topic are authoritative routing facts. A cursor can only enter this type through
/// [`Self::replayed`] or a replay-mode [`FanoutWireCodec`].
#[derive(Clone, Eq, PartialEq)]
pub struct CanonicalFanoutEvent {
    source_id: MessageId,
    tenant_id: TenantId,
    topic: Topic,
    event_type: MessageType,
    correlation_id: Option<MessageId>,
    cursor: Option<OpaqueCursor>,
    data: ObjectPayload,
}

impl CanonicalFanoutEvent {
    /// Creates an ephemeral event without replay claims.
    #[must_use]
    pub const fn new(
        source_id: MessageId,
        tenant_id: TenantId,
        topic: Topic,
        event_type: MessageType,
        correlation_id: Option<MessageId>,
        data: ObjectPayload,
    ) -> Self {
        Self {
            source_id,
            tenant_id,
            topic,
            event_type,
            correlation_id,
            cursor: None,
            data,
        }
    }

    /// Creates an event delivered by a genuine replay source.
    #[must_use]
    pub const fn replayed(
        source_id: MessageId,
        tenant_id: TenantId,
        topic: Topic,
        event_type: MessageType,
        correlation_id: Option<MessageId>,
        cursor: OpaqueCursor,
        data: ObjectPayload,
    ) -> Self {
        Self {
            source_id,
            tenant_id,
            topic,
            event_type,
            correlation_id,
            cursor: Some(cursor),
            data,
        }
    }

    /// Returns the stable source identifier preserved across provider deliveries.
    #[must_use]
    pub const fn source_id(&self) -> MessageId {
        self.source_id
    }

    /// Returns the authoritative tenant routing key.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the validated authoritative topic routing key.
    #[must_use]
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Returns the portable realtime event type.
    #[must_use]
    pub const fn event_type(&self) -> &MessageType {
        &self.event_type
    }

    /// Returns the optional event correlation identifier.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<MessageId> {
        self.correlation_id
    }

    /// Returns a cursor only when the event came from a genuine replay source.
    #[must_use]
    pub const fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    /// Returns the bounded JSON object data.
    #[must_use]
    pub const fn data(&self) -> &ObjectPayload {
        &self.data
    }
}

impl fmt::Debug for CanonicalFanoutEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalFanoutEvent { .. }")
    }
}

/// Whether a provider record is ephemeral or backed by genuine replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutWireMode {
    /// Loss-tolerant delivery with no cursor or replay claim.
    Ephemeral,
    /// Delivery from a provider that genuinely supports replay cursors.
    Replay,
}

/// A stable, value-free fan-out codec failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FanoutCodecError {
    /// Input or encoded output exceeded [`MAX_FANOUT_EVENT_BYTES`].
    #[error("realtime fan-out event exceeds its byte limit")]
    EventTooLarge,
    /// The record was malformed, incomplete, or contained unknown or duplicate fields.
    #[error("realtime fan-out envelope is invalid")]
    InvalidEnvelope,
    /// The record was valid JSON but was not the exact canonical encoding.
    #[error("realtime fan-out envelope is not canonical")]
    NonCanonical,
    /// The fan-out version was unsupported.
    #[error("realtime fan-out version is unsupported")]
    UnsupportedVersion,
    /// The stable source identifier was invalid.
    #[error("realtime fan-out source identifier is invalid")]
    InvalidSourceId,
    /// The authoritative tenant identifier was invalid.
    #[error("realtime fan-out tenant identifier is invalid")]
    InvalidTenantId,
    /// The routing topic was not a bounded portable topic.
    #[error("realtime fan-out topic is invalid")]
    InvalidTopic,
    /// The event type was not a bounded portable type.
    #[error("realtime fan-out type is invalid")]
    InvalidEventType,
    /// The optional correlation identifier was invalid.
    #[error("realtime fan-out correlation identifier is invalid")]
    InvalidCorrelationId,
    /// An ephemeral provider record attempted to carry a replay cursor.
    #[error("realtime fan-out cursor is not allowed for ephemeral delivery")]
    CursorNotAllowed,
    /// A replay cursor was malformed or exceeded its string bound.
    #[error("realtime fan-out cursor is invalid")]
    InvalidCursor,
    /// Event data was not a JSON object.
    #[error("realtime fan-out data is invalid")]
    InvalidData,
    /// Event data exceeded its size, nesting-depth, or node-count bound.
    #[error("realtime fan-out data exceeds a structural limit")]
    DataOutOfBounds,
}

/// Exact canonical JSON codec for provider-neutral fan-out records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FanoutWireCodec {
    mode: FanoutWireMode,
}

impl FanoutWireCodec {
    /// Creates a codec whose cursor policy matches the provider's delivery semantics.
    #[must_use]
    pub const fn new(mode: FanoutWireMode) -> Self {
        Self { mode }
    }

    /// Creates a cursor-free codec for Redis Pub/Sub, Core NATS, or another ephemeral provider.
    #[must_use]
    pub const fn ephemeral() -> Self {
        Self::new(FanoutWireMode::Ephemeral)
    }

    /// Creates a codec reserved for a provider that genuinely supports replay.
    #[must_use]
    pub const fn replay() -> Self {
        Self::new(FanoutWireMode::Replay)
    }

    /// Returns the provider semantics enforced by this codec.
    #[must_use]
    pub const fn mode(self) -> FanoutWireMode {
        self.mode
    }

    /// Encodes the exact compact canonical JSON record.
    ///
    /// # Errors
    ///
    /// Returns [`FanoutCodecError::CursorNotAllowed`] when an ephemeral codec receives a replay
    /// event, or [`FanoutCodecError::EventTooLarge`] when the final record exceeds its fixed bound.
    pub fn encode(self, event: &CanonicalFanoutEvent) -> Result<Vec<u8>, FanoutCodecError> {
        if self.mode == FanoutWireMode::Ephemeral && event.cursor.is_some() {
            return Err(FanoutCodecError::CursorNotAllowed);
        }
        let encoded = serde_json::to_vec(&EncodedFanoutEvent::from(event))
            .map_err(|_| FanoutCodecError::InvalidEnvelope)?;
        if encoded.len() > MAX_FANOUT_EVENT_BYTES {
            return Err(FanoutCodecError::EventTooLarge);
        }
        Ok(encoded)
    }

    /// Decodes and validates an exact compact canonical JSON record.
    ///
    /// The byte bound is checked before JSON decoding. Unknown and duplicate fields at every
    /// object level are rejected, and no failure retains or renders input values.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`FanoutCodecError`] when any wire, value, mode, or structural invariant
    /// is violated.
    pub fn decode(self, input: &[u8]) -> Result<CanonicalFanoutEvent, FanoutCodecError> {
        if input.len() > MAX_FANOUT_EVENT_BYTES {
            return Err(FanoutCodecError::EventTooLarge);
        }
        let decoded: DecodedFanoutEvent =
            serde_json::from_slice(input).map_err(|_| FanoutCodecError::InvalidEnvelope)?;
        if decoded.v != FANOUT_WIRE_VERSION {
            return Err(FanoutCodecError::UnsupportedVersion);
        }

        let source_id = decoded
            .source_id
            .parse()
            .map_err(|_| FanoutCodecError::InvalidSourceId)?;
        let tenant_id = parse_tenant_id(&decoded.tenant_id)?;
        let topic = Topic::new(decoded.topic).map_err(|_| FanoutCodecError::InvalidTopic)?;
        let event_type =
            MessageType::new(decoded.event_type).map_err(|_| FanoutCodecError::InvalidEventType)?;
        let correlation_id = decoded
            .correlation_id
            .0
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| FanoutCodecError::InvalidCorrelationId)?;
        if self.mode == FanoutWireMode::Ephemeral && decoded.cursor.0.is_some() {
            return Err(FanoutCodecError::CursorNotAllowed);
        }
        let cursor = decoded
            .cursor
            .0
            .map(OpaqueCursor::new)
            .transpose()
            .map_err(|_| FanoutCodecError::InvalidCursor)?;
        let Value::Object(data) = decoded.data.0 else {
            return Err(FanoutCodecError::InvalidData);
        };
        let data = ObjectPayload::new(data).map_err(|_| FanoutCodecError::DataOutOfBounds)?;
        let event = CanonicalFanoutEvent {
            source_id,
            tenant_id,
            topic,
            event_type,
            correlation_id,
            cursor,
            data,
        };
        if self.encode(&event)?.as_slice() != input {
            return Err(FanoutCodecError::NonCanonical);
        }
        Ok(event)
    }
}

#[derive(Serialize)]
struct EncodedFanoutEvent<'a> {
    v: u16,
    source_id: MessageId,
    tenant_id: TenantId,
    topic: &'a Topic,
    #[serde(rename = "type")]
    event_type: &'a MessageType,
    correlation_id: Option<MessageId>,
    cursor: Option<&'a OpaqueCursor>,
    data: &'a ObjectPayload,
}

impl<'a> From<&'a CanonicalFanoutEvent> for EncodedFanoutEvent<'a> {
    fn from(event: &'a CanonicalFanoutEvent) -> Self {
        Self {
            v: FANOUT_WIRE_VERSION,
            source_id: event.source_id,
            tenant_id: event.tenant_id,
            topic: &event.topic,
            event_type: &event.event_type,
            correlation_id: event.correlation_id,
            cursor: event.cursor.as_ref(),
            data: &event.data,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedFanoutEvent {
    v: u16,
    source_id: String,
    tenant_id: String,
    topic: String,
    #[serde(rename = "type")]
    event_type: String,
    correlation_id: RequiredNullable<String>,
    cursor: RequiredNullable<String>,
    data: StrictValue,
}

fn parse_tenant_id(value: &str) -> Result<TenantId, FanoutCodecError> {
    let uuid = Uuid::parse_str(value).map_err(|_| FanoutCodecError::InvalidTenantId)?;
    let mut buffer = Uuid::encode_buffer();
    if uuid.hyphenated().encode_lower(&mut buffer) != value {
        return Err(FanoutCodecError::InvalidTenantId);
    }
    TenantId::from_uuid(uuid).map_err(|_| FanoutCodecError::InvalidTenantId)
}

/// Asynchronous application boundary for refreshing authorization before fan-out admission.
pub trait FanoutAuthorizer: Send + Sync {
    /// The application-specific lookup or authorization failure.
    type Error;

    /// Refreshes authoritative facts for one current registry snapshot.
    ///
    /// `Ok(true)` allows delivery. `Ok(false)`, an error, and a decision timeout fail closed by
    /// revoking the exact subscription generation and producing only its existing control intent.
    fn authorize<'a>(
        &'a self,
        event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a;
}

/// One authorized fan-out target without a transport handle or queue operation.
#[derive(Clone, Eq, PartialEq)]
pub struct FanoutTarget {
    connection_id: crate::protocol::ConnectionId,
    subscription_id: SubscriptionId,
    subscription_generation: u64,
    encoded_event: Vec<u8>,
}

impl FanoutTarget {
    /// Returns the target connection.
    #[must_use]
    pub const fn connection_id(&self) -> crate::protocol::ConnectionId {
        self.connection_id
    }

    /// Returns the target subscription.
    #[must_use]
    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    /// Returns the authoritative subscription generation checked immediately before this intent.
    #[must_use]
    pub const fn subscription_generation(&self) -> u64 {
        self.subscription_generation
    }

    /// Returns the exact bounded outbound protocol event.
    #[must_use]
    pub fn encoded_event(&self) -> &[u8] {
        &self.encoded_event
    }

    /// Consumes this target and returns the exact bounded outbound protocol event.
    #[must_use]
    pub fn into_encoded_event(self) -> Vec<u8> {
        self.encoded_event
    }
}

impl fmt::Debug for FanoutTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FanoutTarget")
            .field("subscription_generation", &self.subscription_generation)
            .finish_non_exhaustive()
    }
}

/// One bounded transport-neutral result of fan-out routing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FanoutDeliveryIntent {
    /// An authorized event target checked against the current active registry generation.
    Target(FanoutTarget),
    /// The existing subscription-revoked control intent after denial or authorization failure.
    Control(ControlIntent),
}

/// One capacity reservation acquired before a fan-out intent is allocated or encoded.
pub trait FanoutIntentReservation: Send {
    /// The sink-specific admission failure.
    type Error: Send;

    /// Consumes this reservation by admitting exactly one bounded intent.
    fn admit(
        self,
        intent: FanoutDeliveryIntent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Incremental bounded sink for fan-out intents.
///
/// Implementations must account for `maximum_encoded_bytes` before returning a reservation. A
/// reservation releases that capacity when dropped or transfers it to the admitted intent.
pub trait FanoutIntentSink: Send + Sync {
    /// The sink-specific reservation or admission failure.
    type Error: Send;
    /// An owned single-intent capacity reservation.
    type Reservation: FanoutIntentReservation<Error = Self::Error>;

    /// Asynchronously reserves capacity for one intent before the router allocates its event.
    fn reserve(
        &self,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send;
}

/// A stable, value-free fan-out routing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FanoutRouteError {
    /// Registry state could not be trusted.
    #[error("realtime fan-out routing is unavailable")]
    Unavailable,
    /// The canonical event could not fit the bounded outbound protocol envelope.
    #[error("realtime fan-out event cannot be encoded")]
    Encoding,
    /// The bounded sink could not reserve or admit the intent.
    #[error("realtime fan-out sink is unavailable")]
    SinkUnavailable,
    /// The whole route deadline elapsed.
    #[error("realtime fan-out route deadline exceeded")]
    DeadlineExceeded,
}

/// Provider-neutral router from canonical events to an incremental bounded intent sink.
pub struct FanoutRouter<A> {
    registry: Arc<ConnectionRegistry>,
    authorizer: A,
    config: FanoutRouterConfig,
}

impl<A> FanoutRouter<A>
where
    A: FanoutAuthorizer,
{
    /// Creates a router over a shared registry, application authorizer, and validated limits.
    #[must_use]
    pub fn new(
        registry: Arc<ConnectionRegistry>,
        authorizer: A,
        config: FanoutRouterConfig,
    ) -> Self {
        Self {
            registry,
            authorizer,
            config,
        }
    }

    /// Returns the shared registry used for exact routing and generation checks.
    #[must_use]
    pub const fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.registry
    }

    /// Returns the validated deadlines and retained-work limits.
    #[must_use]
    pub const fn config(&self) -> FanoutRouterConfig {
        self.config
    }

    /// Routes one canonical event incrementally through `sink`.
    ///
    /// Topic traversal retains one registry snapshot at a time. Authorization work is capped by
    /// [`FanoutRouterConfig::authorization_concurrency`], all authorization plus sink work is
    /// capped by [`FanoutRouterConfig::max_in_flight`], and every sink reservation accounts for
    /// [`MAX_ENVELOPE_BYTES`] before event projection or encoding.
    ///
    /// A denial, authorizer error, or per-decision timeout revokes only the exact observed
    /// generation. A stale allow or denial emits nothing. The canonical event remains immutably
    /// shared by every in-flight operation.
    ///
    /// # Errors
    ///
    /// Returns a stable [`FanoutRouteError`] when registry access, event encoding, sink admission,
    /// or the whole route deadline fails.
    pub async fn route<S>(
        &self,
        event: &CanonicalFanoutEvent,
        sink: &S,
    ) -> Result<(), FanoutRouteError>
    where
        S: FanoutIntentSink,
    {
        let route_deadline = Instant::now() + self.config.route_timeout;
        let mut cursor = self
            .registry
            .subscriptions_for_topic(event.tenant_id, &event.topic);
        let mut exhausted = false;
        let mut authorizations = FuturesUnordered::new();
        let mut admissions = FuturesUnordered::new();

        loop {
            while !exhausted
                && authorizations.len() < self.config.authorization_concurrency
                && authorizations.len() + admissions.len() < self.config.max_in_flight
            {
                let Some(subscription) = cursor
                    .next_subscription()
                    .map_err(|_| FanoutRouteError::Unavailable)?
                else {
                    exhausted = true;
                    break;
                };
                authorizations.push(async move {
                    let decision = timeout(
                        self.config.authorization_timeout,
                        self.authorizer.authorize(event, &subscription),
                    )
                    .await;
                    (subscription, matches!(decision, Ok(Ok(true))))
                });
            }

            if exhausted && authorizations.is_empty() && admissions.is_empty() {
                return if Instant::now() >= route_deadline {
                    Err(FanoutRouteError::DeadlineExceeded)
                } else {
                    Ok(())
                };
            }

            tokio::select! {
                () = sleep_until(route_deadline) => {
                    return Err(FanoutRouteError::DeadlineExceeded);
                }
                admission = admissions.next(), if !admissions.is_empty() => {
                    if let Some(result) = admission {
                        result?;
                    }
                }
                authorization = authorizations.next(), if !authorizations.is_empty() => {
                    if let Some((subscription, allowed)) = authorization {
                        let candidate = if allowed {
                            Some(AdmissionCandidate::Target(subscription))
                        } else {
                            revoke_after_failed_authorization(&self.registry, &subscription)?
                                .map(AdmissionCandidate::Control)
                        };
                        if let Some(candidate) = candidate {
                            admissions.push(admit_candidate(
                                &self.registry,
                                event,
                                sink,
                                candidate,
                            ));
                        }
                    }
                }
            }
        }
    }
}

enum AdmissionCandidate {
    Target(SubscriptionSnapshot),
    Control(ControlIntent),
}

fn revoke_after_failed_authorization(
    registry: &ConnectionRegistry,
    subscription: &SubscriptionSnapshot,
) -> Result<Option<ControlIntent>, FanoutRouteError> {
    match registry.revoke_subscription_if_current(
        subscription,
        crate::protocol::RevocationReason::AuthorizationChanged,
    ) {
        Ok(intent) => Ok(Some(intent)),
        Err(
            RegistryError::SubscriptionNotFound
            | RegistryError::SubscriptionConflict
            | RegistryError::InvalidState,
        ) => Ok(None),
        Err(_) => Err(FanoutRouteError::Unavailable),
    }
}

async fn admit_candidate<S>(
    registry: &ConnectionRegistry,
    event: &CanonicalFanoutEvent,
    sink: &S,
    candidate: AdmissionCandidate,
) -> Result<(), FanoutRouteError>
where
    S: FanoutIntentSink,
{
    let reservation = sink
        .reserve(MAX_ENVELOPE_BYTES)
        .await
        .map_err(|_| FanoutRouteError::SinkUnavailable)?;
    let intent = match candidate {
        AdmissionCandidate::Target(subscription) => {
            let is_current = registry
                .is_subscription_current_active(subscription.id(), subscription.generation())
                .map_err(|_| FanoutRouteError::Unavailable)?;
            if !is_current {
                return Ok(());
            }
            let output = EventOutput::with_id(
                event.source_id,
                event.event_type.clone(),
                event.correlation_id,
                subscription.id(),
                subscription.topic().clone(),
                event.cursor.clone(),
                event.data.clone(),
            );
            let encoded_event = OutboundMessage::Event(output)
                .encode()
                .map_err(|_| FanoutRouteError::Encoding)?;
            FanoutDeliveryIntent::Target(FanoutTarget {
                connection_id: subscription.connection_id(),
                subscription_id: subscription.id(),
                subscription_generation: subscription.generation(),
                encoded_event,
            })
        }
        AdmissionCandidate::Control(intent) => FanoutDeliveryIntent::Control(intent),
    };
    reservation
        .admit(intent)
        .await
        .map_err(|_| FanoutRouteError::SinkUnavailable)
}
