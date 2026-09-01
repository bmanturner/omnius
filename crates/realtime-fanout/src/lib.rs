//! Canonical realtime fan-out composition for ephemeral Redis and Core NATS backplanes.
//!
//! Application projectors explicitly construct the allowlisted canonical event. Provider adapters
//! transport only its bounded canonical bytes, while each ingress routes through a caller-owned
//! [`FanoutIntentSink`], including the shared connection delivery hub. Providers never own a
//! connection handle, connection queue, wire writer, or replay store.

#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use futures::future::BoxFuture;
use omnius_core::{ErrorCode, ServiceError};
use omnius_events_nats::{
    DeliveryContext, EventHandler as NatsEventHandler, HandlerOutcome, NatsCoreFanout,
    NatsCoreFanoutMessage, NatsCoreFanoutPublisher as ProviderNatsPublisher,
    NatsCoreFanoutReceiver, NatsCoreFanoutStatus, RawEvent,
};
use omnius_events_redis_ephemeral::{
    EphemeralMessage, RedisEphemeralEvents, RedisEphemeralListenerStatus,
    RedisEphemeralPublisher as ProviderRedisPublisher, RedisEphemeralReceiver,
};
use omnius_jobs_core::FailureCode;
use omnius_realtime_core::{
    CanonicalFanoutEvent, ConnectionDeliveryHub, FanoutAuthorizer, FanoutIntentSink, FanoutRouter,
    FanoutWireCodec,
};
use omnius_runtime::{Criticality, TaskSpec};
use thiserror::Error;

/// Application-owned allowlist projection from a domain event into realtime fan-out.
///
/// Implementations must load authoritative tenant and resource facts and select every exposed data
/// field deliberately. Returning `None` declares that the source event is not realtime-visible.
pub trait FanoutProjector<Source: ?Sized>: Send + Sync {
    /// Projects one source event into a validated canonical realtime event.
    ///
    /// # Errors
    ///
    /// Returns a stable category without retaining source payloads or application diagnostics.
    fn project(
        &self,
        source: &Source,
    ) -> Result<Option<CanonicalFanoutEvent>, FanoutProjectionError>;
}

/// Stable, value-free application projection failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FanoutProjectionError {
    /// Authoritative tenant or resource facts could not be established.
    #[error("realtime fan-out projection facts are unavailable")]
    FactsUnavailable,
    /// The source event cannot be represented by the configured realtime allowlist.
    #[error("realtime fan-out projection is rejected")]
    Rejected,
}

struct RedactedRoute;

impl fmt::Debug for RedactedRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[redacted]")
    }
}

/// Stable, value-free provider composition failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FanoutAdapterError {
    /// A projected event could not be encoded for an ephemeral provider.
    #[error("realtime fan-out event is invalid for ephemeral delivery")]
    InvalidEvent,
    /// Provider bytes were not an exact bounded canonical ephemeral record.
    #[error("realtime fan-out provider record is invalid")]
    InvalidRecord,
    /// Redis delivered a record through a channel other than this adapter's exact route.
    #[error("realtime fan-out provider route is invalid")]
    InvalidRoute,
    /// Current registry state could not be trusted.
    #[error("realtime fan-out routing is unavailable")]
    RoutingUnavailable,
    /// The selected ephemeral provider could not accept a publication.
    #[error("realtime fan-out publishing is unavailable")]
    PublishingUnavailable,
}

fn encode_ephemeral(event: &CanonicalFanoutEvent) -> Result<Vec<u8>, FanoutAdapterError> {
    FanoutWireCodec::ephemeral()
        .encode(event)
        .map_err(|_| FanoutAdapterError::InvalidEvent)
}

fn decode_ephemeral(payload: &[u8]) -> Result<CanonicalFanoutEvent, FanoutAdapterError> {
    FanoutWireCodec::ephemeral()
        .decode(payload)
        .map_err(|_| FanoutAdapterError::InvalidRecord)
}

/// Canonical publisher composition for one statically configured Redis logical channel.
#[derive(Clone)]
pub struct RedisFanoutPublisher {
    provider: ProviderRedisPublisher,
    channel: Box<str>,
}

impl RedisFanoutPublisher {
    /// Binds the canonical publisher to one exact configured logical Redis channel.
    #[must_use]
    pub fn new(provider: ProviderRedisPublisher, channel: impl Into<Box<str>>) -> Self {
        Self {
            provider,
            channel: channel.into(),
        }
    }

    /// Canonically encodes and publishes one cursor-free event.
    ///
    /// A successful result is Redis's point-in-time server acceptance only. It is not a delivery
    /// acknowledgement and provides no replay guarantee.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid ephemeral events or unavailable publication.
    pub async fn publish(&self, event: &CanonicalFanoutEvent) -> Result<(), FanoutAdapterError> {
        let encoded = encode_ephemeral(event)?;
        self.provider
            .publish(&self.channel, &encoded)
            .await
            .map(|_| ())
            .map_err(|_| FanoutAdapterError::PublishingUnavailable)
    }
}

impl fmt::Debug for RedisFanoutPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisFanoutPublisher")
            .field("route", &RedactedRoute)
            .finish_non_exhaustive()
    }
}

/// Redis ingress composition from bounded provider records to authorized delivery intents.
pub struct RedisFanoutIngress<A> {
    router: FanoutRouter<A>,
    channel: Box<str>,
}

impl<A> RedisFanoutIngress<A>
where
    A: FanoutAuthorizer,
{
    /// Binds a provider-neutral router to one exact configured logical Redis channel.
    #[must_use]
    pub fn new(router: FanoutRouter<A>, channel: impl Into<Box<str>>) -> Self {
        Self {
            router,
            channel: channel.into(),
        }
    }

    /// Decodes and authorizes one Redis message immediately before producing local intents.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for a route mismatch, invalid record, or unavailable registry.
    pub async fn route<S>(
        &self,
        message: &EphemeralMessage,
        sink: &S,
    ) -> Result<(), FanoutAdapterError>
    where
        S: FanoutIntentSink,
    {
        if message.channel() != self.channel.as_ref() {
            return Err(FanoutAdapterError::InvalidRoute);
        }
        self.route_payload(message.payload(), sink).await
    }

    /// Receives and routes the next locally retained Redis message incrementally.
    ///
    /// `None` means provider intake stopped. Passing the shared connection delivery hub as `sink`
    /// preserves one bounded queue per transport connection.
    pub async fn recv_and_route<S>(
        &self,
        receiver: &mut RedisEphemeralReceiver,
        sink: &S,
    ) -> Option<Result<(), FanoutAdapterError>>
    where
        S: FanoutIntentSink,
    {
        let message = receiver.recv().await?;
        Some(self.route(&message, sink).await)
    }

    async fn route_payload<S>(&self, payload: &[u8], sink: &S) -> Result<(), FanoutAdapterError>
    where
        S: FanoutIntentSink,
    {
        let event = decode_ephemeral(payload)?;
        self.router
            .route(&event, sink)
            .await
            .map_err(|_| FanoutAdapterError::RoutingUnavailable)
    }
}

impl<A> fmt::Debug for RedisFanoutIngress<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisFanoutIngress")
            .field("route", &RedactedRoute)
            .finish_non_exhaustive()
    }
}

/// Canonical publisher composition for one statically configured Core NATS subject.
#[derive(Clone)]
pub struct NatsFanoutPublisher {
    provider: ProviderNatsPublisher,
}

impl NatsFanoutPublisher {
    /// Wraps a provider publisher whose exact subject was validated at provider construction.
    #[must_use]
    pub const fn new(provider: ProviderNatsPublisher) -> Self {
        Self { provider }
    }

    /// Canonically encodes and publishes one cursor-free event.
    ///
    /// A successful flush is only a server handoff. Core NATS provides no acknowledgement or
    /// replay for this fan-out profile.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid ephemeral events or unavailable publication.
    pub async fn publish(&self, event: &CanonicalFanoutEvent) -> Result<(), FanoutAdapterError> {
        let encoded = encode_ephemeral(event)?;
        self.provider
            .publish(encoded.into())
            .await
            .map_err(|_| FanoutAdapterError::PublishingUnavailable)
    }
}

impl fmt::Debug for NatsFanoutPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsFanoutPublisher")
            .finish_non_exhaustive()
    }
}

/// Core NATS ingress composition from bounded provider records to authorized delivery intents.
pub struct NatsFanoutIngress<A> {
    router: FanoutRouter<A>,
}

impl<A> NatsFanoutIngress<A>
where
    A: FanoutAuthorizer,
{
    /// Binds a provider-neutral router to the provider's one exact Core NATS subject.
    #[must_use]
    pub const fn new(router: FanoutRouter<A>) -> Self {
        Self { router }
    }

    /// Decodes and authorizes one Core NATS record immediately before producing local intents.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid records or unavailable registry state.
    pub async fn route<S>(
        &self,
        message: &NatsCoreFanoutMessage,
        sink: &S,
    ) -> Result<(), FanoutAdapterError>
    where
        S: FanoutIntentSink,
    {
        let event = decode_ephemeral(message.payload())?;
        self.router
            .route(&event, sink)
            .await
            .map_err(|_| FanoutAdapterError::RoutingUnavailable)
    }

    /// Receives and routes the next locally retained Core NATS message incrementally.
    ///
    /// `None` means provider intake stopped. Passing the shared connection delivery hub as `sink`
    /// preserves one bounded queue per transport connection.
    pub async fn recv_and_route<S>(
        &self,
        receiver: &mut NatsCoreFanoutReceiver,
        sink: &S,
    ) -> Option<Result<(), FanoutAdapterError>>
    where
        S: FanoutIntentSink,
    {
        let message = receiver.recv().await?;
        Some(self.route(&message, sink).await)
    }
}

impl<A> fmt::Debug for NatsFanoutIngress<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsFanoutIngress")
            .finish_non_exhaustive()
    }
}

/// Object-safe application publication port for one validated canonical realtime event.
pub trait RealtimeEventPublisher: Send + Sync {
    /// Publishes one event through the statically selected fan-out provider.
    fn publish<'a>(
        &'a self,
        event: &'a CanonicalFanoutEvent,
    ) -> BoxFuture<'a, Result<(), FanoutAdapterError>>;
}

impl RealtimeEventPublisher for RedisFanoutPublisher {
    fn publish<'a>(
        &'a self,
        event: &'a CanonicalFanoutEvent,
    ) -> BoxFuture<'a, Result<(), FanoutAdapterError>> {
        Box::pin(async move { RedisFanoutPublisher::publish(self, event).await })
    }
}

impl RealtimeEventPublisher for NatsFanoutPublisher {
    fn publish<'a>(
        &'a self,
        event: &'a CanonicalFanoutEvent,
    ) -> BoxFuture<'a, Result<(), FanoutAdapterError>> {
        Box::pin(async move { NatsFanoutPublisher::publish(self, event).await })
    }
}

const REDIS_INGRESS_TASK_NAME: &str = "redis-realtime-fanout-ingress";
const NATS_CORE_INGRESS_TASK_NAME: &str = "nats-core-realtime-fanout-ingress";
const FANOUT_MODULE_NAME: &str = "realtime-fanout";
const INGRESS_ERROR_CODE: &str = "REALTIME_FANOUT_INGRESS_STOPPED";

/// Complete Redis realtime fan-out registration.
///
/// Construction consumes [`RedisEphemeralEvents`], so its sole bounded receiver cannot be
/// registered by a second ingress. The returned listener and ingress tasks are both degraded; the
/// inherited HTTP service remains available when the explicitly lossy provider is unavailable.
pub struct RedisFanoutRuntime {
    publisher: RedisFanoutPublisher,
    status: RedisEphemeralListenerStatus,
    listener_task: TaskSpec,
    ingress_task: TaskSpec,
}

impl RedisFanoutRuntime {
    /// Binds one Redis provider instance to one router and the process's shared delivery hub.
    #[must_use]
    pub fn new<A>(
        events: RedisEphemeralEvents,
        router: FanoutRouter<A>,
        channel: impl Into<Box<str>>,
        delivery_hub: ConnectionDeliveryHub,
    ) -> Self
    where
        A: FanoutAuthorizer + 'static,
    {
        let status = events.listener_status();
        let (provider_publisher, receiver, listener_task) = events.into_parts();
        let channel = channel.into();
        let publisher = RedisFanoutPublisher::new(provider_publisher, channel.clone());
        let ingress = RedisFanoutIngress::new(router, channel);
        let ingress_task = redis_ingress_task(ingress, receiver, delivery_hub);
        Self {
            publisher,
            status,
            listener_task,
            ingress_task,
        }
    }

    /// Returns the canonical ephemeral publisher.
    #[must_use]
    pub const fn publisher(&self) -> &RedisFanoutPublisher {
        &self.publisher
    }

    /// Returns current degraded-listener readiness.
    #[must_use]
    pub const fn status(&self) -> &RedisEphemeralListenerStatus {
        &self.status
    }

    /// Consumes the registration into its publisher, readiness handle, sole listener task, and
    /// sole bounded ingress task.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RedisFanoutPublisher,
        RedisEphemeralListenerStatus,
        TaskSpec,
        TaskSpec,
    ) {
        (
            self.publisher,
            self.status,
            self.listener_task,
            self.ingress_task,
        )
    }
}

/// Complete ephemeral Core NATS realtime fan-out registration.
///
/// This type makes no durability, acknowledgement, cursor, or replay claim. Durable consumption
/// remains exclusively in [`omnius_events_nats::NatsJetStreamRuntime`].
pub struct NatsCoreFanoutRuntime {
    publisher: NatsFanoutPublisher,
    status: NatsCoreFanoutStatus,
    listener_task: TaskSpec,
    ingress_task: TaskSpec,
}

impl NatsCoreFanoutRuntime {
    /// Binds one Core NATS provider instance to one router and the process's shared delivery hub.
    #[must_use]
    pub fn new<A>(
        fanout: NatsCoreFanout,
        router: FanoutRouter<A>,
        delivery_hub: ConnectionDeliveryHub,
    ) -> Self
    where
        A: FanoutAuthorizer + 'static,
    {
        let (provider_publisher, receiver, status, listener_task) = fanout.into_parts();
        let publisher = NatsFanoutPublisher::new(provider_publisher);
        let ingress = NatsFanoutIngress::new(router);
        let ingress_task = nats_core_ingress_task(ingress, receiver, delivery_hub);
        Self {
            publisher,
            status,
            listener_task,
            ingress_task,
        }
    }

    /// Returns the canonical ephemeral publisher.
    #[must_use]
    pub const fn publisher(&self) -> &NatsFanoutPublisher {
        &self.publisher
    }

    /// Returns current ephemeral subscription readiness.
    #[must_use]
    pub const fn status(&self) -> &NatsCoreFanoutStatus {
        &self.status
    }

    /// Consumes the registration into its publisher, readiness handle, sole listener task, and
    /// sole bounded ingress task.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        NatsFanoutPublisher,
        NatsCoreFanoutStatus,
        TaskSpec,
        TaskSpec,
    ) {
        (
            self.publisher,
            self.status,
            self.listener_task,
            self.ingress_task,
        )
    }
}

struct OwnedRedisIngress<A> {
    ingress: RedisFanoutIngress<A>,
    receiver: RedisEphemeralReceiver,
    delivery_hub: ConnectionDeliveryHub,
}

struct OwnedNatsCoreIngress<A> {
    ingress: NatsFanoutIngress<A>,
    receiver: NatsCoreFanoutReceiver,
    delivery_hub: ConnectionDeliveryHub,
}

fn redis_ingress_task<A>(
    ingress: RedisFanoutIngress<A>,
    receiver: RedisEphemeralReceiver,
    delivery_hub: ConnectionDeliveryHub,
) -> TaskSpec
where
    A: FanoutAuthorizer + 'static,
{
    let shutdown_timeout = delivery_hub.config().drain_timeout();
    let owned = Arc::new(Mutex::new(Some(OwnedRedisIngress {
        ingress,
        receiver,
        delivery_hub,
    })));
    TaskSpec::new(
        REDIS_INGRESS_TASK_NAME,
        FANOUT_MODULE_NAME,
        Criticality::Degraded,
        shutdown_timeout,
        move |context| {
            let owned = lock(&owned).take();
            async move {
                let Some(mut owned) = owned else {
                    return Err(ingress_stopped_error());
                };
                loop {
                    tokio::select! {
                        biased;
                        () = context.draining() => return Ok(()),
                        () = context.shutdown_requested() => return Ok(()),
                        () = context.cancelled() => return Ok(()),
                        result = owned.ingress.recv_and_route(
                            &mut owned.receiver,
                            &owned.delivery_hub,
                        ) => {
                            match result {
                                Some(Ok(()) | Err(_)) => {}
                                None => return Err(ingress_stopped_error()),
                            }
                        }
                    }
                }
            }
        },
    )
}

fn nats_core_ingress_task<A>(
    ingress: NatsFanoutIngress<A>,
    receiver: NatsCoreFanoutReceiver,
    delivery_hub: ConnectionDeliveryHub,
) -> TaskSpec
where
    A: FanoutAuthorizer + 'static,
{
    let shutdown_timeout = delivery_hub.config().drain_timeout();
    let owned = Arc::new(Mutex::new(Some(OwnedNatsCoreIngress {
        ingress,
        receiver,
        delivery_hub,
    })));
    TaskSpec::new(
        NATS_CORE_INGRESS_TASK_NAME,
        FANOUT_MODULE_NAME,
        Criticality::Degraded,
        shutdown_timeout,
        move |context| {
            let owned = lock(&owned).take();
            async move {
                let Some(mut owned) = owned else {
                    return Err(ingress_stopped_error());
                };
                loop {
                    tokio::select! {
                        biased;
                        () = context.draining() => return Ok(()),
                        () = context.shutdown_requested() => return Ok(()),
                        () = context.cancelled() => return Ok(()),
                        result = owned.ingress.recv_and_route(
                            &mut owned.receiver,
                            &owned.delivery_hub,
                        ) => {
                            match result {
                                Some(Ok(()) | Err(_)) => {}
                                None => return Err(ingress_stopped_error()),
                            }
                        }
                    }
                }
            }
        },
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn ingress_stopped_error() -> ServiceError {
    ServiceError::new(
        static_error_code(INGRESS_ERROR_CODE),
        "realtime fan-out ingress stopped",
    )
}

fn static_error_code(value: &'static str) -> ErrorCode {
    match ErrorCode::try_new(value) {
        Ok(code) => code,
        Err(_) => unreachable!("static realtime fan-out error code must be valid"),
    }
}

/// Application-owned durable event handling result.
#[derive(Clone, Debug)]
pub enum RealtimeEventOutcome {
    /// The event completed without a browser-visible projection.
    Success,
    /// Route this canonical event through the same process delivery hub before acknowledging.
    Deliver(CanonicalFanoutEvent),
    /// Delay and redeliver the source event.
    Retryable(FailureCode),
    /// Dead-letter the source event before acknowledging it.
    Permanent(FailureCode),
}

/// Application port that converts one durable internal event into an explicit handling result.
pub trait RealtimeEventHandler: Send + Sync + 'static {
    /// Handles one verified immutable durable event.
    fn handle(
        &self,
        event: RawEvent,
        context: DeliveryContext,
    ) -> BoxFuture<'_, RealtimeEventOutcome>;
}

/// Canonical `JetStream` handler adapter that routes successful projections into the shared hub.
pub struct NatsJetStreamFanoutHandler<H, A> {
    application: H,
    router: FanoutRouter<A>,
    delivery_hub: ConnectionDeliveryHub,
}

impl<H, A> NatsJetStreamFanoutHandler<H, A> {
    /// Binds a mandatory application handler to one fan-out router and the process's shared hub.
    #[must_use]
    pub const fn new(
        application: H,
        router: FanoutRouter<A>,
        delivery_hub: ConnectionDeliveryHub,
    ) -> Self {
        Self {
            application,
            router,
            delivery_hub,
        }
    }
}

impl<H, A> NatsEventHandler for NatsJetStreamFanoutHandler<H, A>
where
    H: RealtimeEventHandler,
    A: FanoutAuthorizer + 'static,
{
    fn handle(&self, event: RawEvent, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            match self.application.handle(event, context).await {
                RealtimeEventOutcome::Success => HandlerOutcome::Success,
                RealtimeEventOutcome::Deliver(event) => {
                    if self.router.route(&event, &self.delivery_hub).await.is_ok() {
                        HandlerOutcome::Success
                    } else {
                        HandlerOutcome::Retryable(realtime_route_failure_code())
                    }
                }
                RealtimeEventOutcome::Retryable(code) => HandlerOutcome::Retryable(code),
                RealtimeEventOutcome::Permanent(code) => HandlerOutcome::Permanent(code),
            }
        })
    }
}

fn realtime_route_failure_code() -> FailureCode {
    match FailureCode::try_from("realtime_route_unavailable") {
        Ok(code) => code,
        Err(_) => unreachable!("static realtime route failure code must be valid"),
    }
}
