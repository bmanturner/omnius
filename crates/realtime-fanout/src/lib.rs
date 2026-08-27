//! Canonical realtime fan-out composition for ephemeral Redis and Core NATS backplanes.
//!
//! Application projectors explicitly construct the allowlisted canonical event. Provider adapters
//! transport only its bounded canonical bytes, while each ingress routes through a caller-owned
//! [`FanoutIntentSink`], including the shared connection delivery hub. Providers never own a
//! connection handle, connection queue, wire writer, or replay store.

#![forbid(unsafe_code)]

use omnius_events_nats::{
    NatsCoreFanoutMessage, NatsCoreFanoutPublisher as ProviderNatsPublisher, NatsCoreFanoutReceiver,
};
use omnius_events_redis_ephemeral::{
    EphemeralMessage, RedisEphemeralPublisher as ProviderRedisPublisher, RedisEphemeralReceiver,
};
use omnius_realtime_core::{
    CanonicalFanoutEvent, FanoutAuthorizer, FanoutIntentSink, FanoutRouter, FanoutWireCodec,
};
use std::fmt;
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
