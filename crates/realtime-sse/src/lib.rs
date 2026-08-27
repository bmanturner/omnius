//! Authenticated Axum SSE transport adapter for one authorized realtime subscription.
//!
//! Authentication stays in application composition. This adapter accepts the canonical
//! [`Principal`] placed in request extensions, installs the connection delivery receiver before
//! creating its authorized subscription, and supports either the shared hub or an unbuffered
//! provider-neutral source.

#![forbid(unsafe_code)]

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Extension, Router,
    extract::{Query, State, rejection::QueryRejection},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::get,
};
use futures::Stream;
use omnius_auth_core::Principal;
use omnius_authz_basic::AuthorizationProvider;
use omnius_core::{ErrorCode, RequestId, ServiceError};
use omnius_http::ProblemDetails;
use omnius_realtime_core::{
    AcceptedKind, CommandAuthorizationResolver, ConnectionDeliveryHub, ConnectionDeliveryReceiver,
    ConnectionId, ConnectionRegistry, ConnectionSnapshot, DeliveryMessage, DeliveryTerminal,
    InboundCommand, MessageId, OpaqueCursor, OutboundMessage, QueuedDelivery, RealtimeService,
    RejectionCode, SubscribeCommand, SubscriptionId, SubscriptionSnapshot, Topic,
};
use serde::Deserialize;
use thiserror::Error;

/// Reserved browser-facing SSE endpoint.
pub const SSE_EVENTS_PATH: &str = "/events";
/// Default interval between SSE heartbeat comments while the event source is pending.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// Smallest accepted heartbeat interval.
pub const MIN_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// Smallest accepted browser reconnect-retry interval.
pub const MIN_RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// Largest accepted heartbeat or reconnect-retry interval.
pub const MAX_SSE_INTERVAL: Duration = Duration::from_mins(5);
/// Retry used for terminal reconnect signals when no initial retry was configured.
pub const DEFAULT_TERMINAL_RETRY_INTERVAL: Duration = Duration::from_secs(1);

const LAST_EVENT_ID: HeaderName = HeaderName::from_static("last-event-id");
const X_ACCEL_BUFFERING: HeaderName = HeaderName::from_static("x-accel-buffering");

/// Invalid bounded SSE transport configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SseConfigError {
    /// The heartbeat interval falls outside the fixed transport bounds.
    #[error("invalid SSE heartbeat interval")]
    InvalidHeartbeatInterval,
    /// The optional reconnect retry interval falls outside the fixed transport bounds.
    #[error("invalid SSE retry interval")]
    InvalidRetryInterval,
}

/// Validated SSE heartbeat and browser reconnect configuration.
///
/// A retry directive requests a fresh connection only. It never claims resume or replay support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseConfig {
    heartbeat_interval: Duration,
    retry_interval: Option<Duration>,
}

impl SseConfig {
    /// Creates validated SSE transport configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SseConfigError`] when either configured duration falls outside the fixed bounds.
    pub fn new(
        heartbeat_interval: Duration,
        retry_interval: Option<Duration>,
    ) -> Result<Self, SseConfigError> {
        if !(MIN_HEARTBEAT_INTERVAL..=MAX_SSE_INTERVAL).contains(&heartbeat_interval) {
            return Err(SseConfigError::InvalidHeartbeatInterval);
        }
        if retry_interval
            .is_some_and(|interval| !(MIN_RETRY_INTERVAL..=MAX_SSE_INTERVAL).contains(&interval))
        {
            return Err(SseConfigError::InvalidRetryInterval);
        }
        Ok(Self {
            heartbeat_interval,
            retry_interval,
        })
    }

    /// Returns the heartbeat comment interval.
    #[must_use]
    pub const fn heartbeat_interval(self) -> Duration {
        self.heartbeat_interval
    }

    /// Returns the optional fresh-connection retry directive.
    #[must_use]
    pub const fn retry_interval(self) -> Option<Duration> {
        self.retry_interval
    }
}

impl Default for SseConfig {
    fn default() -> Self {
        Self {
            heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
            retry_interval: None,
        }
    }
}

/// A stable, provider-neutral event-source failure safe to expose at the adapter boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SseSourceError {
    /// The event source could not be opened or continue safely.
    #[error("realtime event source is unavailable")]
    Unavailable,
}

/// Unbuffered stream returned by a connection-scoped event source.
pub type SseMessageStream =
    Pin<Box<dyn Stream<Item = Result<OutboundMessage, SseSourceError>> + Send + 'static>>;

/// Future returned while opening a connection-scoped event source.
pub type SseOpenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SseMessageStream, SseSourceError>> + Send + 'a>>;

/// Authorized, immutable connection and subscription facts passed to an event source.
#[derive(Clone, Debug)]
pub struct SseSubscription {
    connection: ConnectionSnapshot,
    subscription: SubscriptionSnapshot,
}

impl SseSubscription {
    fn new(connection: ConnectionSnapshot, subscription: SubscriptionSnapshot) -> Self {
        Self {
            connection,
            subscription,
        }
    }

    /// Returns the active connection snapshot.
    #[must_use]
    pub const fn connection(&self) -> &ConnectionSnapshot {
        &self.connection
    }

    /// Returns the authorized subscription snapshot.
    #[must_use]
    pub const fn subscription(&self) -> &SubscriptionSnapshot {
        &self.subscription
    }
}

/// Opens an unbuffered provider-neutral stream for one already-authorized subscription.
///
/// Implementations must not introduce an unbounded queue. Provider-specific failures must be
/// mapped to [`SseSourceError`] before crossing this boundary.
pub trait SseEventSource: Send + Sync + 'static {
    /// Opens the source after the adapter has accepted and registered the subscription.
    fn open(&self, subscription: SseSubscription) -> SseOpenFuture<'_>;
}

/// Shared Axum state for the SSE route.
pub struct SseState<P, R> {
    service: Arc<RealtimeService<P, R>>,
    source: Option<Arc<dyn SseEventSource>>,
    config: SseConfig,
    delivery_hub: Option<ConnectionDeliveryHub>,
}

impl<P, R> SseState<P, R> {
    /// Creates route state from the transport-neutral service and provider-neutral event source.
    #[must_use]
    pub fn new<S>(service: Arc<RealtimeService<P, R>>, source: Arc<S>, config: SseConfig) -> Self
    where
        S: SseEventSource,
    {
        Self {
            service,
            source: Some(source),
            config,
            delivery_hub: None,
        }
    }

    /// Routes this adapter exclusively through the shared connection delivery hub.
    #[must_use]
    pub fn with_delivery_hub(mut self, delivery_hub: ConnectionDeliveryHub) -> Self {
        self.source = None;
        self.delivery_hub = Some(delivery_hub);
        self
    }

    /// Creates route state backed exclusively by the shared connection delivery hub.
    #[must_use]
    pub fn from_delivery_hub(
        service: Arc<RealtimeService<P, R>>,
        delivery_hub: ConnectionDeliveryHub,
        config: SseConfig,
    ) -> Self {
        Self {
            service,
            source: None,
            config,
            delivery_hub: Some(delivery_hub),
        }
    }

    /// Returns the optional shared delivery hub.
    #[must_use]
    pub const fn delivery_hub(&self) -> Option<&ConnectionDeliveryHub> {
        self.delivery_hub.as_ref()
    }

    /// Returns the transport configuration.
    #[must_use]
    pub const fn config(&self) -> SseConfig {
        self.config
    }
}

impl<P, R> Clone for SseState<P, R> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            source: self.source.clone(),
            config: self.config,
            delivery_hub: self.delivery_hub.clone(),
        }
    }
}

/// Builds a router exposing only authenticated `GET /events`.
///
/// The query requires a canonical `UUIDv7` `subscription_id`, a bounded `topic`, and an optional
/// opaque bounded `cursor`. Application composition must install a canonical [`Principal`]
/// request extension before this router. Missing authentication is rejected as RFC 9457 Problem
/// Details.
pub fn sse_router<P, R>(state: SseState<P, R>) -> Router
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
{
    Router::new()
        .route(SSE_EVENTS_PATH, get(events::<P, R>))
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SseQuery {
    subscription_id: String,
    topic: String,
    #[serde(default)]
    cursor: Option<String>,
}

#[allow(clippy::too_many_lines)]
async fn events<P, R>(
    State(state): State<SseState<P, R>>,
    headers: HeaderMap,
    principal: Option<Extension<Principal>>,
    request_id: Option<Extension<RequestId>>,
    query: Result<Query<SseQuery>, QueryRejection>,
) -> Response
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
{
    let request_id = request_id.map_or_else(RequestId::new, |Extension(id)| id);

    let Some(Extension(principal)) = principal else {
        return problem_response(
            StatusCode::UNAUTHORIZED,
            "SSE_AUTHENTICATION_REQUIRED",
            "authentication is required",
            request_id,
        );
    };
    if headers.contains_key(LAST_EVENT_ID) {
        return problem_response(
            StatusCode::CONFLICT,
            "SSE_REPLAY_UNAVAILABLE",
            "SSE replay is unavailable; reconnect without Last-Event-ID",
            request_id,
        );
    }
    let Ok(Query(query)) = query else {
        return invalid_subscription(request_id);
    };
    let Ok(subscription_id) = query.subscription_id.parse::<SubscriptionId>() else {
        return invalid_subscription(request_id);
    };
    let Ok(topic) = Topic::new(query.topic) else {
        return invalid_subscription(request_id);
    };
    let Ok(cursor) = query.cursor.map(OpaqueCursor::new).transpose() else {
        return invalid_subscription(request_id);
    };

    if state
        .delivery_hub
        .as_ref()
        .is_some_and(|delivery_hub| !delivery_hub.is_accepting())
    {
        return unavailable(request_id);
    }
    let registry = state.service.registry().clone();
    let Ok(connection) = registry.register(principal) else {
        return unavailable(request_id);
    };
    let lifecycle = ConnectionLifecycle::new(registry, connection.id(), state.delivery_hub.clone());
    let Ok(connection) = state.service.registry().activate(connection.id()) else {
        return unavailable(request_id);
    };
    let delivery_receiver = if let Some(delivery_hub) = &state.delivery_hub {
        let Ok(receiver) = delivery_hub.open_connection(connection.id()) else {
            return unavailable(request_id);
        };
        Some(receiver)
    } else {
        None
    };

    let output = state.service.handle(
        connection.id(),
        InboundCommand::Subscribe {
            id: MessageId::new(),
            correlation_id: None,
            command: SubscribeCommand::new(subscription_id, topic, cursor),
        },
    );
    match output {
        OutboundMessage::Accepted(accepted) => match accepted.kind() {
            AcceptedKind::SubscriptionCreated {
                subscription_id: accepted_id,
                ..
            } if *accepted_id == subscription_id => {}
            _ => return unavailable(request_id),
        },
        OutboundMessage::Rejected(rejected) => {
            return rejection_response(rejected.code(), request_id);
        }
        OutboundMessage::Event(_) | OutboundMessage::Control(_) => return unavailable(request_id),
    }

    let Ok(Some(subscription)) = state
        .service
        .registry()
        .subscription_for_connection(connection.id(), subscription_id)
    else {
        return unavailable(request_id);
    };
    let response_source = if let Some(receiver) = delivery_receiver {
        SseResponseSource::Delivery(receiver)
    } else {
        let Some(source) = &state.source else {
            return unavailable(request_id);
        };
        let Ok(source) = source
            .open(SseSubscription::new(connection, subscription))
            .await
        else {
            return unavailable(request_id);
        };
        SseResponseSource::Structured(source)
    };

    let stream = SseResponseStream::new(response_source, lifecycle, state.config.retry_interval());
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(state.config.heartbeat_interval())
                .text("heartbeat"),
        )
        .into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-transform"),
    );
    response
        .headers_mut()
        .insert(X_ACCEL_BUFFERING, HeaderValue::from_static("no"));
    response
}

fn invalid_subscription(request_id: RequestId) -> Response {
    problem_response(
        StatusCode::BAD_REQUEST,
        "SSE_INVALID_SUBSCRIPTION",
        "the SSE subscription query is invalid",
        request_id,
    )
}

fn unavailable(request_id: RequestId) -> Response {
    problem_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "SSE_UNAVAILABLE",
        "the SSE subscription is unavailable",
        request_id,
    )
}

fn rejection_response(code: RejectionCode, request_id: RequestId) -> Response {
    match code {
        RejectionCode::Unauthorized => problem_response(
            StatusCode::FORBIDDEN,
            "SSE_SUBSCRIPTION_FORBIDDEN",
            code.message(),
            request_id,
        ),
        RejectionCode::NotFound => problem_response(
            StatusCode::NOT_FOUND,
            "SSE_SUBSCRIPTION_NOT_FOUND",
            code.message(),
            request_id,
        ),
        RejectionCode::Conflict => problem_response(
            StatusCode::CONFLICT,
            "SSE_SUBSCRIPTION_CONFLICT",
            code.message(),
            request_id,
        ),
        RejectionCode::ConnectionNotActive
        | RejectionCode::CapacityExceeded
        | RejectionCode::Unavailable => unavailable(request_id),
    }
}

fn problem_response(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
) -> Response {
    let Ok(code) = ErrorCode::try_new(code) else {
        return fallback_problem(request_id);
    };
    let error = ServiceError::new(code, detail);
    match ProblemDetails::from_service_error(status, &error, request_id) {
        Ok(problem) => problem.into_response(),
        Err(_) => fallback_problem(request_id),
    }
}

fn fallback_problem(request_id: RequestId) -> Response {
    match ProblemDetails::try_for_status(StatusCode::INTERNAL_SERVER_ERROR, request_id) {
        Ok(problem) => problem.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

struct ConnectionLifecycle {
    registry: ConnectionRegistry,
    connection_id: ConnectionId,
    delivery_hub: Option<ConnectionDeliveryHub>,
    open: bool,
}

impl ConnectionLifecycle {
    fn new(
        registry: ConnectionRegistry,
        connection_id: ConnectionId,
        delivery_hub: Option<ConnectionDeliveryHub>,
    ) -> Self {
        Self {
            registry,
            connection_id,
            delivery_hub,
            open: true,
        }
    }

    fn close(&mut self) {
        if self.open {
            if let Some(delivery_hub) = &self.delivery_hub {
                delivery_hub.close_connection(self.connection_id);
            }
            let _ = self.registry.begin_close(self.connection_id);
            let _ = self.registry.close(self.connection_id);
            self.open = false;
        }
    }
}

impl Drop for ConnectionLifecycle {
    fn drop(&mut self) {
        self.close();
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("SSE stream terminated")]
struct SseStreamError;

enum SseResponseSource {
    Structured(SseMessageStream),
    Delivery(ConnectionDeliveryReceiver),
}

struct SseResponseStream {
    source: SseResponseSource,
    lifecycle: Option<ConnectionLifecycle>,
    retry_interval: Option<Duration>,
    retry_sent: bool,
    terminal_sent: bool,
}

impl SseResponseStream {
    fn new(
        source: SseResponseSource,
        lifecycle: ConnectionLifecycle,
        retry_interval: Option<Duration>,
    ) -> Self {
        Self {
            source,
            lifecycle: Some(lifecycle),
            retry_interval,
            retry_sent: false,
            terminal_sent: false,
        }
    }

    fn close(&mut self) {
        if let Some(mut lifecycle) = self.lifecycle.take() {
            lifecycle.close();
        }
    }
}

impl Stream for SseResponseStream {
    type Item = Result<Event, SseStreamError>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if !self.retry_sent {
            self.retry_sent = true;
            if let Some(retry_interval) = self.retry_interval {
                return Poll::Ready(Some(Ok(Event::default().retry(retry_interval))));
            }
        }

        if self.terminal_sent {
            self.close();
            return Poll::Ready(None);
        }

        let terminal_retry = self
            .retry_interval
            .unwrap_or(DEFAULT_TERMINAL_RETRY_INTERVAL);
        let item = match &mut self.source {
            SseResponseSource::Structured(source) => match source.as_mut().poll_next(context) {
                Poll::Ready(Some(Ok(message))) => encode_event(message),
                Poll::Ready(Some(Err(_))) => Err(SseStreamError),
                Poll::Ready(None) => {
                    self.close();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            },
            SseResponseSource::Delivery(receiver) => match receiver.poll_recv(context) {
                Poll::Ready(Some(QueuedDelivery::Message(message))) => {
                    let event = encode_delivery_event(message);
                    if event.is_ok() {
                        receiver.record_sent();
                    }
                    event
                }
                Poll::Ready(Some(QueuedDelivery::Terminal(terminal))) => {
                    self.terminal_sent = true;
                    let reason = match terminal {
                        DeliveryTerminal::SlowConsumer => "slow-consumer",
                        DeliveryTerminal::Draining => "server-draining",
                    };
                    Ok(Event::default()
                        .event("reconnect")
                        .retry(terminal_retry)
                        .data(reason))
                }
                Poll::Ready(None) => {
                    self.close();
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            },
        };
        match item {
            Ok(event) => Poll::Ready(Some(Ok(event))),
            Err(error) => {
                self.close();
                Poll::Ready(Some(Err(error)))
            }
        }
    }
}

fn encode_event(message: OutboundMessage) -> Result<Event, SseStreamError> {
    let envelope = message.into_envelope().map_err(|_| SseStreamError)?;
    let encoded = envelope.encode().map_err(|_| SseStreamError)?;
    let data = String::from_utf8(encoded).map_err(|_| SseStreamError)?;
    Ok(Event::default()
        .event(envelope.message_type().as_str())
        .data(data))
}

fn encode_delivery_event(message: DeliveryMessage) -> Result<Event, SseStreamError> {
    let event = Event::default().event(message.message_type().as_str());
    let data = String::from_utf8(message.into_encoded()).map_err(|_| SseStreamError)?;
    Ok(event.data(data))
}
