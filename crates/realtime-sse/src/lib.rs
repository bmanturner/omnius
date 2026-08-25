//! Authenticated Axum SSE transport adapter for one authorized realtime subscription.
//!
//! Authentication stays in application composition. This adapter accepts the canonical
//! [`Principal`] placed in request extensions, creates exactly one subscription through
//! [`RealtimeService`], and opens a provider-neutral source only after authorization succeeds.

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
use rsk_auth_core::Principal;
use rsk_authz_basic::AuthorizationProvider;
use rsk_core::{ErrorCode, RequestId, ServiceError};
use rsk_http::ProblemDetails;
use rsk_realtime_core::{
    AcceptedKind, CommandAuthorizationResolver, ConnectionId, ConnectionRegistry,
    ConnectionSnapshot, InboundCommand, MessageId, OpaqueCursor, OutboundMessage, RealtimeService,
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
pub struct SseState<P, R, S> {
    service: Arc<RealtimeService<P, R>>,
    source: Arc<S>,
    config: SseConfig,
}

impl<P, R, S> SseState<P, R, S> {
    /// Creates route state from the transport-neutral service and provider-neutral event source.
    #[must_use]
    pub fn new(service: Arc<RealtimeService<P, R>>, source: Arc<S>, config: SseConfig) -> Self {
        Self {
            service,
            source,
            config,
        }
    }

    /// Returns the transport configuration.
    #[must_use]
    pub const fn config(&self) -> SseConfig {
        self.config
    }
}

impl<P, R, S> Clone for SseState<P, R, S> {
    fn clone(&self) -> Self {
        Self {
            service: Arc::clone(&self.service),
            source: Arc::clone(&self.source),
            config: self.config,
        }
    }
}

/// Builds a router exposing only authenticated `GET /events`.
///
/// The query requires a canonical `UUIDv7` `subscription_id`, a bounded `topic`, and an optional
/// opaque bounded `cursor`. Application composition must install a canonical [`Principal`]
/// request extension before this router. Missing authentication is rejected as RFC 9457 Problem
/// Details.
pub fn sse_router<P, R, S>(state: SseState<P, R, S>) -> Router
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    S: SseEventSource,
{
    Router::new()
        .route(SSE_EVENTS_PATH, get(events::<P, R, S>))
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

async fn events<P, R, S>(
    State(state): State<SseState<P, R, S>>,
    headers: HeaderMap,
    principal: Option<Extension<Principal>>,
    request_id: Option<Extension<RequestId>>,
    query: Result<Query<SseQuery>, QueryRejection>,
) -> Response
where
    P: AuthorizationProvider + Send + Sync + 'static,
    R: CommandAuthorizationResolver + Send + Sync + 'static,
    S: SseEventSource,
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

    let registry = state.service.registry().clone();
    let Ok(connection) = registry.register(principal) else {
        return unavailable(request_id);
    };
    let lifecycle = ConnectionLifecycle::new(registry, connection.id());
    let Ok(connection) = state.service.registry().activate(connection.id()) else {
        return unavailable(request_id);
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
    let Ok(source) = state
        .source
        .open(SseSubscription::new(connection, subscription))
        .await
    else {
        return unavailable(request_id);
    };

    let stream = SseResponseStream::new(source, lifecycle, state.config.retry_interval());
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
    open: bool,
}

impl ConnectionLifecycle {
    fn new(registry: ConnectionRegistry, connection_id: ConnectionId) -> Self {
        Self {
            registry,
            connection_id,
            open: true,
        }
    }

    fn close(&mut self) {
        if self.open {
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

struct SseResponseStream {
    source: SseMessageStream,
    lifecycle: Option<ConnectionLifecycle>,
    retry_interval: Option<Duration>,
    retry_sent: bool,
}

impl SseResponseStream {
    fn new(
        source: SseMessageStream,
        lifecycle: ConnectionLifecycle,
        retry_interval: Option<Duration>,
    ) -> Self {
        Self {
            source,
            lifecycle: Some(lifecycle),
            retry_interval,
            retry_sent: false,
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

        match self.source.as_mut().poll_next(context) {
            Poll::Ready(Some(Ok(message))) => match encode_event(message) {
                Ok(event) => Poll::Ready(Some(Ok(event))),
                Err(error) => {
                    self.close();
                    Poll::Ready(Some(Err(error)))
                }
            },
            Poll::Ready(Some(Err(_))) => {
                self.close();
                Poll::Ready(Some(Err(SseStreamError)))
            }
            Poll::Ready(None) => {
                self.close();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
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
