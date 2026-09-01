//! Stateless MCP 2026-07-28 Streamable HTTP transport.
//!
//! This crate owns HTTP framing and lifecycle only. Application composition supplies an RMCP
//! [`ServerHandler`] whose primitive adapters dispatch through `omnius-mcp-server-core`; this
//! transport does not contain a second capability or authorization registry. Every POST is served
//! by a fresh RMCP one-shot service with complete request metadata. Legacy initialization,
//! sessions, GET event streams, event replay, and SSE resume are deliberately not routed.
//!
//! RMCP provides a fixed-capacity per-request delivery channel; this adapter additionally bounds
//! each terminal JSON body and each complete SSE event. Subscription lifetime remains explicitly
//! long-lived and ends on client cancellation or bounded server drain rather than an invented
//! transport session timeout.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    borrow::Cow,
    fmt,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderMap, HeaderValue, Method, Request, StatusCode, Uri,
        header::{ACCEPT, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, ETAG, HOST, VARY},
        request::Parts,
    },
    response::Response,
    routing::post,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Bytes, BytesMut};
use http_body::{Body as HttpBody, Frame, SizeHint};
use omnius_http::{
    HttpShell, HttpShellConfig, HttpShellError, ProtocolErrorResponse, RouteBodyLimit,
};
use omnius_mcp_server_core::MCP_PROTOCOL_REVISION;
use rmcp::{
    RoleServer, ServerHandler,
    service::RequestContext,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::never::NeverSessionManager,
    },
};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt as _;

/// The only HTTP path exposed by this transport.
pub const MCP_HTTP_PATH: &str = "/mcp";

const HEADER_PROTOCOL_VERSION: &str = "mcp-protocol-version";
const HEADER_MCP_METHOD: &str = "mcp-method";
const HEADER_MCP_NAME: &str = "mcp-name";
const HEADER_MCP_SESSION_ID: &str = "mcp-session-id";
const HEADER_LAST_EVENT_ID: &str = "last-event-id";
const JSON_MEDIA_TYPE: &str = "application/json";
const EVENT_STREAM_MEDIA_TYPE: &str = "text/event-stream";
const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
const META_SERVER_INFO: &str = "io.modelcontextprotocol/serverInfo";
const META_CATALOG_REVISION: &str = "io.omnius.mcp/catalogRevision";
const META_CATALOG_ETAG: &str = "io.omnius.mcp/catalogEtag";
const META_CACHE_CONTROL: &str = "io.omnius.mcp/cacheControl";
const META_TTL_MS: &str = "io.omnius.mcp/ttlMs";
const META_CACHE_SCOPE: &str = "io.omnius.mcp/cacheScope";
const MAX_IDENTITY_FIELD_BYTES: usize = 256;
const MAX_CATALOG_REVISION_BYTES: usize = 256;

/// Stateless HTTP transport settings.
#[derive(Clone, Debug)]
pub struct McpHttpConfig {
    /// Shared HTTP shell settings. Its body bound is also applied inside RMCP.
    pub http: HttpShellConfig,
    /// Exact allowed inbound `Host` authorities. A value without a port accepts any port for that
    /// host. The list must not be empty.
    pub allowed_hosts: Vec<String>,
    /// Maximum bytes in a terminal JSON response.
    pub max_json_response_bytes: usize,
    /// Maximum bytes in one complete response-stream event. RMCP separately bounds the queued
    /// event count.
    pub max_response_frame_bytes: usize,
    /// Time allowed for admitted response bodies and subscriptions to finish after drain starts.
    pub drain_timeout: Duration,
}

impl Default for McpHttpConfig {
    fn default() -> Self {
        Self {
            http: HttpShellConfig::default(),
            allowed_hosts: vec![
                "localhost".to_owned(),
                "127.0.0.1".to_owned(),
                "::1".to_owned(),
            ],
            max_json_response_bytes: 2 * 1024 * 1024,
            max_response_frame_bytes: 2 * 1024 * 1024,
            drain_timeout: Duration::from_secs(10),
        }
    }
}

/// HTTP transport construction failure with no reflected configuration values.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpHttpBuildError {
    /// A transport bound or authority/origin policy is invalid.
    #[error("invalid MCP HTTP transport configuration")]
    InvalidConfig,
    /// The shared HTTP shell rejected its bounded policy.
    #[error(transparent)]
    HttpShell(#[from] HttpShellError),
}

/// Outcome of a bounded graceful drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpDrainOutcome {
    /// All admitted response bodies finished before the deadline.
    Complete,
    /// The deadline elapsed and remaining RMCP work was cancelled.
    Forced,
}

/// Cloneable signal available to RMCP handlers through the HTTP request parts extension.
///
/// A `subscriptions/listen` handler should select on [`Self::cancelled`] and return `Ok(())` when
/// it fires. RMCP then emits the protocol-defined final subscription result before the transport
/// drain waits for the response body to close.
#[derive(Clone)]
pub struct McpDrainSignal {
    token: CancellationToken,
}

impl McpDrainSignal {
    /// Returns the signal installed for an RMCP request, when the request came from this transport.
    #[must_use]
    pub fn from_request_context(context: &RequestContext<RoleServer>) -> Option<&Self> {
        context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<Self>())
    }

    /// Returns whether graceful drain has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Waits until graceful drain begins.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }
}

impl fmt::Debug for McpDrainSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpDrainSignal")
            .field("is_draining", &self.is_draining())
            .finish()
    }
}

/// Readiness and graceful-drain control for an [`McpHttpServer`].
#[derive(Clone)]
pub struct McpHttpDrainHandle {
    inner: Arc<DrainState>,
}

impl McpHttpDrainHandle {
    /// Returns `true` while the endpoint will admit new MCP POSTs.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.inner.accepting.load(Ordering::Acquire)
    }

    /// Returns the number of admitted response bodies that have not closed yet.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.inner.active.load(Ordering::Acquire)
    }

    /// Atomically rejects future work and signals admitted subscriptions to finish gracefully.
    pub fn begin_drain(&self) {
        if self.inner.accepting.swap(false, Ordering::AcqRel) {
            self.inner.graceful.cancel();
            if self.in_flight() == 0 {
                self.inner.idle.notify_one();
            }
        }
    }

    /// Begins drain, waits for admitted bodies up to the configured deadline, then force-cancels
    /// remaining RMCP work.
    pub async fn drain(&self) -> McpDrainOutcome {
        self.begin_drain();
        if tokio::time::timeout(self.inner.timeout, self.wait_until_idle())
            .await
            .is_ok()
        {
            McpDrainOutcome::Complete
        } else {
            self.inner.force.cancel();
            McpDrainOutcome::Forced
        }
    }

    async fn wait_until_idle(&self) {
        while self.in_flight() != 0 {
            self.inner.idle.notified().await;
        }
    }

    fn try_enter(&self) -> Option<InFlightGuard> {
        if !self.is_ready() {
            return None;
        }
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        let guard = InFlightGuard {
            inner: Arc::clone(&self.inner),
        };
        if self.is_ready() { Some(guard) } else { None }
    }

    fn signal(&self) -> McpDrainSignal {
        McpDrainSignal {
            token: self.inner.graceful.clone(),
        }
    }
}

impl fmt::Debug for McpHttpDrainHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpHttpDrainHandle")
            .field("ready", &self.is_ready())
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

struct DrainState {
    accepting: AtomicBool,
    active: AtomicUsize,
    idle: Notify,
    graceful: CancellationToken,
    force: CancellationToken,
    timeout: Duration,
}

struct InFlightGuard {
    inner: Arc<DrainState>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.idle.notify_one();
        }
    }
}

/// Built Axum router plus its readiness/drain control.
pub struct McpHttpServer {
    router: Router,
    drain: McpHttpDrainHandle,
}

impl McpHttpServer {
    /// Builds the strict stateless endpoint around an RMCP handler.
    ///
    /// The supplied handler is cloned once per request by RMCP. Omnius composition must supply a
    /// handler assembled from the projection adapters whose invocation boundary is
    /// `omnius_mcp_server_core::McpDispatch`; the transport intentionally has no handler registry.
    ///
    /// # Errors
    ///
    /// Returns [`McpHttpBuildError`] when any limit, host, origin, or shared HTTP-shell policy is
    /// invalid.
    pub fn new<S>(handler: S, config: McpHttpConfig) -> Result<Self, McpHttpBuildError>
    where
        S: ServerHandler + Clone + Send + Sync + 'static,
    {
        let McpHttpConfig {
            http,
            allowed_hosts,
            max_json_response_bytes,
            max_response_frame_bytes,
            drain_timeout,
        } = config;
        let normalized_hosts = normalize_allowed_hosts(&allowed_hosts)?;
        let normalized_origins = normalize_allowed_origins(&http.trusted_origins)?;
        if max_json_response_bytes == 0
            || max_response_frame_bytes == 0
            || max_json_response_bytes > max_response_frame_bytes
            || drain_timeout.is_zero()
        {
            return Err(McpHttpBuildError::InvalidConfig);
        }

        let max_request_body_bytes = http.max_body_bytes;
        let shell = HttpShell::new(http)?;
        // The MCP endpoint performs its own bounded read so every overflow, including a declared
        // oversized Content-Length, can retain a JSON-RPC envelope through the shared shell.
        let route_limit = RouteBodyLimit::new(Method::POST, MCP_HTTP_PATH, usize::MAX)?;
        let drain = McpHttpDrainHandle {
            inner: Arc::new(DrainState {
                accepting: AtomicBool::new(true),
                active: AtomicUsize::new(0),
                idle: Notify::new(),
                graceful: CancellationToken::new(),
                force: CancellationToken::new(),
                timeout: drain_timeout,
            }),
        };
        let rmcp_config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_sse_retry(None)
            .with_cancellation_token(drain.inner.force.clone())
            .with_max_request_body_bytes(max_request_body_bytes)
            .with_stateless_protocol_metadata_required(true)
            .disable_allowed_hosts()
            .disable_allowed_origins();
        let server_info = serde_json::to_value(handler.get_info().server_info)
            .map_err(|_| McpHttpBuildError::InvalidConfig)?;
        let factory_handler = handler;
        let service = StreamableHttpService::new(
            move || Ok(factory_handler.clone()),
            Arc::new(NeverSessionManager::default()),
            rmcp_config,
        );
        let state = EndpointState {
            service,
            server_info,
            max_request_body_bytes,
            max_json_response_bytes,
            max_response_frame_bytes,
            hosts: normalized_hosts.into(),
            origins: normalized_origins.into(),
            drain: drain.clone(),
        };
        let mcp_routes = Router::new()
            .route(MCP_HTTP_PATH, post(endpoint::<S>))
            .with_state(state);
        let router = shell.apply_with_route_body_limits(mcp_routes, vec![route_limit])?;
        Ok(Self { router, drain })
    }

    /// Borrows the readiness/drain handle.
    #[must_use]
    pub const fn drain_handle(&self) -> &McpHttpDrainHandle {
        &self.drain
    }

    /// Clones the composed Axum router.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Consumes the server and returns the composed Axum router.
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Consumes the server and returns both the router and its owned drain
    /// handle.
    ///
    /// This is the preferred handoff when the HTTP listener is assembled
    /// separately: the listener owner retains `drain` and calls
    /// [`McpHttpDrainHandle::drain`] before shutting the listener down.
    pub fn into_parts(self) -> (Router, McpHttpDrainHandle) {
        (self.router, self.drain)
    }
}

struct EndpointState<S> {
    service: StreamableHttpService<S, NeverSessionManager>,
    server_info: Value,
    max_request_body_bytes: usize,
    max_json_response_bytes: usize,
    max_response_frame_bytes: usize,
    hosts: Arc<[NormalizedAuthority]>,
    origins: Arc<[NormalizedOrigin]>,
    drain: McpHttpDrainHandle,
}

impl<S> Clone for EndpointState<S> {
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            server_info: self.server_info.clone(),
            max_request_body_bytes: self.max_request_body_bytes,
            max_json_response_bytes: self.max_json_response_bytes,
            max_response_frame_bytes: self.max_response_frame_bytes,
            hosts: Arc::clone(&self.hosts),
            origins: Arc::clone(&self.origins),
            drain: self.drain.clone(),
        }
    }
}

async fn endpoint<S>(State(state): State<EndpointState<S>>, request: Request<Body>) -> Response
where
    S: ServerHandler + Clone + Send + Sync + 'static,
{
    let Some(guard) = state.drain.try_enter() else {
        return draining_response();
    };
    let (mut request, method) = match prepare_request(request, &state).await {
        Ok(prepared) => prepared,
        Err(error) => return error.into_response(),
    };
    request.extensions_mut().insert(state.drain.signal());
    let response = match state.service.clone().oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(never) => match never {},
    };
    let response = finalize_response(
        response,
        &method,
        &state.server_info,
        state.max_json_response_bytes,
    )
    .await;
    track_response_body(response, guard, state.max_response_frame_bytes)
}

async fn prepare_request<S>(
    request: Request<Body>,
    state: &EndpointState<S>,
) -> Result<(Request<Body>, String), ProtocolError> {
    validate_authority(request.uri(), request.headers(), &state.hosts)?;
    validate_origin(request.headers(), &state.origins)?;
    validate_transport_headers(request.headers())?;

    let (parts, body) = request.into_parts();
    let body = to_bytes(body, state.max_request_body_bytes)
        .await
        .map_err(|_| {
            fixed_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                -32600,
                "request body is too large",
            )
        })?;
    let envelope: Value = serde_json::from_slice(&body).map_err(|_| {
        fixed_error(
            StatusCode::BAD_REQUEST,
            -32700,
            "request body is not valid JSON",
        )
    })?;
    let method = validate_envelope(&envelope, &parts.headers)?;
    Ok((
        Request::from_parts(parts, Body::from(body)),
        method.to_owned(),
    ))
}

fn validate_transport_headers(headers: &HeaderMap) -> Result<(), ProtocolError> {
    if headers.contains_key(HEADER_MCP_SESSION_ID) || headers.contains_key(HEADER_LAST_EVENT_ID) {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "session and replay headers are not supported",
        ));
    }
    let content_type =
        required_single_header(headers, &CONTENT_TYPE, StatusCode::UNSUPPORTED_MEDIA_TYPE)?;
    if !valid_json_content_type(content_type) {
        return Err(fixed_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            -32600,
            "Content-Type must be application/json",
        ));
    }
    if !accepts_required_media_types(headers) {
        return Err(fixed_error(
            StatusCode::NOT_ACCEPTABLE,
            -32600,
            "Accept must include application/json and text/event-stream",
        ));
    }
    let version = required_single_named_header(headers, HEADER_PROTOCOL_VERSION)?;
    if version != MCP_PROTOCOL_REVISION {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32021,
            "unsupported MCP protocol version",
        ));
    }
    required_single_named_header(headers, HEADER_MCP_METHOD)?;
    if header_count(headers, HEADER_MCP_NAME) > 1 {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32020,
            "request headers do not match request body",
        ));
    }
    Ok(())
}

fn validate_envelope<'a>(
    envelope: &'a Value,
    headers: &HeaderMap,
) -> Result<&'a str, ProtocolError> {
    let object = envelope
        .as_object()
        .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, -32600, "invalid JSON-RPC request"))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "invalid JSON-RPC request",
        ));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, -32600, "invalid JSON-RPC request"))?;
    if matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "resources/subscribe"
            | "resources/unsubscribe"
    ) {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32601,
            "legacy MCP lifecycle method is not supported",
        ));
    }
    if required_single_named_header(headers, HEADER_MCP_METHOD)? != method {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32020,
            "request headers do not match request body",
        ));
    }
    validate_name_header(method, object.get("params"), headers)?;

    if object.contains_key("id") {
        validate_request_metadata(object.get("params"))?;
    }
    Ok(method)
}

fn validate_request_metadata(params: Option<&Value>) -> Result<(), ProtocolError> {
    let meta = params
        .and_then(Value::as_object)
        .and_then(|params| params.get("_meta"))
        .and_then(Value::as_object)
        .ok_or_else(invalid_metadata)?;
    if meta.get(META_PROTOCOL_VERSION).and_then(Value::as_str) != Some(MCP_PROTOCOL_REVISION)
        || !meta
            .get(META_CLIENT_CAPABILITIES)
            .is_some_and(Value::is_object)
    {
        return Err(invalid_metadata());
    }
    let client_info = meta
        .get(META_CLIENT_INFO)
        .and_then(Value::as_object)
        .ok_or_else(invalid_metadata)?;
    for field in ["name", "version"] {
        let Some(value) = client_info.get(field).and_then(Value::as_str) else {
            return Err(invalid_metadata());
        };
        if value.is_empty() || value.len() > MAX_IDENTITY_FIELD_BYTES {
            return Err(invalid_metadata());
        }
    }
    Ok(())
}

fn invalid_metadata() -> ProtocolError {
    fixed_error(
        StatusCode::BAD_REQUEST,
        -32602,
        "request metadata is missing or invalid",
    )
}

fn validate_name_header(
    method: &str,
    params: Option<&Value>,
    headers: &HeaderMap,
) -> Result<(), ProtocolError> {
    let key = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        "tasks/get" | "tasks/update" | "tasks/cancel" => Some("taskId"),
        _ => None,
    };
    match key {
        Some(key) => {
            let expected = params
                .and_then(Value::as_object)
                .and_then(|params| params.get(key))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fixed_error(
                        StatusCode::BAD_REQUEST,
                        -32602,
                        "request parameters are invalid",
                    )
                })?;
            let raw = required_single_named_header(headers, HEADER_MCP_NAME)?;
            if decode_mcp_name(raw).as_deref() != Some(expected) {
                return Err(fixed_error(
                    StatusCode::BAD_REQUEST,
                    -32020,
                    "request headers do not match request body",
                ));
            }
        }
        None if headers.contains_key(HEADER_MCP_NAME) => {
            return Err(fixed_error(
                StatusCode::BAD_REQUEST,
                -32020,
                "request headers do not match request body",
            ));
        }
        None => {}
    }
    Ok(())
}

fn decode_mcp_name(value: &str) -> Option<Cow<'_, str>> {
    let Some(encoded) = value
        .strip_prefix("=?base64?")
        .and_then(|value| value.strip_suffix("?="))
    else {
        return Some(Cow::Borrowed(value));
    };
    let decoded = STANDARD.decode(encoded).ok()?;
    String::from_utf8(decoded).ok().map(Cow::Owned)
}

fn valid_json_content_type(value: &str) -> bool {
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|value| value.eq_ignore_ascii_case(JSON_MEDIA_TYPE))
    {
        return false;
    }
    let mut charset_seen = false;
    for parameter in parts {
        let Some((name, value)) = parameter.split_once('=') else {
            return false;
        };
        if charset_seen
            || !name.trim().eq_ignore_ascii_case("charset")
            || !value.trim().eq_ignore_ascii_case("utf-8")
        {
            return false;
        }
        charset_seen = true;
    }
    true
}

fn accepts_required_media_types(headers: &HeaderMap) -> bool {
    let mut json = false;
    let mut event_stream = false;
    for value in headers.get_all(ACCEPT) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        for range in value.split(',').map(str::trim) {
            let mut parts = range.split(';').map(str::trim);
            let Some(media_type) = parts.next() else {
                continue;
            };
            let permitted = parts.all(|parameter| {
                let Some((name, value)) = parameter.split_once('=') else {
                    return false;
                };
                if !name.trim().eq_ignore_ascii_case("q") {
                    return true;
                }
                value
                    .trim()
                    .parse::<f32>()
                    .is_ok_and(|quality| quality > 0.0 && quality <= 1.0)
            });
            if permitted && media_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE) {
                json = true;
            }
            if permitted && media_type.eq_ignore_ascii_case(EVENT_STREAM_MEDIA_TYPE) {
                event_stream = true;
            }
        }
    }
    json && event_stream
}

fn required_single_header<'a>(
    headers: &'a HeaderMap,
    name: &http::header::HeaderName,
    status: StatusCode,
) -> Result<&'a str, ProtocolError> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| fixed_error(status, -32600, "required request header is missing"))?;
    if values.next().is_some() {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "request contains duplicate singleton headers",
        ));
    }
    value.to_str().map_err(|_| {
        fixed_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "request header encoding is invalid",
        )
    })
}

fn required_single_named_header<'a>(
    headers: &'a HeaderMap,
    name: &str,
) -> Result<&'a str, ProtocolError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or_else(|| {
        fixed_error(
            StatusCode::BAD_REQUEST,
            -32020,
            "required MCP request header is missing",
        )
    })?;
    if values.next().is_some() {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32020,
            "request headers do not match request body",
        ));
    }
    value.to_str().map_err(|_| {
        fixed_error(
            StatusCode::BAD_REQUEST,
            -32020,
            "request header encoding is invalid",
        )
    })
}

fn header_count(headers: &HeaderMap, name: &str) -> usize {
    headers.get_all(name).iter().count()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NormalizedAuthority {
    host: String,
    port: Option<u16>,
}

fn normalize_allowed_hosts(
    allowed_hosts: &[String],
) -> Result<Vec<NormalizedAuthority>, McpHttpBuildError> {
    if allowed_hosts.is_empty() || allowed_hosts.len() > 64 {
        return Err(McpHttpBuildError::InvalidConfig);
    }
    allowed_hosts
        .iter()
        .map(|value| parse_authority(value).ok_or(McpHttpBuildError::InvalidConfig))
        .collect()
}

fn parse_authority(value: &str) -> Option<NormalizedAuthority> {
    if value.bytes().filter(|byte| *byte == b':').count() > 1 && !value.starts_with('[') {
        return Some(NormalizedAuthority {
            host: value.to_ascii_lowercase(),
            port: None,
        });
    }
    let authority = http::uri::Authority::try_from(value).ok()?;
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if host.is_empty() || host == "*" {
        return None;
    }
    Some(NormalizedAuthority {
        host,
        port: authority.port_u16(),
    })
}

fn validate_authority(
    uri: &Uri,
    headers: &HeaderMap,
    allowed: &[NormalizedAuthority],
) -> Result<(), ProtocolError> {
    let mut hosts = headers.get_all(HOST).iter();
    let authority = match (hosts.next(), hosts.next()) {
        (Some(value), None) => value.to_str().ok().and_then(parse_authority),
        (None, None) => uri
            .authority()
            .and_then(|value| parse_authority(value.as_str())),
        _ => None,
    }
    .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, -32600, "invalid Host header"))?;
    let accepted = allowed.iter().any(|candidate| {
        candidate.host == authority.host
            && candidate
                .port
                .is_none_or(|port| authority.port == Some(port))
    });
    if accepted {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            -32600,
            "request origin is not allowed",
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NormalizedOrigin {
    Null,
    Tuple {
        scheme: String,
        host: String,
        port: Option<u16>,
    },
}

fn normalize_allowed_origins(
    allowed_origins: &[String],
) -> Result<Vec<NormalizedOrigin>, McpHttpBuildError> {
    if allowed_origins.len() > 64 {
        return Err(McpHttpBuildError::InvalidConfig);
    }
    allowed_origins
        .iter()
        .map(|value| parse_origin(value).ok_or(McpHttpBuildError::InvalidConfig))
        .collect()
}

fn parse_origin(value: &str) -> Option<NormalizedOrigin> {
    if value == "null" {
        return Some(NormalizedOrigin::Null);
    }
    let uri = Uri::try_from(value).ok()?;
    if uri
        .path_and_query()
        .is_some_and(|path| path.as_str() != "/")
    {
        return None;
    }
    let scheme = uri.scheme_str()?.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return None;
    }
    let authority = uri.authority()?;
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let port = match (scheme.as_str(), authority.port_u16()) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, port) => port,
    };
    Some(NormalizedOrigin::Tuple { scheme, host, port })
}

fn validate_origin(headers: &HeaderMap, allowed: &[NormalizedOrigin]) -> Result<(), ProtocolError> {
    let mut values = headers.get_all(http::header::ORIGIN).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(fixed_error(
            StatusCode::BAD_REQUEST,
            -32600,
            "invalid Origin header",
        ));
    }
    let origin = value
        .to_str()
        .ok()
        .and_then(parse_origin)
        .ok_or_else(|| fixed_error(StatusCode::BAD_REQUEST, -32600, "invalid Origin header"))?;
    if allowed.contains(&origin) {
        Ok(())
    } else {
        Err(fixed_error(
            StatusCode::FORBIDDEN,
            -32600,
            "request origin is not allowed",
        ))
    }
}

async fn finalize_response(
    response: Response,
    method: &str,
    server_info: &Value,
    max_bytes: usize,
) -> Response {
    if !response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(JSON_MEDIA_TYPE))
    {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(body) = to_bytes(body, max_bytes).await else {
        return bounded_response_error();
    };
    let Ok(mut document) = serde_json::from_slice::<Value>(&body) else {
        return bounded_response_error();
    };
    inject_server_identity(&mut document, server_info);
    sanitize_protocol_error(&mut document);
    let protocol_error = document.get("error").is_some_and(Value::is_object);
    apply_cache_headers(method, &document, &mut parts.headers);
    let body = match serde_json::to_vec(&document) {
        Ok(body) if body.len() <= max_bytes => body,
        _ => return bounded_response_error(),
    };
    let Ok(length) = HeaderValue::from_str(&body.len().to_string()) else {
        return bounded_response_error();
    };
    parts.headers.insert(CONTENT_LENGTH, length);
    let mut response = Response::from_parts(parts, Body::from(body));
    if protocol_error {
        ProtocolErrorResponse::mark(&mut response);
    }
    response
}

fn inject_server_identity(document: &mut Value, server_info: &Value) {
    let Some(result) = document.get_mut("result").and_then(Value::as_object_mut) else {
        return;
    };
    let meta = result
        .entry("_meta")
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(META_SERVER_INFO.to_owned(), server_info.clone());
    }
}

fn sanitize_protocol_error(document: &mut Value) {
    let Some(error) = document.get_mut("error").and_then(Value::as_object_mut) else {
        return;
    };
    let message = match error.get("code").and_then(Value::as_i64) {
        Some(-32700) => "request body is not valid JSON",
        Some(-32600) => "invalid JSON-RPC request",
        Some(-32601) => "MCP method is not supported",
        Some(-32602) => "request parameters are invalid",
        Some(-32020) => "request headers do not match request body",
        Some(-32021) => "unsupported MCP protocol version",
        _ => "MCP request failed",
    };
    error.insert("message".to_owned(), Value::String(message.to_owned()));
    error.remove("data");
}

fn apply_cache_headers(method: &str, document: &Value, headers: &mut HeaderMap) {
    if !matches!(
        method,
        "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list"
    ) {
        return;
    }
    headers.remove(ETAG);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));

    let Some(result) = document.get("result").and_then(Value::as_object) else {
        return;
    };
    let Some(meta) = result.get("_meta").and_then(Value::as_object) else {
        return;
    };
    let standard_ttl_ms = result.get("ttlMs").and_then(Value::as_u64);
    let metadata_ttl_ms = meta.get(META_TTL_MS).and_then(Value::as_u64);
    if matches!((standard_ttl_ms, metadata_ttl_ms), (Some(left), Some(right)) if left != right) {
        return;
    }
    let Some(ttl_ms) = standard_ttl_ms.or(metadata_ttl_ms) else {
        return;
    };
    let standard_scope = result.get("cacheScope").and_then(Value::as_str);
    let metadata_scope = meta.get(META_CACHE_SCOPE).and_then(Value::as_str);
    if matches!((standard_scope, metadata_scope), (Some(left), Some(right)) if left != right) {
        return;
    }
    let Some(scope) = standard_scope.or(metadata_scope) else {
        return;
    };
    let Some(revision) = meta.get(META_CATALOG_REVISION).and_then(Value::as_str) else {
        return;
    };
    let Some(etag) = meta.get(META_CATALOG_ETAG).and_then(Value::as_str) else {
        return;
    };
    let Some(cache_control) = meta.get(META_CACHE_CONTROL).and_then(Value::as_str) else {
        return;
    };
    if revision.is_empty()
        || revision.len() > MAX_CATALOG_REVISION_BYTES
        || !valid_catalog_etag(etag)
        || !valid_cache_control(cache_control, scope, ttl_ms)
    {
        return;
    }
    let Ok(etag) = HeaderValue::from_str(etag) else {
        return;
    };
    let Ok(cache_control) = HeaderValue::from_str(cache_control) else {
        return;
    };
    headers.insert(ETAG, etag);
    headers.insert(CACHE_CONTROL, cache_control);
    if scope == "private" {
        append_vary_authorization(headers);
    }
}

fn append_vary_authorization(headers: &mut HeaderMap) {
    let already_varies = headers.get_all(VARY).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.split(',').any(|name| name.trim() == "Authorization"))
    });
    if !already_varies {
        headers.append(VARY, HeaderValue::from_static("Authorization"));
    }
}

fn valid_catalog_etag(value: &str) -> bool {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.strip_prefix("sha256:"))
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}

fn valid_cache_control(value: &str, scope: &str, ttl_ms: u64) -> bool {
    if !matches!(scope, "public" | "private") {
        return false;
    }
    let Some((actual_scope, max_age)) = value.split_once(", max-age=") else {
        return false;
    };
    let Ok(max_age) = max_age.parse::<u64>() else {
        return false;
    };
    actual_scope == scope && max_age == ttl_ms / 1_000
}

fn track_response_body(
    response: Response,
    guard: InFlightGuard,
    max_frame_bytes: usize,
) -> Response {
    let sanitize_events = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(EVENT_STREAM_MEDIA_TYPE));
    response.map(|body| {
        Body::new(TrackedBody {
            inner: Box::pin(body),
            guard: Some(guard),
            max_frame_bytes,
            event_buffer: sanitize_events.then(BytesMut::new),
            pending_trailers: None,
            end_of_stream: false,
        })
    })
}

struct TrackedBody {
    inner: Pin<Box<Body>>,
    guard: Option<InFlightGuard>,
    max_frame_bytes: usize,
    event_buffer: Option<BytesMut>,
    pending_trailers: Option<HeaderMap>,
    end_of_stream: bool,
}

impl TrackedBody {
    fn poll_event_stream(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        loop {
            let Some(buffer) = self.event_buffer.as_mut() else {
                self.guard.take();
                return Poll::Ready(None);
            };
            if let Some(length) = complete_event_length(buffer) {
                let event = buffer.split_to(length).freeze();
                return Poll::Ready(Some(Ok(Frame::data(sanitize_sse_event(event)))));
            }
            if self.end_of_stream {
                if !buffer.is_empty() {
                    let event = buffer.split().freeze();
                    return Poll::Ready(Some(Ok(Frame::data(sanitize_sse_event(event)))));
                }
                if let Some(trailers) = self.pending_trailers.take() {
                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                }
                self.guard.take();
                return Poll::Ready(None);
            }
            match self.inner.as_mut().poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => {
                        if buffer.len().saturating_add(data.len()) > self.max_frame_bytes {
                            self.guard.take();
                            return Poll::Ready(Some(Err(axum::Error::new(ResponseFrameTooLarge))));
                        }
                        buffer.extend_from_slice(&data);
                    }
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.pending_trailers = Some(trailers);
                        }
                    }
                },
                Poll::Ready(Some(Err(error))) => {
                    self.guard.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => self.end_of_stream = true,
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl HttpBody for TrackedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.event_buffer.is_some() {
            return this.poll_event_stream(context);
        }
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame)))
                if frame
                    .data_ref()
                    .is_some_and(|data| data.len() > this.max_frame_bytes) =>
            {
                this.guard.take();
                Poll::Ready(Some(Err(axum::Error::new(ResponseFrameTooLarge))))
            }
            Poll::Ready(Some(Err(error))) => {
                this.guard.take();
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.guard.take();
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.event_buffer.is_some() {
            self.end_of_stream
                && self.event_buffer.as_ref().is_none_or(BytesMut::is_empty)
                && self.pending_trailers.is_none()
        } else {
            self.inner.is_end_stream()
        }
    }

    fn size_hint(&self) -> SizeHint {
        if self.event_buffer.is_some() {
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}

fn complete_event_length(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2)
        .or_else(|| {
            buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|position| position + 4)
        })
}

fn sanitize_sse_event(event: Bytes) -> Bytes {
    let Ok(text) = std::str::from_utf8(&event) else {
        return event;
    };
    let mut output = Vec::with_capacity(event.len());
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        let (content, ending) = line.strip_suffix("\r\n").map_or_else(
            || {
                line.strip_suffix('\n')
                    .map_or((line, ""), |line| (line, "\n"))
            },
            |line| (line, "\r\n"),
        );
        let Some(payload) = content.strip_prefix("data:") else {
            output.extend_from_slice(line.as_bytes());
            continue;
        };
        let payload = payload.strip_prefix(' ').unwrap_or(payload);
        let Ok(mut document) = serde_json::from_str::<Value>(payload) else {
            output.extend_from_slice(line.as_bytes());
            continue;
        };
        if document.get("error").is_none() {
            output.extend_from_slice(line.as_bytes());
            continue;
        }
        sanitize_protocol_error(&mut document);
        let Ok(serialized) = serde_json::to_vec(&document) else {
            output.extend_from_slice(line.as_bytes());
            continue;
        };
        output.extend_from_slice(b"data: ");
        output.extend_from_slice(&serialized);
        output.extend_from_slice(ending.as_bytes());
        changed = true;
    }
    if changed { Bytes::from(output) } else { event }
}

#[derive(Debug)]
struct ResponseFrameTooLarge;

impl fmt::Display for ResponseFrameTooLarge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP response frame exceeded its configured bound")
    }
}

impl std::error::Error for ResponseFrameTooLarge {}

fn bounded_response_error() -> Response {
    fixed_error(
        StatusCode::BAD_GATEWAY,
        -32603,
        "MCP response could not be delivered",
    )
    .into_response()
}

fn draining_response() -> Response {
    let mut response = fixed_error(
        StatusCode::SERVICE_UNAVAILABLE,
        -32003,
        "MCP endpoint is draining",
    )
    .into_response();
    response
        .headers_mut()
        .insert(http::header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

#[derive(Clone, Copy, Debug)]
struct ProtocolError {
    status: StatusCode,
    code: i64,
    message: &'static str,
}

impl ProtocolError {
    fn into_response(self) -> Response {
        let body = json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": self.code,
                "message": self.message,
            }
        })
        .to_string();
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = self.status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(JSON_MEDIA_TYPE));
        ProtocolErrorResponse::mark(&mut response);
        response
    }
}

const fn fixed_error(status: StatusCode, code: i64, message: &'static str) -> ProtocolError {
    ProtocolError {
        status,
        code,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_cache_variation_preserves_existing_dimensions() {
        let mut headers = HeaderMap::new();
        headers.insert(VARY, HeaderValue::from_static("Origin"));

        append_vary_authorization(&mut headers);

        let values = headers
            .get_all(VARY)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert_eq!(values, ["Origin", "Authorization"]);
    }
}
