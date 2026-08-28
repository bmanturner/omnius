//! Axum/Tower HTTP shell with explicit middleware ordering and bounded defaults.

mod conditional;
mod static_delivery;
mod static_observability;
mod web_security;

pub use conditional::{ConditionalHeaderError, IfMatch, VersionEtag};
pub use static_delivery::{
    BackendRoute, BackendRouteMatch, BackendTransport, DEFAULT_ROUTE_TOPOLOGY_JSON,
    PrecompressedConfig, RouteTopology, RouteTopologyError, SourceMapPolicy, StaticDelivery,
    StaticDeliveryConfig, StaticDeliveryError, StaticFallback, StaticReadinessError,
    ValidatedStaticDeliveryConfig,
};
pub use static_observability::{
    MetricsStaticDeliveryObserver, StaticAssetClass, StaticCacheClass, StaticContractMismatch,
    StaticDeliveryObserver, StaticResponseObservation, StaticResponseStatus,
};
pub use web_security::{
    ContentSecurityPolicyConfig, CrossOriginEmbedderPolicy, CrossOriginOpenerPolicy,
    CrossOriginPolicyConfig, CrossOriginResourcePolicy, CspSource, HstsConfig,
    PermissionsPolicyConfig, PermissionsPolicyFeature, ReferrerPolicy, TlsBoundary,
    WebSecurityPolicy, WebSecurityPolicyError,
};

use std::{
    convert::Infallible,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{MatchedPath, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{
            ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE,
            COOKIE, PROXY_AUTHORIZATION, SET_COOKIE, TRANSFER_ENCODING,
        },
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use futures::FutureExt as _;
use omnius_core::{ErrorCode, RequestId, ServiceError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;
use tower::{ServiceExt as _, service_fn};
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, csrf::CsrfLayer, limit::RequestBodyLimit,
    sensitive_headers::SetSensitiveHeadersLayer, timeout::TimeoutLayer, trace::TraceLayer,
};

const DEFAULT_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_HEADER_COUNT: usize = 100;
const DEFAULT_IN_FLIGHT: usize = 1024;
const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_HANDLER_TIMEOUT: Duration = Duration::from_secs(30);

const FORWARDED_HEADERS: &[&str] = &[
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-real-ip",
];

/// Logical request/response middleware stages, outer to inner.
///
/// Response-only policies wrap the request stack but perform their work while
/// the response unwinds. Authentication, request context, and route-rate-limit
/// stages are installed by their owning optional modules at the listed slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MiddlewareStage {
    /// Convert panics to generic server failures.
    PanicBoundary,
    /// Establish or validate the request identifier.
    RequestId,
    /// Mark credentials and cookies as sensitive.
    SensitiveHeaders,
    /// Derive client metadata only from trusted peers.
    TrustedProxy,
    /// Create the server request span.
    Trace,
    /// Reject work above the in-flight bound.
    Concurrency,
    /// Enforce header and request deadlines.
    Deadlines,
    /// Enforce the streaming request-body bound.
    BodyLimit,
    /// Apply deny-by-default CORS policy.
    Cors,
    /// Reject cross-origin mutation requests.
    Csrf,
    /// Authenticate the request when a profile installs identity.
    Authentication,
    /// Attach request and tenant context.
    RequestContext,
    /// Apply route-specific rate limits.
    RouteRateLimit,
    /// Invoke the route handler.
    Handler,
    /// Apply response security headers, compression, and metrics.
    ResponsePolicies,
}

/// Normative effective middleware order from the HTTP contract.
pub const MIDDLEWARE_ORDER: &[MiddlewareStage] = &[
    MiddlewareStage::PanicBoundary,
    MiddlewareStage::RequestId,
    MiddlewareStage::SensitiveHeaders,
    MiddlewareStage::TrustedProxy,
    MiddlewareStage::Trace,
    MiddlewareStage::Concurrency,
    MiddlewareStage::Deadlines,
    MiddlewareStage::BodyLimit,
    MiddlewareStage::Cors,
    MiddlewareStage::Csrf,
    MiddlewareStage::Authentication,
    MiddlewareStage::RequestContext,
    MiddlewareStage::RouteRateLimit,
    MiddlewareStage::Handler,
    MiddlewareStage::ResponsePolicies,
];
/// Header used to return and propagate request identifiers.
pub const REQUEST_ID_HEADER: &str = "x-request-id";

const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";
const PROBLEM_TYPE_PREFIX: &str = "https://errors.omnius.invalid/";
const MAX_FIELD_ERRORS: usize = 100;

/// Trusted-peer marker inserted only after the immediate socket peer is verified.
///
/// Network clients cannot create request extensions. The request-ID boundary
/// accepts an inbound identifier only when the server adapter inserted this
/// marker for the immediate peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrustedProxy;
#[derive(Clone, Debug)]
struct ValidatedProblem(ProblemDetails);

/// One safe validation failure addressed by a JSON Pointer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FieldError {
    pointer: String,
    code: String,
    message: String,
}

impl FieldError {
    /// Builds a field failure after validating its stable code and JSON Pointer.
    ///
    /// # Errors
    ///
    /// Returns [`ProblemBuildError`] for malformed pointers, codes, or empty
    /// messages.
    pub fn try_new(
        pointer: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Result<Self, ProblemBuildError> {
        let pointer = pointer.into();
        let code = code.into();
        let message = message.into();
        if !valid_json_pointer(&pointer) {
            return Err(ProblemBuildError::InvalidPointer);
        }
        if !valid_field_code(&code) {
            return Err(ProblemBuildError::InvalidFieldCode);
        }
        if message.is_empty() {
            return Err(ProblemBuildError::EmptyFieldMessage);
        }
        Ok(Self {
            pointer,
            code,
            message,
        })
    }
}

/// RFC 9457-compatible service error document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    type_uri: String,
    title: &'static str,
    status: u16,
    code: ErrorCode,
    request_id: RequestId,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    errors: Option<Vec<FieldError>>,
}

impl ProblemDetails {
    /// Creates a generic safe document for an HTTP error status.
    ///
    /// # Errors
    ///
    /// Returns [`ProblemBuildError::InvalidHttpStatus`] for a non-error status.
    pub fn try_for_status(
        status: StatusCode,
        request_id: RequestId,
    ) -> Result<Self, ProblemBuildError> {
        validate_problem_status(status)?;
        Ok(Self::new(status, generic_error_code(status), request_id))
    }

    /// Maps a service error without serializing its internal source chain.
    ///
    /// # Errors
    ///
    /// Returns [`ProblemBuildError::InvalidHttpStatus`] for a non-error status.
    pub fn from_service_error(
        status: StatusCode,
        error: &ServiceError,
        request_id: RequestId,
    ) -> Result<Self, ProblemBuildError> {
        validate_problem_status(status)?;
        Ok(Self::new(status, error.code(), request_id).with_detail(error.safe_message()))
    }

    /// Adds client-safe detail text.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Adds at most 100 validated field failures.
    ///
    /// # Errors
    ///
    /// Returns [`ProblemBuildError::TooManyFieldErrors`] when the schema bound
    /// would be exceeded.
    pub fn with_errors(mut self, errors: Vec<FieldError>) -> Result<Self, ProblemBuildError> {
        if errors.len() > MAX_FIELD_ERRORS {
            return Err(ProblemBuildError::TooManyFieldErrors);
        }
        self.errors = (!errors.is_empty()).then_some(errors);
        Ok(self)
    }

    /// Returns the request identifier embedded in this document.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    fn new(status: StatusCode, code: ErrorCode, request_id: RequestId) -> Self {
        Self {
            type_uri: format!(
                "{PROBLEM_TYPE_PREFIX}{}",
                code.as_str().to_ascii_lowercase()
            ),
            title: problem_title(status),
            status: status.as_u16(),
            code,
            request_id,
            detail: None,
            errors: None,
        }
    }
}

impl IntoResponse for ProblemDetails {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let validated = ValidatedProblem(self.clone());
        let mut response = axum::Json(self).into_response();
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(PROBLEM_CONTENT_TYPE));
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response.extensions_mut().insert(validated);
        response
    }
}

/// Invalid Problem Details extension data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProblemBuildError {
    /// Problem Details is defined only for HTTP 4xx and 5xx statuses.
    #[error("Problem Details requires an HTTP error status")]
    InvalidHttpStatus,
    /// A field pointer is not a syntactically valid JSON Pointer.
    #[error("invalid field error JSON Pointer")]
    InvalidPointer,
    /// A field code does not match the lower-snake-case wire contract.
    #[error("invalid field error code")]
    InvalidFieldCode,
    /// A field error message must not be empty.
    #[error("field error message must not be empty")]
    EmptyFieldMessage,
    /// The schema permits at most 100 field failures.
    #[error("too many field errors")]
    TooManyFieldErrors,
}
fn validate_problem_status(status: StatusCode) -> Result<(), ProblemBuildError> {
    if status.is_client_error() || status.is_server_error() {
        Ok(())
    } else {
        Err(ProblemBuildError::InvalidHttpStatus)
    }
}

fn generic_error_code(status: StatusCode) -> ErrorCode {
    let value = match status {
        StatusCode::BAD_REQUEST => "BAD_REQUEST",
        StatusCode::UNAUTHORIZED => "UNAUTHORIZED",
        StatusCode::FORBIDDEN => "FORBIDDEN",
        StatusCode::NOT_FOUND => "NOT_FOUND",
        StatusCode::METHOD_NOT_ALLOWED => "METHOD_NOT_ALLOWED",
        StatusCode::REQUEST_TIMEOUT => "REQUEST_TIMEOUT",
        StatusCode::CONFLICT => "CONFLICT",
        StatusCode::PAYLOAD_TOO_LARGE => "PAYLOAD_TOO_LARGE",
        StatusCode::UNSUPPORTED_MEDIA_TYPE => "UNSUPPORTED_MEDIA_TYPE",
        StatusCode::UNPROCESSABLE_ENTITY => "VALIDATION_FAILED",
        StatusCode::TOO_MANY_REQUESTS => "RATE_LIMITED",
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE => "REQUEST_HEADERS_TOO_LARGE",
        StatusCode::SERVICE_UNAVAILABLE => "SERVICE_UNAVAILABLE",
        status if status.is_server_error() => "INTERNAL_ERROR",
        _ => "REQUEST_FAILED",
    };
    match ErrorCode::try_new(value) {
        Ok(code) => code,
        Err(_) => unreachable!("static Problem Details code is valid"),
    }
}

fn problem_title(status: StatusCode) -> &'static str {
    status.canonical_reason().unwrap_or("Request failed")
}

fn valid_field_code(code: &str) -> bool {
    let mut bytes = code.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let mut bytes = pointer.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'~'
            && !bytes
                .next()
                .is_some_and(|escaped| matches!(escaped, b'0' | b'1'))
        {
            return false;
        }
    }
    true
}

/// Bounded HTTP transport settings.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HttpShellConfig {
    /// Maximum bytes accepted from a request body, including streamed bodies.
    pub max_body_bytes: usize,
    /// Maximum aggregate bytes across request header names and values.
    pub max_header_bytes: usize,
    /// Maximum number of request header entries.
    pub max_header_count: usize,
    /// Maximum requests concurrently executing inside the shell.
    pub max_in_flight: usize,
    /// Header-read timeout passed to the Hyper server adapter.
    #[serde(with = "humantime_serde")]
    pub header_read_timeout: Duration,
    /// Total handler/body deadline enforced by the middleware stack.
    #[serde(with = "humantime_serde")]
    pub handler_timeout: Duration,
    /// Exact trusted browser origins; an empty list is deny-by-default.
    pub trusted_origins: Vec<String>,
}

impl Default for HttpShellConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_BODY_BYTES,
            max_header_bytes: DEFAULT_HEADER_BYTES,
            max_header_count: DEFAULT_HEADER_COUNT,
            max_in_flight: DEFAULT_IN_FLIGHT,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            handler_timeout: DEFAULT_HANDLER_TIMEOUT,
            trusted_origins: Vec::new(),
        }
    }
}

impl HttpShellConfig {
    fn validate(&self) -> Result<(), HttpShellError> {
        if self.max_body_bytes == 0 {
            return Err(HttpShellError::ZeroLimit("max_body_bytes"));
        }
        if self.max_header_bytes == 0 {
            return Err(HttpShellError::ZeroLimit("max_header_bytes"));
        }
        if self.max_header_count == 0 {
            return Err(HttpShellError::ZeroLimit("max_header_count"));
        }
        if self.max_in_flight == 0 {
            return Err(HttpShellError::ZeroLimit("max_in_flight"));
        }
        if self.header_read_timeout.is_zero() {
            return Err(HttpShellError::ZeroLimit("header_read_timeout"));
        }
        if self.handler_timeout.is_zero() {
            return Err(HttpShellError::ZeroLimit("handler_timeout"));
        }
        Ok(())
    }
}

/// Failure to construct a safe HTTP shell.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HttpShellError {
    /// A bound or timeout that must be positive was configured as zero.
    #[error("HTTP limit must be greater than zero: {0}")]
    ZeroLimit(&'static str),
    /// A configured trusted origin is not a valid HTTP header and origin value.
    #[error("invalid trusted HTTP origin")]
    InvalidTrustedOrigin,
    /// A route body override was zero, non-exact, or duplicated another override.
    #[error("invalid route-specific HTTP body limit")]
    InvalidRouteBodyLimit,
}
/// Validated request-body override for one exact routed method and path template.
///
/// Overrides are supplied directly to [`HttpShell::apply_with_route_body_limits`] during router
/// composition. They cannot be selected by request headers or extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteBodyLimit {
    method: Method,
    matched_path: &'static str,
    max_body_bytes: usize,
}

impl RouteBodyLimit {
    /// Creates a finite body limit for one exact Axum matched-path template.
    ///
    /// # Errors
    ///
    /// Returns [`HttpShellError::InvalidRouteBodyLimit`] for a zero limit, a non-absolute path,
    /// or a catch-all path template.
    pub fn new(
        method: Method,
        matched_path: &'static str,
        max_body_bytes: usize,
    ) -> Result<Self, HttpShellError> {
        if max_body_bytes == 0
            || !matched_path.starts_with('/')
            || matched_path.contains("{*")
            || matched_path.contains("//")
        {
            return Err(HttpShellError::InvalidRouteBodyLimit);
        }
        Ok(Self {
            method,
            matched_path,
            max_body_bytes,
        })
    }
}

#[derive(Clone, Debug)]
struct BodyLimitPolicy {
    default_limit: usize,
    route_limits: Arc<[RouteBodyLimit]>,
}

impl BodyLimitPolicy {
    fn limit_for(&self, request: &Request) -> usize {
        let matched_path = request.extensions().get::<MatchedPath>();
        self.route_limits
            .iter()
            .find(|limit| {
                request.method() == limit.method
                    && matched_path.is_some_and(|path| path.as_str() == limit.matched_path)
            })
            .map_or(self.default_limit, |limit| limit.max_body_bytes)
    }
}

/// Validated HTTP middleware composition.
#[derive(Clone, Debug)]
pub struct HttpShell {
    config: HttpShellConfig,
    concurrency_permits: Arc<Semaphore>,
}

impl HttpShell {
    /// Validates settings before any route is exposed.
    ///
    /// # Errors
    ///
    /// Returns [`HttpShellError`] for zero bounds or malformed trusted origins.
    pub fn new(config: HttpShellConfig) -> Result<Self, HttpShellError> {
        config.validate()?;
        validate_origins(&config.trusted_origins)?;
        drop(csrf_layer(&config.trusted_origins)?);
        let concurrency_permits = Arc::new(Semaphore::new(config.max_in_flight));
        Ok(Self {
            config,
            concurrency_permits,
        })
    }

    /// Returns the header-read timeout for the Hyper server adapter.
    #[must_use]
    pub const fn header_read_timeout(&self) -> Duration {
        self.config.header_read_timeout
    }

    /// Applies the standard browser-capable middleware stack to a composed router.
    ///
    /// # Errors
    ///
    /// Returns [`HttpShellError::InvalidTrustedOrigin`] if CSRF origin parsing rejects a value
    /// that passed HTTP header validation.
    pub fn apply(&self, routes: Router) -> Result<Router, HttpShellError> {
        self.apply_with_route_body_limits(routes, Vec::new())
    }

    /// Applies the browser-capable middleware stack with exact route-specific body bounds.
    ///
    /// Every request without an exact method and Axum matched-path-template entry retains the
    /// global [`HttpShellConfig::max_body_bytes`] bound.
    ///
    /// # Errors
    ///
    /// Returns [`HttpShellError::InvalidTrustedOrigin`] for invalid origin policy or
    /// [`HttpShellError::InvalidRouteBodyLimit`] for duplicate route entries.
    pub fn apply_with_route_body_limits(
        &self,
        routes: Router,
        route_limits: Vec<RouteBodyLimit>,
    ) -> Result<Router, HttpShellError> {
        if route_limits.iter().enumerate().any(|(index, limit)| {
            route_limits[..index].iter().any(|previous| {
                previous.method == limit.method && previous.matched_path == limit.matched_path
            })
        }) {
            return Err(HttpShellError::InvalidRouteBodyLimit);
        }
        let csrf = csrf_layer(&self.config.trusted_origins)?;
        let cors = cors_layer(&self.config.trusted_origins)?;
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Handler);
        let routes = routes.layer(csrf);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Csrf);
        let routes = routes.layer(cors);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Cors);
        Ok(self.apply_shared(routes, route_limits))
    }

    /// Applies the shared transport and safety stack to authenticated machine callbacks.
    ///
    /// This variant omits only browser-origin CORS and CSRF policy. It shares the same global
    /// concurrency permits as [`Self::apply`] and retains request IDs, forwarding/header/body
    /// limits, deadlines, tracing, sensitive-header treatment, panic handling, compression, and
    /// security response headers.
    pub fn apply_machine_callbacks(&self, routes: Router) -> Router {
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Handler);
        self.apply_shared(routes, Vec::new())
    }

    fn apply_shared(&self, routes: Router, route_limits: Vec<RouteBodyLimit>) -> Router {
        let body_limits = BodyLimitPolicy {
            default_limit: self.config.max_body_bytes,
            route_limits: route_limits.into(),
        };

        let concurrency = ConcurrencyState {
            permits: Arc::clone(&self.concurrency_permits),
        };
        let header_limits = HeaderLimits {
            bytes: self.config.max_header_bytes,
            count: self.config.max_header_count,
        };
        let sensitive =
            SetSensitiveHeadersLayer::new([AUTHORIZATION, PROXY_AUTHORIZATION, COOKIE, SET_COOKIE]);
        let trace = TraceLayer::new_for_http()
            .make_span_with(|request: &Request| {
                let route = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map_or("unmatched", MatchedPath::as_str);
                let span = tracing::info_span!(
                    "http.request",
                    "http.request.method" = %request.method(),
                    "http.route" = route,
                    request_id = tracing::field::Empty,
                    "http.response.status_code" = tracing::field::Empty,
                );
                if let Some(request_id) = request.extensions().get::<RequestId>() {
                    span.record("request_id", tracing::field::display(request_id));
                }
                span
            })
            .on_response(
                |response: &Response, latency: Duration, span: &tracing::Span| {
                    span.record("http.response.status_code", response.status().as_u16());
                    tracing::info!(
                        parent: span,
                        latency_ms = latency.as_secs_f64() * 1000.0,
                        "http response completed"
                    );
                },
            );

        let routes = routes.layer(middleware::from_fn_with_state(
            body_limits,
            enforce_body_limit,
        ));
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::BodyLimit);
        let routes = routes
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                self.config.handler_timeout,
            ))
            .layer(middleware::from_fn_with_state(
                header_limits,
                enforce_header_limits,
            ));
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Deadlines);
        let routes = routes.layer(middleware::from_fn_with_state(
            concurrency,
            enforce_concurrency,
        ));
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Concurrency);
        let routes = routes.layer(trace);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Trace);
        let routes = routes.layer(middleware::from_fn(strip_untrusted_forwarding));
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::TrustedProxy);
        let routes = routes.layer(sensitive);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::SensitiveHeaders);
        let routes = routes
            .layer(middleware::from_fn(apply_security_headers))
            .layer(CompressionLayer::new());
        #[cfg(test)]
        let routes = probe_response_stage(routes);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::RequestId);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::PanicBoundary);
        routes.layer(middleware::from_fn(panic_boundary))
    }
}

#[derive(Clone, Copy, Debug)]
struct HeaderLimits {
    bytes: usize,
    count: usize,
}
#[derive(Clone, Copy, Debug)]
struct OriginalHeaderUsage {
    bytes: usize,
    count: usize,
}

#[derive(Clone, Debug)]
struct ConcurrencyState {
    permits: Arc<Semaphore>,
}
#[cfg(test)]
#[derive(Clone, Debug)]
struct MiddlewareOrderProbe(Arc<std::sync::Mutex<Vec<MiddlewareStage>>>);

#[cfg(test)]
fn probe_request_stage(routes: Router, stage: MiddlewareStage) -> Router {
    routes.layer(middleware::from_fn_with_state(stage, record_request_stage))
}

#[cfg(test)]
fn probe_response_stage(routes: Router) -> Router {
    routes.layer(middleware::from_fn(record_response_stage))
}

#[cfg(test)]
async fn record_request_stage(
    State(stage): State<MiddlewareStage>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(probe) = request.extensions().get::<MiddlewareOrderProbe>() {
        probe
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(stage);
    }
    next.run(request).await
}

#[cfg(test)]
async fn record_response_stage(request: Request, next: Next) -> Response {
    let probe = request.extensions().get::<MiddlewareOrderProbe>().cloned();
    let response = next.run(request).await;
    if let Some(probe) = probe {
        probe
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(MiddlewareStage::ResponsePolicies);
    }
    response
}

async fn enforce_body_limit(
    State(policy): State<BodyLimitPolicy>,
    request: Request,
    next: Next,
) -> Response {
    let limit = policy.limit_for(&request);
    let service = service_fn(
        move |request: axum::http::Request<tower_http::body::Limited<Body>>| {
            let next = next.clone();
            async move {
                let request = request.map(Body::new);
                Ok::<_, Infallible>(next.run(request).await)
            }
        },
    );
    match RequestBodyLimit::new(service, limit).oneshot(request).await {
        Ok(response) => response.map(Body::new),
        Err(never) => match never {},
    }
}

async fn enforce_header_limits(
    State(limits): State<HeaderLimits>,
    request: Request,
    next: Next,
) -> Response {
    let usage = request
        .extensions()
        .get::<OriginalHeaderUsage>()
        .copied()
        .unwrap_or_else(|| header_usage(request.headers()));
    if usage.count > limits.count || usage.bytes > limits.bytes {
        return StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE.into_response();
    }
    next.run(request).await
}

async fn enforce_concurrency(
    State(state): State<ConcurrencyState>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = state.permits.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

async fn strip_untrusted_forwarding(mut request: Request, next: Next) -> Response {
    let usage = header_usage(request.headers());
    request.extensions_mut().insert(usage);
    for header in FORWARDED_HEADERS {
        request.headers_mut().remove(*header);
    }
    next.run(request).await
}

fn header_usage(headers: &HeaderMap) -> OriginalHeaderUsage {
    let mut usage = OriginalHeaderUsage { bytes: 0, count: 0 };
    for (name, value) in headers {
        usage.count = usage.count.saturating_add(1);
        usage.bytes = usage.bytes.saturating_add(name.as_str().len());
        usage.bytes = usage.bytes.saturating_add(value.as_bytes().len());
    }
    usage
}

async fn apply_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    add_security_headers(&mut response);
    response
}

fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers
        .entry("x-content-type-options")
        .or_insert(HeaderValue::from_static("nosniff"));
    headers
        .entry("x-frame-options")
        .or_insert(HeaderValue::from_static("DENY"));
    headers
        .entry("referrer-policy")
        .or_insert(HeaderValue::from_static("no-referrer"));
    headers
        .entry("content-security-policy")
        .or_insert(HeaderValue::from_static(
            "default-src 'none'; frame-ancestors 'none'",
        ));
}

async fn panic_boundary(mut request: Request, next: Next) -> Response {
    let request_id = inbound_request_id(&request).unwrap_or_default();
    request.extensions_mut().insert(request_id);

    let Ok(future) = catch_unwind(AssertUnwindSafe(|| next.run(request))) else {
        return panic_problem(request_id);
    };
    match AssertUnwindSafe(future).catch_unwind().await {
        Ok(response) => normalize_error_response(response, request_id),
        Err(_) => panic_problem(request_id),
    }
}

fn inbound_request_id(request: &Request) -> Option<RequestId> {
    request.extensions().get::<TrustedProxy>()?;
    let mut values = request.headers().get_all(REQUEST_ID_HEADER).iter();
    let value = values.next()?;
    if values.next().is_some() || value.as_bytes().len() > 128 {
        return None;
    }
    value.to_str().ok()?.parse().ok()
}

fn normalize_error_response(mut response: Response, request_id: RequestId) -> Response {
    if response.status().is_client_error() || response.status().is_server_error() {
        let status = response.status();
        let original_headers = response.headers().clone();
        let mut problem = response.extensions().get::<ValidatedProblem>().map_or_else(
            || ProblemDetails::new(status, generic_error_code(status), request_id),
            |validated| validated.0.clone(),
        );
        problem.request_id = request_id;
        problem.status = status.as_u16();
        problem.title = problem_title(status);
        response = problem.into_response();
        for (name, value) in &original_headers {
            if !matches!(
                name,
                &CONTENT_TYPE
                    | &CONTENT_LENGTH
                    | &CONTENT_ENCODING
                    | &TRANSFER_ENCODING
                    | &CACHE_CONTROL
            ) && name.as_str() != REQUEST_ID_HEADER
            {
                response.headers_mut().append(name, value.clone());
            }
        }
    }
    set_request_id_header(&mut response, request_id);
    response
}

fn panic_problem(request_id: RequestId) -> Response {
    let mut response = ProblemDetails::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        generic_error_code(StatusCode::INTERNAL_SERVER_ERROR),
        request_id,
    )
    .into_response();
    add_security_headers(&mut response);
    set_request_id_header(&mut response, request_id);
    response
}

fn set_request_id_header(response: &mut Response, request_id: RequestId) {
    let encoded = request_id.to_string();
    if let Ok(value) = HeaderValue::from_str(&encoded) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
}

fn validate_origins(origins: &[String]) -> Result<(), HttpShellError> {
    for origin in origins {
        let value =
            HeaderValue::from_str(origin).map_err(|_| HttpShellError::InvalidTrustedOrigin)?;
        if value.as_bytes().is_empty() || origin == "*" {
            return Err(HttpShellError::InvalidTrustedOrigin);
        }
    }
    Ok(())
}

fn csrf_layer(origins: &[String]) -> Result<CsrfLayer, HttpShellError> {
    let mut layer = CsrfLayer::new();
    for origin in origins {
        layer = layer
            .add_trusted_origin(origin)
            .map_err(|_| HttpShellError::InvalidTrustedOrigin)?;
    }
    Ok(layer)
}

fn cors_layer(origins: &[String]) -> Result<CorsLayer, HttpShellError> {
    if origins.is_empty() {
        return Ok(CorsLayer::new());
    }
    let allowed = origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin).map_err(|_| HttpShellError::InvalidTrustedOrigin)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(allowed)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            ACCEPT,
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("idempotency-key"),
            HeaderName::from_static("x-csrf-token"),
        ]))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::{
        Extension,
        body::{Body, to_bytes},
        http::{Request as HttpRequest, header::ORIGIN},
        routing::{get, post, put},
    };

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn shell_with(mut config: HttpShellConfig, body: usize) -> Result<HttpShell, HttpShellError> {
        config.max_body_bytes = body;
        HttpShell::new(config)
    }
    async fn assert_problem(
        response: Response,
        status: StatusCode,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static(PROBLEM_CONTENT_TYPE))
        );
        let header_request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .ok_or("missing request ID header")?
            .to_str()?
            .parse::<RequestId>()?;
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(value["status"], u64::from(status.as_u16()));
        assert_eq!(value["request_id"], header_request_id.to_string());
        assert!(
            value["type"]
                .as_str()
                .is_some_and(|value| value.starts_with("https://errors.omnius.invalid/"))
        );
        assert!(
            value["title"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );
        assert!(value["code"].as_str().is_some_and(|code| {
            code.bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        }));
        Ok(value)
    }
    async fn request_problem(
        app: &Router,
        request: Request,
        status: StatusCode,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        assert_problem(app.clone().oneshot(request).await?, status).await
    }

    #[tokio::test]
    async fn exact_route_body_override_reaches_upload_without_weakening_default_limit() -> TestResult
    {
        let upload_bytes = DEFAULT_BODY_BYTES + 1;
        let upload_reached = Arc::new(AtomicBool::new(false));
        let unrelated_reached = Arc::new(AtomicBool::new(false));
        let upload_handler = {
            let upload_reached = Arc::clone(&upload_reached);
            move |body: Body| {
                let upload_reached = Arc::clone(&upload_reached);
                async move {
                    if to_bytes(body, upload_bytes).await.is_ok() {
                        upload_reached.store(true, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                }
            }
        };
        let unrelated_handler = {
            let unrelated_reached = Arc::clone(&unrelated_reached);
            move || {
                let unrelated_reached = Arc::clone(&unrelated_reached);
                async move {
                    unrelated_reached.store(true, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }
            }
        };
        let shell = HttpShell::new(HttpShellConfig::default())?;
        let app = shell.apply_with_route_body_limits(
            Router::new()
                .route(
                    "/uploads/{upload_id}/content",
                    put(upload_handler).post(|| async { StatusCode::NO_CONTENT }),
                )
                .route("/unrelated", post(unrelated_handler)),
            vec![RouteBodyLimit::new(
                Method::PUT,
                "/uploads/{upload_id}/content",
                upload_bytes,
            )?],
        )?;

        let uploaded = app
            .clone()
            .oneshot(
                HttpRequest::put("/uploads/01890f2a-0000-7000-8000-000000000001/content")
                    .header(CONTENT_LENGTH, upload_bytes.to_string())
                    .body(Body::from(vec![b'x'; upload_bytes]))?,
            )
            .await?;
        assert_eq!(uploaded.status(), StatusCode::NO_CONTENT);
        assert!(upload_reached.load(Ordering::SeqCst));

        let unrelated = app
            .clone()
            .oneshot(
                HttpRequest::post("/unrelated")
                    .header(CONTENT_LENGTH, upload_bytes.to_string())
                    .body(Body::from(vec![b'x'; upload_bytes]))?,
            )
            .await?;
        assert_eq!(unrelated.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(!unrelated_reached.load(Ordering::SeqCst));

        let wrong_method = app
            .oneshot(
                HttpRequest::post("/uploads/01890f2a-0000-7000-8000-000000000001/content")
                    .header(CONTENT_LENGTH, upload_bytes.to_string())
                    .body(Body::from(vec![b'x'; upload_bytes]))?,
            )
            .await?;
        assert_eq!(wrong_method.status(), StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn every_shell_error_is_a_request_scoped_problem_document() -> TestResult {
        async fn slow() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        async fn panics() -> StatusCode {
            panic!("private panic payload")
        }
        let app = HttpShell::new(HttpShellConfig {
            max_body_bytes: 4,
            max_header_bytes: 512,
            handler_timeout: Duration::from_millis(5),
            ..HttpShellConfig::default()
        })?
        .apply(
            Router::new()
                .route("/slow", get(slow))
                .route("/panic", get(panics))
                .route("/mutation", post(|| async { StatusCode::NO_CONTENT })),
        )?;

        request_problem(
            &app,
            HttpRequest::get("/missing").body(Body::empty())?,
            StatusCode::NOT_FOUND,
        )
        .await?;
        request_problem(
            &app,
            HttpRequest::get("/slow").body(Body::empty())?,
            StatusCode::REQUEST_TIMEOUT,
        )
        .await?;
        let panic_body = request_problem(
            &app,
            HttpRequest::get("/panic").body(Body::empty())?,
            StatusCode::INTERNAL_SERVER_ERROR,
        )
        .await?;
        assert!(!panic_body.to_string().contains("private panic payload"));

        let oversized_body = app
            .clone()
            .oneshot(
                HttpRequest::post("/mutation")
                    .header("content-length", "10")
                    .body(Body::empty())?,
            )
            .await?;
        assert_problem(oversized_body, StatusCode::PAYLOAD_TOO_LARGE).await?;

        let oversized_headers = app
            .clone()
            .oneshot(
                HttpRequest::get("/missing")
                    .header("x-large", "a".repeat(600))
                    .body(Body::empty())?,
            )
            .await?;
        assert_problem(
            oversized_headers,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        )
        .await?;

        let csrf = app
            .clone()
            .oneshot(
                HttpRequest::post("/mutation")
                    .header("host", "service.example")
                    .header("sec-fetch-site", "cross-site")
                    .header(ORIGIN, "https://evil.example")
                    .body(Body::empty())?,
            )
            .await?;
        assert_problem(csrf, StatusCode::FORBIDDEN).await?;

        Ok(())
    }

    #[tokio::test]
    async fn counterfeit_or_mismatched_problems_are_rebuilt_by_the_boundary() -> TestResult {
        let wrong_request_id = RequestId::new();
        let app = HttpShell::new(HttpShellConfig::default())?.apply(
            Router::new()
                .route(
                    "/counterfeit",
                    get(|| async {
                        (
                            StatusCode::BAD_REQUEST,
                            [(CONTENT_TYPE, PROBLEM_CONTENT_TYPE)],
                            "not a problem document",
                        )
                    }),
                )
                .route(
                    "/wrong-request-id",
                    get(move || async move {
                        ProblemDetails::new(
                            StatusCode::BAD_REQUEST,
                            generic_error_code(StatusCode::BAD_REQUEST),
                            wrong_request_id,
                        )
                    }),
                ),
        )?;

        let wrong_id = app
            .clone()
            .oneshot(HttpRequest::get("/wrong-request-id").body(Body::empty())?)
            .await?;
        let wrong_id_value = assert_problem(wrong_id, StatusCode::BAD_REQUEST).await?;
        assert_ne!(wrong_id_value["request_id"], wrong_request_id.to_string());

        let counterfeit = app
            .oneshot(HttpRequest::get("/counterfeit").body(Body::empty())?)
            .await?;
        let value = assert_problem(counterfeit, StatusCode::BAD_REQUEST).await?;
        assert_eq!(value["code"], "BAD_REQUEST");
        Ok(())
    }

    #[tokio::test]
    async fn request_ids_generate_propagate_and_only_trust_verified_peers() -> TestResult {
        let app = HttpShell::new(HttpShellConfig::default())?.apply(Router::new().route(
            "/",
            get(
                |Extension(request_id): Extension<RequestId>| async move { request_id.to_string() },
            ),
        ))?;
        let inbound = RequestId::new();
        let mut trusted_request = HttpRequest::get("/")
            .header(REQUEST_ID_HEADER, inbound.to_string())
            .body(Body::empty())?;
        trusted_request.extensions_mut().insert(TrustedProxy);
        let trusted = app.clone().oneshot(trusted_request).await?;
        assert_eq!(
            trusted.headers().get(REQUEST_ID_HEADER),
            Some(&HeaderValue::from_str(&inbound.to_string())?)
        );

        let untrusted = app
            .oneshot(
                HttpRequest::get("/")
                    .header(REQUEST_ID_HEADER, inbound.to_string())
                    .body(Body::empty())?,
            )
            .await?;
        let generated = untrusted
            .headers()
            .get(REQUEST_ID_HEADER)
            .ok_or("missing request ID")?
            .to_str()?
            .parse::<RequestId>()?;
        assert_ne!(generated, inbound);
        assert!(generated.is_v7());
        Ok(())
    }

    #[test]
    fn service_errors_and_field_errors_serialize_only_safe_contract_data() -> TestResult {
        #[derive(Debug, Error)]
        #[error("database password=raw-secret")]
        struct SensitiveCause;

        let code = ErrorCode::try_new("DATABASE_UNAVAILABLE")?;
        let service_error =
            ServiceError::new(code, "service temporarily unavailable").with_source(SensitiveCause);
        let field_error = FieldError::try_new("/profile/email", "invalid_format", "invalid email")?;
        let problem = ProblemDetails::from_service_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &service_error,
            RequestId::new(),
        )?
        .with_errors(vec![field_error.clone()])?;
        let encoded = serde_json::to_string(&problem)?;
        assert!(encoded.contains("service temporarily unavailable"));
        assert!(encoded.contains("invalid_format"));
        assert!(!encoded.contains("raw-secret"));

        assert_eq!(
            FieldError::try_new("not-a-pointer", "invalid_format", "invalid").map(|_| ()),
            Err(ProblemBuildError::InvalidPointer)
        );
        assert_eq!(
            FieldError::try_new("/field", "INVALID", "invalid").map(|_| ()),
            Err(ProblemBuildError::InvalidFieldCode)
        );
        assert_eq!(
            ProblemDetails::try_for_status(StatusCode::BAD_REQUEST, RequestId::new())?
                .with_errors(vec![field_error; MAX_FIELD_ERRORS + 1])
                .map(|_| ()),
            Err(ProblemBuildError::TooManyFieldErrors)
        );
        assert_eq!(
            ProblemDetails::try_for_status(StatusCode::OK, RequestId::new()).map(|_| ()),
            Err(ProblemBuildError::InvalidHttpStatus)
        );
        Ok(())
    }

    #[tokio::test]
    async fn header_and_body_rejections_follow_the_normative_order() -> TestResult {
        let config = HttpShellConfig {
            max_header_bytes: 80,
            max_header_count: 8,
            ..HttpShellConfig::default()
        };
        let app = shell_with(config, 4)?.apply(Router::new().route("/", post(|| async {})))?;

        let oversized_headers = HttpRequest::builder()
            .method(Method::POST)
            .uri("/")
            .header("x-large", "a-value-that-exceeds-the-header-budget")
            .header("content-length", "10")
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())?;
        assert_eq!(
            app.clone().oneshot(oversized_headers).await?.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );

        let oversized_body = HttpRequest::builder()
            .method(Method::POST)
            .uri("/")
            .header("content-length", "10")
            .header("sec-fetch-site", "cross-site")
            .body(Body::empty())?;
        assert_eq!(
            app.clone().oneshot(oversized_body).await?.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );

        let oversized_forwarded = HttpRequest::builder()
            .uri("/")
            .header("x-forwarded-for", "a".repeat(100))
            .body(Body::empty())?;
        assert_eq!(
            app.oneshot(oversized_forwarded).await?.status(),
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        Ok(())
    }

    #[tokio::test]
    async fn concurrency_excess_rejects_instead_of_queueing() -> TestResult {
        let entered = Arc::new(Semaphore::new(0));
        let release = Arc::new(Semaphore::new(0));
        let app = HttpShell::new(HttpShellConfig {
            max_in_flight: 1,
            ..HttpShellConfig::default()
        })?
        .apply(Router::new().route(
            "/",
            get({
                let entered = Arc::clone(&entered);
                let release = Arc::clone(&release);
                move || {
                    let entered = Arc::clone(&entered);
                    let release = Arc::clone(&release);
                    async move {
                        entered.add_permits(1);
                        let _permit = release.acquire().await;
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        ))?;

        let first_app = app.clone();
        let first_request = HttpRequest::get("/").body(Body::empty())?;
        let first = tokio::spawn(async move { first_app.oneshot(first_request).await });
        let _entered = entered.acquire().await?;
        let second = app
            .oneshot(HttpRequest::get("/").body(Body::empty())?)
            .await?;
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        release.add_permits(1);
        assert_eq!(first.await??.status(), StatusCode::NO_CONTENT);
        Ok(())
    }

    #[tokio::test]
    async fn handler_deadline_and_panic_boundary_return_generic_failures() -> TestResult {
        async fn slow() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        async fn panics() -> StatusCode {
            panic!("private panic payload")
        }

        let app = HttpShell::new(HttpShellConfig {
            handler_timeout: Duration::from_millis(5),
            ..HttpShellConfig::default()
        })?
        .apply(
            Router::new()
                .route("/slow", get(slow))
                .route("/panic", get(panics)),
        )?;
        let timeout = app
            .clone()
            .oneshot(HttpRequest::get("/slow").body(Body::empty())?)
            .await?;
        assert_eq!(timeout.status(), StatusCode::REQUEST_TIMEOUT);

        let panic = app
            .oneshot(HttpRequest::get("/panic").body(Body::empty())?)
            .await?;
        assert_eq!(panic.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            panic.headers().get("x-content-type-options"),
            Some(&HeaderValue::from_static("nosniff"))
        );
        let body = to_bytes(panic.into_body(), 1024).await?;
        assert!(
            !body
                .windows("private panic payload".len())
                .any(|window| { window == "private panic payload".as_bytes() })
        );
        Ok(())
    }

    #[tokio::test]
    async fn credentials_are_sensitive_and_untrusted_forwarding_is_removed() -> TestResult {
        let observed = Arc::new(AtomicBool::new(false));
        let app = HttpShell::new(HttpShellConfig::default())?.apply(Router::new().route(
            "/",
            get({
                let observed = Arc::clone(&observed);
                move |request: Request| {
                    let observed = Arc::clone(&observed);
                    async move {
                        let authorization = request.headers().get(AUTHORIZATION);
                        let forwarded = request.headers().get("x-forwarded-for");
                        observed.store(
                            authorization.is_some_and(HeaderValue::is_sensitive)
                                && forwarded.is_none(),
                            Ordering::SeqCst,
                        );
                        StatusCode::NO_CONTENT
                    }
                }
            }),
        ))?;

        let response = app
            .oneshot(
                HttpRequest::get("/")
                    .header(AUTHORIZATION, "Bearer raw-secret")
                    .header("x-forwarded-for", "203.0.113.7")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(observed.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn cors_and_csrf_are_deny_by_default_and_exact_when_configured() -> TestResult {
        let denied = HttpShell::new(HttpShellConfig::default())?
            .apply(Router::new().route("/", post(|| async {})))?
            .oneshot(
                HttpRequest::post("/")
                    .header("host", "service.example")
                    .header("sec-fetch-site", "cross-site")
                    .header(ORIGIN, "https://evil.example")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let allowed = HttpShell::new(HttpShellConfig {
            trusted_origins: vec!["https://app.example".to_owned()],
            ..HttpShellConfig::default()
        })?
        .apply(Router::new().route("/", post(|| async { StatusCode::NO_CONTENT })))?
        .oneshot(
            HttpRequest::post("/")
                .header("host", "service.example")
                .header("sec-fetch-site", "cross-site")
                .header(ORIGIN, "https://app.example")
                .body(Body::empty())?,
        )
        .await?;
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            allowed.headers().get("access-control-allow-origin"),
            Some(&HeaderValue::from_static("https://app.example"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn request_probe_confirms_the_effective_installed_order() -> TestResult {
        let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let probe = MiddlewareOrderProbe(Arc::clone(&observed));
        let app = HttpShell::new(HttpShellConfig::default())?
            .apply(Router::new().route("/", get(|| async { StatusCode::NO_CONTENT })))?;
        let mut request = HttpRequest::get("/").body(Body::empty())?;
        request.extensions_mut().insert(probe);

        assert_eq!(app.oneshot(request).await?.status(), StatusCode::NO_CONTENT);
        let actual = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(
            actual,
            [
                MiddlewareStage::PanicBoundary,
                MiddlewareStage::RequestId,
                MiddlewareStage::SensitiveHeaders,
                MiddlewareStage::TrustedProxy,
                MiddlewareStage::Trace,
                MiddlewareStage::Concurrency,
                MiddlewareStage::Deadlines,
                MiddlewareStage::BodyLimit,
                MiddlewareStage::Cors,
                MiddlewareStage::Csrf,
                MiddlewareStage::Handler,
                MiddlewareStage::ResponsePolicies,
            ]
        );
        Ok(())
    }

    #[test]
    fn validates_limits_origins_and_declared_order() {
        let invalid = HttpShellConfig {
            max_in_flight: 0,
            ..HttpShellConfig::default()
        };
        assert_eq!(
            HttpShell::new(invalid).map(|_| ()),
            Err(HttpShellError::ZeroLimit("max_in_flight"))
        );
        let invalid_origin = HttpShellConfig {
            trusted_origins: vec!["bad\norigin".to_owned()],
            ..HttpShellConfig::default()
        };
        assert_eq!(
            HttpShell::new(invalid_origin).map(|_| ()),
            Err(HttpShellError::InvalidTrustedOrigin)
        );
        let wildcard_origin = HttpShellConfig {
            trusted_origins: vec!["*".to_owned()],
            ..HttpShellConfig::default()
        };
        assert_eq!(
            HttpShell::new(wildcard_origin).map(|_| ()),
            Err(HttpShellError::InvalidTrustedOrigin)
        );
        assert_eq!(MIDDLEWARE_ORDER[0], MiddlewareStage::PanicBoundary);
        assert_eq!(
            MIDDLEWARE_ORDER[MIDDLEWARE_ORDER.len() - 1],
            MiddlewareStage::ResponsePolicies
        );
    }
}
