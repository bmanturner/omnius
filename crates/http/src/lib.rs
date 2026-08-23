//! Axum/Tower HTTP shell with explicit middleware ordering and bounded defaults.

use std::{any::Any, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{MatchedPath, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, COOKIE, PROXY_AUTHORIZATION, SET_COOKIE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Semaphore;
use tower_http::{
    catch_panic::CatchPanicLayer, compression::CompressionLayer, cors::CorsLayer, csrf::CsrfLayer,
    limit::RequestBodyLimitLayer, sensitive_headers::SetSensitiveHeadersLayer,
    timeout::TimeoutLayer, trace::TraceLayer,
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
}

/// Validated HTTP middleware composition.
#[derive(Clone, Debug)]
pub struct HttpShell {
    config: HttpShellConfig,
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
        Ok(Self { config })
    }

    /// Returns the header-read timeout for the Hyper server adapter.
    #[must_use]
    pub const fn header_read_timeout(&self) -> Duration {
        self.config.header_read_timeout
    }

    /// Applies the standard middleware stack to an already composed router.
    ///
    /// # Errors
    ///
    /// Returns [`HttpShellError::InvalidTrustedOrigin`] if CSRF origin parsing
    /// rejects a value that passed HTTP header validation.
    pub fn apply(&self, routes: Router) -> Result<Router, HttpShellError> {
        let csrf = csrf_layer(&self.config.trusted_origins)?;
        let cors = cors_layer(&self.config.trusted_origins)?;
        let concurrency = ConcurrencyState {
            permits: Arc::new(Semaphore::new(self.config.max_in_flight)),
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
                tracing::info_span!(
                    "http.request",
                    "http.request.method" = %request.method(),
                    "http.route" = route,
                    "http.response.status_code" = tracing::field::Empty,
                )
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

        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Handler);
        let routes = routes.layer(csrf);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Csrf);
        let routes = routes.layer(cors);
        #[cfg(test)]
        let routes = probe_request_stage(routes, MiddlewareStage::Cors);
        let routes = routes.layer(RequestBodyLimitLayer::new(self.config.max_body_bytes));
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
        let routes = probe_request_stage(routes, MiddlewareStage::PanicBoundary);
        Ok(routes.layer(CatchPanicLayer::custom(panic_response)))
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

fn panic_response(_: Box<dyn Any + Send + 'static>) -> Response {
    let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
    add_security_headers(&mut response);
    response
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
        body::{Body, to_bytes},
        http::{Request as HttpRequest, header::ORIGIN},
        routing::{get, post},
    };
    use tower::ServiceExt as _;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn shell_with(mut config: HttpShellConfig, body: usize) -> Result<HttpShell, HttpShellError> {
        config.max_body_bytes = body;
        HttpShell::new(config)
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
