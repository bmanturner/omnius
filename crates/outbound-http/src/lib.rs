//! Reusable outbound HTTP clients with bounded redirects, deadlines, and response bodies.
//!
//! The clients deliberately disable reqwest's automatic retries. Provider adapters may add
//! retries only after classifying an operation as safe or idempotent.

use std::{
    fmt,
    time::{Duration, Instant},
};

use reqwest::{
    Client, IntoUrl, Method, Request, RequestBuilder, Response, StatusCode,
    header::{HeaderMap, HeaderName, HeaderValue},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024 * 1024;
const MAX_INITIAL_BODY_CAPACITY: usize = 64 * 1024;
const MAX_REDIRECTS: usize = 10;
const MAX_USER_AGENT_BYTES: usize = 256;
const REDACTED: &str = "[REDACTED]";

/// Selects the prebuilt client policy used for an outbound request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyClass {
    /// Follows redirects up to the configured fixed limit.
    Standard,
    /// Returns redirect responses without following them.
    NoRedirect,
}

impl PolicyClass {
    const fn label(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::NoRedirect => "no_redirect",
        }
    }
}

impl fmt::Display for PolicyClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Controls outbound proxy discovery and explicit proxy routing.
#[derive(Clone, Default, Deserialize, Eq, PartialEq)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ProxyPolicy {
    /// Disables all automatic proxy discovery.
    #[default]
    Disabled,
    /// Enables reqwest's environment/system proxy discovery.
    Environment,
    /// Routes through one explicit proxy URL.
    Explicit {
        /// Proxy URL, which may contain credentials and is always redacted from diagnostics.
        url: String,
    },
}

impl fmt::Debug for ProxyPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Environment => formatter.write_str("Environment"),
            Self::Explicit { .. } => formatter
                .debug_struct("Explicit")
                .field("url", &REDACTED)
                .finish(),
        }
    }
}

/// Bounded configuration shared by every outbound client policy class.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundHttpConfig {
    /// Maximum time allowed to establish a connection.
    #[serde(with = "humantime_serde")]
    pub connect_timeout: Duration,
    /// Total deadline from connection start through response-body completion.
    #[serde(with = "humantime_serde")]
    pub total_timeout: Duration,
    /// Maximum decompressed response body accepted by bounded consumption.
    pub response_body_limit_bytes: usize,
    /// Maximum redirects followed by the standard policy class.
    pub max_redirects: usize,
    /// Proxy policy. Proxying is disabled unless explicitly enabled.
    pub proxy: ProxyPolicy,
    /// User-Agent sent by both prebuilt clients.
    pub user_agent: String,
}

impl Default for OutboundHttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            response_body_limit_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
            proxy: ProxyPolicy::Disabled,
            user_agent: concat!("rsk-outbound-http/", env!("CARGO_PKG_VERSION")).to_owned(),
        }
    }
}

impl fmt::Debug for OutboundHttpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundHttpConfig")
            .field("connect_timeout", &self.connect_timeout)
            .field("total_timeout", &self.total_timeout)
            .field("response_body_limit_bytes", &self.response_body_limit_bytes)
            .field("max_redirects", &self.max_redirects)
            .field("proxy", &self.proxy)
            .field("user_agent", &REDACTED)
            .finish()
    }
}

impl OutboundHttpConfig {
    /// Validates all fixed configuration bounds without exposing rejected values.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for zero or excessive timeouts, inconsistent deadlines,
    /// an out-of-range body or redirect limit, or an invalid User-Agent.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.connect_timeout.is_zero() {
            return Err(ConfigError::ZeroDuration("connect_timeout"));
        }
        if self.connect_timeout > MAX_CONNECT_TIMEOUT {
            return Err(ConfigError::ExceedsMaximum("connect_timeout"));
        }
        if self.total_timeout.is_zero() {
            return Err(ConfigError::ZeroDuration("total_timeout"));
        }
        if self.total_timeout > MAX_TOTAL_TIMEOUT {
            return Err(ConfigError::ExceedsMaximum("total_timeout"));
        }
        if self.connect_timeout > self.total_timeout {
            return Err(ConfigError::ConnectExceedsTotal);
        }
        if !(1..=MAX_RESPONSE_BODY_BYTES).contains(&self.response_body_limit_bytes) {
            return Err(ConfigError::ResponseBodyLimit);
        }
        if !(1..=MAX_REDIRECTS).contains(&self.max_redirects) {
            return Err(ConfigError::RedirectLimit);
        }
        if !valid_user_agent(&self.user_agent) {
            return Err(ConfigError::InvalidUserAgent);
        }
        if matches!(&self.proxy, ProxyPolicy::Explicit { url } if url.is_empty()) {
            return Err(ConfigError::InvalidProxy);
        }
        Ok(())
    }
}

fn valid_user_agent(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_AGENT_BYTES
        && value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        && HeaderValue::from_bytes(value.as_bytes()).is_ok()
}

/// A safe, value-free outbound configuration error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    /// A required duration is zero.
    #[error("outbound HTTP configuration duration must be non-zero: {0}")]
    ZeroDuration(&'static str),
    /// A duration is above its fixed maximum.
    #[error("outbound HTTP configuration duration exceeds its maximum: {0}")]
    ExceedsMaximum(&'static str),
    /// The connect timeout cannot fit within the total deadline.
    #[error("outbound HTTP connect timeout exceeds the total timeout")]
    ConnectExceedsTotal,
    /// The response-body cap is outside its fixed range.
    #[error("outbound HTTP response body limit is outside its allowed range")]
    ResponseBodyLimit,
    /// The controlled redirect count is outside its fixed range.
    #[error("outbound HTTP redirect limit is outside its allowed range")]
    RedirectLimit,
    /// The User-Agent is empty, excessive, or not visible ASCII.
    #[error("outbound HTTP user agent is invalid")]
    InvalidUserAgent,
    /// An explicit proxy URL is empty.
    #[error("outbound HTTP explicit proxy configuration is invalid")]
    InvalidProxy,
}

/// Failure to construct the reusable client set.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BuildError {
    /// Bounded configuration validation failed.
    #[error(transparent)]
    InvalidConfiguration(#[from] ConfigError),
    /// The process could not install or obtain the required rustls crypto provider.
    #[error("outbound HTTP rustls crypto provider is unavailable")]
    CryptoProvider,
    /// An explicit proxy URL could not be parsed.
    #[error("outbound HTTP explicit proxy configuration is invalid")]
    Proxy,
    /// Reqwest rejected a client policy without retaining configuration details.
    #[error("failed to build outbound HTTP client for policy {policy}")]
    Client {
        /// Policy class that could not be constructed.
        policy: PolicyClass,
    },
}

/// Reusable clients, built exactly once per transport policy class.
#[derive(Clone)]
pub struct OutboundHttpClients {
    standard: Client,
    no_redirect: Client,
    response_body_limit_bytes: usize,
}

impl fmt::Debug for OutboundHttpClients {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundHttpClients")
            .field(
                "policies",
                &[PolicyClass::Standard, PolicyClass::NoRedirect],
            )
            .field("response_body_limit_bytes", &self.response_body_limit_bytes)
            .finish_non_exhaustive()
    }
}

impl OutboundHttpClients {
    /// Builds the standard and no-redirect clients once from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when configuration is invalid, the rustls provider is
    /// unavailable, or reqwest rejects either client.
    pub fn new(config: &OutboundHttpConfig) -> Result<Self, BuildError> {
        config.validate()?;
        ensure_crypto_provider()?;
        let standard = build_client(config, PolicyClass::Standard)?;
        let no_redirect = build_client(config, PolicyClass::NoRedirect)?;

        Ok(Self {
            standard,
            no_redirect,
            response_body_limit_bytes: config.response_body_limit_bytes,
        })
    }

    fn client(&self, policy: PolicyClass) -> &Client {
        match policy {
            PolicyClass::Standard => &self.standard,
            PolicyClass::NoRedirect => &self.no_redirect,
        }
    }

    /// Starts an opaque request with the already-built client selected by `policy`.
    ///
    /// The returned builder can only produce an [`OutboundRequest`], keeping execution,
    /// response limits, and telemetry inside this crate.
    pub fn request<U>(&self, policy: PolicyClass, method: Method, url: U) -> OutboundRequestBuilder
    where
        U: IntoUrl,
    {
        OutboundRequestBuilder {
            policy,
            inner: self.client(policy).request(method, url),
            invalid_header: false,
        }
    }

    /// Executes an opaque request with its selected shared client and safe telemetry.
    ///
    /// No request is retried by this client layer.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundHttpError::Timeout`] when the configured total deadline expires and
    /// [`OutboundHttpError::Transport`] for other transport failures.
    pub async fn execute(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundResponse, OutboundHttpError> {
        let OutboundRequest { policy, inner } = request;
        let started = Instant::now();
        let result = self.client(policy).execute(inner).await;
        let elapsed = started.elapsed();
        let outcome = match &result {
            Ok(_) => "response",
            Err(error) if error.is_timeout() => "timeout",
            Err(_) => "transport_error",
        };
        record_request(policy, outcome, elapsed);
        tracing::debug!(
            policy = policy.label(),
            outcome,
            elapsed_ms = elapsed.as_millis(),
            "outbound HTTP request completed"
        );

        result
            .map(|inner| OutboundResponse { policy, inner })
            .map_err(|error| map_reqwest_request_error(&error))
    }

    /// Consumes a response in chunks and aborts before the configured cap is exceeded.
    ///
    /// The limit applies to bytes yielded by reqwest after content decoding. A declared length
    /// may fail early, but every received chunk is checked independently. Dropping the response
    /// on overflow terminates further body consumption.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundHttpError::ResponseTooLarge`] before retaining bytes above the cap,
    /// [`OutboundHttpError::Timeout`] on deadline expiry, or
    /// [`OutboundHttpError::ResponseBody`] on another body-stream failure.
    pub async fn read_body(
        &self,
        mut response: OutboundResponse,
    ) -> Result<Vec<u8>, OutboundHttpError> {
        let started = Instant::now();
        let limit = self.response_body_limit_bytes;
        let content_length = response.inner.content_length();

        if content_length.is_some_and(|length| length > limit as u64) {
            let error = OutboundHttpError::ResponseTooLarge;
            record_body(response.policy, error.label(), started.elapsed());
            return Err(error);
        }

        let initial_capacity = content_length
            .and_then(|length| usize::try_from(length).ok())
            .unwrap_or(0)
            .min(limit)
            .min(MAX_INITIAL_BODY_CAPACITY);
        let mut body = Vec::with_capacity(initial_capacity);

        loop {
            match response.inner.chunk().await {
                Ok(Some(chunk)) => {
                    if chunk.len() > limit - body.len() {
                        let error = OutboundHttpError::ResponseTooLarge;
                        record_body(response.policy, error.label(), started.elapsed());
                        return Err(error);
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => {
                    record_body(response.policy, "success", started.elapsed());
                    return Ok(body);
                }
                Err(error) => {
                    let error = map_reqwest_body_error(&error);
                    record_body(response.policy, error.label(), started.elapsed());
                    return Err(error);
                }
            }
        }
    }

    /// Executes a request and returns its status with a bounded response body.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundHttpError`] for request, deadline, body-stream, or size-limit failure.
    pub async fn execute_bounded(
        &self,
        request: OutboundRequest,
    ) -> Result<BoundedResponse, OutboundHttpError> {
        let response = self.execute(request).await?;
        let status = response.status();
        let body = self.read_body(response).await?;
        Ok(BoundedResponse { status, body })
    }

    /// Returns the configured bounded-response cap.
    #[must_use]
    pub const fn response_body_limit_bytes(&self) -> usize {
        self.response_body_limit_bytes
    }
}

fn ensure_crypto_provider() -> Result<(), BuildError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(BuildError::CryptoProvider);
    }
    Ok(())
}

fn build_client(config: &OutboundHttpConfig, policy: PolicyClass) -> Result<Client, BuildError> {
    let redirect = match policy {
        PolicyClass::Standard => reqwest::redirect::Policy::limited(config.max_redirects),
        PolicyClass::NoRedirect => reqwest::redirect::Policy::none(),
    };

    let builder = Client::builder()
        .use_rustls_tls()
        .connect_timeout(config.connect_timeout)
        .timeout(config.total_timeout)
        .user_agent(&config.user_agent)
        .redirect(redirect)
        .retry(reqwest::retry::never());
    let builder = match &config.proxy {
        ProxyPolicy::Disabled => builder.no_proxy(),
        ProxyPolicy::Environment => builder,
        ProxyPolicy::Explicit { url } => {
            let proxy = reqwest::Proxy::all(url).map_err(|_| BuildError::Proxy)?;
            builder.proxy(proxy)
        }
    };

    builder.build().map_err(|_| BuildError::Client { policy })
}

/// Opaque builder for a request that can only execute through [`OutboundHttpClients`].
pub struct OutboundRequestBuilder {
    policy: PolicyClass,
    inner: RequestBuilder,
    invalid_header: bool,
}

impl OutboundRequestBuilder {
    /// Adds one request header.
    #[must_use]
    pub fn header<K, V>(mut self, name: K, value: V) -> Self
    where
        K: TryInto<HeaderName>,
        V: TryInto<HeaderValue>,
    {
        match (name.try_into(), value.try_into()) {
            (Ok(name), Ok(value)) => self.inner = self.inner.header(name, value),
            _ => self.invalid_header = true,
        }
        self
    }

    /// Merges request headers into the request.
    #[must_use]
    pub fn headers(mut self, headers: HeaderMap) -> Self {
        self.inner = self.inner.headers(headers);
        self
    }

    /// Appends serialized query parameters.
    #[must_use]
    pub fn query<T>(mut self, query: &T) -> Self
    where
        T: Serialize + ?Sized,
    {
        self.inner = self.inner.query(query);
        self
    }

    /// Serializes a JSON request body and sets its content type.
    #[must_use]
    pub fn json<T>(mut self, value: &T) -> Self
    where
        T: Serialize + ?Sized,
    {
        self.inner = self.inner.json(value);
        self
    }

    /// Sets the request body.
    #[must_use]
    pub fn body<T>(mut self, body: T) -> Self
    where
        T: Into<reqwest::Body>,
    {
        self.inner = self.inner.body(body);
        self
    }

    /// Sets a sensitive bearer authorization header.
    #[must_use]
    pub fn bearer_auth<T>(mut self, token: T) -> Self
    where
        T: fmt::Display,
    {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    /// Sets a sensitive basic authorization header.
    #[must_use]
    pub fn basic_auth<U, P>(mut self, username: U, password: Option<P>) -> Self
    where
        U: fmt::Display,
        P: fmt::Display,
    {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    /// Builds an opaque request without exposing its URL, headers, or body.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundHttpError::RequestBuild`] without retaining rejected values.
    pub fn build(self) -> Result<OutboundRequest, OutboundHttpError> {
        if self.invalid_header {
            return Err(OutboundHttpError::RequestBuild);
        }
        let policy = self.policy;
        self.inner
            .build()
            .map(|inner| OutboundRequest { policy, inner })
            .map_err(|_| OutboundHttpError::RequestBuild)
    }
}

impl fmt::Debug for OutboundRequestBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRequestBuilder")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Opaque built request accepted by [`OutboundHttpClients::execute`] and
/// [`OutboundHttpClients::execute_bounded`].
pub struct OutboundRequest {
    policy: PolicyClass,
    inner: Request,
}

impl fmt::Debug for OutboundRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundRequest")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

/// Response metadata retained while its body remains subject to bounded consumption.
pub struct OutboundResponse {
    policy: PolicyClass,
    inner: Response,
}

impl OutboundResponse {
    /// Returns the HTTP status.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// Borrows response headers without logging or copying their values.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }

    /// Returns the declared response length when supplied by the peer.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    /// Returns the client policy that produced this response.
    #[must_use]
    pub const fn policy(&self) -> PolicyClass {
        self.policy
    }
}

impl fmt::Debug for OutboundResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundResponse")
            .field("policy", &self.policy)
            .field("status", &self.status())
            .field("header_count", &self.headers().len())
            .field("content_length", &self.content_length())
            .finish_non_exhaustive()
    }
}

/// Status and bytes returned by [`OutboundHttpClients::execute_bounded`].
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedResponse {
    status: StatusCode,
    body: Vec<u8>,
}

impl BoundedResponse {
    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Borrows the bounded response bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Takes ownership of the bounded response bytes.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl fmt::Debug for BoundedResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedResponse")
            .field("status", &self.status)
            .field("body_length", &self.body.len())
            .finish()
    }
}

/// Safe, value-free request or response-consumption failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OutboundHttpError {
    /// A request URL, header, query, or body could not be built.
    #[error("outbound HTTP request could not be built")]
    RequestBuild,
    /// The configured request deadline expired.
    #[error("outbound HTTP request timed out")]
    Timeout,
    /// The request failed before a response was available.
    #[error("outbound HTTP transport failed")]
    Transport,
    /// The response body stream failed.
    #[error("outbound HTTP response body failed")]
    ResponseBody,
    /// The response body exceeded the configured cap.
    #[error("outbound HTTP response body exceeded its configured limit")]
    ResponseTooLarge,
}

impl OutboundHttpError {
    const fn label(self) -> &'static str {
        match self {
            Self::RequestBuild => "request_build_error",
            Self::Timeout => "timeout",
            Self::Transport => "transport_error",
            Self::ResponseBody => "body_error",
            Self::ResponseTooLarge => "too_large",
        }
    }
}

fn map_reqwest_request_error(error: &reqwest::Error) -> OutboundHttpError {
    if error.is_timeout() {
        OutboundHttpError::Timeout
    } else {
        OutboundHttpError::Transport
    }
}

fn map_reqwest_body_error(error: &reqwest::Error) -> OutboundHttpError {
    if error.is_timeout() {
        OutboundHttpError::Timeout
    } else {
        OutboundHttpError::ResponseBody
    }
}

fn record_request(policy: PolicyClass, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_outbound_http_requests_total",
        "policy" => policy.label(),
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "rsk_outbound_http_request_duration_seconds",
        "policy" => policy.label(),
        "result" => result,
    )
    .record(elapsed.as_secs_f64());
}

fn record_body(policy: PolicyClass, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_outbound_http_response_bodies_total",
        "policy" => policy.label(),
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "rsk_outbound_http_response_body_duration_seconds",
        "policy" => policy.label(),
        "result" => result,
    )
    .record(elapsed.as_secs_f64());
    tracing::debug!(
        policy = policy.label(),
        result,
        elapsed_ms = elapsed.as_millis(),
        "outbound HTTP response body completed"
    );
}
