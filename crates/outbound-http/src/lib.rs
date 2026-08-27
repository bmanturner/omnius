//! Centralized outbound HTTP destination admission and bounded reusable clients.
//!
//! URLs are admitted before request construction, resolved addresses are checked again at the
//! reqwest connect boundary, redirects are followed manually, and decoded bodies are bounded.

mod policy;

use std::{
    collections::HashSet,
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use policy::ValidatingResolver;
pub use policy::{
    ApprovedUrl, OutboundUrlPolicy, OutboundUrlPolicyConfig, Resolver, ResolverError,
    ResolverFuture, SystemResolver,
};
use reqwest::{
    Client, Request, RequestBuilder, Response,
    header::{
        AUTHORIZATION, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, COOKIE, HOST,
        HeaderMap, HeaderName, HeaderValue, LOCATION, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE,
        TRAILER, TRANSFER_ENCODING, UPGRADE, WWW_AUTHENTICATE,
    },
};
pub use reqwest::{Method, StatusCode, Url};
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
    /// Central destination-admission policy.
    pub url_policy: OutboundUrlPolicyConfig,
}

impl Default for OutboundHttpConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(30),
            response_body_limit_bytes: 2 * 1024 * 1024,
            max_redirects: 5,
            proxy: ProxyPolicy::Disabled,
            user_agent: concat!("omnius-outbound-http/", env!("CARGO_PKG_VERSION")).to_owned(),
            url_policy: OutboundUrlPolicyConfig::default(),
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
            .field("url_policy", &self.url_policy)
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
        if !matches!(self.proxy, ProxyPolicy::Disabled) {
            return Err(ConfigError::ProxyUnsupported);
        }
        self.url_policy.validate()
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
    /// Proxy routing cannot preserve resolver-to-connect enforcement.
    #[error("outbound HTTP proxy configuration is unsupported by the destination policy")]
    ProxyUnsupported,
    /// The HTTPS port allowlist is empty, duplicated, excessive, or contains port zero.
    #[error("outbound HTTPS port policy is invalid")]
    HttpsPorts,
    /// A configured deployment-internal CIDR is invalid, duplicated, or excessive.
    #[error("outbound HTTP configured deny CIDRs are invalid")]
    DenyCidrs,
    /// The per-lookup DNS timeout is zero or above its fixed maximum.
    #[error("outbound HTTP DNS timeout is outside its allowed range")]
    DnsTimeout,
    /// The unique DNS answer cap is zero or above its fixed maximum.
    #[error("outbound HTTP DNS answer limit is outside its allowed range")]
    DnsAnswers,
    /// The async resolver could not load system DNS configuration.
    #[error("outbound HTTP system DNS resolver is unavailable")]
    SystemResolver,
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
    /// The explicit ring-backed rustls configuration could not select safe protocols.
    #[error("outbound HTTP rustls configuration is unavailable")]
    TlsConfiguration,
    /// The async resolver could not load system DNS configuration.
    #[error("outbound HTTP system DNS resolver is unavailable")]
    Resolver,
    /// Reqwest rejected the reusable client without retaining configuration details.
    #[error("failed to build outbound HTTP client")]
    Client,
}

/// Reusable client with one centralized destination policy.
#[derive(Clone)]
pub struct OutboundHttpClients {
    client: Client,
    url_policy: OutboundUrlPolicy,
    response_body_limit_bytes: usize,
    total_timeout: Duration,
    max_redirects: usize,
}

impl fmt::Debug for OutboundHttpClients {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundHttpClients")
            .field("response_body_limit_bytes", &self.response_body_limit_bytes)
            .field("total_timeout", &self.total_timeout)
            .field("max_redirects", &self.max_redirects)
            .finish_non_exhaustive()
    }
}

impl OutboundHttpClients {
    /// Builds one reusable client with the bounded system resolver.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when configuration, TLS, or reqwest construction fails.
    pub fn new(config: &OutboundHttpConfig) -> Result<Self, BuildError> {
        config.validate()?;
        let resolver = SystemResolver::new().map_err(|_| BuildError::Resolver)?;
        Self::with_resolver(config, Arc::new(resolver))
    }

    /// Builds one reusable client with an injected deterministic resolver.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] when configuration, TLS, or reqwest construction fails.
    pub fn with_resolver(
        config: &OutboundHttpConfig,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, BuildError> {
        config.validate()?;
        ensure_crypto_provider()?;
        let url_policy =
            OutboundUrlPolicy::with_resolver(config.url_policy.clone(), Arc::clone(&resolver))?;
        let validating_resolver = url_policy.validating_resolver(resolver);
        let client = build_client(config, validating_resolver)?;
        Ok(Self {
            client,
            url_policy,
            response_body_limit_bytes: config.response_body_limit_bytes,
            total_timeout: config.total_timeout,
            max_redirects: config.max_redirects,
        })
    }

    /// Admits a URL under the exact policy enforced by this client's connect-time resolver.
    ///
    /// # Errors
    ///
    /// Returns a value-free policy or resolution failure.
    pub async fn approve(&self, url: Url) -> Result<ApprovedUrl, OutboundHttpError> {
        self.url_policy.approve(url).await
    }

    /// Starts an opaque request from an already approved URL.
    #[must_use]
    pub fn request(
        &self,
        policy: PolicyClass,
        method: Method,
        url: &ApprovedUrl,
    ) -> OutboundRequestBuilder {
        OutboundRequestBuilder {
            policy,
            inner: self.client.request(method, url.as_url().clone()),
            invalid_header: false,
            invalid_destination: !url.belongs_to(&self.url_policy),
        }
    }

    /// Executes an opaque request, manually following policy-approved redirects.
    ///
    /// # Errors
    ///
    /// Returns a value-free destination, redirect, timeout, or transport failure.
    pub async fn execute(
        &self,
        request: OutboundRequest,
    ) -> Result<OutboundResponse, OutboundHttpError> {
        let started = Instant::now();
        let policy = request.policy;
        let result = self.execute_redirect_chain(request, started).await;
        let elapsed = started.elapsed();
        let outcome = result
            .as_ref()
            .map_or_else(|error| error.label(), |_| "response");
        record_request(policy, outcome, elapsed);
        tracing::debug!(
            policy = policy.label(),
            outcome,
            elapsed_ms = elapsed.as_millis(),
            "outbound HTTP request completed"
        );
        result.map(|inner| OutboundResponse { policy, inner })
    }

    async fn execute_redirect_chain(
        &self,
        request: OutboundRequest,
        started: Instant,
    ) -> Result<Response, OutboundHttpError> {
        let OutboundRequest {
            policy,
            inner: mut request,
        } = request;
        let mut visited = HashSet::with_capacity(self.max_redirects + 1);
        visited.insert(request.url().clone());
        let mut redirects = 0_usize;
        loop {
            *request.timeout_mut() = Some(self.remaining(started)?);
            let original_url = request.url().clone();
            let original_method = request.method().clone();
            let original_headers = request.headers().clone();
            let replay = request.try_clone();
            let mut response = self
                .client
                .execute(request)
                .await
                .map_err(|error| map_reqwest_request_error(&error))?;
            if policy == PolicyClass::NoRedirect || !response.status().is_redirection() {
                return Ok(response);
            }
            if redirects >= self.max_redirects {
                return Err(OutboundHttpError::RedirectLimit);
            }
            let location = response
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok())
                .filter(|value| value.len() <= 8 * 1024)
                .ok_or(OutboundHttpError::RedirectRejected)?;
            let next_url = response
                .url()
                .join(location)
                .map_err(|_| OutboundHttpError::RedirectRejected)?;
            let approved =
                tokio::time::timeout(self.remaining(started)?, self.url_policy.approve(next_url))
                    .await
                    .map_err(|_| OutboundHttpError::Timeout)??;
            if !visited.insert(approved.as_url().clone()) {
                return Err(OutboundHttpError::RedirectLoop);
            }
            self.remaining(started)?;
            drain_response(&mut response, self.response_body_limit_bytes).await?;
            self.remaining(started)?;
            let next_method = redirected_method(response.status(), &original_method);
            let retain_body = next_method == original_method;
            let mut next_request = if retain_body {
                replay.ok_or(OutboundHttpError::NonReplayableRedirect)?
            } else {
                let mut request = Request::new(next_method, approved.as_url().clone());
                *request.headers_mut() = original_headers;
                remove_entity_headers(request.headers_mut());
                request
            };
            *next_request.url_mut() = approved.as_url().clone();
            remove_hop_by_hop_headers(next_request.headers_mut());
            if !same_origin(&original_url, approved.as_url()) {
                remove_sensitive_headers(next_request.headers_mut());
            }
            request = next_request;
            redirects += 1;
        }
    }

    fn remaining(&self, started: Instant) -> Result<Duration, OutboundHttpError> {
        self.total_timeout
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(OutboundHttpError::Timeout)
    }

    /// Consumes a response in chunks and aborts before the configured decoded-byte cap.
    ///
    /// # Errors
    ///
    /// Returns a value-free timeout, body-stream, or size-limit failure.
    pub async fn read_body(
        &self,
        response: OutboundResponse,
    ) -> Result<Vec<u8>, OutboundHttpError> {
        Self::read_body_with_limit(response, self.response_body_limit_bytes).await
    }

    async fn read_body_with_limit(
        mut response: OutboundResponse,
        limit: usize,
    ) -> Result<Vec<u8>, OutboundHttpError> {
        let started = Instant::now();
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
                Ok(Some(chunk)) if chunk.len() <= limit - body.len() => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) => {
                    let error = OutboundHttpError::ResponseTooLarge;
                    record_body(response.policy, error.label(), started.elapsed());
                    return Err(error);
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

    /// Executes a request and returns status, headers, and a bounded decoded body.
    ///
    /// # Errors
    ///
    /// Returns a value-free admission, transport, redirect, timeout, body, or size-limit failure.
    pub async fn execute_bounded(
        &self,
        request: OutboundRequest,
    ) -> Result<BoundedResponse, OutboundHttpError> {
        self.execute_bounded_with_limit(request, self.response_body_limit_bytes)
            .await
    }

    /// Executes with a caller cap no greater than the configured cap.
    ///
    /// # Errors
    ///
    /// Returns [`OutboundHttpError::InvalidResponseBodyLimit`] for a zero caller cap, or a
    /// value-free admission, transport, redirect, timeout, body, or size-limit failure.
    pub async fn execute_bounded_with_limit(
        &self,
        request: OutboundRequest,
        max_bytes: usize,
    ) -> Result<BoundedResponse, OutboundHttpError> {
        if max_bytes == 0 {
            return Err(OutboundHttpError::InvalidResponseBodyLimit);
        }
        let response = self.execute(request).await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body =
            Self::read_body_with_limit(response, max_bytes.min(self.response_body_limit_bytes))
                .await?;
        Ok(BoundedResponse {
            status,
            headers,
            body,
        })
    }

    /// Returns the configured decoded-response cap.
    #[must_use]
    pub const fn response_body_limit_bytes(&self) -> usize {
        self.response_body_limit_bytes
    }
}

fn redirected_method(status: StatusCode, method: &Method) -> Method {
    match status {
        StatusCode::MOVED_PERMANENTLY | StatusCode::FOUND if method == Method::POST => Method::GET,
        StatusCode::SEE_OTHER if method != Method::HEAD => Method::GET,
        _ => method.clone(),
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn remove_entity_headers(headers: &mut HeaderMap) {
    for name in [
        CONTENT_ENCODING,
        CONTENT_LENGTH,
        CONTENT_TYPE,
        TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
}

fn remove_hop_by_hop_headers(headers: &mut HeaderMap) {
    let mut nominated = Vec::new();
    for value in headers.get_all(CONNECTION) {
        let Ok(value) = value.to_str() else {
            continue;
        };
        for token in value.split(',') {
            if let Ok(name) = HeaderName::from_bytes(token.trim().as_bytes()) {
                nominated.push(name);
            }
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        HOST,
        PROXY_AUTHENTICATE,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
    for name in ["keep-alive", "proxy-connection"] {
        headers.remove(name);
    }
}

fn remove_sensitive_headers(headers: &mut HeaderMap) {
    for name in [AUTHORIZATION, COOKIE, PROXY_AUTHORIZATION, WWW_AUTHENTICATE] {
        headers.remove(name);
    }
    let internal = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name == "cookie2"
                || name == "x-api-key"
                || name == "x-auth-token"
                || name.starts_with("x-internal-")
                || name.starts_with("x-omnius-internal-")
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in internal {
        headers.remove(name);
    }
}

async fn drain_response(response: &mut Response, limit: usize) -> Result<(), OutboundHttpError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(OutboundHttpError::ResponseTooLarge);
    }
    let mut received = 0_usize;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                received = received
                    .checked_add(chunk.len())
                    .filter(|received| *received <= limit)
                    .ok_or(OutboundHttpError::ResponseTooLarge)?;
            }
            Ok(None) => return Ok(()),
            Err(error) => return Err(map_reqwest_body_error(&error)),
        }
    }
}

fn ensure_crypto_provider() -> Result<(), BuildError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(BuildError::CryptoProvider);
    }
    Ok(())
}

fn embedded_root_store() -> rustls::RootCertStore {
    rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

fn rustls_client_config() -> Result<rustls::ClientConfig, BuildError> {
    rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| BuildError::TlsConfiguration)
        .map(|builder| {
            builder
                .with_root_certificates(embedded_root_store())
                .with_no_client_auth()
        })
}

fn build_client(
    config: &OutboundHttpConfig,
    resolver: ValidatingResolver,
) -> Result<Client, BuildError> {
    Client::builder()
        .use_preconfigured_tls(rustls_client_config()?)
        .connect_timeout(config.connect_timeout)
        .timeout(config.total_timeout)
        .user_agent(&config.user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .dns_resolver(resolver)
        .build()
        .map_err(|_| BuildError::Client)
}

/// Opaque builder for a request that can only execute through [`OutboundHttpClients`].
pub struct OutboundRequestBuilder {
    policy: PolicyClass,
    inner: RequestBuilder,
    invalid_header: bool,
    invalid_destination: bool,
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
        if self.invalid_destination {
            return Err(OutboundHttpError::DestinationRejected);
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

/// Opaque built request accepted by [`OutboundHttpClients::execute`],
/// [`OutboundHttpClients::execute_bounded`], and
/// [`OutboundHttpClients::execute_bounded_with_limit`].
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

/// Status and bytes returned by [`OutboundHttpClients::execute_bounded`] or
/// [`OutboundHttpClients::execute_bounded_with_limit`].
#[derive(Clone, Eq, PartialEq)]
pub struct BoundedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
}

impl BoundedResponse {
    /// Returns the HTTP status.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        self.status
    }

    /// Borrows response headers.
    #[must_use]
    pub const fn headers(&self) -> &HeaderMap {
        &self.headers
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
            .field("header_count", &self.headers.len())
            .field("body_length", &self.body.len())
            .finish()
    }
}

/// Safe, value-free request, admission, redirect, or response-consumption failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum OutboundHttpError {
    /// A request header, query, or body could not be built.
    #[error("outbound HTTP request could not be built")]
    RequestBuild,
    /// URL syntax, authority, scheme, port, or resolved addresses were rejected.
    #[error("outbound HTTP destination was rejected")]
    DestinationRejected,
    /// DNS resolution failed or returned no usable complete answer set.
    #[error("outbound HTTP destination resolution failed")]
    Resolution,
    /// A redirect was malformed or did not provide a valid location.
    #[error("outbound HTTP redirect was rejected")]
    RedirectRejected,
    /// The redirect limit was reached.
    #[error("outbound HTTP redirect limit was reached")]
    RedirectLimit,
    /// A redirect repeated a previously visited URL.
    #[error("outbound HTTP redirect loop was rejected")]
    RedirectLoop,
    /// A redirect required replaying a streaming body.
    #[error("outbound HTTP redirect required a non-replayable body")]
    NonReplayableRedirect,
    /// The configured request deadline expired.
    #[error("outbound HTTP request timed out")]
    Timeout,
    /// The request failed before a response was available.
    #[error("outbound HTTP transport failed")]
    Transport,
    /// The response body stream failed.
    #[error("outbound HTTP response body failed")]
    ResponseBody,
    /// A caller-provided response-body cap was zero.
    #[error("outbound HTTP response body limit must be greater than zero")]
    InvalidResponseBodyLimit,
    /// The decoded response body exceeded the configured cap.
    #[error("outbound HTTP response body exceeded its configured limit")]
    ResponseTooLarge,
}

impl OutboundHttpError {
    const fn label(self) -> &'static str {
        match self {
            Self::RequestBuild => "request_build_error",
            Self::DestinationRejected => "destination_rejected",
            Self::Resolution => "resolution_error",
            Self::RedirectRejected => "redirect_rejected",
            Self::RedirectLimit => "redirect_limit",
            Self::RedirectLoop => "redirect_loop",
            Self::NonReplayableRedirect => "non_replayable_redirect",
            Self::Timeout => "timeout",
            Self::Transport => "transport_error",
            Self::ResponseBody => "body_error",
            Self::InvalidResponseBodyLimit => "invalid_body_limit",
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
        "omnius_outbound_http_requests_total",
        "policy" => policy.label(),
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_outbound_http_request_duration_seconds",
        "policy" => policy.label(),
        "result" => result,
    )
    .record(elapsed.as_secs_f64());
}

fn record_body(policy: PolicyClass, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "omnius_outbound_http_response_bodies_total",
        "policy" => policy.label(),
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_outbound_http_response_body_duration_seconds",
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
