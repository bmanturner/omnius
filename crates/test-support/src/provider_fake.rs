use std::{
    fmt, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
};

use thiserror::Error;
use url::Url;
use wiremock::MockServer;

pub use wiremock::matchers as provider_matchers;
pub use wiremock::{
    Mock as ProviderMock, MockGuard as ProviderMockGuard, Request as ProviderRequest,
    ResponseTemplate as ProviderResponse,
};

/// An isolated, request-recording HTTP provider fake bound to loopback.
///
/// Provider modules own their request and response semantics. This fixture owns
/// only the real HTTP lifecycle, origin-safe endpoint construction, matching,
/// recording, expectations, and deterministic failure injection supplied by
/// [`ProviderMock`] and [`ProviderResponse`].
pub struct ProviderFake {
    server: MockServer,
    base_url: Url,
}

impl ProviderFake {
    /// Starts a dedicated server on an OS-assigned IPv4 loopback port.
    ///
    /// Successful return is the readiness condition; no startup sleep or poll
    /// is required.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFakeError`] when crypto initialization, loopback
    /// binding, or URL construction fails.
    pub async fn start() -> Result<Self, ProviderFakeError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(ProviderFakeError::CryptoProvider);
        }
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .map_err(ProviderFakeError::Bind)?;
        let server = MockServer::builder().listener(listener).start().await;
        let base_url = Url::parse(&format!("{}/", server.uri())).map_err(ProviderFakeError::Url)?;
        Ok(Self { server, base_url })
    }

    /// Returns the loopback origin used to configure a provider client.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Returns the bound loopback socket address.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        *self.server.address()
    }

    /// Builds an origin-relative provider endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFakeError`] unless `path` begins with exactly one `/`
    /// and resolves within this fake's origin.
    pub fn endpoint(&self, path: &str) -> Result<Url, ProviderFakeError> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(ProviderFakeError::InvalidPath);
        }
        let endpoint = self.base_url.join(path).map_err(ProviderFakeError::Url)?;
        if endpoint.origin() != self.base_url.origin() {
            return Err(ProviderFakeError::InvalidPath);
        }
        Ok(endpoint)
    }

    /// Mounts a mock for the lifetime of this fake.
    ///
    /// Call-count expectations are verified when the fake is dropped.
    pub async fn mount(&self, provider_mock: ProviderMock) {
        provider_mock.mount(&self.server).await;
    }

    /// Mounts a mock whose expectations are verified when its guard is dropped.
    ///
    /// Scoped mocks are useful for deterministic multi-stage provider flows.
    pub async fn mount_scoped(&self, provider_mock: ProviderMock) -> ProviderMockGuard {
        provider_mock.mount_as_scoped(&self.server).await
    }

    /// Returns every request received by this fake in arrival order.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderFakeError::RecordingDisabled`] if Wiremock's recording
    /// policy is changed underneath this fixture.
    pub async fn requests(&self) -> Result<Vec<ProviderRequest>, ProviderFakeError> {
        self.server
            .received_requests()
            .await
            .ok_or(ProviderFakeError::RecordingDisabled)
    }
}

impl fmt::Debug for ProviderFake {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderFake")
            .field("address", &self.address())
            .finish_non_exhaustive()
    }
}

/// Failure to construct or use a provider HTTP fake.
#[derive(Debug, Error)]
pub enum ProviderFakeError {
    /// The approved rustls provider could not be installed.
    #[error("provider fake client crypto provider initialization failed")]
    CryptoProvider,
    /// The dedicated IPv4 loopback listener could not bind.
    #[error("provider fake loopback bind failed")]
    Bind(#[source] io::Error),
    /// A provider fake URL could not be represented.
    #[error("provider fake URL is invalid")]
    Url(#[source] url::ParseError),
    /// The endpoint was not an origin-relative absolute path.
    #[error("provider fake endpoint must start with exactly one slash")]
    InvalidPath,
    /// Request recording was disabled contrary to the fixture contract.
    #[error("provider fake request recording is disabled")]
    RecordingDisabled,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io::ErrorKind, time::Duration};

    use reqwest::{Client, StatusCode};

    use super::*;

    type TestResult = Result<(), Box<dyn Error>>;

    #[tokio::test]
    async fn provider_contract_records_success_and_preserves_unmatched_failure() -> TestResult {
        let fake = ProviderFake::start().await?;
        assert!(fake.address().ip().is_loopback());
        assert_ne!(fake.address().port(), 0);
        assert_eq!(
            fake.endpoint("/v1/events")?.origin(),
            fake.base_url().origin()
        );
        assert!(matches!(
            fake.endpoint("//example.invalid/events"),
            Err(ProviderFakeError::InvalidPath)
        ));

        fake.mount(
            ProviderMock::given(provider_matchers::method("POST"))
                .and(provider_matchers::path("/v1/events"))
                .and(provider_matchers::header(
                    "authorization",
                    "Bearer test-token",
                ))
                .and(provider_matchers::body_string(r#"{"event":"created"}"#))
                .respond_with(
                    ProviderResponse::new(202)
                        .insert_header("x-provider-request-id", "request-1")
                        .set_body_raw(r#"{"accepted":true}"#, "application/json"),
                )
                .expect(1)
                .named("provider event submission"),
        )
        .await;

        let client = Client::new();
        let response = client
            .post(fake.endpoint("/v1/events")?)
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(r#"{"event":"created"}"#)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            response.headers().get("x-provider-request-id"),
            Some(&reqwest::header::HeaderValue::from_static("request-1"))
        );
        assert_eq!(response.text().await?, r#"{"accepted":true}"#);

        let unmatched = client.get(fake.endpoint("/not-mounted")?).send().await?;
        assert_eq!(unmatched.status(), StatusCode::NOT_FOUND);

        let requests = fake.requests().await?;
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].method.as_str(), "POST");
        assert_eq!(requests[0].url.path(), "/v1/events");
        assert_eq!(requests[0].body, br#"{"event":"created"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn provider_contract_injects_rate_limit_latency_and_transport_failure() -> TestResult {
        let fake = ProviderFake::start().await?;
        fake.mount(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/slow"))
                .respond_with(ProviderResponse::new(200).set_delay(Duration::from_millis(100)))
                .expect(1),
        )
        .await;
        fake.mount(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/rate-limited"))
                .respond_with(ProviderResponse::new(429).insert_header("retry-after", "1"))
                .expect(1),
        )
        .await;
        fake.mount(
            ProviderMock::given(provider_matchers::method("GET"))
                .and(provider_matchers::path("/reset"))
                .respond_with_err(|_: &ProviderRequest| {
                    io::Error::new(ErrorKind::ConnectionReset, "injected connection reset")
                })
                .expect(1),
        )
        .await;

        let timeout_client = Client::builder()
            .timeout(Duration::from_millis(10))
            .build()?;
        let timeout = timeout_client.get(fake.endpoint("/slow")?).send().await;
        assert!(timeout.is_err_and(|error| error.is_timeout()));
        let rate_limited = Client::new()
            .get(fake.endpoint("/rate-limited")?)
            .send()
            .await?;
        assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            rate_limited.headers().get("retry-after"),
            Some(&reqwest::header::HeaderValue::from_static("1"))
        );

        let reset = Client::new().get(fake.endpoint("/reset")?).send().await;
        assert!(reset.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn provider_contract_instances_use_distinct_live_ports() -> TestResult {
        let first = ProviderFake::start().await?;
        let second = ProviderFake::start().await?;
        assert_ne!(first.address(), second.address());
        Ok(())
    }
}
