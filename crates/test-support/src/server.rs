use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use axum::Router;
use reqwest::{Client, Response};
use thiserror::Error;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use url::Url;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// A real HTTP client restricted to one loopback test server.
#[derive(Clone, Debug)]
pub struct TestClient {
    base_url: Url,
    inner: Client,
}

impl TestClient {
    /// Returns the loopback origin used by this client.
    #[must_use]
    pub const fn base_url(&self) -> &Url {
        &self.base_url
    }

    /// Sends a GET request through the real HTTP transport.
    ///
    /// # Errors
    ///
    /// Returns [`TestServerError`] for a malformed route path or transport
    /// failure. Paths must start with one `/` and cannot replace the origin.
    pub async fn get(&self, path: &str) -> Result<Response, TestServerError> {
        let url = self.route_url(path)?;
        self.inner
            .get(url)
            .send()
            .await
            .map_err(TestServerError::Client)
    }

    fn route_url(&self, path: &str) -> Result<Url, TestServerError> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(TestServerError::InvalidPath);
        }
        let url = self.base_url.join(path).map_err(TestServerError::Url)?;
        if url.origin() != self.base_url.origin() {
            return Err(TestServerError::InvalidPath);
        }
        Ok(url)
    }
}

/// A bound loopback Axum server and its restricted client.
#[derive(Debug)]
pub struct TestServer {
    address: SocketAddr,
    client: TestClient,
    draining: CancellationToken,
    task: Option<JoinHandle<io::Result<()>>>,
}

impl TestServer {
    /// Binds an ephemeral loopback port before returning and starts Axum.
    ///
    /// A successful return is the readiness condition; callers never need a
    /// startup sleep or polling loop.
    ///
    /// # Errors
    ///
    /// Returns [`TestServerError`] if the listener, URL, or client cannot be
    /// constructed.
    pub async fn spawn(app: Router) -> Result<Self, TestServerError> {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .map_err(TestServerError::Bind)?;
        let address = listener.local_addr().map_err(TestServerError::Bind)?;
        let base_url = Url::parse(&format!("http://{address}/")).map_err(TestServerError::Url)?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(TestServerError::CryptoProvider);
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(TestServerError::Client)?;
        let draining = CancellationToken::new();
        let graceful = draining.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    graceful.cancelled().await;
                })
                .await
        });
        Ok(Self {
            address,
            client: TestClient {
                base_url,
                inner: client,
            },
            draining,
            task: Some(task),
        })
    }

    /// Returns the bound loopback socket address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the origin-restricted real HTTP client.
    #[must_use]
    pub const fn client(&self) -> &TestClient {
        &self.client
    }

    /// Requests graceful shutdown and waits under the harness deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TestServerError`] when serving fails, the task panics, or the
    /// bounded shutdown deadline expires.
    pub async fn shutdown(mut self) -> Result<(), TestServerError> {
        self.draining.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match tokio::time::timeout(SHUTDOWN_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(source))) => Err(TestServerError::Serve(source)),
            Ok(Err(error)) => Err(TestServerError::Join {
                cancelled: error.is_cancelled(),
                panicked: error.is_panic(),
            }),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(TestServerError::ShutdownTimeout)
            }
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.draining.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Failure to construct, use, or stop a loopback test server.
#[derive(Debug, Error)]
pub enum TestServerError {
    /// The approved rustls provider could not be installed.
    #[error("test client rustls provider initialization failed")]
    CryptoProvider,
    /// The loopback listener could not bind or report its address.
    #[error("test server loopback bind failed")]
    Bind(#[source] io::Error),
    /// A loopback URL could not be constructed.
    #[error("test server URL is invalid")]
    Url(#[source] url::ParseError),
    /// The client route was not an origin-relative absolute path.
    #[error("test client path must start with exactly one slash")]
    InvalidPath,
    /// The real HTTP client could not be built or complete a request.
    #[error("test client request failed")]
    Client(#[source] reqwest::Error),
    /// Axum stopped with a listener error.
    #[error("test server failed while serving")]
    Serve(#[source] io::Error),
    /// The server task was cancelled or panicked unexpectedly.
    #[error("test server task failed (cancelled={cancelled}, panicked={panicked})")]
    Join {
        /// Whether Tokio reported cancellation.
        cancelled: bool,
        /// Whether Tokio reported a panic.
        panicked: bool,
    },
    /// Graceful shutdown exceeded the bounded harness deadline.
    #[error("test server shutdown deadline exceeded")]
    ShutdownTimeout,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[tokio::test]
    async fn bound_listener_is_immediately_ready_for_real_client_requests()
    -> Result<(), Box<dyn std::error::Error>> {
        let app = Router::new().route("/ready", get(|| async { "ready" }));
        let server = TestServer::spawn(app).await?;

        assert!(server.address().ip().is_loopback());
        let response = server.client().get("/ready").await?;
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await?, "ready");
        server.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn client_cannot_replace_the_loopback_origin() -> Result<(), Box<dyn std::error::Error>> {
        let server = TestServer::spawn(Router::new()).await?;
        assert!(matches!(
            server.client().get("//example.invalid/path").await,
            Err(TestServerError::InvalidPath)
        ));
        let scheme_like = server.client().route_url("/https://example.invalid/path")?;
        assert_eq!(scheme_like.origin(), server.client().base_url().origin());
        server.shutdown().await?;
        Ok(())
    }
}
