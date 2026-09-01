//! Generic Hyper listener and graceful connection-drain support.

use std::{io, net::SocketAddr, time::Duration};

use axum::{Extension, Router, extract::ConnectInfo};
use hyper::server::conn::http1;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder as AutoBuilder,
    service::TowerToHyperService,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinError, JoinSet},
};
use tokio_util::sync::CancellationToken;

type ConnectionError = Box<dyn std::error::Error + Send + Sync>;

/// Selects the protocol and upgrade behavior for accepted connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionMode {
    /// Serve HTTP/1 without protocol upgrades.
    Http1,
    /// Negotiate HTTP/1 or HTTP/2 and support HTTP upgrades.
    AutoWithUpgrades,
}

/// Selects whether the peer socket address is exposed through Axum request extensions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAddressMode {
    /// Do not add peer address request metadata.
    None,
    /// Add `ConnectInfo<SocketAddr>` to every request.
    ConnectInfo,
}

/// Configuration for the generic HTTP listener.
#[derive(Clone, Copy, Debug)]
pub struct HttpServerConfig {
    /// Maximum time allowed to receive HTTP/1 request headers.
    pub header_read_timeout: Duration,
    /// Protocol and upgrade behavior for each connection.
    pub connection_mode: ConnectionMode,
    /// Peer address metadata exposed to request handlers.
    pub peer_address_mode: PeerAddressMode,
}

/// Synchronous handle that stops new accepts and gracefully drains active connections.
#[derive(Clone)]
pub struct HttpDrainHandle {
    draining: CancellationToken,
}

impl HttpDrainHandle {
    /// Stops accepting new connections and asks active connections to finish gracefully.
    pub fn begin_drain(&self) {
        self.draining.cancel();
    }

    /// Returns whether draining has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.is_cancelled()
    }
}

/// Bound HTTP listener with explicit connection and peer-address behavior.
pub struct HttpServer {
    listener: TcpListener,
    app: Router,
    config: HttpServerConfig,
    drain: HttpDrainHandle,
}

impl HttpServer {
    /// Binds a listener and prepares the HTTP server without accepting traffic yet.
    pub async fn bind(
        listen_address: SocketAddr,
        app: Router,
        config: HttpServerConfig,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(listen_address).await?;
        Ok(Self {
            listener,
            app,
            config,
            drain: HttpDrainHandle {
                draining: CancellationToken::new(),
            },
        })
    }

    /// Returns the address assigned to the bound listener.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Returns a handle that can begin graceful HTTP draining.
    #[must_use]
    pub fn drain_handle(&self) -> HttpDrainHandle {
        self.drain.clone()
    }

    /// Accepts connections until draining begins, then awaits every active connection.
    pub async fn serve(self) -> io::Result<()> {
        let Self {
            listener,
            app,
            config,
            drain,
        } = self;
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                () = drain.draining.cancelled() => break,
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    observe_connection(result);
                }
                accepted = listener.accept() => {
                    let (stream, peer_address) = accepted?;
                    connections.spawn(serve_connection(
                        stream,
                        peer_address,
                        app.clone(),
                        config,
                        drain.draining.clone(),
                    ));
                }
            }
        }
        drop(listener);
        while let Some(result) = connections.join_next().await {
            observe_connection(result);
        }
        Ok(())
    }
}

async fn serve_connection(
    stream: TcpStream,
    peer_address: SocketAddr,
    app: Router,
    config: HttpServerConfig,
    draining: CancellationToken,
) -> Result<(), ConnectionError> {
    let app = match config.peer_address_mode {
        PeerAddressMode::None => app,
        PeerAddressMode::ConnectInfo => app.layer(Extension(ConnectInfo(peer_address))),
    };
    match config.connection_mode {
        ConnectionMode::Http1 => {
            serve_http1_connection(stream, app, config.header_read_timeout, draining).await
        }
        ConnectionMode::AutoWithUpgrades => {
            serve_auto_connection(stream, app, config.header_read_timeout, draining).await
        }
    }
}

async fn serve_http1_connection(
    stream: TcpStream,
    app: Router,
    header_read_timeout: Duration,
    draining: CancellationToken,
) -> Result<(), ConnectionError> {
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let connection = builder.serve_connection(TokioIo::new(stream), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result?,
        () = draining.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await?;
        }
    }
    Ok(())
}

async fn serve_auto_connection(
    stream: TcpStream,
    app: Router,
    header_read_timeout: Duration,
    draining: CancellationToken,
) -> Result<(), ConnectionError> {
    let mut builder = AutoBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let connection =
        builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(app));
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result?,
        () = draining.cancelled() => {
            connection.as_mut().graceful_shutdown();
            connection.await?;
        }
    }
    Ok(())
}

fn observe_connection(result: Result<Result<(), ConnectionError>, JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => tracing::debug!("HTTP connection ended with a protocol error"),
        Err(error) => tracing::error!(
            cancelled = error.is_cancelled(),
            panicked = error.is_panic(),
            "HTTP connection task failed"
        ),
    }
}
