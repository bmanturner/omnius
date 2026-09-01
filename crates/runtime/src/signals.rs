//! Cross-platform process termination signal handling.

use std::io;

/// Receives interrupt and termination requests through one application-facing API.
#[cfg(unix)]
pub struct TerminationSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl TerminationSignals {
    /// Installs handlers for `SIGINT` and `SIGTERM`.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if either signal handler cannot be installed.
    pub fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    /// Waits for the next interrupt or termination request.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.interrupt.recv() => {}
            _ = self.terminate.recv() => {}
        }
    }
}

/// Receives the platform's Ctrl-C termination request.
#[cfg(not(unix))]
pub struct TerminationSignals;

#[cfg(not(unix))]
impl TerminationSignals {
    /// Installs the platform termination handler.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error if the platform termination handler cannot be installed.
    pub fn new() -> io::Result<Self> {
        Ok(Self)
    }

    /// Waits for the next termination request.
    pub async fn recv(&mut self) {
        let _ = tokio::signal::ctrl_c().await;
    }
}
