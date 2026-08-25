use thiserror::Error;

use crate::config::NatsConfigError;

/// Value-free durable-events provider error.
///
/// Provider SDK errors, server text, URLs, credentials, subjects, and payloads are deliberately not
/// retained, formatted, or exposed through this type.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsEventsError {
    /// Declarative configuration was rejected before network use.
    #[error("NATS events configuration is invalid")]
    Config,
    /// Connection or authentication failed.
    #[error("NATS events connection failed")]
    Connect,
    /// An explicitly requested administrative operation failed.
    #[error("NATS events provisioning failed")]
    Provision,
    /// Existing state cannot be changed safely without data loss or weaker retention.
    #[error("NATS events provisioning rejected unsafe drift")]
    UnsafeDrift,
    /// Runtime state does not exactly match the declaration.
    #[error("NATS events runtime verification failed")]
    Drift,
    /// Runtime credentials cannot perform a required operation.
    #[error("NATS events runtime access verification failed")]
    Access,
    /// A bounded event envelope was invalid or inconsistent.
    #[error("NATS event envelope is invalid")]
    InvalidEvent,
    /// A destination has no static route.
    #[error("NATS event destination is not configured")]
    UnknownDestination,
    /// `JetStream` publication or its acknowledgement failed.
    #[error("NATS event publication failed")]
    Publish,
    /// The server acknowledgement did not identify the declared stream.
    #[error("NATS event publication acknowledgement is invalid")]
    AckMismatch,
    /// A bounded pull request failed.
    #[error("NATS event delivery failed")]
    Fetch,
    /// Bounded shutdown or flush failed.
    #[error("NATS events shutdown failed")]
    Shutdown,
}

impl From<NatsConfigError> for NatsEventsError {
    fn from(_: NatsConfigError) -> Self {
        Self::Config
    }
}
