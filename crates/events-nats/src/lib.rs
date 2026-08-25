//! Durable NATS `JetStream` domain events and ephemeral Core NATS fan-out.
//!
//! Resource administration is intentionally separated from runtime connection. Durable publishing
//! reuses [`rsk_outbox::OutboxPublisher`]. Core NATS fan-out owns no stream, acknowledgement,
//! cursor, or replay state and retains only bounded opaque bytes in local ingress.
//!
//! All public errors and lifecycle status are value-free and never retain broker text, URLs,
//! credentials, subjects, payloads, or tenant information.

#![forbid(unsafe_code)]

mod config;
mod connection;
mod error;
mod event;
mod fanout;
mod provision;
mod publisher;
mod resource;
mod runtime;
mod verification;

pub use config::{
    NatsAuthConfig, NatsConfigError, NatsConnectionConfig, NatsConsumerConfig,
    NatsCoreFanoutConfig, NatsCoreFanoutConfigError, NatsDeliveryConfig, NatsDiscardPolicy,
    NatsDlqConfig, NatsEventsConfig, NatsRestartConfig, NatsRetentionPolicy, NatsStorage,
    NatsStreamConfig,
};
pub use error::NatsEventsError;
pub use event::RawEvent;
pub use fanout::{
    NatsCoreFanout, NatsCoreFanoutError, NatsCoreFanoutLifecycle, NatsCoreFanoutMessage,
    NatsCoreFanoutPublishError, NatsCoreFanoutPublisher, NatsCoreFanoutReceiver,
    NatsCoreFanoutStatus, NatsCoreFanoutStatusError,
};
pub use provision::{NatsJetStreamProvisioner, ProvisioningReport};
pub use publisher::NatsOutboxPublisher;
pub use runtime::{
    ConsumerStatus, DeliveryContext, EventHandler, HandlerOutcome, NatsJetStreamEvents,
};

/// Stable metrics prefix for this provider.
pub const METRICS_PREFIX: &str = "rsk_events_nats";
/// Stable required supervisor task name.
pub const CONSUMER_TASK_NAME: &str = "nats-consumers";
/// Stable dependency health-check name.
pub const HEALTH_CHECK_NAME: &str = "nats-jetstream";
/// Stable degraded supervisor task name for the ephemeral Core NATS listener.
pub const CORE_FANOUT_TASK_NAME: &str = "nats-core-fanout-listener";
