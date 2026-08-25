//! Durable NATS `JetStream` domain events with explicit provisioning and verified runtime access.
//!
//! Resource administration is intentionally separated from runtime connection. Publishing reuses
//! [`rsk_outbox::OutboxPublisher`], while durable pull delivery acknowledges only after a handler's
//! durable effect or a confirmed DLQ publication. All public errors are value-free and never retain
//! broker text, URLs, credentials, subjects, or payloads.

#![forbid(unsafe_code)]

mod config;
mod connection;
mod error;
mod event;
mod provision;
mod publisher;
mod resource;
mod runtime;
mod verification;

pub use config::{
    NatsAuthConfig, NatsConfigError, NatsConnectionConfig, NatsConsumerConfig, NatsDeliveryConfig,
    NatsDiscardPolicy, NatsDlqConfig, NatsEventsConfig, NatsRestartConfig, NatsRetentionPolicy,
    NatsStorage, NatsStreamConfig,
};
pub use error::NatsEventsError;
pub use event::RawEvent;
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
