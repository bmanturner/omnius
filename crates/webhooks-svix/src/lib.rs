//! Thin, bounded outbound-webhook adapter over the pinned Svix 2.0.0 SDK.
//!
//! The crate forwards the transactional outbox's canonical raw JSON envelope with the leased event
//! ID as both Svix `eventId` and `idempotency-key`. It owns safe application/endpoint administration,
//! secret and token rotation, bounded delivery/replay status, cancellation/drain, health, metrics,
//! strict TLS/config values, and a deterministic fixed-capacity semantic fake.
//!
//! Svix remains responsible for signing, delivery scheduling, retries, history, and replay. A
//! required [`ReplayAdmission`] implementation durably owns cross-replica replay exclusion,
//! tenant budgets, cooldown, and task authorization across process restarts. The SDK is a
//! deliberate provider edge because 2.0.0 cannot accept `omnius-outbound-http`, cap response bodies,
//! separate connect timeouts, or fail closed on invalid proxy configuration. This crate does not
//! fake conformance: SDK retries are disabled, an outer total deadline is enforced, proxy config is
//! absent, and production composition must retain the central egress/SSRF controls.

#![forbid(unsafe_code)]

mod config;
mod error;
mod fake;
mod health;
mod port;
mod sdk;
mod value;

pub use config::SvixConfig;
pub use error::{
    ConfigError, FailureClass, FakeError, ProviderError, ProviderFailureFacts, ValueError,
    classify_provider_failure,
};
pub use fake::{CapturedPublish, FakeBehavior, FakeConfig, FakeWebhookProvider};
pub use health::svix_health_check;
pub use port::{ReplayAdmission, WebhookProvider};
pub use sdk::SvixWebhookProvider;
pub use value::{
    ApplicationId, ApplicationName, ApplicationRecord, ApplicationSpec, AttemptState,
    DeliveryAttempt, DeliveryStatus, Destination, EndpointDescription, EndpointId, EndpointRecord,
    EndpointSpec, EventType, IdempotencyKey, MessageId, ProviderOperation, PublishReceipt,
    PublishRequest, ReplayAdmissionRequest, ReplayCompletion, ReplayFingerprint, ReplayLease,
    ReplayLeaseId, ReplayMode, ReplayRequest, ReplayState, ReplayTask, ReplayTaskBinding,
    ReplayTaskId, ReplayWindow, SigningSecret, SvixToken,
};
