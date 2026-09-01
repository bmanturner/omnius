//! Strict raw-body verification, durable replay fencing, and asynchronous inbound webhook handling.
//!
//! The receive path is deliberately ordered: resource limits, exact bytes, provider verification
//! and timestamp, provider/scope/event digest fence, versioned parsing, durable receipt commit,
//! provider acknowledgement. Domain handlers run only from fenced PostgreSQL receipt leases.

#[path = "http.rs"]
mod axum_route;
mod composition;
mod config;
mod processor;
mod provider;
mod service;
mod store;

pub use axum_route::webhook_router;
pub use composition::{
    InboundWebhookAssembly, InboundWebhookAssemblyError, InboundWebhookContributions,
};
pub use config::{FixtureHmacProviderConfig, ProcessorConfig, WebhookConfig, WebhookConfigError};
pub use processor::{
    HandlerError, HandlerRegistry, HandlerRegistryError, HandlerRoute, ProcessorError,
    WebhookHandler, WebhookProcessor, processor_task,
};
pub use provider::{
    AcknowledgementDisposition, FixtureHmacSha256Adapter, FixtureSigningError, IdentifierError,
    ParseError, ParsedProviderEvent, ProviderAdapter, ProviderId, ProviderRegistry,
    ProviderResponse, RegistryError, VerificationError, VerifiedRequest, sign_fixture_request,
};
pub use service::{
    InboundWebhookService, RawWebhookRequest, ReceiveBuildError, ReceiveError, ReceiveLimits,
};
pub use store::{
    ClaimedReceipt, FailureClass, InvalidFailureClass, NewReceipt, PostgresReceiptStore, ReceiptId,
    ReceiptRepository, ReceiptStoreError, ReceiveDisposition,
};
