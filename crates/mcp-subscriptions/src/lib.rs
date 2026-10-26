//! Authorized, transport-neutral MCP task subscriptions.
//!
//! The crate carries only complete task snapshots and task replay-gap controls. Ordinary request
//! progress and messages are intentionally unrepresentable. Durable claims, authoritative task
//! snapshots, replay, authorization, runtime expiry, and response delivery remain typed ports so
//! MCP core, transports, and the Tasks extension can integrate without importing wire types here.

#![forbid(unsafe_code)]

mod adapter;
mod backplane;
mod delivery;
mod ports;
mod service;
mod types;

pub use adapter::{
    BoundTaskSubscriptionFrameSink, TASK_SUBSCRIPTION_REQUEST_META_KEY,
    TaskSubscriptionBridgeFrame, TaskSubscriptionDrainHandle, TaskSubscriptionFrameSink,
    TaskSubscriptionFrameSinkError, TaskSubscriptionRmcpAdapter,
};
pub use backplane::{
    BackplaneAdapterError, BackplaneWireLimits, LocalTaskBackplane, NatsCoreTaskBackplane,
    RedisTaskBackplane,
};
pub use delivery::{BoundedDeliveryQueue, DeliveryStream};
pub use ports::{
    AuthorizationAction, AuthorizationCheck, AuthorizationError, BackplaneError,
    BackplaneGuarantee, BackplaneHint, BackplaneKind, BackplaneReceiver, BackplaneRecord,
    BackplaneRegistration, BackplaneSelectionError, BeginSubscription, BeginSubscriptionResult,
    DeliveryAdmission, DeliveryAttachmentSignal, DeliveryAttachmentState, DeliveryCloseMode,
    DeliveryDisconnectSignal, DeliveryError, DeliveryLimits, DeliveryOpen, FinishSubscription,
    ReplayResult, ReplayWindow, RepositoryError, RuntimeError, RuntimeLease, SelectedBackplane,
    SelectedBackplaneParts, SelectedBackplaneReceiver, SubscriptionAuthorizer,
    SubscriptionCheckpoint, SubscriptionDelivery, SubscriptionRepository, SubscriptionRuntime,
    TaskSubscriptionBackplane,
};
pub use service::{
    ExpireOutcome, SubscriptionConfig, SubscriptionError, SubscriptionLease, TASKS_EXTENSION_ID,
    TASKS_EXTENSION_REVISION, TaskSubscriptionService, tasks_extension_negotiated,
};
pub use types::{
    CloseReason, ConfidentialStatusMessage, DeliveryFrame, DrainOutcome, EventPosition,
    IdempotencyKey, PrincipalId, PublicStatusMessage, ReconnectProof, ReplayGap, ReplayGapReason,
    RequestedEventClass, SubscribeRequest, SubscriptionAcknowledgement, SubscriptionClosed,
    SubscriptionHandle, SubscriptionId, SubscriptionStart, TaskCursor, TaskHandle, TaskId,
    TaskReconnectHandles, TaskSnapshot, TaskSnapshotData, TaskStatus, TenantId, ValueError,
};

#[cfg(test)]
mod tests;
