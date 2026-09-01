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
pub use ports::*;
pub use service::*;
pub use types::*;

#[cfg(test)]
mod tests;
