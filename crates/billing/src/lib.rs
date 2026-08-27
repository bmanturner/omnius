//! Provider-preserving billing mirrors and entitlement reconciliation.
//!
//! The crate deliberately does not expose a universal Stripe-like API. An exact
//! [`BillingProviderAdapter`] owns provider event ordering, API revision, usage idempotency, and
//! state translation. Raw request signature/timestamp/replay verification stays in
//! `omnius-webhooks-inbound`; [`BillingReconciler`] implements its asynchronous [`WebhookHandler`]
//! contract over already verified durable receipts.
//!
//! PostgreSQL is authoritative for local customer, subscription, invoice, plan, entitlement, and
//! usage facts. Effective entitlement reads require an authoritative `omnius-tenancy::TenantContext`
//! and never call a provider. They change only after a complete provider API snapshot commits under
//! a monotonic revision and live reconciliation lease. The same transaction appends audit and
//! outbox intent. Provider-event identity/sequence, snapshot revision/fingerprint, usage
//! idempotency, and lease-token invariants are also enforced by migration constraints.
//!
//! [`FakeBillingAdapter`] has an exact documented schema only for contract tests. This crate
//! contains no Stripe facade because no Stripe-specific semantics or ADR are implemented here.

#![forbid(unsafe_code)]

mod config;
mod job;
mod provider;
mod service;
mod store;
mod types;

pub use config::{BillingConfig, BillingConfigError};
pub use job::{
    ReconcileBillingJob, ReconcileBillingJobHandler, RedriveBillingUsageJob,
    RedriveBillingUsageJobHandler,
};
pub use provider::{
    BillingProviderAdapter, FakeBillingAdapter, ProviderAdapterError, ProviderFailureClass,
    ProviderUsageRequest, UsageAcknowledgement,
};
pub use service::{BILLING_RECOVERY_TASK_NAME, BillingReconciler, BillingServiceError};
pub use store::{
    BillingStoreError, ClaimedReconciliation, ClaimedUsage, EntitlementsReconciled,
    EventEnqueueOutcome, PostgresBillingStore, RepairEnqueueOutcome, SnapshotApplyOutcome,
    UsageCompletionOutcome, UsageRecordOutcome, UsageRecordState,
};
pub use types::{
    BillingStanding, BillingValueError, CurrencyCode, DunningFacts, EffectiveEntitlement,
    EntitlementGrant, EntitlementKey, EntitlementValue, MeterKey, NewUsageRecord, PlanDefinition,
    PlanKey, ProviderCustomer, ProviderEvent, ProviderEventId, ProviderEventSequence, ProviderId,
    ProviderInvoice, ProviderObjectId, ProviderPriceMapping, ProviderRevision, ProviderSnapshot,
    ProviderStateFacts, ProviderStateKey, ProviderStateText, ProviderStateValue,
    ProviderSubscription, ReconciliationTaskId, RepairIdempotencyKey, UsageIdempotencyKey,
    UsageRecordId,
};

pub use omnius_webhooks_inbound::WebhookHandler;
