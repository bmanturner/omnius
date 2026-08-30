//! Exact, tenant-safe LLM quota reservations and usage-cost reconciliation.
//!
//! [`UsageLedger`] reserves a checked [`UsageBreakdown`] before dispatch under hard policies,
//! then commits, releases, or reconciles it through a versioned compare-and-set repository port.
//! Missing and ambiguous provider usage remains explicit and conservatively accounted. Primary,
//! retry, repair, and tool work never collapse into an unattributed cost. The production
//! PostgreSQL adapter persists only accounting metadata, never prompts or provider bodies.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod amount;
mod model;
mod postgres;
mod repository;
mod service;
mod types;

pub use amount::{
    ArithmeticError, CostMicrounits, SignedCostMicrounits, SignedUsageAmount, UsageAmount,
    UsageBreakdown, UsageDelta, UsageVector,
};
pub use model::{
    AuditAction, AuditLedgerEvent, AuditOutcome, BudgetCeilings, BudgetDimension, BudgetExhaustion,
    BudgetMetric, BudgetPolicy, BudgetValue, LedgerEvent, LedgerEventKind, LedgerOperation,
    RequestError, Reservation, ReservationRequest, ReservationRestoreError, ReservationState,
    ReservationStateKind, TenantBoundaryError, UsageEvidence, UsageStatus,
};
pub use postgres::PostgresUsageLedgerRepository;
pub use repository::{
    CompareAndSetDecision, RepositoryError, ReserveStoreDecision, UsageLedgerRepository,
};
pub use service::{LedgerError, UsageLedger};
pub use types::{
    ApiKeyId, BudgetScope, DimensionSet, IdempotencyKey, IdentifierError, JobId, LedgerVersion,
    ModelId, OperationId, PrincipalId, ProviderId, RequestFingerprint, ReservationId, RouteId,
    TenantId, ToolId, VersionOverflow,
};

pub(crate) use model::ensure_tenant;

/// Deterministic in-memory reference adapter for tests only.
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

#[cfg(test)]
mod tests;
