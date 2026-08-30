use async_trait::async_trait;
use thiserror::Error;

use crate::{
    BudgetExhaustion, LedgerEvent, LedgerVersion, Reservation, ReservationId, ReservationRequest,
    TenantId,
};

/// Atomic pre-dispatch reservation decision returned by persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReserveStoreDecision {
    /// A new reservation and its version-zero event were inserted atomically.
    Applied {
        /// Newly persisted reservation.
        reservation: Reservation,
        /// Newly appended redacted event.
        event: LedgerEvent,
    },
    /// The same tenant-scoped idempotency request was already persisted.
    Replay {
        /// Previously persisted reservation.
        reservation: Reservation,
        /// Event at the reservation's current version.
        event: LedgerEvent,
    },
    /// The tenant-scoped idempotency key was reused with conflicting input.
    Conflict,
    /// A hard ceiling rejected dispatch without inserting a reservation.
    Exhausted(BudgetExhaustion),
}

/// Compare-and-set persistence decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompareAndSetDecision {
    /// The replacement and its event were committed atomically.
    Applied,
    /// The row exists at a different version.
    VersionConflict,
    /// No tenant-scoped row exists.
    NotFound,
}

/// Safe, closed persistence failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    /// Storage is temporarily unavailable.
    #[error("usage ledger storage is unavailable")]
    Unavailable,
    /// Persisted state violates the ledger contract.
    #[error("usage ledger storage contains invalid state")]
    CorruptState,
    /// Exact persisted accounting would overflow.
    #[error("usage ledger storage arithmetic overflow")]
    Arithmetic,
}

/// Tenant-scoped persistence port for authoritative global quota accounting.
///
/// Implementations must make [`Self::reserve`] one serializable operation: lock or otherwise fence
/// every applicable budget aggregate, evaluate policies in their canonical order, insert the
/// reservation under a unique `(tenant, idempotency_key)` constraint, and append the version-zero
/// ledger event. [`Self::compare_and_set`] must update exactly one `(tenant, reservation_id,
/// expected_version)` row and append its matching event in the same transaction. Mutations that
/// change effective usage must acquire the same aggregate fences as reservation so reconciliation
/// and new dispatch decisions serialize. Implementations must never perform cross-tenant lookups
/// or return provider response bodies in errors.
#[async_trait]
pub trait UsageLedgerRepository: Send + Sync {
    /// Atomically deduplicates, checks all hard ceilings, reserves, and appends the initial event.
    ///
    /// # Errors
    ///
    /// Returns a closed [`RepositoryError`] without sensitive database or provider details.
    async fn reserve(
        &self,
        request: &ReservationRequest,
    ) -> Result<ReserveStoreDecision, RepositoryError>;

    /// Loads one reservation using both tenant and reservation identifiers.
    ///
    /// # Errors
    ///
    /// Returns a closed [`RepositoryError`] without sensitive database details.
    async fn load(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
    ) -> Result<Option<Reservation>, RepositoryError>;

    /// Replaces one expected version and appends its exact event atomically.
    ///
    /// The replacement version must be `expected_version + 1`, the event must describe that same
    /// replacement/version, and both tenant predicates must match.
    ///
    /// # Errors
    ///
    /// Returns a closed [`RepositoryError`] for unavailable, corrupt, or overflowing storage.
    async fn compare_and_set(
        &self,
        tenant: &TenantId,
        expected_version: LedgerVersion,
        replacement: &Reservation,
        event: &LedgerEvent,
    ) -> Result<CompareAndSetDecision, RepositoryError>;

    /// Loads the immutable event at one exact tenant-scoped reservation version.
    ///
    /// # Errors
    ///
    /// Returns a closed [`RepositoryError`] without sensitive database details.
    async fn event_at(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
        version: LedgerVersion,
    ) -> Result<Option<LedgerEvent>, RepositoryError>;
}
