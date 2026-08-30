use std::sync::Arc;

use thiserror::Error;

use crate::{
    BudgetExhaustion, CompareAndSetDecision, LedgerEvent, LedgerEventKind, LedgerOperation,
    RepositoryError, Reservation, ReservationId, ReservationRequest, ReservationState,
    ReserveStoreDecision, TenantId, UsageBreakdown, UsageEvidence, UsageLedgerRepository,
};

const MAX_COMPARE_AND_SET_ATTEMPTS: usize = 16;

/// Concurrency-safe quota reservation and reconciliation service.
pub struct UsageLedger<R> {
    repository: Arc<R>,
}

impl<R> Clone for UsageLedger<R> {
    fn clone(&self) -> Self {
        Self {
            repository: Arc::clone(&self.repository),
        }
    }
}

impl<R> UsageLedger<R>
where
    R: UsageLedgerRepository,
{
    /// Creates a service over the authoritative repository.
    #[must_use]
    pub fn new(repository: Arc<R>) -> Self {
        Self { repository }
    }

    /// Borrows the repository for composition and diagnostics.
    #[must_use]
    pub fn repository(&self) -> &R {
        self.repository.as_ref()
    }

    /// Reserves estimated usage under all hard ceilings before provider dispatch.
    ///
    /// Exact duplicates replay the existing reservation. Conflicting reuse of an idempotency key
    /// fails closed, and no reservation is written when a ceiling is exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::BudgetExhausted`], [`LedgerError::IdempotencyConflict`], or a safe
    /// repository error.
    pub async fn reserve(
        &self,
        request: &ReservationRequest,
    ) -> Result<LedgerOperation, LedgerError> {
        match self.repository.reserve(request).await? {
            ReserveStoreDecision::Applied { reservation, event } => {
                Ok(LedgerOperation::new(reservation, event, false))
            }
            ReserveStoreDecision::Replay { reservation, event } => {
                Ok(LedgerOperation::new(reservation, event, true))
            }
            ReserveStoreDecision::Conflict => Err(LedgerError::IdempotencyConflict),
            ReserveStoreDecision::Exhausted(exhaustion) => {
                Err(LedgerError::BudgetExhausted(exhaustion))
            }
        }
    }

    /// Commits the provider usage classification after dispatch finishes.
    ///
    /// Complete provider actual usage reconciles immediately. Missing or ambiguous usage remains
    /// explicitly committed and conservatively accounted until [`Self::reconcile`] supplies actual
    /// usage. Exact duplicate commits replay; release/commit races allow only the first terminal
    /// transition.
    ///
    /// # Errors
    ///
    /// Returns a closed not-found, transition, concurrency, arithmetic, or repository error.
    pub async fn commit(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
        evidence: UsageEvidence,
    ) -> Result<LedgerOperation, LedgerError> {
        for _ in 0..MAX_COMPARE_AND_SET_ATTEMPTS {
            let current = self.load_required(tenant, reservation_id).await?;
            if let UsageEvidence::Actual(actual) = &evidence {
                Self::ensure_dispatched_requests_are_preserved(actual)?;
            }
            match current.state() {
                ReservationState::Committed(existing) if existing == &evidence => {
                    return self.replay(tenant, current).await;
                }
                ReservationState::Reconciled(actual)
                    if matches!(
                        &evidence,
                        UsageEvidence::Actual(provided) if provided == actual
                    ) =>
                {
                    return self.replay(tenant, current).await;
                }
                ReservationState::Reserved => {}
                ReservationState::Committed(_)
                | ReservationState::Reconciled(_)
                | ReservationState::Released => return Err(LedgerError::TransitionConflict),
            }
            let next_state = match &evidence {
                UsageEvidence::Actual(actual) => ReservationState::Reconciled(actual.clone()),
                UsageEvidence::Missing => ReservationState::Committed(UsageEvidence::Missing),
                UsageEvidence::Ambiguous(observed) => {
                    ReservationState::Committed(UsageEvidence::Ambiguous(observed.clone()))
                }
            };
            if let Some(operation) = self
                .apply_transition(tenant, &current, next_state, LedgerEventKind::Committed)
                .await?
            {
                return Ok(operation);
            }
        }
        Err(LedgerError::ConcurrentModification)
    }

    /// Replaces committed missing or ambiguous usage with complete provider actual usage.
    ///
    /// Positive and negative adjustments are both exact and durable. Reconciliation never rejects
    /// an already incurred positive overage; it raises accounted usage so later reservations
    /// deterministically observe exhaustion.
    ///
    /// # Errors
    ///
    /// Returns a closed not-found, transition, concurrency, arithmetic, or repository error.
    pub async fn reconcile(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
        actual: UsageBreakdown,
    ) -> Result<LedgerOperation, LedgerError> {
        actual
            .checked_total()
            .map_err(|_| LedgerError::Arithmetic)?;
        for _ in 0..MAX_COMPARE_AND_SET_ATTEMPTS {
            let current = self.load_required(tenant, reservation_id).await?;
            Self::ensure_dispatched_requests_are_preserved(&actual)?;
            match current.state() {
                ReservationState::Reconciled(existing) if existing == &actual => {
                    return self.replay(tenant, current).await;
                }
                ReservationState::Committed(_) => {}
                ReservationState::Reserved
                | ReservationState::Reconciled(_)
                | ReservationState::Released => return Err(LedgerError::TransitionConflict),
            }
            if let Some(operation) = self
                .apply_transition(
                    tenant,
                    &current,
                    ReservationState::Reconciled(actual.clone()),
                    LedgerEventKind::Reconciled,
                )
                .await?
            {
                return Ok(operation);
            }
        }
        Err(LedgerError::ConcurrentModification)
    }

    /// Releases a reservation only when dispatch did not occur.
    ///
    /// Exact duplicate releases replay. A commit/release race allows one transition and returns a
    /// closed conflict to the loser, so incurred work can never be silently released.
    ///
    /// # Errors
    ///
    /// Returns a closed not-found, transition, concurrency, arithmetic, or repository error.
    pub async fn release(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
    ) -> Result<LedgerOperation, LedgerError> {
        for _ in 0..MAX_COMPARE_AND_SET_ATTEMPTS {
            let current = self.load_required(tenant, reservation_id).await?;
            match current.state() {
                ReservationState::Released => return self.replay(tenant, current).await,
                ReservationState::Reserved => {}
                ReservationState::Committed(_) | ReservationState::Reconciled(_) => {
                    return Err(LedgerError::TransitionConflict);
                }
            }
            if let Some(operation) = self
                .apply_transition(
                    tenant,
                    &current,
                    ReservationState::Released,
                    LedgerEventKind::Released,
                )
                .await?
            {
                return Ok(operation);
            }
        }
        Err(LedgerError::ConcurrentModification)
    }

    fn ensure_dispatched_requests_are_preserved(
        actual: &UsageBreakdown,
    ) -> Result<(), LedgerError> {
        let preserved = actual
            .includes_dispatched_request()
            .map_err(|_| LedgerError::Arithmetic)?;
        if !preserved {
            return Err(LedgerError::UnderreportedUsage);
        }
        Ok(())
    }

    async fn load_required(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
    ) -> Result<Reservation, LedgerError> {
        self.repository
            .load(tenant, reservation_id)
            .await?
            .ok_or(LedgerError::NotFound)
    }

    async fn replay(
        &self,
        tenant: &TenantId,
        reservation: Reservation,
    ) -> Result<LedgerOperation, LedgerError> {
        let event = self
            .repository
            .event_at(tenant, reservation.id(), reservation.version())
            .await?
            .ok_or(LedgerError::CorruptState)?;
        Ok(LedgerOperation::new(reservation, event, true))
    }

    async fn apply_transition(
        &self,
        tenant: &TenantId,
        current: &Reservation,
        state: ReservationState,
        kind: LedgerEventKind,
    ) -> Result<Option<LedgerOperation>, LedgerError> {
        let next = current
            .transition(state)
            .map_err(|_| LedgerError::VersionExhausted)?;
        let previous = current.effective_usage();
        let event = LedgerEvent::for_transition(kind, &previous, &next)
            .map_err(|_| LedgerError::Arithmetic)?;
        match self
            .repository
            .compare_and_set(tenant, current.version(), &next, &event)
            .await?
        {
            CompareAndSetDecision::Applied => Ok(Some(LedgerOperation::new(next, event, false))),
            CompareAndSetDecision::VersionConflict => Ok(None),
            CompareAndSetDecision::NotFound => Err(LedgerError::CorruptState),
        }
    }
}

/// Closed ledger failure classification with no tenant, principal, prompt, model output, or body.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum LedgerError {
    /// Persistence failed safely.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    /// A hard ceiling rejected dispatch.
    #[error("LLM budget exhausted before dispatch")]
    BudgetExhausted(BudgetExhaustion),
    /// An idempotency key was replayed with conflicting input.
    #[error("conflicting LLM reservation replay")]
    IdempotencyConflict,
    /// No reservation exists in the requested tenant boundary.
    #[error("LLM reservation not found")]
    NotFound,
    /// The requested lifecycle transition conflicts with the durable state.
    #[error("LLM reservation transition conflicts with durable state")]
    TransitionConflict,
    /// Exact accounting could not be represented.
    #[error("exact LLM accounting arithmetic overflow")]
    Arithmetic,
    /// Provider actuals omitted an application-observed dispatched request.
    #[error("provider actual usage underreports dispatched requests")]
    UnderreportedUsage,
    /// Compare-and-set contention did not settle within the bounded retry count.
    #[error("LLM reservation changed concurrently")]
    ConcurrentModification,
    /// The monotonic version has no successor.
    #[error("LLM reservation version exhausted")]
    VersionExhausted,
    /// The repository omitted a required immutable event.
    #[error("LLM usage ledger contains invalid state")]
    CorruptState,
}
