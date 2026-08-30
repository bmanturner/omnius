//! Deterministic in-memory reference repository for contract tests only.

use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;

use crate::{
    BudgetDimension, CompareAndSetDecision, IdempotencyKey, LedgerEvent, LedgerEventKind,
    LedgerVersion, RepositoryError, Reservation, ReservationId, ReservationRequest,
    ReservationState, ReserveStoreDecision, TenantId, UsageLedgerRepository, UsageVector,
    ensure_tenant,
};

type ReservationKey = (TenantId, ReservationId);
type IdempotencyIndexKey = (TenantId, IdempotencyKey);
type EventKey = (TenantId, ReservationId, LedgerVersion);

#[derive(Default)]
struct MemoryState {
    reservations: BTreeMap<ReservationKey, Reservation>,
    idempotency: BTreeMap<IdempotencyIndexKey, ReservationKey>,
    events: BTreeMap<EventKey, LedgerEvent>,
}

/// Deterministic, mutex-serialized reference implementation of the repository contract.
///
/// This adapter is compiled only for crate tests or the explicit `test-support` feature. It models
/// the required atomic boundary but is not a production persistence implementation.
#[derive(Clone, Default)]
pub struct InMemoryUsageLedgerRepository {
    state: Arc<Mutex<MemoryState>>,
}

impl InMemoryUsageLedgerRepository {
    /// Creates an empty deterministic repository.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a tenant-scoped reservation snapshot in identifier order.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Unavailable`] if a panicking test poisoned the mutex.
    pub fn reservations_for_tenant(
        &self,
        tenant: &TenantId,
    ) -> Result<Vec<Reservation>, RepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(state
            .reservations
            .iter()
            .filter(|((stored_tenant, _), _)| stored_tenant == tenant)
            .map(|(_, reservation)| reservation.clone())
            .collect())
    }
}

impl fmt::Debug for InMemoryUsageLedgerRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InMemoryUsageLedgerRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl UsageLedgerRepository for InMemoryUsageLedgerRepository {
    async fn reserve(
        &self,
        request: &ReservationRequest,
    ) -> Result<ReserveStoreDecision, RepositoryError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let tenant = request.scope().tenant();
        let idempotency_key = (tenant.clone(), request.idempotency_key().clone());
        if let Some(existing_key) = state.idempotency.get(&idempotency_key) {
            let reservation = state
                .reservations
                .get(existing_key)
                .ok_or(RepositoryError::CorruptState)?;
            if !reservation.is_replay_of(request) {
                return Ok(ReserveStoreDecision::Conflict);
            }
            let event_key = (
                tenant.clone(),
                reservation.id().clone(),
                reservation.version(),
            );
            let event = state
                .events
                .get(&event_key)
                .ok_or(RepositoryError::CorruptState)?;
            return Ok(ReserveStoreDecision::Replay {
                reservation: reservation.clone(),
                event: event.clone(),
            });
        }

        let reservation_key = (tenant.clone(), request.id().clone());
        if state.reservations.contains_key(&reservation_key) {
            return Ok(ReserveStoreDecision::Conflict);
        }

        let requested = request
            .estimate()
            .checked_total()
            .map_err(|_| RepositoryError::Arithmetic)?;
        for policy in request.policies() {
            let current =
                aggregate_for_dimension(state.reservations.values(), request, policy.dimension())?;
            if let Some(exhaustion) =
                policy
                    .ceilings()
                    .first_exhaustion(policy.dimension(), &current, &requested)
            {
                return Ok(ReserveStoreDecision::Exhausted(exhaustion));
            }
        }

        let (reservation, event) =
            Reservation::initial(request).map_err(|_| RepositoryError::Arithmetic)?;
        let event_key = (
            tenant.clone(),
            reservation.id().clone(),
            reservation.version(),
        );
        state
            .idempotency
            .insert(idempotency_key, reservation_key.clone());
        state
            .reservations
            .insert(reservation_key, reservation.clone());
        state.events.insert(event_key, event.clone());
        Ok(ReserveStoreDecision::Applied { reservation, event })
    }

    async fn load(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
    ) -> Result<Option<Reservation>, RepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(state
            .reservations
            .get(&(tenant.clone(), reservation_id.clone()))
            .cloned())
    }

    async fn compare_and_set(
        &self,
        tenant: &TenantId,
        expected_version: LedgerVersion,
        replacement: &Reservation,
        event: &LedgerEvent,
    ) -> Result<CompareAndSetDecision, RepositoryError> {
        ensure_tenant(tenant, replacement).map_err(|_| RepositoryError::CorruptState)?;
        let expected_next = expected_version
            .checked_next()
            .map_err(|_| RepositoryError::Arithmetic)?;
        let replacement_effective = replacement.effective_usage();
        if replacement.version() != expected_next
            || event.version() != replacement.version()
            || event.state() != replacement.state().kind()
            || event.usage_status() != replacement.state().usage_status()
            || event.dimensions() != replacement.scope().dimensions()
            || event.effective_usage() != &replacement_effective
        {
            return Err(RepositoryError::CorruptState);
        }

        let key = (tenant.clone(), replacement.id().clone());
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        let Some(current) = state.reservations.get(&key) else {
            return Ok(CompareAndSetDecision::NotFound);
        };
        if current.version() != expected_version {
            return Ok(CompareAndSetDecision::VersionConflict);
        }
        if current.idempotency_key() != replacement.idempotency_key()
            || current.fingerprint() != replacement.fingerprint()
            || current.scope() != replacement.scope()
            || current.estimate() != replacement.estimate()
            || current.policies() != replacement.policies()
            || !valid_transition(current.state(), replacement.state(), event.kind())
        {
            return Err(RepositoryError::CorruptState);
        }
        let previous = current.effective_usage();
        let expected_event = LedgerEvent::for_transition(event.kind(), &previous, replacement)
            .map_err(|_| RepositoryError::Arithmetic)?;
        if &expected_event != event {
            return Err(RepositoryError::CorruptState);
        }
        let event_key = (
            tenant.clone(),
            replacement.id().clone(),
            replacement.version(),
        );
        if state.events.contains_key(&event_key) {
            return Err(RepositoryError::CorruptState);
        }
        state.reservations.insert(key, replacement.clone());
        state.events.insert(event_key, event.clone());
        Ok(CompareAndSetDecision::Applied)
    }

    async fn event_at(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
        version: LedgerVersion,
    ) -> Result<Option<LedgerEvent>, RepositoryError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::Unavailable)?;
        Ok(state
            .events
            .get(&(tenant.clone(), reservation_id.clone(), version))
            .cloned())
    }
}

fn aggregate_for_dimension<'a>(
    reservations: impl Iterator<Item = &'a Reservation>,
    request: &ReservationRequest,
    dimension: BudgetDimension,
) -> Result<UsageVector, RepositoryError> {
    reservations
        .filter(|reservation| {
            reservation
                .scope()
                .matches_dimension(request.scope(), dimension)
        })
        .try_fold(UsageVector::zero(), |total, reservation| {
            let effective = reservation.effective_usage();
            let usage = effective
                .checked_total()
                .map_err(|_| RepositoryError::Arithmetic)?;
            total
                .checked_add(&usage)
                .map_err(|_| RepositoryError::Arithmetic)
        })
}

fn valid_transition(
    current: &ReservationState,
    replacement: &ReservationState,
    kind: LedgerEventKind,
) -> bool {
    matches!(
        (current, replacement, kind),
        (
            ReservationState::Reserved,
            ReservationState::Committed(_) | ReservationState::Reconciled(_),
            LedgerEventKind::Committed
        ) | (
            ReservationState::Reserved,
            ReservationState::Released,
            LedgerEventKind::Released
        ) | (
            ReservationState::Committed(_),
            ReservationState::Reconciled(_),
            LedgerEventKind::Reconciled
        )
    )
}
