use async_trait::async_trait;
use uuid::Uuid;

use crate::model::{
    ClaimResult, InvocationDisposition, MrtrAuditEvent, NormalInvocationRequest, PendingMrtrState,
    ReplacementReason, StateClaim, TerminalStatus,
};

/// Failure at the authoritative MRTR repository and audit boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("MRTR repository operation failed")]
pub struct RepositoryError;

/// Failure returned by the existing normal capability invocation boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("normal capability invocation failed")]
pub struct InvocationError;

/// Authoritative durable replay ledger and redacted lifecycle history for MRTR state.
///
/// Every method that mutates state must commit its supplied audit event in the same durable
/// transaction. `claim_pending` must conditionally transition exactly one live pending row only
/// when every field in [`StateClaim::expected_binding`] matches, and atomically persist exactly one
/// of its supplied success or rejection events. Absence, expiry, mismatch, replay, and concurrent
/// loss all return [`ClaimResult::Rejected`]. `replace_claimed` must finalize the old row, insert the
/// fresh row, and persist its event atomically. Implementations must never enrich events with raw
/// arguments, input responses, identity values, credentials, or request-state tokens.
#[async_trait]
pub trait MrtrStateRepository: Send + Sync {
    /// Atomically creates one unique pending state and its issued event.
    ///
    /// The returned state carries repository-authoritative issuance and expiry timestamps and is
    /// the only state that may be exposed in a signed challenge.
    async fn create_pending(
        &self,
        state: &PendingMrtrState,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError>;

    /// Atomically claims a matching live pending state and records the selected outcome event.
    async fn claim_pending(
        &self,
        claim: StateClaim,
        claimed_event: MrtrAuditEvent,
        rejected_event: MrtrAuditEvent,
    ) -> Result<ClaimResult, RepositoryError>;

    /// Atomically finalizes a claimed handle, creates its successor, and records the transition.
    ///
    /// The returned successor carries repository-authoritative issuance and expiry timestamps.
    async fn replace_claimed(
        &self,
        claimed_state_id: Uuid,
        fresh: &PendingMrtrState,
        reason: ReplacementReason,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError>;

    /// Atomically marks one claimed handle terminal and records the transition.
    async fn finish_claimed(
        &self,
        claimed_state_id: Uuid,
        status: TerminalStatus,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError>;

    /// Records an event only while the referenced state remains claimed.
    async fn record_claimed(
        &self,
        claimed_state_id: Uuid,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError>;

    /// Records a redacted rejection that cannot be bound to authenticated state.
    async fn record_untrusted_rejection(
        &self,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError>;
}

/// Existing capability-registry/server-core invocation boundary.
///
/// This is deliberately the only execution port. Implementations must use the canonical request
/// context on [`NormalInvocationRequest`] to perform ordinary current authorization, tenant,
/// availability, confirmation, deadline, cancellation, and idempotency checks again.
/// [`NormalInvocationRequest::mrtr`] is audit correlation and must never be promoted to an
/// idempotency key.
///
/// Before returning [`InvocationDisposition::InputRequired`], an implementation must durably
/// commit any application state needed from the accepted round and return its non-authorizing
/// [`crate::model::InvocationContinuation`]. On the next invocation it must resolve that reference
/// under freshly evaluated authorization; the MRTR repository never stores the accepted values.
#[async_trait]
pub trait NormalInvocationPort: Send + Sync {
    /// Canonical transport-neutral normal result.
    type Output: Send;

    /// Reinvokes the original operation through the normal registry path.
    async fn invoke(
        &self,
        request: NormalInvocationRequest,
    ) -> Result<InvocationDisposition<Self::Output>, InvocationError>;
}
