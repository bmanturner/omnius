use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use futures::future::BoxFuture;
use rsk_auth_core::TenantId;
use rsk_webhooks_inbound::ClaimedReceipt;
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    BillingValueError, MeterKey, NewUsageRecord, ProviderEvent, ProviderEventId,
    ProviderEventSequence, ProviderId, ProviderObjectId, ProviderSnapshot, UsageIdempotencyKey,
    UsageRecordId,
};

/// Stable provider failure classification safe for persistence and metrics.
#[derive(Clone, Eq, PartialEq)]
pub struct ProviderFailureClass(String);

impl ProviderFailureClass {
    /// Creates a lowercase low-cardinality failure code of at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BillingValueError::InvalidIdentifier`] for malformed values.
    pub fn parse(value: impl Into<String>) -> Result<Self, BillingValueError> {
        let value = value.into();
        let mut bytes = value.bytes();
        if value.len() <= 64
            && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            && bytes.all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            Ok(Self(value))
        } else {
            Err(BillingValueError::InvalidIdentifier)
        }
    }

    /// Returns the safe persistence representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProviderFailureClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ProviderFailureClass")
            .field(&self.0)
            .finish()
    }
}

/// A provider adapter failed without retaining provider payloads, identifiers, or credentials.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderAdapterError {
    /// A transient provider or transport failure may be retried under the durable lease.
    #[error("billing provider operation failed transiently")]
    Retryable(ProviderFailureClass),
    /// Provider-specific input or state is permanently unsupported or incoherent.
    #[error("billing provider operation failed permanently")]
    Permanent(ProviderFailureClass),
}

impl ProviderAdapterError {
    /// Returns the safe failure classification.
    #[must_use]
    pub const fn class(&self) -> &ProviderFailureClass {
        match self {
            Self::Retryable(class) | Self::Permanent(class) => class,
        }
    }

    /// Returns whether retry is permitted.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }
}

/// Provider usage submission containing the durable local idempotency identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUsageRequest {
    tenant_id: TenantId,
    record_id: UsageRecordId,
    meter: MeterKey,
    idempotency_key: UsageIdempotencyKey,
    quantity: u64,
    occurred_at: OffsetDateTime,
}

impl ProviderUsageRequest {
    /// Builds a submission from an already validated local usage record.
    #[must_use]
    pub fn new(tenant_id: TenantId, record_id: UsageRecordId, usage: &NewUsageRecord) -> Self {
        Self {
            tenant_id,
            record_id,
            meter: usage.meter().clone(),
            idempotency_key: usage.idempotency_key().clone(),
            quantity: usage.quantity(),
            occurred_at: usage.occurred_at(),
        }
    }

    pub(crate) const fn restored(
        tenant_id: TenantId,
        record_id: UsageRecordId,
        meter: MeterKey,
        idempotency_key: UsageIdempotencyKey,
        quantity: u64,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            tenant_id,
            record_id,
            meter,
            idempotency_key,
            quantity,
            occurred_at,
        }
    }

    /// Returns the canonical tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the durable local usage record identity.
    #[must_use]
    pub const fn record_id(&self) -> UsageRecordId {
        self.record_id
    }

    /// Returns the application meter.
    #[must_use]
    pub const fn meter(&self) -> &MeterKey {
        &self.meter
    }

    /// Returns the provider submission idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &UsageIdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the positive quantity.
    #[must_use]
    pub const fn quantity(&self) -> u64 {
        self.quantity
    }

    /// Returns when usage occurred.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
}

/// Exact provider acknowledgement for one idempotent usage submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UsageAcknowledgement {
    provider_usage_id: ProviderObjectId,
    accepted_at: OffsetDateTime,
}

impl UsageAcknowledgement {
    /// Creates an acknowledgement returned only after provider acceptance.
    #[must_use]
    pub const fn new(provider_usage_id: ProviderObjectId, accepted_at: OffsetDateTime) -> Self {
        Self {
            provider_usage_id,
            accepted_at,
        }
    }

    /// Returns the provider-owned usage identity.
    #[must_use]
    pub const fn provider_usage_id(&self) -> &ProviderObjectId {
        &self.provider_usage_id
    }

    /// Returns when the provider accepted the submission.
    #[must_use]
    pub const fn accepted_at(&self) -> OffsetDateTime {
        self.accepted_at
    }
}

/// Exact provider seam for verified event decoding, authoritative reads, and idempotent usage.
///
/// Implementations must document the provider semantics behind event sequence and snapshot revision
/// ordering. An adapter must not synthesize a monotonic fence from wall-clock arrival order. Usage
/// submission must pass the supplied idempotency key to a provider primitive with equivalent replay
/// semantics; unsupported providers return a permanent error rather than pretending success.
pub trait BillingProviderAdapter: Send + Sync + 'static {
    /// Returns the stable adapter and persistence identity.
    fn provider_id(&self) -> &ProviderId;

    /// Decodes only the safe projection of a raw-body-verified receipt.
    ///
    /// # Errors
    ///
    /// Returns a permanent error when scope, event identity, payload version, or ordering facts do
    /// not exactly match this adapter's semantics.
    fn decode_verified_event(
        &self,
        receipt: &ClaimedReceipt,
    ) -> Result<ProviderEvent, ProviderAdapterError>;

    /// Fetches a complete authoritative provider API snapshot.
    ///
    /// # Errors
    ///
    /// Returns a safe retryable or permanent provider classification.
    fn fetch_snapshot(
        &self,
        tenant_id: TenantId,
    ) -> BoxFuture<'_, Result<ProviderSnapshot, ProviderAdapterError>>;

    /// Submits one usage effect with provider-backed idempotency.
    ///
    /// # Errors
    ///
    /// Returns a safe retryable or permanent provider classification.
    fn submit_usage<'a>(
        &'a self,
        request: &'a ProviderUsageRequest,
    ) -> BoxFuture<'a, Result<UsageAcknowledgement, ProviderAdapterError>>;

    /// Executes the provider-native health operation named `billing-provider` in the catalog.
    ///
    /// # Errors
    ///
    /// Returns a safe retryable or permanent provider classification.
    fn check_health(&self) -> BoxFuture<'_, Result<(), ProviderAdapterError>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SubmittedUsage {
    request: ProviderUsageRequest,
    acknowledgement: UsageAcknowledgement,
}

#[derive(Default)]
struct FakeState {
    snapshots: BTreeMap<TenantId, ProviderSnapshot>,
    submitted_usage: BTreeMap<(TenantId, MeterKey, UsageIdempotencyKey), SubmittedUsage>,
    failure: Option<ProviderAdapterError>,
}

/// Deterministic provider with an explicit fixture event schema and real idempotency conflicts.
///
/// Its verified payload schema contains `tenant_id` (`UUIDv7`) and `event_sequence` (`u64`);
/// authenticated receipt scope must equal the tenant UUID string. It is an in-memory test fixture,
/// not a production provider or Stripe facade.
#[derive(Clone)]
pub struct FakeBillingAdapter {
    provider: ProviderId,
    state: Arc<RwLock<FakeState>>,
}

impl FakeBillingAdapter {
    /// Creates an empty fake for one provider route.
    #[must_use]
    pub fn new(provider: ProviderId) -> Self {
        Self {
            provider,
            state: Arc::new(RwLock::new(FakeState::default())),
        }
    }

    /// Installs or replaces an authoritative tenant snapshot.
    ///
    /// # Errors
    ///
    /// Returns a permanent fixture error if the snapshot belongs to another provider or the fake
    /// lock is unavailable.
    pub fn put_snapshot(&self, snapshot: ProviderSnapshot) -> Result<(), ProviderAdapterError> {
        if snapshot.provider() != &self.provider {
            return Err(permanent("fixture_provider_mismatch"));
        }
        write_state(&self.state)?
            .snapshots
            .insert(snapshot.tenant_id(), snapshot);
        Ok(())
    }

    /// Selects a safe failure returned by every provider operation until cleared.
    ///
    /// # Errors
    ///
    /// Returns a retryable fake-lock failure when fixture state cannot be written.
    pub fn set_failure(
        &self,
        failure: Option<ProviderAdapterError>,
    ) -> Result<(), ProviderAdapterError> {
        write_state(&self.state)?.failure = failure;
        Ok(())
    }

    /// Returns how many distinct provider-idempotent usage effects were accepted.
    ///
    /// # Errors
    ///
    /// Returns a retryable fake-lock failure when fixture state cannot be read.
    pub fn submitted_usage_count(&self) -> Result<usize, ProviderAdapterError> {
        Ok(read_state(&self.state)?.submitted_usage.len())
    }
}

impl fmt::Debug for FakeBillingAdapter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FakeBillingAdapter")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FakeEventPayload {
    tenant_id: TenantId,
    event_sequence: u64,
}

impl BillingProviderAdapter for FakeBillingAdapter {
    fn provider_id(&self) -> &ProviderId {
        &self.provider
    }

    fn decode_verified_event(
        &self,
        receipt: &ClaimedReceipt,
    ) -> Result<ProviderEvent, ProviderAdapterError> {
        if receipt.provider().as_str() != self.provider.as_str() {
            return Err(permanent("fixture_provider_mismatch"));
        }
        if receipt.event_type() != "billing.changed" || receipt.event_version() != 1 {
            return Err(permanent("fixture_event_route"));
        }
        let payload: FakeEventPayload = serde_json::from_value(receipt.parsed_payload().clone())
            .map_err(|_| permanent("fixture_event_schema"))?;
        if receipt.scope() != payload.tenant_id.to_string() {
            return Err(permanent("fixture_scope_mismatch"));
        }
        let event_id = ProviderEventId::parse(receipt.event_id())
            .map_err(|_| permanent("fixture_event_id"))?;
        let sequence = ProviderEventSequence::new(payload.event_sequence)
            .map_err(|_| permanent("fixture_event_sequence"))?;
        Ok(ProviderEvent::new(payload.tenant_id, event_id, sequence))
    }

    fn fetch_snapshot(
        &self,
        tenant_id: TenantId,
    ) -> BoxFuture<'_, Result<ProviderSnapshot, ProviderAdapterError>> {
        Box::pin(async move {
            let state = read_state(&self.state)?;
            if let Some(failure) = &state.failure {
                return Err(failure.clone());
            }
            state
                .snapshots
                .get(&tenant_id)
                .cloned()
                .ok_or_else(|| permanent("fixture_snapshot_missing"))
        })
    }

    fn submit_usage<'a>(
        &'a self,
        request: &'a ProviderUsageRequest,
    ) -> BoxFuture<'a, Result<UsageAcknowledgement, ProviderAdapterError>> {
        Box::pin(async move {
            let mut state = write_state(&self.state)?;
            if let Some(failure) = &state.failure {
                return Err(failure.clone());
            }
            let key = (
                request.tenant_id(),
                request.meter().clone(),
                request.idempotency_key().clone(),
            );
            if let Some(existing) = state.submitted_usage.get(&key) {
                if existing.request == *request {
                    return Ok(existing.acknowledgement.clone());
                }
                return Err(permanent("fixture_usage_conflict"));
            }
            let provider_usage_id = ProviderObjectId::parse(Uuid::now_v7().to_string())
                .map_err(|_| permanent("fixture_usage_id"))?;
            let acknowledgement =
                UsageAcknowledgement::new(provider_usage_id, OffsetDateTime::now_utc());
            state.submitted_usage.insert(
                key,
                SubmittedUsage {
                    request: request.clone(),
                    acknowledgement: acknowledgement.clone(),
                },
            );
            Ok(acknowledgement)
        })
    }

    fn check_health(&self) -> BoxFuture<'_, Result<(), ProviderAdapterError>> {
        Box::pin(async move {
            let state = read_state(&self.state)?;
            state.failure.clone().map_or(Ok(()), Err)
        })
    }
}

fn retryable(class: &str) -> ProviderAdapterError {
    match ProviderFailureClass::parse(class) {
        Ok(class) => ProviderAdapterError::Retryable(class),
        Err(_) => ProviderAdapterError::Retryable(ProviderFailureClass("invalid_class".to_owned())),
    }
}

fn permanent(class: &str) -> ProviderAdapterError {
    match ProviderFailureClass::parse(class) {
        Ok(class) => ProviderAdapterError::Permanent(class),
        Err(_) => ProviderAdapterError::Permanent(ProviderFailureClass("invalid_class".to_owned())),
    }
}

fn read_state(
    state: &RwLock<FakeState>,
) -> Result<RwLockReadGuard<'_, FakeState>, ProviderAdapterError> {
    state.read().map_err(|_| retryable("fixture_lock"))
}

fn write_state(
    state: &RwLock<FakeState>,
) -> Result<RwLockWriteGuard<'_, FakeState>, ProviderAdapterError> {
    state.write().map_err(|_| retryable("fixture_lock"))
}
