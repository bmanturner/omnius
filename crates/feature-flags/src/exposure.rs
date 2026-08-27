use std::{
    collections::VecDeque,
    fmt,
    sync::{Mutex, TryLockError},
};

use omnius_auth_core::{SubjectId, TenantId};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{FlagKey, FlagPurpose, FlagValueKind, ProviderKind, ProviderReason, Variant};

/// Maximum records retained by the supplied in-memory exposure recorder.
pub const MAX_MEMORY_EXPOSURES: usize = 4_096;
/// Maximum records buffered by the supplied non-blocking channel recorder.
pub const MAX_EXPOSURE_QUEUE: usize = 4_096;

/// Why a provider result was replaced with the typed flag default.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FailureDefaultReason {
    /// Provider evaluation exceeded the configured deadline.
    Timeout,
    /// Provider was unavailable or returned a redacted general failure.
    Unavailable,
    /// The provider did not contain the flag.
    NotFound,
    /// The provider rejected the bounded context.
    ContextRejected,
    /// Provider response type or bounds were invalid.
    InvalidResponse,
}

impl FailureDefaultReason {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Unavailable => "unavailable",
            Self::NotFound => "not_found",
            Self::ContextRejected => "context_rejected",
            Self::InvalidResponse => "invalid_response",
        }
    }
}

/// The trusted source of an evaluation result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EvaluationSource {
    /// A live provider response.
    Provider,
    /// A context-scoped unexpired cached provider response.
    Cache,
    /// The flag definition's typed default after a bounded failure.
    FailureDefault(FailureDefaultReason),
}

impl EvaluationSource {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Cache => "cache",
            Self::FailureDefault(_) => "failure_default",
        }
    }

    pub(crate) const fn failure_metric_label(self) -> &'static str {
        match self {
            Self::FailureDefault(reason) => reason.metric_label(),
            Self::Provider | Self::Cache => "none",
        }
    }
}

/// One bounded, redacted feature-flag exposure record.
///
/// Actual context values, flag values, provider metadata, credentials, error messages, and
/// diagnostics are deliberately absent. Subject and tenant fields use canonical identity types.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExposureRecord {
    occurred_at: OffsetDateTime,
    flag_key: FlagKey,
    value_kind: FlagValueKind,
    purpose: FlagPurpose,
    provider: ProviderKind,
    source: EvaluationSource,
    provider_reason: Option<ProviderReason>,
    variant: Option<Variant>,
    subject_id: Option<SubjectId>,
    tenant_id: Option<TenantId>,
    temporary: bool,
}
pub(crate) struct ExposureRecordInput {
    pub(crate) flag_key: FlagKey,
    pub(crate) value_kind: FlagValueKind,
    pub(crate) purpose: FlagPurpose,
    pub(crate) provider: ProviderKind,
    pub(crate) source: EvaluationSource,
    pub(crate) provider_reason: Option<ProviderReason>,
    pub(crate) variant: Option<Variant>,
    pub(crate) subject_id: Option<SubjectId>,
    pub(crate) tenant_id: Option<TenantId>,
    pub(crate) temporary: bool,
}

impl ExposureRecord {
    pub(crate) fn new(input: ExposureRecordInput) -> Self {
        Self {
            occurred_at: OffsetDateTime::now_utc(),
            flag_key: input.flag_key,
            value_kind: input.value_kind,
            purpose: input.purpose,
            provider: input.provider,
            source: input.source,
            provider_reason: input.provider_reason,
            variant: input.variant,
            subject_id: input.subject_id,
            tenant_id: input.tenant_id,
            temporary: input.temporary,
        }
    }

    /// Returns the UTC exposure timestamp.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    /// Returns the bounded product flag key.
    #[must_use]
    pub const fn flag_key(&self) -> &FlagKey {
        &self.flag_key
    }

    /// Returns the value's closed type, not its possibly sensitive value.
    #[must_use]
    pub const fn value_kind(&self) -> FlagValueKind {
        self.value_kind
    }

    /// Returns the closed product purpose.
    #[must_use]
    pub const fn purpose(&self) -> FlagPurpose {
        self.purpose
    }

    /// Returns the low-cardinality provider class.
    #[must_use]
    pub const fn provider(&self) -> ProviderKind {
        self.provider
    }

    /// Returns whether the result came from the provider, cache, or typed failure default.
    #[must_use]
    pub const fn source(&self) -> EvaluationSource {
        self.source
    }

    /// Returns the provider's normalized reason for provider/cache results.
    #[must_use]
    pub const fn provider_reason(&self) -> Option<ProviderReason> {
        self.provider_reason
    }

    /// Returns the bounded provider variation identifier, when supplied.
    #[must_use]
    pub const fn variant(&self) -> Option<&Variant> {
        self.variant.as_ref()
    }

    /// Returns the canonical exposed subject, when authenticated.
    #[must_use]
    pub const fn subject_id(&self) -> Option<SubjectId> {
        self.subject_id
    }

    /// Returns the canonical exposed tenant, when established.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.tenant_id
    }

    /// Returns whether removal metadata exists on the flag definition.
    #[must_use]
    pub const fn is_temporary(&self) -> bool {
        self.temporary
    }
}

/// A non-blocking exposure sink could not accept a record.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExposureRecordError {
    /// The bounded sink has no immediately available capacity.
    #[error("feature-flag exposure sink is full")]
    Full,
    /// The sink has been closed or can no longer safely accept records.
    #[error("feature-flag exposure sink is closed")]
    Closed,
}

impl ExposureRecordError {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Closed => "closed",
        }
    }
}

/// Application sink for bounded exposure/audit records.
///
/// Implementations must return immediately: they must never wait for capacity, perform I/O, await,
/// or acquire a blocking lock. The evaluator emits a stable failure metric and preserves the flag
/// result when a sink returns [`ExposureRecordError`].
pub trait ExposureRecorder: Send + Sync + 'static {
    /// Tries to accept one already bounded, redacted exposure without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureRecordError::Full`] when bounded capacity is exhausted or
    /// [`ExposureRecordError::Closed`] when the consumer is gone.
    fn try_record(&self, exposure: ExposureRecord) -> Result<(), ExposureRecordError>;
}

/// Bounded in-memory exposure recorder for tests and small deployments.
pub struct MemoryExposureRecorder {
    capacity: usize,
    records: Mutex<VecDeque<ExposureRecord>>,
}

impl MemoryExposureRecorder {
    /// Creates a recorder retaining at most `capacity` newest exposures.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureCapacityError`] for zero or more than 4096 records.
    pub fn new(capacity: usize) -> Result<Self, ExposureCapacityError> {
        validate_capacity(capacity, MAX_MEMORY_EXPOSURES)?;
        Ok(Self {
            capacity,
            records: Mutex::new(VecDeque::with_capacity(capacity)),
        })
    }

    /// Tries to return a bounded snapshot from oldest to newest without waiting for the lock.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureRecordError::Full`] on lock contention or
    /// [`ExposureRecordError::Closed`] after lock poisoning.
    pub fn records(&self) -> Result<Vec<ExposureRecord>, ExposureRecordError> {
        self.records
            .try_lock()
            .map(|records| records.iter().cloned().collect())
            .map_err(|error| map_try_lock_error(&error))
    }

    /// Returns the configured record bound.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
}

impl fmt::Debug for MemoryExposureRecorder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MemoryExposureRecorder")
            .field("capacity", &self.capacity)
            .field("records", &"[REDACTED]")
            .finish()
    }
}

impl ExposureRecorder for MemoryExposureRecorder {
    fn try_record(&self, exposure: ExposureRecord) -> Result<(), ExposureRecordError> {
        let mut records = self
            .records
            .try_lock()
            .map_err(|error| map_try_lock_error(&error))?;
        if records.len() == self.capacity {
            records.pop_front();
        }
        records.push_back(exposure);
        Ok(())
    }
}

/// Non-blocking producer for a bounded exposure channel.
///
/// The paired [`ExposureReceiver`] is consumed by an audit/outbox task outside the evaluation
/// path. Saturation and consumer shutdown are reported immediately.
#[derive(Clone)]
pub struct ExposureChannelRecorder {
    sender: tokio::sync::mpsc::Sender<ExposureRecord>,
}

impl ExposureChannelRecorder {
    /// Creates a bounded non-blocking producer and its single consumer.
    ///
    /// # Errors
    ///
    /// Returns [`ExposureCapacityError`] for zero or more than 4096 queued records.
    pub fn new(capacity: usize) -> Result<(Self, ExposureReceiver), ExposureCapacityError> {
        validate_capacity(capacity, MAX_EXPOSURE_QUEUE)?;
        let (sender, receiver) = tokio::sync::mpsc::channel(capacity);
        Ok((Self { sender }, ExposureReceiver { receiver }))
    }

    /// Returns immediately available queue slots.
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        self.sender.capacity()
    }
}

impl fmt::Debug for ExposureChannelRecorder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExposureChannelRecorder")
            .field(
                "sender",
                &format_args!(
                    "[REDACTED; {} of {} slots available]",
                    self.sender.capacity(),
                    self.sender.max_capacity(),
                ),
            )
            .finish()
    }
}

impl ExposureRecorder for ExposureChannelRecorder {
    fn try_record(&self, exposure: ExposureRecord) -> Result<(), ExposureRecordError> {
        self.sender.try_send(exposure).map_err(|error| match error {
            tokio::sync::mpsc::error::TrySendError::Full(_) => ExposureRecordError::Full,
            tokio::sync::mpsc::error::TrySendError::Closed(_) => ExposureRecordError::Closed,
        })
    }
}

/// Single consumer for a bounded exposure channel.
pub struct ExposureReceiver {
    receiver: tokio::sync::mpsc::Receiver<ExposureRecord>,
}

impl ExposureReceiver {
    /// Waits outside the evaluation path for the next exposure, or `None` after producer shutdown.
    pub async fn recv(&mut self) -> Option<ExposureRecord> {
        self.receiver.recv().await
    }
}

impl fmt::Debug for ExposureReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExposureReceiver")
            .field("receiver", &"[REDACTED]")
            .finish()
    }
}

/// Invalid bounded exposure capacity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("exposure capacity must be between 1 and 4096")]
pub struct ExposureCapacityError;

fn validate_capacity(capacity: usize, maximum: usize) -> Result<(), ExposureCapacityError> {
    if (1..=maximum).contains(&capacity) {
        Ok(())
    } else {
        Err(ExposureCapacityError)
    }
}

fn map_try_lock_error<T>(error: &TryLockError<T>) -> ExposureRecordError {
    match error {
        TryLockError::WouldBlock => ExposureRecordError::Full,
        TryLockError::Poisoned(_) => ExposureRecordError::Closed,
    }
}
