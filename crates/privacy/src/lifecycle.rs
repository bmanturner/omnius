use std::{fmt, time::Duration};

use omnius_auth_core::{SubjectId, TenantId};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, IdempotencyRequirement, Jitter, Job, JobPolicy,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{PolicyVersion, PrivacyValueError, types::privacy_uuid_id};

const MAX_WORKER_ID_BYTES: usize = 64;

privacy_uuid_id!(
    LifecycleRequestId,
    "A durable privacy lifecycle request identity."
);
privacy_uuid_id!(LegalHoldId, "A durable legal-hold identity.");

/// Closed privacy lifecycle operations reconciled across the data inventory.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleKind {
    /// Produce tenant- or subject-scoped export artifacts.
    Export,
    /// Delete matching data where policy permits.
    Delete,
    /// Irreversibly anonymize matching data.
    Anonymize,
    /// Apply a retention cutoff.
    Retention,
    /// Apply a legal hold to every inventory entry.
    LegalHoldApply,
    /// Release a legal hold from every inventory entry.
    LegalHoldRelease,
}

impl LifecycleKind {
    /// Reports whether an active or pending legal hold fences this operation.
    #[must_use]
    pub const fn is_destructive(self) -> bool {
        matches!(self, Self::Delete | Self::Anonymize | Self::Retention)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Export => "export",
            Self::Delete => "delete",
            Self::Anonymize => "anonymize",
            Self::Retention => "retention",
            Self::LegalHoldApply => "legal_hold_apply",
            Self::LegalHoldRelease => "legal_hold_release",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "export" => Some(Self::Export),
            "delete" => Some(Self::Delete),
            "anonymize" => Some(Self::Anonymize),
            "retention" => Some(Self::Retention),
            "legal_hold_apply" => Some(Self::LegalHoldApply),
            "legal_hold_release" => Some(Self::LegalHoldRelease),
            _ => None,
        }
    }
}

/// Durable lifecycle request state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Ready for an initial lease.
    Pending,
    /// Owned under an unexpired lease and fence.
    Running,
    /// Waiting for a bounded retry instant.
    RetryWait,
    /// Paused and fenced while an overlapping legal hold is blocking destructive work.
    HoldWait,
    /// Every snapshotted inventory adapter reconciled successfully.
    Completed,
    /// A terminal failure or exhausted retry budget requires operator review.
    DeadLetter,
}

impl LifecycleState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::RetryWait => "retry_wait",
            Self::HoldWait => "hold_wait",
            Self::Completed => "completed",
            Self::DeadLetter => "dead_letter",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "retry_wait" => Some(Self::RetryWait),
            "hold_wait" => Some(Self::HoldWait),
            "completed" => Some(Self::Completed),
            "dead_letter" => Some(Self::DeadLetter),
            _ => None,
        }
    }
}

/// Closed, redaction-safe reason a lifecycle request is waiting or dead-lettered.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LifecycleFailureCode {
    /// A store or provider was unavailable.
    Unavailable,
    /// An adapter deadline elapsed.
    Timeout,
    /// A provider rate limit was reached.
    RateLimited,
    /// An adapter observed incompatible durable state.
    InvalidState,
    /// A process adapter contract revision did not match the snapshot.
    IncompatibleRevision,
    /// Provider permission was denied.
    PermissionDenied,
    /// The snapshotted operation is unsupported.
    UnsupportedOperation,
    /// A snapshotted adapter was absent after restart.
    AdapterMissing,
    /// A final worker lease expired.
    LeaseExpired,
    /// No safe failure code was retained when the attempt budget ended.
    AttemptsExhausted,
}

impl LifecycleFailureCode {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "unavailable" => Some(Self::Unavailable),
            "timeout" => Some(Self::Timeout),
            "rate_limited" => Some(Self::RateLimited),
            "invalid_state" => Some(Self::InvalidState),
            "incompatible_revision" => Some(Self::IncompatibleRevision),
            "permission_denied" => Some(Self::PermissionDenied),
            "unsupported_operation" => Some(Self::UnsupportedOperation),
            "adapter_missing" => Some(Self::AdapterMissing),
            "lease_expired" => Some(Self::LeaseExpired),
            "attempts_exhausted" => Some(Self::AttemptsExhausted),
            _ => None,
        }
    }
}

/// Tenant scope with an optional subject restriction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleTarget {
    /// Tenant containing every affected store.
    pub tenant_id: TenantId,
    /// Optional subject restriction; `None` means the whole tenant.
    pub subject_id: Option<SubjectId>,
}

impl LifecycleTarget {
    /// Creates a tenant-wide target.
    #[must_use]
    pub const fn tenant(tenant_id: TenantId) -> Self {
        Self {
            tenant_id,
            subject_id: None,
        }
    }

    /// Creates a tenant-scoped subject target.
    #[must_use]
    pub const fn subject(tenant_id: TenantId, subject_id: SubjectId) -> Self {
        Self {
            tenant_id,
            subject_id: Some(subject_id),
        }
    }
}

/// Validated lifecycle request command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateLifecycleRequest {
    target: LifecycleTarget,
    operation: LifecycleKind,
    retention_before: Option<OffsetDateTime>,
}

impl CreateLifecycleRequest {
    /// Creates a data export request.
    #[must_use]
    pub const fn export(target: LifecycleTarget) -> Self {
        Self {
            target,
            operation: LifecycleKind::Export,
            retention_before: None,
        }
    }

    /// Creates a deletion request.
    #[must_use]
    pub const fn delete(target: LifecycleTarget) -> Self {
        Self {
            target,
            operation: LifecycleKind::Delete,
            retention_before: None,
        }
    }

    /// Creates an anonymization request.
    #[must_use]
    pub const fn anonymize(target: LifecycleTarget) -> Self {
        Self {
            target,
            operation: LifecycleKind::Anonymize,
            retention_before: None,
        }
    }

    /// Creates a retention request with an exclusive cutoff.
    #[must_use]
    pub const fn retention(target: LifecycleTarget, before: OffsetDateTime) -> Self {
        Self {
            target,
            operation: LifecycleKind::Retention,
            retention_before: Some(before),
        }
    }

    /// Returns the tenant and optional subject scope.
    #[must_use]
    pub const fn target(self) -> LifecycleTarget {
        self.target
    }

    /// Returns the closed operation.
    #[must_use]
    pub const fn operation(self) -> LifecycleKind {
        self.operation
    }

    /// Returns the retention cutoff only for retention requests.
    #[must_use]
    pub const fn retention_before(self) -> Option<OffsetDateTime> {
        self.retention_before
    }
}

/// Legal basis for a durable hold.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegalHoldBasis {
    /// Anticipated or active litigation.
    Litigation,
    /// Statutory or regulatory preservation.
    Regulatory,
    /// An approved investigation.
    Investigation,
    /// Contractual preservation duty.
    Contractual,
}

impl LegalHoldBasis {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Litigation => "litigation",
            Self::Regulatory => "regulatory",
            Self::Investigation => "investigation",
            Self::Contractual => "contractual",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "litigation" => Some(Self::Litigation),
            "regulatory" => Some(Self::Regulatory),
            "investigation" => Some(Self::Investigation),
            "contractual" => Some(Self::Contractual),
            _ => None,
        }
    }
}

/// Durable legal-hold state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LegalHoldState {
    /// The hold blocks destructive work while inventory application is pending.
    PendingActive,
    /// Every inventory adapter confirmed the hold.
    Active,
    /// The hold continues blocking while inventory release is pending.
    ReleasePending,
    /// Every inventory adapter confirmed release.
    Released,
}

impl LegalHoldState {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_active" => Some(Self::PendingActive),
            "active" => Some(Self::Active),
            "release_pending" => Some(Self::ReleasePending),
            "released" => Some(Self::Released),
            _ => None,
        }
    }
}

/// Command to place a legal hold and reconcile it across the current inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateLegalHold {
    /// Tenant and optional subject protected by the hold.
    pub target: LifecycleTarget,
    /// Closed legal basis.
    pub basis: LegalHoldBasis,
    /// Policy revision governing the hold.
    pub policy_version: PolicyVersion,
}

/// Command to release an existing legal hold after authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseLegalHold {
    /// Hold to release.
    pub hold_id: LegalHoldId,
    /// Expected tenant, preventing cross-tenant identifier use.
    pub tenant_id: TenantId,
}
/// Tenant-scoped identity for authorized dead-letter review or redrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadLetterCommand {
    /// Dead-lettered lifecycle request.
    pub request_id: LifecycleRequestId,
    /// Expected tenant, preventing cross-tenant identifier use.
    pub tenant_id: TenantId,
}

/// Persisted legal-hold summary without provider data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegalHoldRecord {
    /// Hold identity.
    pub id: LegalHoldId,
    /// Protected target.
    pub target: LifecycleTarget,
    /// Closed legal basis.
    pub basis: LegalHoldBasis,
    /// Governing policy revision.
    pub policy_version: PolicyVersion,
    /// Durable hold state.
    pub state: LegalHoldState,
    /// Request time.
    pub requested_at: OffsetDateTime,
    /// Activation time after all inventory adapters reconcile.
    pub activated_at: Option<OffsetDateTime>,
    /// Release time after all inventory adapters reconcile.
    pub released_at: Option<OffsetDateTime>,
}

/// A validated worker identity persisted in leases.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WorkerId(String);

impl WorkerId {
    /// Validates a portable worker identity of at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyValueError`] for an empty, oversized, or non-portable value.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivacyValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PrivacyValueError::Empty);
        }
        if value.len() > MAX_WORKER_ID_BYTES {
            return Err(PrivacyValueError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(PrivacyValueError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the stable worker identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WorkerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("WorkerId").field(&self.0).finish()
    }
}

impl Serialize for WorkerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for WorkerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Invalid lifecycle retry or lease policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RetryPolicyError {
    /// Attempts must be in 1 through 100.
    #[error("lifecycle maximum attempts must be within 1 through 100")]
    Attempts,
    /// Lease duration must be in 1 second through 1 hour.
    #[error("lifecycle lease duration is out of bounds")]
    Lease,
    /// Adapter timeout must be nonzero and no longer than the lease.
    #[error("lifecycle adapter timeout is out of bounds")]
    AdapterTimeout,
    /// Backoff bounds must be nonzero, ordered, and no longer than 24 hours.
    #[error("lifecycle backoff bounds are invalid")]
    Backoff,
}

/// Bounded durable retry, lease, and adapter timeout policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u16,
    lease_duration: Duration,
    adapter_timeout: Duration,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryPolicy {
    /// Validates lifecycle retry and execution bounds.
    ///
    /// # Errors
    ///
    /// Returns [`RetryPolicyError`] for unsafe bounds.
    pub fn new(
        max_attempts: u16,
        lease_duration: Duration,
        adapter_timeout: Duration,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Result<Self, RetryPolicyError> {
        if !(1..=100).contains(&max_attempts) {
            return Err(RetryPolicyError::Attempts);
        }
        if lease_duration < Duration::from_secs(1) || lease_duration > Duration::from_hours(1) {
            return Err(RetryPolicyError::Lease);
        }
        if adapter_timeout.is_zero() || adapter_timeout > lease_duration {
            return Err(RetryPolicyError::AdapterTimeout);
        }
        if initial_backoff.is_zero()
            || initial_backoff > Duration::from_hours(24)
            || max_backoff < initial_backoff
            || max_backoff > Duration::from_hours(24)
        {
            return Err(RetryPolicyError::Backoff);
        }
        Ok(Self {
            max_attempts,
            lease_duration,
            adapter_timeout,
            initial_backoff,
            max_backoff,
        })
    }

    /// Attempt ceiling including the first pass.
    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }

    /// Lease interval renewed before every adapter call.
    #[must_use]
    pub const fn lease_duration(self) -> Duration {
        self.lease_duration
    }

    /// Per-adapter execution deadline.
    #[must_use]
    pub const fn adapter_timeout(self) -> Duration {
        self.adapter_timeout
    }

    /// Calculates deterministic exponential backoff capped by policy.
    #[must_use]
    pub fn backoff(self, attempt: u16) -> Duration {
        let shift = u32::from(attempt.saturating_sub(1).min(31));
        let multiplier = 1_u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.initial_backoff
            .saturating_mul(multiplier)
            .min(self.max_backoff)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            lease_duration: Duration::from_mins(1),
            adapter_timeout: Duration::from_secs(30),
            initial_backoff: Duration::from_secs(5),
            max_backoff: Duration::from_mins(15),
        }
    }
}

/// Persisted lifecycle request summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRequest {
    /// Request identity.
    pub id: LifecycleRequestId,
    /// Tenant and optional subject scope.
    pub target: LifecycleTarget,
    /// Closed operation.
    pub operation: LifecycleKind,
    /// Retention cutoff only for retention work.
    pub retention_before: Option<OffsetDateTime>,
    /// Hold identity only for hold apply or release.
    pub legal_hold_id: Option<LegalHoldId>,
    /// Durable state.
    pub state: LifecycleState,
    /// Number of leases acquired.
    pub attempt_count: u16,
    /// Exact number of required manifest members snapshotted at creation.
    pub inventory_count: u16,
    /// Configured attempt ceiling.
    pub max_attempts: u16,
    /// Current monotonic fence.
    pub fence: u64,
    /// Last closed failure code, when retrying or dead-lettered.
    pub last_failure_code: Option<LifecycleFailureCode>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Terminal time.
    pub completed_at: Option<OffsetDateTime>,
}

/// One exclusive lifecycle lease with its exact required inventory snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleLease {
    /// Persisted request.
    pub request: LifecycleRequest,
    /// Owning worker.
    pub worker_id: WorkerId,
    /// Exclusive lease deadline.
    pub expires_at: OffsetDateTime,
    /// Stable name, category, and minimum revision of every member still requiring success.
    pub pending_adapters: Vec<(crate::AdapterName, crate::InventoryCategory, u16)>,
}

const PRIVACY_LIFECYCLE_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Required,
    10,
    1_000,
    60_000,
    2,
    Jitter::Full,
    300,
    16,
    Some(600),
    "privacy",
    4,
    2_592_000,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    256,
) {
    Ok(policy) => policy,
    Err(_) => panic!("privacy lifecycle job policy must be valid"),
};

/// At-least-once wake-up for one durable lifecycle request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PrivacyLifecycleJob {
    /// Durable request whose PostgreSQL state remains authoritative.
    pub request_id: LifecycleRequestId,
}

impl Job for PrivacyLifecycleJob {
    const NAME: &'static str = "privacy.lifecycle";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = PRIVACY_LIFECYCLE_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_privacy_lifecycle";
    const RUNBOOK: &'static str = "runbooks/privacy-lifecycle";
}
