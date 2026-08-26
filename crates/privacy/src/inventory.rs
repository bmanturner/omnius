use std::{collections::BTreeMap, fmt, future::Future, num::NonZeroU16, pin::Pin, sync::Arc};

use rsk_auth_core::{SubjectId, TenantId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;

use crate::{
    LegalHoldId, LifecycleKind, LifecycleRequestId, LifecycleTarget, PrivacyValueError,
    types::privacy_uuid_id,
};

const MAX_INVENTORY_ADAPTERS: usize = 64;
const MAX_ADAPTER_NAME_BYTES: usize = 64;

privacy_uuid_id!(ArtifactId, "An opaque durable export artifact identity.");

/// One of the closed inventory categories a lifecycle request must reconcile.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InventoryCategory {
    /// Tenant or subject data in PostgreSQL.
    PostgreSql,
    /// Data and media in object storage.
    Object,
    /// Derived documents in a search index.
    Search,
    /// Durable queued or scheduled work.
    Queue,
    /// Data retained by an approved external provider adapter.
    Provider,
}

impl InventoryCategory {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgresql",
            Self::Object => "object",
            Self::Search => "search",
            Self::Queue => "queue",
            Self::Provider => "provider",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "postgresql" => Some(Self::PostgreSql),
            "object" => Some(Self::Object),
            "search" => Some(Self::Search),
            "queue" => Some(Self::Queue),
            "provider" => Some(Self::Provider),
            _ => None,
        }
    }
}

/// A portable, bounded inventory adapter identity.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AdapterName(String);

impl AdapterName {
    /// Validates and owns an adapter identity of at most 64 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyValueError`] for an empty, oversized, or non-portable value.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivacyValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PrivacyValueError::Empty);
        }
        if value.len() > MAX_ADAPTER_NAME_BYTES {
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

    /// Returns the stable adapter identity.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdapterName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("AdapterName").field(&self.0).finish()
    }
}

impl Serialize for AdapterName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AdapterName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// Immutable identity, category, and current contract revision of one process adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryDescriptor {
    name: AdapterName,
    category: InventoryCategory,
    revision: NonZeroU16,
}

impl InventoryDescriptor {
    /// Declares revision 1 of a stable adapter identity within a closed inventory category.
    #[must_use]
    pub const fn new(name: AdapterName, category: InventoryCategory) -> Self {
        Self {
            name,
            category,
            revision: NonZeroU16::MIN,
        }
    }
    /// Returns the stable name matched against the required manifest.
    #[must_use]
    pub const fn name(&self) -> &AdapterName {
        &self.name
    }

    /// Returns the closed inventory category.
    #[must_use]
    pub const fn category(&self) -> InventoryCategory {
        self.category
    }

    /// Selects a nonzero reconciliation-contract revision for rolling deployments.
    #[must_use]
    pub const fn with_revision(mut self, revision: NonZeroU16) -> Self {
        self.revision = revision;
        self
    }
    /// Returns the process adapter's current reconciliation-contract revision.
    #[must_use]
    pub const fn revision(&self) -> NonZeroU16 {
        self.revision
    }
}

/// A fixed SHA-256 digest proving an adapter reconciliation without retaining raw evidence.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EvidenceDigest([u8; 32]);

impl EvidenceDigest {
    /// Hashes transient evidence bytes and retains only their SHA-256 digest.
    #[must_use]
    pub fn hash(evidence: &[u8]) -> Self {
        Self(Sha256::digest(evidence).into())
    }

    /// Restores a previously calculated SHA-256 digest.
    #[must_use]
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }

    /// Returns the fixed digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for EvidenceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EvidenceDigest([SHA-256])")
    }
}

impl<'de> Deserialize<'de> for EvidenceDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let digest = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Self(digest))
    }
}

/// Closed effect produced by a successful reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryEffect {
    /// The adapter authoritatively found no matching data.
    NoData,
    /// The adapter placed matching export data into a durable opaque artifact.
    Exported(ArtifactId),
    /// The requested deletion, anonymization, retention, or hold mutation was applied.
    Mutated,
}

impl InventoryEffect {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NoData => "no_data",
            Self::Exported(_) => "exported",
            Self::Mutated => "mutated",
        }
    }

    pub(crate) const fn artifact_id(self) -> Option<ArtifactId> {
        match self {
            Self::Exported(id) => Some(id),
            Self::NoData | Self::Mutated => None,
        }
    }
}

/// Typed, bounded proof of a successful adapter reconciliation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterEvidence {
    effect: InventoryEffect,
    affected_records: u64,
    digest: EvidenceDigest,
}

impl AdapterEvidence {
    /// Describes a successful result without carrying provider output or raw evidence.
    #[must_use]
    pub const fn new(
        effect: InventoryEffect,
        affected_records: u64,
        digest: EvidenceDigest,
    ) -> Self {
        Self {
            effect,
            affected_records,
            digest,
        }
    }

    /// Returns the closed effect.
    #[must_use]
    pub const fn effect(self) -> InventoryEffect {
        self.effect
    }

    /// Returns the non-negative number of reconciled records.
    #[must_use]
    pub const fn affected_records(self) -> u64 {
        self.affected_records
    }

    /// Returns the fixed reconciliation digest.
    #[must_use]
    pub const fn digest(self) -> EvidenceDigest {
        self.digest
    }

    pub(crate) const fn valid_for(self, operation: LifecycleKind) -> bool {
        match (operation, self.effect) {
            (_, InventoryEffect::NoData) => self.affected_records == 0,
            (LifecycleKind::Export, InventoryEffect::Exported(_))
            | (
                LifecycleKind::Delete
                | LifecycleKind::Anonymize
                | LifecycleKind::Retention
                | LifecycleKind::LegalHoldApply
                | LifecycleKind::LegalHoldRelease,
                InventoryEffect::Mutated,
            ) => true,
            (LifecycleKind::Export, InventoryEffect::Mutated)
            | (
                LifecycleKind::Delete
                | LifecycleKind::Anonymize
                | LifecycleKind::Retention
                | LifecycleKind::LegalHoldApply
                | LifecycleKind::LegalHoldRelease,
                InventoryEffect::Exported(_),
            ) => false,
        }
    }
}
/// Redaction-safe evidence for one adapter in a completed export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportManifestEntry {
    /// Stable required inventory identity.
    pub adapter_name: AdapterName,
    /// Closed store category.
    pub category: InventoryCategory,
    /// Minimum contract revision snapshotted from the independent manifest.
    pub minimum_revision: u16,
    /// Opaque durable export artifact, absent when the adapter found no matching data.
    pub artifact_id: Option<ArtifactId>,
    /// Fixed evidence digest.
    pub evidence_digest: EvidenceDigest,
    /// Non-negative reconciled record count.
    pub affected_records: u64,
    /// Durable reconciliation time.
    pub reconciled_at: OffsetDateTime,
}

/// Authorized, bounded manifest for one completed export request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportManifest {
    /// Completed export request identity.
    pub request_id: LifecycleRequestId,
    /// Export tenant and optional subject scope.
    pub target: LifecycleTarget,
    /// One entry per validated required inventory member.
    pub entries: Vec<ExportManifestEntry>,
}

/// Closed, redaction-safe adapter failure classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterFailureCode {
    /// The backing store or provider is temporarily unavailable.
    Unavailable,
    /// The bounded adapter deadline elapsed.
    Timeout,
    /// The provider imposed a transient rate limit.
    RateLimited,
    /// The adapter found state incompatible with the requested operation.
    InvalidState,
    /// The process adapter revision differs from the durable request snapshot.
    IncompatibleRevision,
    /// The configured provider credential lacks the required permission.
    PermissionDenied,
    /// The adapter does not implement an operation in the snapshotted inventory contract.
    UnsupportedOperation,
    /// A snapshotted adapter is absent from the current process registry.
    AdapterMissing,
}

impl AdapterFailureCode {
    /// Reports whether another bounded attempt can be useful.
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Unavailable | Self::Timeout | Self::RateLimited | Self::AdapterMissing
        )
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::RateLimited => "rate_limited",
            Self::InvalidState => "invalid_state",
            Self::IncompatibleRevision => "incompatible_revision",
            Self::PermissionDenied => "permission_denied",
            Self::UnsupportedOperation => "unsupported_operation",
            Self::AdapterMissing => "adapter_missing",
        }
    }
}

/// A typed adapter failure that never carries a provider message or payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterFailure {
    code: AdapterFailureCode,
}

impl AdapterFailure {
    /// Creates a redaction-safe adapter failure.
    #[must_use]
    pub const fn new(code: AdapterFailureCode) -> Self {
        Self { code }
    }

    /// Returns the closed failure class.
    #[must_use]
    pub const fn code(self) -> AdapterFailureCode {
        self.code
    }
}

/// Stable work facts supplied to an inventory adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterWork {
    /// Durable lifecycle request identity.
    pub request_id: LifecycleRequestId,
    /// Tenant containing all matching data.
    pub tenant_id: TenantId,
    /// Optional subject restriction within the tenant.
    pub subject_id: Option<SubjectId>,
    /// Closed lifecycle operation.
    pub operation: LifecycleKind,
    /// Exclusive retention cutoff, only for retention work.
    pub retention_before: Option<OffsetDateTime>,
    /// Hold identity, only for hold apply or release.
    pub legal_hold_id: Option<LegalHoldId>,
    /// One-based durable request attempt.
    pub attempt: u16,
    /// Monotonic database fence for this lease.
    pub fence: u64,
}

/// Borrowing, object-safe future returned by an inventory adapter.
pub type AdapterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AdapterEvidence, AdapterFailure>> + Send + 'a>>;

/// Provider-neutral port for one exact data inventory entry.
///
/// Implementations must make effects idempotent by request and adapter identity and durably reject
/// a fence lower than the greatest fence already observed for that request. A timed-out future may
/// continue in provider infrastructure, so the database fence alone is not sufficient to protect
/// external mutations. Implementations return only closed outcomes and SHA-256 evidence; provider
/// messages, response bodies, credentials, and raw exported data must never enter this contract.
pub trait DataInventoryAdapter: Send + Sync {
    /// Returns the immutable process descriptor validated against the independent manifest.
    fn descriptor(&self) -> &InventoryDescriptor;

    /// Reconciles one fenced operation and returns only typed, hashed evidence.
    fn reconcile<'a>(&'a self, work: &'a AdapterWork) -> AdapterFuture<'a>;
}

/// One required inventory member and its minimum compatible adapter revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InventoryRequirement {
    name: AdapterName,
    category: InventoryCategory,
    minimum_revision: NonZeroU16,
}

impl InventoryRequirement {
    /// Declares one required inventory member.
    #[must_use]
    pub const fn new(
        name: AdapterName,
        category: InventoryCategory,
        minimum_revision: NonZeroU16,
    ) -> Self {
        Self {
            name,
            category,
            minimum_revision,
        }
    }

    /// Returns the required stable adapter name.
    #[must_use]
    pub const fn name(&self) -> &AdapterName {
        &self.name
    }

    /// Returns the required store category.
    #[must_use]
    pub const fn category(&self) -> InventoryCategory {
        self.category
    }

    /// Returns the minimum compatible contract revision.
    #[must_use]
    pub const fn minimum_revision(&self) -> NonZeroU16 {
        self.minimum_revision
    }
}

/// Independently configured, bounded inventory that every process must provide exactly.
#[derive(Clone, Debug)]
pub struct RequiredInventoryManifest {
    requirements: Arc<BTreeMap<AdapterName, InventoryRequirement>>,
}

impl RequiredInventoryManifest {
    /// Validates and owns a nonempty inventory manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryRegistryError`] when empty, oversized, or duplicate-named.
    pub fn new(
        requirements: impl IntoIterator<Item = InventoryRequirement>,
    ) -> Result<Self, InventoryRegistryError> {
        let mut entries = BTreeMap::new();
        for requirement in requirements {
            if entries.len() == MAX_INVENTORY_ADAPTERS {
                return Err(InventoryRegistryError::TooMany);
            }
            if entries
                .insert(requirement.name().clone(), requirement)
                .is_some()
            {
                return Err(InventoryRegistryError::DuplicateRequirement);
            }
        }
        if entries.is_empty() {
            return Err(InventoryRegistryError::Empty);
        }
        Ok(Self {
            requirements: Arc::new(entries),
        })
    }

    /// Returns the required member count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requirements.len()
    }

    /// Reports whether the manifest is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requirements.is_empty()
    }

    fn get(&self, name: &AdapterName) -> Option<&InventoryRequirement> {
        self.requirements.get(name)
    }

    fn iter(&self) -> impl Iterator<Item = &InventoryRequirement> {
        self.requirements.values()
    }
}

/// Invalid bounded registry construction.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum InventoryRegistryError {
    /// At least one inventory member is required.
    #[error("required data inventory manifest must not be empty")]
    Empty,
    /// The manifest or registry exceeded 64 members.
    #[error("data inventory exceeds 64 members")]
    TooMany,
    /// Two manifest entries declared the same stable identity.
    #[error("required data inventory contains a duplicate name")]
    DuplicateRequirement,
    /// Two adapters declared the same stable identity.
    #[error("data inventory registry contains a duplicate adapter name")]
    DuplicateAdapter,
    /// A required adapter was not provided by the process.
    #[error("required data inventory adapter is missing")]
    MissingRequiredAdapter,
    /// The process provided an adapter absent from the required manifest.
    #[error("data inventory registry contains an unexpected adapter")]
    UnexpectedAdapter,
    /// A provided adapter declared the wrong closed store category.
    #[error("data inventory adapter category differs from the required manifest")]
    CategoryMismatch,
    /// A provided adapter is older than the minimum required revision.
    #[error("data inventory adapter revision is older than the required manifest")]
    RevisionTooOld,
}

/// Bounded registry proven to cover an independently configured manifest exactly.
#[derive(Clone)]
pub struct InventoryRegistry {
    manifest: RequiredInventoryManifest,
    adapters: Arc<BTreeMap<AdapterName, Arc<dyn DataInventoryAdapter>>>,
}

impl InventoryRegistry {
    /// Validates exact adapter coverage of the independent required manifest.
    ///
    /// # Errors
    ///
    /// Returns [`InventoryRegistryError`] for missing, unexpected, duplicate, incompatible,
    /// empty, or oversized inventory.
    pub fn new(
        manifest: RequiredInventoryManifest,
        adapters: impl IntoIterator<Item = Arc<dyn DataInventoryAdapter>>,
    ) -> Result<Self, InventoryRegistryError> {
        let mut entries = BTreeMap::new();
        for adapter in adapters {
            if entries.len() == MAX_INVENTORY_ADAPTERS {
                return Err(InventoryRegistryError::TooMany);
            }
            let name = adapter.descriptor().name().clone();
            if entries.insert(name, adapter).is_some() {
                return Err(InventoryRegistryError::DuplicateAdapter);
            }
        }

        for requirement in manifest.iter() {
            let Some(adapter) = entries.get(requirement.name()) else {
                return Err(InventoryRegistryError::MissingRequiredAdapter);
            };
            let descriptor = adapter.descriptor();
            if descriptor.category() != requirement.category() {
                return Err(InventoryRegistryError::CategoryMismatch);
            }
            if descriptor.revision() < requirement.minimum_revision() {
                return Err(InventoryRegistryError::RevisionTooOld);
            }
        }
        if entries.keys().any(|name| manifest.get(name).is_none()) {
            return Err(InventoryRegistryError::UnexpectedAdapter);
        }

        Ok(Self {
            manifest,
            adapters: Arc::new(entries),
        })
    }

    /// Returns the number of validated required inventory entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.manifest.len()
    }

    /// Reports whether the validated manifest has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.manifest.is_empty()
    }

    /// Returns the exact registered adapter for a snapshotted name.
    #[must_use]
    pub fn get(&self, name: &AdapterName) -> Option<&Arc<dyn DataInventoryAdapter>> {
        self.adapters.get(name)
    }

    pub(crate) fn requirements(&self) -> impl Iterator<Item = &InventoryRequirement> {
        self.manifest.iter()
    }
}

impl fmt::Debug for InventoryRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InventoryRegistry")
            .field("required_count", &self.manifest.len())
            .field("adapter_count", &self.adapters.len())
            .finish()
    }
}
