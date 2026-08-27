use std::{fmt, str::FromStr, time::Duration};

use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::ObjectKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

use crate::UploadError;

const MAX_FILENAME_BYTES: usize = 180;
const MAX_OBJECT_BYTES: u64 = 5 * 1024 * 1024 * 1024;
const MAX_RECONCILE_CLAIM_BATCH: u16 = 16;

macro_rules! uuid_v7_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new time-ordered identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an RFC-compatible `UUIDv7` identifier.
            ///
            /// # Errors
            ///
            /// Returns [`UploadError::Invalid`] for any non-UUIDv7 value.
            pub fn from_uuid(value: Uuid) -> Result<Self, UploadError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(UploadError::Invalid)
                }
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = UploadError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map_err(|_| UploadError::Invalid)
                    .and_then(Self::from_uuid)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(UploadId, "A validated, time-ordered upload identifier.");
uuid_v7_id!(
    WorkId,
    "A validated durable reconciliation-work identifier."
);
uuid_v7_id!(LeaseToken, "A validated reconciliation lease fence.");

/// Exact SHA-256 digest declared before bytes enter quarantine.
#[derive(Clone, Copy, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Restores a digest from its exact 32-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Parses a lowercase or uppercase 64-character hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] when the input is not exactly one SHA-256 digest.
    pub fn from_hex(value: &str) -> Result<Self, UploadError> {
        if value.len() != 64 {
            return Err(UploadError::Invalid);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = hex_nibble(pair[0]).ok_or(UploadError::Invalid)?;
            let low = hex_nibble(pair[1]).ok_or(UploadError::Invalid)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(REDACTED)")
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// A bounded normalized display filename, never a storage path.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct NormalizedFilename(String);

impl NormalizedFilename {
    /// Removes path components and unsafe formatting characters, collapses whitespace, and bounds
    /// the UTF-8 representation without splitting a code point.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] when no safe filename remains.
    pub fn normalize(value: &str) -> Result<Self, UploadError> {
        let basename = value.rsplit(['/', '\\']).next().unwrap_or_default();
        let mut normalized = String::with_capacity(basename.len().min(MAX_FILENAME_BYTES));
        let mut pending_space = false;
        for character in basename.trim().chars() {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                continue;
            }
            if character.is_whitespace() {
                pending_space = !normalized.is_empty();
                continue;
            }
            if pending_space && normalized.len() < MAX_FILENAME_BYTES {
                normalized.push(' ');
            }
            pending_space = false;
            if normalized.len() + character.len_utf8() > MAX_FILENAME_BYTES {
                break;
            }
            normalized.push(character);
        }
        while normalized.ends_with(' ') || normalized.ends_with('.') {
            normalized.pop();
        }
        if normalized.is_empty() || normalized == "." || normalized == ".." {
            return Err(UploadError::Invalid);
        }
        Ok(Self(normalized))
    }

    /// Restores a value that must already be in canonical normalized form.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] when normalization changes the value.
    pub fn parse(value: impl Into<String>) -> Result<Self, UploadError> {
        let value = value.into();
        let normalized = Self::normalize(&value)?;
        if normalized.0 == value {
            Ok(normalized)
        } else {
            Err(UploadError::Invalid)
        }
    }

    /// Returns the safe display value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NormalizedFilename {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NormalizedFilename(REDACTED)")
    }
}

/// MIME types accepted by the server-side magic-signature detector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeclaredMime {
    /// Portable Network Graphics.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// Portable Document Format.
    Pdf,
    /// ZIP archive.
    Zip,
}

impl DeclaredMime {
    /// Returns the canonical MIME serialization.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Gif => "image/gif",
            Self::Pdf => "application/pdf",
            Self::Zip => "application/zip",
        }
    }
}

impl fmt::Display for DeclaredMime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DeclaredMime {
    type Err = UploadError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "image/png" => Ok(Self::Png),
            "image/jpeg" => Ok(Self::Jpeg),
            "image/gif" => Ok(Self::Gif),
            "application/pdf" => Ok(Self::Pdf),
            "application/zip" => Ok(Self::Zip),
            _ => Err(UploadError::Invalid),
        }
    }
}

impl Serialize for DeclaredMime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for DeclaredMime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

/// Durable upload state. Only [`UploadState::Available`] may be served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadState {
    /// Upload metadata and dormant verification intent exist; bytes may not exist yet.
    PendingUpload,
    /// Bytes are quarantined pending verification or scanning.
    Quarantined,
    /// Verification and malware scanning completed successfully.
    Available,
    /// The upload failed closed and deletion is durably scheduled.
    Rejected,
    /// The quarantined object was idempotently deleted.
    Deleted,
}

impl UploadState {
    pub(crate) fn parse(value: &str) -> Result<Self, UploadError> {
        match value {
            "pending_upload" => Ok(Self::PendingUpload),
            "quarantined" => Ok(Self::Quarantined),
            "available" => Ok(Self::Available),
            "rejected" => Ok(Self::Rejected),
            "deleted" => Ok(Self::Deleted),
            _ => Err(UploadError::Database),
        }
    }
}

/// Bounded safe failure reason persisted for rejected uploads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectionReason {
    /// The object did not exist when reconciliation attempted to read it.
    MissingObject,
    /// Stored length differed from the declaration.
    SizeMismatch,
    /// Full-stream checksum verification failed.
    ChecksumMismatch,
    /// Magic-signature detection differed from the declaration.
    MimeMismatch,
    /// The malware scanner returned a malicious verdict.
    Malware,
    /// The scanner returned a non-retryable safe failure.
    ScannerFailure,
    /// The authenticated owner explicitly abandoned the upload before publication.
    Abandoned,
    /// The authorized upload window elapsed before completion.
    PendingExpired,
}

impl RejectionReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MissingObject => "missing_object",
            Self::SizeMismatch => "size_mismatch",
            Self::ChecksumMismatch => "checksum_mismatch",
            Self::MimeMismatch => "mime_mismatch",
            Self::Malware => "malware",
            Self::ScannerFailure => "scanner_failure",
            Self::Abandoned => "abandoned",
            Self::PendingExpired => "pending_expired",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, UploadError> {
        match value {
            "missing_object" => Ok(Self::MissingObject),
            "size_mismatch" => Ok(Self::SizeMismatch),
            "checksum_mismatch" => Ok(Self::ChecksumMismatch),
            "mime_mismatch" => Ok(Self::MimeMismatch),
            "malware" => Ok(Self::Malware),
            "scanner_failure" => Ok(Self::ScannerFailure),
            "abandoned" => Ok(Self::Abandoned),
            "pending_expired" => Ok(Self::PendingExpired),
            _ => Err(UploadError::Database),
        }
    }
}

/// One authoritative upload record.
#[derive(Clone)]
pub struct Upload {
    /// Stable upload identifier.
    pub id: UploadId,
    /// Tenant that owns the namespace.
    pub tenant_id: TenantId,
    /// Authenticated subject that initiated the upload.
    pub owner_id: SubjectId,
    /// Immutable server-generated staging key exposed only to authorized upload transport.
    pub object_key: ObjectKey,
    /// Immutable server-generated publication key never exposed outside this workflow crate.
    pub(crate) published_object_key: ObjectKey,
    /// Safe display filename.
    pub filename: NormalizedFilename,
    /// Exact declared length.
    pub declared_size: u64,
    /// Exact declared digest.
    pub expected_sha256: Sha256Digest,
    /// Declared MIME type.
    pub declared_mime: DeclaredMime,
    /// Latest PostgreSQL-clock deadline covering every direct credential issued for this key.
    pub direct_credential_expires_at: Option<OffsetDateTime>,
    /// PostgreSQL-clock deadline after which an incomplete upload is rejected and deleted.
    pub pending_expires_at: OffsetDateTime,
    /// Server-detected MIME type after verification.
    pub detected_mime: Option<DeclaredMime>,
    /// Current durable state.
    pub state: UploadState,
    /// Safe rejection reason, if rejected or deleted after rejection.
    pub rejection_reason: Option<RejectionReason>,
    /// Monotonic row revision.
    pub revision: i64,
    /// Database creation time.
    pub created_at: OffsetDateTime,
    /// Last database transition time.
    pub updated_at: OffsetDateTime,
}

impl fmt::Debug for Upload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Upload")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("owner_id", &self.owner_id)
            .field("state", &self.state)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// Durable reconciliation operation kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkKind {
    /// Verify size, checksum, and server-detected MIME.
    Verify,
    /// Re-read and stream every byte through malware scanning.
    Scan,
    /// Idempotently delete a rejected or orphaned object.
    Delete,
}

impl WorkKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Scan => "scan",
            Self::Delete => "delete",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, UploadError> {
        match value {
            "verify" => Ok(Self::Verify),
            "scan" => Ok(Self::Scan),
            "delete" => Ok(Self::Delete),
            _ => Err(UploadError::Database),
        }
    }
}

/// Safe, bounded class stored for retry diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkFailureCode {
    /// Object storage was unavailable.
    StorageUnavailable,
    /// Malware scanning was unavailable.
    ScannerUnavailable,
    /// A work deadline expired.
    Timeout,
    /// Supervisor cancellation interrupted work.
    Cancelled,
}

impl WorkFailureCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::StorageUnavailable => "storage_unavailable",
            Self::ScannerUnavailable => "scanner_unavailable",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// One leased reconciliation item fenced by a distinct `UUIDv7` token.
#[derive(Clone, Debug)]
pub struct LeasedWork {
    /// Durable work identifier.
    pub id: WorkId,
    /// Upload identifier, absent only for durable orphan deletion.
    pub upload_id: Option<UploadId>,
    /// Tenant namespace.
    pub tenant_id: TenantId,
    /// Immutable opaque key.
    pub object_key: ObjectKey,
    /// Effect kind.
    pub kind: WorkKind,
    /// Live `UUIDv7` lease fence.
    pub lease_token: LeaseToken,
    /// Attempt count including this claim.
    pub attempt_count: u16,
    /// Claim-transaction snapshot used to keep database reads outside the external-effect budget.
    pub(crate) upload_snapshot: Option<Upload>,
}

/// Validated reconciliation limits.
#[derive(Clone, Debug)]
pub struct ReconcilerConfig {
    /// Stable low-cardinality owner label written into leases.
    pub lease_owner: String,
    /// Maximum disjoint work items claimed and started concurrently per poll (at most 16).
    pub claim_batch: u16,
    /// PostgreSQL-clock lease duration.
    pub lease_duration: Duration,
    /// Deadline for each independent object/scanner effect.
    pub work_timeout: Duration,
    /// PostgreSQL finalization budget reserved after an object or scanner deadline.
    pub finalization_margin: Duration,
    /// Empty-poll delay.
    pub poll_interval: Duration,
    /// Maximum claim attempts before operator repair is required.
    pub max_attempts: u16,
    /// First deterministic retry delay.
    pub initial_retry: Duration,
    /// Maximum deterministic retry delay.
    pub max_retry: Duration,
    /// Grace before an unreferenced object is scheduled for deletion.
    pub orphan_grace: Duration,
}

impl ReconcilerConfig {
    /// Validates every operational bound.
    ///
    /// # Errors
    ///
    /// Returns [`UploadError::Invalid`] for empty owners or unsafe zero/excessive bounds.
    pub fn validate(&self) -> Result<(), UploadError> {
        let minimum_lease = self.work_timeout.checked_add(self.finalization_margin);
        if self.lease_owner.is_empty()
            || self.lease_owner.len() > 128
            || !self
                .lease_owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
            || self.claim_batch == 0
            || self.claim_batch > MAX_RECONCILE_CLAIM_BATCH
            || self.max_attempts == 0
            || self.max_attempts > 100
            || self.lease_duration.is_zero()
            || self.lease_duration > Duration::from_hours(24)
            || self.work_timeout.is_zero()
            || self.finalization_margin.is_zero()
            || self.finalization_margin > Duration::from_secs(60)
            || minimum_lease.is_none_or(|minimum| self.lease_duration < minimum)
            || self.poll_interval.is_zero()
            || self.poll_interval > Duration::from_secs(60)
            || self.initial_retry.is_zero()
            || self.max_retry < self.initial_retry
            || self.max_retry > Duration::from_hours(24)
            || self.orphan_grace < Duration::from_secs(60)
            || self.orphan_grace > Duration::from_hours(24 * 30)
        {
            return Err(UploadError::Invalid);
        }
        Ok(())
    }

    pub(crate) fn retry_delay(&self, attempt_count: u16) -> Duration {
        let exponent = u32::from(attempt_count.saturating_sub(1)).min(31);
        self.initial_retry
            .saturating_mul(1_u32 << exponent)
            .min(self.max_retry)
    }
}

pub(crate) fn postgres_interval_micros(duration: Duration) -> Result<i64, UploadError> {
    let rounded = duration.as_nanos().saturating_add(999) / 1_000;
    i64::try_from(rounded).map_err(|_| UploadError::Invalid)
}

/// Maximum accepted object size enforced before persistence.
#[must_use]
pub const fn max_object_bytes() -> u64 {
    MAX_OBJECT_BYTES
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_reconciler_config() -> ReconcilerConfig {
        ReconcilerConfig {
            lease_owner: "upload-test".to_owned(),
            claim_batch: 16,
            lease_duration: Duration::from_secs(35),
            work_timeout: Duration::from_secs(30),
            finalization_margin: Duration::from_secs(5),
            poll_interval: Duration::from_secs(1),
            max_attempts: 5,
            initial_retry: Duration::from_millis(1),
            max_retry: Duration::from_secs(1),
            orphan_grace: Duration::from_secs(60),
        }
    }

    #[test]
    fn reconciler_config_accepts_maximum_concurrent_batch() {
        assert_eq!(valid_reconciler_config().validate(), Ok(()));
    }

    #[test]
    fn reconciler_config_rejects_oversized_claim_batch() {
        let mut config = valid_reconciler_config();
        config.claim_batch = 17;

        assert_eq!(config.validate(), Err(UploadError::Invalid));
    }

    #[test]
    fn reconciler_config_reserves_finalization_time_in_lease() {
        let mut config = valid_reconciler_config();
        config.lease_duration = Duration::from_secs(34);

        assert_eq!(config.validate(), Err(UploadError::Invalid));
    }

    #[test]
    fn postgres_interval_rounds_nonzero_submicrosecond_up() {
        assert_eq!(postgres_interval_micros(Duration::from_nanos(1)), Ok(1));
    }

    #[test]
    fn postgres_interval_rounds_fractional_microsecond_up() {
        assert_eq!(postgres_interval_micros(Duration::from_nanos(1_001)), Ok(2));
    }
}
