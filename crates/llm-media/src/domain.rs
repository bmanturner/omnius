use std::{fmt, num::NonZeroU16, str::FromStr, time::Duration};

use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::ObjectKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};

use crate::MediaError;

const MAX_MIME_BYTES: usize = 127;
const DEFAULT_MAX_MEDIA_BYTES: u64 = 512 * 1024 * 1024;
const DEFAULT_MAX_INLINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_TTL: Duration = Duration::from_hours(720);
const DEFAULT_CLAIM_LEASE: Duration = Duration::from_secs(60);
const DEFAULT_RECONCILE_BATCH: u16 = 16;

/// A media identifier was malformed or was not a canonical `UUIDv7` value.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum MediaIdError {
    /// The input was not a syntactically valid UUID.
    #[error("media identifier is not a valid UUID")]
    InvalidUuid,
    /// The UUID was not an RFC-compatible version 7 UUID.
    #[error("media identifier must be a UUIDv7 value")]
    NotVersion7,
}

macro_rules! uuid_v7_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new server-owned, time-ordered identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an identifier after validating its UUID version and variant.
            ///
            /// # Errors
            ///
            /// Returns [`MediaIdError::NotVersion7`] unless `value` is an RFC-compatible `UUIDv7`.
            pub fn from_uuid(value: Uuid) -> Result<Self, MediaIdError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(MediaIdError::NotVersion7)
                }
            }

            /// Returns the UUID for persistence and correlation.
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
            type Err = MediaIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(value).map_err(|_| MediaIdError::InvalidUuid)?;
                if value.len() != 36 || uuid.hyphenated().to_string() != value {
                    return Err(MediaIdError::InvalidUuid);
                }
                Self::from_uuid(uuid)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(MediaId, "An opaque server-generated LLM media identifier.");
uuid_v7_id!(
    ClaimToken,
    "A repository-issued reconciliation lease token."
);

/// A lowercase, parameter-free MIME type used as an exact verification contract.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MediaMime(String);

impl MediaMime {
    /// Validates and owns an exact MIME type.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::InvalidMime`] for non-ASCII, uppercase, parameterized, malformed, or
    /// overlength values.
    pub fn parse(value: impl Into<String>) -> Result<Self, MediaError> {
        let value = value.into();
        let mut segments = value.split('/');
        let type_name = segments.next().unwrap_or_default();
        let subtype = segments.next().unwrap_or_default();
        let valid_token = |part: &str| {
            !part.is_empty()
                && part.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(
                            byte,
                            b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+'
                        )
                })
        };
        if value.len() > MAX_MIME_BYTES
            || !value.is_ascii()
            || segments.next().is_some()
            || !valid_token(type_name)
            || !valid_token(subtype)
        {
            return Err(MediaError::InvalidMime);
        }
        Ok(Self(value))
    }

    /// Borrows the canonical MIME string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MediaMime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("MediaMime").field(&self.0).finish()
    }
}

impl fmt::Display for MediaMime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for MediaMime {
    type Err = MediaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for MediaMime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// An exact SHA-256 digest declared before media is made available.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// Creates a digest from its 32 raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses a lowercase 64-character hexadecimal digest.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::InvalidChecksum`] when the representation is not canonical.
    pub fn parse_hex(value: &str) -> Result<Self, MediaError> {
        if value.len() != 64
            || value
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err(MediaError::InvalidChecksum);
        }
        let mut digest = [0_u8; 32];
        for (index, chunk) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = hex_nibble(chunk[0]).ok_or(MediaError::InvalidChecksum)?;
            let low = hex_nibble(chunk[1]).ok_or(MediaError::InvalidChecksum)?;
            digest[index] = (high << 4) | low;
        }
        Ok(Self(digest))
    }

    fn write_hex(self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest(REDACTED)")
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_hex(formatter)
    }
}

impl FromStr for Sha256Digest {
    type Err = MediaError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_hex(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse_hex(&value).map_err(D::Error::custom)
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The broad media class used for policy and scanner context.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaKind {
    /// Image media.
    Image,
    /// Audio media.
    Audio,
    /// Video media.
    Video,
    /// Other file media.
    File,
}

/// The trust origin of stored media.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaOrigin {
    /// Bytes entered through an authenticated upload workflow.
    UserUpload,
    /// Bytes were produced by an LLM provider and remain untrusted until scanned.
    ProviderOutput,
}

/// Exact size, checksum, and MIME expectations for one stored object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedMedia {
    size_bytes: u64,
    sha256: Sha256Digest,
    mime: MediaMime,
}

impl ExpectedMedia {
    /// Validates an expected media contract against the workflow policy.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::InvalidSize`] for zero or over-policy sizes.
    pub fn new(
        size_bytes: u64,
        sha256: Sha256Digest,
        mime: MediaMime,
        policy: &MediaPolicy,
    ) -> Result<Self, MediaError> {
        if size_bytes == 0 || size_bytes > policy.max_media_bytes {
            return Err(MediaError::InvalidSize);
        }
        Ok(Self {
            size_bytes,
            sha256,
            mime,
        })
    }

    /// Returns the exact expected byte count.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Returns the expected full-stream SHA-256 digest.
    #[must_use]
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }

    /// Borrows the exact expected MIME type.
    #[must_use]
    pub const fn mime(&self) -> &MediaMime {
        &self.mime
    }
}

/// Validated workflow limits that bound inline content, stored media, leases, and batch work.
#[derive(Clone, Debug)]
pub struct MediaPolicy {
    max_media_bytes: u64,
    max_inline_bytes: usize,
    max_ttl: Duration,
    claim_lease: Duration,
    reconcile_batch: NonZeroU16,
}

impl MediaPolicy {
    /// Creates a bounded media workflow policy.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::InvalidPolicy`] for zero limits, an inline limit above the object
    /// limit, a zero TTL or lease, or an unsupported batch size above 256.
    pub fn new(
        max_media_bytes: u64,
        max_inline_bytes: usize,
        max_ttl: Duration,
        claim_lease: Duration,
        reconcile_batch: u16,
    ) -> Result<Self, MediaError> {
        let batch = NonZeroU16::new(reconcile_batch).ok_or(MediaError::InvalidPolicy)?;
        let inline_u64 = u64::try_from(max_inline_bytes).map_err(|_| MediaError::InvalidPolicy)?;
        if max_media_bytes == 0
            || max_inline_bytes == 0
            || inline_u64 > max_media_bytes
            || max_ttl.is_zero()
            || claim_lease.is_zero()
            || reconcile_batch > 256
        {
            return Err(MediaError::InvalidPolicy);
        }
        Ok(Self {
            max_media_bytes,
            max_inline_bytes,
            max_ttl,
            claim_lease,
            reconcile_batch: batch,
        })
    }

    /// Returns the maximum stored object size.
    #[must_use]
    pub const fn max_media_bytes(&self) -> u64 {
        self.max_media_bytes
    }

    /// Returns the maximum decoded inline byte count.
    #[must_use]
    pub const fn max_inline_bytes(&self) -> usize {
        self.max_inline_bytes
    }

    /// Returns the maximum lifetime accepted at registration.
    #[must_use]
    pub const fn max_ttl(&self) -> Duration {
        self.max_ttl
    }

    /// Returns the reconciliation lease lifetime.
    #[must_use]
    pub const fn claim_lease(&self) -> Duration {
        self.claim_lease
    }

    /// Returns the maximum claims processed by one reconciliation pass.
    #[must_use]
    pub const fn reconcile_batch(&self) -> NonZeroU16 {
        self.reconcile_batch
    }
}

impl Default for MediaPolicy {
    fn default() -> Self {
        Self {
            max_media_bytes: DEFAULT_MAX_MEDIA_BYTES,
            max_inline_bytes: DEFAULT_MAX_INLINE_BYTES,
            max_ttl: DEFAULT_MAX_TTL,
            claim_lease: DEFAULT_CLAIM_LEASE,
            reconcile_batch: NonZeroU16::new(DEFAULT_RECONCILE_BATCH).unwrap_or(NonZeroU16::MIN),
        }
    }
}

/// Durable lifecycle state. Only [`MediaState::Clean`] may be resolved or used.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaState {
    /// Bytes are untrusted and awaiting checksum, size, MIME, and scanner verification.
    Quarantined,
    /// All verification and scanning gates completed successfully.
    Clean,
    /// Verification or scanning failed and cleanup is scheduled.
    Rejected,
    /// Authorized or expiry-driven deletion is scheduled.
    DeletionPending,
    /// Storage deletion completed under the durable deletion fence.
    Deleted,
}

/// Bounded rejection classifications safe for persistence and authorized status responses.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaRejection {
    /// The registered object was absent when verification began.
    MissingObject,
    /// Stored byte count differed from the declared size.
    SizeMismatch,
    /// Full-stream SHA-256 differed from the declaration.
    ChecksumMismatch,
    /// Server-detected MIME differed from the declaration.
    MimeMismatch,
    /// The scanner rejected the bytes as unsafe.
    ScanRejected,
    /// The scanner failed permanently and the workflow failed closed.
    ScannerFailure,
    /// Object storage failed permanently while verification was consuming the object.
    StorageFailure,
}

/// Why a clean or quarantined object entered deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteCause {
    /// The owner requested deletion.
    OwnerRequest,
    /// The finite media lifetime elapsed.
    Expired,
}

/// Monotonic repository revision that fences deletion completion.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeletionRevision(u64);

impl DeletionRevision {
    /// Restores a non-zero deletion revision.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::CorruptRecord`] for zero.
    pub fn new(value: u64) -> Result<Self, MediaError> {
        if value == 0 {
            return Err(MediaError::CorruptRecord);
        }
        Ok(Self(value))
    }

    /// Returns the persistence value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Persistence fields used to restore an authoritative media row.
#[derive(Clone)]
pub struct PersistedMediaObject {
    /// Server-generated media identifier.
    pub id: MediaId,
    /// Authenticated tenant owner.
    pub tenant_id: TenantId,
    /// Authenticated principal owner.
    pub owner_id: SubjectId,
    /// Server-owned object-storage key, never part of [`MediaReference`].
    pub storage_key: ObjectKey,
    /// Input or provider origin.
    pub origin: MediaOrigin,
    /// Broad media class.
    pub kind: MediaKind,
    /// Exact verification contract.
    pub expected: ExpectedMedia,
    /// Current durable lifecycle state.
    pub state: MediaState,
    /// Optional safe rejection classification.
    pub rejection: Option<MediaRejection>,
    /// Mandatory finite expiry.
    pub expires_at: OffsetDateTime,
    /// Monotonic optimistic-concurrency revision.
    pub revision: u64,
    /// Immutable fence for a scheduled storage deletion.
    pub deletion_revision: Option<DeletionRevision>,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Last authoritative transition time.
    pub updated_at: OffsetDateTime,
}

impl fmt::Debug for PersistedMediaObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedMediaObject")
            .field("id", &self.id)
            .field("origin", &self.origin)
            .field("kind", &self.kind)
            .field("state", &self.state)
            .field("revision", &self.revision)
            .finish_non_exhaustive()
    }
}

/// One authoritative server-side media object record.
#[derive(Clone)]
pub struct MediaObject(PersistedMediaObject);

impl MediaObject {
    #[allow(
        clippy::too_many_arguments,
        reason = "construction requires every immutable quarantine and ownership invariant together"
    )]
    pub(crate) fn new_quarantined(
        id: MediaId,
        tenant_id: TenantId,
        owner_id: SubjectId,
        storage_key: ObjectKey,
        origin: MediaOrigin,
        kind: MediaKind,
        expected: ExpectedMedia,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Self {
        Self(PersistedMediaObject {
            id,
            tenant_id,
            owner_id,
            storage_key,
            origin,
            kind,
            expected,
            state: MediaState::Quarantined,
            rejection: None,
            expires_at,
            revision: 1,
            deletion_revision: None,
            created_at: now,
            updated_at: now,
        })
    }

    /// Restores and validates one authoritative persistence row.
    ///
    /// # Errors
    ///
    /// Returns [`MediaError::CorruptRecord`] when revisions, timestamps, state, rejection, and
    /// deletion-fence fields do not form a valid lifecycle state.
    pub fn restore(fields: PersistedMediaObject) -> Result<Self, MediaError> {
        let deletion_valid = fields
            .deletion_revision
            .is_none_or(|revision| revision.get() <= fields.revision);
        let state_valid = match fields.state {
            MediaState::Quarantined | MediaState::Clean => {
                fields.rejection.is_none() && fields.deletion_revision.is_none()
            }
            MediaState::Rejected => {
                fields.rejection.is_some() && fields.deletion_revision.is_some()
            }
            MediaState::DeletionPending => {
                fields.rejection.is_none() && fields.deletion_revision.is_some()
            }
            MediaState::Deleted => fields.deletion_revision.is_some(),
        };
        if fields.revision == 0
            || fields.expected.size_bytes == 0
            || fields.expires_at <= fields.created_at
            || fields.updated_at < fields.created_at
            || !deletion_valid
            || !state_valid
        {
            return Err(MediaError::CorruptRecord);
        }
        Ok(Self(fields))
    }

    /// Returns the server-generated media identifier.
    #[must_use]
    pub const fn id(&self) -> MediaId {
        self.0.id
    }

    /// Returns the tenant owner.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.0.tenant_id
    }

    /// Returns the principal owner.
    #[must_use]
    pub const fn owner_id(&self) -> SubjectId {
        self.0.owner_id
    }

    /// Borrows the server-internal object-storage key.
    #[must_use]
    pub const fn storage_key(&self) -> &ObjectKey {
        &self.0.storage_key
    }

    /// Returns whether the bytes came from an upload or provider.
    #[must_use]
    pub const fn origin(&self) -> MediaOrigin {
        self.0.origin
    }

    /// Returns the broad media kind.
    #[must_use]
    pub const fn kind(&self) -> MediaKind {
        self.0.kind
    }

    /// Borrows the verification contract.
    #[must_use]
    pub const fn expected(&self) -> &ExpectedMedia {
        &self.0.expected
    }

    /// Returns the durable lifecycle state.
    #[must_use]
    pub const fn state(&self) -> MediaState {
        self.0.state
    }

    /// Returns a safe terminal rejection classification, when present.
    #[must_use]
    pub const fn rejection(&self) -> Option<MediaRejection> {
        self.0.rejection
    }

    /// Returns the mandatory finite expiry.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.0.expires_at
    }

    /// Returns the current optimistic-concurrency revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.0.revision
    }

    /// Returns the immutable scheduled-deletion fence.
    #[must_use]
    pub const fn deletion_revision(&self) -> Option<DeletionRevision> {
        self.0.deletion_revision
    }

    /// Returns the creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.0.created_at
    }

    /// Returns the latest authoritative transition time.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.0.updated_at
    }

    /// Returns all persistence fields without changing them.
    #[must_use]
    pub fn into_persisted(self) -> PersistedMediaObject {
        self.0
    }

    pub(crate) fn public_reference(&self) -> MediaReference {
        MediaReference { id: self.id() }
    }
}

impl fmt::Debug for MediaObject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MediaObject")
            .field("id", &self.id())
            .field("origin", &self.origin())
            .field("kind", &self.kind())
            .field("state", &self.state())
            .field("revision", &self.revision())
            .finish_non_exhaustive()
    }
}

/// Credential-free public media reference containing no tenant, principal, URL, or storage key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MediaReference {
    id: MediaId,
}

impl MediaReference {
    /// Creates a reference from a server-generated media identifier.
    #[must_use]
    pub const fn new(id: MediaId) -> Self {
        Self { id }
    }

    /// Returns the opaque media identifier.
    #[must_use]
    pub const fn id(self) -> MediaId {
        self.id
    }

    /// Encodes this media identifier in the canonical LLM object-source slot.
    ///
    /// The encoded value remains a media identifier; it is never the underlying object-storage
    /// key. Callers must pass it back through [`crate::MediaWorkflow::use_llm_source`] so tenant,
    /// principal, lifecycle, and expiry checks run again.
    ///
    /// # Errors
    ///
    /// Returns a core contract error if the canonical identifier cannot be represented.
    pub fn to_llm_source(
        self,
    ) -> Result<omnius_llm_core::BinarySource, omnius_llm_core::ContractError> {
        omnius_llm_core::BinarySource::object(self.id.to_string())
    }
}

/// Authorized clean media metadata safe to return without storage coordinates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMedia {
    /// Opaque public reference.
    pub reference: MediaReference,
    /// Broad media class.
    pub kind: MediaKind,
    /// Exact verified size.
    pub size_bytes: u64,
    /// Exact verified MIME type.
    pub mime: MediaMime,
    /// Mandatory finite expiry.
    pub expires_at: OffsetDateTime,
}

/// Fence attached to a claimed state transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionFence {
    /// Media revision observed when work was claimed.
    pub expected_revision: u64,
    /// Repository-issued lease token.
    pub claim_token: ClaimToken,
}

/// Immutable fence required to publish storage deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeleteFence {
    /// Revision assigned when deletion was first scheduled.
    pub deletion_revision: DeletionRevision,
}

/// Reconciliation effect selected atomically by the repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileAction {
    /// Verify and scan a quarantined object.
    Scan,
    /// Delete an object under its immutable deletion revision.
    Delete(DeleteFence),
}

/// One bounded, leased reconciliation item.
#[derive(Clone, Debug)]
pub struct ReconciliationClaim {
    /// Authoritative media snapshot at claim time.
    pub media: MediaObject,
    /// Claimed effect.
    pub action: ReconcileAction,
    /// Revision and lease-token fence.
    pub transition: TransitionFence,
}

/// Result of an optimistic deletion request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteRequestOutcome {
    /// Deletion was newly scheduled.
    Scheduled,
    /// The same deletion was already scheduled.
    AlreadyScheduled,
    /// Storage deletion was already published.
    AlreadyDeleted,
    /// The caller's media revision was stale and should be reloaded.
    Stale,
}

/// Authorized delete response with no storage details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteResult {
    /// Deletion was durably scheduled.
    Scheduled,
    /// A prior request already scheduled deletion.
    AlreadyScheduled,
    /// The media had already been deleted.
    AlreadyDeleted,
}

/// Repository result of a fenced scan publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanCommitOutcome {
    /// A clean object became available.
    PublishedClean,
    /// A rejected object durably scheduled cleanup.
    PublishedRejected,
    /// Expiry won the race and cleanup was durably scheduled instead of availability.
    Expired,
    /// Another transition invalidated the scan revision or lease.
    Stale,
    /// This exact idempotent publication was already applied.
    AlreadyApplied,
}
