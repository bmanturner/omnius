use std::{fmt, pin::Pin};

use bytes::Bytes;
use futures::{Stream, future::BoxFuture};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_object_storage::ObjectKey;
use time::OffsetDateTime;

use crate::{
    ClaimToken, DeleteCause, DeleteRequestOutcome, DeletionRevision, MediaId, MediaKind, MediaMime,
    MediaObject, MediaRejection, ReconciliationClaim, RepositoryError, ScanCommitOutcome,
    ScannerError, Sha256Digest, StorageError,
};

/// A fallible asynchronous object stream. Provider errors are reduced to [`StorageError`].
pub type MediaByteStream =
    Pin<Box<dyn Stream<Item = Result<Bytes, StorageError>> + Send + 'static>>;

/// Independently authorized media operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MediaAction {
    /// Resolve clean media metadata from an opaque reference.
    Resolve,
    /// Open clean media bytes for an LLM operation.
    Use,
    /// Schedule media deletion.
    Delete,
}

/// Value-only authorization input with no checksum, MIME, URL, credential, or storage key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    /// Exact operation being authorized.
    pub action: MediaAction,
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated actor.
    pub actor_id: SubjectId,
    /// Durable media identity.
    pub media_id: MediaId,
    /// Persisted principal owner.
    pub owner_id: SubjectId,
}

/// Stable authorization-port result with no policy details.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum AuthorizationError {
    /// Policy denied the exact operation.
    #[error("media operation denied")]
    Denied,
    /// The policy decision service failed closed.
    #[error("media authorization unavailable")]
    Unavailable,
}

/// Application authorization port invoked separately for resolve, use, and delete.
pub trait MediaAuthorization: Send + Sync {
    /// Authorizes exactly one operation without retaining sensitive media attributes.
    fn authorize(
        &self,
        request: AuthorizationRequest,
    ) -> BoxFuture<'_, Result<(), AuthorizationError>>;
}

/// Request to open quarantined bytes for full verification and scanning.
#[derive(Clone)]
pub struct QuarantineReadRequest {
    /// Authenticated storage namespace.
    pub tenant_id: TenantId,
    /// Server-internal object key.
    pub object_key: ObjectKey,
    /// Absolute stream limit enforced by the adapter as defense in depth.
    pub max_bytes: u64,
}

impl fmt::Debug for QuarantineReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuarantineReadRequest")
            .field("max_bytes", &self.max_bytes)
            .finish_non_exhaustive()
    }
}

/// Request to open bytes after the authoritative row was found clean and unexpired.
#[derive(Clone)]
pub struct CleanReadRequest {
    /// Authenticated storage namespace.
    pub tenant_id: TenantId,
    /// Server-internal object key.
    pub object_key: ObjectKey,
    /// Exact expected stream length.
    pub expected_size: u64,
    /// Exact full-stream checksum the adapter must enforce through EOF.
    pub expected_sha256: Sha256Digest,
    /// Absolute lifecycle fence; adapters must not start or continue reads at or after this time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for CleanReadRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CleanReadRequest")
            .field("expected_size", &self.expected_size)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// Clean byte stream returned only after authorization and lifecycle checks.
pub struct SafeMediaRead {
    /// Verified media kind.
    pub kind: MediaKind,
    /// Verified media MIME type.
    pub mime: MediaMime,
    /// Verified exact size.
    pub size_bytes: u64,
    /// Full object stream; adapters must fail if EOF integrity does not match.
    pub body: MediaByteStream,
}

impl fmt::Debug for SafeMediaRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SafeMediaRead")
            .field("kind", &self.kind)
            .field("mime", &self.mime)
            .field("size_bytes", &self.size_bytes)
            .finish_non_exhaustive()
    }
}

/// Idempotent storage deletion request.
#[derive(Clone)]
pub struct DeleteObjectRequest {
    /// Authenticated storage namespace.
    pub tenant_id: TenantId,
    /// Server-internal object key that is never reused.
    pub object_key: ObjectKey,
    /// Immutable cleanup idempotency and completion fence.
    pub deletion_revision: DeletionRevision,
}

impl fmt::Debug for DeleteObjectRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeleteObjectRequest")
            .field("deletion_revision", &self.deletion_revision)
            .finish_non_exhaustive()
    }
}

/// Idempotent object deletion result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteObjectOutcome {
    /// Bytes were deleted.
    Deleted,
    /// Bytes were already absent; cleanup may still be published.
    NotFound,
}

/// Narrow object-storage port used by media workflow and reconciliation.
pub trait MediaStorage: Send + Sync {
    /// Opens untrusted bytes for full verification. No provider URL or credential is returned.
    fn open_quarantined(
        &self,
        request: QuarantineReadRequest,
    ) -> BoxFuture<'_, Result<MediaByteStream, StorageError>>;

    /// Opens clean bytes with streaming length and checksum enforcement through EOF.
    fn open_clean(
        &self,
        request: CleanReadRequest,
    ) -> BoxFuture<'_, Result<MediaByteStream, StorageError>>;

    /// Deletes an object idempotently. A missing object is a successful cleanup observation.
    fn delete(
        &self,
        request: DeleteObjectRequest,
    ) -> BoxFuture<'_, Result<DeleteObjectOutcome, StorageError>>;
}

/// Safe scanner input metadata excluding tenant, principal, object key, URL, and content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanMetadata {
    /// Opaque media correlation identity.
    pub media_id: MediaId,
    /// Broad media class.
    pub kind: MediaKind,
    /// Exact declared byte count.
    pub expected_size: u64,
    /// Exact declared checksum.
    pub expected_sha256: Sha256Digest,
    /// Exact declared MIME type.
    pub expected_mime: MediaMime,
}

/// Final scanner safety verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanVerdict {
    /// Full-stream scanning accepted the bytes.
    Clean,
    /// Full-stream scanning rejected the bytes.
    Rejected,
}

/// Scanner report emitted only after it consumed the complete stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanReport {
    /// Safety verdict.
    pub verdict: ScanVerdict,
    /// MIME detected from bytes by a server-side detector.
    pub detected_mime: MediaMime,
}

/// One full-stream scanner session.
pub trait ScannerSession: Send {
    /// Feeds one non-empty chunk to the scanner.
    fn scan_chunk(&mut self, chunk: Bytes) -> BoxFuture<'_, Result<(), ScannerError>>;

    /// Finalizes after object EOF and returns both safety and detected MIME.
    fn finish(&mut self) -> BoxFuture<'_, Result<ScanReport, ScannerError>>;
}

/// Factory for isolated scanner sessions.
pub trait MediaScanner: Send + Sync {
    /// Starts a full-stream scan for one quarantined object.
    fn start(
        &self,
        metadata: ScanMetadata,
    ) -> BoxFuture<'_, Result<Box<dyn ScannerSession>, ScannerError>>;
}

/// Bounded request for durable reconciliation claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimReconciliationRequest {
    /// Time used for expiry selection and expired-lease reclamation.
    pub now: OffsetDateTime,
    /// Exclusive lease deadline.
    pub lease_until: OffsetDateTime,
    /// Maximum number of rows to claim.
    pub limit: u16,
}

/// Optimistic request to schedule deletion without holding a transaction across storage effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RequestDeletion {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Durable media identity.
    pub media_id: MediaId,
    /// Revision observed by the caller.
    pub expected_revision: u64,
    /// Owner or expiry trigger.
    pub cause: DeleteCause,
    /// Authoritative transition time.
    pub now: OffsetDateTime,
}

/// Fenced scan publication value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanPublication {
    /// Publish clean availability only if the row is still quarantined and unexpired.
    Clean,
    /// Persist a bounded rejection and atomically schedule deletion.
    Rejected(MediaRejection),
}

/// Request to publish scan outcome under both media revision and lease token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishScanRequest {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Durable media identity.
    pub media_id: MediaId,
    /// Media revision observed at claim time.
    pub expected_revision: u64,
    /// Claim lease token.
    pub claim_token: ClaimToken,
    /// Clean or bounded rejection publication.
    pub publication: ScanPublication,
    /// Completion time; repositories must let expiry win over clean publication.
    pub observed_at: OffsetDateTime,
}

/// Request to publish idempotent storage deletion under the immutable deletion revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteDeletionRequest {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Durable media identity.
    pub media_id: MediaId,
    /// Media revision observed at claim time.
    pub expected_revision: u64,
    /// Claim lease token.
    pub claim_token: ClaimToken,
    /// Immutable revision assigned when deletion was scheduled.
    pub deletion_revision: crate::DeletionRevision,
    /// Completion time.
    pub observed_at: OffsetDateTime,
}

/// Request to release retryable work without changing lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReleaseClaimRequest {
    /// Authenticated tenant namespace.
    pub tenant_id: TenantId,
    /// Durable media identity.
    pub media_id: MediaId,
    /// Media revision observed at claim time.
    pub expected_revision: u64,
    /// Claim lease token.
    pub claim_token: ClaimToken,
}

/// Result of a fenced idempotent repository publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconciliationRepositoryOutcome {
    /// The transition was newly applied.
    Applied,
    /// Another transition invalidated the revision, claim, or deletion fence.
    Stale,
    /// The same terminal transition was already applied.
    AlreadyApplied,
}

/// Durable media repository port.
///
/// Implementations must scope every lookup by `(tenant_id, media_id)`, enforce a unique
/// `(tenant_id, object_key)`, keep deletion revisions immutable, and atomically couple rejected or
/// expired transitions to their deletion fence. No method may retain a database transaction across
/// object-storage or scanner calls.
pub trait MediaRepository: Send + Sync {
    /// Inserts one quarantined row atomically.
    fn insert(&self, media: MediaObject) -> BoxFuture<'_, Result<(), RepositoryError>>;

    /// Loads one tenant-scoped row without looking in another tenant namespace.
    fn find(
        &self,
        tenant_id: TenantId,
        media_id: MediaId,
    ) -> BoxFuture<'_, Result<Option<MediaObject>, RepositoryError>>;

    /// Schedules owner- or expiry-driven deletion using optimistic revision fencing.
    fn request_deletion(
        &self,
        request: RequestDeletion,
    ) -> BoxFuture<'_, Result<DeleteRequestOutcome, RepositoryError>>;

    /// Claims a bounded batch using lease tokens and expired-lease reclamation.
    fn claim_reconciliation(
        &self,
        request: ClaimReconciliationRequest,
    ) -> BoxFuture<'_, Result<Vec<ReconciliationClaim>, RepositoryError>>;

    /// Publishes scan outcome atomically; clean publication must lose to expiry.
    fn publish_scan(
        &self,
        request: PublishScanRequest,
    ) -> BoxFuture<'_, Result<ScanCommitOutcome, RepositoryError>>;

    /// Publishes storage deletion only under the matching immutable deletion revision.
    fn complete_deletion(
        &self,
        request: CompleteDeletionRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, RepositoryError>>;

    /// Releases retryable work only if its revision and claim token still match.
    fn release_claim(
        &self,
        request: ReleaseClaimRequest,
    ) -> BoxFuture<'_, Result<ReconciliationRepositoryOutcome, RepositoryError>>;
}
