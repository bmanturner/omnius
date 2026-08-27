use bytes::Bytes;
use futures::future::BoxFuture;
use omnius_auth_core::{SubjectId, TenantId};
use tokio_util::sync::CancellationToken;

use crate::{DeclaredMime, Sha256Digest, UploadError, UploadId};

/// Independently authorized upload operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadAction {
    /// Create or retry upload initiation.
    Initiate,
    /// Announce that an object upload has completed.
    Complete,
    /// Open an available object for safe attachment serving.
    Download,
}

/// Value-only authorization input. It contains no filename, object key, digest, or provider data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadAuthorization {
    /// Operation being authorized.
    pub action: UploadAction,
    /// Requested tenant namespace.
    pub tenant_id: TenantId,
    /// Authenticated actor.
    pub actor_id: SubjectId,
    /// Durable upload identifier.
    pub upload_id: UploadId,
    /// Persisted owner for completion and download; the actor for new initiation.
    pub owner_id: SubjectId,
}

/// Narrow application authorization port used at every upload trust boundary.
pub trait UploadAuthorizer: Send + Sync {
    /// Authorizes exactly one upload operation.
    ///
    /// Implementations must return [`UploadError::Unauthorized`] without retaining policy details
    /// when access is denied.
    fn authorize(&self, request: UploadAuthorization) -> BoxFuture<'_, Result<(), UploadError>>;
}

/// Safe scanner failure classification without engine messages or sample values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScannerFailure {
    /// Temporary capacity, network, or service failure; the object remains quarantined.
    Retryable,
    /// A scanner protocol or policy failure that cannot become clean on retry.
    Permanent,
}

/// Final malware-scanner verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanVerdict {
    /// The full stream was scanned and accepted.
    Clean,
    /// The full stream was scanned and rejected.
    Malicious,
}

/// Safe scanner session metadata. Object keys, names, bytes, and tenant values are excluded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScanMetadata {
    /// Durable upload identifier used only as a safe correlation identifier.
    pub upload_id: UploadId,
    /// Exact declared length.
    pub declared_size: u64,
    /// Expected full-stream checksum.
    pub expected_sha256: Sha256Digest,
    /// Server-detected MIME from verification.
    pub detected_mime: DeclaredMime,
}

/// One streaming scanner session. The workflow, not the scanner, owns object reads and EOF.
pub trait ScannerSession: Send {
    /// Feeds one non-empty object chunk into the scanner.
    fn scan_chunk<'a>(
        &'a mut self,
        chunk: Bytes,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ScannerFailure>>;

    /// Finalizes the session only after the workflow has observed object EOF.
    fn finish<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ScanVerdict, ScannerFailure>>;
}

/// Factory for independent full-stream malware-scanner sessions.
pub trait MalwareScanner: Send + Sync {
    /// Starts a scanner session for one already checksum/MIME-verified upload.
    fn start<'a>(
        &'a self,
        metadata: ScanMetadata,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ScannerSession>, ScannerFailure>>;
}
