use thiserror::Error;

/// Stable upload-workflow failures that never retain filenames, object keys, digests, URLs,
/// scanner messages, or database/provider error text.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum UploadError {
    /// An identifier, filename, MIME declaration, digest, size, duration, or request was invalid.
    #[error("upload request is invalid")]
    Invalid,
    /// The authenticated subject is not allowed to perform the requested upload operation.
    #[error("upload operation is not authorized")]
    Unauthorized,
    /// The upload is not present in the requested tenant.
    #[error("upload was not found")]
    NotFound,
    /// An idempotency identifier was reused with different immutable upload data.
    #[error("upload initiation conflicts with an existing upload")]
    Conflict,
    /// The operation is not valid for the upload's current state.
    #[error("upload state does not allow this operation")]
    State,
    /// The uploaded byte count differs from the declared byte count.
    #[error("upload size did not match")]
    SizeMismatch,
    /// The uploaded bytes differ from the declared SHA-256 digest.
    #[error("upload checksum did not match")]
    ChecksumMismatch,
    /// Server-side content detection disagreed with the declared MIME type.
    #[error("upload MIME type did not match")]
    MimeMismatch,
    /// The scanner rejected the object.
    #[error("upload was rejected by malware scanning")]
    MalwareDetected,
    /// PostgreSQL could not complete the requested operation.
    #[error("upload persistence is unavailable")]
    Database,
    /// Object storage could not complete the requested operation.
    #[error("upload object storage is unavailable")]
    Storage,
    /// Malware scanning could not complete the requested operation.
    #[error("upload malware scanner is unavailable")]
    Scanner,
    /// The work item lease expired or was superseded by another `UUIDv7` fence.
    #[error("upload reconciliation lease was lost")]
    LostLease,
    /// A bounded operation deadline expired.
    #[error("upload operation timed out")]
    Timeout,
    /// Caller or supervisor cancellation stopped the operation.
    #[error("upload operation was cancelled")]
    Cancelled,
}
