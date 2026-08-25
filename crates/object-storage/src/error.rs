use thiserror::Error;

/// Stable object-storage failure classes that never retain provider error text or object values.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BlobStoreError {
    /// Provider or limit configuration is invalid for the deployment environment.
    #[error("object storage configuration is invalid")]
    Config,
    /// The requested object does not exist.
    #[error("object was not found")]
    NotFound,
    /// A conditional create encountered an existing object.
    #[error("object already exists")]
    AlreadyExists,
    /// A read, update, copy, or move precondition was not satisfied.
    #[error("object precondition failed")]
    Precondition,
    /// The provider or its credentials are temporarily unavailable.
    #[error("object storage is unavailable")]
    Unavailable,
    /// The adapter-owned total deadline expired.
    #[error("object storage operation timed out")]
    Timeout,
    /// The caller cancelled the operation.
    #[error("object storage operation was cancelled")]
    Cancelled,
    /// An object key, cursor, range, conditional value, or request shape is invalid.
    #[error("object storage request is invalid")]
    Invalid,
    /// The declared or streamed object size violates the configured bound.
    #[error("object size is invalid")]
    Size,
    /// Streamed bytes did not match the required SHA-256 digest.
    #[error("object checksum did not match")]
    Checksum,
    /// Content type or user metadata violates the configured bounds.
    #[error("object metadata is invalid")]
    Metadata,
    /// The selected provider cannot safely implement the requested capability.
    #[error("object storage capability is unsupported")]
    Unsupported,
    /// Multipart state, part ordering, completion, or abort failed.
    #[error("object storage multipart operation failed")]
    Multipart,
    /// New work was rejected because drain or shutdown has begun.
    #[error("object storage is shutting down")]
    Shutdown,
}

pub(crate) fn map_provider_error(error: &object_store::Error) -> BlobStoreError {
    match error {
        object_store::Error::NotFound { .. } => BlobStoreError::NotFound,
        object_store::Error::AlreadyExists { .. } => BlobStoreError::AlreadyExists,
        object_store::Error::Precondition { .. } | object_store::Error::NotModified { .. } => {
            BlobStoreError::Precondition
        }
        object_store::Error::InvalidPath { .. }
        | object_store::Error::UnknownConfigurationKey { .. } => BlobStoreError::Invalid,
        object_store::Error::NotSupported { .. } | object_store::Error::NotImplemented { .. } => {
            BlobStoreError::Unsupported
        }
        _ => BlobStoreError::Unavailable,
    }
}
