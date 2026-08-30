use crate::MediaState;

/// Stable repository failure classes that carry no SQL text or persisted values.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum RepositoryError {
    /// The repository is temporarily unavailable.
    #[error("media repository unavailable")]
    Unavailable,
    /// An optimistic write or uniqueness condition conflicted.
    #[error("media repository conflict")]
    Conflict,
    /// A persisted row violated the media lifecycle invariants.
    #[error("media repository record is invalid")]
    Corrupt,
}

/// Stable object-storage failure classes with no provider URLs, keys, credentials, or messages.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum StorageError {
    /// The requested stored object does not exist.
    #[error("media object is unavailable")]
    NotFound,
    /// The media expiry fence closed before the next stream chunk was admitted.
    #[error("media read expired")]
    Expired,
    /// A retryable provider or capacity failure occurred.
    #[error("media storage temporarily unavailable")]
    Retryable,
    /// A permanent provider protocol or integrity failure occurred.
    #[error("media storage operation failed")]
    Permanent,
}

/// Stable scanner failure classes with no engine messages or sampled content.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum ScannerError {
    /// A retryable scanner capacity or transport failure occurred.
    #[error("media scanner temporarily unavailable")]
    Retryable,
    /// A permanent scanner protocol or policy failure occurred.
    #[error("media scanner failed closed")]
    Permanent,
}

/// Value-free media workflow failures safe for transport mapping and ordinary diagnostics.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum MediaError {
    /// Workflow limits were invalid.
    #[error("invalid media policy")]
    InvalidPolicy,
    /// The declared size was zero or exceeded policy.
    #[error("invalid media size")]
    InvalidSize,
    /// The exact MIME declaration was malformed.
    #[error("invalid media MIME type")]
    InvalidMime,
    /// A SHA-256 representation was malformed.
    #[error("invalid media checksum")]
    InvalidChecksum,
    /// Expiry was not in the future or exceeded the configured maximum lifetime.
    #[error("invalid media expiry")]
    InvalidExpiry,
    /// A persistence row violated lifecycle invariants.
    #[error("invalid persisted media record")]
    CorruptRecord,
    /// An object-source token was not a canonical media identifier.
    #[error("invalid media reference")]
    InvalidReference,
    /// The media does not exist in the authenticated tenant namespace.
    #[error("media not found")]
    NotFound,
    /// The principal or policy denied this exact operation.
    #[error("media operation unauthorized")]
    Unauthorized,
    /// Media was not clean and available for the requested operation.
    #[error("media is unavailable in state {0:?}")]
    Unavailable(MediaState),
    /// The mandatory finite media lifetime elapsed.
    #[error("media expired")]
    Expired,
    /// Inline bytes exceeded the strict decoded-size bound.
    #[error("inline media exceeds the configured limit")]
    InlineTooLarge,
    /// Inline content was not canonical base64.
    #[error("inline media encoding is invalid")]
    InvalidInlineEncoding,
    /// Direct URL media is not accepted by the server-side lifecycle.
    #[error("external media URLs are not permitted")]
    ExternalUrlForbidden,
    /// A future core source variant is not admitted until explicitly reviewed.
    #[error("unsupported media source")]
    UnsupportedSource,
    /// The durable repository was unavailable.
    #[error("media repository unavailable")]
    RepositoryUnavailable,
    /// Object storage was unavailable.
    #[error("media storage unavailable")]
    StorageUnavailable,
    /// The scanner was temporarily unavailable and the object remains quarantined.
    #[error("media scanner unavailable")]
    ScannerUnavailable,
}

impl From<RepositoryError> for MediaError {
    fn from(error: RepositoryError) -> Self {
        match error {
            RepositoryError::Corrupt => Self::CorruptRecord,
            RepositoryError::Unavailable | RepositoryError::Conflict => Self::RepositoryUnavailable,
        }
    }
}
