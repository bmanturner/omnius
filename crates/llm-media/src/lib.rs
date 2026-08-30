//! Authorized lifecycle management for LLM media stored outside request and response bodies.
//!
//! A public [`MediaReference`] contains only a server-generated media identifier. Tenant,
//! principal, object-storage key, checksum, and scanner details remain on the server. Registered
//! input and provider-produced objects both begin in quarantine; only a fenced clean publication
//! makes bytes available. Resolve, use, and delete are independently authorized.
//!
//! The workflow depends on narrow storage, scanner, and authorization ports. The production
//! [`PostgresMediaRepository`] owns the `llm_media_objects` transaction boundary, while an
//! object-storage adapter maps [`StorageObjectKey`](omnius_object_storage::ObjectKey) operations
//! without exposing provider URLs or credentials.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod domain;
mod error;
mod ports;
mod postgres;
mod workflow;

pub use domain::{
    ClaimToken, DeleteCause, DeleteFence, DeleteRequestOutcome, DeleteResult, DeletionRevision,
    ExpectedMedia, MediaId, MediaIdError, MediaKind, MediaMime, MediaObject, MediaOrigin,
    MediaPolicy, MediaReference, MediaRejection, MediaState, PersistedMediaObject, ReconcileAction,
    ReconciliationClaim, ResolvedMedia, ScanCommitOutcome, Sha256Digest, TransitionFence,
};
pub use error::{MediaError, RepositoryError, ScannerError, StorageError};
pub use ports::{
    AuthorizationError, AuthorizationRequest, ClaimReconciliationRequest, CleanReadRequest,
    CompleteDeletionRequest, DeleteObjectOutcome, DeleteObjectRequest, MediaAction,
    MediaAuthorization, MediaByteStream, MediaRepository, MediaScanner, MediaStorage,
    PublishScanRequest, QuarantineReadRequest, ReconciliationRepositoryOutcome,
    ReleaseClaimRequest, RequestDeletion, SafeMediaRead, ScanMetadata, ScanPublication, ScanReport,
    ScanVerdict, ScannerSession,
};
pub use postgres::PostgresMediaRepository;
pub use workflow::{
    AccessMediaRequest, AdmittedLlmMedia, MediaReconcileSummary, MediaWorkflow,
    RegisterMediaRequest, RegisteredMedia, UseLlmSourceRequest,
};

#[cfg(test)]
mod tests;
