//! PostgreSQL-authoritative, tenant-scoped upload quarantine and reconciliation.
//!
//! Initiation and completion are independently authorized. Object keys are generated server-side,
//! and upload identity plus dormant verification intent commits atomically. Completion only moves
//! bytes into quarantine. Separate fenced work then reads to EOF with SHA-256 enforcement, detects
//! MIME from a bounded magic prefix, re-reads every byte through a streaming malware scanner, and
//! publishes only a clean result. All provider and scanner effects occur outside transactions.
//!
//! Serving is deliberately proxied: only `available` rows may open a checksum-checking stream, and
//! responses are forced to `attachment` plus `X-Content-Type-Options: nosniff`. Presigned GET is not
//! part of this API. At-least-once job delivery and process restarts are safe because PostgreSQL
//! leases use expiry-checked `UUIDv7` fences and every follow-up intent is inserted atomically with
//! the state transition it follows.

#![forbid(unsafe_code)]

mod error;
mod mime;
mod ports;
mod reconciler;
mod repository;
mod types;
mod workflow;

pub use error::UploadError;
pub use mime::MimeInspector;
pub use ports::{
    MalwareScanner, ScanMetadata, ScanVerdict, ScannerFailure, ScannerSession, UploadAction,
    UploadAuthorization, UploadAuthorizer,
};
pub use reconciler::{ReconcileUploadsJob, UploadReconciler};
pub use repository::{PostgresUploadRepository, UploadHealth};
pub use types::{
    DeclaredMime, LeaseToken, LeasedWork, NormalizedFilename, ReconcilerConfig, RejectionReason,
    Sha256Digest, Upload, UploadId, UploadState, WorkFailureCode, WorkId, WorkKind,
    max_object_bytes,
};
pub use workflow::{
    AlreadyStartedUpload, CompleteUploadRequest, DirectUploadForm, InitiateUploadRequest,
    InitiatedUpload, OpenDownloadRequest, ProxiedUploadContract, ProxiedUploadResult, SafeDownload,
    UploadWorkflow,
};
