//! Bounded tenant-scoped object storage over Apache Arrow `object_store` providers.
//!
//! The public port owns opaque `UUIDv7` object keys, fixed provider paths, streaming integrity,
//! deadlines, cancellation, drain admission, stable errors, capability reporting, and safe health
//! diagnostics. Provider clients, paths, credentials, and provider error strings remain private.
//! Upload authorization, filename policy, quarantine/scanning, public serving, persistence intent,
//! and reconciliation belong to the higher-level upload workflow rather than this crate.

#![forbid(unsafe_code)]

mod composition;
mod config;
mod error;
mod health;
mod key;
mod provider;
mod store;

pub use composition::ObjectStorageAssembly;
pub use config::{ObjectStorageConfig, ObjectStorageLimits, ProviderConfig};
pub use error::BlobStoreError;
pub use health::object_store_health_check;
pub use key::{ListCursor, ObjectKey};
pub use store::{
    AttributePersistence, BeginMultipartRequest, BlobMultipartUpload, BlobStore, ByteRange,
    ByteStream, GetCondition, GetObjectResult, GetRequest, ListItem, ListPage, ListRequest,
    ObjectAttributes, ObjectMetadata, ObjectVersion, OperationContext, PresignMethod,
    PresignRequest, PresignedUrl, ProviderCapabilities, ProviderKind, ProviderLifecycle,
    ProviderStatus, PutObjectResult, PutRequest, TransferRequest, WriteCondition,
};
