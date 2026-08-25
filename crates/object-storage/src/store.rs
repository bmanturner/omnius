use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytes::{Buf as _, Bytes, BytesMut};
use chrono::{DateTime, SecondsFormat, Utc};
use futures::{Stream, StreamExt as _, stream::BoxStream};
use hmac::Hmac;
use http::Method;
use object_store::{
    Attribute, AttributeValue, Attributes, CopyMode, CopyOptions, GetOptions, MultipartUpload,
    ObjectMeta, ObjectStore, ObjectStoreExt as _, PutMode, PutMultipartOptions, PutOptions,
    PutPayload, RenameOptions, RenameTargetMode, UpdateVersion,
};
use rsk_auth_core::TenantId;
use rsk_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use sha2::{Digest as _, Sha256};
use tokio::{sync::Mutex, time::Instant};
use tokio_util::sync::CancellationToken;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    BlobStoreError, ListCursor, ObjectKey, ObjectStorageConfig, ObjectStorageLimits,
    ProviderConfig,
    error::map_provider_error,
    key::{key_from_location, namespace_path, object_path},
    provider::{self, StoreBackend},
};

const READY: u8 = 0;
const DEGRADED: u8 = 1;
const DRAINING: u8 = 2;
const SHUTDOWN: u8 = 3;
const MAX_CONDITION_BYTES: usize = 512;
const MAX_CONTENT_TYPE_BYTES: usize = 255;
const MULTIPART_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// Provider family selected at runtime, without endpoint, bucket, path, or credential values.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ProviderKind {
    /// Process-local in-memory provider.
    Memory,
    /// Rooted local-filesystem provider.
    Local,
    /// AWS S3 or path-style S3-compatible provider.
    S3Compatible,
    /// Google Cloud Storage provider.
    Gcs,
    /// Azure Blob Storage provider.
    Azure,
}

impl ProviderKind {
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Local => "local",
            Self::S3Compatible => "s3_compatible",
            Self::Gcs => "gcs",
            Self::Azure => "azure",
        }
    }
}

/// Value-free capability description for a configured provider.
// The explicit immutable bitmap is the value-free provider capability contract.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCapabilities {
    /// Whether content type and bounded user metadata are persisted natively.
    pub native_attributes: bool,
    /// Whether conditional create is supported for bounded non-multipart writes.
    pub conditional_create: bool,
    /// Whether conditional update using ETag/version is supported.
    pub conditional_update: bool,
    /// Whether conditional destination creation is supported for copy and move.
    pub conditional_copy: bool,
    /// Whether move waits for destination completion before deleting the source.
    pub move_object: bool,
    /// Whether explicit multipart upload is supported.
    pub multipart: bool,
    /// Whether provider-native presigned GET URLs are supported.
    pub presigned_get: bool,
    /// Whether integrity-bound signed direct-upload forms are supported.
    pub presigned_put: bool,
}

impl ProviderCapabilities {
    pub(crate) const fn memory() -> Self {
        Self {
            native_attributes: true,
            conditional_create: true,
            conditional_update: true,
            conditional_copy: true,
            move_object: true,
            multipart: true,
            presigned_get: false,
            presigned_put: false,
        }
    }

    pub(crate) const fn local() -> Self {
        Self {
            native_attributes: false,
            conditional_create: true,
            conditional_update: false,
            conditional_copy: true,
            move_object: true,
            multipart: true,
            presigned_get: false,
            presigned_put: false,
        }
    }

    pub(crate) const fn cloud(move_object: bool) -> Self {
        Self {
            native_attributes: true,
            conditional_create: true,
            conditional_update: true,
            conditional_copy: true,
            move_object,
            multipart: true,
            presigned_get: true,
            presigned_put: false,
        }
    }
}

/// Safe provider lifecycle state exposed to diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProviderLifecycle {
    /// Provider is configured and the last bounded operation succeeded.
    Ready,
    /// The last bounded operation failed or timed out.
    Degraded,
    /// New operations are rejected while admitted work drains.
    Draining,
    /// All work is cancelled and new operations are rejected.
    Shutdown,
}

/// Value-free provider status snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderStatus {
    /// Selected provider family.
    pub kind: ProviderKind,
    /// Current adapter lifecycle.
    pub lifecycle: ProviderLifecycle,
    /// Provider capabilities known at construction time.
    pub capabilities: ProviderCapabilities,
}

/// Caller-owned cancellation context for one object-storage operation.
#[derive(Clone)]
pub struct OperationContext {
    cancellation: CancellationToken,
}

impl OperationContext {
    /// Creates a context cancelled when the supplied token is cancelled.
    #[must_use]
    pub const fn new(cancellation: CancellationToken) -> Self {
        Self { cancellation }
    }

    /// Creates a context with an independent, initially active cancellation token.
    #[must_use]
    pub fn uncancelled() -> Self {
        Self::new(CancellationToken::new())
    }

    /// Returns the caller cancellation token for child work.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

impl fmt::Debug for OperationContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OperationContext")
            .field("cancelled", &self.cancellation.is_cancelled())
            .finish()
    }
}

/// A fallible asynchronous byte stream used for uploads and downloads.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, BlobStoreError>> + Send + 'static>>;

/// Required behavior for a write at an existing object key.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum WriteCondition {
    /// Replace any existing object.
    #[default]
    Overwrite,
    /// Atomically fail if an object already exists.
    Create,
    /// Atomically replace only the supplied provider version.
    Update {
        /// Provider `ETag` returned by an earlier operation.
        e_tag: Option<String>,
        /// Provider version returned by an earlier operation.
        version: Option<String>,
    },
}

/// Streamed object upload request.
pub struct PutRequest {
    /// Canonical tenant namespace.
    pub tenant_id: TenantId,
    /// Opaque server-owned object key.
    pub key: ObjectKey,
    /// Exact byte count the stream must yield.
    pub declared_length: u64,
    /// Required SHA-256 digest of the complete stream.
    pub expected_sha256: [u8; 32],
    /// Optional bounded content type.
    pub content_type: Option<String>,
    /// Bounded portable user metadata.
    pub metadata: BTreeMap<String, String>,
    /// Conditional write behavior.
    pub condition: WriteCondition,
    /// Fallible source stream consumed exactly once.
    pub stream: ByteStream,
}

impl fmt::Debug for PutRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PutRequest")
            .field("declared_length", &self.declared_length)
            .field("metadata_fields", &self.metadata.len())
            .field("has_content_type", &self.content_type.is_some())
            .field("condition", &self.condition)
            .finish_non_exhaustive()
    }
}

/// Whether requested content type and user metadata were persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AttributePersistence {
    /// The request contained no attributes.
    NotRequested,
    /// The provider persisted attributes natively.
    Native,
    /// Core bytes were stored, but this provider does not support portable attributes.
    Unsupported,
}

/// Provider version identity preserved across conditional operations.
#[derive(Clone, Eq, PartialEq)]
pub struct ObjectVersion {
    /// Provider `ETag`, when supplied.
    pub e_tag: Option<String>,
    /// Provider version identifier, when supplied.
    pub version: Option<String>,
}

impl fmt::Debug for ObjectVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectVersion")
            .field("has_e_tag", &self.e_tag.is_some())
            .field("has_version", &self.version.is_some())
            .finish()
    }
}

/// Result of a successful streamed or multipart write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PutObjectResult {
    /// Provider version identity for later conditional use.
    pub version: ObjectVersion,
    /// SHA-256 digest verified by the adapter while streaming.
    pub sha256: [u8; 32],
    /// Attribute persistence behavior for this provider.
    pub attributes: AttributePersistence,
}

/// Bounded portable attributes recovered from the provider.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct ObjectAttributes {
    /// Native content type, when supported and present.
    pub content_type: Option<String>,
    /// Native user metadata, when supported and present.
    pub metadata: BTreeMap<String, String>,
}

impl fmt::Debug for ObjectAttributes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectAttributes")
            .field("has_content_type", &self.content_type.is_some())
            .field("metadata_fields", &self.metadata.len())
            .finish()
    }
}

/// Provider-neutral object metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    /// Opaque object key within the requested tenant namespace.
    pub key: ObjectKey,
    /// Stored byte count.
    pub size: u64,
    /// Provider last-modified timestamp.
    pub last_modified: DateTime<Utc>,
    /// Provider version identity.
    pub version: ObjectVersion,
    /// Portable attributes supported by the selected provider.
    pub attributes: ObjectAttributes,
}

/// Optional bounded byte range and read preconditions.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GetCondition {
    /// Require this `ETag` to match.
    pub if_match: Option<String>,
    /// Require this `ETag` not to match.
    pub if_none_match: Option<String>,
    /// Read this provider version when supported.
    pub version: Option<String>,
}

/// Half-open byte range `[start, end)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteRange {
    /// First byte offset included.
    pub start: u64,
    /// First byte offset excluded.
    pub end: u64,
}

impl ByteRange {
    /// Creates a non-empty half-open range.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError::Invalid`] unless `start < end`.
    pub const fn new(start: u64, end: u64) -> Result<Self, BlobStoreError> {
        if start >= end {
            return Err(BlobStoreError::Invalid);
        }
        Ok(Self { start, end })
    }
}

/// Streamed object download request.
#[derive(Clone, Debug)]
pub struct GetRequest {
    /// Canonical tenant namespace.
    pub tenant_id: TenantId,
    /// Opaque object key.
    pub key: ObjectKey,
    /// Optional half-open byte range.
    pub range: Option<ByteRange>,
    /// Optional read preconditions.
    pub condition: GetCondition,
    /// Optional expected SHA-256 digest, allowed only for complete-object reads.
    pub expected_sha256: Option<[u8; 32]>,
}

/// Streaming download response. The checksum is finalized only when the stream reaches EOF.
pub struct GetObjectResult {
    /// Object metadata returned with the read.
    pub metadata: ObjectMetadata,
    /// Provider byte stream, bounded by the original total deadline and caller cancellation.
    pub stream: ByteStream,
}

impl fmt::Debug for GetObjectResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetObjectResult")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// One object in a tenant-scoped list page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListItem {
    /// Opaque object key.
    pub key: ObjectKey,
    /// Stored byte count.
    pub size: u64,
    /// Provider last-modified timestamp.
    pub last_modified: DateTime<Utc>,
    /// Provider version identity.
    pub version: ObjectVersion,
}

/// Bounded tenant list request.
#[derive(Clone, Debug)]
pub struct ListRequest {
    /// Canonical tenant namespace.
    pub tenant_id: TenantId,
    /// Requested page size, capped by configuration.
    pub limit: u16,
    /// Provider-neutral cursor returned by an earlier page.
    pub cursor: Option<ListCursor>,
}

/// Bounded tenant list page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListPage {
    /// Objects in provider list order.
    pub items: Vec<ListItem>,
    /// Cursor for the next page, present only when another item was observed.
    pub next_cursor: Option<ListCursor>,
}

/// Same-tenant copy or move request.
#[derive(Clone, Debug)]
pub struct TransferRequest {
    /// Canonical tenant namespace shared by source and destination.
    pub tenant_id: TenantId,
    /// Source opaque key.
    pub source: ObjectKey,
    /// Destination opaque key.
    pub destination: ObjectKey,
    /// Atomically reject an existing destination when true.
    pub create_only: bool,
}

/// Provider-native presign method.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PresignMethod {
    /// Presigned private object download.
    Get,
    /// Presigned direct object upload bound to one exact size and SHA-256 digest.
    Put {
        /// Exact uploaded object length.
        declared_length: u64,
        /// Required SHA-256 digest of the uploaded object.
        expected_sha256: [u8; 32],
    },
}

/// Request for a short-lived provider-native signed download or integrity-bound upload.
#[derive(Clone, Debug)]
pub struct PresignRequest {
    /// Canonical tenant namespace.
    pub tenant_id: TenantId,
    /// Opaque object key.
    pub key: ObjectKey,
    /// Signed method.
    pub method: PresignMethod,
    /// Requested validity duration.
    pub expires_in: Duration,
}

/// Credential-bearing signed URL and optional POST fields whose diagnostics are always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct PresignedUrl {
    url: Url,
    form_fields: BTreeMap<String, String>,
}

impl PresignedUrl {
    /// Explicitly exposes the signed URL for transport to an authorized caller.
    #[must_use]
    pub fn expose(&self) -> &Url {
        &self.url
    }

    /// Explicitly exposes required signed POST fields for a direct upload.
    #[must_use]
    pub fn expose_form_fields(&self) -> &BTreeMap<String, String> {
        &self.form_fields
    }
}

impl fmt::Debug for PresignedUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PresignedUrl(REDACTED)")
    }
}

/// Request that begins an explicit overwrite-only multipart lifecycle.
pub struct BeginMultipartRequest {
    /// Canonical tenant namespace.
    pub tenant_id: TenantId,
    /// Opaque object key.
    pub key: ObjectKey,
    /// Exact byte count all parts must total.
    pub declared_length: u64,
    /// Required SHA-256 digest across parts in ascending part order.
    pub expected_sha256: [u8; 32],
    /// Optional bounded content type.
    pub content_type: Option<String>,
    /// Bounded portable user metadata.
    pub metadata: BTreeMap<String, String>,
}

struct S3PostSigner {
    endpoint: Url,
    region: String,
    bucket: String,
    access_key_id: SecretString,
    secret_access_key: SecretString,
    session_token: Option<SecretString>,
}

impl S3PostSigner {
    fn from_config(config: &ObjectStorageConfig) -> Option<Self> {
        let ProviderConfig::S3Compatible {
            endpoint,
            region,
            bucket,
            access_key_id,
            secret_access_key,
            session_token,
            ..
        } = &config.provider
        else {
            return None;
        };
        Some(Self {
            endpoint: endpoint.clone(),
            region: region.clone(),
            bucket: bucket.clone(),
            access_key_id: access_key_id.clone(),
            secret_access_key: secret_access_key.clone(),
            session_token: session_token.clone(),
        })
    }

    fn sign(
        &self,
        tenant_id: TenantId,
        key: &ObjectKey,
        declared_length: u64,
        expected_sha256: [u8; 32],
        expires_in: Duration,
    ) -> Result<PresignedUrl, BlobStoreError> {
        let now = Utc::now();
        let date = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let expiration =
            now + chrono::Duration::from_std(expires_in).map_err(|_| BlobStoreError::Invalid)?;
        let algorithm = "AWS4-HMAC-SHA256";
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let credential = format!("{}/{scope}", self.access_key_id.expose_secret());
        let object_key = object_path(tenant_id, key).to_string();
        let checksum = BASE64_STANDARD.encode(expected_sha256);
        let mut conditions = vec![
            serde_json::json!({"bucket": self.bucket.as_str()}),
            serde_json::json!({"key": object_key.as_str()}),
            serde_json::json!({"x-amz-algorithm": algorithm}),
            serde_json::json!({"x-amz-credential": credential.as_str()}),
            serde_json::json!({"x-amz-date": amz_date.as_str()}),
            serde_json::json!({"x-amz-checksum-sha256": checksum.as_str()}),
            serde_json::json!(["content-length-range", declared_length, declared_length]),
        ];
        if let Some(token) = &self.session_token {
            conditions.push(serde_json::json!({"x-amz-security-token": token.expose_secret()}));
        }
        let policy_document = serde_json::json!({
            "expiration": expiration.to_rfc3339_opts(SecondsFormat::Secs, true),
            "conditions": conditions,
        });
        let policy = BASE64_STANDARD
            .encode(serde_json::to_vec(&policy_document).map_err(|_| BlobStoreError::Unavailable)?);

        let secret = self.secret_access_key.expose_secret();
        let mut prefixed_secret = Zeroizing::new(Vec::with_capacity(4 + secret.len()));
        prefixed_secret.extend_from_slice(b"AWS4");
        prefixed_secret.extend_from_slice(secret.as_bytes());
        let date_key = Zeroizing::new(hmac_sha256(&prefixed_secret, date.as_bytes())?);
        let region_key = Zeroizing::new(hmac_sha256(date_key.as_slice(), self.region.as_bytes())?);
        let service_key = Zeroizing::new(hmac_sha256(region_key.as_slice(), b"s3")?);
        let signing_key = Zeroizing::new(hmac_sha256(service_key.as_slice(), b"aws4_request")?);
        let signature = lower_hex(&hmac_sha256(signing_key.as_slice(), policy.as_bytes())?);

        let mut form_fields = BTreeMap::from([
            ("key".to_owned(), object_key),
            ("policy".to_owned(), policy),
            ("x-amz-algorithm".to_owned(), algorithm.to_owned()),
            ("x-amz-checksum-sha256".to_owned(), checksum),
            ("x-amz-credential".to_owned(), credential),
            ("x-amz-date".to_owned(), amz_date),
            ("x-amz-signature".to_owned(), signature),
        ]);
        if let Some(token) = &self.session_token {
            form_fields.insert(
                "x-amz-security-token".to_owned(),
                token.expose_secret().to_owned(),
            );
        }
        let url = self
            .endpoint
            .join(&format!("{}/", self.bucket))
            .map_err(|_| BlobStoreError::Config)?;
        Ok(PresignedUrl { url, form_fields })
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], BlobStoreError> {
    let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key)
        .map_err(|_| BlobStoreError::Unavailable)?;
    hmac::Mac::update(&mut mac, data);
    Ok(hmac::Mac::finalize(mac).into_bytes().into())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    output
}

/// Configured object-storage port with hidden provider paths and provider types.
#[derive(Clone)]
pub struct BlobStore {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<dyn ObjectStore>,
    signer: Option<Arc<dyn object_store::signer::Signer>>,
    post_signer: Option<S3PostSigner>,
    kind: ProviderKind,
    capabilities: ProviderCapabilities,
    limits: ObjectStorageLimits,
    lifecycle: AtomicU8,
    shutdown: CancellationToken,
}

impl BlobStore {
    /// Validates configuration and constructs the selected provider.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`BlobStoreError`] for unsafe configuration, forbidden local/test
    /// providers, invalid cloud credentials, or provider builder failure.
    pub fn build(
        config: ObjectStorageConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, BlobStoreError> {
        let post_signer = S3PostSigner::from_config(&config);
        let mut store = provider::build(config, environment)?;
        if let Some(post_signer) = post_signer {
            let Some(inner) = Arc::get_mut(&mut store.inner) else {
                return Err(BlobStoreError::Config);
            };
            inner.post_signer = Some(post_signer);
            inner.capabilities.presigned_put = true;
        }
        Ok(store)
    }

    pub(crate) fn from_backend(backend: StoreBackend, limits: ObjectStorageLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                store: backend.store,
                signer: backend.signer,
                post_signer: None,
                kind: backend.kind,
                capabilities: backend.capabilities,
                limits,
                lifecycle: AtomicU8::new(READY),
                shutdown: CancellationToken::new(),
            }),
        }
    }

    /// Returns a safe value-free provider status snapshot.
    #[must_use]
    pub fn status(&self) -> ProviderStatus {
        let lifecycle = match self.inner.lifecycle.load(Ordering::Acquire) {
            READY => ProviderLifecycle::Ready,
            DEGRADED => ProviderLifecycle::Degraded,
            DRAINING => ProviderLifecycle::Draining,
            _ => ProviderLifecycle::Shutdown,
        };
        ProviderStatus {
            kind: self.inner.kind,
            lifecycle,
            capabilities: self.inner.capabilities,
        }
    }

    /// Stops admission of new operations while allowing already-returned streams and multipart
    /// handles to continue to their original deadlines.
    pub fn begin_drain(&self) {
        self.inner.lifecycle.fetch_max(DRAINING, Ordering::AcqRel);
    }

    /// Cancels all outstanding work and terminally closes admission.
    pub fn shutdown(&self) {
        self.inner.lifecycle.fetch_max(SHUTDOWN, Ordering::AcqRel);
        self.inner.shutdown.cancel();
    }

    /// Streams an object into a bounded small-object put or fixed-size multipart upload.
    ///
    /// # Errors
    ///
    /// Returns stable validation, cancellation, deadline, checksum, conditional, multipart, or
    /// provider errors. Multipart is explicitly aborted on every pre-completion failure.
    pub async fn put_stream(
        &self,
        context: &OperationContext,
        request: PutRequest,
    ) -> Result<PutObjectResult, BlobStoreError> {
        let result = self.put_stream_inner(context, request).await;
        self.record("put", result.as_ref().map(|_| ()).map_err(|error| *error));
        result
    }

    async fn put_stream_inner(
        &self,
        context: &OperationContext,
        request: PutRequest,
    ) -> Result<PutObjectResult, BlobStoreError> {
        self.admit(context)?;
        self.validate_put(&request)?;
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        if request.declared_length <= self.inner.limits.multipart_part_size {
            self.put_bounded(context, request, deadline).await
        } else if request.condition == WriteCondition::Overwrite {
            self.put_multipart_stream(context, request, deadline).await
        } else {
            Err(BlobStoreError::Unsupported)
        }
    }

    async fn put_bounded(
        &self,
        context: &OperationContext,
        mut request: PutRequest,
        deadline: Instant,
    ) -> Result<PutObjectResult, BlobStoreError> {
        let mut payload = BytesMut::new();
        let mut total = 0_u64;
        let mut hasher = Sha256::new();
        while let Some(chunk) =
            next_upload_chunk(&mut request.stream, context, &self.inner.shutdown, deadline).await?
        {
            let chunk_length = u64::try_from(chunk.len()).map_err(|_| BlobStoreError::Size)?;
            total = total
                .checked_add(chunk_length)
                .ok_or(BlobStoreError::Size)?;
            if total > request.declared_length {
                return Err(BlobStoreError::Size);
            }
            if !chunk.is_empty() {
                hasher.update(&chunk);
                payload.extend_from_slice(&chunk);
            }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if total != request.declared_length {
            return Err(BlobStoreError::Size);
        }
        if digest != request.expected_sha256 {
            return Err(BlobStoreError::Checksum);
        }
        let (attributes, persistence) =
            self.attributes_for_write(request.content_type.as_deref(), &request.metadata);
        let options = PutOptions {
            mode: self.put_mode(request.condition)?,
            attributes,
            ..Default::default()
        };
        let path = object_path(request.tenant_id, &request.key);
        let put = await_provider(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner
                .store
                .put_opts(&path, PutPayload::from_bytes(payload.freeze()), options),
        )
        .await?
        .map_err(|error| map_provider_error(&error))?;
        Ok(PutObjectResult {
            version: ObjectVersion {
                e_tag: put.e_tag,
                version: put.version,
            },
            sha256: digest,
            attributes: persistence,
        })
    }

    // Upload, integrity, and abort sequencing form one cohesive multipart state machine.
    #[allow(clippy::too_many_lines)]
    async fn put_multipart_stream(
        &self,
        context: &OperationContext,
        mut request: PutRequest,
        deadline: Instant,
    ) -> Result<PutObjectResult, BlobStoreError> {
        let path = object_path(request.tenant_id, &request.key);
        let (attributes, persistence) =
            self.attributes_for_write(request.content_type.as_deref(), &request.metadata);
        let options = PutMultipartOptions {
            attributes,
            ..Default::default()
        };
        let mut upload = await_multipart_init(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner.store.put_multipart_opts(&path, options),
        )
        .await?;
        let part_size = usize::try_from(self.inner.limits.multipart_part_size)
            .map_err(|_| BlobStoreError::Config)?;
        let mut buffer = BytesMut::with_capacity(part_size);
        let mut total = 0_u64;
        let mut parts = 0_u16;
        let mut hasher = Sha256::new();

        let streamed = async {
            while let Some(mut chunk) =
                next_upload_chunk(&mut request.stream, context, &self.inner.shutdown, deadline)
                    .await?
            {
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| BlobStoreError::Size)?;
                total = total
                    .checked_add(chunk_length)
                    .ok_or(BlobStoreError::Size)?;
                if total > request.declared_length {
                    return Err(BlobStoreError::Size);
                }
                hasher.update(&chunk);
                while !chunk.is_empty() {
                    let remaining = part_size - buffer.len();
                    let take = remaining.min(chunk.len());
                    buffer.extend_from_slice(&chunk[..take]);
                    chunk.advance(take);
                    if buffer.len() == part_size {
                        parts = parts.checked_add(1).ok_or(BlobStoreError::Size)?;
                        if parts > self.inner.limits.max_multipart_parts {
                            return Err(BlobStoreError::Size);
                        }
                        let part = buffer.split().freeze();
                        await_provider(
                            context,
                            &self.inner.shutdown,
                            deadline,
                            upload.put_part(PutPayload::from_bytes(part)),
                        )
                        .await?
                        .map_err(|error| map_provider_error(&error))?;
                    }
                }
            }
            if !buffer.is_empty() {
                parts = parts.checked_add(1).ok_or(BlobStoreError::Size)?;
                if parts > self.inner.limits.max_multipart_parts {
                    return Err(BlobStoreError::Size);
                }
                let part = buffer.split().freeze();
                await_provider(
                    context,
                    &self.inner.shutdown,
                    deadline,
                    upload.put_part(PutPayload::from_bytes(part)),
                )
                .await?
                .map_err(|error| map_provider_error(&error))?;
            }
            if total != request.declared_length {
                return Err(BlobStoreError::Size);
            }
            let digest: [u8; 32] = hasher.finalize().into();
            if digest != request.expected_sha256 {
                return Err(BlobStoreError::Checksum);
            }
            Ok(digest)
        }
        .await;

        let digest = match streamed {
            Ok(digest) => digest,
            Err(error) => return abort_after_error(&mut *upload, error).await,
        };
        let put = match await_provider(context, &self.inner.shutdown, deadline, upload.complete())
            .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                return abort_after_error(&mut *upload, BlobStoreError::Multipart).await;
            }
            Err(error) => return abort_after_error(&mut *upload, error).await,
        };
        Ok(PutObjectResult {
            version: ObjectVersion {
                e_tag: put.e_tag,
                version: put.version,
            },
            sha256: digest,
            attributes: persistence,
        })
    }

    /// Begins an explicit overwrite-only multipart upload.
    ///
    /// The returned handle is already admitted and may finish during drain, but every part and
    /// completion remains bounded by the original total deadline. Dropping an incomplete handle
    /// schedules an adapter-owned abort with a separate bounded cleanup deadline.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, shutdown, cancellation, timeout, or multipart error.
    pub async fn begin_multipart(
        &self,
        context: &OperationContext,
        request: BeginMultipartRequest,
    ) -> Result<BlobMultipartUpload, BlobStoreError> {
        let result = self.begin_multipart_inner(context, request).await;
        self.record(
            "multipart_begin",
            result.as_ref().map(|_| ()).map_err(|error| *error),
        );
        result
    }

    async fn begin_multipart_inner(
        &self,
        context: &OperationContext,
        request: BeginMultipartRequest,
    ) -> Result<BlobMultipartUpload, BlobStoreError> {
        self.admit(context)?;
        self.validate_multipart_request(&request)?;
        let cleanup_handle =
            tokio::runtime::Handle::try_current().map_err(|_| BlobStoreError::Multipart)?;
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let (attributes, persistence) =
            self.attributes_for_write(request.content_type.as_deref(), &request.metadata);
        let path = object_path(request.tenant_id, &request.key);
        let upload = await_multipart_init(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner.store.put_multipart_opts(
                &path,
                PutMultipartOptions {
                    attributes,
                    ..Default::default()
                },
            ),
        )
        .await?;
        Ok(BlobMultipartUpload {
            inner: Arc::clone(&self.inner),
            cleanup_handle,
            deadline,
            persistence,
            expected_length: request.declared_length,
            expected_sha256: request.expected_sha256,
            state: Mutex::new(MultipartState {
                upload: Some(upload),
                next_part: 1,
                total: 0,
                hasher: Sha256::new(),
                final_seen: false,
                terminal: false,
            }),
        })
    }

    /// Opens a bounded streaming read without aggregating the response body.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, conditional, cancellation, deadline, or provider error.
    pub async fn get_stream(
        &self,
        context: &OperationContext,
        request: GetRequest,
    ) -> Result<GetObjectResult, BlobStoreError> {
        self.admit(context)?;
        Self::validate_get(&request)?;
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let path = object_path(request.tenant_id, &request.key);
        let options = GetOptions::new()
            .with_if_match(request.condition.if_match.clone())
            .with_if_none_match(request.condition.if_none_match.clone())
            .with_version(request.condition.version.clone())
            .with_range(request.range.map(|range| range.start..range.end));
        let result = match await_provider(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner.store.get_opts(&path, options),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                let error = map_provider_error(&error);
                self.record("get", Err(error));
                return Err(error);
            }
            Err(error) => {
                self.record("get", Err(error));
                return Err(error);
            }
        };
        let metadata =
            match self.metadata_from_get(request.tenant_id, &result.meta, &result.attributes) {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.record("get", Err(error));
                    return Err(error);
                }
            };
        let stream = download_stream(
            Arc::clone(&self.inner),
            context.cancellation.clone(),
            deadline,
            result.into_stream(),
            request.expected_sha256,
        );
        Ok(GetObjectResult { metadata, stream })
    }

    /// Returns metadata and native portable attributes without downloading the object body.
    ///
    /// # Errors
    ///
    /// Returns a stable shutdown, cancellation, deadline, metadata, or provider error.
    pub async fn head(
        &self,
        context: &OperationContext,
        tenant_id: TenantId,
        key: &ObjectKey,
    ) -> Result<ObjectMetadata, BlobStoreError> {
        self.admit(context)?;
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let path = object_path(tenant_id, key);
        let result = match await_provider(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner
                .store
                .get_opts(&path, GetOptions::new().with_head(true)),
        )
        .await
        {
            Ok(Ok(result)) => self.metadata_from_get(tenant_id, &result.meta, &result.attributes),
            Ok(Err(error)) => Err(map_provider_error(&error)),
            Err(error) => Err(error),
        };
        self.record("head", result.as_ref().map(|_| ()).map_err(|error| *error));
        result
    }

    /// Deletes an object. A missing object is normalized to success on every provider.
    ///
    /// # Errors
    ///
    /// Returns a stable shutdown, cancellation, deadline, or provider error.
    pub async fn delete(
        &self,
        context: &OperationContext,
        tenant_id: TenantId,
        key: &ObjectKey,
    ) -> Result<(), BlobStoreError> {
        self.admit(context)?;
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let path = object_path(tenant_id, key);
        let result = match await_provider(
            context,
            &self.inner.shutdown,
            deadline,
            self.inner.store.delete(&path),
        )
        .await
        {
            Ok(Ok(()) | Err(object_store::Error::NotFound { .. })) => Ok(()),
            Ok(Err(error)) => Err(map_provider_error(&error)),
            Err(error) => Err(error),
        };
        self.record("delete", result);
        result
    }

    /// Returns one bounded page from exactly one tenant namespace.
    ///
    /// Memory is bounded to `limit + 1`. Local filesystem rows are scanned only until the
    /// operation deadline so their unspecified provider order can be converted to a stable
    /// lexical page; ordered cloud and memory providers consume at most `limit + 1` rows.
    ///
    /// # Errors
    ///
    /// Returns a stable invalid-cursor, bound, shutdown, cancellation, deadline, or provider
    /// error.
    pub async fn list(
        &self,
        context: &OperationContext,
        request: ListRequest,
    ) -> Result<ListPage, BlobStoreError> {
        self.admit(context)?;
        if request.limit == 0 || request.limit > self.inner.limits.max_list_page_size {
            return Err(BlobStoreError::Invalid);
        }
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let prefix = namespace_path(request.tenant_id);
        let cursor_key = request.cursor.as_ref().map(ListCursor::key).transpose()?;
        if self.inner.kind == ProviderKind::Local {
            return self
                .list_local_ordered(
                    context,
                    request.tenant_id,
                    cursor_key.as_ref(),
                    request.limit,
                    deadline,
                )
                .await;
        }
        let offset = cursor_key
            .as_ref()
            .map(|key| object_path(request.tenant_id, key));
        let mut provider_stream: BoxStream<'_, object_store::Result<ObjectMeta>> = match &offset {
            Some(offset) => self.inner.store.list_with_offset(Some(&prefix), offset),
            None => self.inner.store.list(Some(&prefix)),
        };
        let mut items = Vec::with_capacity(usize::from(request.limit));
        let mut has_more = false;
        while items.len() <= usize::from(request.limit) {
            let next = match await_provider(
                context,
                &self.inner.shutdown,
                deadline,
                provider_stream.next(),
            )
            .await
            {
                Ok(next) => next,
                Err(error) => {
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            let Some(meta) = next else {
                break;
            };
            let meta = match meta {
                Ok(meta) => meta,
                Err(error) => {
                    let error = map_provider_error(&error);
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            if items.len() == usize::from(request.limit) {
                has_more = true;
                break;
            }
            let key = match key_from_location(request.tenant_id, &meta.location) {
                Ok(key) => key,
                Err(error) => {
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            items.push(list_item(key, meta));
        }
        let next_cursor = has_more
            .then(|| items.last().map(|item| ListCursor::from_key(&item.key)))
            .flatten();
        let page = ListPage { items, next_cursor };
        self.record("list", Ok(()));
        Ok(page)
    }

    async fn list_local_ordered(
        &self,
        context: &OperationContext,
        tenant_id: TenantId,
        cursor: Option<&ObjectKey>,
        limit: u16,
        deadline: Instant,
    ) -> Result<ListPage, BlobStoreError> {
        let prefix = namespace_path(tenant_id);
        let mut provider_stream = self.inner.store.list(Some(&prefix));
        let capacity = usize::from(limit) + 1;
        let mut selected = BTreeMap::new();
        let mut has_more = false;
        loop {
            let next = match await_provider(
                context,
                &self.inner.shutdown,
                deadline,
                provider_stream.next(),
            )
            .await
            {
                Ok(next) => next,
                Err(error) => {
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            let Some(meta) = next else {
                break;
            };
            let meta = match meta {
                Ok(meta) => meta,
                Err(error) => {
                    let error = map_provider_error(&error);
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            let key = match key_from_location(tenant_id, &meta.location) {
                Ok(key) => key,
                Err(error) => {
                    self.record("list", Err(error));
                    return Err(error);
                }
            };
            if cursor.is_some_and(|cursor| &key <= cursor) {
                continue;
            }
            selected.insert(key, meta);
            if selected.len() > capacity {
                selected.pop_last();
                has_more = true;
            }
        }
        if selected.len() > usize::from(limit) {
            selected.pop_last();
            has_more = true;
        }
        let items = selected
            .into_iter()
            .map(|(key, meta)| list_item(key, meta))
            .collect::<Vec<_>>();
        let next_cursor = has_more
            .then(|| items.last().map(|item| ListCursor::from_key(&item.key)))
            .flatten();
        let page = ListPage { items, next_cursor };
        self.record("list", Ok(()));
        Ok(page)
    }

    /// Copies an object within one tenant namespace.
    ///
    /// # Errors
    ///
    /// Returns stable conditional, shutdown, cancellation, deadline, unsupported, or provider
    /// errors.
    pub async fn copy(
        &self,
        context: &OperationContext,
        request: TransferRequest,
    ) -> Result<(), BlobStoreError> {
        self.transfer(context, request, false).await
    }

    /// Moves an object within one tenant namespace using provider conditional-target semantics.
    ///
    /// # Errors
    ///
    /// Returns stable conditional, shutdown, cancellation, deadline, unsupported, or provider
    /// errors.
    pub async fn move_object(
        &self,
        context: &OperationContext,
        request: TransferRequest,
    ) -> Result<(), BlobStoreError> {
        self.transfer(context, request, true).await
    }

    async fn transfer(
        &self,
        context: &OperationContext,
        request: TransferRequest,
        rename: bool,
    ) -> Result<(), BlobStoreError> {
        self.admit(context)?;
        if request.source == request.destination {
            return Err(BlobStoreError::Invalid);
        }
        if rename && !self.inner.capabilities.move_object {
            return Err(BlobStoreError::Unsupported);
        }
        if request.create_only && !self.inner.capabilities.conditional_copy {
            return Err(BlobStoreError::Unsupported);
        }
        let operation = if rename { "move" } else { "copy" };
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let source = object_path(request.tenant_id, &request.source);
        let destination = object_path(request.tenant_id, &request.destination);
        if self.inner.kind == ProviderKind::S3Compatible {
            const S3_MAX_COPY_BYTES: u64 = 5 * 1024 * 1024 * 1024;
            let source_meta = match await_provider(
                context,
                &self.inner.shutdown,
                deadline,
                self.inner.store.head(&source),
            )
            .await
            {
                Ok(Ok(meta)) => meta,
                Ok(Err(error)) => {
                    let error = map_provider_error(&error);
                    self.record(operation, Err(error));
                    return Err(error);
                }
                Err(error) => {
                    self.record(operation, Err(error));
                    return Err(error);
                }
            };
            if source_meta.size > S3_MAX_COPY_BYTES {
                self.record(operation, Err(BlobStoreError::Unsupported));
                return Err(BlobStoreError::Unsupported);
            }
        }
        let result = if rename {
            let mode = if request.create_only {
                RenameTargetMode::Create
            } else {
                RenameTargetMode::Overwrite
            };
            match await_provider(
                context,
                &self.inner.shutdown,
                deadline,
                self.inner.store.rename_opts(
                    &source,
                    &destination,
                    RenameOptions::new().with_target_mode(mode),
                ),
            )
            .await
            {
                Ok(result) => result.map_err(|error| map_provider_error(&error)),
                Err(error) => Err(error),
            }
        } else {
            let mode = if request.create_only {
                CopyMode::Create
            } else {
                CopyMode::Overwrite
            };
            match await_provider(
                context,
                &self.inner.shutdown,
                deadline,
                self.inner.store.copy_opts(
                    &source,
                    &destination,
                    CopyOptions::new().with_mode(mode),
                ),
            )
            .await
            {
                Ok(result) => result.map_err(|error| map_provider_error(&error)),
                Err(error) => Err(error),
            }
        };
        self.record(operation, result);
        result
    }

    /// Issues a bounded provider-native signed URL.
    ///
    /// GET signing uses the provider-native signer. Integrity-bound PUT signing is exposed only
    /// for S3-compatible providers through an exact `SigV4` POST policy.
    ///
    /// # Errors
    ///
    /// Returns a stable unsupported, invalid-expiry, shutdown, cancellation, deadline, or provider
    /// error.
    pub async fn presign(
        &self,
        context: &OperationContext,
        request: PresignRequest,
    ) -> Result<PresignedUrl, BlobStoreError> {
        self.admit(context)?;
        if request.expires_in < Duration::from_secs(1)
            || request.expires_in > self.inner.limits.max_signed_url_expiry
            || request.expires_in.subsec_nanos() != 0
        {
            return Err(BlobStoreError::Invalid);
        }
        let result = match request.method {
            PresignMethod::Get => {
                let signer = self
                    .inner
                    .signer
                    .as_ref()
                    .ok_or(BlobStoreError::Unsupported)?;
                let deadline = Instant::now() + self.inner.limits.operation_timeout;
                let path = object_path(request.tenant_id, &request.key);
                match await_provider(
                    context,
                    &self.inner.shutdown,
                    deadline,
                    signer.signed_url(Method::GET, &path, request.expires_in),
                )
                .await
                {
                    Ok(result) => result
                        .map(|url| PresignedUrl {
                            url,
                            form_fields: BTreeMap::new(),
                        })
                        .map_err(|error| map_provider_error(&error)),
                    Err(error) => Err(error),
                }
            }
            PresignMethod::Put {
                declared_length,
                expected_sha256,
            } => {
                if declared_length > self.inner.limits.max_object_size {
                    return Err(BlobStoreError::Size);
                }
                self.inner
                    .post_signer
                    .as_ref()
                    .ok_or(BlobStoreError::Unsupported)?
                    .sign(
                        request.tenant_id,
                        &request.key,
                        declared_length,
                        expected_sha256,
                        request.expires_in,
                    )
            }
        };
        self.record(
            "presign",
            result.as_ref().map(|_| ()).map_err(|error| *error),
        );
        result
    }

    pub(crate) async fn health_probe(&self) -> Result<(), BlobStoreError> {
        if self.inner.lifecycle.load(Ordering::Acquire) >= DRAINING {
            return Err(BlobStoreError::Shutdown);
        }
        let deadline = Instant::now() + self.inner.limits.operation_timeout;
        let context = OperationContext::uncancelled();
        let prefix = object_store::path::Path::from("rsk/objects");
        let mut stream = self.inner.store.list(Some(&prefix));
        let result =
            match await_provider(&context, &self.inner.shutdown, deadline, stream.next()).await {
                Ok(Some(Err(error))) => Err(map_provider_error(&error)),
                Ok(Some(Ok(_)) | None) => Ok(()),
                Err(error) => Err(error),
            };
        self.record("health", result);
        result
    }

    fn admit(&self, context: &OperationContext) -> Result<(), BlobStoreError> {
        if context.cancellation.is_cancelled() {
            return Err(BlobStoreError::Cancelled);
        }
        if self.inner.shutdown.is_cancelled()
            || self.inner.lifecycle.load(Ordering::Acquire) >= DRAINING
        {
            return Err(BlobStoreError::Shutdown);
        }
        Ok(())
    }

    fn validate_put(&self, request: &PutRequest) -> Result<(), BlobStoreError> {
        if request.declared_length > self.inner.limits.max_object_size {
            return Err(BlobStoreError::Size);
        }
        self.validate_attributes(request.content_type.as_deref(), &request.metadata)?;
        self.validate_condition(&request.condition)
    }

    fn validate_multipart_request(
        &self,
        request: &BeginMultipartRequest,
    ) -> Result<(), BlobStoreError> {
        if request.declared_length == 0
            || request.declared_length > self.inner.limits.max_object_size
        {
            return Err(BlobStoreError::Size);
        }
        self.validate_attributes(request.content_type.as_deref(), &request.metadata)
    }

    fn validate_get(request: &GetRequest) -> Result<(), BlobStoreError> {
        if request.range.is_some() && request.expected_sha256.is_some() {
            return Err(BlobStoreError::Invalid);
        }
        if let Some(range) = request.range
            && range.start >= range.end
        {
            return Err(BlobStoreError::Invalid);
        }
        for value in [
            request.condition.if_match.as_deref(),
            request.condition.if_none_match.as_deref(),
            request.condition.version.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            validate_condition_value(value)?;
        }
        Ok(())
    }

    fn validate_condition(&self, condition: &WriteCondition) -> Result<(), BlobStoreError> {
        match condition {
            WriteCondition::Overwrite => Ok(()),
            WriteCondition::Create if self.inner.capabilities.conditional_create => Ok(()),
            WriteCondition::Update { e_tag, version }
                if self.inner.capabilities.conditional_update
                    && (e_tag.is_some() || version.is_some()) =>
            {
                for value in [e_tag.as_deref(), version.as_deref()].into_iter().flatten() {
                    validate_condition_value(value)?;
                }
                Ok(())
            }
            WriteCondition::Create | WriteCondition::Update { .. } => {
                Err(BlobStoreError::Unsupported)
            }
        }
    }

    fn validate_attributes(
        &self,
        content_type: Option<&str>,
        metadata: &BTreeMap<String, String>,
    ) -> Result<(), BlobStoreError> {
        if let Some(content_type) = content_type
            && (content_type.is_empty()
                || content_type.len() > MAX_CONTENT_TYPE_BYTES
                || content_type.bytes().any(|byte| byte.is_ascii_control()))
        {
            return Err(BlobStoreError::Metadata);
        }
        if metadata.len() > usize::from(self.inner.limits.max_metadata_fields) {
            return Err(BlobStoreError::Metadata);
        }
        let mut aggregate = content_type.map_or(0_usize, str::len);
        for (key, value) in metadata {
            if key.is_empty()
                || key.len() > usize::from(self.inner.limits.max_metadata_key_bytes)
                || value.len() > usize::from(self.inner.limits.max_metadata_value_bytes)
                || !key.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_')
                })
                || value.bytes().any(|byte| byte.is_ascii_control())
            {
                return Err(BlobStoreError::Metadata);
            }
            aggregate = aggregate
                .checked_add(key.len())
                .and_then(|size| size.checked_add(value.len()))
                .ok_or(BlobStoreError::Metadata)?;
        }
        if aggregate
            > usize::try_from(self.inner.limits.max_metadata_bytes)
                .map_err(|_| BlobStoreError::Metadata)?
        {
            return Err(BlobStoreError::Metadata);
        }
        Ok(())
    }

    fn attributes_for_write(
        &self,
        content_type: Option<&str>,
        metadata: &BTreeMap<String, String>,
    ) -> (Attributes, AttributePersistence) {
        let requested = content_type.is_some() || !metadata.is_empty();
        if !requested {
            return (Attributes::new(), AttributePersistence::NotRequested);
        }
        if !self.inner.capabilities.native_attributes {
            return (Attributes::new(), AttributePersistence::Unsupported);
        }
        let mut attributes =
            Attributes::with_capacity(metadata.len() + usize::from(content_type.is_some()));
        if let Some(content_type) = content_type {
            attributes.insert(
                Attribute::ContentType,
                AttributeValue::from(content_type.to_owned()),
            );
        }
        for (key, value) in metadata {
            attributes.insert(
                Attribute::Metadata(key.to_owned().into()),
                AttributeValue::from(value.to_owned()),
            );
        }
        (attributes, AttributePersistence::Native)
    }

    fn put_mode(&self, condition: WriteCondition) -> Result<PutMode, BlobStoreError> {
        self.validate_condition(&condition)?;
        Ok(match condition {
            WriteCondition::Overwrite => PutMode::Overwrite,
            WriteCondition::Create => PutMode::Create,
            WriteCondition::Update { e_tag, version } => {
                PutMode::Update(UpdateVersion { e_tag, version })
            }
        })
    }

    fn metadata_from_get(
        &self,
        tenant_id: TenantId,
        meta: &ObjectMeta,
        attributes: &Attributes,
    ) -> Result<ObjectMetadata, BlobStoreError> {
        let mut portable = ObjectAttributes::default();
        if self.inner.capabilities.native_attributes {
            for (attribute, value) in attributes {
                match attribute {
                    Attribute::ContentType => {
                        portable.content_type = Some(value.as_ref().to_owned());
                    }
                    Attribute::Metadata(key) => {
                        portable
                            .metadata
                            .insert(key.as_ref().to_owned(), value.as_ref().to_owned());
                    }
                    _ => {}
                }
            }
            self.validate_attributes(portable.content_type.as_deref(), &portable.metadata)?;
        }
        Ok(ObjectMetadata {
            key: key_from_location(tenant_id, &meta.location)?,
            size: meta.size,
            last_modified: meta.last_modified,
            version: ObjectVersion {
                e_tag: meta.e_tag.clone(),
                version: meta.version.clone(),
            },
            attributes: portable,
        })
    }

    fn record(&self, operation: &'static str, result: Result<(), BlobStoreError>) {
        record_inner(&self.inner, operation, result);
    }
}

fn record_inner(inner: &Inner, operation: &'static str, result: Result<(), BlobStoreError>) {
    let (outcome, lifecycle) = if result.is_ok() {
        ("success", READY)
    } else {
        ("error", DEGRADED)
    };
    transition_operational_lifecycle(inner, lifecycle);
    metrics::counter!(
        "rsk_object_storage_operations_total",
        "provider" => inner.kind.label(),
        "operation" => operation,
        "outcome" => outcome,
    )
    .increment(1);
}

fn transition_operational_lifecycle(inner: &Inner, next: u8) {
    let mut current = inner.lifecycle.load(Ordering::Acquire);
    while current < DRAINING {
        match inner.lifecycle.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

impl fmt::Debug for BlobStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobStore")
            .field("kind", &self.inner.kind)
            .field("lifecycle", &self.status().lifecycle)
            .field("capabilities", &self.inner.capabilities)
            .finish()
    }
}

/// An admitted explicit multipart lifecycle.
pub struct BlobMultipartUpload {
    inner: Arc<Inner>,
    cleanup_handle: tokio::runtime::Handle,
    deadline: Instant,
    persistence: AttributePersistence,
    expected_length: u64,
    expected_sha256: [u8; 32],
    state: Mutex<MultipartState>,
}

struct MultipartState {
    upload: Option<Box<dyn MultipartUpload>>,
    next_part: u16,
    total: u64,
    hasher: Sha256,
    final_seen: bool,
    terminal: bool,
}

impl BlobMultipartUpload {
    /// Uploads exactly the next sequential part.
    ///
    /// Non-final parts must equal the configured fixed part size. A final part must be non-empty
    /// and no larger than that size. Part numbers start at one.
    ///
    /// # Errors
    ///
    /// Returns a stable ordering, size, cancellation, deadline, shutdown, or multipart error and
    /// aborts the provider upload when possible.
    pub async fn upload_part(
        &self,
        context: &OperationContext,
        part_number: u16,
        bytes: Bytes,
        final_part: bool,
    ) -> Result<(), BlobStoreError> {
        let result = self
            .upload_part_inner(context, part_number, bytes, final_part)
            .await;
        record_inner(&self.inner, "multipart_upload_part", result);
        result
    }

    async fn upload_part_inner(
        &self,
        context: &OperationContext,
        part_number: u16,
        bytes: Bytes,
        final_part: bool,
    ) -> Result<(), BlobStoreError> {
        let mut state = self.state.lock().await;
        if state.terminal {
            return Err(BlobStoreError::Multipart);
        }
        let Ok(part_size) = usize::try_from(self.inner.limits.multipart_part_size) else {
            return abort_state(&mut state, BlobStoreError::Multipart).await;
        };
        if state.final_seen
            || part_number != state.next_part
            || part_number > self.inner.limits.max_multipart_parts
            || bytes.is_empty()
            || bytes.len() > part_size
            || (!final_part && bytes.len() != part_size)
        {
            return abort_state(&mut state, BlobStoreError::Multipart).await;
        }
        let Ok(bytes_length) = u64::try_from(bytes.len()) else {
            return abort_state(&mut state, BlobStoreError::Size).await;
        };
        let Some(next_total) = state.total.checked_add(bytes_length) else {
            return abort_state(&mut state, BlobStoreError::Size).await;
        };
        if next_total > self.expected_length {
            return abort_state(&mut state, BlobStoreError::Size).await;
        }
        let Some(upload) = state.upload.as_mut() else {
            return Err(BlobStoreError::Multipart);
        };
        match await_provider(
            context,
            &self.inner.shutdown,
            self.deadline,
            upload.put_part(PutPayload::from_bytes(bytes.clone())),
        )
        .await
        {
            Ok(Ok(())) => {
                state.hasher.update(&bytes);
                state.total = next_total;
                state.final_seen = final_part;
                state.next_part = state
                    .next_part
                    .checked_add(1)
                    .ok_or(BlobStoreError::Multipart)?;
                Ok(())
            }
            Ok(Err(_)) => abort_state(&mut state, BlobStoreError::Multipart).await,
            Err(error) => abort_state(&mut state, error).await,
        }
    }

    /// Verifies total length and SHA-256, then completes the provider upload exactly once.
    ///
    /// # Errors
    ///
    /// Returns a stable incomplete, checksum, cancellation, deadline, shutdown, or multipart
    /// error. Validation and completion failures trigger a bounded abort attempt.
    pub async fn complete(
        &self,
        context: &OperationContext,
    ) -> Result<PutObjectResult, BlobStoreError> {
        let result = self.complete_inner(context).await;
        record_inner(
            &self.inner,
            "multipart_complete",
            result.as_ref().map(|_| ()).map_err(|error| *error),
        );
        result
    }

    async fn complete_inner(
        &self,
        context: &OperationContext,
    ) -> Result<PutObjectResult, BlobStoreError> {
        let mut state = self.state.lock().await;
        if state.terminal {
            return Err(BlobStoreError::Multipart);
        }
        if !state.final_seen {
            return abort_state(&mut state, BlobStoreError::Multipart).await;
        }
        if state.total != self.expected_length {
            return abort_state(&mut state, BlobStoreError::Size).await;
        }
        let digest: [u8; 32] = state.hasher.clone().finalize().into();
        if digest != self.expected_sha256 {
            return abort_state(&mut state, BlobStoreError::Checksum).await;
        }
        let Some(upload) = state.upload.as_mut() else {
            return Err(BlobStoreError::Multipart);
        };
        let put = match await_provider(
            context,
            &self.inner.shutdown,
            self.deadline,
            upload.complete(),
        )
        .await
        {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => {
                return abort_state(&mut state, BlobStoreError::Multipart).await;
            }
            Err(error) => return abort_state(&mut state, error).await,
        };
        state.terminal = true;
        state.upload = None;
        Ok(PutObjectResult {
            version: ObjectVersion {
                e_tag: put.e_tag,
                version: put.version,
            },
            sha256: digest,
            attributes: self.persistence,
        })
    }

    /// Idempotently aborts an incomplete provider upload with a bounded cleanup deadline.
    ///
    /// # Errors
    ///
    /// Returns [`BlobStoreError::Multipart`] if provider cleanup fails or its separate cleanup
    /// deadline is exhausted.
    pub async fn abort(&self) -> Result<(), BlobStoreError> {
        let result = self.abort_inner().await;
        record_inner(&self.inner, "multipart_abort", result);
        result
    }

    async fn abort_inner(&self) -> Result<(), BlobStoreError> {
        let mut state = self.state.lock().await;
        if state.terminal {
            return Ok(());
        }
        let Some(upload) = state.upload.as_mut() else {
            state.terminal = true;
            return Ok(());
        };
        let result = tokio::time::timeout(MULTIPART_CLEANUP_TIMEOUT, upload.abort()).await;
        state.terminal = true;
        state.upload = None;
        match result {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) | Err(_) => Err(BlobStoreError::Multipart),
        }
    }
}

impl fmt::Debug for BlobMultipartUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlobMultipartUpload")
            .field("provider", &self.inner.kind)
            .finish_non_exhaustive()
    }
}

impl Drop for BlobMultipartUpload {
    fn drop(&mut self) {
        let state = self.state.get_mut();
        if state.terminal {
            return;
        }
        state.terminal = true;
        let Some(mut upload) = state.upload.take() else {
            return;
        };
        let cleanup = self.cleanup_handle.spawn(async move {
            let _outcome = tokio::time::timeout(MULTIPART_CLEANUP_TIMEOUT, upload.abort()).await;
        });
        std::mem::drop(cleanup);
    }
}

fn validate_condition_value(value: &str) -> Result<(), BlobStoreError> {
    if value.is_empty()
        || value.len() > MAX_CONDITION_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(BlobStoreError::Invalid);
    }
    Ok(())
}

fn list_item(key: ObjectKey, meta: ObjectMeta) -> ListItem {
    ListItem {
        key,
        size: meta.size,
        last_modified: meta.last_modified,
        version: ObjectVersion {
            e_tag: meta.e_tag,
            version: meta.version,
        },
    }
}

async fn next_upload_chunk(
    stream: &mut ByteStream,
    context: &OperationContext,
    shutdown: &CancellationToken,
    deadline: Instant,
) -> Result<Option<Bytes>, BlobStoreError> {
    await_provider(context, shutdown, deadline, stream.next())
        .await?
        .transpose()
}

async fn await_provider<T>(
    context: &OperationContext,
    shutdown: &CancellationToken,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, BlobStoreError> {
    tokio::pin!(future);
    tokio::select! {
        biased;
        () = context.cancellation.cancelled() => Err(BlobStoreError::Cancelled),
        () = shutdown.cancelled() => Err(BlobStoreError::Shutdown),
        () = tokio::time::sleep_until(deadline) => Err(BlobStoreError::Timeout),
        result = &mut future => Ok(result),
    }
}

async fn await_multipart_init<F>(
    context: &OperationContext,
    shutdown: &CancellationToken,
    deadline: Instant,
    future: F,
) -> Result<Box<dyn MultipartUpload>, BlobStoreError>
where
    F: Future<Output = object_store::Result<Box<dyn MultipartUpload>>>,
{
    tokio::pin!(future);
    let interrupted = tokio::select! {
        biased;
        () = context.cancellation.cancelled() => BlobStoreError::Cancelled,
        () = shutdown.cancelled() => BlobStoreError::Shutdown,
        result = &mut future => return result.map_err(|error| map_provider_error(&error)),
        () = tokio::time::sleep_until(deadline) => BlobStoreError::Timeout,
    };
    let cleanup_deadline = Instant::now() + MULTIPART_CLEANUP_TIMEOUT;
    let initialization = tokio::select! {
        biased;
        result = &mut future => Some(result),
        () = tokio::time::sleep_until(cleanup_deadline) => None,
    };
    match initialization {
        Some(Ok(mut upload)) => {
            abort_after_error_until(&mut *upload, cleanup_deadline, interrupted).await
        }
        Some(Err(_)) | None => Err(interrupted),
    }
}

async fn abort_after_error<T>(
    upload: &mut dyn MultipartUpload,
    original: BlobStoreError,
) -> Result<T, BlobStoreError> {
    abort_after_error_until(upload, Instant::now() + MULTIPART_CLEANUP_TIMEOUT, original).await
}

async fn abort_after_error_until<T>(
    upload: &mut dyn MultipartUpload,
    deadline: Instant,
    original: BlobStoreError,
) -> Result<T, BlobStoreError> {
    match tokio::time::timeout_at(deadline, upload.abort()).await {
        Ok(Ok(())) => Err(original),
        Ok(Err(_)) | Err(_) => Err(BlobStoreError::Multipart),
    }
}

async fn abort_state<T>(
    state: &mut MultipartState,
    original: BlobStoreError,
) -> Result<T, BlobStoreError> {
    let Some(upload) = state.upload.as_mut() else {
        state.terminal = true;
        return Err(original);
    };
    let result = tokio::time::timeout(MULTIPART_CLEANUP_TIMEOUT, upload.abort()).await;
    state.terminal = true;
    state.upload = None;
    match result {
        Ok(Ok(())) => Err(original),
        Ok(Err(_)) | Err(_) => Err(BlobStoreError::Multipart),
    }
}

struct DownloadState {
    inner: Arc<Inner>,
    source: BoxStream<'static, object_store::Result<Bytes>>,
    cancellation: CancellationToken,
    deadline: Instant,
    expected_sha256: Option<[u8; 32]>,
    hasher: Sha256,
    finished: bool,
}

fn download_stream(
    inner: Arc<Inner>,
    cancellation: CancellationToken,
    deadline: Instant,
    source: BoxStream<'static, object_store::Result<Bytes>>,
    expected_sha256: Option<[u8; 32]>,
) -> ByteStream {
    let state = DownloadState {
        inner,
        source,
        cancellation,
        deadline,
        expected_sha256,
        hasher: Sha256::new(),
        finished: false,
    };
    Box::pin(futures::stream::unfold(state, |mut state| async move {
        if state.finished {
            return None;
        }
        let next = tokio::select! {
            biased;
            () = state.cancellation.cancelled() => Err(BlobStoreError::Cancelled),
            () = state.inner.shutdown.cancelled() => Err(BlobStoreError::Shutdown),
            () = tokio::time::sleep_until(state.deadline) => Err(BlobStoreError::Timeout),
            next = state.source.next() => match next {
                Some(Ok(bytes)) => Ok(Some(bytes)),
                Some(Err(error)) => Err(map_provider_error(&error)),
                None => Ok(None),
            },
        };
        match next {
            Ok(Some(bytes)) => {
                if state.expected_sha256.is_some() {
                    state.hasher.update(&bytes);
                }
                Some((Ok(bytes), state))
            }
            Ok(None) => {
                state.finished = true;
                if let Some(expected) = state.expected_sha256 {
                    let actual: [u8; 32] = state.hasher.clone().finalize().into();
                    if actual != expected {
                        record_inner(&state.inner, "get_stream", Err(BlobStoreError::Checksum));
                        return Some((Err(BlobStoreError::Checksum), state));
                    }
                }
                record_inner(&state.inner, "get_stream", Ok(()));
                None
            }
            Err(error) => {
                state.finished = true;
                record_inner(&state.inner, "get_stream", Err(error));
                Some((Err(error), state))
            }
        }
    }))
}
