//! PostgreSQL-backed upload security and lifecycle contracts.

use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fmt,
    fs::{FileTimes, OpenOptions},
    io,
    str::FromStr as _,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, SystemTime},
};

use bytes::Bytes;
use futures::{TryStreamExt as _, future::BoxFuture, stream};
use http::header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use rsk_auth_core::{SubjectId, TenantId};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_object_storage::{
    BlobStore, BlobStoreError, ByteStream, GetCondition, GetRequest, ObjectKey,
    ObjectStorageConfig, ObjectStorageLimits, OperationContext, ProviderConfig, PutRequest,
    WriteCondition,
};
use rsk_outbound_http::{OutboundUrlPolicy, OutboundUrlPolicyConfig};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{CleanDirectory, PostgresFixture};
use rsk_upload_workflow::{
    CompleteUploadRequest, DeclaredMime, InitiateUploadRequest, InitiatedUpload, LeasedWork,
    MalwareScanner, NormalizedFilename, OpenDownloadRequest, PostgresUploadRepository,
    ProxiedUploadContract, ReconcilerConfig, RejectionReason, ScanMetadata, ScanVerdict,
    ScannerFailure, ScannerSession, Sha256Digest, UploadAction, UploadAuthorization,
    UploadAuthorizer, UploadError, UploadId, UploadReconciler, UploadState, UploadWorkflow,
    WorkKind, max_object_bytes,
};
use sha2::{Digest as _, Sha256};
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const UPLOAD_HEAD: i64 = 2_026_082_320;
const MAX_FAKE_OBSERVATIONS: usize = 32;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct Harness {
    workflow: UploadWorkflow,
    repository: PostgresUploadRepository,
    store: BlobStore,
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

#[derive(Default)]
struct BoundedAuthorizer {
    denied: Mutex<Vec<UploadAction>>,
    observations: Mutex<VecDeque<UploadAuthorization>>,
}

impl BoundedAuthorizer {
    fn deny_only(&self, action: UploadAction) {
        *mutex_guard(&self.denied) = vec![action];
    }

    fn allow_all(&self) {
        mutex_guard(&self.denied).clear();
    }

    fn observations(&self) -> Vec<UploadAuthorization> {
        mutex_guard(&self.observations).iter().copied().collect()
    }
}

impl fmt::Debug for BoundedAuthorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedAuthorizer")
            .field("denied_action_count", &mutex_guard(&self.denied).len())
            .field("observation_count", &mutex_guard(&self.observations).len())
            .finish()
    }
}

impl UploadAuthorizer for BoundedAuthorizer {
    fn authorize(&self, request: UploadAuthorization) -> BoxFuture<'_, Result<(), UploadError>> {
        push_bounded(&mut mutex_guard(&self.observations), request);
        let denied = mutex_guard(&self.denied).contains(&request.action);
        Box::pin(async move {
            if denied {
                Err(UploadError::Unauthorized)
            } else {
                Ok(())
            }
        })
    }
}

#[derive(Clone, Copy)]
enum ScannerPlan {
    Clean,
    Malicious,
    RetryableFinish,
}

#[derive(Clone)]
struct ScanObservation {
    metadata: ScanMetadata,
    byte_count: u64,
    chunk_count: u64,
    actual_sha256: [u8; 32],
    eof_seen: bool,
}

#[derive(Default)]
struct BoundedStreamingScanner {
    plans: Mutex<BTreeMap<UploadId, ScannerPlan>>,
    observations: Arc<Mutex<VecDeque<ScanObservation>>>,
}

impl BoundedStreamingScanner {
    fn set_plan(&self, upload_id: UploadId, plan: ScannerPlan) {
        mutex_guard(&self.plans).insert(upload_id, plan);
    }

    fn observations(&self) -> Vec<ScanObservation> {
        mutex_guard(&self.observations).iter().cloned().collect()
    }
}

impl fmt::Debug for BoundedStreamingScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedStreamingScanner")
            .field("planned_session_count", &mutex_guard(&self.plans).len())
            .field("observation_count", &mutex_guard(&self.observations).len())
            .finish()
    }
}

impl MalwareScanner for BoundedStreamingScanner {
    fn start<'a>(
        &'a self,
        metadata: ScanMetadata,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ScannerSession>, ScannerFailure>> {
        let plan = mutex_guard(&self.plans)
            .get(&metadata.upload_id)
            .copied()
            .unwrap_or(ScannerPlan::Clean);
        let observations = Arc::clone(&self.observations);
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ScannerFailure::Retryable);
            }
            Ok(Box::new(StreamingScannerSession {
                metadata,
                plan,
                observations,
                byte_count: 0,
                chunk_count: 0,
                hasher: Sha256::new(),
            }) as Box<dyn ScannerSession>)
        })
    }
}

struct StreamingScannerSession {
    metadata: ScanMetadata,
    plan: ScannerPlan,
    observations: Arc<Mutex<VecDeque<ScanObservation>>>,
    byte_count: u64,
    chunk_count: u64,
    hasher: Sha256,
}

impl StreamingScannerSession {
    fn record_eof(&self) {
        push_bounded(
            &mut mutex_guard(&self.observations),
            ScanObservation {
                metadata: self.metadata,
                byte_count: self.byte_count,
                chunk_count: self.chunk_count,
                actual_sha256: self.hasher.clone().finalize().into(),
                eof_seen: true,
            },
        );
    }
}

impl ScannerSession for StreamingScannerSession {
    fn scan_chunk<'a>(
        &'a mut self,
        chunk: Bytes,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ScannerFailure>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ScannerFailure::Retryable);
            }
            self.byte_count = self.byte_count.saturating_add(byte_len(&chunk));
            self.chunk_count = self.chunk_count.saturating_add(1);
            self.hasher.update(&chunk);
            Ok(())
        })
    }

    fn finish<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ScanVerdict, ScannerFailure>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ScannerFailure::Retryable);
            }
            self.record_eof();
            match self.plan {
                ScannerPlan::Clean => Ok(ScanVerdict::Clean),
                ScannerPlan::Malicious => Ok(ScanVerdict::Malicious),
                ScannerPlan::RetryableFinish => Err(ScannerFailure::Retryable),
            }
        })
    }
}

struct FinishGateScanner {
    gate: Mutex<Option<FinishGate>>,
}

struct FinishGate {
    reached: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

impl FinishGateScanner {
    fn new() -> (Arc<Self>, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (reached, reached_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        (
            Arc::new(Self {
                gate: Mutex::new(Some(FinishGate {
                    reached,
                    release: release_rx,
                })),
            }),
            reached_rx,
            release,
        )
    }
}

impl fmt::Debug for FinishGateScanner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinishGateScanner")
            .field("gate_available", &mutex_guard(&self.gate).is_some())
            .finish()
    }
}

impl MalwareScanner for FinishGateScanner {
    fn start<'a>(
        &'a self,
        _metadata: ScanMetadata,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ScannerSession>, ScannerFailure>> {
        let gate = mutex_guard(&self.gate).take();
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ScannerFailure::Retryable);
            }
            let gate = gate.ok_or(ScannerFailure::Permanent)?;
            Ok(Box::new(FinishGateSession {
                reached: Some(gate.reached),
                release: Some(gate.release),
            }) as Box<dyn ScannerSession>)
        })
    }
}

struct FinishGateSession {
    reached: Option<oneshot::Sender<()>>,
    release: Option<oneshot::Receiver<()>>,
}

impl ScannerSession for FinishGateSession {
    fn scan_chunk<'a>(
        &'a mut self,
        _chunk: Bytes,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ScannerFailure>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                Err(ScannerFailure::Retryable)
            } else {
                Ok(())
            }
        })
    }

    fn finish<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ScanVerdict, ScannerFailure>> {
        Box::pin(async move {
            let reached = self.reached.take().ok_or(ScannerFailure::Permanent)?;
            reached.send(()).map_err(|()| ScannerFailure::Permanent)?;
            let release = self.release.take().ok_or(ScannerFailure::Permanent)?;
            release.await.map_err(|_| ScannerFailure::Permanent)?;
            if cancellation.is_cancelled() {
                Err(ScannerFailure::Retryable)
            } else {
                Ok(ScanVerdict::Clean)
            }
        })
    }
}

fn mutex_guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn push_bounded<T>(observations: &mut VecDeque<T>, value: T) {
    if observations.len() == MAX_FAKE_OBSERVATIONS {
        observations.pop_front();
    }
    observations.push_back(value);
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 8,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-upload-contract-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(5),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

fn storage_limits() -> ObjectStorageLimits {
    ObjectStorageLimits {
        operation_timeout: Duration::from_secs(3),
        connect_timeout: Duration::from_secs(1),
        max_signed_url_expiry: Duration::from_secs(60),
        retry_timeout: Duration::from_secs(1),
        ..ObjectStorageLimits::default()
    }
}

async fn memory_store() -> Result<BlobStore, BlobStoreError> {
    let policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig::default())
        .map_err(|_| BlobStoreError::Config)?;
    BlobStore::build(
        ObjectStorageConfig {
            provider: ProviderConfig::Memory,
            limits: storage_limits(),
        },
        DeploymentEnvironment::Test,
        &policy,
    )
    .await
}

async fn harness_with_store(
    store: BlobStore,
    authorizer: Arc<BoundedAuthorizer>,
) -> TestResult<Harness> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, UPLOAD_HEAD)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    let repository = PostgresUploadRepository::new(pool.clone());
    let workflow = UploadWorkflow::new(repository.clone(), store.clone(), authorizer);
    Ok(Harness {
        workflow,
        repository,
        store,
        pool,
        _fixture: fixture,
    })
}

async fn memory_harness(authorizer: Arc<BoundedAuthorizer>) -> TestResult<Harness> {
    harness_with_store(memory_store().await?, authorizer).await
}

async fn seed_tenant(pool: &PostgresPool) -> TestResult<TenantId> {
    let tenant_id = TenantId::new();
    let owner_id = SubjectId::new();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, clock_timestamp())")
        .bind(owner_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO organizations (
            id, name, status, version, created_at, updated_at
         ) VALUES ($1, 'Upload contract tenant', 'active', 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(tenant_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships (
            organization_id, user_id, role, status, grant_version, created_at, updated_at
         ) VALUES ($1, $2, 'owner', 'active', 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(tenant_id.as_uuid())
    .bind(owner_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(tenant_id)
}

async fn seed_user(pool: &PostgresPool, user_id: SubjectId) -> TestResult {
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, clock_timestamp())")
        .bind(user_id.as_uuid())
        .execute(&mut *connection)
        .await?;
    Ok(())
}

fn png_payload(label: &'static [u8]) -> Bytes {
    let mut payload = Vec::with_capacity(8 + label.len());
    payload.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    payload.extend_from_slice(label);
    Bytes::from(payload)
}

fn byte_len(bytes: &Bytes) -> u64 {
    u64::try_from(bytes.len()).unwrap_or(u64::MAX)
}

fn digest(bytes: &Bytes) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn upload_request(
    upload_id: UploadId,
    tenant_id: TenantId,
    actor_id: SubjectId,
    filename: &str,
    declared_size: u64,
    expected_sha256: Sha256Digest,
    declared_mime: DeclaredMime,
) -> InitiateUploadRequest {
    InitiateUploadRequest {
        upload_id,
        tenant_id,
        actor_id,
        filename: filename.to_owned(),
        declared_size,
        expected_sha256,
        declared_mime,
        direct_upload_expires_in: Duration::from_secs(1),
        pending_upload_ttl: Duration::from_secs(31),
    }
}

fn proxied_contract(outcome: &InitiatedUpload) -> Result<ProxiedUploadContract, UploadError> {
    match outcome {
        InitiatedUpload::Proxied(contract) => Ok(*contract),
        InitiatedUpload::Direct(_) | InitiatedUpload::AlreadyStarted(_) => Err(UploadError::State),
    }
}

async fn initiate_proxied(
    harness: &Harness,
    request: InitiateUploadRequest,
) -> TestResult<ProxiedUploadContract> {
    let outcome = harness
        .workflow
        .initiate(&OperationContext::uncancelled(), request)
        .await?;
    Ok(proxied_contract(&outcome)?)
}

fn chunked(bytes: &Bytes) -> ByteStream {
    let split = bytes.len().min(5);
    let first = bytes.slice(..split);
    let second = bytes.slice(split..);
    Box::pin(stream::iter([
        Ok::<Bytes, BlobStoreError>(first),
        Ok::<Bytes, BlobStoreError>(second),
    ]))
}

fn one_chunk(bytes: Bytes) -> ByteStream {
    Box::pin(stream::once(
        async move { Ok::<Bytes, BlobStoreError>(bytes) },
    ))
}

fn paused_chunk(bytes: Bytes) -> (ByteStream, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (started, started_rx) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let stream = Box::pin(stream::once(async move {
        let _ = started.send(());
        if release_rx.await.is_err() {
            return Err(BlobStoreError::Cancelled);
        }
        Ok(bytes)
    }));
    (stream, started_rx, release)
}

async fn put_direct(
    harness: &Harness,
    tenant_id: TenantId,
    upload_id: UploadId,
    bytes: Bytes,
) -> TestResult {
    let upload = harness.repository.lookup(tenant_id, upload_id).await?;
    harness
        .store
        .put_stream(
            &OperationContext::uncancelled(),
            PutRequest {
                tenant_id,
                key: upload.object_key,
                declared_length: byte_len(&bytes),
                expected_sha256: digest(&bytes).as_bytes(),
                content_type: Some(upload.declared_mime.as_str().to_owned()),
                metadata: BTreeMap::new(),
                condition: WriteCondition::Overwrite,
                stream: one_chunk(bytes),
            },
        )
        .await?;
    Ok(())
}

async fn put_proxied(
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    upload_id: UploadId,
    bytes: Bytes,
) -> TestResult {
    harness
        .workflow
        .put_proxied(
            &OperationContext::uncancelled(),
            tenant_id,
            actor_id,
            upload_id,
            chunked(&bytes),
        )
        .await?;
    Ok(())
}

async fn complete(
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    upload_id: UploadId,
) -> Result<rsk_upload_workflow::Upload, UploadError> {
    harness
        .workflow
        .complete(
            &OperationContext::uncancelled(),
            CompleteUploadRequest {
                upload_id,
                tenant_id,
                actor_id,
            },
        )
        .await
}

async fn read_object(
    store: &BlobStore,
    tenant_id: TenantId,
    key: ObjectKey,
    expected_sha256: Sha256Digest,
) -> TestResult<Bytes> {
    let object = store
        .get_stream(
            &OperationContext::uncancelled(),
            GetRequest {
                tenant_id,
                key,
                range: None,
                condition: GetCondition::default(),
                expected_sha256: Some(expected_sha256.as_bytes()),
            },
        )
        .await?;
    let bytes = object
        .stream
        .try_fold(Vec::new(), |mut collected, chunk| async move {
            collected.extend_from_slice(&chunk);
            Ok(collected)
        })
        .await?;
    Ok(Bytes::from(bytes))
}

fn reconciler_config(owner: &str) -> ReconcilerConfig {
    ReconcilerConfig {
        lease_owner: owner.to_owned(),
        claim_batch: 16,
        lease_duration: Duration::from_secs(30),
        work_timeout: Duration::from_secs(5),
        finalization_margin: Duration::from_secs(1),
        poll_interval: Duration::from_millis(10),
        max_attempts: 5,
        initial_retry: Duration::from_millis(1),
        max_retry: Duration::from_secs(1),
        orphan_grace: Duration::from_secs(60),
    }
}

fn reconciler(
    harness: &Harness,
    scanner: Arc<BoundedStreamingScanner>,
    config: ReconcilerConfig,
) -> Result<UploadReconciler, UploadError> {
    let scanner: Arc<dyn MalwareScanner> = scanner;
    UploadReconciler::new(
        harness.repository.clone(),
        harness.store.clone(),
        scanner,
        config,
    )
}

async fn create_pending(
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    filename: &str,
    payload: &Bytes,
    mime: DeclaredMime,
) -> TestResult<InitiateUploadRequest> {
    let request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        filename,
        byte_len(payload),
        digest(payload),
        mime,
    );
    initiate_proxied(harness, request.clone()).await?;
    Ok(request)
}

async fn create_quarantined(
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    filename: &str,
    payload: Bytes,
) -> TestResult<InitiateUploadRequest> {
    let request = create_pending(
        harness,
        tenant_id,
        actor_id,
        filename,
        &payload,
        DeclaredMime::Png,
    )
    .await?;
    put_proxied(harness, tenant_id, actor_id, request.upload_id, payload).await?;
    let upload = complete(harness, tenant_id, actor_id, request.upload_id).await?;
    if upload.state != UploadState::Quarantined {
        return Err(io::Error::other("completion did not quarantine the upload").into());
    }
    Ok(request)
}

fn only_work(mut work: Vec<LeasedWork>) -> TestResult<LeasedWork> {
    if work.len() != 1 {
        return Err(io::Error::other("expected exactly one leased work item").into());
    }
    match work.pop() {
        Some(item) => Ok(item),
        None => Err(io::Error::other("leased work item disappeared").into()),
    }
}

async fn expire_pending(pool: &PostgresPool, upload_id: UploadId) -> TestResult {
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("ALTER TABLE uploads DISABLE TRIGGER uploads_immutable_identity")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE uploads
         SET pending_expires_at = created_at + INTERVAL '1 microsecond',
             updated_at = clock_timestamp(), revision = revision + 1
         WHERE id = $1",
    )
    .bind(upload_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("ALTER TABLE uploads ENABLE TRIGGER uploads_immutable_identity")
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok(())
}

async fn advance_direct_credential_clock(pool: &PostgresPool, upload_id: UploadId) -> TestResult {
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("ALTER TABLE uploads DISABLE TRIGGER uploads_immutable_identity")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE uploads
         SET direct_credential_expires_at = created_at + INTERVAL '1 microsecond',
             updated_at = clock_timestamp(), revision = revision + 1
         WHERE id = $1",
    )
    .bind(upload_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query("ALTER TABLE uploads ENABLE TRIGGER uploads_immutable_identity")
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE upload_reconciliation
         SET available_at = clock_timestamp(), updated_at = clock_timestamp()
         WHERE upload_id = $1 AND kind = 'verify' AND completed_at IS NULL",
    )
    .bind(upload_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

#[test]
fn public_filename_contract_strips_paths_controls_and_preserves_utf8_bounds() -> TestResult {
    let normalized = NormalizedFilename::normalize("C:\\private\\\u{202e} résumé\t final.png ")?;
    assert_eq!(normalized.as_str(), "résumé final.png");
    assert!(NormalizedFilename::parse("résumé\tfinal.png").is_err());
    let bounded = NormalizedFilename::normalize(&"é".repeat(100))?;
    assert_eq!(bounded.as_str().len(), 180);
    assert!(bounded.as_str().is_char_boundary(bounded.as_str().len()));
    Ok(())
}

#[test]
fn public_digest_contract_accepts_exact_hex_and_redacts_diagnostics() -> TestResult {
    let expected = Sha256Digest::from_bytes([0xab; 32]);
    assert_eq!(Sha256Digest::from_hex(&"AB".repeat(32))?, expected);
    assert_eq!(Sha256Digest::from_hex(&"ab".repeat(32))?, expected);
    assert_eq!(Sha256Digest::from_hex("ab"), Err(UploadError::Invalid));
    assert_eq!(
        Sha256Digest::from_hex(&format!("{}z", "ab".repeat(31))),
        Err(UploadError::Invalid)
    );
    assert_eq!(format!("{expected:?}"), "Sha256Digest(REDACTED)");
    Ok(())
}

#[test]
fn public_config_contract_enforces_concurrency_deadline_and_object_bounds() {
    let valid = reconciler_config("upload.contract-1");
    assert_eq!(valid.validate(), Ok(()));
    let mut oversized_batch = valid.clone();
    oversized_batch.claim_batch = 17;
    assert_eq!(oversized_batch.validate(), Err(UploadError::Invalid));
    let mut unsafe_owner = valid.clone();
    unsafe_owner.lease_owner = "owner/secret".to_owned();
    assert_eq!(unsafe_owner.validate(), Err(UploadError::Invalid));
    let mut short_lease = valid.clone();
    short_lease.lease_duration = Duration::from_secs(5);
    assert_eq!(short_lease.validate(), Err(UploadError::Invalid));
    let mut short_orphan_grace = valid;
    short_orphan_grace.orphan_grace = Duration::from_secs(59);
    assert_eq!(short_orphan_grace.validate(), Err(UploadError::Invalid));
    assert_eq!(max_object_bytes(), 5 * 1024 * 1024 * 1024);
}

#[tokio::test]
async fn initiation_retry_retains_one_identity_and_never_reissues_after_completion() -> TestResult {
    let authorizer = Arc::new(BoundedAuthorizer::default());
    let harness = memory_harness(Arc::clone(&authorizer)).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let other_tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"retry-stable-form");
    let request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        "stable.png",
        byte_len(&payload),
        digest(&payload),
        DeclaredMime::Png,
    );
    let first = initiate_proxied(&harness, request.clone()).await?;
    let first_key = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?
        .object_key;
    let retry = initiate_proxied(&harness, request.clone()).await?;
    let retry_key = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?
        .object_key;
    assert_eq!(retry, first);
    assert_eq!(retry_key, first_key);

    let mut changed_filename = request.clone();
    changed_filename.filename = "different.png".to_owned();
    assert!(matches!(
        harness
            .workflow
            .initiate(&OperationContext::uncancelled(), changed_filename)
            .await,
        Err(UploadError::Conflict)
    ));
    let mut changed_size = request.clone();
    changed_size.declared_size = changed_size.declared_size.saturating_add(1);
    assert!(matches!(
        harness
            .workflow
            .initiate(&OperationContext::uncancelled(), changed_size)
            .await,
        Err(UploadError::Conflict)
    ));
    let mut changed_actor = request.clone();
    changed_actor.actor_id = SubjectId::new();
    assert!(matches!(
        harness
            .workflow
            .initiate(&OperationContext::uncancelled(), changed_actor)
            .await,
        Err(UploadError::Conflict)
    ));
    let mut changed_tenant = request.clone();
    changed_tenant.tenant_id = other_tenant_id;
    assert!(matches!(
        harness
            .workflow
            .initiate(&OperationContext::uncancelled(), changed_tenant)
            .await,
        Err(UploadError::Conflict)
    ));

    let mut connection = harness.pool.acquire().await?;
    let row = sqlx::query(
        "SELECT COUNT(*) AS upload_count,
                COUNT(DISTINCT object_key) AS object_key_count,
                COUNT(DISTINCT published_object_key) AS published_key_count,
                bool_and(object_key <> published_object_key) AS keys_distinct,
                (SELECT COUNT(*) FROM upload_reconciliation
                 WHERE upload_id = $1 AND kind = 'verify') AS verify_count
         FROM uploads WHERE id = $1",
    )
    .bind(request.upload_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.try_get::<i64, _>("upload_count")?, 1);
    assert_eq!(row.try_get::<i64, _>("object_key_count")?, 1);
    assert_eq!(row.try_get::<i64, _>("published_key_count")?, 1);
    assert!(row.try_get::<bool, _>("keys_distinct")?);
    assert_eq!(row.try_get::<i64, _>("verify_count")?, 1);
    drop(connection);

    put_proxied(&harness, tenant_id, actor_id, request.upload_id, payload).await?;
    assert_eq!(
        complete(&harness, tenant_id, actor_id, request.upload_id)
            .await?
            .state,
        UploadState::Quarantined
    );
    assert!(matches!(
        harness.workflow.initiate(&OperationContext::uncancelled(), request).await?,
        InitiatedUpload::AlreadyStarted(started) if started.state == UploadState::Quarantined
    ));
    Ok(())
}

async fn assert_initiation_requires_authorization(
    authorizer: &BoundedAuthorizer,
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    request: &InitiateUploadRequest,
    payload: Bytes,
) -> TestResult {
    authorizer.deny_only(UploadAction::Initiate);
    assert!(matches!(
        harness
            .workflow
            .initiate(&OperationContext::uncancelled(), request.clone())
            .await,
        Err(UploadError::Unauthorized)
    ));
    assert!(matches!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await,
        Err(UploadError::NotFound)
    ));
    authorizer.allow_all();
    initiate_proxied(harness, request.clone()).await?;
    put_proxied(harness, tenant_id, actor_id, request.upload_id, payload).await
}

async fn assert_completion_requires_authorization(
    authorizer: &BoundedAuthorizer,
    harness: &Harness,
    tenant_id: TenantId,
    actor_id: SubjectId,
    upload_id: UploadId,
) -> TestResult {
    authorizer.deny_only(UploadAction::Complete);
    assert!(matches!(
        complete(harness, tenant_id, actor_id, upload_id).await,
        Err(UploadError::Unauthorized)
    ));
    assert_eq!(
        harness.repository.lookup(tenant_id, upload_id).await?.state,
        UploadState::PendingUpload
    );
    authorizer.allow_all();
    complete(harness, tenant_id, actor_id, upload_id).await?;
    let scanner = Arc::new(BoundedStreamingScanner::default());
    let reconciler = reconciler(harness, scanner, reconciler_config("auth-contract"))?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    Ok(())
}

async fn assert_cross_tenant_actions_fail_closed(
    authorizer: &BoundedAuthorizer,
    harness: &Harness,
    tenant_id: TenantId,
    other_tenant_id: TenantId,
    actor_id: SubjectId,
    upload_id: UploadId,
) -> TestResult {
    authorizer.deny_only(UploadAction::Download);
    assert!(matches!(
        harness
            .workflow
            .open_download(
                &OperationContext::uncancelled(),
                OpenDownloadRequest {
                    upload_id,
                    tenant_id,
                    actor_id,
                },
            )
            .await,
        Err(UploadError::Unauthorized)
    ));
    let before = authorizer.observations().len();
    assert!(matches!(
        complete(harness, other_tenant_id, actor_id, upload_id).await,
        Err(UploadError::NotFound)
    ));
    assert!(matches!(
        harness
            .workflow
            .open_download(
                &OperationContext::uncancelled(),
                OpenDownloadRequest {
                    upload_id,
                    tenant_id: other_tenant_id,
                    actor_id,
                },
            )
            .await,
        Err(UploadError::NotFound)
    ));
    let observations = authorizer.observations();
    assert_eq!(observations.len(), before);
    assert!(observations.len() <= MAX_FAKE_OBSERVATIONS);
    assert!(
        observations
            .iter()
            .any(|request| request.action == UploadAction::Initiate)
    );
    assert!(
        observations
            .iter()
            .any(|request| request.action == UploadAction::Complete)
    );
    assert!(
        observations
            .iter()
            .any(|request| request.action == UploadAction::Download)
    );
    Ok(())
}

#[tokio::test]
async fn authorization_is_independent_and_cross_tenant_lookup_fails_closed() -> TestResult {
    let authorizer = Arc::new(BoundedAuthorizer::default());
    let harness = memory_harness(Arc::clone(&authorizer)).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let other_tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"independent-authorization");
    let request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        "private.png",
        byte_len(&payload),
        digest(&payload),
        DeclaredMime::Png,
    );

    assert_initiation_requires_authorization(
        &authorizer,
        &harness,
        tenant_id,
        actor_id,
        &request,
        payload,
    )
    .await?;
    assert_completion_requires_authorization(
        &authorizer,
        &harness,
        tenant_id,
        actor_id,
        request.upload_id,
    )
    .await?;
    assert_cross_tenant_actions_fail_closed(
        &authorizer,
        &harness,
        tenant_id,
        other_tenant_id,
        actor_id,
        request.upload_id,
    )
    .await
}

#[tokio::test]
async fn proxied_upload_stores_the_exact_stream_before_quarantine() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"exact-proxied-stream-across-chunks");
    let request = create_pending(
        &harness,
        tenant_id,
        actor_id,
        "exact.png",
        &payload,
        DeclaredMime::Png,
    )
    .await?;
    put_proxied(
        &harness,
        tenant_id,
        actor_id,
        request.upload_id,
        payload.clone(),
    )
    .await?;
    let upload = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?;
    assert_eq!(
        read_object(
            &harness.store,
            tenant_id,
            upload.object_key,
            request.expected_sha256
        )
        .await?,
        payload
    );
    let completed = complete(&harness, tenant_id, actor_id, request.upload_id).await?;
    assert_eq!(completed.state, UploadState::Quarantined);
    assert_eq!(completed.detected_mime, None);
    assert!(matches!(
        harness
            .workflow
            .open_download(
                &OperationContext::uncancelled(),
                OpenDownloadRequest {
                    upload_id: request.upload_id,
                    tenant_id,
                    actor_id,
                },
            )
            .await,
        Err(UploadError::State)
    ));
    Ok(())
}

async fn assert_mismatch_rejections(
    harness: &Harness,
    tenant_id: TenantId,
    size_upload_id: UploadId,
    checksum_upload_id: UploadId,
    mime_upload_id: UploadId,
) -> TestResult {
    let scanner = Arc::new(BoundedStreamingScanner::default());
    let reconciler = reconciler(
        harness,
        Arc::clone(&scanner),
        reconciler_config("mismatch-contract"),
    )?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        3
    );
    let size = harness.repository.lookup(tenant_id, size_upload_id).await?;
    let checksum = harness
        .repository
        .lookup(tenant_id, checksum_upload_id)
        .await?;
    let mime = harness.repository.lookup(tenant_id, mime_upload_id).await?;
    assert_ne!(size.state, UploadState::Available);
    assert_ne!(checksum.state, UploadState::Available);
    assert_ne!(mime.state, UploadState::Available);
    assert_eq!(size.rejection_reason, Some(RejectionReason::SizeMismatch));
    assert_eq!(
        checksum.rejection_reason,
        Some(RejectionReason::ChecksumMismatch)
    );
    assert_eq!(mime.rejection_reason, Some(RejectionReason::MimeMismatch));
    assert!(scanner.observations().is_empty());
    Ok(())
}

#[tokio::test]
async fn size_checksum_and_mime_mismatches_never_become_available() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"mismatch-contract");

    let size_request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        "wrong-size.png",
        byte_len(&payload).saturating_add(1),
        digest(&payload),
        DeclaredMime::Png,
    );
    initiate_proxied(&harness, size_request.clone()).await?;
    put_direct(&harness, tenant_id, size_request.upload_id, payload.clone()).await?;
    assert!(matches!(
        complete(&harness, tenant_id, actor_id, size_request.upload_id).await,
        Err(UploadError::SizeMismatch)
    ));

    let checksum_request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        "wrong-checksum.png",
        byte_len(&payload),
        Sha256Digest::from_bytes([0x5a; 32]),
        DeclaredMime::Png,
    );
    initiate_proxied(&harness, checksum_request.clone()).await?;
    put_direct(
        &harness,
        tenant_id,
        checksum_request.upload_id,
        payload.clone(),
    )
    .await?;
    assert_eq!(
        complete(&harness, tenant_id, actor_id, checksum_request.upload_id)
            .await?
            .state,
        UploadState::Quarantined
    );

    let mime_request = upload_request(
        UploadId::new(),
        tenant_id,
        actor_id,
        "wrong-mime.pdf",
        byte_len(&payload),
        digest(&payload),
        DeclaredMime::Pdf,
    );
    initiate_proxied(&harness, mime_request.clone()).await?;
    put_proxied(
        &harness,
        tenant_id,
        actor_id,
        mime_request.upload_id,
        payload,
    )
    .await?;
    complete(&harness, tenant_id, actor_id, mime_request.upload_id).await?;

    assert_mismatch_rejections(
        &harness,
        tenant_id,
        size_request.upload_id,
        checksum_request.upload_id,
        mime_request.upload_id,
    )
    .await
}

async fn reconcile_scanner_outcomes(
    harness: &Harness,
    scanner: Arc<BoundedStreamingScanner>,
    tenant_id: TenantId,
    clean: &InitiateUploadRequest,
    malicious: &InitiateUploadRequest,
    retryable: &InitiateUploadRequest,
) -> TestResult {
    scanner.set_plan(clean.upload_id, ScannerPlan::Clean);
    scanner.set_plan(malicious.upload_id, ScannerPlan::Malicious);
    scanner.set_plan(retryable.upload_id, ScannerPlan::RetryableFinish);
    let reconciler = reconciler(harness, scanner, reconciler_config("scanner-contract"))?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        3
    );
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        3
    );

    let clean_upload = harness
        .repository
        .lookup(tenant_id, clean.upload_id)
        .await?;
    let malicious_upload = harness
        .repository
        .lookup(tenant_id, malicious.upload_id)
        .await?;
    let retry_upload = harness
        .repository
        .lookup(tenant_id, retryable.upload_id)
        .await?;
    assert_eq!(clean_upload.state, UploadState::Available);
    assert_eq!(malicious_upload.state, UploadState::Rejected);
    assert_eq!(
        malicious_upload.rejection_reason,
        Some(RejectionReason::Malware)
    );
    assert_eq!(retry_upload.state, UploadState::Quarantined);
    assert_eq!(retry_upload.detected_mime, Some(DeclaredMime::Png));

    let mut connection = harness.pool.acquire().await?;
    let published_key: Uuid =
        sqlx::query_scalar("SELECT published_object_key FROM uploads WHERE id = $1")
            .bind(clean.upload_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    let published_key = ObjectKey::from_str(&published_key.hyphenated().to_string())?;
    assert_ne!(clean_upload.object_key, published_key);
    let cleanup = sqlx::query(
        "SELECT upload_id FROM upload_reconciliation
         WHERE organization_id = $1 AND object_key = $2 AND kind = 'delete'
           AND completed_at IS NULL",
    )
    .bind(tenant_id.as_uuid())
    .bind(Uuid::parse_str(clean_upload.object_key.as_str())?)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(cleanup.try_get::<Option<Uuid>, _>("upload_id")?, None);
    let retry_row = sqlx::query("SELECT last_error_code, lease_token, completed_at FROM upload_reconciliation WHERE upload_id = $1 AND kind = 'scan'")
        .bind(retryable.upload_id.as_uuid()).fetch_one(&mut *connection).await?;
    assert_eq!(
        retry_row.try_get::<Option<String>, _>("last_error_code")?,
        Some("scanner_unavailable".to_owned())
    );
    assert_eq!(retry_row.try_get::<Option<Uuid>, _>("lease_token")?, None);
    assert_eq!(
        retry_row.try_get::<Option<OffsetDateTime>, _>("completed_at")?,
        None
    );
    drop(connection);
    let published = read_object(
        &harness.store,
        tenant_id,
        published_key.clone(),
        clean.expected_sha256,
    )
    .await?;
    assert_eq!(digest(&published), clean.expected_sha256);
    assert!(
        !harness
            .repository
            .object_is_known(tenant_id, &clean_upload.object_key)
            .await?
    );
    assert!(
        harness
            .repository
            .object_is_known(tenant_id, &published_key)
            .await?
    );
    Ok(())
}

fn assert_scanner_observations(
    scanner: &BoundedStreamingScanner,
    clean: &InitiateUploadRequest,
    clean_payload: &Bytes,
    malicious: &InitiateUploadRequest,
    malicious_payload: &Bytes,
    retryable: &InitiateUploadRequest,
    retry_payload: &Bytes,
) -> TestResult<Vec<ScanObservation>> {
    let observations = scanner.observations();
    assert_eq!(observations.len(), 3);
    for (request, payload) in [
        (clean, clean_payload),
        (malicious, malicious_payload),
        (retryable, retry_payload),
    ] {
        let observation = observations
            .iter()
            .find(|observation| observation.metadata.upload_id == request.upload_id)
            .ok_or_else(|| io::Error::other("scanner observation was not recorded"))?;
        assert_eq!(observation.byte_count, byte_len(payload));
        assert!(observation.chunk_count > 0);
        assert_eq!(observation.actual_sha256, digest(payload).as_bytes());
        assert!(observation.eof_seen);
        assert_eq!(observation.metadata.declared_size, byte_len(payload));
        assert_eq!(observation.metadata.detected_mime, DeclaredMime::Png);
    }
    Ok(observations)
}

#[tokio::test]
async fn scanner_clean_malicious_and_retryable_outcomes_are_fail_closed() -> TestResult {
    let authorizer = Arc::new(BoundedAuthorizer::default());
    let harness = memory_harness(Arc::clone(&authorizer)).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let clean_payload = png_payload(b"clean-super-secret-body-token");
    let malicious_payload = png_payload(b"malicious-super-secret-body-token");
    let retry_payload = png_payload(b"retry-super-secret-body-token");
    let clean = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "clean-private-name.png",
        clean_payload.clone(),
    )
    .await?;
    let malicious = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "malicious-private-name.png",
        malicious_payload.clone(),
    )
    .await?;
    let retryable = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "retry-private-name.png",
        retry_payload.clone(),
    )
    .await?;

    let scanner = Arc::new(BoundedStreamingScanner::default());
    reconcile_scanner_outcomes(
        &harness,
        Arc::clone(&scanner),
        tenant_id,
        &clean,
        &malicious,
        &retryable,
    )
    .await?;
    let observations = assert_scanner_observations(
        &scanner,
        &clean,
        &clean_payload,
        &malicious,
        &malicious_payload,
        &retryable,
        &retry_payload,
    )?;
    let diagnostics = format!("{authorizer:?} {scanner:?}");
    assert!(!diagnostics.contains("super-secret-body-token"));
    assert!(!diagnostics.contains("private-name"));
    assert!(observations.len() <= MAX_FAKE_OBSERVATIONS);
    Ok(())
}

#[tokio::test]
async fn verification_does_not_run_until_the_latest_credential_expiry() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"credential-expiry-fence");
    let request = create_pending(
        &harness,
        tenant_id,
        actor_id,
        "credential.png",
        &payload,
        DeclaredMime::Png,
    )
    .await?;
    let mut connection = harness.pool.acquire().await?;
    sqlx::query("UPDATE uploads SET direct_credential_expires_at = clock_timestamp() + INTERVAL '1 hour', pending_expires_at = clock_timestamp() + INTERVAL '2 hours', updated_at = clock_timestamp(), revision = revision + 1 WHERE id = $1")
        .bind(request.upload_id.as_uuid()).execute(&mut *connection).await?;
    drop(connection);
    put_proxied(&harness, tenant_id, actor_id, request.upload_id, payload).await?;
    complete(&harness, tenant_id, actor_id, request.upload_id).await?;

    let mut connection = harness.pool.acquire().await?;
    let row = sqlx::query("SELECT work.available_at, upload.direct_credential_expires_at FROM upload_reconciliation AS work JOIN uploads AS upload ON upload.id = work.upload_id WHERE work.upload_id = $1 AND work.kind = 'verify'")
        .bind(request.upload_id.as_uuid()).fetch_one(&mut *connection).await?;
    let available_at: OffsetDateTime = row.try_get("available_at")?;
    let credential_expires_at: OffsetDateTime = row.try_get("direct_credential_expires_at")?;
    assert!(available_at >= credential_expires_at);
    drop(connection);

    let scanner = Arc::new(BoundedStreamingScanner::default());
    let reconciler = reconciler(
        &harness,
        Arc::clone(&scanner),
        reconciler_config("credential-contract"),
    )?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        0
    );
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await?
            .state,
        UploadState::Quarantined
    );
    assert!(scanner.observations().is_empty());
    advance_direct_credential_clock(&harness.pool, request.upload_id).await?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await?
            .state,
        UploadState::Available
    );
    Ok(())
}

#[tokio::test]
async fn available_download_is_exact_attachment_only_and_nosniff() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"safe-download-body");
    let request = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "C:\\private\\résumé  final.png",
        payload.clone(),
    )
    .await
    .map_err(|error| io::Error::other(format!("create quarantined: {error:?}")))?;
    let reconciler = reconciler(
        &harness,
        Arc::new(BoundedStreamingScanner::default()),
        reconciler_config("download-contract"),
    )?;
    reconciler
        .reconcile_once(&CancellationToken::new())
        .await
        .map_err(|error| io::Error::other(format!("verification reconciliation: {error:?}")))?;
    reconciler
        .reconcile_once(&CancellationToken::new())
        .await
        .map_err(|error| io::Error::other(format!("scan reconciliation: {error:?}")))?;
    let download = harness
        .workflow
        .open_download(
            &OperationContext::uncancelled(),
            OpenDownloadRequest {
                upload_id: request.upload_id,
                tenant_id,
                actor_id,
            },
        )
        .await?;
    assert_eq!(
        download
            .headers
            .get(CONTENT_TYPE)
            .ok_or_else(|| io::Error::other("download omitted Content-Type"))?
            .to_str()?,
        "image/png"
    );
    assert_eq!(
        download
            .headers
            .get(CONTENT_LENGTH)
            .ok_or_else(|| io::Error::other("download omitted Content-Length"))?
            .to_str()?,
        byte_len(&payload).to_string()
    );
    assert_eq!(
        download
            .headers
            .get("x-content-type-options")
            .ok_or_else(|| io::Error::other("download omitted nosniff"))?
            .to_str()?,
        "nosniff"
    );
    let disposition = download
        .headers
        .get(CONTENT_DISPOSITION)
        .ok_or_else(|| io::Error::other("download omitted Content-Disposition"))?
        .to_str()?;
    assert!(disposition.starts_with("attachment;"));
    assert!(!disposition.contains("inline"));
    assert!(disposition.contains("filename*=UTF-8''r%C3%A9sum%C3%A9%20final.png"));
    let downloaded = download
        .body
        .try_fold(Vec::new(), |mut collected, chunk| async move {
            collected.extend_from_slice(&chunk);
            Ok(collected)
        })
        .await?;
    assert_eq!(Bytes::from(downloaded), payload);
    Ok(())
}

#[tokio::test]
async fn concurrent_claimers_are_disjoint_and_a_stale_fence_cannot_publish() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let first = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "first.png",
        png_payload(b"first-concurrent-claim"),
    )
    .await?;
    let second = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "second.png",
        png_payload(b"second-concurrent-claim"),
    )
    .await?;
    let mut first_config = reconciler_config("claimer-a");
    first_config.claim_batch = 1;
    let mut second_config = reconciler_config("claimer-b");
    second_config.claim_batch = 1;
    let (first_claim, second_claim) = tokio::join!(
        harness.repository.claim(&first_config),
        harness.repository.claim(&second_config)
    );
    let first_work = only_work(first_claim?)?;
    let second_work = only_work(second_claim?)?;
    assert_ne!(first_work.id, second_work.id);
    assert_ne!(first_work.upload_id, second_work.upload_id);
    assert!(
        [first.upload_id, second.upload_id].contains(
            &first_work
                .upload_id
                .ok_or_else(|| io::Error::other("verify work omitted its upload"))?
        )
    );
    assert!(
        [first.upload_id, second.upload_id].contains(
            &second_work
                .upload_id
                .ok_or_else(|| io::Error::other("verify work omitted its upload"))?
        )
    );

    let mut connection = harness.pool.acquire().await?;
    sqlx::query("UPDATE upload_reconciliation SET lease_expires_at = created_at, updated_at = clock_timestamp() WHERE id = $1")
        .bind(first_work.id.as_uuid()).execute(&mut *connection).await?;
    drop(connection);
    let mut replacement_config = reconciler_config("claimer-c");
    replacement_config.claim_batch = 1;
    let replacement = only_work(harness.repository.claim(&replacement_config).await?)?;
    assert_eq!(replacement.id, first_work.id);
    assert_ne!(replacement.lease_token, first_work.lease_token);
    assert_eq!(
        harness
            .repository
            .complete_verification(&first_work, DeclaredMime::Png)
            .await,
        Err(UploadError::LostLease)
    );
    let upload_id = first_work
        .upload_id
        .ok_or_else(|| io::Error::other("verify work omitted its upload"))?;
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, upload_id)
            .await?
            .detected_mime,
        None
    );
    harness
        .repository
        .complete_verification(&replacement, DeclaredMime::Png)
        .await?;
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, upload_id)
            .await?
            .detected_mime,
        Some(DeclaredMime::Png)
    );
    Ok(())
}

#[tokio::test]
async fn expired_pending_upload_atomically_schedules_idempotent_deletion() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"expired-pending");
    let request = create_pending(
        &harness,
        tenant_id,
        actor_id,
        "expired.png",
        &payload,
        DeclaredMime::Png,
    )
    .await?;
    expire_pending(&harness.pool, request.upload_id).await?;
    let work = only_work(
        harness
            .repository
            .claim(&reconciler_config("expiry-claimer"))
            .await?,
    )?;
    assert_eq!(work.kind, WorkKind::Delete);
    assert_eq!(work.upload_id, Some(request.upload_id));
    let expired = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?;
    assert_eq!(expired.state, UploadState::Rejected);
    assert_eq!(
        expired.rejection_reason,
        Some(RejectionReason::PendingExpired)
    );

    let mut connection = harness.pool.acquire().await?;
    let row = sqlx::query("SELECT COUNT(*) FILTER (WHERE kind = 'verify' AND completed_at IS NOT NULL) AS completed_verify, COUNT(*) FILTER (WHERE kind = 'delete' AND completed_at IS NULL) AS pending_delete FROM upload_reconciliation WHERE upload_id = $1")
        .bind(request.upload_id.as_uuid()).fetch_one(&mut *connection).await?;
    assert_eq!(row.try_get::<i64, _>("completed_verify")?, 1);
    assert_eq!(row.try_get::<i64, _>("pending_delete")?, 1);
    drop(connection);
    harness
        .store
        .delete(
            &OperationContext::uncancelled(),
            work.tenant_id,
            &work.object_key,
        )
        .await?;
    harness.repository.complete_delete(&work).await?;
    harness
        .store
        .delete(
            &OperationContext::uncancelled(),
            work.tenant_id,
            &work.object_key,
        )
        .await?;
    assert_eq!(
        harness.repository.complete_delete(&work).await,
        Err(UploadError::LostLease)
    );
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await?
            .state,
        UploadState::Deleted
    );
    Ok(())
}

#[tokio::test]
async fn late_staging_commit_cannot_replace_the_published_object() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"immutable-publication");
    let request = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "publication.png",
        payload.clone(),
    )
    .await?;
    let reconciler = reconciler(
        &harness,
        Arc::new(BoundedStreamingScanner::default()),
        reconciler_config("publication-isolation-contract"),
    )?;
    for _ in 0..3 {
        assert_eq!(
            reconciler.reconcile_once(&CancellationToken::new()).await?,
            1
        );
    }
    let upload = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?;
    assert_eq!(upload.state, UploadState::Available);
    assert!(matches!(
        harness
            .store
            .head(
                &OperationContext::uncancelled(),
                tenant_id,
                &upload.object_key
            )
            .await,
        Err(BlobStoreError::NotFound)
    ));

    put_direct(&harness, tenant_id, request.upload_id, payload.clone()).await?;
    assert!(
        !harness
            .repository
            .object_is_known(tenant_id, &upload.object_key)
            .await?
    );
    assert!(
        harness
            .repository
            .schedule_orphan_delete(tenant_id, &upload.object_key)
            .await?
    );
    let mut connection = harness.pool.acquire().await?;
    let published_key: Uuid =
        sqlx::query_scalar("SELECT published_object_key FROM uploads WHERE id = $1")
            .bind(request.upload_id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    drop(connection);
    let published_key = ObjectKey::from_str(&published_key.hyphenated().to_string())?;
    assert_eq!(
        read_object(
            &harness.store,
            tenant_id,
            published_key.clone(),
            request.expected_sha256,
        )
        .await?,
        payload
    );
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    assert!(matches!(
        harness
            .store
            .head(
                &OperationContext::uncancelled(),
                tenant_id,
                &upload.object_key
            )
            .await,
        Err(BlobStoreError::NotFound)
    ));
    assert_eq!(
        read_object(
            &harness.store,
            tenant_id,
            published_key,
            request.expected_sha256,
        )
        .await?,
        payload
    );
    Ok(())
}

#[tokio::test]
async fn proxied_write_finishing_after_delete_reopens_durable_cleanup() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let payload = png_payload(b"late-after-delete");
    let request = create_pending(
        &harness,
        tenant_id,
        actor_id,
        "late-delete.png",
        &payload,
        DeclaredMime::Png,
    )
    .await?;
    let object_key = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?
        .object_key;
    let (stream, started, release) = paused_chunk(payload);
    let workflow = harness.workflow.clone();
    let upload_id = request.upload_id;
    let writer = tokio::spawn(async move {
        workflow
            .put_proxied(
                &OperationContext::uncancelled(),
                tenant_id,
                actor_id,
                upload_id,
                stream,
            )
            .await
    });
    started.await?;

    assert!(matches!(
        complete(&harness, tenant_id, actor_id, request.upload_id).await,
        Err(UploadError::NotFound)
    ));
    let cleanup = reconciler(
        &harness,
        Arc::new(BoundedStreamingScanner::default()),
        reconciler_config("late-delete-contract"),
    )?;
    assert_eq!(cleanup.reconcile_once(&CancellationToken::new()).await?, 1);
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await?
            .state,
        UploadState::Deleted
    );

    release
        .send(())
        .map_err(|()| io::Error::other("late writer disappeared"))?;
    assert_eq!(writer.await?, Err(UploadError::State));
    let mut connection = harness.pool.acquire().await?;
    let pending_delete: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM upload_reconciliation
         WHERE upload_id = $1 AND kind = 'delete' AND completed_at IS NULL",
    )
    .bind(request.upload_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(pending_delete, 1);
    drop(connection);

    assert_eq!(cleanup.reconcile_once(&CancellationToken::new()).await?, 1);
    assert!(matches!(
        harness
            .store
            .head(&OperationContext::uncancelled(), tenant_id, &object_key)
            .await,
        Err(BlobStoreError::NotFound)
    ));
    Ok(())
}

#[tokio::test]
async fn effect_deadline_reserves_an_independent_fenced_finalization_margin() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let request = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "finalization-margin.png",
        png_payload(b"finalization-margin"),
    )
    .await
    .map_err(|error| io::Error::other(format!("create quarantined: {error:?}")))?;
    let (scanner, finish_reached, release_finish) = FinishGateScanner::new();
    let mut config = reconciler_config("finalization-margin-contract");
    config.claim_batch = 1;
    config.work_timeout = Duration::from_secs(1);
    config.finalization_margin = Duration::from_secs(1);
    config.lease_duration = Duration::from_secs(3);
    let scanner_port: Arc<dyn MalwareScanner> = scanner;
    let upload_reconciler = UploadReconciler::new(
        harness.repository.clone(),
        harness.store.clone(),
        scanner_port,
        config,
    )?;
    let first_reconciliation = upload_reconciler
        .reconcile_once(&CancellationToken::new())
        .await
        .map_err(|error| io::Error::other(format!("verification reconciliation: {error:?}")))?;
    assert_eq!(first_reconciliation, 1);

    let scan_reconciler = upload_reconciler.clone();
    let scan = tokio::spawn(async move {
        scan_reconciler
            .reconcile_once(&CancellationToken::new())
            .await
    });
    finish_reached.await?;
    let mut connection = harness.pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("SELECT id FROM uploads WHERE id = $1 FOR UPDATE")
        .bind(request.upload_id.as_uuid())
        .fetch_one(&mut *transaction)
        .await?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    release_finish
        .send(())
        .map_err(|()| io::Error::other("scanner finish gate disappeared"))?;
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    transaction.commit().await?;

    let scan_result = scan
        .await?
        .map_err(|error| io::Error::other(format!("scan reconciliation: {error:?}")))?;
    assert_eq!(scan_result, 1);
    assert_eq!(
        harness
            .repository
            .lookup(tenant_id, request.upload_id)
            .await?
            .state,
        UploadState::Available
    );
    Ok(())
}

#[tokio::test]
async fn duplicate_reconciliation_delivery_is_observably_idempotent() -> TestResult {
    let harness = memory_harness(Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let actor_id = SubjectId::new();
    seed_user(&harness.pool, actor_id).await?;
    let request = create_quarantined(
        &harness,
        tenant_id,
        actor_id,
        "duplicate.png",
        png_payload(b"duplicate-job-delivery"),
    )
    .await?;
    let scanner = Arc::new(BoundedStreamingScanner::default());
    let reconciler = reconciler(
        &harness,
        Arc::clone(&scanner),
        reconciler_config("duplicate-contract"),
    )?;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    let available = harness
        .repository
        .lookup(tenant_id, request.upload_id)
        .await?;
    assert_eq!(available.state, UploadState::Available);
    let revision = available.revision;
    assert_eq!(
        reconciler.reconcile_once(&CancellationToken::new()).await?,
        1
    );
    let first_cancellation = CancellationToken::new();
    let second_cancellation = CancellationToken::new();
    let (first_duplicate, second_duplicate) = tokio::join!(
        reconciler.reconcile_once(&first_cancellation),
        reconciler.reconcile_once(&second_cancellation)
    );
    assert_eq!(first_duplicate?, 0);
    assert_eq!(second_duplicate?, 0);
    assert_eq!(scanner.observations().len(), 1);
    assert_eq!(
        complete(&harness, tenant_id, actor_id, request.upload_id)
            .await?
            .revision,
        revision
    );

    let mut connection = harness.pool.acquire().await?;
    let row = sqlx::query("SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE completed_at IS NOT NULL) AS completed FROM upload_reconciliation WHERE upload_id = $1")
        .bind(request.upload_id.as_uuid()).fetch_one(&mut *connection).await?;
    assert_eq!(row.try_get::<i64, _>("total")?, 2);
    assert_eq!(row.try_get::<i64, _>("completed")?, 2);
    Ok(())
}

#[tokio::test]
async fn orphan_repair_honors_grace_and_schedules_only_old_unreferenced_objects() -> TestResult {
    let directory = CleanDirectory::new("upload-orphan-contract")?;
    let policy = OutboundUrlPolicy::new(OutboundUrlPolicyConfig::default())?;
    let store = BlobStore::build(
        ObjectStorageConfig {
            provider: ProviderConfig::Local {
                root: directory.path().to_owned(),
            },
            limits: storage_limits(),
        },
        DeploymentEnvironment::Test,
        &policy,
    )
    .await?;
    let harness = harness_with_store(store, Arc::new(BoundedAuthorizer::default())).await?;
    let tenant_id = seed_tenant(&harness.pool).await?;
    let old_key = ObjectKey::new();
    let young_key = ObjectKey::new();
    let old_bytes = png_payload(b"old-orphan");
    let young_bytes = png_payload(b"young-orphan");
    for (key, bytes) in [
        (old_key.clone(), old_bytes),
        (young_key.clone(), young_bytes),
    ] {
        harness
            .store
            .put_stream(
                &OperationContext::uncancelled(),
                PutRequest {
                    tenant_id,
                    key,
                    declared_length: byte_len(&bytes),
                    expected_sha256: digest(&bytes).as_bytes(),
                    content_type: Some("image/png".to_owned()),
                    metadata: BTreeMap::new(),
                    condition: WriteCondition::Overwrite,
                    stream: one_chunk(bytes),
                },
            )
            .await?;
    }
    let old_path = directory
        .path()
        .join("rsk")
        .join("objects")
        .join("v1")
        .join(tenant_id.as_uuid().to_string())
        .join(old_key.as_str());
    let old_time = SystemTime::now()
        .checked_sub(Duration::from_secs(120))
        .ok_or_else(|| io::Error::other("system time cannot represent orphan age"))?;
    OpenOptions::new()
        .write(true)
        .open(old_path)?
        .set_times(FileTimes::new().set_modified(old_time))?;
    assert_eq!(
        harness
            .workflow
            .repair_orphans(
                &OperationContext::uncancelled(),
                tenant_id,
                1,
                &reconciler_config("orphan-contract")
            )
            .await?,
        1
    );

    let mut connection = harness.pool.acquire().await?;
    let rows = sqlx::query("SELECT object_key, upload_id FROM upload_reconciliation WHERE organization_id = $1 AND kind = 'delete' AND completed_at IS NULL")
        .bind(tenant_id.as_uuid()).fetch_all(&mut *connection).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].try_get::<Uuid, _>("object_key")?,
        Uuid::parse_str(old_key.as_str())?
    );
    assert_eq!(rows[0].try_get::<Option<Uuid>, _>("upload_id")?, None);
    assert_ne!(
        rows[0].try_get::<Uuid, _>("object_key")?,
        Uuid::parse_str(young_key.as_str())?
    );
    Ok(())
}
