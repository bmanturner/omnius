//! Authenticated tenant and upload HTTP assembly over production service-kit providers.

use std::{
    collections::BTreeMap, fmt, net::SocketAddr, str::FromStr as _, sync::Arc, time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode},
    response::Response,
    routing::{get, post, put},
};
use bytes::Bytes;
use futures::{StreamExt as _, future::BoxFuture};
use omnius_auth_core::{Principal, SubjectId, TenantId};
use omnius_authz_basic::{
    Action, AuthorizationContext, BasicAuthorizer, BasicPolicy, Decision, Grant, PolicyMatrix,
    PolicyRule, Resource, ResourceKind,
};
use omnius_config::DeploymentEnvironment;
use omnius_core::RequestId;
use omnius_http::{ProblemDetails, RouteBodyLimit};
use omnius_object_storage::{
    BlobStore, BlobStoreError, ByteStream, ObjectStorageConfig, OperationContext,
};
use omnius_outbound_http::OutboundUrlPolicy;
use omnius_postgres::PostgresPool;
use omnius_tenancy::{
    MembershipRole, TenancyConfig, TenancyStore, TenancyStoreError, TenantContext,
};
use omnius_upload_workflow::{
    AbandonUploadRequest, CompleteUploadRequest, DeclaredMime, GetUploadStatusRequest,
    InitiateUploadRequest, InitiatedUpload, MalwareScanner, OpenDownloadRequest,
    PostgresUploadRepository, ReconcilerConfig, RejectionReason, ScanMetadata, ScanVerdict,
    ScannerFailure, ScannerSession, Sha256Digest, UploadAction, UploadAuthorization,
    UploadAuthorizer, UploadError, UploadId, UploadReconciler, UploadState, UploadStatus,
    UploadWorkflow,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpStream,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use super::browser_auth::{BrowserAuthSession, bind_browser_session_tenant};

const TENANT_HEADER: &str = "x-omnius-tenant-id";
const MAX_EXTERNAL_IDENTITY_BYTES: usize = 256;
const MAX_CLAMD_RESPONSE_BYTES: usize = 1_024;
const PROXIED_UPLOAD_PATH: &str = "/uploads/{upload_id}/content";

/// Bounded browser upload credential and pending-window policy.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserUploadPolicy {
    /// Lifetime of a freshly issued direct-transfer credential.
    #[serde(with = "humantime_serde")]
    pub direct_upload_expires_in: Duration,
    /// Maximum age of an upload that has not reached terminal state.
    #[serde(with = "humantime_serde")]
    pub pending_upload_ttl: Duration,
}

impl Default for BrowserUploadPolicy {
    fn default() -> Self {
        Self {
            direct_upload_expires_in: Duration::from_secs(300),
            pending_upload_ttl: Duration::from_mins(30),
        }
    }
}

/// Strict connection and deadline policy for a real `ClamAV` `clamd` INSTREAM scanner.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClamdScannerConfig {
    /// `clamd` TCP endpoint.
    pub address: SocketAddr,
    #[serde(with = "humantime_serde")]
    /// Maximum time allowed to establish the scanner connection.
    pub connect_timeout: Duration,
    #[serde(with = "humantime_serde")]
    /// Maximum time allowed for each scanner I/O operation.
    pub io_timeout: Duration,
}

/// Production `ClamAV` streaming scanner; it never buffers a whole upload.
#[derive(Clone)]
pub struct ClamdScanner {
    config: ClamdScannerConfig,
}

impl fmt::Debug for ClamdScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClamdScanner")
            .field("address", &self.config.address)
            .field("connect_timeout", &self.config.connect_timeout)
            .field("io_timeout", &self.config.io_timeout)
            .finish()
    }
}

impl ClamdScanner {
    /// Validates bounded scanner deadlines and creates the streaming adapter.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserUploadBuildError::ScannerConfiguration`] for zero or excessive deadlines.
    pub fn new(config: ClamdScannerConfig) -> Result<Self, BrowserUploadBuildError> {
        if config.connect_timeout.is_zero()
            || config.io_timeout.is_zero()
            || config.connect_timeout > Duration::from_secs(30)
            || config.io_timeout > Duration::from_secs(60)
        {
            return Err(BrowserUploadBuildError::ScannerConfiguration);
        }
        Ok(Self { config })
    }
}

impl MalwareScanner for ClamdScanner {
    fn start<'a>(
        &'a self,
        _metadata: ScanMetadata,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Box<dyn ScannerSession>, ScannerFailure>> {
        Box::pin(async move {
            if cancellation.is_cancelled() {
                return Err(ScannerFailure::Retryable);
            }
            let stream = tokio::select! {
                () = cancellation.cancelled() => return Err(ScannerFailure::Retryable),
                result = timeout(self.config.connect_timeout, TcpStream::connect(self.config.address)) => {
                    result.map_err(|_| ScannerFailure::Retryable)?.map_err(|_| ScannerFailure::Retryable)?
                }
            };
            stream
                .set_nodelay(true)
                .map_err(|_| ScannerFailure::Retryable)?;
            let mut session = ClamdSession {
                stream,
                io_timeout: self.config.io_timeout,
                finished: false,
            };
            session.write_all(b"zINSTREAM\0", cancellation).await?;
            Ok(Box::new(session) as Box<dyn ScannerSession>)
        })
    }
}

async fn read_clamd_verdict<R>(
    reader: &mut R,
    io_timeout: Duration,
    cancellation: &CancellationToken,
) -> Result<ScanVerdict, ScannerFailure>
where
    R: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(128);
    let mut buffer = [0_u8; 128];
    loop {
        let read = tokio::select! {
            () = cancellation.cancelled() => return Err(ScannerFailure::Retryable),
            result = timeout(io_timeout, reader.read(&mut buffer)) => {
                result.map_err(|_| ScannerFailure::Retryable)?.map_err(|_| ScannerFailure::Retryable)?
            }
        };
        if read == 0 {
            return Err(ScannerFailure::Permanent);
        }
        let chunk = &buffer[..read];
        let end = chunk.iter().position(|byte| matches!(byte, b'\0' | b'\n'));
        let retained = end.map_or(chunk, |index| &chunk[..index]);
        if response.len().saturating_add(retained.len()) > MAX_CLAMD_RESPONSE_BYTES {
            return Err(ScannerFailure::Permanent);
        }
        response.extend_from_slice(retained);
        if end.is_some() {
            break;
        }
    }
    if response == b"OK" || response.ends_with(b" OK") {
        Ok(ScanVerdict::Clean)
    } else if response == b"FOUND" || response.ends_with(b" FOUND") {
        Ok(ScanVerdict::Malicious)
    } else {
        Err(ScannerFailure::Permanent)
    }
}

struct ClamdSession {
    stream: TcpStream,
    io_timeout: Duration,
    finished: bool,
}

impl ClamdSession {
    async fn write_all(
        &mut self,
        bytes: &[u8],
        cancellation: &CancellationToken,
    ) -> Result<(), ScannerFailure> {
        tokio::select! {
            () = cancellation.cancelled() => Err(ScannerFailure::Retryable),
            result = timeout(self.io_timeout, self.stream.write_all(bytes)) => {
                result.map_err(|_| ScannerFailure::Retryable)?.map_err(|_| ScannerFailure::Retryable)
            }
        }
    }

    async fn verdict(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<ScanVerdict, ScannerFailure> {
        read_clamd_verdict(&mut self.stream, self.io_timeout, cancellation).await
    }
}

impl ScannerSession for ClamdSession {
    fn scan_chunk<'a>(
        &'a mut self,
        chunk: Bytes,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<(), ScannerFailure>> {
        Box::pin(async move {
            if self.finished || chunk.is_empty() {
                return Err(ScannerFailure::Permanent);
            }
            let length = u32::try_from(chunk.len()).map_err(|_| ScannerFailure::Permanent)?;
            self.write_all(&length.to_be_bytes(), cancellation).await?;
            self.write_all(&chunk, cancellation).await
        })
    }

    fn finish<'a>(
        &'a mut self,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<ScanVerdict, ScannerFailure>> {
        Box::pin(async move {
            if self.finished {
                return Err(ScannerFailure::Permanent);
            }
            self.finished = true;
            self.write_all(&0_u32.to_be_bytes(), cancellation).await?;
            self.verdict(cancellation).await
        })
    }
}

/// Assembled browser route state and its durable verifier/scanner/cleanup reconciler.
pub struct BrowserUploadAssembly {
    /// Router state containing the authoritative tenancy and upload providers.
    pub state: BrowserUploadState,
    /// Durable verification, scanning, and cleanup worker.
    pub reconciler: UploadReconciler,
}

/// Configuration for assembling the browser upload providers.
pub struct BrowserUploadAssemblyConfig<'a> {
    /// Authoritative tenancy-provider configuration.
    pub tenancy_config: &'a TenancyConfig,
    /// Object-storage provider and limit configuration.
    pub object_storage_config: ObjectStorageConfig,
    /// Streaming malware-scanner configuration.
    pub scanner_config: ClamdScannerConfig,
    /// Durable verification and cleanup reconciler configuration.
    pub reconciler_config: ReconcilerConfig,
    /// Upload credential and pending-window policy.
    pub upload_policy: BrowserUploadPolicy,
    /// Deployment environment used to enforce provider policy.
    pub deployment: DeploymentEnvironment,
    /// Outbound URL policy applied to object-storage endpoints.
    pub url_policy: &'a OutboundUrlPolicy,
}

/// Failure to assemble the browser tenancy and upload providers.
#[derive(Debug, Error)]
pub enum BrowserUploadBuildError {
    /// Tenancy policy or provider construction failed.
    #[error("browser tenancy configuration is invalid")]
    Tenancy(#[from] TenancyStoreError),
    /// Object-storage policy or adapter construction failed.
    #[error("browser object storage configuration is invalid")]
    ObjectStorage(#[from] BlobStoreError),
    /// Scanner deadlines are zero or exceed supported bounds.
    #[error("browser malware scanner configuration is invalid")]
    ScannerConfiguration,
    /// Upload credential or pending lifetime policy is invalid.
    #[error("browser upload lifecycle policy is invalid")]
    UploadPolicy,
    /// The object bound cannot be represented as a finite HTTP request-body limit.
    #[error("browser proxied upload body limit is invalid")]
    UploadBodyLimit,
    /// The built-in upload authorization policy is invalid.
    #[error("browser upload authorization policy is invalid")]
    AuthorizationPolicy,
    /// Durable reconciliation configuration is invalid.
    #[error("browser upload reconciliation configuration is invalid")]
    Reconciler(UploadError),
}

/// Builds real tenancy, object-storage, basic-authorization, `ClamAV`, workflow, and reconciler providers.
///
/// # Errors
///
/// Returns [`BrowserUploadBuildError`] when provider construction or any tenancy, storage,
/// scanner, upload lifecycle, authorization, body-limit, or reconciliation policy is invalid.
pub async fn assemble_browser_uploads(
    pool: PostgresPool,
    config: BrowserUploadAssemblyConfig<'_>,
) -> Result<BrowserUploadAssembly, BrowserUploadBuildError> {
    let BrowserUploadAssemblyConfig {
        tenancy_config,
        object_storage_config,
        scanner_config,
        reconciler_config,
        upload_policy,
        deployment,
        url_policy,
    } = config;
    let credential_window = upload_policy
        .direct_upload_expires_in
        .checked_add(Duration::from_secs(30))
        .ok_or(BrowserUploadBuildError::UploadPolicy)?;
    if upload_policy.direct_upload_expires_in.is_zero()
        || upload_policy.direct_upload_expires_in.subsec_nanos() != 0
        || upload_policy.direct_upload_expires_in
            > object_storage_config.limits.max_signed_url_expiry
        || upload_policy.pending_upload_ttl < credential_window
        || upload_policy.pending_upload_ttl > Duration::from_hours(24)
    {
        return Err(BrowserUploadBuildError::UploadPolicy);
    }
    let proxied_body_bytes = usize::try_from(object_storage_config.limits.max_object_size)
        .map_err(|_| BrowserUploadBuildError::UploadBodyLimit)?;
    let proxied_body_limit =
        RouteBodyLimit::new(Method::PUT, PROXIED_UPLOAD_PATH, proxied_body_bytes)
            .map_err(|_| BrowserUploadBuildError::UploadBodyLimit)?;
    let tenancy = TenancyStore::new(pool.clone(), tenancy_config)?;
    let blob_store = BlobStore::build(object_storage_config, deployment, url_policy).await?;
    let repository = PostgresUploadRepository::new(pool);
    let authorization = Arc::new(BrowserAuthorization::build()?);
    let scanner: Arc<dyn MalwareScanner> = Arc::new(ClamdScanner::new(scanner_config)?);
    let reconciler = UploadReconciler::new(
        repository.clone(),
        blob_store.clone(),
        scanner,
        reconciler_config,
    )
    .map_err(BrowserUploadBuildError::Reconciler)?;
    Ok(BrowserUploadAssembly {
        state: BrowserUploadState {
            tenancy,
            repository,
            blob_store,
            authorization,
            upload_policy,
            proxied_body_limit,
        },
        reconciler,
    })
}

/// Shared authoritative state for tenant and upload browser routes.
#[derive(Clone)]
pub struct BrowserUploadState {
    tenancy: TenancyStore,
    repository: PostgresUploadRepository,
    blob_store: BlobStore,
    authorization: Arc<BrowserAuthorization>,
    upload_policy: BrowserUploadPolicy,
    proxied_body_limit: RouteBodyLimit,
}

impl fmt::Debug for BrowserUploadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserUploadState").finish_non_exhaustive()
    }
}

impl BrowserUploadState {
    /// Returns the exact shell override for streamed proxied upload content.
    #[must_use]
    pub fn proxied_body_limit(&self) -> RouteBodyLimit {
        self.proxied_body_limit.clone()
    }
}

struct BrowserAuthorization {
    service: BasicAuthorizer,
    resource_kind: ResourceKind,
    initiate: Action,
    complete: Action,
    status: Action,
    abandon: Action,
    download: Action,
}

impl BrowserAuthorization {
    fn build() -> Result<Self, BrowserUploadBuildError> {
        let kind = ResourceKind::new("upload")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let initiate = Action::new("upload.initiate")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let complete = Action::new("upload.complete")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let status = Action::new("upload.status")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let abandon = Action::new("upload.abandon")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let download = Action::new("upload.download")
            .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        let rules = [&initiate, &complete, &status, &abandon, &download]
            .into_iter()
            .map(|action| {
                PolicyRule::new(action.clone(), kind.clone(), vec![Grant::Owner])
                    .map(PolicyRule::requiring_tenant_membership)
                    .map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let matrix =
            PolicyMatrix::new(rules).map_err(|_| BrowserUploadBuildError::AuthorizationPolicy)?;
        Ok(Self {
            service: BasicAuthorizer::new(BasicPolicy::new(matrix)),
            resource_kind: kind,
            initiate,
            complete,
            status,
            abandon,
            download,
        })
    }

    const fn action(&self, action: UploadAction) -> &Action {
        match action {
            UploadAction::Initiate => &self.initiate,
            UploadAction::Complete => &self.complete,
            UploadAction::Status => &self.status,
            UploadAction::Abandon => &self.abandon,
            UploadAction::Download => &self.download,
        }
    }
}

struct TenantUploadAuthorizer {
    principal: Principal,
    context: AuthorizationContext,
    authorization: Arc<BrowserAuthorization>,
}

impl UploadAuthorizer for TenantUploadAuthorizer {
    fn authorize(&self, request: UploadAuthorization) -> BoxFuture<'_, Result<(), UploadError>> {
        Box::pin(async move {
            if self.principal.subject_id != request.actor_id
                || self.principal.tenant_id != Some(request.tenant_id)
            {
                return Err(UploadError::Unauthorized);
            }
            let resource = Resource::new(self.authorization.resource_kind.clone())
                .owned_by(request.owner_id)
                .in_tenant(request.tenant_id);
            match self.authorization.service.authorize(
                &self.principal,
                self.authorization.action(request.action),
                &resource,
                &self.context,
            ) {
                Decision::Allow => Ok(()),
                Decision::Deny(_) => Err(UploadError::Unauthorized),
            }
        })
    }
}

struct RequestUploadContext {
    workflow: UploadWorkflow,
    actor_id: SubjectId,
}

impl BrowserUploadState {
    async fn for_tenant(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        request_id: RequestId,
    ) -> Result<RequestUploadContext, BrowserHttpError> {
        let context = self
            .tenancy
            .resolve_tenant_context(principal, tenant_id)
            .await
            .map_err(|error| BrowserHttpError::from_tenancy(error, request_id))?;
        let canonical = context.principal().clone();
        let authorizer: Arc<dyn UploadAuthorizer> = Arc::new(TenantUploadAuthorizer {
            principal: canonical.clone(),
            context: context.authorization_context().clone(),
            authorization: Arc::clone(&self.authorization),
        });
        Ok(RequestUploadContext {
            workflow: UploadWorkflow::new(
                self.repository.clone(),
                self.blob_store.clone(),
                authorizer,
            ),
            actor_id: canonical.subject_id,
        })
    }
}

/// Returns routes that must be wrapped by `browser_auth::protected_browser_router`.
pub fn browser_upload_router(state: BrowserUploadState) -> Router {
    Router::new()
        .route("/tenants", get(list_tenants))
        .route("/tenants/{tenant_id}/switch", post(switch_tenant))
        .route("/uploads", post(initiate_upload))
        .route(PROXIED_UPLOAD_PATH, put(transfer_upload))
        .route("/uploads/{upload_id}/complete", post(complete_upload))
        .route("/uploads/{upload_id}/status", post(upload_status))
        .route("/uploads/{upload_id}/abandon", post(abandon_upload))
        .route("/uploads/{upload_id}/download", get(download_upload))
        .with_state(state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantSummary {
    tenant_id: TenantId,
    name: String,
    permission_scope: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TenantSwitchMetadata {
    tenant_id: TenantId,
    principal_id: SubjectId,
    role: &'static str,
    grant_version: i64,
}

async fn list_tenants(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Json<Vec<TenantSummary>>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    list_tenant_summaries(&state.tenancy, &principal, request_id)
        .await
        .map(Json)
}

async fn switch_tenant(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    Path(tenant): Path<String>,
) -> Result<Json<TenantSwitchMetadata>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = parse_tenant_id(&tenant, request_id)?;
    let context = resolve_switch_context(&state.tenancy, &principal, tenant_id, request_id).await?;
    bind_browser_session_tenant(&auth, tenant_id)
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    Ok(Json(tenant_switch_metadata(&context)))
}

fn tenantless_principal(principal: &Principal) -> Principal {
    let mut canonical = principal.clone();
    canonical.tenant_id = None;
    canonical
}

async fn list_tenant_summaries(
    tenancy: &TenancyStore,
    principal: &Principal,
    request_id: RequestId,
) -> Result<Vec<TenantSummary>, BrowserHttpError> {
    let canonical = tenantless_principal(principal);
    let organizations = tenancy
        .list_organizations(canonical.subject_id)
        .await
        .map_err(|error| BrowserHttpError::from_tenancy(error, request_id))?;
    let mut summaries = Vec::with_capacity(organizations.len());
    for organization in organizations {
        let context = tenancy
            .resolve_tenant_context(&canonical, organization.id)
            .await
            .map_err(|error| BrowserHttpError::from_tenancy(error, request_id))?;
        summaries.push(TenantSummary {
            tenant_id: organization.id,
            name: organization.name.to_string(),
            permission_scope: context.membership().grant_version.to_string(),
        });
    }
    Ok(summaries)
}

async fn resolve_switch_context(
    tenancy: &TenancyStore,
    principal: &Principal,
    tenant_id: TenantId,
    request_id: RequestId,
) -> Result<TenantContext, BrowserHttpError> {
    let canonical = tenantless_principal(principal);
    tenancy
        .resolve_tenant_context(&canonical, tenant_id)
        .await
        .map_err(|error| BrowserHttpError::from_tenancy(error, request_id))
}

fn tenant_switch_metadata(context: &TenantContext) -> TenantSwitchMetadata {
    let membership = context.membership();
    TenantSwitchMetadata {
        tenant_id: membership.organization_id,
        principal_id: context.principal().subject_id,
        role: match membership.role {
            MembershipRole::Owner => "owner",
            MembershipRole::Admin => "admin",
            MembershipRole::Member => "member",
        },
        grant_version: membership.grant_version,
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalIdentityPayload {
    workflow_key: String,
    idempotency_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitiateUploadPayload {
    identity: ExternalIdentityPayload,
    file_name: String,
    media_type: Option<String>,
    byte_length: u64,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IdentityOperationPayload {
    identity: ExternalIdentityPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompleteUploadPayload {
    identity: ExternalIdentityPayload,
    sha256: String,
    parts: Vec<PartReceiptPayload>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartReceiptPayload {
    part_number: u16,
    receipt: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BrowserUploadTargetResponse {
    url: String,
    method: &'static str,
    headers: BTreeMap<String, String>,
    body: BrowserUploadBodyResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
enum BrowserUploadBodyResponse {
    Raw,
    Form {
        fields: BTreeMap<String, String>,
        file_field: &'static str,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadPartResponse {
    part_number: u16,
    offset: u64,
    length: u64,
    target: BrowserUploadTargetResponse,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadTransferResponse {
    mode: &'static str,
    parts: Vec<UploadPartResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case", tag = "decision")]
enum InitiateUploadResponse {
    Started {
        #[serde(rename = "uploadId")]
        upload_id: UploadId,
        transfer: UploadTransferResponse,
    },
    AlreadyStarted {
        #[serde(rename = "uploadId")]
        upload_id: UploadId,
        status: UploadStatusResponse,
    },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadStatusResponse {
    state: &'static str,
    revision: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    rejection: Option<UploadRejectionResponse>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UploadRejectionResponse {
    code: &'static str,
    message: &'static str,
    phase: &'static str,
    retryable: bool,
}

async fn initiate_upload(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    Json(payload): Json<InitiateUploadPayload>,
) -> Result<Json<InitiateUploadResponse>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    let hashes = external_identity_hashes(&payload.identity, request_id)?;
    let upload_id = state
        .repository
        .resolve_external_identity(tenant_id, context.actor_id, hashes.0, hashes.1)
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    let declared_mime = payload
        .media_type
        .as_deref()
        .unwrap_or("application/octet-stream")
        .parse::<DeclaredMime>()
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    let initiated = context
        .workflow
        .initiate(
            &OperationContext::uncancelled(),
            InitiateUploadRequest {
                upload_id,
                tenant_id,
                actor_id: context.actor_id,
                filename: payload.file_name,
                declared_size: payload.byte_length,
                expected_sha256: parse_sha256(&payload.sha256, request_id)?,
                declared_mime,
                direct_upload_expires_in: state.upload_policy.direct_upload_expires_in,
                pending_upload_ttl: state.upload_policy.pending_upload_ttl,
            },
        )
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    let response = match initiated {
        InitiatedUpload::Direct(form) => {
            let signed = form.signed();
            InitiateUploadResponse::Started {
                upload_id,
                transfer: UploadTransferResponse {
                    mode: "direct",
                    parts: vec![UploadPartResponse {
                        part_number: 1,
                        offset: 0,
                        length: payload.byte_length,
                        target: BrowserUploadTargetResponse {
                            url: signed.expose().to_string(),
                            method: "POST",
                            headers: BTreeMap::new(),
                            body: BrowserUploadBodyResponse::Form {
                                fields: signed.expose_form_fields().clone(),
                                file_field: "file",
                            },
                        },
                    }],
                },
            }
        }
        InitiatedUpload::Proxied(contract) => InitiateUploadResponse::Started {
            upload_id,
            transfer: UploadTransferResponse {
                mode: "proxied",
                parts: vec![UploadPartResponse {
                    part_number: 1,
                    offset: 0,
                    length: contract.declared_size,
                    target: BrowserUploadTargetResponse {
                        url: format!("/uploads/{upload_id}/content"),
                        method: "PUT",
                        headers: BTreeMap::from([(
                            TENANT_HEADER.to_owned(),
                            tenant_id.to_string(),
                        )]),
                        body: BrowserUploadBodyResponse::Raw,
                    },
                }],
            },
        },
        InitiatedUpload::AlreadyStarted(started) => {
            let status = context
                .workflow
                .status(GetUploadStatusRequest {
                    upload_id: started.upload_id,
                    tenant_id,
                    actor_id: context.actor_id,
                })
                .await
                .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
            InitiateUploadResponse::AlreadyStarted {
                upload_id: started.upload_id,
                status: upload_status_response(status),
            }
        }
    };
    Ok(Json(response))
}

async fn transfer_upload(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(upload): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let upload_id = parse_upload_id(&upload, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    let stream: ByteStream = Box::pin(
        body.into_data_stream()
            .map(|item| item.map_err(|_| BlobStoreError::Unavailable)),
    );
    context
        .workflow
        .put_proxied(
            &OperationContext::uncancelled(),
            tenant_id,
            context.actor_id,
            upload_id,
            stream,
        )
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn complete_upload(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(upload): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<CompleteUploadPayload>,
) -> Result<Json<UploadStatusResponse>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let upload_id = parse_upload_id(&upload, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    verify_identity(
        &state.repository,
        tenant_id,
        context.actor_id,
        upload_id,
        &payload.identity,
        request_id,
    )
    .await?;
    let expected = parse_sha256(&payload.sha256, request_id)?;
    let persisted = state
        .repository
        .lookup(tenant_id, upload_id)
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    if persisted.expected_sha256 != expected
        || payload.parts.len() != 1
        || payload.parts[0].part_number != 1
        || payload.parts[0].receipt.is_empty()
    {
        return Err(BrowserHttpError::conflict(request_id));
    }
    context
        .workflow
        .complete(
            &OperationContext::uncancelled(),
            CompleteUploadRequest {
                upload_id,
                tenant_id,
                actor_id: context.actor_id,
            },
        )
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    status_json(&context, upload_id, tenant_id, request_id).await
}

async fn upload_status(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(upload): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<IdentityOperationPayload>,
) -> Result<Json<UploadStatusResponse>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let upload_id = parse_upload_id(&upload, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    verify_identity(
        &state.repository,
        tenant_id,
        context.actor_id,
        upload_id,
        &payload.identity,
        request_id,
    )
    .await?;
    status_json(&context, upload_id, tenant_id, request_id).await
}

async fn status_json(
    context: &RequestUploadContext,
    upload_id: UploadId,
    tenant_id: TenantId,
    request_id: RequestId,
) -> Result<Json<UploadStatusResponse>, BrowserHttpError> {
    let status = context
        .workflow
        .status(GetUploadStatusRequest {
            upload_id,
            tenant_id,
            actor_id: context.actor_id,
        })
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    Ok(Json(upload_status_response(status)))
}

async fn abandon_upload(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(upload): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<IdentityOperationPayload>,
) -> Result<Json<UploadStatusResponse>, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let upload_id = parse_upload_id(&upload, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    verify_identity(
        &state.repository,
        tenant_id,
        context.actor_id,
        upload_id,
        &payload.identity,
        request_id,
    )
    .await?;
    let status = context
        .workflow
        .abandon(AbandonUploadRequest {
            upload_id,
            tenant_id,
            actor_id: context.actor_id,
        })
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    Ok(Json(upload_status_response(status)))
}

async fn download_upload(
    State(state): State<BrowserUploadState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(upload): Path<String>,
    headers: HeaderMap,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = tenant_from_headers(&headers, request_id)?;
    let upload_id = parse_upload_id(&upload, request_id)?;
    let context = state.for_tenant(&principal, tenant_id, request_id).await?;
    let download = context
        .workflow
        .open_download(
            &OperationContext::uncancelled(),
            OpenDownloadRequest {
                upload_id,
                tenant_id,
                actor_id: context.actor_id,
            },
        )
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))?;
    let mut response = Response::new(Body::from_stream(download.body));
    *response.headers_mut() = download.headers;
    Ok(response)
}

async fn verify_identity(
    repository: &PostgresUploadRepository,
    tenant_id: TenantId,
    owner_id: SubjectId,
    upload_id: UploadId,
    identity: &ExternalIdentityPayload,
    request_id: RequestId,
) -> Result<(), BrowserHttpError> {
    let hashes = external_identity_hashes(identity, request_id)?;
    repository
        .verify_external_identity(tenant_id, owner_id, upload_id, hashes.0, hashes.1)
        .await
        .map_err(|error| BrowserHttpError::from_upload(error, request_id))
}

fn external_identity_hashes(
    identity: &ExternalIdentityPayload,
    request_id: RequestId,
) -> Result<([u8; 32], [u8; 32]), BrowserHttpError> {
    fn valid(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= MAX_EXTERNAL_IDENTITY_BYTES
            && value.trim() == value
            && !value.chars().any(char::is_control)
    }
    if !valid(&identity.workflow_key) || !valid(&identity.idempotency_key) {
        return Err(BrowserHttpError::bad_request(request_id));
    }
    let mut workflow_hasher = Sha256::new();
    workflow_hasher.update(b"omnius-upload-workflow\0");
    workflow_hasher.update(identity.workflow_key.as_bytes());
    let mut idempotency_hasher = Sha256::new();
    idempotency_hasher.update(b"omnius-upload-idempotency\0");
    idempotency_hasher.update(identity.idempotency_key.as_bytes());
    Ok((
        workflow_hasher.finalize().into(),
        idempotency_hasher.finalize().into(),
    ))
}

fn parse_sha256(value: &str, request_id: RequestId) -> Result<Sha256Digest, BrowserHttpError> {
    let hex = value
        .strip_prefix("sha256:")
        .ok_or_else(|| BrowserHttpError::bad_request(request_id))?;
    Sha256Digest::from_hex(hex).map_err(|error| BrowserHttpError::from_upload(error, request_id))
}

fn tenant_from_headers(
    headers: &HeaderMap,
    request_id: RequestId,
) -> Result<TenantId, BrowserHttpError> {
    let mut values = headers.get_all(TENANT_HEADER).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| BrowserHttpError::bad_request(request_id))?;
    parse_tenant_id(value, request_id)
}

fn parse_tenant_id(value: &str, request_id: RequestId) -> Result<TenantId, BrowserHttpError> {
    TenantId::from_str(value).map_err(|_| BrowserHttpError::bad_request(request_id))
}

fn parse_upload_id(value: &str, request_id: RequestId) -> Result<UploadId, BrowserHttpError> {
    UploadId::from_str(value).map_err(|_| BrowserHttpError::not_found(request_id))
}

fn upload_status_response(status: UploadStatus) -> UploadStatusResponse {
    UploadStatusResponse {
        state: match status.state {
            UploadState::PendingUpload => "pending",
            UploadState::Quarantined => "quarantined",
            UploadState::Available => "available",
            UploadState::Rejected => "rejected",
            UploadState::Deleted => "deleted",
        },
        revision: status.revision,
        rejection: status.rejection_reason.map(rejection_response),
    }
}

const fn rejection_response(reason: RejectionReason) -> UploadRejectionResponse {
    match reason {
        RejectionReason::Abandoned => UploadRejectionResponse {
            code: "cancelled",
            message: "The upload was abandoned and cleanup was scheduled.",
            phase: "cleanup",
            retryable: false,
        },
        RejectionReason::Malware => UploadRejectionResponse {
            code: "remote-rejection",
            message: "The upload was rejected by content security policy.",
            phase: "scan",
            retryable: false,
        },
        RejectionReason::ScannerFailure => UploadRejectionResponse {
            code: "scan",
            message: "The upload could not pass content security verification.",
            phase: "scan",
            retryable: false,
        },
        RejectionReason::PendingExpired => UploadRejectionResponse {
            code: "state",
            message: "The authorized upload window expired.",
            phase: "finalize",
            retryable: false,
        },
        RejectionReason::MissingObject
        | RejectionReason::SizeMismatch
        | RejectionReason::ChecksumMismatch
        | RejectionReason::MimeMismatch => UploadRejectionResponse {
            code: "remote-rejection",
            message: "The upload failed integrity verification.",
            phase: "finalize",
            retryable: false,
        },
    }
}

#[derive(Clone, Copy, Debug)]
struct BrowserHttpError {
    status: StatusCode,
    request_id: RequestId,
}

impl BrowserHttpError {
    const fn bad_request(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            request_id,
        }
    }
    const fn unavailable(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            request_id,
        }
    }
    const fn not_found(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            request_id,
        }
    }
    const fn conflict(request_id: RequestId) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            request_id,
        }
    }

    const fn from_upload(error: UploadError, request_id: RequestId) -> Self {
        let status = match error {
            UploadError::Invalid => StatusCode::BAD_REQUEST,
            UploadError::Unauthorized | UploadError::NotFound => StatusCode::NOT_FOUND,
            UploadError::Conflict | UploadError::State => StatusCode::CONFLICT,
            UploadError::SizeMismatch
            | UploadError::ChecksumMismatch
            | UploadError::MimeMismatch
            | UploadError::MalwareDetected => StatusCode::UNPROCESSABLE_ENTITY,
            UploadError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            UploadError::Cancelled => StatusCode::REQUEST_TIMEOUT,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        Self { status, request_id }
    }

    const fn from_tenancy(error: TenancyStoreError, request_id: RequestId) -> Self {
        let status = match error {
            TenancyStoreError::AccessDenied
            | TenancyStoreError::TenantMismatch
            | TenancyStoreError::MembershipNotFound
            | TenancyStoreError::UserNotFound => StatusCode::NOT_FOUND,
            TenancyStoreError::Unavailable | TenancyStoreError::Transient(_) => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            TenancyStoreError::Conflict
            | TenancyStoreError::MembershipAlreadyActive
            | TenancyStoreError::InvalidMembershipTransition
            | TenancyStoreError::LastOwner
            | TenancyStoreError::InvitationAlreadyPending
            | TenancyStoreError::InvitationUnavailable
            | TenancyStoreError::InvitationExpired => StatusCode::CONFLICT,
            TenancyStoreError::InvalidInvitationExpiry | TenancyStoreError::ListLimitExceeded => {
                StatusCode::BAD_REQUEST
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self { status, request_id }
    }
}

impl axum::response::IntoResponse for BrowserHttpError {
    fn into_response(self) -> Response {
        match ProblemDetails::try_for_status(self.status, self.request_id) {
            Ok(problem) => problem.into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        error::Error,
        io,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use omnius_auth_core::{AssuranceLevel, AuthMethod, PrincipalKind, Scope};
    use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
    use omnius_postgres::{
        PostgresConfig, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
    };
    use omnius_tenancy::OrganizationName;
    use omnius_test_support::PostgresFixture;
    use time::OffsetDateTime;
    use tokio::{io::ReadBuf, net::TcpListener, task::JoinHandle};

    use super::*;

    const FIRST_MIGRATION: i64 = 2_026_082_301;
    async fn fragmented_clamd_peer()
    -> io::Result<(SocketAddr, JoinHandle<io::Result<Vec<Vec<u8>>>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut buffered = Vec::new();
            let mut scratch = [0_u8; 3];
            let mut cursor = 0;

            while buffered.len() < b"zINSTREAM\0".len() {
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                buffered.extend_from_slice(&scratch[..read]);
            }
            if !buffered.starts_with(b"zINSTREAM\0") {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            cursor += b"zINSTREAM\0".len();

            let mut chunks = Vec::new();
            loop {
                while buffered.len().saturating_sub(cursor) < size_of::<u32>() {
                    let read = stream.read(&mut scratch).await?;
                    if read == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    buffered.extend_from_slice(&scratch[..read]);
                }
                let length = u32::from_be_bytes(
                    buffered[cursor..cursor + size_of::<u32>()]
                        .try_into()
                        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
                ) as usize;
                cursor += size_of::<u32>();
                if length == 0 {
                    break;
                }
                while buffered.len().saturating_sub(cursor) < length {
                    let read = stream.read(&mut scratch).await?;
                    if read == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                    }
                    buffered.extend_from_slice(&scratch[..read]);
                }
                chunks.push(buffered[cursor..cursor + length].to_vec());
                cursor += length;
            }
            stream.write_all(b"stream: OK\0").await?;
            Ok(chunks)
        });
        Ok((address, peer))
    }
    struct FragmentedVerdictReader {
        fragments: VecDeque<&'static [u8]>,
        reads: usize,
    }

    impl FragmentedVerdictReader {
        fn new(fragments: impl IntoIterator<Item = &'static [u8]>) -> Self {
            Self {
                fragments: fragments.into_iter().collect(),
                reads: 0,
            }
        }
    }

    impl AsyncRead for FragmentedVerdictReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let Some(fragment) = self.fragments.pop_front() else {
                return Poll::Ready(Ok(()));
            };
            self.reads += 1;
            let length = fragment.len().min(buffer.remaining());
            buffer.put_slice(&fragment[..length]);
            if length < fragment.len() {
                self.fragments.push_front(&fragment[length..]);
            }
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn clamd_verdict_accumulates_deterministically_fragmented_reads()
    -> Result<(), Box<dyn Error>> {
        let mut reader = FragmentedVerdictReader::new([b"stream: ".as_slice(), b"OK\0".as_slice()]);
        let verdict = read_clamd_verdict(
            &mut reader,
            Duration::from_secs(1),
            &CancellationToken::new(),
        )
        .await
        .map_err(|_| "fragmented verdict was rejected")?;

        assert_eq!((verdict, reader.reads), (ScanVerdict::Clean, 2));
        Ok(())
    }

    #[tokio::test]
    async fn clamd_scanner_streams_all_chunks_to_a_fragmented_peer() -> Result<(), Box<dyn Error>> {
        let (address, peer) = fragmented_clamd_peer().await?;
        let scanner = ClamdScanner::new(ClamdScannerConfig {
            address,
            connect_timeout: Duration::from_secs(1),
            io_timeout: Duration::from_secs(1),
        })?;
        let cancellation = CancellationToken::new();
        let mut session = scanner
            .start(
                ScanMetadata {
                    upload_id: UploadId::new(),
                    declared_size: 10,
                    expected_sha256: Sha256Digest::from_bytes([7; 32]),
                    detected_mime: DeclaredMime::Pdf,
                },
                &cancellation,
            )
            .await
            .map_err(|_| "scanner did not connect")?;
        session
            .scan_chunk(Bytes::from_static(b"first"), &cancellation)
            .await
            .map_err(|_| "scanner rejected the first chunk")?;
        session
            .scan_chunk(Bytes::from_static(b"second"), &cancellation)
            .await
            .map_err(|_| "scanner rejected the second chunk")?;
        let verdict = session
            .finish(&cancellation)
            .await
            .map_err(|_| "scanner rejected the peer verdict")?;
        let chunks = peer.await??;

        assert_eq!(
            (verdict, chunks),
            (
                ScanVerdict::Clean,
                vec![b"first".to_vec(), b"second".to_vec()]
            )
        );
        Ok(())
    }

    struct TenantFixture {
        _postgres: PostgresFixture,
        store: TenancyStore,
        subject_id: SubjectId,
        first_tenant: TenantId,
        second_tenant: TenantId,
        unauthorized_tenant: TenantId,
    }

    fn postgres_config(fixture: &PostgresFixture) -> PostgresConfig {
        PostgresConfig {
            url: fixture.database_url().clone(),
            tls_mode: PostgresTlsMode::Disable,
            min_connections: 1,
            max_connections: 3,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(30),
            max_lifetime: Duration::from_secs(60),
            max_lifetime_jitter: Duration::from_secs(10),
            application_name: "omnius-browser-upload-test".to_owned(),
            initialization_sql: Vec::new(),
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(1),
            health_timeout: Duration::from_secs(2),
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

    async fn seed_user(pool: &PostgresPool) -> Result<SubjectId, Box<dyn Error>> {
        let subject_id = SubjectId::new();
        let mut connection = pool.acquire().await?;
        sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
            .bind(subject_id.as_uuid())
            .bind(OffsetDateTime::now_utc())
            .execute(&mut *connection)
            .await?;
        Ok(subject_id)
    }

    async fn tenant_fixture() -> Result<TenantFixture, Box<dyn Error>> {
        let postgres = PostgresFixture::start().await?;
        let pool =
            PostgresPool::connect(&postgres_config(&postgres), DeploymentEnvironment::Test).await?;
        MigrationRunner::new(
            pool.clone(),
            &MIGRATOR,
            SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
            MigrationConfig {
                run_on_startup: false,
                operation_timeout: Duration::from_secs(10),
            },
            DeploymentEnvironment::Test,
        )?
        .run()
        .await?;
        let subject_id = seed_user(&pool).await?;
        let other_subject_id = seed_user(&pool).await?;
        let store = TenancyStore::new(pool, &TenancyConfig::default())?;
        let first = store
            .create_organization(subject_id, OrganizationName::new("First tenant")?)
            .await?;
        let second = store
            .create_organization(subject_id, OrganizationName::new("Second tenant")?)
            .await?;
        let unauthorized = store
            .create_organization(
                other_subject_id,
                OrganizationName::new("Unauthorized tenant")?,
            )
            .await?;
        Ok(TenantFixture {
            _postgres: postgres,
            store,
            subject_id,
            first_tenant: first.organization.id,
            second_tenant: second.organization.id,
            unauthorized_tenant: unauthorized.organization.id,
        })
    }

    fn bound_principal(fixture: &TenantFixture) -> Result<Principal, Box<dyn Error>> {
        Ok(Principal::new(
            fixture.subject_id,
            PrincipalKind::User,
            Some(fixture.first_tenant),
            AuthMethod::Session,
            OffsetDateTime::now_utc(),
            AssuranceLevel::Aal2,
            vec![Scope::new("browser:tenant")?],
        )?)
    }

    #[tokio::test]
    async fn listing_from_bound_tenant_resolves_both_memberships() -> Result<(), Box<dyn Error>> {
        let fixture = tenant_fixture().await?;
        let principal = bound_principal(&fixture)?;
        let summaries = list_tenant_summaries(&fixture.store, &principal, RequestId::new())
            .await
            .map_err(|_| "tenant listing failed")?;

        assert_eq!(summaries.len(), 2);
        assert!(
            summaries
                .iter()
                .any(|summary| summary.tenant_id == fixture.first_tenant)
        );
        assert!(
            summaries
                .iter()
                .any(|summary| summary.tenant_id == fixture.second_tenant)
        );
        assert_eq!(principal.tenant_id, Some(fixture.first_tenant));
        Ok(())
    }

    #[tokio::test]
    async fn switching_from_bound_tenant_resolves_second_membership_and_preserves_auth_context()
    -> Result<(), Box<dyn Error>> {
        let fixture = tenant_fixture().await?;
        let principal = bound_principal(&fixture)?;
        let context = resolve_switch_context(
            &fixture.store,
            &principal,
            fixture.second_tenant,
            RequestId::new(),
        )
        .await
        .map_err(|_| "tenant switch resolution failed")?;

        assert_eq!(context.principal().tenant_id, Some(fixture.second_tenant));
        assert_eq!(context.principal().subject_id, principal.subject_id);
        assert_eq!(context.principal().kind, principal.kind);
        assert_eq!(context.principal().auth_method, principal.auth_method);
        assert_eq!(
            context.principal().authenticated_at,
            principal.authenticated_at
        );
        assert_eq!(context.principal().assurance, principal.assurance);
        assert_eq!(&context.principal().scopes, &principal.scopes);
        Ok(())
    }

    #[tokio::test]
    async fn switching_from_bound_tenant_fails_closed_for_unauthorized_target()
    -> Result<(), Box<dyn Error>> {
        let fixture = tenant_fixture().await?;
        let principal = bound_principal(&fixture)?;
        let result = resolve_switch_context(
            &fixture.store,
            &principal,
            fixture.unauthorized_tenant,
            RequestId::new(),
        )
        .await;
        let Err(error) = result else {
            return Err("unauthorized tenant switch unexpectedly succeeded".into());
        };

        assert_eq!(error.status, StatusCode::NOT_FOUND);
        assert_eq!(principal.tenant_id, Some(fixture.first_tenant));
        Ok(())
    }
}
