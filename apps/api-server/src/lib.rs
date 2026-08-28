//! Reference Axum API profile with transactional idempotency and deterministic `OpenAPI`.

pub mod browser_auth;
pub mod browser_realtime;
pub mod browser_uploads;
mod contracts;

use std::{str::FromStr as _, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_MATCH, WWW_AUTHENTICATE},
    },
    middleware,
    response::{IntoResponse, Response},
    routing::get,
};
use axum_login::{AuthManagerLayerBuilder, AuthSession};
use browser_realtime::{ReferenceRecordInvalidationPublisher, ReferenceRecordMutation};
use contracts::{__path_runtime_metadata, RuntimeMetadataResponse};
pub use contracts::{
    BUILD_REVISION, CONTRACT_SCHEMA_VERSION, ContractMetadataError, MINIMUM_SDK_VERSION,
    PUBLIC_API_VERSION, PUBLIC_METADATA_PATH, PUBLIC_PROFILE, PUBLIC_PROFILE_MODULES,
    PublicCapability, PublicCapabilityId, PublicPermission, PublicPermissionId, PublicTransports,
    aggregate_contract_sha256, capabilities_contract_json, metadata_router,
    permissions_contract_json, public_capabilities, public_permissions, public_transports,
    selected_browser_command_actions,
};
use garde::Validate as _;
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, SessionConfig, SessionConfigError,
    SessionValidation, TenantId,
};
use omnius_auth_jwt::{JwtVerifier, JwtVerifyError};
use omnius_auth_session_postgres::{
    PostgresSessionLifecycle, SessionBackend, SessionGuardError, SessionRevocationGuard,
    SessionUser, guard_revoked_session, session_manager_layer,
};
use omnius_config::DeploymentEnvironment;
use omnius_core::{Clock, ErrorCode, RequestId, ServiceError};
use omnius_http::{FieldError, IfMatch, ProblemDetails, VersionEtag};
use omnius_idempotency::{
    ClaimOutcome, IdempotencyKey, IdempotencyOperation, IdempotencyRequest, IdempotencyScope,
    IdempotencyStoreError, PostgresIdempotencyStore, RequestFingerprint, SafeResponse,
};
pub use omnius_openapi::{ExpectedOperation, OpenApiCatalog, OpenApiConfig, OpenApiError};
use omnius_pagination::{CursorCodec, OpaqueCursor, PageLimit, PageRequest};
use omnius_postgres::PostgresPool;
use omnius_realtime_core::MessageId;
use omnius_reference_domain::{
    ReferenceDomainError, ReferencePaginationError, ReferenceRecord, ReferenceRecordId,
    ReferenceRecordNameFilter, ReferenceRecordPageRequest, ReferenceRecordUpdate,
};
use omnius_reference_postgres::{
    PostgresReferenceRecordPaginator, PostgresReferenceRecordRepository, ReferenceStoreError,
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection as _, PgConnection};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use utoipa::{
    Modify, ToSchema,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};

const COLLECTION_PATH: &str = "/reference-records";
const ITEM_PATH: &str = "/reference-records/{id}";
const CURRENT_PRINCIPAL_PATH: &str = "/whoami";
const JSON_CONTENT_TYPE: &str = "application/json";
const CREATE_OPERATION: &str = "reference-records.create";
const CREATE_FINGERPRINT_PREFIX: &[u8] =
    b"POST\n/reference-records\ncontent-type:application/json\n\n";

/// Complete browser-consumable route registry for the assembled reference API.
///
/// Documentation endpoints supplied by `omnius-openapi` are operator-only and
/// intentionally excluded.
pub const PUBLIC_HTTP_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new(
        "get",
        PUBLIC_METADATA_PATH,
        "getRuntimeMetadata",
        "metadata",
    ),
    ExpectedOperation::new("get", "/live", "getLiveness", "health"),
    ExpectedOperation::new("get", "/ready", "getReadiness", "health"),
    ExpectedOperation::new("get", "/startup", "getStartup", "health"),
    ExpectedOperation::new("get", "/version", "getVersion", "health"),
    ExpectedOperation::new(
        "get",
        COLLECTION_PATH,
        "listReferenceRecords",
        "reference-records",
    ),
    ExpectedOperation::new(
        "post",
        COLLECTION_PATH,
        "createReferenceRecord",
        "reference-records",
    ),
    ExpectedOperation::new("get", ITEM_PATH, "getReferenceRecord", "reference-records"),
    ExpectedOperation::new(
        "put",
        ITEM_PATH,
        "updateReferenceRecord",
        "reference-records",
    ),
    ExpectedOperation::new(
        "delete",
        ITEM_PATH,
        "deleteReferenceRecord",
        "reference-records",
    ),
    ExpectedOperation::new(
        "get",
        CURRENT_PRINCIPAL_PATH,
        "getCurrentPrincipal",
        "identity",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/login",
        "loginBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/session",
        "getBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/logout",
        "logoutBrowserSession",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/logout-all",
        "logoutAllBrowserSessions",
        "authentication",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/permissions/privileged",
        "checkPrivilegedBrowserPermission",
        "authorization",
    ),
    ExpectedOperation::new("get", "/tenants", "listBrowserTenants", "tenancy"),
    ExpectedOperation::new(
        "post",
        "/tenants/{tenant_id}/switch",
        "switchBrowserTenant",
        "tenancy",
    ),
    ExpectedOperation::new("post", "/uploads", "initiateBrowserUpload", "uploads"),
    ExpectedOperation::new(
        "put",
        "/uploads/{upload_id}/content",
        "transferBrowserUploadContent",
        "uploads",
    ),
    ExpectedOperation::new(
        "post",
        "/uploads/{upload_id}/complete",
        "completeBrowserUpload",
        "uploads",
    ),
    ExpectedOperation::new(
        "post",
        "/uploads/{upload_id}/status",
        "getBrowserUploadStatus",
        "uploads",
    ),
    ExpectedOperation::new(
        "post",
        "/uploads/{upload_id}/abandon",
        "abandonBrowserUpload",
        "uploads",
    ),
    ExpectedOperation::new(
        "get",
        "/uploads/{upload_id}/download",
        "downloadBrowserUpload",
        "uploads",
    ),
];
/// Shared application state for the reference CRUD profile.
#[derive(Clone)]
pub struct ReferenceApiState {
    pool: PostgresPool,
    repository: PostgresReferenceRecordRepository,
    paginator: PostgresReferenceRecordPaginator,
    cursor_codec: CursorCodec,
    idempotency_store: PostgresIdempotencyStore,
    clock: Arc<dyn Clock>,
    realtime_publisher: Arc<dyn ReferenceRecordInvalidationPublisher>,
}

impl ReferenceApiState {
    /// Builds the reference profile from its provider adapters and deterministic clock.
    #[must_use]
    pub fn new(
        pool: PostgresPool,
        cursor_codec: CursorCodec,
        idempotency_store: PostgresIdempotencyStore,
        clock: Arc<dyn Clock>,
        realtime_publisher: Arc<dyn ReferenceRecordInvalidationPublisher>,
    ) -> Self {
        let repository = PostgresReferenceRecordRepository::new(pool.clone());
        let paginator = PostgresReferenceRecordPaginator::new(pool.clone(), cursor_codec.clone());
        Self {
            pool,
            repository,
            paginator,
            cursor_codec,
            idempotency_store,
            clock,
            realtime_publisher,
        }
    }
}

/// Runtime state for the authenticated profile's canonical identity endpoint.
#[derive(Clone)]
pub struct AuthenticatedIdentityState {
    pool: PostgresPool,
    session_config: SessionConfig,
    jwt_verifier: Option<JwtVerifier>,
}

impl AuthenticatedIdentityState {
    /// Builds identity composition from the PostgreSQL session provider and optional JWT verifier.
    #[must_use]
    pub const fn new(
        pool: PostgresPool,
        session_config: SessionConfig,
        jwt_verifier: Option<JwtVerifier>,
    ) -> Self {
        Self {
            pool,
            session_config,
            jwt_verifier,
        }
    }
}

/// Failure to compose the authenticated identity endpoint and its fail-closed session guard.
#[derive(Debug, Error)]
pub enum AuthenticatedIdentityBuildError {
    /// Session cookie or persistence policy is invalid.
    #[error("session manager configuration is invalid: {0}")]
    Session(#[from] SessionConfigError),
    /// Revocation guard policy is invalid.
    #[error("session revocation guard configuration is invalid: {0}")]
    Guard(#[from] SessionGuardError),
}

async fn prefer_bearer_over_session_cookie(
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.headers().contains_key(AUTHORIZATION) {
        request.headers_mut().remove(axum::http::header::COOKIE);
    }
    next.run(request).await
}

/// Builds the authenticated profile endpoint with the real session manager and JWT verifier.
///
/// # Errors
///
/// Returns [`AuthenticatedIdentityBuildError`] when the session manager or its outer revocation
/// guard cannot enforce the configured cookie and expiry policy.
pub fn authenticated_identity_router(
    state: AuthenticatedIdentityState,
    deployment: DeploymentEnvironment,
) -> Result<Router, AuthenticatedIdentityBuildError> {
    let auth_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(state.pool.clone()),
        session_manager_layer(&state.pool, &state.session_config, deployment)?,
    )
    .build();
    let revocation_guard = SessionRevocationGuard::new(state.pool.clone(), &state.session_config)?;
    Ok(Router::new()
        .route(CURRENT_PRINCIPAL_PATH, get(current_principal))
        .with_state(state)
        .layer(auth_layer)
        .layer(middleware::from_fn_with_state(
            revocation_guard,
            guard_revoked_session,
        ))
        .layer(middleware::from_fn(prefer_bearer_over_session_cookie)))
}

type BrowserAuthSession = AuthSession<SessionBackend>;

#[derive(Serialize, ToSchema)]
struct PrincipalResponse {
    subject_id: String,
    kind: &'static str,
    tenant_id: Option<String>,
    auth_method: &'static str,
    authenticated_at: String,
    assurance: &'static str,
    scopes: Vec<String>,
}

impl PrincipalResponse {
    fn from_principal(principal: Principal) -> Result<Self, time::error::Format> {
        Ok(Self {
            subject_id: principal.subject_id.to_string(),
            kind: match principal.kind {
                PrincipalKind::User => "user",
                PrincipalKind::ServiceAccount => "service_account",
            },
            tenant_id: principal.tenant_id.map(|tenant_id| tenant_id.to_string()),
            auth_method: match principal.auth_method {
                AuthMethod::Password => "password",
                AuthMethod::Session => "session",
                AuthMethod::Jwt => "jwt",
                AuthMethod::Oidc => "oidc",
                AuthMethod::ApiKey => "api_key",
                AuthMethod::WebAuthn => "web_authn",
                AuthMethod::Totp => "totp",
            },
            authenticated_at: principal.authenticated_at.format(&Rfc3339)?,
            assurance: match principal.assurance {
                AssuranceLevel::Aal1 => "aal1",
                AssuranceLevel::Aal2 => "aal2",
                AssuranceLevel::Aal3 => "aal3",
            },
            scopes: principal
                .scopes
                .into_iter()
                .map(|scope| scope.to_string())
                .collect(),
        })
    }
}

#[utoipa::path(
    get,
    path = "/whoami",
    operation_id = "getCurrentPrincipal",
    tag = "identity",
    responses(
        (status = 200, description = "Canonical principal for the accepted credential", body = PrincipalResponse, content_type = "application/json"),
        (status = 401, description = "Session or bearer credential is missing or invalid", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Authentication persistence is unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(
        ("session_cookie" = []),
        ("bearer_auth" = [])
    )
)]
async fn current_principal(
    State(state): State<AuthenticatedIdentityState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
) -> Result<Response, AuthenticationError> {
    let request_id = resolve_request_id(request_id);
    let principal = if headers.contains_key(AUTHORIZATION) {
        authenticate_bearer(&state, &headers)
            .await
            .map_err(|failure| match failure {
                BearerFailure::Rejected => AuthenticationError::unauthorized(request_id),
                BearerFailure::Unavailable => AuthenticationError::unavailable(request_id),
            })?
    } else {
        authenticate_session(&state, &mut auth, request_id).await?
    };
    let response = PrincipalResponse::from_principal(principal)
        .map_err(|_| AuthenticationError::internal(request_id))?;
    let mut response = Json(response).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

#[derive(Clone, Copy)]
enum BearerFailure {
    Rejected,
    Unavailable,
}

async fn authenticate_bearer(
    state: &AuthenticatedIdentityState,
    headers: &HeaderMap,
) -> Result<Principal, BearerFailure> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(BearerFailure::Rejected)?;
    if values.next().is_some() {
        return Err(BearerFailure::Rejected);
    }
    let value = value.to_str().map_err(|_| BearerFailure::Rejected)?;
    let (scheme, token) = value.split_once(' ').ok_or(BearerFailure::Rejected)?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return Err(BearerFailure::Rejected);
    }
    state
        .jwt_verifier
        .as_ref()
        .ok_or(BearerFailure::Rejected)?
        .verify(token)
        .await
        .map_err(|error| match error {
            JwtVerifyError::JwksUnavailable | JwtVerifyError::InvalidJwks => {
                BearerFailure::Unavailable
            }
            JwtVerifyError::MalformedToken
            | JwtVerifyError::AlgorithmRejected
            | JwtVerifyError::KeyIdRejected
            | JwtVerifyError::TokenClassRejected
            | JwtVerifyError::ClaimsRejected
            | JwtVerifyError::TokenRejected => BearerFailure::Rejected,
        })
}

async fn authenticate_session(
    state: &AuthenticatedIdentityState,
    auth: &mut BrowserAuthSession,
    request_id: RequestId,
) -> Result<Principal, AuthenticationError> {
    let subject_id = auth
        .user
        .as_ref()
        .map(SessionUser::subject_id)
        .ok_or_else(|| AuthenticationError::unauthorized(request_id))?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| AuthenticationError::unavailable(request_id))?;
    let validation = PostgresSessionLifecycle
        .validate_and_touch_with(
            &mut connection,
            &auth.session,
            subject_id,
            &state.session_config,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|_| AuthenticationError::unavailable(request_id))?;
    drop(connection);
    match validation {
        SessionValidation::Active(metadata) => auth
            .user
            .as_ref()
            .map(|user| user.principal(metadata.created_at))
            .ok_or_else(|| AuthenticationError::unauthorized(request_id)),
        SessionValidation::Rejected => {
            auth.logout()
                .await
                .map_err(|_| AuthenticationError::internal(request_id))?;
            Err(AuthenticationError::unauthorized(request_id))
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct AuthenticationError(ApiError);

impl AuthenticationError {
    const fn unauthorized(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "a valid session or bearer credential is required",
            request_id,
        ))
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "AUTHENTICATION_UNAVAILABLE",
            "authentication is temporarily unavailable",
            request_id,
        ))
    }

    const fn internal(request_id: RequestId) -> Self {
        Self(ApiError::internal(request_id))
    }
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        if response.status() == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// Builds the five-route reference CRUD router with all dependencies installed.
pub fn reference_router(state: ReferenceApiState) -> Router {
    Router::new()
        .route(
            COLLECTION_PATH,
            get(list_reference_records).post(create_reference_record),
        )
        .route(
            ITEM_PATH,
            get(get_reference_record)
                .put(update_reference_record)
                .delete(delete_reference_record),
        )
        .with_state(state)
}

/// Generates the policy-validated, canonical `OpenAPI` 3.1 document.
///
/// # Errors
///
/// Returns [`OpenApiError`] if generation, validation, or canonical serialization fails.
pub fn openapi_json() -> Result<Vec<u8>, OpenApiError> {
    let document = <ReferenceApiDocument as utoipa::OpenApi>::openapi();
    omnius_openapi::validate_operation_coverage(&document, PUBLIC_HTTP_OPERATIONS)?;
    omnius_openapi::deterministic_json(&document)
}

/// Generates and validates the locally served API catalog.
///
/// # Errors
///
/// Returns [`OpenApiError`] if the catalog configuration, document policy, or
/// public route coverage is invalid.
pub fn openapi_catalog(config: OpenApiConfig) -> Result<OpenApiCatalog, OpenApiError> {
    let document = <ReferenceApiDocument as utoipa::OpenApi>::openapi();
    omnius_openapi::validate_operation_coverage(&document, PUBLIC_HTTP_OPERATIONS)?;
    OpenApiCatalog::try_new(&document, config)
}

#[derive(Debug, Deserialize, garde::Validate)]
#[serde(deny_unknown_fields)]
struct ReferenceRecordPath {
    #[garde(ascii, length(bytes, equal = 36))]
    id: String,
}

#[derive(Debug, Default, Deserialize, garde::Validate)]
#[serde(default, deny_unknown_fields)]
struct ListReferenceRecordsQuery {
    #[garde(inner(range(min = 1, max = 100)))]
    limit: Option<u16>,
    #[garde(inner(ascii, length(bytes, min = 1, max = 256)))]
    cursor: Option<String>,
    #[garde(inner(length(chars, min = 1, max = 100), custom(validate_reference_name)))]
    name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, garde::Validate, ToSchema)]
#[serde(deny_unknown_fields)]
struct CreateReferenceRecordRequest {
    #[garde(length(chars, min = 1, max = 100), custom(validate_reference_name))]
    #[schema(min_length = 1, max_length = 100, pattern = r".*\S.*")]
    name: String,
}

#[derive(Debug, Deserialize, garde::Validate, ToSchema)]
#[serde(deny_unknown_fields)]
struct UpdateReferenceRecordRequest {
    #[garde(length(chars, min = 1, max = 100), custom(validate_reference_name))]
    #[schema(min_length = 1, max_length = 100, pattern = r".*\S.*")]
    name: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ReferenceRecordResponse {
    #[schema(format = Uuid, pattern = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")]
    id: String,
    #[schema(min_length = 1, max_length = 100)]
    name: String,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    updated_at: String,
    #[schema(minimum = 1)]
    version: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct ReferenceRecordPageResponse {
    #[schema(max_items = 100)]
    items: Vec<ReferenceRecordResponse>,
    #[schema(required = true, value_type = Option<String>, min_length = 1, max_length = 256)]
    next_cursor: Option<OpaqueCursor>,
}

#[expect(
    dead_code,
    reason = "schema-only health contract implemented by omnius-health"
)]
#[derive(ToSchema)]
struct HealthStatusSchema {
    #[schema(pattern = r"^(live|ready|not_ready|started|starting|startup_failed)$")]
    status: String,
}

#[expect(
    dead_code,
    reason = "schema-only version contract implemented by omnius-health"
)]
#[derive(ToSchema)]
struct VersionStatusSchema {
    service: String,
    version: String,
    #[schema(required = true)]
    git_revision: Option<String>,
    #[schema(required = true, format = DateTime)]
    build_time: Option<String>,
    compiler: String,
    kit_version: String,
    profile: String,
    modules: Vec<String>,
    schema: SchemaCompatibilitySchema,
}

#[expect(
    dead_code,
    reason = "schema-only version contract implemented by omnius-core"
)]
#[derive(ToSchema)]
struct SchemaCompatibilitySchema {
    minimum: String,
    maximum: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of omnius_http::FieldError"
)]
#[derive(ToSchema)]
struct ProblemFieldErrorSchema {
    #[schema(pattern = r"^(|/(?:[^~/]|~[01])*)$")]
    pointer: String,
    #[schema(pattern = r"^[a-z][a-z0-9_]*$")]
    code: String,
    #[schema(min_length = 1)]
    message: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of omnius_http::ProblemDetails"
)]
#[derive(ToSchema)]
struct ProblemDetailsSchema {
    #[schema(format = "uri", example = "https://errors.omnius.invalid/internal")]
    r#type: String,
    #[schema(min_length = 1)]
    title: String,
    #[schema(minimum = 400, maximum = 599)]
    status: u16,
    #[schema(pattern = r"^[A-Z][A-Z0-9_]{0,63}$")]
    code: String,
    #[schema(format = Uuid)]
    request_id: String,
    detail: Option<String>,
    #[schema(max_items = 100)]
    errors: Option<Vec<ProblemFieldErrorSchema>>,
}

struct AuthenticationSecurity;

impl Modify for AuthenticationSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let Some(components) = openapi.components.as_mut() else {
            return;
        };
        components.add_security_scheme(
            "session_cookie",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("__Host-omnius_session"))),
        );
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Omnius Reference API",
        version = "0.1.0",
        description = "Authenticated reference CRUD profile"
    ),
    paths(
        current_principal,
        live_contract,
        ready_contract,
        startup_contract,
        version_contract,
        runtime_metadata,
        list_reference_records,
        create_reference_record,
        get_reference_record,
        update_reference_record,
        browser_login_contract,
        browser_session_contract,
        browser_logout_contract,
        browser_logout_all_contract,
        browser_privileged_permission_contract,
        browser_tenant_list_contract,
        browser_tenant_switch_contract,
        browser_upload_initiate_contract,
        browser_upload_content_contract,
        browser_upload_complete_contract,
        browser_upload_status_contract,
        browser_upload_abandon_contract,
        browser_upload_download_contract,
        delete_reference_record
    ),
    components(schemas(
        PrincipalResponse,
        CreateReferenceRecordRequest,
        UpdateReferenceRecordRequest,
        ReferenceRecordResponse,
        ReferenceRecordPageResponse,
        HealthStatusSchema,
        VersionStatusSchema,
        SchemaCompatibilitySchema,
        ProblemFieldErrorSchema,
        ProblemDetailsSchema,
        RuntimeMetadataResponse,
        PublicTransports,
    )),
    tags(
        (name = "health", description = "Process and dependency health"),
        (name = "reference-records", description = "Reference record CRUD operations"),
        (name = "identity", description = "Canonical authenticated identity"),
        (name = "metadata", description = "Public consumer contract compatibility metadata"),
        (name = "authentication", description = "Opaque browser session lifecycle"),
        (name = "authorization", description = "Backend permission decisions"),
        (name = "tenancy", description = "Authenticated tenant selection"),
        (name = "uploads", description = "Tenant-scoped upload lifecycle"),
    ),
    modifiers(&AuthenticationSecurity)
)]
struct ReferenceApiDocument;

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    post, path = "/auth/login", operation_id = "loginBrowserSession", tag = "authentication",
    request_body(content = serde_json::Value, content_type = "application/json"),
    responses(
        (status = 200, description = "Authenticated browser session", body = serde_json::Value),
        (status = 401, description = "Credentials rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "Request validation failed", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn browser_login_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    get, path = "/auth/session", operation_id = "getBrowserSession", tag = "authentication",
    responses(
        (status = 200, description = "Current browser session", body = serde_json::Value),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_session_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    post, path = "/auth/logout", operation_id = "logoutBrowserSession", tag = "authentication",
    responses(
        (status = 204, description = "Current session revoked"),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_logout_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    post, path = "/auth/logout-all", operation_id = "logoutAllBrowserSessions", tag = "authentication",
    responses(
        (status = 204, description = "All subject sessions revoked"),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_logout_all_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    post, path = "/auth/permissions/privileged", operation_id = "checkPrivilegedBrowserPermission", tag = "authorization",
    responses(
        (status = 204, description = "Permission granted"),
        (status = 403, description = "Permission denied", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_privileged_permission_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    get, path = "/tenants", operation_id = "listBrowserTenants", tag = "tenancy",
    responses(
        (status = 200, description = "Active tenant memberships", body = Vec<serde_json::Value>),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_tenant_list_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    post, path = "/tenants/{tenant_id}/switch", operation_id = "switchBrowserTenant", tag = "tenancy",
    params(("tenant_id" = String, Path, format = Uuid)),
    responses(
        (status = 200, description = "Authoritative selected tenant", body = serde_json::Value),
        (status = 403, description = "Membership denied", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_tenant_switch_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    post, path = "/uploads", operation_id = "initiateBrowserUpload", tag = "uploads",
    request_body(content = serde_json::Value, content_type = "application/json"),
    responses(
        (status = 200, description = "Upload initiated or resumed", body = serde_json::Value),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_initiate_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    put, path = "/uploads/{upload_id}/content", operation_id = "transferBrowserUploadContent", tag = "uploads",
    params(("upload_id" = String, Path, format = Uuid)),
    request_body(content = Vec<u8>, content_type = "application/octet-stream"),
    responses(
        (status = 204, description = "Upload bytes accepted"),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_content_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    post, path = "/uploads/{upload_id}/complete", operation_id = "completeBrowserUpload", tag = "uploads",
    params(("upload_id" = String, Path, format = Uuid)),
    request_body(content = serde_json::Value, content_type = "application/json"),
    responses(
        (status = 200, description = "Upload completion status", body = serde_json::Value),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_complete_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    post, path = "/uploads/{upload_id}/status", operation_id = "getBrowserUploadStatus", tag = "uploads",
    params(("upload_id" = String, Path, format = Uuid)),
    request_body(content = serde_json::Value, content_type = "application/json"),
    responses(
        (status = 200, description = "Authoritative upload status", body = serde_json::Value),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_status_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    post, path = "/uploads/{upload_id}/abandon", operation_id = "abandonBrowserUpload", tag = "uploads",
    params(("upload_id" = String, Path, format = Uuid)),
    request_body(content = serde_json::Value, content_type = "application/json"),
    responses(
        (status = 204, description = "Pending upload abandoned"),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_abandon_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_uploads")]
#[utoipa::path(
    get, path = "/uploads/{upload_id}/download", operation_id = "downloadBrowserUpload", tag = "uploads",
    params(("upload_id" = String, Path, format = Uuid)),
    responses(
        (status = 200, description = "Authorized upload bytes", body = Vec<u8>, content_type = "application/octet-stream"),
        (status = 401, description = "Session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_upload_download_contract() {}
/// `OpenAPI` metadata carrier for the `omnius-health` `GET /live` handler.
#[expect(dead_code, reason = "runtime route is implemented by omnius-health")]
#[utoipa::path(
    get,
    path = "/live",
    operation_id = "getLiveness",
    tag = "health",
    responses(
        (status = 200, description = "Process is live", body = HealthStatusSchema, content_type = "application/json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn live_contract() {}

/// `OpenAPI` metadata carrier for the `omnius-health` `GET /ready` handler.
#[expect(dead_code, reason = "runtime route is implemented by omnius-health")]
#[utoipa::path(
    get,
    path = "/ready",
    operation_id = "getReadiness",
    tag = "health",
    responses(
        (status = 200, description = "Required dependencies are ready", body = HealthStatusSchema, content_type = "application/json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Required dependencies are not ready", body = HealthStatusSchema, content_type = "application/json")
    ),
    security(())
)]
fn ready_contract() {}

/// `OpenAPI` metadata carrier for the `omnius-health` `GET /startup` handler.
#[expect(dead_code, reason = "runtime route is implemented by omnius-health")]
#[utoipa::path(
    get,
    path = "/startup",
    operation_id = "getStartup",
    tag = "health",
    responses(
        (status = 200, description = "Startup completed", body = HealthStatusSchema, content_type = "application/json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Startup is incomplete or failed", body = HealthStatusSchema, content_type = "application/json")
    ),
    security(())
)]
fn startup_contract() {}

/// `OpenAPI` metadata carrier for the `omnius-health` `GET /version` handler.
#[expect(dead_code, reason = "runtime route is implemented by omnius-health")]
#[utoipa::path(
    get,
    path = "/version",
    operation_id = "getVersion",
    tag = "health",
    responses(
        (status = 200, description = "Safe build and composition metadata", body = VersionStatusSchema, content_type = "application/json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn version_contract() {}

#[utoipa::path(
    get,
    path = "/reference-records",
    operation_id = "listReferenceRecords",
    tag = "reference-records",
    params(
        ("limit" = Option<u16>, Query, minimum = 1, maximum = 100, description = "Maximum records to return"),
        ("cursor" = Option<String>, Query, min_length = 1, max_length = 256, description = "Opaque authenticated continuation cursor"),
        ("name" = Option<String>, Query, min_length = 1, max_length = 100, description = "Case-insensitive name substring")
    ),
    responses(
        (status = 200, description = "Bounded page in canonical creation order", body = ReferenceRecordPageResponse, content_type = "application/json"),
        (status = 400, description = "Malformed query, invalid filter, or invalid cursor", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
async fn list_reference_records(
    State(state): State<ReferenceApiState>,
    request_id: Option<Extension<RequestId>>,
    query: Result<Query<ListReferenceRecordsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let Query(mut query) = query.map_err(|_| {
        ApiError::bad_request(
            "INVALID_PAGINATION",
            "pagination parameters are invalid",
            request_id,
        )
    })?;
    let name_filter = query
        .name
        .take()
        .map(ReferenceRecordNameFilter::try_new)
        .transpose()
        .map_err(|error| map_pagination_error(error, request_id))?;
    query.validate().map_err(|_| {
        ApiError::bad_request(
            "INVALID_PAGINATION",
            "pagination parameters are invalid",
            request_id,
        )
    })?;

    let limit = PageLimit::new(query.limit.unwrap_or(PageLimit::DEFAULT)).map_err(|_| {
        ApiError::bad_request(
            "INVALID_PAGINATION",
            "pagination parameters are invalid",
            request_id,
        )
    })?;
    let cursor = query
        .cursor
        .map(OpaqueCursor::new)
        .transpose()
        .map_err(|_| {
            ApiError::bad_request(
                "INVALID_PAGINATION",
                "pagination parameters are invalid",
                request_id,
            )
        })?;
    let page_request = PageRequest::new(limit, cursor);
    let page_request = ReferenceRecordPageRequest::decode(&page_request, &state.cursor_codec)
        .map_err(|error| map_pagination_error(error, request_id))?
        .with_name_filter(name_filter);

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let page = state
        .paginator
        .list_with(&mut connection, page_request)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    let items = page
        .items
        .iter()
        .map(reference_record_response)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| ApiError::internal(request_id))?;
    let response = ReferenceRecordPageResponse {
        items,
        next_cursor: page.next_cursor,
    };
    json_response(StatusCode::OK, &response, request_id)
}

#[utoipa::path(
    post,
    path = "/reference-records",
    operation_id = "createReferenceRecord",
    tag = "reference-records",
    params(
        ("Idempotency-Key" = String, Header, min_length = 1, max_length = 128, pattern = r"^[!-~]+$", description = "Required opaque idempotency key")
    ),
    request_body(content = CreateReferenceRecordRequest, description = "Reference record to create", content_type = "application/json"),
    responses(
        (status = 201, description = "Created record, or exact replay of the original creation response", body = ReferenceRecordResponse, content_type = "application/json"),
        (status = 400, description = "Malformed JSON or idempotency key", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "Idempotency or persisted-state conflict", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported request media type", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "Request validation failed", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
async fn create_reference_record(
    State(state): State<ReferenceApiState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    payload: Result<Json<CreateReferenceRecordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = mutation_tenant(&principal, request_id)?;
    let key = required_single_header(&headers, "idempotency-key").map_err(|()| {
        ApiError::bad_request(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must contain one valid value",
            request_id,
        )
    })?;
    let key = IdempotencyKey::try_from(key).map_err(|_| {
        ApiError::bad_request(
            "INVALID_IDEMPOTENCY_KEY",
            "Idempotency-Key must contain one valid value",
            request_id,
        )
    })?;
    let Json(command) = payload.map_err(|error| map_json_rejection(&error, request_id))?;
    command.validate().map_err(|_| {
        ApiError::unprocessable_field(
            "VALIDATION_FAILED",
            "request body validation failed",
            request_id,
        )
    })?;
    let fingerprint = create_fingerprint(&command).map_err(|()| ApiError::internal(request_id))?;
    let operation =
        IdempotencyOperation::new(CREATE_OPERATION).map_err(|_| ApiError::internal(request_id))?;
    let identity =
        IdempotencyRequest::new(IdempotencyScope::unscoped(), operation, key, fingerprint);

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let result =
        create_in_transaction(&state, &mut transaction, &identity, command, request_id).await;
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            if transaction.rollback().await.is_err() {
                return Err(ApiError::database_unavailable(request_id));
            }
            return Err(error);
        }
    };
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    match outcome {
        CreateTransactionOutcome::Started { body, record_id } => {
            publish_committed_reference_mutation(
                &state,
                tenant_id,
                record_id,
                ReferenceRecordMutation::Created,
            )
            .await;
            Ok(json_bytes_response(StatusCode::CREATED, body))
        }
        CreateTransactionOutcome::Replay(response) => replay_response(&response, request_id),
        CreateTransactionOutcome::InProgress => Err(ApiError::conflict(
            "IDEMPOTENCY_IN_PROGRESS",
            "an equivalent request is still in progress",
            request_id,
        )),
    }
}

#[utoipa::path(
    get,
    path = "/reference-records/{id}",
    operation_id = "getReferenceRecord",
    tag = "reference-records",
    params(
        ("id" = String, Path, format = Uuid, pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", description = "Reference record UUIDv7")
    ),
    responses(
        (status = 200, description = "Current record representation", body = ReferenceRecordResponse, content_type = "application/json", headers(("ETag" = String, description = "Strong version entity tag"))),
        (status = 400, description = "Malformed reference record identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Reference record not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
async fn get_reference_record(
    State(state): State<ReferenceApiState>,
    request_id: Option<Extension<RequestId>>,
    path: Result<Path<ReferenceRecordPath>, PathRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let id = parse_reference_record_id(path, request_id)?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let record = state
        .repository
        .get_with(&mut connection, id)
        .await
        .map_err(|error| map_store_error(error, request_id))?
        .ok_or_else(|| ApiError::not_found(request_id))?;
    record_json_response(StatusCode::OK, &record, request_id)
}

#[utoipa::path(
    put,
    path = "/reference-records/{id}",
    operation_id = "updateReferenceRecord",
    tag = "reference-records",
    params(
        ("id" = String, Path, format = Uuid, pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", description = "Reference record UUIDv7"),
        ("If-Match" = String, Header, pattern = r#"^(\*|"v[1-9][0-9]*")$"#, description = "Required wildcard or exact strong version entity tag")
    ),
    request_body(content = UpdateReferenceRecordRequest, description = "Replacement mutable state", content_type = "application/json"),
    responses(
        (status = 200, description = "Updated record representation", body = ReferenceRecordResponse, content_type = "application/json", headers(("ETag" = String, description = "Strong version entity tag"))),
        (status = 400, description = "Malformed path, precondition, or JSON", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Reference record not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 412, description = "Version precondition failed or update lost a race", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 413, description = "Request body too large", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 415, description = "Unsupported request media type", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "Request validation failed", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 428, description = "If-Match precondition required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
async fn update_reference_record(
    State(state): State<ReferenceApiState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    path: Result<Path<ReferenceRecordPath>, PathRejection>,
    payload: Result<Json<UpdateReferenceRecordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = mutation_tenant(&principal, request_id)?;
    let id = parse_reference_record_id(path, request_id)?;
    let if_match = parse_required_if_match(&headers, request_id)?;
    let Json(command) = payload.map_err(|error| map_json_rejection(&error, request_id))?;
    command.validate().map_err(|_| {
        ApiError::unprocessable_field(
            "VALIDATION_FAILED",
            "request body validation failed",
            request_id,
        )
    })?;

    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut record = state
        .repository
        .get_with(&mut transaction, id)
        .await
        .map_err(|error| map_store_error(error, request_id))?
        .ok_or_else(|| ApiError::not_found(request_id))?;
    if !if_match.matches(record.version().get()) {
        return Err(ApiError::precondition_failed(request_id));
    }
    record
        .rename(command.name, state.clock.now_utc())
        .map_err(|error| map_domain_error(error, request_id))?;
    let record = match state
        .repository
        .update_with(&mut transaction, &record)
        .await
        .map_err(|error| map_store_error(error, request_id))?
    {
        ReferenceRecordUpdate::Updated(record) => record,
        ReferenceRecordUpdate::NotFound | ReferenceRecordUpdate::VersionConflict => {
            return Err(ApiError::precondition_failed(request_id));
        }
    };
    let response = record_json_response(StatusCode::OK, &record, request_id)?;
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    publish_committed_reference_mutation(
        &state,
        tenant_id,
        record.id(),
        ReferenceRecordMutation::Updated,
    )
    .await;
    Ok(response)
}

#[utoipa::path(
    delete,
    path = "/reference-records/{id}",
    operation_id = "deleteReferenceRecord",
    tag = "reference-records",
    params(
        ("id" = String, Path, format = Uuid, pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-7[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$", description = "Reference record UUIDv7")
    ),
    responses(
        (status = 204, description = "Reference record deleted"),
        (status = 400, description = "Malformed reference record identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Reference record not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
async fn delete_reference_record(
    State(state): State<ReferenceApiState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    path: Result<Path<ReferenceRecordPath>, PathRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let tenant_id = mutation_tenant(&principal, request_id)?;
    let id = parse_reference_record_id(path, request_id)?;
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let mut transaction = connection
        .begin()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    let deleted = state
        .repository
        .delete_with(&mut transaction, id)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    if !deleted {
        return Err(ApiError::not_found(request_id));
    }
    transaction
        .commit()
        .await
        .map_err(|_| ApiError::database_unavailable(request_id))?;
    publish_committed_reference_mutation(&state, tenant_id, id, ReferenceRecordMutation::Deleted)
        .await;
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    Ok(response)
}

async fn create_in_transaction(
    state: &ReferenceApiState,
    connection: &mut PgConnection,
    identity: &IdempotencyRequest,
    command: CreateReferenceRecordRequest,
    request_id: RequestId,
) -> Result<CreateTransactionOutcome, ApiError> {
    match state
        .idempotency_store
        .claim_with(connection, identity)
        .await
        .map_err(|error| map_idempotency_error(error, request_id))?
    {
        ClaimOutcome::Replay(response) => Ok(CreateTransactionOutcome::Replay(response)),
        ClaimOutcome::InProgress => Ok(CreateTransactionOutcome::InProgress),
        ClaimOutcome::Started => {
            let record = ReferenceRecord::create(
                ReferenceRecordId::new(),
                command.name,
                state.clock.now_utc(),
            )
            .map_err(|error| map_domain_error(error, request_id))?;
            let record = state
                .repository
                .create_with(connection, &record)
                .await
                .map_err(|error| map_store_error(error, request_id))?;
            let response =
                reference_record_response(&record).map_err(|()| ApiError::internal(request_id))?;
            let body = serde_json::to_vec(&response).map_err(|_| ApiError::internal(request_id))?;
            let safe_response = SafeResponse::new(
                StatusCode::CREATED.as_u16(),
                Some(JSON_CONTENT_TYPE.to_owned()),
                body.clone(),
            )
            .map_err(|_| ApiError::internal(request_id))?;
            state
                .idempotency_store
                .complete_with(connection, identity, &safe_response)
                .await
                .map_err(|error| map_idempotency_error(error, request_id))?;
            Ok(CreateTransactionOutcome::Started {
                body,
                record_id: record.id(),
            })
        }
    }
}

enum CreateTransactionOutcome {
    Started {
        body: Vec<u8>,
        record_id: ReferenceRecordId,
    },
    Replay(SafeResponse),
    InProgress,
}

fn mutation_tenant(principal: &Principal, request_id: RequestId) -> Result<TenantId, ApiError> {
    principal.tenant_id.ok_or_else(|| {
        ApiError::bad_request(
            "TENANT_CONTEXT_REQUIRED",
            "an active tenant context is required",
            request_id,
        )
    })
}

async fn publish_committed_reference_mutation(
    state: &ReferenceApiState,
    tenant_id: TenantId,
    record_id: ReferenceRecordId,
    mutation: ReferenceRecordMutation,
) {
    if state
        .realtime_publisher
        .publish_reference_record_invalidation(MessageId::new(), tenant_id, record_id, mutation)
        .await
        .is_err()
    {
        tracing::warn!("committed reference-record invalidation was not admitted");
    }
}

fn resolve_request_id(extension: Option<Extension<RequestId>>) -> RequestId {
    extension.map_or_else(RequestId::new, |Extension(request_id)| request_id)
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Garde custom validators require a borrowed context"
)]
fn validate_reference_name(value: &str, _context: &()) -> Result<(), garde::Error> {
    if value.trim().is_empty() {
        Err(garde::Error::new("must contain non-whitespace text"))
    } else {
        Ok(())
    }
}

fn parse_reference_record_id(
    path: Result<Path<ReferenceRecordPath>, PathRejection>,
    request_id: RequestId,
) -> Result<ReferenceRecordId, ApiError> {
    let Path(path) = path.map_err(|_| {
        ApiError::bad_request(
            "INVALID_REFERENCE_RECORD_ID",
            "reference record identifier is invalid",
            request_id,
        )
    })?;
    path.validate().map_err(|_| {
        ApiError::bad_request(
            "INVALID_REFERENCE_RECORD_ID",
            "reference record identifier is invalid",
            request_id,
        )
    })?;
    ReferenceRecordId::from_str(&path.id).map_err(|_| {
        ApiError::bad_request(
            "INVALID_REFERENCE_RECORD_ID",
            "reference record identifier is invalid",
            request_id,
        )
    })
}

fn required_single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, ()> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map_err(|_| ())
}

fn parse_required_if_match(
    headers: &HeaderMap,
    request_id: RequestId,
) -> Result<IfMatch, ApiError> {
    let mut values = headers.get_all(IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(ApiError::new(
            StatusCode::PRECONDITION_REQUIRED,
            "PRECONDITION_REQUIRED",
            "If-Match is required",
            request_id,
        ));
    };
    if values.next().is_some() {
        return Err(ApiError::bad_request(
            "INVALID_IF_MATCH",
            "If-Match must contain one supported value",
            request_id,
        ));
    }
    IfMatch::from_header_value(value).map_err(|_| {
        ApiError::bad_request(
            "INVALID_IF_MATCH",
            "If-Match must contain one supported value",
            request_id,
        )
    })
}

fn create_fingerprint(command: &CreateReferenceRecordRequest) -> Result<RequestFingerprint, ()> {
    let body = serde_json::to_vec(command).map_err(|_| ())?;
    let mut canonical = Vec::with_capacity(CREATE_FINGERPRINT_PREFIX.len() + body.len());
    canonical.extend_from_slice(CREATE_FINGERPRINT_PREFIX);
    canonical.extend_from_slice(&body);
    Ok(RequestFingerprint::sha256(&canonical))
}

fn reference_record_response(record: &ReferenceRecord) -> Result<ReferenceRecordResponse, ()> {
    Ok(ReferenceRecordResponse {
        id: record.id().to_string(),
        name: record.name().to_owned(),
        created_at: record.created_at().format(&Rfc3339).map_err(|_| ())?,
        updated_at: record.updated_at().format(&Rfc3339).map_err(|_| ())?,
        version: record.version().get(),
    })
}

fn record_json_response(
    status: StatusCode,
    record: &ReferenceRecord,
    request_id: RequestId,
) -> Result<Response, ApiError> {
    let etag = VersionEtag::new(record.version().get())
        .and_then(VersionEtag::to_header_value)
        .map_err(|_| ApiError::internal(request_id))?;
    let body = reference_record_response(record).map_err(|()| ApiError::internal(request_id))?;
    let mut response = json_response(status, &body, request_id)?;
    response.headers_mut().insert(ETAG, etag);
    Ok(response)
}

fn json_response<T: Serialize>(
    status: StatusCode,
    body: &T,
    request_id: RequestId,
) -> Result<Response, ApiError> {
    let body = serde_json::to_vec(body).map_err(|_| ApiError::internal(request_id))?;
    Ok(json_bytes_response(status, body))
}

fn json_bytes_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(JSON_CONTENT_TYPE));
    response
}

fn replay_response(response: &SafeResponse, request_id: RequestId) -> Result<Response, ApiError> {
    let status =
        StatusCode::from_u16(response.status()).map_err(|_| ApiError::internal(request_id))?;
    let mut replay = Response::new(Body::from(response.body().to_vec()));
    *replay.status_mut() = status;
    if let Some(content_type) = response.content_type() {
        let content_type =
            HeaderValue::from_str(content_type).map_err(|_| ApiError::internal(request_id))?;
        replay.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    Ok(replay)
}

fn map_json_rejection(error: &JsonRejection, request_id: RequestId) -> ApiError {
    match error.status() {
        StatusCode::PAYLOAD_TOO_LARGE => ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PAYLOAD_TOO_LARGE",
            "request body exceeds the configured limit",
            request_id,
        ),
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "UNSUPPORTED_MEDIA_TYPE",
            "Content-Type must be application/json",
            request_id,
        ),
        _ => ApiError::bad_request(
            "INVALID_JSON",
            "request body must be valid JSON",
            request_id,
        ),
    }
}

const fn map_pagination_error(error: ReferencePaginationError, request_id: RequestId) -> ApiError {
    match error {
        ReferencePaginationError::InvalidCursor => {
            ApiError::bad_request("INVALID_CURSOR", "pagination cursor is invalid", request_id)
        }
        ReferencePaginationError::InvalidFilter => {
            ApiError::bad_request("INVALID_FILTER", "list filter is invalid", request_id)
        }
        ReferencePaginationError::CursorEncoding => ApiError::internal(request_id),
    }
}

const fn map_domain_error(error: ReferenceDomainError, request_id: RequestId) -> ApiError {
    match error {
        ReferenceDomainError::InvalidName => ApiError::unprocessable(
            "VALIDATION_FAILED",
            "reference record name is invalid",
            request_id,
        ),
        ReferenceDomainError::InvalidId
        | ReferenceDomainError::InvalidTimeline
        | ReferenceDomainError::InvalidVersion => ApiError::internal(request_id),
    }
}

const fn map_store_error(error: ReferenceStoreError, request_id: RequestId) -> ApiError {
    match error {
        ReferenceStoreError::Conflict => ApiError::conflict(
            "REFERENCE_RECORD_CONFLICT",
            "reference record conflicts with persisted state",
            request_id,
        ),
        ReferenceStoreError::Unavailable | ReferenceStoreError::Transient(_) => {
            ApiError::database_unavailable(request_id)
        }
        ReferenceStoreError::CorruptData => ApiError::internal(request_id),
    }
}

const fn map_idempotency_error(error: IdempotencyStoreError, request_id: RequestId) -> ApiError {
    match error {
        IdempotencyStoreError::Conflict => ApiError::conflict(
            "IDEMPOTENCY_CONFLICT",
            "Idempotency-Key was already used for a different request",
            request_id,
        ),
        IdempotencyStoreError::ClaimLost | IdempotencyStoreError::ClaimExpired => {
            ApiError::conflict(
                "IDEMPOTENCY_CLAIM_LOST",
                "idempotency claim can no longer be completed",
                request_id,
            )
        }
        IdempotencyStoreError::Transient(_) | IdempotencyStoreError::Unavailable => {
            ApiError::database_unavailable(request_id)
        }
        IdempotencyStoreError::ResponseTooLarge
        | IdempotencyStoreError::ConstraintViolation
        | IdempotencyStoreError::CorruptData => ApiError::internal(request_id),
    }
}

#[derive(Clone, Copy, Debug)]
struct ApiFieldError {
    pointer: &'static str,
    code: &'static str,
    message: &'static str,
}

const NAME_FIELD_ERRORS: &[ApiFieldError] = &[ApiFieldError {
    pointer: "/name",
    code: "invalid",
    message: "Enter a name between 1 and 100 characters.",
}];

#[derive(Clone, Copy, Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
    field_errors: &'static [ApiFieldError],
}

impl ApiError {
    const fn new(
        status: StatusCode,
        code: &'static str,
        detail: &'static str,
        request_id: RequestId,
    ) -> Self {
        Self {
            status,
            code,
            detail,
            request_id,
            field_errors: &[],
        }
    }

    const fn bad_request(code: &'static str, detail: &'static str, request_id: RequestId) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, detail, request_id)
    }

    const fn unprocessable(
        code: &'static str,
        detail: &'static str,
        request_id: RequestId,
    ) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, detail, request_id)
    }

    const fn unprocessable_field(
        code: &'static str,
        detail: &'static str,
        request_id: RequestId,
    ) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code,
            detail,
            request_id,
            field_errors: NAME_FIELD_ERRORS,
        }
    }

    const fn conflict(code: &'static str, detail: &'static str, request_id: RequestId) -> Self {
        Self::new(StatusCode::CONFLICT, code, detail, request_id)
    }

    const fn not_found(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "REFERENCE_RECORD_NOT_FOUND",
            "reference record was not found",
            request_id,
        )
    }

    const fn precondition_failed(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::PRECONDITION_FAILED,
            "PRECONDITION_FAILED",
            "If-Match does not match the current reference record version",
            request_id,
        )
    }

    const fn database_unavailable(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "DATABASE_UNAVAILABLE",
            "service is temporarily unavailable",
            request_id,
        )
    }

    const fn internal(request_id: RequestId) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "an internal service error occurred",
            request_id,
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let Ok(code) = ErrorCode::try_new(self.code) else {
            unreachable!("static API error code is valid");
        };
        let error = ServiceError::new(code, self.detail);
        let Ok(problem) = ProblemDetails::from_service_error(self.status, &error, self.request_id)
        else {
            unreachable!("API errors always use HTTP error statuses");
        };
        if self.field_errors.is_empty() {
            return problem.into_response();
        }
        let field_errors = self
            .field_errors
            .iter()
            .map(|field| FieldError::try_new(field.pointer, field.code, field.message))
            .collect::<Result<Vec<_>, _>>();
        let Ok(field_errors) = field_errors else {
            unreachable!("static API field errors are valid");
        };
        let Ok(problem) = problem.with_errors(field_errors) else {
            unreachable!("static API field errors fit the public bound");
        };
        problem.into_response()
    }
}
