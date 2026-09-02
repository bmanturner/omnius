//! Reference Axum API profile with transactional idempotency and deterministic `OpenAPI`.

pub mod account_auth;
pub mod api_key_auth;
pub mod browser_auth;
pub mod browser_tenancy;
mod composition;
mod contracts;
pub mod oauth_provider;
mod optional_identity;
mod runtime;

use std::{str::FromStr as _, sync::Arc};

pub use api_key_auth::{
    AuthenticatedIdentityBuildError, AuthenticatedIdentityState, authenticated_identity_router,
};
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Extension, Path, Query, State,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CONTENT_TYPE, ETAG, IF_MATCH},
    },
    response::{IntoResponse, Response},
    routing::get,
};
pub use composition::{
    AuthenticatedApi, AuthenticatedApiBuildError, AuthenticatedApiInput, OAuthProviderApi,
    OAuthProviderApiParts, OAuthProviderBuildError, OAuthProviderInput, build_authenticated_api,
    extend_oauth_provider,
};
use contracts::{__path_runtime_metadata, RuntimeMetadataResponse};
pub use contracts::{
    BUILD_REVISION, CONTRACT_SCHEMA_VERSION, ContractMetadataError, MINIMUM_SDK_VERSION,
    PUBLIC_API_VERSION, PUBLIC_METADATA_PATH, PUBLIC_PROFILE, PUBLIC_PROFILE_MODULES,
    PublicCapability, PublicCapabilityId, PublicPermission, PublicPermissionId, PublicTransports,
    aggregate_contract_sha256, capabilities_contract_json, generated_metadata_router,
    metadata_router, permissions_contract_json, public_capabilities, public_permissions,
    public_transports, selected_browser_command_actions,
};
use garde::Validate as _;
use omnius_core::{Clock, ErrorCode, RequestId, ServiceError};
use omnius_http::{FieldError, IfMatch, ProblemDetails, VersionEtag};
use omnius_idempotency::{
    ClaimOutcome, IdempotencyKey, IdempotencyOperation, IdempotencyRequest, IdempotencyScope,
    IdempotencyStoreError, PostgresIdempotencyStore, RequestFingerprint, SafeResponse,
};
pub use omnius_openapi::{ExpectedOperation, OpenApiCatalog, OpenApiConfig, OpenApiError};
use omnius_pagination::{CursorCodec, CursorPage, OpaqueCursor, PageLimit, PageRequest};
use omnius_postgres::PostgresPool;
use omnius_reference_domain::{
    ReferenceDomainError, ReferencePaginationError, ReferenceRecord, ReferenceRecordId,
    ReferenceRecordNameFilter, ReferenceRecordPageRequest, ReferenceRecordPaginator,
    ReferenceRecordUpdate,
};
use omnius_reference_postgres::{
    PostgresReferenceRecordPaginator, PostgresReferenceRecordRepository, ReferenceStoreError,
};
pub use optional_identity::{
    IdentityRouteParts, OIDC_CALLBACK_PATH, OIDC_PENDING_CLEANUP_TASK_ID, OIDC_START_PATH,
    OidcIdentityBuildError, OidcIdentityComposition, OidcIdentityInput, OidcIdentityParts,
    OidcPendingCleanupConfig, OptionalIdentityContext, PASSKEY_AUTHENTICATE_FINISH_PATH,
    PASSKEY_AUTHENTICATE_START_PATH, PASSKEY_REGISTER_FINISH_PATH, PASSKEY_REGISTER_START_PATH,
    PASSKEYS_PATH, TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH, TOTP_ENROLL_PATH, TotpIdentityBuildError,
    TotpIdentityComposition, TotpIdentityInput, WebAuthnIdentityBuildError,
    WebAuthnIdentityComposition, WebAuthnIdentityInput, compose_oidc_identity,
    compose_totp_identity, compose_webauthn_identity,
};
pub use runtime::{
    AccountEmailConfig, ApiKeyApplicationConfig, AuthConfig, AuthenticatedRuntime,
    AuthenticatedRuntimeBuildError, AuthenticatedRuntimeInput, OAuthRateLimitConfig,
    OAuthRateLimitPolicyConfig, OAuthRuntimeBuildError, OAuthRuntimeInput, PaginationConfig,
    PasswordConfig, PasswordPepperConfig, ReferenceRuntimeConfigError, RegistrationConfig,
    build_authenticated_runtime, extend_oauth_runtime,
};
use serde::{Deserialize, Serialize};
use sqlx::{Connection as _, PgConnection};
use time::format_description::well_known::Rfc3339;
use utoipa::{
    Modify, ToSchema,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};

const COLLECTION_PATH: &str = "/reference-records";
const ITEM_PATH: &str = "/reference-records/{id}";
const CURRENT_PRINCIPAL_PATH: &str = api_key_auth::CURRENT_PRINCIPAL_PATH;
const JSON_CONTENT_TYPE: &str = "application/json";
const CREATE_OPERATION: &str = "reference-records.create";
const CREATE_FINGERPRINT_PREFIX: &[u8] =
    b"POST\n/reference-records\ncontent-type:application/json\n\n";

/// Operations mounted by the unauthenticated persisted reference-record stage.
pub const REFERENCE_HTTP_OPERATIONS: &[ExpectedOperation] = &[
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
];

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
    ExpectedOperation::new("post", "/auth/register", "registerLocalAccount", "accounts"),
    ExpectedOperation::new(
        "post",
        "/auth/email/verification/request",
        "requestEmailVerification",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/email/verification/complete",
        "completeEmailVerification",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/reset/request",
        "requestPasswordReset",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/reset/complete",
        "completePasswordReset",
        "accounts",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/password/change",
        "changePassword",
        "accounts",
    ),
    ExpectedOperation::new("get", "/auth/sessions", "listActiveSessions", "sessions"),
    ExpectedOperation::new(
        "delete",
        "/auth/sessions/{device_id}",
        "revokeSessionDevice",
        "sessions",
    ),
    ExpectedOperation::new(
        "post",
        "/auth/registration-invitations",
        "issueRegistrationInvitation",
        "registration-invitations",
    ),
    ExpectedOperation::new(
        "get",
        "/auth/registration-invitations",
        "listRegistrationInvitations",
        "registration-invitations",
    ),
    ExpectedOperation::new(
        "delete",
        "/auth/registration-invitations/{invitation_id}",
        "revokeRegistrationInvitation",
        "registration-invitations",
    ),
    ExpectedOperation::new(
        "post",
        api_key_auth::SERVICE_ACCOUNTS_PATH,
        "createServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "get",
        api_key_auth::SERVICE_ACCOUNTS_PATH,
        "listServiceAccounts",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "get",
        api_key_auth::SERVICE_ACCOUNT_PATH,
        "getServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "delete",
        api_key_auth::SERVICE_ACCOUNT_PATH,
        "disableServiceAccount",
        "service-accounts",
    ),
    ExpectedOperation::new(
        "post",
        api_key_auth::SERVICE_ACCOUNT_API_KEYS_PATH,
        "issueServiceAccountApiKey",
        "api-keys",
    ),
    ExpectedOperation::new(
        "get",
        api_key_auth::SERVICE_ACCOUNT_API_KEYS_PATH,
        "listServiceAccountApiKeys",
        "api-keys",
    ),
    ExpectedOperation::new(
        "post",
        api_key_auth::API_KEY_ROTATE_PATH,
        "rotateApiKey",
        "api-keys",
    ),
    ExpectedOperation::new(
        "delete",
        api_key_auth::API_KEY_PATH,
        "revokeApiKey",
        "api-keys",
    ),
    ExpectedOperation::new("get", "/tenants", "listBrowserTenants", "tenancy"),
    ExpectedOperation::new(
        "post",
        "/tenants/{tenant_id}/switch",
        "switchBrowserTenant",
        "tenancy",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::AUTHORIZATION_SERVER_METADATA_PATH,
        "oauth.discovery.authorization-server",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OPENID_CONFIGURATION_PATH,
        "oidc.discovery",
        "openid",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::PROTECTED_RESOURCE_METADATA_PATH,
        "oauth.discovery.protected-resource",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_JWKS_PATH,
        "oauth.jwks",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_AUTHORIZE_PATH,
        "oauth.authorize",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_INTERACTION_PATH,
        "oauth.authorize.interaction",
        "oauth",
    ),
    ExpectedOperation::new(
        "post",
        oauth_provider::OAUTH_DECISION_PATH,
        "oauth.authorize.decision",
        "oauth",
    ),
    ExpectedOperation::new(
        "post",
        oauth_provider::OAUTH_TOKEN_PATH,
        "oauth.token",
        "oauth",
    ),
    ExpectedOperation::new(
        "post",
        oauth_provider::OAUTH_REVOKE_PATH,
        "oauth.revoke",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_GRANTS_PATH,
        "oauth.grants.list",
        "oauth",
    ),
    ExpectedOperation::new(
        "delete",
        oauth_provider::OAUTH_GRANT_PATH,
        "oauth.grants.revoke",
        "oauth",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_USERINFO_PATH,
        "oidc.userinfo.get",
        "openid",
    ),
    ExpectedOperation::new(
        "post",
        oauth_provider::OAUTH_USERINFO_PATH,
        "oidc.userinfo.post",
        "openid",
    ),
    ExpectedOperation::new(
        "get",
        oauth_provider::OAUTH_LOGOUT_PATH,
        "oidc.logout.get",
        "openid",
    ),
    ExpectedOperation::new(
        "post",
        oauth_provider::OAUTH_LOGOUT_PATH,
        "oidc.logout.post",
        "openid",
    ),
];
/// Transport-independent input for one bounded reference-record list operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceRecordListRequest {
    /// Optional page size; defaults to the shared pagination default.
    pub limit: Option<u16>,
    /// Optional authenticated continuation cursor.
    pub cursor: Option<String>,
    /// Optional case-insensitive name substring.
    pub name: Option<String>,
}

/// Transport-independent output from [`ReferenceRecordService::list`].
pub type ReferenceRecordPage = CursorPage<ReferenceRecord>;

/// Stable failures from [`ReferenceRecordService::list`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReferenceRecordListError {
    /// The page limit or opaque cursor envelope is malformed or outside its bound.
    #[error("reference record pagination input is invalid")]
    InvalidPagination,
    /// The decoded cursor or normalized name filter violates the domain contract.
    #[error("reference record pagination policy failed: {0}")]
    Pagination(#[from] ReferencePaginationError),
    /// PostgreSQL state could not safely satisfy the list request.
    #[error("reference record persistence failed: {0}")]
    Store(#[from] ReferenceStoreError),
}

/// Axum-independent reference-record query service shared by REST and MCP transports.
#[derive(Clone, Debug)]
pub struct ReferenceRecordService {
    paginator: PostgresReferenceRecordPaginator,
    cursor_codec: CursorCodec,
}

impl ReferenceRecordService {
    /// Creates the list service from the real PostgreSQL paginator and cursor policy.
    #[must_use]
    pub fn new(pool: PostgresPool, cursor_codec: CursorCodec) -> Self {
        Self {
            paginator: PostgresReferenceRecordPaginator::new(pool, cursor_codec.clone()),
            cursor_codec,
        }
    }

    /// Validates transport-neutral inputs and lists one canonical bounded page.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceRecordListError`] for invalid pagination/filter input,
    /// authenticated cursor failures, or PostgreSQL availability/corruption failures.
    pub async fn list(
        &self,
        mut request: ReferenceRecordListRequest,
    ) -> Result<ReferenceRecordPage, ReferenceRecordListError> {
        let name_filter = request
            .name
            .take()
            .map(ReferenceRecordNameFilter::try_new)
            .transpose()?;
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.is_ascii())
        {
            return Err(ReferenceRecordListError::InvalidPagination);
        }
        let limit = PageLimit::new(request.limit.unwrap_or(PageLimit::DEFAULT))
            .map_err(|_| ReferenceRecordListError::InvalidPagination)?;
        let cursor = request
            .cursor
            .map(OpaqueCursor::new)
            .transpose()
            .map_err(|_| ReferenceRecordListError::InvalidPagination)?;
        let page_request = ReferenceRecordPageRequest::decode(
            &PageRequest::new(limit, cursor),
            &self.cursor_codec,
        )?
        .with_name_filter(name_filter);
        self.paginator.list(page_request).await.map_err(Into::into)
    }
}

/// Shared application state for the reference CRUD profile.
#[derive(Clone)]
pub struct ReferenceApiState {
    pool: PostgresPool,
    repository: PostgresReferenceRecordRepository,
    list_service: ReferenceRecordService,
    idempotency_store: PostgresIdempotencyStore,
    clock: Arc<dyn Clock>,
}

impl ReferenceApiState {
    /// Builds the reference profile from its provider adapters and deterministic clock.
    #[must_use]
    pub fn new(
        pool: PostgresPool,
        cursor_codec: CursorCodec,
        idempotency_store: PostgresIdempotencyStore,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let repository = PostgresReferenceRecordRepository::new(pool.clone());
        let list_service = ReferenceRecordService::new(pool.clone(), cursor_codec);
        Self {
            pool,
            repository,
            list_service,
            idempotency_store,
            clock,
        }
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
/// Provider resources required to assemble persisted unauthenticated reference CRUD.
pub struct ReferenceApiInput {
    /// Shared PostgreSQL pool used by the repository and paginator.
    pub pool: PostgresPool,
    /// Authenticated cursor codec used by bounded pagination.
    pub cursor_codec: CursorCodec,
    /// Transactional idempotency store used by record creation.
    pub idempotency_store: PostgresIdempotencyStore,
    /// Deterministic clock used for idempotency lease decisions.
    pub clock: Arc<dyn Clock>,
}

/// Persisted unauthenticated reference API router and its exact `OpenAPI` contribution.
pub struct ReferenceApi {
    routes: Router,
    openapi: serde_json::Value,
}

impl ReferenceApi {
    /// Returns a cloneable router containing exactly the five reference CRUD routes.
    pub fn router(&self) -> Router {
        self.routes.clone()
    }

    /// Returns the `OpenAPI` contribution for the mounted reference CRUD routes.
    #[must_use]
    pub const fn openapi(&self) -> &serde_json::Value {
        &self.openapi
    }

    /// Consumes the stage into its router and `OpenAPI` contribution.
    #[must_use]
    pub fn into_parts(self) -> ReferenceApiParts {
        ReferenceApiParts {
            routes: self.routes,
            openapi: self.openapi,
        }
    }
}

/// Owned outputs from [`ReferenceApi::into_parts`].
pub struct ReferenceApiParts {
    /// Router containing exactly the five persisted reference CRUD routes.
    pub routes: Router,
    /// `OpenAPI` contribution containing exactly those mounted operations.
    pub openapi: serde_json::Value,
}

/// Stable construction failures for [`build_reference_api`].
#[derive(Debug, thiserror::Error)]
pub enum ReferenceApiBuildError {
    /// The exact reference `OpenAPI` contribution could not be serialized or validated.
    #[error("reference OpenAPI contribution failed: {0}")]
    OpenApi(#[from] OpenApiError),
}

/// Builds persisted unauthenticated reference CRUD and its exact `OpenAPI` contribution.
///
/// # Errors
///
/// Returns [`ReferenceApiBuildError`] when the generated contribution cannot be serialized
/// or does not cover exactly the operations mounted by [`reference_router`].
pub fn build_reference_api(
    input: ReferenceApiInput,
) -> Result<ReferenceApi, ReferenceApiBuildError> {
    let ReferenceApiInput {
        pool,
        cursor_codec,
        idempotency_store,
        clock,
    } = input;
    let routes = reference_router(ReferenceApiState::new(
        pool,
        cursor_codec,
        idempotency_store,
        clock,
    ));
    let openapi = reference_openapi_contribution()?;
    Ok(ReferenceApi { routes, openapi })
}

/// Generates the exact unauthenticated `OpenAPI` contribution for reference CRUD.
///
/// # Errors
///
/// Returns [`OpenApiError`] if serialization or exact operation coverage validation fails.
pub fn reference_openapi_contribution() -> Result<serde_json::Value, OpenApiError> {
    let mut document =
        serde_json::to_value(<ReferenceRecordsDocument as utoipa::OpenApi>::openapi())
            .map_err(|_| OpenApiError::SerializationFailed)?;
    if let Some(paths) = document
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    {
        for path in paths
            .values_mut()
            .filter_map(serde_json::Value::as_object_mut)
        {
            for operation in path
                .values_mut()
                .filter_map(serde_json::Value::as_object_mut)
            {
                operation.insert("security".to_owned(), serde_json::Value::Array(Vec::new()));
            }
        }
    }
    omnius_openapi::validate_operation_coverage_value(&document, REFERENCE_HTTP_OPERATIONS)?;
    Ok(document)
}

/// Generates the policy-validated, canonical `OpenAPI` 3.1 document.
///
/// # Errors
///
/// Returns [`OpenApiError`] if generation, validation, or canonical serialization fails.
pub fn openapi_json() -> Result<Vec<u8>, OpenApiError> {
    let document = openapi_document_value()?;
    omnius_openapi::validate_operation_coverage_value(&document, PUBLIC_HTTP_OPERATIONS)?;
    omnius_openapi::deterministic_json_value(document)
}

/// Generates and validates the locally served API catalog.
///
/// # Errors
///
/// Returns [`OpenApiError`] if the catalog configuration, document policy, or
/// public route coverage is invalid.
pub fn openapi_catalog(config: OpenApiConfig) -> Result<OpenApiCatalog, OpenApiError> {
    let document = openapi_document_value()?;
    omnius_openapi::validate_operation_coverage_value(&document, PUBLIC_HTTP_OPERATIONS)?;
    OpenApiCatalog::try_from_value(document, config)
}

fn openapi_document_value() -> Result<serde_json::Value, OpenApiError> {
    serde_json::to_value(<ReferenceApiDocument as utoipa::OpenApi>::openapi())
        .map_err(|_| OpenApiError::SerializationFailed)
}

#[derive(Debug, Deserialize, garde::Validate)]
#[serde(deny_unknown_fields)]
struct ReferenceRecordPath {
    #[garde(ascii, length(bytes, equal = 36))]
    id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ListReferenceRecordsQuery {
    limit: Option<u16>,
    cursor: Option<String>,
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

#[expect(
    dead_code,
    reason = "schema-only representation of account registration input"
)]
#[derive(ToSchema)]
struct AccountRegisterRequestSchema {
    #[schema(format = Email)]
    email: String,
    #[schema(format = Password)]
    password: String,
    invitation: Option<String>,
}

#[expect(
    dead_code,
    reason = "schema-only representation of an account identity request"
)]
#[derive(ToSchema)]
struct AccountIdentityRequestSchema {
    #[schema(format = Email)]
    email: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of one-time account token input"
)]
#[derive(ToSchema)]
struct AccountTokenCompletionRequestSchema {
    token: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of password recovery input"
)]
#[derive(ToSchema)]
struct AccountPasswordResetRequestSchema {
    token: String,
    #[schema(format = Password)]
    new_password: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of password change input"
)]
#[derive(ToSchema)]
struct AccountPasswordChangeRequestSchema {
    #[schema(format = Password)]
    current_password: String,
    #[schema(format = Password)]
    new_password: String,
}

#[expect(dead_code, reason = "schema-only representation of invitation input")]
#[derive(ToSchema)]
struct AccountInvitationIssueRequestSchema {
    #[schema(format = Email)]
    email: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of enumeration-safe acceptance"
)]
#[derive(ToSchema)]
struct AccountAcceptedResponseSchema {
    status: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of safe session metadata"
)]
#[derive(ToSchema)]
struct AccountSessionResponseSchema {
    #[schema(format = Uuid)]
    device_id: String,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    last_seen_at: String,
    #[schema(format = DateTime)]
    absolute_expires_at: String,
    current: bool,
}

#[expect(
    dead_code,
    reason = "schema-only representation of a safe session page"
)]
#[derive(ToSchema)]
struct AccountSessionListResponseSchema {
    sessions: Vec<AccountSessionResponseSchema>,
}

#[expect(
    dead_code,
    reason = "schema-only representation of invitation metadata"
)]
#[derive(ToSchema)]
struct AccountInvitationResponseSchema {
    #[schema(format = Uuid)]
    id: String,
    #[schema(format = Email)]
    email: String,
    issuer_kind: String,
    issuer_id: Option<String>,
    #[schema(format = DateTime)]
    created_at: String,
    #[schema(format = DateTime)]
    expires_at: String,
    #[schema(format = DateTime)]
    consumed_at: Option<String>,
    #[schema(format = DateTime)]
    revoked_at: Option<String>,
}

#[expect(dead_code, reason = "schema-only representation of an invitation page")]
#[derive(ToSchema)]
struct AccountInvitationListResponseSchema {
    invitations: Vec<AccountInvitationResponseSchema>,
}
#[expect(
    dead_code,
    reason = "schema-only representation of browser login input"
)]
#[derive(ToSchema)]
struct BrowserLoginRequestSchema {
    identifier: String,
    #[schema(format = Password)]
    password: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of browser resource permissions"
)]
#[derive(ToSchema)]
struct BrowserResourcePermissionSchema {
    permission: String,
    context: serde_json::Value,
}

#[expect(
    dead_code,
    reason = "schema-only representation of selected tenant metadata"
)]
#[derive(ToSchema)]
struct BrowserTenantSchema {
    #[schema(format = Uuid)]
    id: String,
}

#[expect(
    dead_code,
    reason = "schema-only representation of browser session bootstrap"
)]
#[derive(ToSchema)]
struct BrowserSessionResponseSchema {
    #[schema(format = Uuid)]
    subject_id: String,
    kind: String,
    #[schema(format = Uuid)]
    tenant_id: Option<String>,
    #[schema(format = DateTime)]
    authenticated_at: String,
    auth_method: String,
    assurance: String,
    scopes: Vec<String>,
    #[schema(format = DateTime)]
    expires_at: String,
    presentation_permissions: Vec<String>,
    resource_permissions: Vec<BrowserResourcePermissionSchema>,
    tenant: Option<BrowserTenantSchema>,
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
        components.add_security_scheme(
            "api_key_auth",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("Authorization"))),
        );
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Omnius Reference Records API",
        version = "0.1.0",
        description = "Persisted unauthenticated reference CRUD contribution"
    ),
    paths(
        list_reference_records,
        create_reference_record,
        get_reference_record,
        update_reference_record,
        delete_reference_record
    ),
    components(schemas(
        CreateReferenceRecordRequest,
        UpdateReferenceRecordRequest,
        ReferenceRecordResponse,
        ReferenceRecordPageResponse,
        ProblemFieldErrorSchema,
        ProblemDetailsSchema,
    )),
    tags(
        (name = "reference-records", description = "Reference record CRUD operations"),
    )
)]
struct ReferenceRecordsDocument;

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "Omnius Reference API",
        version = "0.1.0",
        description = "Authenticated reference CRUD profile"
    ),
    paths(
        api_key_auth::current_principal,
        api_key_auth::create_service_account,
        api_key_auth::list_service_accounts,
        api_key_auth::get_service_account,
        api_key_auth::disable_service_account,
        api_key_auth::issue_api_key,
        api_key_auth::list_api_keys,
        api_key_auth::rotate_api_key,
        api_key_auth::revoke_api_key,
        account_register_contract,
        account_verification_request_contract,
        account_verification_complete_contract,
        account_password_reset_request_contract,
        account_password_reset_complete_contract,
        account_password_change_contract,
        account_sessions_contract,
        account_session_revoke_contract,
        account_invitation_issue_contract,
        account_invitations_contract,
        account_invitation_revoke_contract,
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
        delete_reference_record,
        oauth_provider::authorization_server_metadata,
        oauth_provider::openid_configuration,
        oauth_provider::protected_resource_metadata,
        oauth_provider::jwks,
        oauth_provider::authorize,
        oauth_provider::interaction,
        oauth_provider::decision,
        oauth_provider::token,
        oauth_provider::revoke,
        oauth_provider::grants,
        oauth_provider::revoke_grant,
        oauth_provider::userinfo_get,
        oauth_provider::userinfo_post,
        oauth_provider::logout_get,
        oauth_provider::logout_post
    ),
    components(schemas(
        api_key_auth::PrincipalResponse,
        api_key_auth::CreateServiceAccountRequest,
        api_key_auth::IssueApiKeyRequest,
        api_key_auth::RotateApiKeyRequest,
        api_key_auth::ServiceAccountResponse,
        api_key_auth::ServiceAccountListResponse,
        api_key_auth::ApiKeyResponse,
        api_key_auth::ApiKeyListResponse,
        api_key_auth::CreatedApiKeyResponseSchema,
        AccountRegisterRequestSchema,
        AccountIdentityRequestSchema,
        AccountTokenCompletionRequestSchema,
        AccountPasswordResetRequestSchema,
        AccountPasswordChangeRequestSchema,
        AccountInvitationIssueRequestSchema,
        AccountAcceptedResponseSchema,
        AccountSessionResponseSchema,
        AccountSessionListResponseSchema,
        AccountInvitationResponseSchema,
        AccountInvitationListResponseSchema,
        BrowserLoginRequestSchema,
        BrowserResourcePermissionSchema,
        BrowserTenantSchema,
        browser_tenancy::TenantSummary,
        browser_tenancy::TenantSwitchMetadata,
        BrowserSessionResponseSchema,
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
        oauth_provider::OAuthErrorResponseSchema,
        oauth_provider::OAuthTokenResponseSchema,
        oauth_provider::OAuthInteractionScopeSchema,
        oauth_provider::OAuthAuthorizationInteractionSchema,
        oauth_provider::OAuthConnectedGrantSchema,
        oauth_provider::OAuthUserInfoResponseSchema,
    )),
    tags(
        (name = "health", description = "Process and dependency health"),
        (name = "reference-records", description = "Reference record CRUD operations"),
        (name = "identity", description = "Canonical authenticated identity"),
        (name = "metadata", description = "Public consumer contract compatibility metadata"),
        (name = "authentication", description = "Opaque browser session lifecycle"),
        (name = "accounts", description = "Local account verification and password lifecycle"),
        (name = "sessions", description = "Safe browser-session inventory and revocation"),
        (name = "registration-invitations", description = "AAL2 registration invitation lifecycle"),
        (name = "service-accounts", description = "Owner and tenant-policy service-account lifecycle"),
        (name = "api-keys", description = "Single-reveal service-account API-key lifecycle"),
        (name = "authorization", description = "Backend permission decisions"),
        (name = "tenancy", description = "Authenticated tenant selection"),
        (name = "oauth", description = "OAuth Authorization Server protocol and grant lifecycle"),
        (name = "openid", description = "OpenID Provider discovery, UserInfo, and logout"),
    ),
    modifiers(&AuthenticationSecurity)
)]
struct ReferenceApiDocument;
#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/register", operation_id = "registerLocalAccount", tag = "accounts",
    request_body(content = AccountRegisterRequestSchema, content_type = "application/json"),
    responses(
        (status = 202, description = "Enumeration-safe registration accepted", body = AccountAcceptedResponseSchema),
        (status = 400, description = "Registration input or mode mismatch", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "Password policy rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Registration persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn account_register_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/email/verification/request", operation_id = "requestEmailVerification", tag = "accounts",
    request_body(content = AccountIdentityRequestSchema, content_type = "application/json"),
    responses(
        (status = 202, description = "Enumeration-safe verification request accepted", body = AccountAcceptedResponseSchema),
        (status = 400, description = "Invalid bounded identity", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Account persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn account_verification_request_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/email/verification/complete", operation_id = "completeEmailVerification", tag = "accounts",
    request_body(content = AccountTokenCompletionRequestSchema, content_type = "application/json"),
    responses(
        (status = 204, description = "Email verified and pending account activated"),
        (status = 400, description = "One-time token rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Account persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn account_verification_complete_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/password/reset/request", operation_id = "requestPasswordReset", tag = "accounts",
    request_body(content = AccountIdentityRequestSchema, content_type = "application/json"),
    responses(
        (status = 202, description = "Enumeration-safe password reset request accepted", body = AccountAcceptedResponseSchema),
        (status = 400, description = "Invalid bounded identity", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Account persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn account_password_reset_request_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/password/reset/complete", operation_id = "completePasswordReset", tag = "accounts",
    request_body(content = AccountPasswordResetRequestSchema, content_type = "application/json"),
    responses(
        (status = 204, description = "Password replaced and all browser sessions revoked"),
        (status = 400, description = "One-time token rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "Password policy rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Account persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(())
)]
fn account_password_reset_complete_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/password/change", operation_id = "changePassword", tag = "accounts",
    request_body(content = AccountPasswordChangeRequestSchema, content_type = "application/json"),
    responses(
        (status = 204, description = "Password changed, sibling sessions revoked, and current session rotated"),
        (status = 401, description = "Session or current password rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 422, description = "New password policy rejected", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Account persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn account_password_change_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    get, path = "/auth/sessions", operation_id = "listActiveSessions", tag = "sessions",
    responses(
        (status = 200, description = "Safe active-device session inventory", body = AccountSessionListResponseSchema),
        (status = 401, description = "Active browser session required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Session persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn account_sessions_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    delete, path = "/auth/sessions/{device_id}", operation_id = "revokeSessionDevice", tag = "sessions",
    params(("device_id" = String, Path, format = Uuid)),
    responses(
        (status = 204, description = "Device session revoked; current-device deletion also clears the cookie"),
        (status = 400, description = "Invalid device identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Active browser session required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Active device not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Session persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn account_session_revoke_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    post, path = "/auth/registration-invitations", operation_id = "issueRegistrationInvitation", tag = "registration-invitations",
    request_body(content = AccountInvitationIssueRequestSchema, content_type = "application/json"),
    responses(
        (status = 201, description = "Invitation committed and delivered without exposing its token", body = AccountInvitationResponseSchema),
        (status = 401, description = "Active browser session required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "AAL2 and invitation-management scope required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "Active invitation already exists", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Invitation persistence or delivery unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
fn account_invitation_issue_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    get, path = "/auth/registration-invitations", operation_id = "listRegistrationInvitations", tag = "registration-invitations",
    params(
        ("limit" = Option<u16>, Query, description = "Bounded page size"),
        ("before_created_at" = Option<String>, Query, format = DateTime),
        ("before_id" = Option<Uuid>, Query)
    ),
    responses(
        (status = 200, description = "Safe invitation metadata page", body = AccountInvitationListResponseSchema),
        (status = 400, description = "Invalid pagination input", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Active browser session required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "AAL2 and invitation-management scope required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Invitation persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
fn account_invitations_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by account_auth")]
#[utoipa::path(
    delete, path = "/auth/registration-invitations/{invitation_id}", operation_id = "revokeRegistrationInvitation", tag = "registration-invitations",
    params(("invitation_id" = String, Path, format = Uuid)),
    responses(
        (status = 204, description = "Pending invitation revoked"),
        (status = 400, description = "Invalid invitation identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Active browser session required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "AAL2 and invitation-management scope required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Pending invitation not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Invitation persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
fn account_invitation_revoke_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_auth")]
#[utoipa::path(
    post, path = "/auth/login", operation_id = "loginBrowserSession", tag = "authentication",
    request_body(content = BrowserLoginRequestSchema, content_type = "application/json"),
    responses(
        (status = 200, description = "Authenticated browser session", body = BrowserSessionResponseSchema),
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
        (status = 200, description = "Current browser session", body = BrowserSessionResponseSchema),
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

#[expect(dead_code, reason = "runtime route is implemented by browser_tenancy")]
#[utoipa::path(
    get, path = "/tenants", operation_id = "listBrowserTenants", tag = "tenancy",
    responses(
        (status = 200, description = "Active tenant memberships", body = Vec<browser_tenancy::TenantSummary>),
        (status = 401, description = "Authentication missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Principal or membership not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Tenancy persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
fn browser_tenant_list_contract() {}

#[expect(dead_code, reason = "runtime route is implemented by browser_tenancy")]
#[utoipa::path(
    post, path = "/tenants/{tenant_id}/switch", operation_id = "switchBrowserTenant", tag = "tenancy",
    params(("tenant_id" = String, Path, format = Uuid)),
    responses(
        (status = 200, description = "Authoritative selected tenant", body = browser_tenancy::TenantSwitchMetadata),
        (status = 400, description = "Malformed tenant identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Browser session missing, expired, or revoked", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Tenant membership denied or not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "Tenancy state conflict", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Tenancy persistence or session binding unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []))
)]
fn browser_tenant_switch_contract() {}

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
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
async fn list_reference_records(
    State(state): State<ReferenceApiState>,
    request_id: Option<Extension<RequestId>>,
    query: Result<Query<ListReferenceRecordsQuery>, QueryRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
    let Query(query) = query.map_err(|_| {
        ApiError::bad_request(
            "INVALID_PAGINATION",
            "pagination parameters are invalid",
            request_id,
        )
    })?;
    let page = state
        .list_service
        .list(ReferenceRecordListRequest {
            limit: query.limit,
            cursor: query.cursor,
            name: query.name,
        })
        .await
        .map_err(|error| map_list_error(error, request_id))?;
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
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
async fn create_reference_record(
    State(state): State<ReferenceApiState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    payload: Result<Json<CreateReferenceRecordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
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
        CreateTransactionOutcome::Started(body) => {
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
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
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
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
async fn update_reference_record(
    State(state): State<ReferenceApiState>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    path: Result<Path<ReferenceRecordPath>, PathRejection>,
    payload: Result<Json<UpdateReferenceRecordRequest>, JsonRejection>,
) -> Result<Response, ApiError> {
    let request_id = resolve_request_id(request_id);
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
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
async fn delete_reference_record(
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
            Ok(CreateTransactionOutcome::Started(body))
        }
    }
}

enum CreateTransactionOutcome {
    Started(Vec<u8>),
    Replay(SafeResponse),
    InProgress,
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

const fn map_list_error(error: ReferenceRecordListError, request_id: RequestId) -> ApiError {
    match error {
        ReferenceRecordListError::InvalidPagination => ApiError::bad_request(
            "INVALID_PAGINATION",
            "pagination parameters are invalid",
            request_id,
        ),
        ReferenceRecordListError::Pagination(error) => map_pagination_error(error, request_id),
        ReferenceRecordListError::Store(error) => map_store_error(error, request_id),
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
