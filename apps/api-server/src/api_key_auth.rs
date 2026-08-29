//! Common protected-resource authentication and API-key lifecycle HTTP integration.

use std::str::FromStr as _;

use axum::{
    Json, Router,
    extract::{
        Extension, Path, Query, Request, State,
        rejection::{JsonRejection, QueryRejection},
    },
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use axum_login::{AuthManagerLayerBuilder, AuthSession};
use omnius_auth_api_key::{
    ApiKeyCredential, ApiKeyListCursor, ApiKeyListRequest, ApiKeyMetadata, ApiKeyStore,
    ApiKeyStoreError, CreatedApiKey, ServiceAccountListCursor, ServiceAccountListRequest,
    ServiceAccountListScope, ServiceAccountMetadata,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SessionConfig, SessionConfigError,
    SessionValidation, SubjectId, TenantId,
};
use omnius_auth_jwt::{JwtVerifier, JwtVerifyError};
use omnius_auth_session_postgres::{
    PostgresSessionLifecycle, SessionBackend, SessionGuardError, SessionRevocationGuard,
    SessionUser, guard_revoked_session, session_manager_layer,
};
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, Decision, Grant, IdentifierError, PolicyError,
    PolicyMatrix, PolicyRule, Resource, ResourceKind, Role,
};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_core::RequestId;
use omnius_pagination::{CursorCodec, OpaqueCursor};
use omnius_postgres::PostgresPool;
use omnius_tenancy::{TenancyStore, TenancyStoreError, TenantContext};
use serde::{Deserialize, Serialize, ser::SerializeStruct as _};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::browser_auth::browser_session_tenant;
use crate::{
    ApiError, ProblemDetailsSchema, map_json_rejection,
    oauth_provider::{OAuthResourceTokenVerifier, OAuthResourceVerifyError},
    resolve_request_id,
};

/// Exact service-account collection route.
pub const SERVICE_ACCOUNTS_PATH: &str = "/auth/service-accounts";
/// Exact service-account item route.
pub const SERVICE_ACCOUNT_PATH: &str = "/auth/service-accounts/{service_account_id}";
/// Exact service-account API-key collection route.
pub const SERVICE_ACCOUNT_API_KEYS_PATH: &str =
    "/auth/service-accounts/{service_account_id}/api-keys";
/// Exact API-key rotation route.
pub const API_KEY_ROTATE_PATH: &str = "/auth/api-keys/{api_key_id}/rotate";
/// Exact API-key revocation route.
pub const API_KEY_PATH: &str = "/auth/api-keys/{api_key_id}";
/// Exact canonical-principal inspection route.
pub const CURRENT_PRINCIPAL_PATH: &str = "/whoami";

const SERVICE_ACCOUNT_MANAGE_ACTION: &str = "service_accounts:manage";
const SERVICE_ACCOUNT_RESOURCE: &str = "service_account";
const OWNER_ROLE: &str = "organization:owner";
const ADMIN_ROLE: &str = "organization:admin";
const SERVICE_ACCOUNT_CURSOR_KIND: &str = "service-account";
const API_KEY_CURSOR_KIND: &str = "api-key";

/// Authentication state shared by every protected API and resource route.
#[derive(Clone)]
pub struct CanonicalPrincipalState {
    pool: PostgresPool,
    session_config: SessionConfig,
    jwt_verifier: Option<JwtVerifier>,
    api_key_store: Option<ApiKeyStore>,
    oauth_verifier: Option<OAuthResourceTokenVerifier>,
    trusted_origins: Vec<String>,
}

impl CanonicalPrincipalState {
    /// Builds the common credential boundary from its already-validated providers.
    #[must_use]
    pub const fn new(
        pool: PostgresPool,
        session_config: SessionConfig,
        jwt_verifier: Option<JwtVerifier>,
        api_key_store: Option<ApiKeyStore>,
    ) -> Self {
        Self {
            pool,
            session_config,
            jwt_verifier,
            api_key_store,
            oauth_verifier: None,
            trusted_origins: Vec::new(),
        }
    }

    /// Enables issuer-local resource-token authentication without remote JWKS fetching.
    #[must_use]
    pub fn with_oauth_resource_verifier(mut self, verifier: OAuthResourceTokenVerifier) -> Self {
        self.oauth_verifier = Some(verifier);
        self
    }

    /// Requires exact trusted origins for unsafe cookie-authenticated requests.
    #[must_use]
    pub fn with_trusted_origins(mut self, trusted_origins: Vec<String>) -> Self {
        self.trusted_origins = trusted_origins;
        self
    }
}

/// Backwards-compatible state constructor for the canonical identity route.
#[derive(Clone)]
pub struct AuthenticatedIdentityState(CanonicalPrincipalState);

impl AuthenticatedIdentityState {
    /// Builds identity composition from PostgreSQL sessions and an optional JWT verifier.
    #[must_use]
    pub const fn new(
        pool: PostgresPool,
        session_config: SessionConfig,
        jwt_verifier: Option<JwtVerifier>,
    ) -> Self {
        Self(CanonicalPrincipalState::new(
            pool,
            session_config,
            jwt_verifier,
            None,
        ))
    }

    /// Enables API-key presentation at the same canonical identity boundary.
    #[must_use]
    pub fn with_api_key_store(mut self, store: ApiKeyStore) -> Self {
        self.0.api_key_store = Some(store);
        self
    }
}

/// Failure to compose the common principal boundary and fail-closed session guard.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthenticatedIdentityBuildError {
    /// Session cookie or persistence policy is invalid.
    #[error("session manager configuration is invalid: {0}")]
    Session(#[from] SessionConfigError),
    /// Revocation guard policy is invalid.
    #[error("session revocation guard configuration is invalid: {0}")]
    Guard(#[from] SessionGuardError),
}

/// Builds the canonical identity endpoint using the reusable protected-route boundary.
///
/// # Errors
///
/// Returns an error when the session manager or revocation guard configuration is invalid.
pub fn authenticated_identity_router(
    state: AuthenticatedIdentityState,
    deployment: DeploymentEnvironment,
) -> Result<Router, AuthenticatedIdentityBuildError> {
    protected_principal_router(
        state.0,
        deployment,
        Router::new().route(CURRENT_PRINCIPAL_PATH, get(current_principal)),
    )
}

/// Wraps protected routes with deterministic JWT, API-key, or active-session authentication.
///
/// An explicit `Authorization` header is authoritative and suppresses cookie loading. Duplicate,
/// malformed, or unsupported headers are rejected without falling back to a browser session.
///
/// # Errors
///
/// Returns an error when the session manager or revocation guard configuration is invalid.
pub fn protected_principal_router<S>(
    state: CanonicalPrincipalState,
    deployment: DeploymentEnvironment,
    routes: Router<S>,
) -> Result<Router<S>, AuthenticatedIdentityBuildError>
where
    S: Clone + Send + Sync + 'static,
{
    let auth_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(state.pool.clone()),
        session_manager_layer(&state.pool, &state.session_config, deployment)?,
    )
    .build();
    let guard = SessionRevocationGuard::new(state.pool.clone(), &state.session_config)?;
    Ok(routes
        .layer(middleware::from_fn_with_state(
            state,
            attach_canonical_principal,
        ))
        .layer(auth_layer)
        .layer(middleware::from_fn_with_state(guard, guard_revoked_session))
        .layer(middleware::from_fn(prefer_authorization_header)))
}
/// Returns the state-free identity route for composition inside one shared protected router.
pub fn canonical_identity_route() -> Router {
    Router::new().route(CURRENT_PRINCIPAL_PATH, get(current_principal))
}

async fn prefer_authorization_header(mut request: Request, next: Next) -> Response {
    if request.headers().contains_key(header::AUTHORIZATION) {
        request.headers_mut().remove(header::COOKIE);
    }
    next.run(request).await
}

type BrowserAuthSession = AuthSession<SessionBackend>;

async fn attach_canonical_principal(
    State(state): State<CanonicalPrincipalState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    let principal = if request.headers().contains_key(header::AUTHORIZATION) {
        authenticate_authorization(&state, request.headers())
            .await
            .map_err(|failure| match failure {
                CredentialFailure::Rejected => AuthenticationError::unauthorized(request_id),
                CredentialFailure::Unavailable => AuthenticationError::unavailable(request_id),
            })
    } else {
        if requires_trusted_origin(request.method())
            && !has_trusted_origin(&state.trusted_origins, request.headers())
        {
            return AuthenticationError::csrf_origin_denied(request_id).into_response();
        }
        let Some(mut auth) = request.extensions().get::<BrowserAuthSession>().cloned() else {
            return AuthenticationError::internal(request_id).into_response();
        };
        authenticate_session(&state, &mut auth, request_id).await
    };
    match principal {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

fn requires_trusted_origin(method: &axum::http::Method) -> bool {
    !matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    )
}

fn has_trusted_origin(trusted_origins: &[String], headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return false;
    };
    trusted_origins
        .iter()
        .any(|trusted| origin.as_bytes() == trusted.as_bytes())
}

#[derive(Clone, Copy)]
enum CredentialFailure {
    Rejected,
    Unavailable,
}

async fn authenticate_authorization(
    state: &CanonicalPrincipalState,
    headers: &HeaderMap,
) -> Result<Principal, CredentialFailure> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(CredentialFailure::Rejected)?;
    if values.next().is_some() {
        return Err(CredentialFailure::Rejected);
    }
    let value = value.to_str().map_err(|_| CredentialFailure::Rejected)?;
    let (scheme, presentation) = value.split_once(' ').ok_or(CredentialFailure::Rejected)?;
    if presentation.is_empty()
        || presentation.starts_with(' ')
        || presentation.ends_with(' ')
        || presentation.contains(',')
    {
        return Err(CredentialFailure::Rejected);
    }
    if scheme.eq_ignore_ascii_case("bearer") {
        if let Some(verifier) = state.oauth_verifier.as_ref() {
            match verifier.verify(presentation).await {
                Ok(principal) => return Ok(principal),
                Err(OAuthResourceVerifyError::Unavailable) => {
                    return Err(CredentialFailure::Unavailable);
                }
                Err(OAuthResourceVerifyError::Rejected) => {}
            }
        }
        let principal = state
            .jwt_verifier
            .as_ref()
            .ok_or(CredentialFailure::Rejected)?
            .verify(presentation)
            .await
            .map_err(map_jwt_failure)?;
        revalidate_bearer_subject(state, &principal).await?;
        return Ok(principal);
    }
    if scheme.eq_ignore_ascii_case("apikey") {
        let credential = ApiKeyCredential::parse(SecretString::from(presentation.to_owned()))
            .map_err(|_| CredentialFailure::Rejected)?;
        return state
            .api_key_store
            .as_ref()
            .ok_or(CredentialFailure::Rejected)?
            .authenticate(&credential)
            .await
            .map_err(map_api_key_auth_failure);
    }
    Err(CredentialFailure::Rejected)
}

const fn map_jwt_failure(error: JwtVerifyError) -> CredentialFailure {
    match error {
        JwtVerifyError::JwksUnavailable | JwtVerifyError::InvalidJwks => {
            CredentialFailure::Unavailable
        }
        JwtVerifyError::MalformedToken
        | JwtVerifyError::AlgorithmRejected
        | JwtVerifyError::KeyIdRejected
        | JwtVerifyError::TokenClassRejected
        | JwtVerifyError::ClaimsRejected
        | JwtVerifyError::TokenRejected => CredentialFailure::Rejected,
    }
}

const fn map_api_key_auth_failure(error: ApiKeyStoreError) -> CredentialFailure {
    match error {
        ApiKeyStoreError::Unavailable
        | ApiKeyStoreError::Transient(_)
        | ApiKeyStoreError::CorruptData => CredentialFailure::Unavailable,
        _ => CredentialFailure::Rejected,
    }
}
async fn revalidate_bearer_subject(
    state: &CanonicalPrincipalState,
    principal: &Principal,
) -> Result<(), CredentialFailure> {
    if principal.kind != PrincipalKind::User {
        return Ok(());
    }
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| CredentialFailure::Unavailable)?;
    let active =
        sqlx::query_scalar::<_, i32>("SELECT 1 FROM users WHERE id = $1 AND status = 'active'")
            .bind(principal.subject_id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|_| CredentialFailure::Unavailable)?
            .is_some();
    if active {
        Ok(())
    } else {
        Err(CredentialFailure::Rejected)
    }
}

async fn authenticate_session(
    state: &CanonicalPrincipalState,
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
        SessionValidation::Active(metadata) => {
            let mut principal = auth
                .user
                .as_ref()
                .map(|user| user.principal(metadata.created_at))
                .ok_or_else(|| AuthenticationError::unauthorized(request_id))?;
            principal.tenant_id = browser_session_tenant(&auth.session)
                .await
                .map_err(|()| AuthenticationError::internal(request_id))?;
            Ok(principal)
        }
        SessionValidation::Rejected => {
            auth.logout()
                .await
                .map_err(|_| AuthenticationError::internal(request_id))?;
            Err(AuthenticationError::unauthorized(request_id))
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct AuthenticationError(ApiError);

impl AuthenticationError {
    const fn unauthorized(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "a valid session, bearer token, or API key is required",
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

    const fn csrf_origin_denied(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "CSRF_ORIGIN_DENIED",
            "the request origin is not trusted for cookie-authenticated mutation",
            request_id,
        ))
    }
}

impl IntoResponse for AuthenticationError {
    fn into_response(self) -> Response {
        let mut response = self.0.into_response();
        if response.status() == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer, ApiKey"),
            );
        }
        response
    }
}

#[derive(Serialize, ToSchema)]
pub(crate) struct PrincipalResponse {
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
        (status = 401, description = "Credential is missing, duplicated, malformed, or inactive", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 500, description = "Internal service failure", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Authentication persistence is unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(
        ("session_cookie" = []),
        ("bearer_auth" = []),
        ("api_key_auth" = [])
    )
)]
pub(crate) async fn current_principal(
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, AuthenticationError> {
    let request_id = resolve_request_id(request_id);
    let response = PrincipalResponse::from_principal(principal)
        .map_err(|_| AuthenticationError::internal(request_id))?;
    Ok(no_store_json(response))
}

/// Shared state for service-account and API-key lifecycle routes.
#[derive(Clone)]
pub struct ApiKeyManagementState {
    store: ApiKeyStore,
    tenancy: TenancyStore,
    cursor_codec: CursorCodec,
    tenant_authorizer: omnius_authz_basic::BasicAuthorizer,
    manage_action: Action,
    resource_kind: ResourceKind,
}

impl ApiKeyManagementState {
    /// Builds the owner-or-tenant-administrator policy used by lifecycle routes.
    ///
    /// # Errors
    /// Returns a value-free identifier or policy error if the fixed matrix is invalid.
    pub fn new(
        store: ApiKeyStore,
        tenancy: TenancyStore,
        cursor_codec: CursorCodec,
    ) -> Result<Self, ApiKeyManagementBuildError> {
        let manage_action = Action::new(SERVICE_ACCOUNT_MANAGE_ACTION)?;
        let resource_kind = ResourceKind::new(SERVICE_ACCOUNT_RESOURCE)?;
        let rule = PolicyRule::new(
            manage_action.clone(),
            resource_kind.clone(),
            vec![
                Grant::Role(Role::new(OWNER_ROLE)?),
                Grant::Role(Role::new(ADMIN_ROLE)?),
            ],
        )?
        .requiring_tenant_membership();
        let tenant_authorizer =
            AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
        Ok(Self {
            store,
            tenancy,
            cursor_codec,
            tenant_authorizer,
            manage_action,
            resource_kind,
        })
    }

    /// Returns the cloneable key store used by the common authentication boundary.
    #[must_use]
    pub const fn store(&self) -> &ApiKeyStore {
        &self.store
    }

    fn tenant_policy_allows(&self, context: &TenantContext, tenant_id: TenantId) -> bool {
        self.tenant_authorizer.authorize(
            context.principal(),
            &self.manage_action,
            &Resource::new(self.resource_kind.clone()).in_tenant(tenant_id),
            context.authorization_context(),
        ) == Decision::Allow
    }
}

/// Fixed API-key management policy construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ApiKeyManagementBuildError {
    /// A compiled policy identifier is invalid.
    #[error("API-key management authorization identifier is invalid")]
    Identifier(#[from] IdentifierError),
    /// The compiled basic policy matrix is invalid.
    #[error("API-key management authorization policy is invalid: {0}")]
    Policy(#[from] PolicyError),
}

/// Builds every service-account and API-key management route.
pub fn api_key_management_router(state: ApiKeyManagementState) -> Router {
    Router::new()
        .route(
            SERVICE_ACCOUNTS_PATH,
            post(create_service_account).get(list_service_accounts),
        )
        .route(
            SERVICE_ACCOUNT_PATH,
            get(get_service_account).delete(disable_service_account),
        )
        .route(
            SERVICE_ACCOUNT_API_KEYS_PATH,
            post(issue_api_key).get(list_api_keys),
        )
        .route(API_KEY_ROTATE_PATH, post(rotate_api_key))
        .route(API_KEY_PATH, delete(revoke_api_key))
        .with_state(state)
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateServiceAccountRequest {
    name: String,
    tenant_id: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct IssueApiKeyRequest {
    name: String,
    #[serde(default)]
    scopes: Vec<String>,
    expires_at: Option<String>,
}

#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct RotateApiKeyRequest {
    expires_at: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ServiceAccountListQuery {
    limit: Option<u16>,
    cursor: Option<String>,
    tenant_id: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct ApiKeyListQuery {
    limit: Option<u16>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagementCursor {
    kind: String,
    created_at_nanos: i128,
    id: Uuid,
}

#[derive(Serialize)]
struct ManagementCursorRef<'kind> {
    kind: &'kind str,
    created_at_nanos: i128,
    id: Uuid,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceAccountResponse {
    id: String,
    name: String,
    tenant_id: Option<String>,
    created_by_user_id: String,
    created_at: String,
    disabled_at: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ServiceAccountListResponse {
    items: Vec<ServiceAccountResponse>,
    next_cursor: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ApiKeyResponse {
    id: Uuid,
    service_account_id: String,
    key_prefix: String,
    name: String,
    scopes: Vec<String>,
    expires_at: Option<String>,
    created_at: String,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
    rotated_from_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ApiKeyListResponse {
    items: Vec<ApiKeyResponse>,
    next_cursor: Option<String>,
}

#[expect(
    dead_code,
    reason = "schema-only representation of a single-reveal response"
)]
#[derive(ToSchema)]
pub(crate) struct CreatedApiKeyResponseSchema {
    api_key: String,
    metadata: ApiKeyResponse,
}

struct CreatedApiKeyResponse {
    api_key: SecretString,
    metadata: ApiKeyResponse,
}

impl Serialize for CreatedApiKeyResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut output = serializer.serialize_struct("CreatedApiKeyResponse", 2)?;
        output.serialize_field("api_key", self.api_key.expose_secret())?;
        output.serialize_field("metadata", &self.metadata)?;
        output.end()
    }
}

#[utoipa::path(
    post,
    path = "/auth/service-accounts",
    operation_id = "createServiceAccount",
    tag = "service-accounts",
    request_body(content = CreateServiceAccountRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "Service account created", body = ServiceAccountResponse),
        (status = 400, description = "Invalid bounded request", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Active user tenant membership required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "Lifecycle conflict", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn create_service_account(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<CreateServiceAccountRequest>, JsonRejection>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    require_user(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| ApiKeyHttpError(map_json_rejection(&error, request_id)))?;
    let tenant_id = payload
        .tenant_id
        .as_deref()
        .map(TenantId::from_str)
        .transpose()
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    if let Some(tenant_id) = tenant_id {
        state
            .tenancy
            .resolve_tenant_context(&principal, tenant_id)
            .await
            .map_err(|error| map_tenancy_error(error, request_id))?;
    }
    let metadata = state
        .store
        .create_service_account(&payload.name, tenant_id, principal.subject_id)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    let response = service_account_response(metadata, request_id)?;
    Ok(no_store_json_status(StatusCode::CREATED, response))
}

#[utoipa::path(
    get,
    path = "/auth/service-accounts",
    operation_id = "listServiceAccounts",
    tag = "service-accounts",
    params(
        ("limit" = Option<u16>, Query, description = "Page size from 1 through 100"),
        ("cursor" = Option<String>, Query, description = "Opaque authenticated continuation cursor"),
        ("tenant_id" = Option<String>, Query, description = "Optional tenant filter")
    ),
    responses(
        (status = 200, description = "Authorized safe service-account metadata page", body = ServiceAccountListResponse),
        (status = 400, description = "Invalid pagination input", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "User or tenant membership required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn list_service_accounts(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    query: Result<Query<ServiceAccountListQuery>, QueryRejection>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    require_user(&principal, request_id)?;
    let Query(query) = query.map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    let limit = query.limit.unwrap_or(20);
    let scope = if let Some(raw_tenant_id) = query.tenant_id {
        let tenant_id = TenantId::from_str(&raw_tenant_id)
            .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
        let context = state
            .tenancy
            .resolve_tenant_context(&principal, tenant_id)
            .await
            .map_err(|error| map_tenancy_error(error, request_id))?;
        if state.tenant_policy_allows(&context, tenant_id) {
            ServiceAccountListScope::Tenant(tenant_id)
        } else {
            ServiceAccountListScope::TenantCreatedBy {
                tenant_id,
                created_by_user_id: principal.subject_id,
            }
        }
    } else {
        ServiceAccountListScope::TenantlessCreatedBy(principal.subject_id)
    };
    let mut request = ServiceAccountListRequest::new(scope, limit)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    if let Some(raw_cursor) = query.cursor {
        request = request.before(decode_service_account_cursor(
            &state.cursor_codec,
            &raw_cursor,
            request_id,
        )?);
    }
    let page = state
        .store
        .list_service_accounts(request)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    let items = page
        .items
        .into_iter()
        .map(|metadata| service_account_response(metadata, request_id))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = page
        .next_cursor
        .map(|cursor| encode_service_account_cursor(&state.cursor_codec, cursor, request_id))
        .transpose()?;
    Ok(no_store_json(ServiceAccountListResponse {
        items,
        next_cursor,
    }))
}

#[utoipa::path(
    get,
    path = "/auth/service-accounts/{service_account_id}",
    operation_id = "getServiceAccount",
    tag = "service-accounts",
    params(("service_account_id" = String, Path, description = "Canonical service-account subject")),
    responses(
        (status = 200, description = "Authorized safe service-account metadata", body = ServiceAccountResponse),
        (status = 400, description = "Invalid identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Service account not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn get_service_account(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(service_account_id): Path<String>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let id = parse_subject_id(&service_account_id, request_id)?;
    let metadata = authorize_account(&state, &principal, id, request_id).await?;
    Ok(no_store_json(service_account_response(
        metadata, request_id,
    )?))
}

#[utoipa::path(
    delete,
    path = "/auth/service-accounts/{service_account_id}",
    operation_id = "disableServiceAccount",
    tag = "service-accounts",
    params(("service_account_id" = String, Path, description = "Canonical service-account subject")),
    responses(
        (status = 204, description = "Service account and its keys are disabled idempotently"),
        (status = 400, description = "Invalid identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Service account not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn disable_service_account(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(service_account_id): Path<String>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let id = parse_subject_id(&service_account_id, request_id)?;
    authorize_account(&state, &principal, id, request_id).await?;
    state
        .store
        .disable_service_account(id)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    Ok(no_content())
}

#[utoipa::path(
    post,
    path = "/auth/service-accounts/{service_account_id}/api-keys",
    operation_id = "issueServiceAccountApiKey",
    tag = "api-keys",
    params(("service_account_id" = String, Path, description = "Canonical service-account subject")),
    request_body(content = IssueApiKeyRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "API key created; plaintext appears only in this response", body = CreatedApiKeyResponseSchema),
        (status = 400, description = "Invalid name, scopes, or expiry", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required; scopes cannot exceed actor scopes", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Service account not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "Service account inactive", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn issue_api_key(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(service_account_id): Path<String>,
    payload: Result<Json<IssueApiKeyRequest>, JsonRejection>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let id = parse_subject_id(&service_account_id, request_id)?;
    authorize_account(&state, &principal, id, request_id).await?;
    let Json(payload) =
        payload.map_err(|error| ApiKeyHttpError(map_json_rejection(&error, request_id)))?;
    let scopes = parse_issued_scopes(&payload.scopes, &principal, request_id)?;
    let expires_at = parse_optional_time(payload.expires_at.as_deref(), request_id)?;
    let created = state
        .store
        .issue(id, &payload.name, &scopes, expires_at)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    created_key_response(created, request_id)
}

#[utoipa::path(
    get,
    path = "/auth/service-accounts/{service_account_id}/api-keys",
    operation_id = "listServiceAccountApiKeys",
    tag = "api-keys",
    params(
        ("service_account_id" = String, Path, description = "Canonical service-account subject"),
        ("limit" = Option<u16>, Query, description = "Page size from 1 through 100"),
        ("cursor" = Option<String>, Query, description = "Opaque authenticated continuation cursor")
    ),
    responses(
        (status = 200, description = "Safe API-key metadata page without secrets or digests", body = ApiKeyListResponse),
        (status = 400, description = "Invalid identifier or pagination input", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "Service account not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn list_api_keys(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(service_account_id): Path<String>,
    query: Result<Query<ApiKeyListQuery>, QueryRejection>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let id = parse_subject_id(&service_account_id, request_id)?;
    authorize_account(&state, &principal, id, request_id).await?;
    let Query(query) = query.map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    let mut request = ApiKeyListRequest::new(id, query.limit.unwrap_or(20))
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    if let Some(raw_cursor) = query.cursor {
        request = request.before(decode_api_key_cursor(
            &state.cursor_codec,
            &raw_cursor,
            request_id,
        )?);
    }
    let page = state
        .store
        .list_api_keys(request)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    let items = page
        .items
        .into_iter()
        .map(|metadata| api_key_response(metadata, request_id))
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = page
        .next_cursor
        .map(|cursor| encode_api_key_cursor(&state.cursor_codec, cursor, request_id))
        .transpose()?;
    Ok(no_store_json(ApiKeyListResponse { items, next_cursor }))
}

#[utoipa::path(
    post,
    path = "/auth/api-keys/{api_key_id}/rotate",
    operation_id = "rotateApiKey",
    tag = "api-keys",
    params(("api_key_id" = Uuid, Path, description = "API-key identifier")),
    request_body(content = RotateApiKeyRequest, content_type = "application/json"),
    responses(
        (status = 201, description = "Overlapping replacement created; plaintext appears only in this response", body = CreatedApiKeyResponseSchema),
        (status = 400, description = "Invalid identifier or expiry", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required; existing scopes cannot exceed actor scopes", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "API key not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 409, description = "API key or service account inactive", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn rotate_api_key(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(api_key_id): Path<String>,
    payload: Result<Json<RotateApiKeyRequest>, JsonRejection>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let key_id = parse_key_id(&api_key_id, request_id)?;
    let metadata = authorized_key(&state, &principal, key_id, request_id).await?;
    ensure_scope_subset(&metadata.scopes, &principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| ApiKeyHttpError(map_json_rejection(&error, request_id)))?;
    let expires_at = parse_optional_time(payload.expires_at.as_deref(), request_id)?;
    let created = state
        .store
        .rotate(key_id, expires_at)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    created_key_response(created, request_id)
}

#[utoipa::path(
    delete,
    path = "/auth/api-keys/{api_key_id}",
    operation_id = "revokeApiKey",
    tag = "api-keys",
    params(("api_key_id" = Uuid, Path, description = "API-key identifier")),
    responses(
        (status = 204, description = "API key revoked idempotently"),
        (status = 400, description = "Invalid identifier", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 401, description = "Authentication required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 403, description = "Owner or tenant policy required", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 404, description = "API key not found", body = ProblemDetailsSchema, content_type = "application/problem+json"),
        (status = 503, description = "Persistence unavailable", body = ProblemDetailsSchema, content_type = "application/problem+json")
    ),
    security(("session_cookie" = []), ("bearer_auth" = []), ("api_key_auth" = []))
)]
pub(crate) async fn revoke_api_key(
    State(state): State<ApiKeyManagementState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    Path(api_key_id): Path<String>,
) -> Result<Response, ApiKeyHttpError> {
    let request_id = resolve_request_id(request_id);
    let key_id = parse_key_id(&api_key_id, request_id)?;
    authorized_key(&state, &principal, key_id, request_id).await?;
    state
        .store
        .revoke(key_id)
        .await
        .map_err(|error| map_store_error(error, request_id))?;
    Ok(no_content())
}

async fn authorize_account(
    state: &ApiKeyManagementState,
    principal: &Principal,
    account_id: SubjectId,
    request_id: RequestId,
) -> Result<ServiceAccountMetadata, ApiKeyHttpError> {
    require_user(principal, request_id)?;
    let metadata = state
        .store
        .service_account_metadata(account_id)
        .await
        .map_err(|error| map_store_error(error, request_id))?
        .ok_or_else(|| ApiKeyHttpError::not_found("SERVICE_ACCOUNT_NOT_FOUND", request_id))?;
    match metadata.tenant_id {
        None if metadata.created_by_user_id == principal.subject_id => Ok(metadata),
        None => Err(ApiKeyHttpError::permission_denied(request_id)),
        Some(tenant_id) => {
            let context = state
                .tenancy
                .resolve_tenant_context(principal, tenant_id)
                .await
                .map_err(|error| map_tenancy_error(error, request_id))?;
            if metadata.created_by_user_id == principal.subject_id
                || state.tenant_policy_allows(&context, tenant_id)
            {
                Ok(metadata)
            } else {
                Err(ApiKeyHttpError::permission_denied(request_id))
            }
        }
    }
}

async fn authorized_key(
    state: &ApiKeyManagementState,
    principal: &Principal,
    key_id: Uuid,
    request_id: RequestId,
) -> Result<ApiKeyMetadata, ApiKeyHttpError> {
    let metadata = state
        .store
        .api_key_metadata(key_id)
        .await
        .map_err(|error| map_store_error(error, request_id))?
        .ok_or_else(|| ApiKeyHttpError::not_found("API_KEY_NOT_FOUND", request_id))?;
    authorize_account(state, principal, metadata.service_account_id, request_id).await?;
    Ok(metadata)
}

fn require_user(principal: &Principal, request_id: RequestId) -> Result<(), ApiKeyHttpError> {
    if principal.kind == PrincipalKind::User {
        Ok(())
    } else {
        Err(ApiKeyHttpError::permission_denied(request_id))
    }
}

fn parse_issued_scopes(
    raw: &[String],
    principal: &Principal,
    request_id: RequestId,
) -> Result<Vec<Scope>, ApiKeyHttpError> {
    let mut scopes = raw
        .iter()
        .map(|value| Scope::new(value).map_err(|_| ApiKeyHttpError::invalid_request(request_id)))
        .collect::<Result<Vec<_>, _>>()?;
    scopes.sort_unstable();
    if scopes.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ApiKeyHttpError::invalid_request(request_id));
    }
    ensure_scope_subset(&scopes, principal, request_id)?;
    Ok(scopes)
}

fn ensure_scope_subset(
    scopes: &[Scope],
    principal: &Principal,
    request_id: RequestId,
) -> Result<(), ApiKeyHttpError> {
    if scopes
        .iter()
        .all(|scope| principal.scopes.binary_search(scope).is_ok())
    {
        Ok(())
    } else {
        Err(ApiKeyHttpError::scope_escalation(request_id))
    }
}

fn parse_optional_time(
    value: Option<&str>,
    request_id: RequestId,
) -> Result<Option<OffsetDateTime>, ApiKeyHttpError> {
    value
        .map(|value| {
            OffsetDateTime::parse(value, &Rfc3339)
                .map_err(|_| ApiKeyHttpError::invalid_request(request_id))
        })
        .transpose()
}

fn parse_subject_id(value: &str, request_id: RequestId) -> Result<SubjectId, ApiKeyHttpError> {
    SubjectId::from_str(value).map_err(|_| ApiKeyHttpError::invalid_path(request_id))
}

fn parse_key_id(value: &str, request_id: RequestId) -> Result<Uuid, ApiKeyHttpError> {
    let id = Uuid::parse_str(value).map_err(|_| ApiKeyHttpError::invalid_path(request_id))?;
    if id.get_version() == Some(uuid::Version::SortRand)
        && id.get_variant() == uuid::Variant::RFC4122
    {
        Ok(id)
    } else {
        Err(ApiKeyHttpError::invalid_path(request_id))
    }
}

fn decode_service_account_cursor(
    codec: &CursorCodec,
    raw: &str,
    request_id: RequestId,
) -> Result<ServiceAccountListCursor, ApiKeyHttpError> {
    let cursor = decode_cursor(codec, raw, SERVICE_ACCOUNT_CURSOR_KIND, request_id)?;
    let created_at = OffsetDateTime::from_unix_timestamp_nanos(cursor.created_at_nanos)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    let id = SubjectId::from_uuid(cursor.id)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    Ok(ServiceAccountListCursor::new(created_at, id))
}

fn decode_api_key_cursor(
    codec: &CursorCodec,
    raw: &str,
    request_id: RequestId,
) -> Result<ApiKeyListCursor, ApiKeyHttpError> {
    let cursor = decode_cursor(codec, raw, API_KEY_CURSOR_KIND, request_id)?;
    let created_at = OffsetDateTime::from_unix_timestamp_nanos(cursor.created_at_nanos)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    ApiKeyListCursor::new(created_at, cursor.id)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))
}

fn decode_cursor(
    codec: &CursorCodec,
    raw: &str,
    expected_kind: &str,
    request_id: RequestId,
) -> Result<ManagementCursor, ApiKeyHttpError> {
    let opaque =
        OpaqueCursor::try_from(raw).map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    let payload = codec
        .decode(&opaque)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    let cursor: ManagementCursor = serde_json::from_slice(&payload)
        .map_err(|_| ApiKeyHttpError::invalid_request(request_id))?;
    if cursor.kind != expected_kind {
        return Err(ApiKeyHttpError::invalid_request(request_id));
    }
    Ok(cursor)
}

fn encode_service_account_cursor(
    codec: &CursorCodec,
    cursor: ServiceAccountListCursor,
    request_id: RequestId,
) -> Result<String, ApiKeyHttpError> {
    encode_cursor(
        codec,
        SERVICE_ACCOUNT_CURSOR_KIND,
        cursor.created_at(),
        cursor.id().as_uuid(),
        request_id,
    )
}

fn encode_api_key_cursor(
    codec: &CursorCodec,
    cursor: ApiKeyListCursor,
    request_id: RequestId,
) -> Result<String, ApiKeyHttpError> {
    encode_cursor(
        codec,
        API_KEY_CURSOR_KIND,
        cursor.created_at(),
        cursor.id(),
        request_id,
    )
}

fn encode_cursor(
    codec: &CursorCodec,
    kind: &str,
    created_at: OffsetDateTime,
    id: Uuid,
    request_id: RequestId,
) -> Result<String, ApiKeyHttpError> {
    let payload = serde_json::to_vec(&ManagementCursorRef {
        kind,
        created_at_nanos: created_at.unix_timestamp_nanos(),
        id,
    })
    .map_err(|_| ApiKeyHttpError::internal(request_id))?;
    codec
        .encode(&payload)
        .map(|cursor| cursor.to_string())
        .map_err(|_| ApiKeyHttpError::internal(request_id))
}

fn service_account_response(
    metadata: ServiceAccountMetadata,
    request_id: RequestId,
) -> Result<ServiceAccountResponse, ApiKeyHttpError> {
    Ok(ServiceAccountResponse {
        id: metadata.id.to_string(),
        name: metadata.name,
        tenant_id: metadata.tenant_id.map(|id| id.to_string()),
        created_by_user_id: metadata.created_by_user_id.to_string(),
        created_at: format_time(metadata.created_at, request_id)?,
        disabled_at: metadata
            .disabled_at
            .map(|time| format_time(time, request_id))
            .transpose()?,
    })
}

fn api_key_response(
    metadata: ApiKeyMetadata,
    request_id: RequestId,
) -> Result<ApiKeyResponse, ApiKeyHttpError> {
    Ok(ApiKeyResponse {
        id: metadata.id,
        service_account_id: metadata.service_account_id.to_string(),
        key_prefix: metadata.key_prefix,
        name: metadata.name,
        scopes: metadata
            .scopes
            .into_iter()
            .map(|scope| scope.to_string())
            .collect(),
        expires_at: metadata
            .expires_at
            .map(|time| format_time(time, request_id))
            .transpose()?,
        created_at: format_time(metadata.created_at, request_id)?,
        last_used_at: metadata
            .last_used_at
            .map(|time| format_time(time, request_id))
            .transpose()?,
        revoked_at: metadata
            .revoked_at
            .map(|time| format_time(time, request_id))
            .transpose()?,
        rotated_from_id: metadata.rotated_from_id,
    })
}

fn created_key_response(
    created: CreatedApiKey,
    request_id: RequestId,
) -> Result<Response, ApiKeyHttpError> {
    let metadata = api_key_response(created.metadata().clone(), request_id)?;
    let api_key = created.expose_once();
    Ok(no_store_json_status(
        StatusCode::CREATED,
        CreatedApiKeyResponse { api_key, metadata },
    ))
}

fn format_time(value: OffsetDateTime, request_id: RequestId) -> Result<String, ApiKeyHttpError> {
    value
        .format(&Rfc3339)
        .map_err(|_| ApiKeyHttpError::internal(request_id))
}

fn no_store_json(value: impl Serialize) -> Response {
    no_store_json_status(StatusCode::OK, value)
}

fn no_store_json_status(status: StatusCode, value: impl Serialize) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn no_content() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ApiKeyHttpError(ApiError);

impl ApiKeyHttpError {
    const fn invalid_request(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_API_KEY_REQUEST",
            "the API-key lifecycle request is invalid",
            request_id,
        ))
    }

    const fn invalid_path(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "INVALID_PATH_PARAMETER",
            "a path parameter is invalid",
            request_id,
        ))
    }

    const fn permission_denied(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "the authenticated principal may not manage this service account",
            request_id,
        ))
    }

    const fn scope_escalation(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "API_KEY_SCOPE_ESCALATION",
            "issued API-key scopes must be a subset of the actor's effective scopes",
            request_id,
        ))
    }

    const fn not_found(code: &'static str, request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::NOT_FOUND,
            code,
            "the requested API-key lifecycle resource was not found",
            request_id,
        ))
    }

    const fn conflict(code: &'static str, request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::CONFLICT,
            code,
            "the requested API-key lifecycle transition conflicts with current state",
            request_id,
        ))
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "API_KEY_PERSISTENCE_UNAVAILABLE",
            "API-key lifecycle persistence is temporarily unavailable",
            request_id,
        ))
    }

    const fn internal(request_id: RequestId) -> Self {
        Self(ApiError::internal(request_id))
    }
}

impl IntoResponse for ApiKeyHttpError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

const fn map_store_error(error: ApiKeyStoreError, request_id: RequestId) -> ApiKeyHttpError {
    match error {
        ApiKeyStoreError::InvalidName
        | ApiKeyStoreError::InvalidExpiry
        | ApiKeyStoreError::TooManyScopes
        | ApiKeyStoreError::InvalidListLimit
        | ApiKeyStoreError::InvalidIdentifier => ApiKeyHttpError::invalid_request(request_id),
        ApiKeyStoreError::CreatorNotFound => {
            ApiKeyHttpError::conflict("API_KEY_CREATOR_INACTIVE", request_id)
        }
        ApiKeyStoreError::TenantUnavailable => ApiKeyHttpError::permission_denied(request_id),
        ApiKeyStoreError::ServiceAccountNotFound => {
            ApiKeyHttpError::not_found("SERVICE_ACCOUNT_NOT_FOUND", request_id)
        }
        ApiKeyStoreError::ApiKeyNotFound => {
            ApiKeyHttpError::not_found("API_KEY_NOT_FOUND", request_id)
        }
        ApiKeyStoreError::ServiceAccountDisabled => {
            ApiKeyHttpError::conflict("SERVICE_ACCOUNT_DISABLED", request_id)
        }
        ApiKeyStoreError::ApiKeyInactive => {
            ApiKeyHttpError::conflict("API_KEY_INACTIVE", request_id)
        }
        ApiKeyStoreError::Conflict => {
            ApiKeyHttpError::conflict("API_KEY_STATE_CONFLICT", request_id)
        }
        ApiKeyStoreError::Unavailable | ApiKeyStoreError::Transient(_) => {
            ApiKeyHttpError::unavailable(request_id)
        }
        _ => ApiKeyHttpError::internal(request_id),
    }
}

const fn map_tenancy_error(error: TenancyStoreError, request_id: RequestId) -> ApiKeyHttpError {
    match error {
        TenancyStoreError::AccessDenied
        | TenancyStoreError::TenantMismatch
        | TenancyStoreError::MembershipNotFound => ApiKeyHttpError::permission_denied(request_id),
        TenancyStoreError::Unavailable | TenancyStoreError::Transient(_) => {
            ApiKeyHttpError::unavailable(request_id)
        }
        _ => ApiKeyHttpError::internal(request_id),
    }
}
