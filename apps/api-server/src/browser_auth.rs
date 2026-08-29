//! Browser password authentication assembled from the production PostgreSQL providers.
//!
//! Merge [`browser_auth_router`] and any routes wrapped by [`protected_browser_router`]
//! into the normal application router before applying `omnius_http::HttpShell::apply`.
//! The shell is the canonical Origin/CSRF boundary for every unsafe cookie-authenticated
//! request; these routes must never be mounted through the machine-callback shell.

use std::{str::FromStr as _, sync::Arc};

use axum::{
    Json, Router,
    extract::{Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::{get, post},
};
use axum_login::{AuthManagerLayerBuilder, AuthSession, AuthUser as _, AuthnBackend as _};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, SessionConfig, SessionMetadata,
    SessionRegistration, SessionValidation, SubjectId, TenantId, hash_user_agent,
};
use omnius_auth_password::{
    PasswordInput, PasswordStoreError, PasswordVerification, PasswordWorker, PostgresPasswordStore,
};
use omnius_auth_session_postgres::{
    PostgresSessionLifecycle, PostgresSessionStore, SessionBackend, SessionGuardError,
    SessionRevocationGuard, SessionStoreError, guard_revoked_session, session_manager_layer,
};
use omnius_authz_basic::{
    Action, AuthorizationContext, BasicAuthorizer, Decision, Resource, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_core::RequestId;
use omnius_postgres::PostgresPool;
use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tower_sessions::{Session, cookie::Cookie, session::Id};
use uuid::Uuid;

use super::{ApiError, map_json_rejection, resolve_request_id};

/// Exact password-login route.
pub const BROWSER_LOGIN_PATH: &str = "/auth/login";
/// Exact authenticated session-bootstrap route.
pub const BROWSER_SESSION_PATH: &str = "/auth/session";
/// Exact current-session logout route.
pub const BROWSER_LOGOUT_PATH: &str = "/auth/logout";
/// Exact all-session logout route.
pub const BROWSER_LOGOUT_ALL_PATH: &str = "/auth/logout-all";
/// Exact backend-enforced privileged-operation route.
pub const BROWSER_PRIVILEGED_PATH: &str = "/auth/permissions/privileged";

const MAX_IDENTITY_PROVIDER_BYTES: usize = 2_048;
const MAX_LOGIN_IDENTIFIER_BYTES: usize = 255;
const AXUM_LOGIN_DATA_KEY: &str = "axum-login.data";
const BROWSER_TENANT_KEY: &str = "omnius.browser.tenant_id";

/// The maintained `axum-login` session extractor used by browser and protected routes.
pub type BrowserAuthSession = AuthSession<SessionBackend>;

/// Validated identity provider namespace used to resolve password login identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordLoginProvider(String);

impl PasswordLoginProvider {
    /// Validates and owns a provider namespace such as `email`.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordLoginProviderError`] for an empty, padded, oversized, or
    /// control-character-containing provider.
    pub fn new(value: impl Into<String>) -> Result<Self, PasswordLoginProviderError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_IDENTITY_PROVIDER_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(PasswordLoginProviderError);
        }
        Ok(Self(value))
    }

    /// Returns the validated provider namespace.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A password-login identity provider namespace was unsafe for persistence lookup.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("password login identity provider is invalid")]
pub struct PasswordLoginProviderError;

/// Backend authorization facts for the browser's privileged operation.
///
/// The target is always owned by the authenticated principal, while the authorizer
/// independently applies its configured scope, assurance, and grant gates. Browser
/// presentation state is never accepted as authorization input.
#[derive(Clone, Debug)]
pub struct BrowserAuthorization {
    authorizer: BasicAuthorizer,
    action: Action,
    resource_kind: ResourceKind,
}

impl BrowserAuthorization {
    /// Installs an existing fail-closed authorizer and the protected operation vocabulary.
    #[must_use]
    pub const fn new(
        authorizer: BasicAuthorizer,
        action: Action,
        resource_kind: ResourceKind,
    ) -> Self {
        Self {
            authorizer,
            action,
            resource_kind,
        }
    }

    fn authorize(&self, principal: &Principal) -> Decision {
        let resource = Resource::new(self.resource_kind.clone()).owned_by(principal.subject_id);
        self.authorizer.authorize(
            principal,
            &self.action,
            &resource,
            &AuthorizationContext::default(),
        )
    }

    fn presentation_permissions(&self, principal: &Principal) -> Vec<String> {
        if self.authorize(principal) == Decision::Allow {
            vec![self.action.as_str().to_owned()]
        } else {
            Vec::new()
        }
    }
}

/// Shared production state for password login, browser sessions, and authorization.
#[derive(Clone)]
pub struct BrowserAuthState {
    pool: PostgresPool,
    session_config: SessionConfig,
    password_worker: PasswordWorker,
    login_provider: PasswordLoginProvider,
    authorization: BrowserAuthorization,
    trusted_origins: Arc<[String]>,
}

impl BrowserAuthState {
    /// Assembles already-validated production provider state.
    #[must_use]
    pub fn new(
        pool: PostgresPool,
        session_config: SessionConfig,
        password_worker: PasswordWorker,
        login_provider: PasswordLoginProvider,
        authorization: BrowserAuthorization,
        trusted_origins: Vec<String>,
    ) -> Self {
        Self {
            pool,
            session_config,
            password_worker,
            login_provider,
            trusted_origins: trusted_origins.into(),
            authorization,
        }
    }

    /// Returns the managed PostgreSQL pool used by session adapters.
    #[must_use]
    pub const fn pool(&self) -> &PostgresPool {
        &self.pool
    }

    /// Returns the exact cookie and expiry policy used by session adapters.
    #[must_use]
    pub const fn session_config(&self) -> &SessionConfig {
        &self.session_config
    }

    /// Returns a header-authentication boundary for transports that cannot use Axum extractors.
    #[must_use]
    pub fn cookie_identity(&self) -> BrowserCookieIdentity {
        BrowserCookieIdentity {
            pool: self.pool.clone(),
            session_config: self.session_config.clone(),
        }
    }
}

/// Failure to install the maintained browser-session layers.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrowserAuthBuildError {
    /// Session cookie or persistence policy is invalid.
    #[error("browser session configuration is invalid: {0}")]
    Session(#[from] omnius_auth_core::SessionConfigError),
    /// The response-time revocation guard could not form its secure cookie policy.
    #[error("browser session revocation guard is invalid: {0}")]
    Guard(#[from] SessionGuardError),
}

/// Builds real password-login, bootstrap, logout, logout-all, and authorization routes.
///
/// The returned router includes the maintained session manager and the outer
/// response-time revocation guard. The caller must merge it before applying the
/// normal `HttpShell`, which supplies canonical Origin/CSRF and request-identity
/// middleware to these unsafe cookie-authenticated routes.
///
/// # Errors
///
/// Returns [`BrowserAuthBuildError`] when secure session layers cannot be constructed.
pub fn browser_auth_router(
    state: BrowserAuthState,
    deployment: DeploymentEnvironment,
) -> Result<Router, BrowserAuthBuildError> {
    let layer_state = state.clone();
    let routes = Router::new()
        .route(BROWSER_LOGIN_PATH, post(login))
        .route(BROWSER_SESSION_PATH, get(session_bootstrap))
        .route(BROWSER_LOGOUT_PATH, post(logout))
        .route(BROWSER_LOGOUT_ALL_PATH, post(logout_all))
        .route(BROWSER_PRIVILEGED_PATH, post(require_privileged_permission))
        .with_state(state);
    install_session_layers(&layer_state, deployment, routes)
}

/// Wraps an application router with canonical browser identity enforcement.
///
/// Successful requests receive authoritative [`Principal`] and [`SessionMetadata`]
/// extensions. Missing, expired, or revoked sessions never reach the wrapped handler.
/// Merge the result before applying the normal `HttpShell` so its unsafe methods are
/// protected by the same Origin/CSRF policy as the auth routes.
///
/// # Errors
///
/// Returns [`BrowserAuthBuildError`] when secure session layers cannot be constructed.
pub fn protected_browser_router<S>(
    state: &BrowserAuthState,
    deployment: DeploymentEnvironment,
    routes: Router<S>,
) -> Result<Router<S>, BrowserAuthBuildError>
where
    S: Clone + Send + Sync + 'static,
{
    let routes = routes.layer(middleware::from_fn_with_state(
        state.clone(),
        attach_browser_principal,
    ));
    install_session_layers(state, deployment, routes)
}

fn install_session_layers<S>(
    state: &BrowserAuthState,
    deployment: DeploymentEnvironment,
    routes: Router<S>,
) -> Result<Router<S>, BrowserAuthBuildError>
where
    S: Clone + Send + Sync + 'static,
{
    let auth_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(state.pool.clone()),
        session_manager_layer(&state.pool, &state.session_config, deployment)?,
    )
    .build();
    let revocation_guard = SessionRevocationGuard::new(state.pool.clone(), &state.session_config)?;
    Ok(routes
        .layer(auth_layer)
        .layer(middleware::from_fn_with_state(
            revocation_guard,
            guard_revoked_session,
        )))
}

/// An active, validated browser session with no provider session identifier exposed.
#[derive(Clone, Debug)]
pub struct ActiveBrowserSession {
    /// Canonical identity restored from authoritative user and session state.
    pub principal: Principal,
    /// Safe lifecycle metadata for the current session.
    pub metadata: SessionMetadata,
}

/// Stable session authentication failure without credential or provider details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrowserSessionError {
    /// No authenticated session user was restored.
    #[error("browser authentication is required")]
    Missing,
    /// The session expired, was revoked, or no longer belongs to the restored user.
    #[error("browser session expired or was revoked")]
    RevokedOrExpired,
    /// Authoritative persistence could not be reached.
    #[error("browser authentication is unavailable")]
    Unavailable,
    /// Provider session data could not be cleared safely.
    #[error("browser session data is invalid")]
    SessionData,
}

/// Validates and touches an extracted session before producing a canonical principal.
///
/// Rejected lifecycle state is flushed immediately so the response clears the browser
/// cookie. The caller still needs [`SessionRevocationGuard`] outside the session manager
/// to close response-save revocation races.
///
/// # Errors
///
/// Returns [`BrowserSessionError`] for missing, inactive, unavailable, or corrupt
/// authoritative session state.
pub async fn require_active_session(
    state: &BrowserAuthState,
    auth: &mut BrowserAuthSession,
) -> Result<ActiveBrowserSession, BrowserSessionError> {
    let Some(subject_id) = auth
        .user
        .as_ref()
        .map(omnius_auth_session_postgres::SessionUser::subject_id)
    else {
        auth.logout()
            .await
            .map_err(|_| BrowserSessionError::SessionData)?;
        return Err(BrowserSessionError::Missing);
    };
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| BrowserSessionError::Unavailable)?;
    let validation = PostgresSessionLifecycle
        .validate_and_touch_with(
            &mut connection,
            &auth.session,
            subject_id,
            &state.session_config,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(map_session_validation_error)?;
    drop(connection);

    match validation {
        SessionValidation::Active(metadata) => {
            let mut principal = auth
                .user
                .as_ref()
                .map(|user| user.principal(metadata.created_at))
                .ok_or(BrowserSessionError::Missing)?;
            principal.tenant_id = browser_session_tenant(&auth.session)
                .await
                .map_err(|()| BrowserSessionError::SessionData)?;
            Ok(ActiveBrowserSession {
                principal,
                metadata,
            })
        }
        SessionValidation::Rejected => {
            auth.logout()
                .await
                .map_err(|_| BrowserSessionError::SessionData)?;
            Err(BrowserSessionError::RevokedOrExpired)
        }
    }
}

/// Binds an already-authorized tenant to the exact current browser session.
///
/// Callers must resolve authoritative membership before invoking this function. The selected
/// tenant is restored into every subsequent HTTP, WebSocket, and SSE principal created from this
/// session; sibling sessions remain independent.
///
/// # Errors
///
/// Returns [`BrowserSessionError::SessionData`] when the session store cannot persist the binding.
pub async fn bind_browser_session_tenant(
    auth: &BrowserAuthSession,
    tenant_id: TenantId,
) -> Result<(), BrowserSessionError> {
    auth.session
        .insert(BROWSER_TENANT_KEY, tenant_id.to_string())
        .await
        .map_err(|_| BrowserSessionError::SessionData)
}

pub(crate) async fn browser_session_tenant(session: &Session) -> Result<Option<TenantId>, ()> {
    session
        .get::<String>(BROWSER_TENANT_KEY)
        .await
        .map_err(|_| ())?
        .map(|value| TenantId::from_str(&value).map_err(|_| ()))
        .transpose()
}

async fn attach_browser_principal(
    State(state): State<BrowserAuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    let had_cookie =
        request_has_session_cookie(request.headers(), &state.session_config.cookie_name);
    let Some(mut auth) = request.extensions().get::<BrowserAuthSession>().cloned() else {
        return BrowserHttpError::internal(request_id).into_response();
    };
    match require_active_session(&state, &mut auth).await {
        Ok(active) => {
            request.extensions_mut().insert(active.principal);
            request.extensions_mut().insert(active.metadata);
            next.run(request).await
        }
        Err(error) => BrowserHttpError::from_session(error, had_cookie, request_id).into_response(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    identifier: String,
    password: SecretString,
}

async fn login(
    State(state): State<BrowserAuthState>,
    request_id: Option<axum::Extension<RequestId>>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
    payload: Result<Json<LoginRequest>, JsonRejection>,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    if !trusted_login_origin(&state, &headers) {
        return Err(BrowserHttpError::csrf_origin_denied(request_id));
    }
    let Json(payload) =
        payload.map_err(|error| BrowserHttpError(map_json_rejection(&error, request_id)))?;
    if !valid_login_identifier(&payload.identifier) {
        return Err(BrowserHttpError::login_rejected(request_id));
    }
    let candidate = PasswordInput::new(payload.password)
        .map_err(|_| BrowserHttpError::login_rejected(request_id))?;
    let now = OffsetDateTime::now_utc();
    let mut connection = state
        .pool
        .acquire()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    let subject_id = resolve_login_subject(
        &mut connection,
        state.login_provider.as_str(),
        &payload.identifier,
    )
    .await
    .map_err(|()| BrowserHttpError::unavailable(request_id))?;
    let verification_subject = subject_id.unwrap_or_else(SubjectId::new);
    let verification = PostgresPasswordStore
        .verify_password_with(
            &mut connection,
            verification_subject,
            candidate,
            &state.password_worker,
            now,
        )
        .await
        .map_err(|error| map_password_store_error(error, request_id))?;
    drop(connection);
    if subject_id.is_none() || !matches!(verification, PasswordVerification::Verified { .. }) {
        return Err(BrowserHttpError::login_rejected(request_id));
    }
    let subject_id = subject_id.ok_or_else(|| BrowserHttpError::login_rejected(request_id))?;
    let user = auth
        .backend
        .get_user(&subject_id)
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?
        .ok_or_else(|| BrowserHttpError::login_rejected(request_id))?;

    revoke_existing_login_session(&state, &mut auth, now, request_id).await?;
    auth.login(&user)
        .await
        .map_err(|_| BrowserHttpError::internal(request_id))?;
    let user_agent_hash = headers
        .get(header::USER_AGENT)
        .map(|value| hash_user_agent(value.as_bytes()));
    PostgresSessionLifecycle
        .register_after_login(
            &state.pool,
            &auth.session,
            &SessionRegistration {
                subject_id,
                device_id: Uuid::now_v7(),
                created_at: now,
                user_agent_hash,
                ip_prefix: None,
            },
            &state.session_config,
        )
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    Ok(no_content_response())
}

fn trusted_login_origin(state: &BrowserAuthState, headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return false;
    };
    state
        .trusted_origins
        .iter()
        .any(|trusted| origin.as_bytes() == trusted.as_bytes())
}

async fn revoke_existing_login_session(
    state: &BrowserAuthState,
    auth: &mut BrowserAuthSession,
    now: OffsetDateTime,
    request_id: RequestId,
) -> Result<(), BrowserHttpError> {
    let Some(subject_id) = auth
        .user
        .as_ref()
        .map(omnius_auth_session_postgres::SessionUser::subject_id)
    else {
        return Ok(());
    };
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    let revoked = PostgresSessionLifecycle
        .revoke_current_with(&mut transaction, &auth.session, subject_id, now)
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    auth.logout()
        .await
        .map_err(|_| BrowserHttpError::internal(request_id))?;
    if !revoked {
        return Err(BrowserHttpError::internal(request_id));
    }
    Ok(())
}

async fn session_bootstrap(
    State(state): State<BrowserAuthState>,
    request_id: Option<axum::Extension<RequestId>>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let had_cookie = request_has_session_cookie(&headers, &state.session_config.cookie_name);
    let active = require_active_session(&state, &mut auth)
        .await
        .map_err(|error| BrowserHttpError::from_session(error, had_cookie, request_id))?;
    let response = SessionBootstrapResponse::from_active(&state.authorization, active)
        .map_err(|_| BrowserHttpError::internal(request_id))?;
    Ok(no_store_json(response))
}

async fn logout(
    State(state): State<BrowserAuthState>,
    request_id: Option<axum::Extension<RequestId>>,
    mut auth: BrowserAuthSession,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let Some(subject_id) = auth
        .user
        .as_ref()
        .map(omnius_auth_session_postgres::SessionUser::subject_id)
    else {
        auth.logout()
            .await
            .map_err(|_| BrowserHttpError::internal(request_id))?;
        return Ok(no_content_response());
    };
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    let revoked = PostgresSessionLifecycle
        .revoke_current_with(
            &mut transaction,
            &auth.session,
            subject_id,
            OffsetDateTime::now_utc(),
        )
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    auth.logout()
        .await
        .map_err(|_| BrowserHttpError::internal(request_id))?;
    if !revoked {
        return Err(BrowserHttpError::internal(request_id));
    }
    Ok(no_content_response())
}

async fn logout_all(
    State(state): State<BrowserAuthState>,
    request_id: Option<axum::Extension<RequestId>>,
    mut auth: BrowserAuthSession,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let Some(subject_id) = auth
        .user
        .as_ref()
        .map(omnius_auth_session_postgres::SessionUser::subject_id)
    else {
        auth.logout()
            .await
            .map_err(|_| BrowserHttpError::internal(request_id))?;
        return Ok(no_content_response());
    };
    let mut transaction = state
        .pool
        .sqlx_pool()
        .begin()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    PostgresSessionLifecycle
        .revoke_all_with(&mut transaction, subject_id, OffsetDateTime::now_utc())
        .await
        .map_err(|error| map_session_store_error(error, request_id))?;
    transaction
        .commit()
        .await
        .map_err(|_| BrowserHttpError::unavailable(request_id))?;
    auth.logout()
        .await
        .map_err(|_| BrowserHttpError::internal(request_id))?;
    Ok(no_content_response())
}

async fn require_privileged_permission(
    State(state): State<BrowserAuthState>,
    request_id: Option<axum::Extension<RequestId>>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
) -> Result<Response, BrowserHttpError> {
    let request_id = resolve_request_id(request_id);
    let had_cookie = request_has_session_cookie(&headers, &state.session_config.cookie_name);
    let active = require_active_session(&state, &mut auth)
        .await
        .map_err(|error| BrowserHttpError::from_session(error, had_cookie, request_id))?;
    if state.authorization.authorize(&active.principal) != Decision::Allow {
        return Err(BrowserHttpError::permission_denied(request_id));
    }
    Ok(no_content_response())
}

#[derive(Serialize)]
struct SessionBootstrapResponse {
    subject_id: String,
    kind: &'static str,
    tenant_id: Option<String>,
    authenticated_at: String,
    auth_method: &'static str,
    assurance: &'static str,
    scopes: Vec<String>,
    expires_at: String,
    presentation_permissions: Vec<String>,
    resource_permissions: Vec<ResourcePermissionResponse>,
    tenant: Option<TenantResponse>,
}

impl SessionBootstrapResponse {
    fn from_active(
        authorization: &BrowserAuthorization,
        active: ActiveBrowserSession,
    ) -> Result<Self, time::error::Format> {
        let ActiveBrowserSession {
            principal,
            metadata,
        } = active;
        let presentation_permissions = authorization.presentation_permissions(&principal);
        let tenant_id = principal.tenant_id.map(|tenant_id| tenant_id.to_string());
        Ok(Self {
            subject_id: principal.subject_id.to_string(),
            kind: principal_kind(principal.kind),
            tenant_id: tenant_id.clone(),
            authenticated_at: principal.authenticated_at.format(&Rfc3339)?,
            auth_method: auth_method(principal.auth_method),
            assurance: assurance(principal.assurance),
            scopes: principal
                .scopes
                .into_iter()
                .map(|scope| scope.to_string())
                .collect(),
            expires_at: metadata.absolute_expires_at.format(&Rfc3339)?,
            presentation_permissions,
            resource_permissions: Vec::new(),
            tenant: tenant_id.map(|id| TenantResponse { id }),
        })
    }
}

#[derive(Serialize)]
struct ResourcePermissionResponse {
    permission: String,
    context: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize)]
struct TenantResponse {
    id: String,
}

const fn principal_kind(kind: PrincipalKind) -> &'static str {
    match kind {
        PrincipalKind::User => "user",
        PrincipalKind::ServiceAccount => "service_account",
    }
}

const fn auth_method(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::Password => "password",
        AuthMethod::Session => "session",
        AuthMethod::Jwt => "jwt",
        AuthMethod::Oidc => "oidc",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::WebAuthn => "web_authn",
        AuthMethod::Totp => "totp",
    }
}

const fn assurance(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Aal1 => "aal1",
        AssuranceLevel::Aal2 => "aal2",
        AssuranceLevel::Aal3 => "aal3",
    }
}

fn valid_login_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOGIN_IDENTIFIER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

async fn resolve_login_subject(
    connection: &mut sqlx::PgConnection,
    provider: &str,
    identifier: &str,
) -> Result<Option<SubjectId>, ()> {
    let row = sqlx::query(
        "SELECT i.user_id FROM identities i JOIN users u ON u.id = i.user_id \
         WHERE i.provider = $1 AND i.provider_subject = $2",
    )
    .bind(provider)
    .bind(identifier)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|_| ())?;
    row.map(|row| {
        let id: Uuid = row.try_get("user_id").map_err(|_| ())?;
        SubjectId::from_uuid(id).map_err(|_| ())
    })
    .transpose()
}

fn request_has_session_cookie(headers: &HeaderMap, cookie_name: &str) -> bool {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|value| Cookie::parse_encoded(value.trim().to_owned()).ok())
        .any(|cookie| cookie.name() == cookie_name && !cookie.value().is_empty())
}

fn no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn no_store_json(value: impl Serialize) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Clone, Copy, Debug)]
struct BrowserHttpError(ApiError);

impl BrowserHttpError {
    const fn login_rejected(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "LOGIN_REJECTED",
            "the supplied credentials were rejected",
            request_id,
        ))
    }

    const fn authentication_required(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "a valid browser session is required",
            request_id,
        ))
    }

    const fn revoked_or_expired(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "SESSION_REVOKED_OR_EXPIRED",
            "the browser session expired or was revoked",
            request_id,
        ))
    }

    const fn permission_denied(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "PERMISSION_DENIED",
            "the authenticated principal is not permitted to perform this operation",
            request_id,
        ))
    }
    const fn csrf_origin_denied(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::FORBIDDEN,
            "CSRF_ORIGIN_DENIED",
            "the request origin is not trusted for browser authentication",
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

    const fn from_session(
        error: BrowserSessionError,
        had_cookie: bool,
        request_id: RequestId,
    ) -> Self {
        match error {
            BrowserSessionError::Missing if had_cookie => Self::revoked_or_expired(request_id),
            BrowserSessionError::Missing => Self::authentication_required(request_id),
            BrowserSessionError::RevokedOrExpired => Self::revoked_or_expired(request_id),
            BrowserSessionError::Unavailable => Self::unavailable(request_id),
            BrowserSessionError::SessionData => Self::internal(request_id),
        }
    }
}

impl axum::response::IntoResponse for BrowserHttpError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

const fn map_session_validation_error(error: SessionStoreError) -> BrowserSessionError {
    match error {
        SessionStoreError::Inactive => BrowserSessionError::RevokedOrExpired,
        SessionStoreError::Unavailable | SessionStoreError::Transient(_) => {
            BrowserSessionError::Unavailable
        }
        _ => BrowserSessionError::SessionData,
    }
}

const fn map_session_store_error(
    error: SessionStoreError,
    request_id: RequestId,
) -> BrowserHttpError {
    match error {
        SessionStoreError::Unavailable | SessionStoreError::Transient(_) => {
            BrowserHttpError::unavailable(request_id)
        }
        SessionStoreError::Inactive => BrowserHttpError::revoked_or_expired(request_id),
        _ => BrowserHttpError::internal(request_id),
    }
}

const fn map_password_store_error(
    error: PasswordStoreError,
    request_id: RequestId,
) -> BrowserHttpError {
    match error {
        PasswordStoreError::Unavailable | PasswordStoreError::Transient(_) => {
            BrowserHttpError::unavailable(request_id)
        }
        _ => BrowserHttpError::internal(request_id),
    }
}

/// Header-only browser-cookie identity boundary for upgrade and streaming authentication.
///
/// It hydrates the maintained provider record, checks the `axum-login` authentication
/// version hash, and validates/touches lifecycle state. The raw cookie and provider ID
/// are never returned.
#[derive(Clone)]
pub struct BrowserCookieIdentity {
    pool: PostgresPool,
    session_config: SessionConfig,
}

/// Opaque, exact session state retained for one authenticated streaming connection.
///
/// Fields intentionally have no accessors or `Debug` representation, so transport
/// adapters can retain and return the binding without observing the provider session ID.
pub struct BrowserSessionBinding {
    session: Session,
    subject_id: SubjectId,
}

/// Authoritative result of revalidating an exact bound browser session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrowserSessionRevalidation {
    /// The exact session and immutable principal remain active.
    Active,
    /// The bound session expired, was revoked, changed identity, or was rejected.
    Revoked,
    /// Authoritative provider state could not be established safely.
    Unavailable,
}

/// Stable header-authentication classification with no credential or provider details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BrowserCookieAuthenticationError {
    /// No browser session cookie was supplied.
    #[error("browser session cookie is missing")]
    Missing,
    /// The cookie, provider session, authentication hash, or lifecycle state was rejected.
    #[error("browser session cookie was rejected")]
    Rejected,
    /// Authoritative session state could not be established safely.
    #[error("browser session authentication is unavailable")]
    Unavailable,
}

#[derive(Deserialize)]
struct StoredAxumLoginData {
    user_id: Option<SubjectId>,
    auth_hash: Option<Vec<u8>>,
}

impl BrowserCookieIdentity {
    /// Authenticates an exact opaque session cookie into a canonical principal.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserCookieAuthenticationError`] for a missing or rejected cookie,
    /// corrupt provider state, or unavailable authoritative persistence.
    pub async fn authenticate_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<ActiveBrowserSession, BrowserCookieAuthenticationError> {
        self.authenticate_bound_headers(headers)
            .await
            .map(|(active, _binding)| active)
    }

    /// Authenticates headers and retains an opaque exact-session revalidation binding.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserCookieAuthenticationError`] under the same fail-closed policy as
    /// [`Self::authenticate_headers`].
    pub async fn authenticate_bound_headers(
        &self,
        headers: &HeaderMap,
    ) -> Result<(ActiveBrowserSession, BrowserSessionBinding), BrowserCookieAuthenticationError>
    {
        let raw_id = exact_session_cookie(headers, &self.session_config.cookie_name)?;
        let id = Id::from_str(&raw_id).map_err(|_| BrowserCookieAuthenticationError::Rejected)?;
        let session = Session::new(
            Some(id),
            Arc::new(PostgresSessionStore::new(&self.pool)),
            None,
        );
        let active = self.active_bound_session(&session, None).await?;
        let binding = BrowserSessionBinding {
            subject_id: active.principal.subject_id,
            session,
        };
        Ok((active, binding))
    }

    /// Revalidates the exact provider session retained at initial authentication.
    ///
    /// Authentication-version changes, principal changes, expiry, and revocation all
    /// return [`BrowserSessionRevalidation::Revoked`]. Provider failures return
    /// [`BrowserSessionRevalidation::Unavailable`] so transports fail closed without
    /// misclassifying an outage as a credential event.
    pub async fn revalidate_bound_session(
        &self,
        principal: &Principal,
        binding: &BrowserSessionBinding,
    ) -> BrowserSessionRevalidation {
        if principal.subject_id != binding.subject_id
            || principal.auth_method != AuthMethod::Session
        {
            return BrowserSessionRevalidation::Revoked;
        }
        match self
            .active_bound_session(&binding.session, Some(binding.subject_id))
            .await
        {
            Ok(active) if active.principal == *principal => BrowserSessionRevalidation::Active,
            Ok(_)
            | Err(
                BrowserCookieAuthenticationError::Missing
                | BrowserCookieAuthenticationError::Rejected,
            ) => BrowserSessionRevalidation::Revoked,
            Err(BrowserCookieAuthenticationError::Unavailable) => {
                BrowserSessionRevalidation::Unavailable
            }
        }
    }

    async fn active_bound_session(
        &self,
        session: &Session,
        expected_subject: Option<SubjectId>,
    ) -> Result<ActiveBrowserSession, BrowserCookieAuthenticationError> {
        let data = session
            .get::<StoredAxumLoginData>(AXUM_LOGIN_DATA_KEY)
            .await
            .map_err(|_| BrowserCookieAuthenticationError::Unavailable)?
            .ok_or(BrowserCookieAuthenticationError::Rejected)?;
        let subject_id = data
            .user_id
            .ok_or(BrowserCookieAuthenticationError::Rejected)?;
        if expected_subject.is_some_and(|expected| expected != subject_id) {
            return Err(BrowserCookieAuthenticationError::Rejected);
        }
        let user = SessionBackend::new(self.pool.clone())
            .get_user(&subject_id)
            .await
            .map_err(|_| BrowserCookieAuthenticationError::Unavailable)?
            .ok_or(BrowserCookieAuthenticationError::Rejected)?;
        if data.auth_hash.as_deref() != Some(user.session_auth_hash()) {
            return Err(BrowserCookieAuthenticationError::Rejected);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| BrowserCookieAuthenticationError::Unavailable)?;
        let validation = PostgresSessionLifecycle
            .validate_and_touch_with(
                &mut connection,
                session,
                subject_id,
                &self.session_config,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(|_| BrowserCookieAuthenticationError::Unavailable)?;
        let SessionValidation::Active(metadata) = validation else {
            return Err(BrowserCookieAuthenticationError::Rejected);
        };
        let mut principal = user.principal(metadata.created_at);
        principal.tenant_id = browser_session_tenant(session)
            .await
            .map_err(|()| BrowserCookieAuthenticationError::Unavailable)?;
        Ok(ActiveBrowserSession {
            principal,
            metadata,
        })
    }
}

fn exact_session_cookie(
    headers: &HeaderMap,
    cookie_name: &str,
) -> Result<String, BrowserCookieAuthenticationError> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        let value = value
            .to_str()
            .map_err(|_| BrowserCookieAuthenticationError::Rejected)?;
        for candidate in value.split(';') {
            let cookie = Cookie::parse_encoded(candidate.trim().to_owned())
                .map_err(|_| BrowserCookieAuthenticationError::Rejected)?;
            if cookie.name() != cookie_name {
                continue;
            }
            if cookie.value().is_empty() || found.is_some() {
                return Err(BrowserCookieAuthenticationError::Rejected);
            }
            found = Some(cookie.value().to_owned());
        }
    }
    found.ok_or(BrowserCookieAuthenticationError::Missing)
}
