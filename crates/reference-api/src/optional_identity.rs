//! Reusable upstream OIDC, passkey, and TOTP route composition.
//!
//! These adapters extend the canonical authenticated reference API. The OIDC adapter is an
//! upstream relying party and never constructs or exposes the hosted OAuth authorization server.

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use axum::{
    Extension, Json, Router,
    extract::{Path, Query, Request, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse as _, Redirect, Response},
    routing::{get, post},
};
use omnius_auth_core::{Principal, PrincipalKind, SubjectId};
use omnius_auth_oidc::{
    AccountOutcome, FlowPurpose, OidcBuildError, OidcConfig, OidcFlow, OidcFlowError,
    OidcIdentityStore, OidcPendingStore, OidcPendingStoreError, OidcStoreError,
    PendingAuthorizationId,
};
use omnius_auth_totp::{
    ConfirmedTotpEnrollment, PendingTotpEnrollment, TotpConfig, TotpCredentialMetadata, TotpStore,
    TotpStoreError,
};
use omnius_auth_webauthn::{
    CeremonyHandle, PasskeyMetadata, PublicKeyCredential, RegisterPublicKeyCredential,
    WebAuthnConfig, WebAuthnService, WebAuthnServiceError,
};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _};
use omnius_core::{ErrorCode, RequestId, ServiceError};
use omnius_outbound_http::OutboundHttpClients;
use omnius_postgres::PostgresPool;
use omnius_runtime::{Criticality, RestartPolicy, TaskSpec};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ApiError,
    api_key_auth::{
        AuthenticatedIdentityBuildError, CanonicalPrincipalState, protected_principal_router,
    },
    browser_auth::{
        BrowserAuthBuildError, BrowserAuthSession, BrowserAuthState, BrowserHttpError,
        browser_session_router, establish_browser_session, require_active_session,
    },
    map_json_rejection, resolve_request_id,
};

/// Exact upstream OIDC authorization start route.
pub const OIDC_START_PATH: &str = "/auth/oidc/{provider}/start";
/// Exact upstream OIDC authorization callback route.
pub const OIDC_CALLBACK_PATH: &str = "/auth/oidc/{provider}/callback";
/// Exact passkey collection route.
pub const PASSKEYS_PATH: &str = "/auth/passkeys";
/// Exact passkey registration start route.
pub const PASSKEY_REGISTER_START_PATH: &str = "/auth/passkeys/register/start";
/// Exact passkey registration finish route.
pub const PASSKEY_REGISTER_FINISH_PATH: &str = "/auth/passkeys/register/finish";
/// Exact account-bound passkey authentication start route.
pub const PASSKEY_AUTHENTICATE_START_PATH: &str = "/auth/passkeys/authenticate/start";
/// Exact account-bound passkey authentication finish route.
pub const PASSKEY_AUTHENTICATE_FINISH_PATH: &str = "/auth/passkeys/authenticate/finish";
/// Exact TOTP enrollment route.
pub const TOTP_ENROLL_PATH: &str = "/auth/mfa/totp/enroll";
/// Exact TOTP enrollment confirmation route.
pub const TOTP_CONFIRM_PATH: &str = "/auth/mfa/totp/confirm";
/// Exact TOTP disable route.
pub const TOTP_DISABLE_PATH: &str = "/auth/mfa/totp/disable";
/// Bounded pending-authorization cleanup task identifier.
pub const OIDC_PENDING_CLEANUP_TASK_ID: &str = "oidc-pending-authorization-cleanup";

const OIDC_ROUTE_IDS: &[&str] = &[OIDC_START_PATH, OIDC_CALLBACK_PATH];
const WEBAUTHN_ROUTE_IDS: &[&str] = &[
    PASSKEYS_PATH,
    PASSKEY_REGISTER_START_PATH,
    PASSKEY_REGISTER_FINISH_PATH,
    PASSKEY_AUTHENTICATE_START_PATH,
    PASSKEY_AUTHENTICATE_FINISH_PATH,
];
const TOTP_ROUTE_IDS: &[&str] = &[TOTP_ENROLL_PATH, TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH];
const OIDC_TASK_IDS: &[&str] = &[OIDC_PENDING_CLEANUP_TASK_ID];
const OIDC_PENDING_SESSION_KEY: &str = "omnius.auth_oidc.pending_authorization.v1";
const PASSKEY_REGISTRATION_SESSION_KEY: &str = "omnius.auth_webauthn.registration.v1";
const PASSKEY_AUTHENTICATION_SESSION_KEY: &str = "omnius.auth_webauthn.authentication.v1";
const OIDC_MODULE_ID: &str = "auth-oidc";
const MIN_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const MIN_CLEANUP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CLEANUP_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CLEANUP_BATCH_SIZE: u32 = 10_000;

/// Canonical authenticated resources shared by independently selected identity modules.
#[derive(Clone)]
pub struct OptionalIdentityContext {
    pool: PostgresPool,
    principal_state: CanonicalPrincipalState,
    browser_auth: BrowserAuthState,
    deployment: DeploymentEnvironment,
}

impl OptionalIdentityContext {
    pub(crate) const fn new(
        pool: PostgresPool,
        principal_state: CanonicalPrincipalState,
        browser_auth: BrowserAuthState,
        deployment: DeploymentEnvironment,
    ) -> Self {
        Self {
            pool,
            principal_state,
            browser_auth,
            deployment,
        }
    }
}

/// Strict bounds for the OIDC pending-authorization cleanup loop.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPendingCleanupConfig {
    /// Delay between bounded cleanup attempts.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Maximum expired rows deleted by one attempt.
    pub batch_size: u32,
    /// Maximum supervisor grace period for task shutdown.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

impl OidcPendingCleanupConfig {
    fn validate(&self) -> Result<(), OidcIdentityBuildError> {
        if !(MIN_CLEANUP_INTERVAL..=MAX_CLEANUP_INTERVAL).contains(&self.interval)
            || !(1..=MAX_CLEANUP_BATCH_SIZE).contains(&self.batch_size)
            || !(MIN_CLEANUP_SHUTDOWN_TIMEOUT..=MAX_CLEANUP_SHUTDOWN_TIMEOUT)
                .contains(&self.shutdown_timeout)
        {
            return Err(OidcIdentityBuildError::InvalidCleanupConfig);
        }
        Ok(())
    }
}

/// Resources required to compose upstream OIDC login and linking routes.
pub struct OidcIdentityInput {
    /// Canonical authenticated composition context.
    pub context: Option<OptionalIdentityContext>,
    /// Enabled upstream relying-party configuration.
    pub config: Option<OidcConfig>,
    /// Restricted outbound clients used for discovery and token exchange.
    pub outbound_http: Option<OutboundHttpClients>,
    /// Bounded pending-state cleanup policy.
    pub cleanup: Option<OidcPendingCleanupConfig>,
}

/// Resources required to compose protected passkey management routes.
pub struct WebAuthnIdentityInput {
    /// Canonical authenticated composition context.
    pub context: Option<OptionalIdentityContext>,
    /// Enabled exact-origin relying-party configuration.
    pub config: Option<WebAuthnConfig>,
}

/// Resources required to compose protected TOTP management routes.
pub struct TotpIdentityInput {
    /// Canonical authenticated composition context.
    pub context: Option<OptionalIdentityContext>,
    /// Enabled encrypted TOTP configuration.
    pub config: Option<TotpConfig>,
}

/// Router and exact catalog route evidence returned by a composition constructor.
pub struct IdentityRouteParts {
    /// Router containing only the selected optional module's routes.
    pub router: Router,
    /// Exact paths actually mounted by `router`.
    pub route_ids: &'static [&'static str],
}

/// Fully composed upstream OIDC routes and their separately registered cleanup task.
pub struct OidcIdentityComposition {
    router: Router,
    cleanup_task: TaskSpec,
}

impl OidcIdentityComposition {
    /// Returns a cloneable router containing only upstream OIDC relying-party routes.
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns exact paths mounted by this composition.
    #[must_use]
    pub const fn route_ids(&self) -> &'static [&'static str] {
        OIDC_ROUTE_IDS
    }

    /// Returns exact task identifiers owned by this composition.
    #[must_use]
    pub const fn task_ids(&self) -> &'static [&'static str] {
        OIDC_TASK_IDS
    }

    /// Consumes the composition into route evidence and its bounded cleanup task.
    #[must_use]
    pub fn into_parts(self) -> OidcIdentityParts {
        OidcIdentityParts {
            routes: IdentityRouteParts {
                router: self.router,
                route_ids: OIDC_ROUTE_IDS,
            },
            cleanup_task: self.cleanup_task,
            task_ids: OIDC_TASK_IDS,
        }
    }
}

/// Application lifecycle parts returned by [`OidcIdentityComposition::into_parts`].
pub struct OidcIdentityParts {
    /// Mounted upstream OIDC routes and exact route evidence.
    pub routes: IdentityRouteParts,
    /// Bounded pending-authorization cleanup task.
    pub cleanup_task: TaskSpec,
    /// Exact task identifiers represented by `cleanup_task`.
    pub task_ids: &'static [&'static str],
}

/// Fully composed protected passkey routes.
pub struct WebAuthnIdentityComposition {
    router: Router,
}

impl WebAuthnIdentityComposition {
    /// Returns a cloneable router containing only protected passkey routes.
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns exact paths mounted by this composition.
    #[must_use]
    pub const fn route_ids(&self) -> &'static [&'static str] {
        WEBAUTHN_ROUTE_IDS
    }

    /// Consumes the composition into its router and exact route evidence.
    #[must_use]
    pub fn into_parts(self) -> IdentityRouteParts {
        IdentityRouteParts {
            router: self.router,
            route_ids: WEBAUTHN_ROUTE_IDS,
        }
    }
}

/// Fully composed protected TOTP routes.
pub struct TotpIdentityComposition {
    router: Router,
}

impl TotpIdentityComposition {
    /// Returns a cloneable router containing only protected TOTP routes.
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns exact paths mounted by this composition.
    #[must_use]
    pub const fn route_ids(&self) -> &'static [&'static str] {
        TOTP_ROUTE_IDS
    }

    /// Consumes the composition into its router and exact route evidence.
    #[must_use]
    pub fn into_parts(self) -> IdentityRouteParts {
        IdentityRouteParts {
            router: self.router,
            route_ids: TOTP_ROUTE_IDS,
        }
    }
}

/// Stable upstream OIDC composition failures.
#[derive(Debug, Error)]
pub enum OidcIdentityBuildError {
    /// The canonical authenticated application stage was not supplied.
    #[error("OIDC composition requires the authenticated principal context")]
    MissingAuthenticatedContext,
    /// The strict OIDC relying-party configuration was not supplied.
    #[error("OIDC composition requires configuration")]
    MissingConfig,
    /// Restricted outbound HTTP clients were not supplied.
    #[error("OIDC composition requires outbound HTTP clients")]
    MissingOutboundHttp,
    /// Bounded pending-state cleanup policy was not supplied.
    #[error("OIDC composition requires pending-state cleanup configuration")]
    MissingCleanupConfig,
    /// Pending-state cleanup bounds are invalid.
    #[error("OIDC pending-state cleanup configuration is invalid")]
    InvalidCleanupConfig,
    /// Upstream provider state could not be initialized.
    #[error("OIDC relying-party construction failed: {0}")]
    Flow(#[from] OidcBuildError),
    /// Maintained browser-session layers could not be installed.
    #[error("OIDC browser-session composition failed: {0}")]
    BrowserSession(#[from] BrowserAuthBuildError),
    /// The cleanup task's stable service error code could not be constructed.
    #[error("OIDC pending-state cleanup error code is invalid")]
    CleanupErrorCode,
}

/// Stable protected passkey composition failures.
#[derive(Debug, Error)]
pub enum WebAuthnIdentityBuildError {
    /// The canonical authenticated application stage was not supplied.
    #[error("WebAuthn composition requires the authenticated principal context")]
    MissingAuthenticatedContext,
    /// Strict relying-party configuration was not supplied.
    #[error("WebAuthn composition requires configuration")]
    MissingConfig,
    /// The enabled WebAuthn service could not be built.
    #[error("WebAuthn service construction failed: {0}")]
    Service(#[from] WebAuthnServiceError),
    /// The canonical protected-principal boundary could not be installed.
    #[error("WebAuthn principal boundary construction failed: {0}")]
    Principal(#[from] AuthenticatedIdentityBuildError),
}

/// Stable protected TOTP composition failures.
#[derive(Debug, Error)]
pub enum TotpIdentityBuildError {
    /// The canonical authenticated application stage was not supplied.
    #[error("TOTP composition requires the authenticated principal context")]
    MissingAuthenticatedContext,
    /// Strict encrypted TOTP configuration was not supplied.
    #[error("TOTP composition requires configuration")]
    MissingConfig,
    /// The enabled TOTP store could not be built.
    #[error("TOTP store construction failed: {0}")]
    Store(#[from] TotpStoreError),
    /// The canonical protected-principal boundary could not be installed.
    #[error("TOTP principal boundary construction failed: {0}")]
    Principal(#[from] AuthenticatedIdentityBuildError),
}

/// Composes upstream OIDC start/callback routes and bounded pending-state cleanup.
///
/// # Errors
///
/// Returns [`OidcIdentityBuildError`] when required context, configuration, outbound clients,
/// provider discovery, browser-session layers, or cleanup bounds cannot be constructed.
pub async fn compose_oidc_identity(
    input: OidcIdentityInput,
) -> Result<OidcIdentityComposition, OidcIdentityBuildError> {
    let context = input
        .context
        .ok_or(OidcIdentityBuildError::MissingAuthenticatedContext)?;
    let config = input.config.ok_or(OidcIdentityBuildError::MissingConfig)?;
    let outbound_http = input
        .outbound_http
        .ok_or(OidcIdentityBuildError::MissingOutboundHttp)?;
    let cleanup = input
        .cleanup
        .ok_or(OidcIdentityBuildError::MissingCleanupConfig)?;
    cleanup.validate()?;

    let flow = OidcFlow::initialize(&config, context.deployment, outbound_http).await?;
    let redirect_uris = config
        .providers
        .iter()
        .map(|provider| (provider.provider_id.clone(), provider.redirect_uri.clone()))
        .collect();
    let pending_store = OidcPendingStore::new(context.pool.clone());
    let state = OidcHttpState {
        flow,
        pending_store: pending_store.clone(),
        identity_store: OidcIdentityStore::new(context.pool, &config),
        browser_auth: context.browser_auth.clone(),
        redirect_uris: Arc::new(redirect_uris),
    };
    let routes = Router::new()
        .route(OIDC_START_PATH, get(oidc_start))
        .route(OIDC_CALLBACK_PATH, get(oidc_callback))
        .with_state(state);
    let router = browser_session_router(&context.browser_auth, context.deployment, routes)?;
    let cleanup_task = oidc_pending_cleanup_task(pending_store, cleanup)?;

    Ok(OidcIdentityComposition {
        router,
        cleanup_task,
    })
}

/// Composes passkey management under the canonical protected-principal boundary.
///
/// # Errors
///
/// Returns [`WebAuthnIdentityBuildError`] when required context/configuration, the service, or
/// canonical session/principal middleware cannot be constructed.
pub fn compose_webauthn_identity(
    input: WebAuthnIdentityInput,
) -> Result<WebAuthnIdentityComposition, WebAuthnIdentityBuildError> {
    let context = input
        .context
        .ok_or(WebAuthnIdentityBuildError::MissingAuthenticatedContext)?;
    let config = input
        .config
        .ok_or(WebAuthnIdentityBuildError::MissingConfig)?;
    let state = WebAuthnHttpState {
        service: WebAuthnService::new(context.pool, &config, context.deployment)?,
    };
    let routes = Router::new()
        .route(PASSKEYS_PATH, get(list_passkeys).delete(disable_passkey))
        .route(
            PASSKEY_REGISTER_START_PATH,
            post(start_passkey_registration),
        )
        .route(
            PASSKEY_REGISTER_FINISH_PATH,
            post(finish_passkey_registration),
        )
        .route(
            PASSKEY_AUTHENTICATE_START_PATH,
            post(start_passkey_authentication),
        )
        .route(
            PASSKEY_AUTHENTICATE_FINISH_PATH,
            post(finish_passkey_authentication),
        )
        .with_state(state)
        .route_layer(middleware::from_fn(require_optional_principal));
    let router = protected_principal_router(context.principal_state, context.deployment, routes)?;
    Ok(WebAuthnIdentityComposition { router })
}

/// Composes TOTP enrollment, confirmation, and disablement under the protected-principal boundary.
///
/// # Errors
///
/// Returns [`TotpIdentityBuildError`] when required context/configuration, encrypted storage, or
/// canonical session/principal middleware cannot be constructed.
pub fn compose_totp_identity(
    input: TotpIdentityInput,
) -> Result<TotpIdentityComposition, TotpIdentityBuildError> {
    let context = input
        .context
        .ok_or(TotpIdentityBuildError::MissingAuthenticatedContext)?;
    let config = input.config.ok_or(TotpIdentityBuildError::MissingConfig)?;
    let state = TotpHttpState {
        store: TotpStore::new(context.pool, &config)?,
    };
    let routes = Router::new()
        .route(TOTP_ENROLL_PATH, post(enroll_totp))
        .route(TOTP_CONFIRM_PATH, post(confirm_totp))
        .route(TOTP_DISABLE_PATH, post(disable_totp))
        .with_state(state)
        .route_layer(middleware::from_fn(require_optional_principal));
    let router = protected_principal_router(context.principal_state, context.deployment, routes)?;
    Ok(TotpIdentityComposition { router })
}

#[derive(Clone)]
struct OidcHttpState {
    flow: OidcFlow,
    pending_store: OidcPendingStore,
    identity_store: OidcIdentityStore,
    browser_auth: BrowserAuthState,
    redirect_uris: Arc<BTreeMap<String, String>>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OidcStartPurpose {
    #[default]
    Login,
    Link,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcStartQuery {
    #[serde(default)]
    purpose: OidcStartPurpose,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OidcCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingOidcCallback {
    provider_id: String,
    redirect_uri: String,
    pending_id: PendingAuthorizationId,
}

async fn oidc_start(
    State(state): State<OidcHttpState>,
    Path(provider): Path<String>,
    Query(query): Query<OidcStartQuery>,
    request_id: Option<Extension<RequestId>>,
    mut auth: BrowserAuthSession,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    let redirect_uri = state
        .redirect_uris
        .get(&provider)
        .ok_or_else(|| IdentityHttpError::invalid_oidc(request_id))?;
    let start = match query.purpose {
        OidcStartPurpose::Login => state.flow.start_login(&provider),
        OidcStartPurpose::Link => {
            let active = require_active_session(&state.browser_auth, &mut auth)
                .await
                .map_err(|error| IdentityHttpError::browser_session(error, request_id))?;
            state.flow.start_link(&provider, &active.principal)
        }
    }
    .map_err(|error| IdentityHttpError::from_oidc_flow(error, request_id))?;
    let (authorization_url, pending_id) = state
        .pending_store
        .issue(start)
        .await
        .map_err(|error| IdentityHttpError::from_oidc_pending(error, request_id))?
        .into_parts();
    auth.session
        .insert(
            OIDC_PENDING_SESSION_KEY,
            PendingOidcCallback {
                provider_id: provider,
                redirect_uri: redirect_uri.clone(),
                pending_id,
            },
        )
        .await
        .map_err(|_| IdentityHttpError::internal(request_id))?;
    let mut response = Redirect::to(authorization_url.as_str()).into_response();
    set_no_store(&mut response);
    Ok(response)
}

async fn oidc_callback(
    State(state): State<OidcHttpState>,
    Path(provider): Path<String>,
    Query(query): Query<OidcCallbackQuery>,
    request_id: Option<Extension<RequestId>>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    let pending = auth
        .session
        .remove::<PendingOidcCallback>(OIDC_PENDING_SESSION_KEY)
        .await
        .map_err(|_| IdentityHttpError::internal(request_id))?
        .ok_or_else(|| IdentityHttpError::invalid_oidc(request_id))?;
    if pending.provider_id != provider {
        return Err(IdentityHttpError::invalid_oidc(request_id));
    }
    let taken = state
        .pending_store
        .take(pending.pending_id)
        .await
        .map_err(|error| IdentityHttpError::from_oidc_pending(error, request_id))?;
    let completed = state
        .flow
        .complete(
            taken,
            &provider,
            &pending.redirect_uri,
            &query.code,
            &query.state,
        )
        .await
        .map_err(|error| IdentityHttpError::from_oidc_flow(error, request_id))?;

    if let FlowPurpose::Link { subject_id, .. } = completed.purpose() {
        let active = require_active_session(&state.browser_auth, &mut auth)
            .await
            .map_err(|error| IdentityHttpError::browser_session(error, request_id))?;
        if &active.principal.subject_id != subject_id {
            return Err(IdentityHttpError::permission_denied(request_id));
        }
    }

    let outcome = state
        .identity_store
        .complete(completed)
        .await
        .map_err(|error| IdentityHttpError::from_oidc_store(error, request_id))?;
    if let AccountOutcome::Login(principal) = outcome {
        establish_browser_session(
            &state.browser_auth,
            &mut auth,
            principal.subject_id,
            &headers,
            request_id,
        )
        .await
        .map_err(IdentityHttpError::from)?;
    }
    Ok(no_content_response())
}

fn oidc_pending_cleanup_task(
    pending_store: OidcPendingStore,
    config: OidcPendingCleanupConfig,
) -> Result<TaskSpec, OidcIdentityBuildError> {
    let code = ErrorCode::try_new("OIDC_PENDING_CLEANUP_FAILED")
        .map_err(|_| OidcIdentityBuildError::CleanupErrorCode)?;
    Ok(TaskSpec::new(
        OIDC_PENDING_CLEANUP_TASK_ID,
        OIDC_MODULE_ID,
        Criticality::Degraded,
        config.shutdown_timeout,
        move |context| {
            let pending_store = pending_store.clone();
            async move {
                let mut interval = tokio::time::interval(config.interval);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = context.draining() => return Ok(()),
                        _ = interval.tick() => {
                            pending_store
                                .cleanup_expired(config.batch_size)
                                .await
                                .map_err(|error| ServiceError::new(code, "OIDC pending authorization cleanup failed").with_source(error))?;
                        }
                    }
                }
            }
        },
    )
    .with_restart_policy(RestartPolicy::on_failure(
        5,
        Duration::from_secs(1),
        Duration::from_secs(30),
        20,
    )))
}

#[derive(Clone)]
struct WebAuthnHttpState {
    service: WebAuthnService,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StartPasskeyRegistrationRequest {
    user_name: String,
    user_display_name: String,
    credential_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishPasskeyRegistrationRequest {
    ceremony_handle: CeremonyHandle,
    response: RegisterPublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishPasskeyAuthenticationRequest {
    ceremony_handle: CeremonyHandle,
    response: PublicKeyCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisablePasskeyRequest {
    credential_id: Uuid,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingPasskeyCeremony {
    subject_id: SubjectId,
    ceremony_handle: CeremonyHandle,
}

#[derive(Serialize)]
struct PasskeyListResponse {
    passkeys: Vec<PasskeyMetadataResponse>,
}

#[derive(Serialize)]
struct PasskeyMetadataResponse {
    id: Uuid,
    user_id: SubjectId,
    name: String,
    transports: Vec<String>,
    sign_count: u32,
    user_verified: bool,
    backup_eligible: bool,
    backup_state: bool,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    last_used_at: Option<OffsetDateTime>,
    disabled_at: Option<OffsetDateTime>,
}

impl From<PasskeyMetadata> for PasskeyMetadataResponse {
    fn from(metadata: PasskeyMetadata) -> Self {
        Self {
            id: metadata.id,
            user_id: metadata.user_id,
            name: metadata.name,
            transports: metadata.transports,
            sign_count: metadata.sign_count,
            user_verified: metadata.user_verified,
            backup_eligible: metadata.backup_eligible,
            backup_state: metadata.backup_state,
            created_at: metadata.created_at,
            updated_at: metadata.updated_at,
            last_used_at: metadata.last_used_at,
            disabled_at: metadata.disabled_at,
        }
    }
}

async fn list_passkeys(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let passkeys = state
        .service
        .list_credentials(principal.subject_id)
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?
        .into_iter()
        .map(PasskeyMetadataResponse::from)
        .collect();
    Ok(no_store_json(PasskeyListResponse { passkeys }))
}

async fn disable_passkey(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<DisablePasskeyRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    let metadata = state
        .service
        .disable_credential(&principal, payload.credential_id)
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?;
    Ok(no_store_json(PasskeyMetadataResponse::from(metadata)))
}

async fn start_passkey_registration(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<StartPasskeyRegistrationRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    let start = state
        .service
        .start_registration(
            &principal,
            &payload.user_name,
            &payload.user_display_name,
            &payload.credential_name,
        )
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?;
    auth.session
        .insert(
            PASSKEY_REGISTRATION_SESSION_KEY,
            PendingPasskeyCeremony {
                subject_id: principal.subject_id,
                ceremony_handle: start.ceremony_handle.clone(),
            },
        )
        .await
        .map_err(|_| IdentityHttpError::internal(request_id))?;
    Ok(no_store_json(start))
}

async fn finish_passkey_registration(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<FinishPasskeyRegistrationRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    take_passkey_ceremony(
        &auth,
        PASSKEY_REGISTRATION_SESSION_KEY,
        principal.subject_id,
        &payload.ceremony_handle,
        request_id,
    )
    .await?;
    let metadata = state
        .service
        .finish_registration(&payload.ceremony_handle, &payload.response)
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?;
    if metadata.user_id != principal.subject_id {
        return Err(IdentityHttpError::permission_denied(request_id));
    }
    Ok(no_store_json(PasskeyMetadataResponse::from(metadata)))
}

async fn start_passkey_authentication(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let start = state
        .service
        .start_authentication(principal.subject_id)
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?;
    auth.session
        .insert(
            PASSKEY_AUTHENTICATION_SESSION_KEY,
            PendingPasskeyCeremony {
                subject_id: principal.subject_id,
                ceremony_handle: start.ceremony_handle.clone(),
            },
        )
        .await
        .map_err(|_| IdentityHttpError::internal(request_id))?;
    Ok(no_store_json(start))
}

async fn finish_passkey_authentication(
    State(state): State<WebAuthnHttpState>,
    Extension(principal): Extension<Principal>,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<FinishPasskeyAuthenticationRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    take_passkey_ceremony(
        &auth,
        PASSKEY_AUTHENTICATION_SESSION_KEY,
        principal.subject_id,
        &payload.ceremony_handle,
        request_id,
    )
    .await?;
    let verified = state
        .service
        .finish_authentication(&payload.ceremony_handle, &payload.response)
        .await
        .map_err(|error| IdentityHttpError::from_webauthn(error, request_id))?;
    if verified.subject_id != principal.subject_id {
        return Err(IdentityHttpError::permission_denied(request_id));
    }
    Ok(no_content_response())
}

async fn take_passkey_ceremony(
    auth: &BrowserAuthSession,
    session_key: &str,
    subject_id: SubjectId,
    ceremony_handle: &CeremonyHandle,
    request_id: RequestId,
) -> Result<(), IdentityHttpError> {
    let pending = auth
        .session
        .remove::<PendingPasskeyCeremony>(session_key)
        .await
        .map_err(|_| IdentityHttpError::internal(request_id))?
        .ok_or_else(|| IdentityHttpError::invalid_passkey(request_id))?;
    if pending.subject_id != subject_id || &pending.ceremony_handle != ceremony_handle {
        return Err(IdentityHttpError::invalid_passkey(request_id));
    }
    Ok(())
}

#[derive(Clone)]
struct TotpHttpState {
    store: TotpStore,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollTotpRequest {
    account_name: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmTotpRequest {
    token: String,
}

#[derive(Serialize)]
struct EnrollTotpResponse {
    credential: TotpCredentialMetadataResponse,
    otpauth_uri: String,
}

#[derive(Serialize)]
struct ConfirmTotpResponse {
    credential: TotpCredentialMetadataResponse,
    recovery_codes: Vec<String>,
}

#[derive(Serialize)]
struct TotpCredentialMetadataResponse {
    id: Uuid,
    user_id: SubjectId,
    account_name: String,
    created_at: OffsetDateTime,
    confirmed_at: Option<OffsetDateTime>,
    locked_until: Option<OffsetDateTime>,
    disabled_at: Option<OffsetDateTime>,
}

impl From<TotpCredentialMetadata> for TotpCredentialMetadataResponse {
    fn from(metadata: TotpCredentialMetadata) -> Self {
        Self {
            id: metadata.id,
            user_id: metadata.user_id,
            account_name: metadata.account_name,
            created_at: metadata.created_at,
            confirmed_at: metadata.confirmed_at,
            locked_until: metadata.locked_until,
            disabled_at: metadata.disabled_at,
        }
    }
}

async fn enroll_totp(
    State(state): State<TotpHttpState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<EnrollTotpRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    let pending = state
        .store
        .enroll(&principal, &payload.account_name)
        .await
        .map_err(|error| IdentityHttpError::from_totp(error, request_id))?;
    Ok(no_store_json(enrollment_response(pending)))
}

async fn confirm_totp(
    State(state): State<TotpHttpState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
    payload: Result<Json<ConfirmTotpRequest>, JsonRejection>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let Json(payload) =
        payload.map_err(|error| IdentityHttpError(map_json_rejection(&error, request_id)))?;
    let confirmed = state
        .store
        .confirm(&principal, &payload.token)
        .await
        .map_err(|error| IdentityHttpError::from_totp(error, request_id))?;
    Ok(no_store_json(confirmation_response(confirmed)))
}

async fn disable_totp(
    State(state): State<TotpHttpState>,
    Extension(principal): Extension<Principal>,
    request_id: Option<Extension<RequestId>>,
) -> Result<Response, IdentityHttpError> {
    let request_id = resolve_request_id(request_id);
    require_human_principal(&principal, request_id)?;
    let metadata = state
        .store
        .disable(&principal)
        .await
        .map_err(|error| IdentityHttpError::from_totp(error, request_id))?;
    Ok(no_store_json(TotpCredentialMetadataResponse::from(
        metadata,
    )))
}

fn enrollment_response(pending: PendingTotpEnrollment) -> EnrollTotpResponse {
    let credential = pending.metadata().clone().into();
    let otpauth_uri = pending.expose_once();
    EnrollTotpResponse {
        credential,
        otpauth_uri: otpauth_uri.expose_secret().to_owned(),
    }
}

fn confirmation_response(confirmed: ConfirmedTotpEnrollment) -> ConfirmTotpResponse {
    let credential = confirmed.metadata().clone().into();
    let recovery_codes = confirmed
        .expose_recovery_codes_once()
        .into_iter()
        .map(|code| code.expose_secret().to_owned())
        .collect();
    ConfirmTotpResponse {
        credential,
        recovery_codes,
    }
}

fn require_human_principal(
    principal: &Principal,
    request_id: RequestId,
) -> Result<(), IdentityHttpError> {
    if principal.kind != PrincipalKind::User {
        return Err(IdentityHttpError::permission_denied(request_id));
    }
    Ok(())
}

async fn require_optional_principal(request: Request, next: Next) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    if request.extensions().get::<Principal>().is_none() {
        return IdentityHttpError::authentication_required(request_id).into_response();
    }
    next.run(request).await
}

#[derive(Debug)]
struct IdentityHttpError(ApiError);

impl IdentityHttpError {
    const fn invalid_oidc(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "OIDC_REQUEST_REJECTED",
            "the OIDC authorization request was rejected",
            request_id,
        ))
    }

    const fn authentication_required(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "a valid recently authenticated user principal is required",
            request_id,
        ))
    }

    const fn invalid_passkey(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::BAD_REQUEST,
            "PASSKEY_REQUEST_REJECTED",
            "the passkey request was rejected",
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

    const fn conflict(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::CONFLICT,
            "IDENTITY_STATE_CONFLICT",
            "identity state conflicts with the requested operation",
            request_id,
        ))
    }

    const fn unavailable(request_id: RequestId) -> Self {
        Self(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "IDENTITY_CAPABILITY_UNAVAILABLE",
            "identity capability is temporarily unavailable",
            request_id,
        ))
    }

    const fn internal(request_id: RequestId) -> Self {
        Self(ApiError::internal(request_id))
    }

    const fn browser_session(
        error: crate::browser_auth::BrowserSessionError,
        request_id: RequestId,
    ) -> Self {
        match error {
            crate::browser_auth::BrowserSessionError::Missing
            | crate::browser_auth::BrowserSessionError::RevokedOrExpired => {
                Self::authentication_required(request_id)
            }
            crate::browser_auth::BrowserSessionError::Unavailable => Self::unavailable(request_id),
            crate::browser_auth::BrowserSessionError::SessionData => Self::internal(request_id),
        }
    }

    const fn from_oidc_flow(error: OidcFlowError, request_id: RequestId) -> Self {
        match error {
            OidcFlowError::UnknownProvider
            | OidcFlowError::MalformedCallback
            | OidcFlowError::ContextMismatch
            | OidcFlowError::StateMismatch
            | OidcFlowError::Expired
            | OidcFlowError::MissingIdToken
            | OidcFlowError::IdTokenRejected => Self::invalid_oidc(request_id),
            OidcFlowError::LinkProofRequired => Self::authentication_required(request_id),
            OidcFlowError::ProviderMetadataRejected
            | OidcFlowError::TokenExchangeFailed
            | OidcFlowError::ProviderRefreshUnavailable => Self::unavailable(request_id),
            OidcFlowError::InternalState => Self::internal(request_id),
        }
    }

    const fn from_oidc_pending(error: OidcPendingStoreError, request_id: RequestId) -> Self {
        match error {
            OidcPendingStoreError::UnavailableAuthorization
            | OidcPendingStoreError::ExpiredAuthorization => Self::invalid_oidc(request_id),
            OidcPendingStoreError::Unavailable | OidcPendingStoreError::Transient(_) => {
                Self::unavailable(request_id)
            }
            OidcPendingStoreError::InvalidAuthorization
            | OidcPendingStoreError::CorruptAuthorization
            | OidcPendingStoreError::InvalidCleanupBatch => Self::internal(request_id),
            _ => Self::internal(request_id),
        }
    }

    const fn from_oidc_store(error: OidcStoreError, request_id: RequestId) -> Self {
        match error {
            OidcStoreError::Unavailable | OidcStoreError::Transient(_) => {
                Self::unavailable(request_id)
            }
            OidcStoreError::Conflict
            | OidcStoreError::IdentityConflict
            | OidcStoreError::LastRecoveryMethod => Self::conflict(request_id),
            OidcStoreError::UserNotFound
            | OidcStoreError::IdentityNotLinked
            | OidcStoreError::RecentAuthenticationRequired => {
                Self::authentication_required(request_id)
            }
            OidcStoreError::InvalidIdentity => Self::invalid_oidc(request_id),
            OidcStoreError::CorruptData => Self::internal(request_id),
            _ => Self::internal(request_id),
        }
    }

    const fn from_webauthn(error: WebAuthnServiceError, request_id: RequestId) -> Self {
        match error {
            WebAuthnServiceError::RecentAuthenticationRequired => {
                Self::authentication_required(request_id)
            }
            WebAuthnServiceError::CredentialNotFound | WebAuthnServiceError::UserNotFound => {
                Self(ApiError::new(
                    StatusCode::NOT_FOUND,
                    "PASSKEY_NOT_FOUND",
                    "the requested passkey resource was not found",
                    request_id,
                ))
            }
            WebAuthnServiceError::Conflict
            | WebAuthnServiceError::CredentialLimitReached
            | WebAuthnServiceError::CounterReplay => Self::conflict(request_id),
            WebAuthnServiceError::InvalidName
            | WebAuthnServiceError::CeremonyNotFound
            | WebAuthnServiceError::CeremonyExpired
            | WebAuthnServiceError::CeremonyCapacityReached
            | WebAuthnServiceError::WrongCeremonyType
            | WebAuthnServiceError::NoActiveCredentials
            | WebAuthnServiceError::VerificationFailed => Self(ApiError::new(
                StatusCode::BAD_REQUEST,
                "PASSKEY_REQUEST_REJECTED",
                "the passkey request was rejected",
                request_id,
            )),
            WebAuthnServiceError::Unavailable | WebAuthnServiceError::Transient(_) => {
                Self::unavailable(request_id)
            }
            WebAuthnServiceError::Disabled
            | WebAuthnServiceError::InvalidConfiguration
            | WebAuthnServiceError::CeremonyHandleCollision
            | WebAuthnServiceError::CorruptData => Self::internal(request_id),
            _ => Self::internal(request_id),
        }
    }

    const fn from_totp(error: TotpStoreError, request_id: RequestId) -> Self {
        match error {
            TotpStoreError::InvalidPrincipal | TotpStoreError::RecentAuthenticationRequired => {
                Self::authentication_required(request_id)
            }
            TotpStoreError::InvalidAccountName | TotpStoreError::VerificationFailed => {
                Self(ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "TOTP_REQUEST_REJECTED",
                    "the TOTP request was rejected",
                    request_id,
                ))
            }
            TotpStoreError::AlreadyEnrolled
            | TotpStoreError::NotEnrolled
            | TotpStoreError::AlreadyConfirmed
            | TotpStoreError::Locked
            | TotpStoreError::Conflict => Self::conflict(request_id),
            TotpStoreError::WorkerUnavailable
            | TotpStoreError::Unavailable
            | TotpStoreError::Transient(_) => Self::unavailable(request_id),
            TotpStoreError::Disabled
            | TotpStoreError::InvalidConfiguration
            | TotpStoreError::EntropyUnavailable
            | TotpStoreError::Cryptography
            | TotpStoreError::InvalidIdentifier
            | TotpStoreError::CorruptData => Self::internal(request_id),
            _ => Self::internal(request_id),
        }
    }
}

impl From<BrowserHttpError> for IdentityHttpError {
    fn from(error: BrowserHttpError) -> Self {
        Self(error.0)
    }
}

impl axum::response::IntoResponse for IdentityHttpError {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

fn no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    set_no_store(&mut response);
    response
}

fn no_store_json(value: impl Serialize) -> Response {
    let mut response = Json(value).into_response();
    set_no_store(&mut response);
    response
}

fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use axum::{body::Body, http::Request, routing::get};
    use tower::ServiceExt as _;

    use super::*;

    #[test]
    fn constructors_publish_exact_catalog_route_and_task_ids() {
        assert_eq!(OIDC_ROUTE_IDS, &[OIDC_START_PATH, OIDC_CALLBACK_PATH]);
        assert_eq!(
            WEBAUTHN_ROUTE_IDS,
            &[
                PASSKEYS_PATH,
                PASSKEY_REGISTER_START_PATH,
                PASSKEY_REGISTER_FINISH_PATH,
                PASSKEY_AUTHENTICATE_START_PATH,
                PASSKEY_AUTHENTICATE_FINISH_PATH,
            ]
        );
        assert_eq!(
            TOTP_ROUTE_IDS,
            &[TOTP_ENROLL_PATH, TOTP_CONFIRM_PATH, TOTP_DISABLE_PATH]
        );
        assert_eq!(OIDC_TASK_IDS, &[OIDC_PENDING_CLEANUP_TASK_ID]);
    }

    #[tokio::test]
    async fn passkey_and_totp_routes_reject_missing_principal() -> Result<(), Box<dyn Error>> {
        let app = Router::new()
            .route(PASSKEYS_PATH, get(StatusCode::OK))
            .route(TOTP_ENROLL_PATH, post(StatusCode::OK))
            .route_layer(middleware::from_fn(require_optional_principal));

        let passkey = app
            .clone()
            .oneshot(Request::get(PASSKEYS_PATH).body(Body::empty())?)
            .await?;
        assert_eq!(passkey.status(), StatusCode::UNAUTHORIZED);

        let totp = app
            .oneshot(Request::post(TOTP_ENROLL_PATH).body(Body::empty())?)
            .await?;
        assert_eq!(totp.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[test]
    fn oidc_cleanup_policy_is_bounded() {
        let valid = OidcPendingCleanupConfig {
            interval: MIN_CLEANUP_INTERVAL,
            batch_size: 1,
            shutdown_timeout: MIN_CLEANUP_SHUTDOWN_TIMEOUT,
        };
        assert!(valid.validate().is_ok());

        for invalid in [
            OidcPendingCleanupConfig {
                batch_size: 0,
                ..valid.clone()
            },
            OidcPendingCleanupConfig {
                interval: Duration::ZERO,
                ..valid.clone()
            },
            OidcPendingCleanupConfig {
                shutdown_timeout: MAX_CLEANUP_SHUTDOWN_TIMEOUT + Duration::from_secs(1),
                ..valid
            },
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(OidcIdentityBuildError::InvalidCleanupConfig)
            ));
        }
    }

    #[test]
    fn upstream_oidc_evidence_is_disjoint_from_hosted_provider() {
        assert_eq!(OIDC_MODULE_ID, "auth-oidc");
        assert_ne!(OIDC_MODULE_ID, "auth-oauth-server");
        assert!(OIDC_ROUTE_IDS.iter().all(|path| {
            path.starts_with("/auth/oidc/")
                && !path.starts_with("/oauth/")
                && !path.starts_with("/.well-known/")
        }));
    }

    #[test]
    fn base_contract_omits_unselected_optional_identity_routes() -> Result<(), Box<dyn Error>> {
        let document = String::from_utf8(crate::openapi_json()?)?;
        for path in OIDC_ROUTE_IDS
            .iter()
            .chain(WEBAUTHN_ROUTE_IDS)
            .chain(TOTP_ROUTE_IDS)
        {
            assert!(!document.contains(path));
        }
        Ok(())
    }
}
