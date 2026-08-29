//! Axum transport adapter for the first-party OAuth Authorization Server and `OpenID` Provider.
#![expect(
    missing_docs,
    reason = "Axum handlers and schema carriers are documented by their source OpenAPI annotations"
)]

use std::{
    collections::BTreeMap, future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration,
};

use axum::{
    Extension, Json, Router,
    body::{Body, Bytes, to_bytes},
    extract::{ConnectInfo, Path, RawQuery, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use axum_login::{AuthManagerLayerBuilder, AuthSession};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use omnius_audit::{
    AuditActor, AuditConfig, AuditEvent, AuditOutcome, AuditResourceId, AuditScope,
    PostgresAuditSink, SecurityEventName,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId};
use omnius_auth_oauth_server::{
    AccessTokenVerificationError, AccessTokenVerifier, AuthorizationCodeTokenRequest,
    AuthorizationRedirect, AuthorizationRequestInput, AuthorizationRequestParts,
    AuthorizationServer, AuthorizedBrowserSession, BeginAuthorizationResult, ClientAuthentication,
    ClientAuthenticationParts, ClientId, ClientMetadata, ConsentDecision, GrantId, IdTokenHint,
    IssuerUri, LogoutRequest, LogoutSession, OAuthAuditError, OAuthAuditEvent, OAuthAuditSink,
    OAuthErrorCode, OAuthSessionAuthority, OsEntropy, PkceChallenge, PkceVerifier,
    PostgresAdapterConfigError, PostgresOAuthAdapter, PostgresOAuthAdapterInput,
    PrivateKeyJwtAssertion, Prompt, ProtocolError, RedirectUri, RefreshTokenRequest, ResourceUri,
    ResponseMode, ResponseType, RevocationRequest, SessionAuthorityError, SessionCandidate,
    SystemClock, TokenEndpointAuthMethod, TokenRequest, TokenTypeHint,
    ValidatedAuthorizationServerConfig,
};
use omnius_auth_oauth_server::{
    ClientMetadataResolver, cleanup::OAuthCleanup, store::OAuthPostgresStore,
};
use omnius_auth_session_postgres::{
    SessionBackend, SessionGuardError, SessionRevocationGuard, guard_revoked_session,
    session_manager_layer,
};
use omnius_authz_basic::{Action, ResourceKind};
use omnius_config::DeploymentEnvironment;
use omnius_core::{Clock as _, ErrorCode, RequestId, ServiceError};
use omnius_http::ProblemDetails;
use omnius_outbound_http::OutboundHttpClients;
use omnius_postgres::PostgresPool;
use omnius_rate_limit_local::{LocalRateLimiter, RateLimitClientId, TrustedRateLimitContext};
use omnius_runtime::{Criticality, RestartPolicy, TaskSpec};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use crate::{
    ProblemDetailsSchema,
    browser_auth::{BrowserAuthState, BrowserSessionError, require_active_session},
    resolve_request_id,
};

pub const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OPENID_CONFIGURATION_PATH: &str = "/.well-known/openid-configuration";
pub const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";
pub const OAUTH_JWKS_PATH: &str = "/oauth/jwks.json";
pub const OAUTH_AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const OAUTH_INTERACTION_PATH: &str = "/oauth/authorize/interaction";
pub const OAUTH_DECISION_PATH: &str = "/oauth/authorize/decision";
pub const OAUTH_TOKEN_PATH: &str = "/oauth/token";
pub const OAUTH_REGISTER_PATH: &str = "/oauth/register";
pub const OAUTH_REVOKE_PATH: &str = "/oauth/revoke";
pub const OAUTH_GRANTS_PATH: &str = "/oauth/grants";
pub const OAUTH_GRANT_PATH: &str = "/oauth/grants/{grant_id}";
pub const OAUTH_USERINFO_PATH: &str = "/oauth/userinfo";
pub const OAUTH_LOGOUT_PATH: &str = "/oauth/logout";

const DISCOVERY_CACHE_CONTROL: &str = "public, max-age=300, immutable";
const JWKS_CACHE_CONTROL: &str = "public, max-age=300, immutable";
const NO_STORE: &str = "no-store";
const MAX_FORM_BYTES: usize = 64 * 1024;
const MAX_BASIC_BYTES: usize = 4 * 1024;
const MAX_CLEANUP_BATCH: u32 = 1_000;
const OAUTH_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const OAUTH_CLEANUP_SHUTDOWN: Duration = Duration::from_secs(5);

type BrowserAuthSession = AuthSession<SessionBackend>;
pub type OAuthAdapter = PostgresOAuthAdapter<
    SystemClock,
    OsEntropy,
    OAuthAuditBridge,
    OAuthSessionAuthorityBridge,
    ClientMetadataResolver,
>;
type OAuthService = AuthorizationServer<OAuthAdapter, SystemClock, OsEntropy>;
type LocalVerifier = AccessTokenVerifier<OAuthAdapter, SystemClock>;

#[derive(Clone)]
pub struct OAuthProviderState {
    service: Arc<OAuthService>,
    adapter: Arc<OAuthAdapter>,
    browser_auth: BrowserAuthState,
    authorization_ui: Url,
    max_client_metadata_bytes: usize,
    max_authorization_request_bytes: usize,
    root_resource: ResourceUri,
}

#[derive(Clone)]
pub struct OAuthResourceTokenVerifier {
    verifier: Arc<LocalVerifier>,
}

impl OAuthResourceTokenVerifier {
    /// Verifies an issuer-local access token and returns its canonical principal.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthResourceVerifyError::Rejected`] for invalid or inactive tokens and
    /// [`OAuthResourceVerifyError::Unavailable`] when live token state cannot be checked.
    pub async fn verify(&self, token: &str) -> Result<Principal, OAuthResourceVerifyError> {
        self.verifier
            .verify(token)
            .await
            .map(|verified| verified.principal)
            .map_err(|error| match error {
                AccessTokenVerificationError::StoreUnavailable => {
                    OAuthResourceVerifyError::Unavailable
                }
                AccessTokenVerificationError::InvalidToken
                | AccessTokenVerificationError::Inactive => OAuthResourceVerifyError::Rejected,
            })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthResourceVerifyError {
    Rejected,
    Unavailable,
}

pub struct OAuthProviderRuntime {
    pub routes: Router,
    pub resource_verifier: OAuthResourceTokenVerifier,
    pub cleanup_task: TaskSpec,
    pub adapter: Arc<OAuthAdapter>,
}

pub struct OAuthProviderBuildInput {
    pub config: ValidatedAuthorizationServerConfig,
    pub pool: PostgresPool,
    pub outbound_http: Arc<OutboundHttpClients>,
    pub session_config: omnius_auth_core::SessionConfig,
    pub browser_auth: BrowserAuthState,
    pub local_identity_provider: String,
    pub authorization_ui: Url,
    pub deployment: DeploymentEnvironment,
    pub rate_limits: OAuthRateLimiters,
}

pub struct OAuthAdminAdapterInput {
    pub config: Arc<ValidatedAuthorizationServerConfig>,
    pub pool: PostgresPool,
    pub outbound_http: Arc<OutboundHttpClients>,
    pub session_config: omnius_auth_core::SessionConfig,
    pub local_identity_provider: String,
}

/// Builds the OAuth adapter used by administrative client-management commands.
///
/// # Errors
///
/// Returns [`OAuthProviderBuildError`] when client metadata resolution or the PostgreSQL
/// adapter cannot be configured.
pub fn build_oauth_admin_adapter(
    input: OAuthAdminAdapterInput,
) -> Result<Arc<OAuthAdapter>, OAuthProviderBuildError> {
    let clock = Arc::new(SystemClock);
    let entropy = Arc::new(OsEntropy);
    let resolver = Arc::new(
        ClientMetadataResolver::new(
            input.outbound_http,
            Arc::clone(&clock) as Arc<dyn omnius_auth_oauth_server::Clock>,
            &input.config,
            16,
        )
        .map_err(|_| OAuthProviderBuildError::ClientMetadata)?,
    );
    let audit = Arc::new(OAuthAuditBridge::new(Arc::clone(&clock)));
    let sessions = Arc::new(OAuthSessionAuthorityBridge::new(
        input.pool.clone(),
        input.session_config,
    ));
    Ok(Arc::new(PostgresOAuthAdapter::new(
        PostgresOAuthAdapterInput {
            store: OAuthPostgresStore::new(input.pool),
            pepper: input.config.token_pepper().clone(),
            issuer: input.config.issuer().clone(),
            client_metadata: resolver,
            dynamic_client_registration_enabled: input.config.dynamic_client_registration(),
            local_identity_provider: input.local_identity_provider,
            clock,
            entropy,
            audit,
            sessions,
        },
    )?))
}

#[derive(Clone)]
pub struct OAuthRateLimiters {
    pub authorize: LocalRateLimiter,
    pub token: LocalRateLimiter,
    pub register: LocalRateLimiter,
    pub revoke: LocalRateLimiter,
}
#[derive(Clone, Copy)]
struct OAuthRateLimitMiddlewareState {
    max_authorization_request_bytes: usize,
}

#[derive(Debug, Error)]
pub enum OAuthProviderBuildError {
    #[error("OAuth PostgreSQL adapter configuration is invalid")]
    Adapter(#[from] PostgresAdapterConfigError),
    #[error("OAuth client metadata resolver configuration is invalid")]
    ClientMetadata,
    #[error("OAuth root resource must exactly equal the issuer")]
    RootResource,
    #[error("OAuth browser session layer configuration is invalid")]
    Session(#[from] omnius_auth_core::SessionConfigError),
    #[error("OAuth browser session revocation guard is invalid")]
    SessionGuard(#[from] SessionGuardError),
    #[error("OAuth local access-token verifier configuration is invalid")]
    Verifier,
    #[error("OAuth authorization UI URL is invalid")]
    AuthorizationUi,
    #[error("OAuth cleanup task error code is invalid")]
    CleanupCode,
}

/// Builds the complete OAuth/OIDC HTTP runtime.
///
/// # Errors
///
/// Returns [`OAuthProviderBuildError`] when the configured resource, adapter, verifier,
/// browser-session layers, authorization UI, or cleanup task cannot be constructed.
pub fn build_oauth_provider(
    input: OAuthProviderBuildInput,
) -> Result<OAuthProviderRuntime, OAuthProviderBuildError> {
    let OAuthProviderBuildInput {
        config,
        pool,
        outbound_http,
        session_config,
        browser_auth,
        local_identity_provider,
        authorization_ui,
        deployment,
        rate_limits,
    } = input;
    let (root_resource, allowed_scopes) = oauth_root_resource(&config)?;
    let clock = Arc::new(SystemClock);
    let entropy = Arc::new(OsEntropy);
    let config = Arc::new(config);
    let resolver = Arc::new(
        ClientMetadataResolver::new(
            outbound_http,
            Arc::clone(&clock) as Arc<dyn omnius_auth_oauth_server::Clock>,
            &config,
            16,
        )
        .map_err(|_| OAuthProviderBuildError::ClientMetadata)?,
    );
    let audit = Arc::new(OAuthAuditBridge::new(Arc::clone(&clock)));
    let sessions = Arc::new(OAuthSessionAuthorityBridge::new(
        pool.clone(),
        session_config.clone(),
    ));
    let adapter = Arc::new(PostgresOAuthAdapter::new(PostgresOAuthAdapterInput {
        store: OAuthPostgresStore::new(pool.clone()),
        pepper: config.token_pepper().clone(),
        issuer: config.issuer().clone(),
        client_metadata: resolver,
        dynamic_client_registration_enabled: config.dynamic_client_registration(),
        local_identity_provider,
        clock: Arc::clone(&clock),
        entropy: Arc::clone(&entropy),
        audit,
        sessions,
    })?);
    let service = Arc::new(AuthorizationServer::new(
        Arc::clone(&config),
        Arc::clone(&adapter),
        Arc::clone(&clock),
        Arc::clone(&entropy),
    ));
    let verifier = AccessTokenVerifier::new(
        Arc::new(config.signing_keys().clone()),
        config.issuer().clone(),
        root_resource.clone(),
        allowed_scopes,
        Arc::clone(&adapter),
        Arc::clone(&clock),
    )
    .map_err(|_| OAuthProviderBuildError::Verifier)?;
    let state = OAuthProviderState {
        service,
        adapter: Arc::clone(&adapter),
        browser_auth,
        authorization_ui: oauth_authorization_ui(authorization_ui)?,
        max_authorization_request_bytes: config.max_authorization_request_bytes(),
        max_client_metadata_bytes: config.max_client_metadata_bytes(),
        root_resource,
    };
    let routes = oauth_provider_router(
        state,
        &pool,
        &session_config,
        deployment,
        config.dynamic_client_registration(),
        &rate_limits,
    )?;
    Ok(OAuthProviderRuntime {
        routes,
        resource_verifier: OAuthResourceTokenVerifier {
            verifier: Arc::new(verifier),
        },
        cleanup_task: oauth_cleanup_task(OAuthCleanup::new(pool))?,
        adapter,
    })
}

fn oauth_root_resource(
    config: &ValidatedAuthorizationServerConfig,
) -> Result<(ResourceUri, Vec<Scope>), OAuthProviderBuildError> {
    let root_resource = config
        .resources()
        .iter()
        .find(|resource| resource.uri().as_str() == config.issuer().as_str())
        .ok_or(OAuthProviderBuildError::RootResource)?;
    let mut allowed_scopes = root_resource
        .scopes()
        .iter()
        .map(|scope| scope.name().clone())
        .collect::<Vec<_>>();
    for scope in ["openid", "email", "offline_access"] {
        allowed_scopes
            .push(Scope::new(scope.to_owned()).map_err(|_| OAuthProviderBuildError::Verifier)?);
    }
    allowed_scopes.sort_unstable();
    allowed_scopes.dedup();
    Ok((root_resource.uri().clone(), allowed_scopes))
}

fn oauth_authorization_ui(mut authorization_ui: Url) -> Result<Url, OAuthProviderBuildError> {
    let mut segments = authorization_ui
        .path_segments_mut()
        .map_err(|()| OAuthProviderBuildError::AuthorizationUi)?;
    segments.pop_if_empty().push("authorize");
    drop(segments);
    Ok(authorization_ui)
}

fn oauth_provider_router(
    state: OAuthProviderState,
    pool: &PostgresPool,
    session_config: &omnius_auth_core::SessionConfig,
    deployment: DeploymentEnvironment,
    dcr_enabled: bool,
    rate_limits: &OAuthRateLimiters,
) -> Result<Router, OAuthProviderBuildError> {
    let max_authorization_request_bytes = state.max_authorization_request_bytes;
    let discovery = Router::new()
        .route(
            AUTHORIZATION_SERVER_METADATA_PATH,
            get(authorization_server_metadata),
        )
        .route(OPENID_CONFIGURATION_PATH, get(openid_configuration))
        .route(
            PROTECTED_RESOURCE_METADATA_PATH,
            get(protected_resource_metadata),
        )
        .route(OAUTH_JWKS_PATH, get(jwks));

    let authorize = with_rate_limit(
        Router::new().route(OAUTH_AUTHORIZE_PATH, get(authorize)),
        &rate_limits.authorize,
        max_authorization_request_bytes,
    );
    let browser_routes = authorize
        .route(OAUTH_INTERACTION_PATH, get(interaction))
        .route(OAUTH_DECISION_PATH, post(decision))
        .route(OAUTH_GRANTS_PATH, get(grants))
        .route(OAUTH_GRANT_PATH, delete(revoke_grant))
        .route(OAUTH_LOGOUT_PATH, get(logout_get).post(logout_post));
    let auth_layer = AuthManagerLayerBuilder::new(
        SessionBackend::new(pool.clone()),
        session_manager_layer(pool, session_config, deployment)?,
    )
    .build();
    let guard = SessionRevocationGuard::new(pool.clone(), session_config)?;
    let browser_routes = browser_routes
        .layer(auth_layer)
        .layer(middleware::from_fn_with_state(guard, guard_revoked_session));

    let mut machine_routes = with_rate_limit(
        Router::new().route(OAUTH_TOKEN_PATH, post(token)),
        &rate_limits.token,
        max_authorization_request_bytes,
    )
    .merge(with_rate_limit(
        Router::new().route(OAUTH_REVOKE_PATH, post(revoke)),
        &rate_limits.revoke,
        max_authorization_request_bytes,
    ))
    .route(OAUTH_USERINFO_PATH, get(userinfo_get).post(userinfo_post));
    if dcr_enabled {
        machine_routes = machine_routes.merge(with_rate_limit(
            Router::new().route(OAUTH_REGISTER_PATH, post(register)),
            &rate_limits.register,
            max_authorization_request_bytes,
        ));
    }
    Ok(discovery
        .merge(browser_routes)
        .merge(machine_routes)
        .with_state(state))
}

fn with_rate_limit(
    router: Router<OAuthProviderState>,
    limiter: &LocalRateLimiter,
    max_authorization_request_bytes: usize,
) -> Router<OAuthProviderState> {
    limiter.apply(router).layer(middleware::from_fn_with_state(
        OAuthRateLimitMiddlewareState {
            max_authorization_request_bytes,
        },
        insert_trusted_rate_limit_context,
    ))
}

async fn insert_trusted_rate_limit_context(
    State(state): State<OAuthRateLimitMiddlewareState>,
    request: Request,
    next: Next,
) -> Response {
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or_else(|| std::net::Ipv4Addr::LOCALHOST.into(), |peer| peer.0.ip());
    let query_client_id = request
        .uri()
        .query()
        .filter(|query| query.len() <= state.max_authorization_request_bytes)
        .and_then(|query| parse_unique_form(query.as_bytes()).ok())
        .and_then(|fields| fields.get("client_id").cloned());
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    let (parts, body) = request.into_parts();
    let (request, form_client_id) = if is_form_content_type(&parts.headers) {
        let Ok(bytes) = to_bytes(body, MAX_FORM_BYTES).await else {
            return problem_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                request_id,
                "OAuth form body exceeds its configured limit",
            );
        };
        let client_id = parse_unique_form(&bytes)
            .ok()
            .and_then(|fields| fields.get("client_id").cloned())
            .or_else(|| basic_rate_limit_client_id(&parts.headers));
        (Request::from_parts(parts, Body::from(bytes)), client_id)
    } else {
        (Request::from_parts(parts, body), None)
    };
    let mut context = TrustedRateLimitContext::new(ip);
    if let Some(client_id) = query_client_id.or(form_client_id)
        && let Ok(client_id) = ClientId::parse(client_id)
        && let Ok(client_id) = RateLimitClientId::new(client_id.as_str())
    {
        context = context.with_oauth_client_id(client_id);
    }
    let mut request = request;
    request.extensions_mut().insert(context);
    next.run(request).await
}

fn basic_rate_limit_client_id(headers: &HeaderMap) -> Option<String> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    if encoded.is_empty() || encoded.len() > MAX_BASIC_BYTES {
        return None;
    }
    let decoded = STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (client_id, _) = decoded.split_once(':')?;
    decode_form_component(client_id)
}

#[utoipa::path(get, path = "/.well-known/oauth-authorization-server", operation_id = "oauth.discovery.authorization-server", tag = "oauth", responses((status = 200, body = serde_json::Value), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn authorization_server_metadata(State(state): State<OAuthProviderState>) -> Response {
    cached_json(
        state.service.authorization_server_metadata(),
        DISCOVERY_CACHE_CONTROL,
    )
}

#[utoipa::path(get, path = "/.well-known/openid-configuration", operation_id = "oidc.discovery", tag = "openid", responses((status = 200, body = serde_json::Value), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn openid_configuration(State(state): State<OAuthProviderState>) -> Response {
    cached_json(
        state.service.openid_provider_metadata(),
        DISCOVERY_CACHE_CONTROL,
    )
}

#[utoipa::path(get, path = "/.well-known/oauth-protected-resource", operation_id = "oauth.discovery.protected-resource", tag = "oauth", responses((status = 200, body = serde_json::Value), (status = 404, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn protected_resource_metadata(State(state): State<OAuthProviderState>) -> Response {
    match state
        .service
        .protected_resource_metadata(state.root_resource.as_str())
    {
        Some(metadata) => cached_json(metadata, DISCOVERY_CACHE_CONTROL),
        None => problem_response(
            StatusCode::NOT_FOUND,
            RequestId::new(),
            "OAuth resource metadata is unavailable",
        ),
    }
}

#[utoipa::path(get, path = "/oauth/jwks.json", operation_id = "oauth.jwks", tag = "oauth", responses((status = 200, body = serde_json::Value), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn jwks(State(state): State<OAuthProviderState>) -> Response {
    cached_json(&state.service.jwks(), JWKS_CACHE_CONTROL)
}

#[utoipa::path(get, path = "/oauth/authorize", operation_id = "oauth.authorize", tag = "oauth", responses((status = 303, description = "Validated client or first-party interaction redirect"), (status = 400, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn authorize(
    State(state): State<OAuthProviderState>,
    RawQuery(raw): RawQuery,
    mut auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Some(raw) = raw else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let request = match parse_authorization_request(&raw, state.max_authorization_request_bytes) {
        Ok(request) => request,
        Err(AuthorizationRequestParseError::Endpoint(code)) => {
            return oauth_endpoint_error(code, request_id);
        }
        Err(AuthorizationRequestParseError::Redirectable {
            client_id,
            redirect_uri,
            state: client_state,
            code,
        }) => {
            let error = state
                .service
                .authorization_request_error(
                    &client_id,
                    &redirect_uri,
                    client_state.as_deref(),
                    code,
                )
                .await;
            return protocol_error_response(&error, request_id);
        }
    };
    let session = match optional_session_candidate(&state.browser_auth, &mut auth).await {
        Ok(session) => session,
        Err(BrowserSessionError::Unavailable) => {
            return problem_response(
                StatusCode::SERVICE_UNAVAILABLE,
                request_id,
                "OAuth session authority is unavailable",
            );
        }
        Err(_) => None,
    };
    match state.service.begin_authorization(request, session).await {
        Ok(BeginAuthorizationResult::Interaction(interaction)) => {
            let mut target = state.authorization_ui.clone();
            target
                .query_pairs_mut()
                .append_pair("request", interaction.handle.expose());
            no_store_redirect(StatusCode::SEE_OTHER, target.as_str())
        }
        Ok(BeginAuthorizationResult::Redirect(redirect)) => authorization_redirect(redirect),
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(get, path = "/oauth/authorize/interaction", operation_id = "oauth.authorize.interaction", tag = "oauth", params(("request" = String, Query, description = "Opaque authorization interaction handle")), responses((status = 200, body = OAuthAuthorizationInteractionSchema), (status = 400, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn interaction(
    State(state): State<OAuthProviderState>,
    RawQuery(raw): RawQuery,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let handle = raw
        .as_deref()
        .and_then(|raw| parse_unique_form(raw.as_bytes()).ok())
        .and_then(|mut fields| fields.remove("request"))
        .filter(|value| !value.is_empty());
    let Some(handle) = handle else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    match state.service.interaction(&handle).await {
        Ok(interaction) => no_store_json(interaction),
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(post, path = "/oauth/authorize/decision", operation_id = "oauth.authorize.decision", tag = "oauth", request_body(content_type = "application/x-www-form-urlencoded", content = String), responses((status = 303, description = "Exact registered client redirect"), (status = 401, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("session_cookie" = [])))]
pub async fn decision(
    State(state): State<OAuthProviderState>,
    headers: HeaderMap,
    mut auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Ok(fields) = parse_form_request(&headers, &body, MAX_FORM_BYTES) else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let Some(handle) = fields.get("request").filter(|value| !value.is_empty()) else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let decision = match fields.get("decision").map(String::as_str) {
        Some("approve") => ConsentDecision::Approve,
        Some("deny") => ConsentDecision::Deny,
        _ => return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id),
    };
    let session = match required_session_candidate(&state.browser_auth, &mut auth).await {
        Ok(session) => session,
        Err(error) => return required_session_error_response(error, request_id),
    };
    match state.service.decide(handle, session, decision).await {
        Ok(redirect) => authorization_redirect(redirect),
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(post, path = "/oauth/token", operation_id = "oauth.token", tag = "oauth", request_body(content_type = "application/x-www-form-urlencoded", content = String), responses((status = 200, body = OAuthTokenResponseSchema), (status = 400, body = OAuthErrorResponseSchema), (status = 401, body = OAuthErrorResponseSchema), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn token(
    State(state): State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Ok(fields) = parse_form_request(&headers, &body, MAX_FORM_BYTES) else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let request = match token_request(&headers, &fields) {
        Ok(request) => request,
        Err(code) => return oauth_endpoint_error(code, request_id),
    };
    match state.service.token(request).await {
        Ok(response) => {
            let scope = response
                .scopes
                .iter()
                .map(Scope::as_str)
                .collect::<Vec<_>>()
                .join(" ");
            no_store_json(OAuthTokenResponseSchema {
                access_token: response.access_token,
                token_type: response.token_type,
                expires_in: response.expires_in,
                scope,
                refresh_token: response.refresh_token,
                id_token: response.id_token,
            })
        }
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(post, path = "/oauth/register", operation_id = "oauth.register", tag = "oauth", request_body(content_type = "application/json", content = serde_json::Value), responses((status = 201, body = OAuthClientRegistrationResponseSchema), (status = 400, body = OAuthErrorResponseSchema), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn register(
    State(state): State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    let request_id = resolve_request_id(request_id);
    if !is_json_content_type(&headers) || body.len() > state.max_client_metadata_bytes {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    }
    let Ok(metadata) = ClientMetadata::from_json(&body, state.max_client_metadata_bytes, None)
    else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    match state.adapter.register_dynamic_client(metadata).await {
        Ok(mut onboarded) => {
            let secret = onboarded
                .client_secret
                .take()
                .map(omnius_auth_oauth_server::OpaqueBearer::expose_once);
            let response =
                OAuthClientRegistrationResponseSchema::from_client(onboarded.client, secret);
            let mut response = (StatusCode::CREATED, Json(response)).into_response();
            set_no_store(&mut response);
            response
        }
        Err(_) => oauth_endpoint_error(OAuthErrorCode::ServerError, request_id),
    }
}

#[utoipa::path(post, path = "/oauth/revoke", operation_id = "oauth.revoke", tag = "oauth", request_body(content_type = "application/x-www-form-urlencoded", content = String), responses((status = 200, description = "Known or unknown token processed"), (status = 400, body = OAuthErrorResponseSchema), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(()))]
pub async fn revoke(
    State(state): State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Ok(fields) = parse_form_request(&headers, &body, MAX_FORM_BYTES) else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let client_authentication = match client_authentication(&headers, &fields) {
        Ok(authentication) => authentication,
        Err(code) => return oauth_endpoint_error(code, request_id),
    };
    let Some(token) = fields.get("token").cloned() else {
        return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id);
    };
    let token_type_hint = fields
        .get("token_type_hint")
        .map(|hint| match hint.as_str() {
            "access_token" => TokenTypeHint::AccessToken,
            "refresh_token" => TokenTypeHint::RefreshToken,
            _ => TokenTypeHint::Unsupported,
        });
    let audience = match fields.get("resource") {
        Some(resource) => match ResourceUri::parse(resource.clone(), false) {
            Ok(resource) => Some(resource),
            Err(_) => return oauth_endpoint_error(OAuthErrorCode::InvalidTarget, request_id),
        },
        None => None,
    };
    match state
        .service
        .revoke(RevocationRequest {
            client_authentication,
            token,
            token_type_hint,
            audience,
        })
        .await
    {
        Ok(_) => {
            let mut response = StatusCode::OK.into_response();
            set_no_store(&mut response);
            response
        }
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(get, path = "/oauth/grants", operation_id = "oauth.grants.list", tag = "oauth", responses((status = 200, body = Vec<OAuthConnectedGrantSchema>), (status = 401, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("session_cookie" = [])))]
pub async fn grants(
    State(state): State<OAuthProviderState>,
    mut auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let session = match required_session_candidate(&state.browser_auth, &mut auth).await {
        Ok(session) => session,
        Err(error) => return required_session_error_response(error, request_id),
    };
    match state.service.connected_grants(session.subject_id).await {
        Ok(grants) => Json(grants).into_response(),
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(delete, path = "/oauth/grants/{grant_id}", operation_id = "oauth.grants.revoke", tag = "oauth", params(("grant_id" = Uuid, Path)), responses((status = 204), (status = 404, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("session_cookie" = [])))]
pub async fn revoke_grant(
    State(state): State<OAuthProviderState>,
    Path(grant_id): Path<Uuid>,
    mut auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Ok(grant_id) = GrantId::from_uuid(grant_id) else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            request_id,
            "OAuth grant identifier is invalid",
        );
    };
    let session = match required_session_candidate(&state.browser_auth, &mut auth).await {
        Ok(session) => session,
        Err(error) => return required_session_error_response(error, request_id),
    };
    match state
        .service
        .revoke_connected_grant(session.subject_id, grant_id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => problem_response(
            StatusCode::NOT_FOUND,
            request_id,
            "OAuth grant was not found",
        ),
        Err(error) => protocol_error_response(&error, request_id),
    }
}

#[utoipa::path(get, path = "/oauth/userinfo", operation_id = "oidc.userinfo.get", tag = "openid", responses((status = 200, body = OAuthUserInfoResponseSchema), (status = 401, body = OAuthErrorResponseSchema), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("bearer_auth" = ["openid"])))]
pub async fn userinfo_get(
    state: State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    userinfo_response(state, headers, request_id).await
}

#[utoipa::path(post, path = "/oauth/userinfo", operation_id = "oidc.userinfo.post", tag = "openid", responses((status = 200, body = OAuthUserInfoResponseSchema), (status = 401, body = OAuthErrorResponseSchema), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("bearer_auth" = ["openid"])))]
pub async fn userinfo_post(
    state: State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    userinfo_response(state, headers, request_id).await
}

async fn userinfo_response(
    State(state): State<OAuthProviderState>,
    headers: HeaderMap,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let Ok(token) = sole_bearer(&headers) else {
        return userinfo_invalid_token_response(request_id);
    };
    match state.service.userinfo(token).await {
        Ok(userinfo) => no_store_json(userinfo),
        Err(error) if error.code() == OAuthErrorCode::ServerError => {
            protocol_error_response(&error, request_id)
        }
        Err(_) => userinfo_invalid_token_response(request_id),
    }
}

#[utoipa::path(get, path = "/oauth/logout", operation_id = "oidc.logout.get", tag = "openid", responses((status = 303, description = "Validated post-logout redirect"), (status = 204), (status = 400, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("session_cookie" = [])))]
pub async fn logout_get(
    state: State<OAuthProviderState>,
    query: RawQuery,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    logout_from_fields(
        state,
        query.0.as_deref().map(str::as_bytes),
        auth,
        request_id,
    )
    .await
}

#[utoipa::path(post, path = "/oauth/logout", operation_id = "oidc.logout.post", tag = "openid", request_body(content_type = "application/x-www-form-urlencoded", content = String), responses((status = 303, description = "Validated post-logout redirect"), (status = 204), (status = 400, body = ProblemDetailsSchema, content_type = "application/problem+json"), (status = 500, body = ProblemDetailsSchema, content_type = "application/problem+json")), security(("session_cookie" = [])))]
pub async fn logout_post(
    state: State<OAuthProviderState>,
    headers: HeaderMap,
    auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
    body: Bytes,
) -> Response {
    if !is_form_content_type(&headers) {
        return problem_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            resolve_request_id(request_id),
            "OAuth logout form media type is required",
        );
    }
    logout_from_fields(state, Some(&body), auth, request_id).await
}

async fn logout_from_fields(
    State(state): State<OAuthProviderState>,
    input: Option<&[u8]>,
    mut auth: BrowserAuthSession,
    request_id: Option<Extension<RequestId>>,
) -> Response {
    let request_id = resolve_request_id(request_id);
    let fields = match input.map(parse_unique_form).transpose() {
        Ok(Some(fields)) => fields,
        Ok(None) => BTreeMap::new(),
        Err(()) => return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id),
    };
    let session = match required_session_candidate(&state.browser_auth, &mut auth).await {
        Ok(session) => session,
        Err(error) => return required_session_error_response(error, request_id),
    };
    let hint = match fields.get("id_token_hint") {
        Some(token) => match untrusted_id_token_hint(token.clone()) {
            Ok(hint) => Some(hint),
            Err(()) => return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id),
        },
        None => None,
    };
    let post_logout_redirect_uri = match fields.get("post_logout_redirect_uri") {
        Some(uri) => match RedirectUri::parse(uri.clone()) {
            Ok(uri) => Some(uri),
            Err(_) => return oauth_endpoint_error(OAuthErrorCode::InvalidRequest, request_id),
        },
        None => None,
    };
    match state
        .service
        .logout(LogoutRequest {
            subject_id: session.subject_id,
            id_token_hint: hint,
            post_logout_redirect_uri,
            state: fields.get("state").cloned(),
        })
        .await
    {
        Ok(result) => {
            if auth.logout().await.is_err() {
                return problem_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    request_id,
                    "Browser logout is unavailable",
                );
            }
            if let Some(uri) = result.redirect_uri {
                let Ok(mut target) = Url::parse(uri.as_str()) else {
                    return problem_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        request_id,
                        "OAuth logout failed",
                    );
                };
                if let Some(state) = result.state {
                    target.query_pairs_mut().append_pair("state", &state);
                }
                no_store_redirect(StatusCode::SEE_OTHER, target.as_str())
            } else {
                let mut response = StatusCode::NO_CONTENT.into_response();
                set_no_store(&mut response);
                response
            }
        }
        Err(error) => protocol_error_response(&error, request_id),
    }
}

enum AuthorizationRequestParseError {
    Endpoint(OAuthErrorCode),
    Redirectable {
        client_id: ClientId,
        redirect_uri: RedirectUri,
        state: Option<String>,
        code: OAuthErrorCode,
    },
}

fn parse_authorization_request(
    raw: &str,
    max_bytes: usize,
) -> Result<AuthorizationRequestInput, AuthorizationRequestParseError> {
    if raw.len() > max_bytes {
        return Err(AuthorizationRequestParseError::Endpoint(
            OAuthErrorCode::InvalidRequest,
        ));
    }
    let fields = parse_unique_form(raw.as_bytes())
        .map_err(|()| AuthorizationRequestParseError::Endpoint(OAuthErrorCode::InvalidRequest))?;
    let client_id = required(&fields, "client_id")
        .ok()
        .and_then(|value| ClientId::parse(value.to_owned()).ok())
        .ok_or(AuthorizationRequestParseError::Endpoint(
            OAuthErrorCode::InvalidRequest,
        ))?;
    let redirect_uri = required(&fields, "redirect_uri")
        .ok()
        .and_then(|value| RedirectUri::parse(value.to_owned()).ok())
        .ok_or(AuthorizationRequestParseError::Endpoint(
            OAuthErrorCode::InvalidRequest,
        ))?;
    let client_state = fields.get("state").cloned();
    parse_authorization_request_fields(&fields, client_id.clone(), redirect_uri.clone()).map_err(
        |code| AuthorizationRequestParseError::Redirectable {
            client_id,
            redirect_uri,
            state: client_state,
            code,
        },
    )
}

fn parse_authorization_request_fields(
    fields: &BTreeMap<String, String>,
    client_id: ClientId,
    redirect_uri: RedirectUri,
) -> Result<AuthorizationRequestInput, OAuthErrorCode> {
    match required(fields, "response_type").map_err(|()| OAuthErrorCode::InvalidRequest)? {
        "code" => {}
        _ => return Err(OAuthErrorCode::UnsupportedResponseType),
    }
    if fields
        .get("response_mode")
        .is_some_and(|mode| mode != "query")
    {
        return Err(OAuthErrorCode::InvalidRequest);
    }
    let scopes = required(fields, "scope")
        .map_err(|()| OAuthErrorCode::InvalidRequest)?
        .split_ascii_whitespace()
        .map(|scope| Scope::new(scope.to_owned()).map_err(|_| OAuthErrorCode::InvalidRequest))
        .collect::<Result<Vec<_>, _>>()?;
    let resources = fields
        .get("resource")
        .into_iter()
        .map(|resource| {
            ResourceUri::parse(resource.clone(), false).map_err(|_| OAuthErrorCode::InvalidRequest)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let prompt = match fields.get("prompt").map(String::as_str) {
        None => None,
        Some("none") => Some(Prompt::None),
        Some("login") => Some(Prompt::Login),
        Some("consent") => Some(Prompt::Consent),
        Some(_) => return Err(OAuthErrorCode::InvalidRequest),
    };
    let expected_issuer = fields
        .get("iss")
        .map(|issuer| {
            IssuerUri::parse(issuer.clone(), false).map_err(|_| OAuthErrorCode::InvalidRequest)
        })
        .transpose()?;
    AuthorizationRequestInput::new(AuthorizationRequestParts {
        client_id,
        redirect_uri,
        response_type: ResponseType::Code,
        response_mode: ResponseMode::Query,
        state: fields.get("state").cloned(),
        scopes,
        resources,
        pkce_challenge: PkceChallenge::parse(
            required(fields, "code_challenge")
                .map_err(|()| OAuthErrorCode::InvalidRequest)?
                .to_owned(),
        )
        .map_err(|_| OAuthErrorCode::InvalidRequest)?,
        pkce_method: required(fields, "code_challenge_method")
            .map_err(|()| OAuthErrorCode::InvalidRequest)?
            .to_owned(),
        nonce: fields.get("nonce").cloned(),
        prompt,
        max_age_seconds: fields
            .get("max_age")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| OAuthErrorCode::InvalidRequest)
            })
            .transpose()?,
        expected_issuer,
    })
    .map_err(|_| OAuthErrorCode::InvalidRequest)
}

fn token_request(
    headers: &HeaderMap,
    fields: &BTreeMap<String, String>,
) -> Result<TokenRequest, OAuthErrorCode> {
    let client_authentication = client_authentication(headers, fields)?;
    match required(fields, "grant_type").map_err(|()| OAuthErrorCode::InvalidRequest)? {
        "authorization_code" => Ok(TokenRequest::AuthorizationCode(
            AuthorizationCodeTokenRequest {
                client_authentication,
                code: required(fields, "code")
                    .map_err(|()| OAuthErrorCode::InvalidRequest)?
                    .to_owned(),
                redirect_uri: RedirectUri::parse(
                    required(fields, "redirect_uri")
                        .map_err(|()| OAuthErrorCode::InvalidRequest)?
                        .to_owned(),
                )
                .map_err(|_| OAuthErrorCode::InvalidRequest)?,
                code_verifier: PkceVerifier::parse(
                    required(fields, "code_verifier")
                        .map_err(|()| OAuthErrorCode::InvalidRequest)?
                        .to_owned(),
                )
                .map_err(|_| OAuthErrorCode::InvalidGrant)?,
                resource: fields
                    .get("resource")
                    .map(|resource| {
                        ResourceUri::parse(resource.clone(), false)
                            .map_err(|_| OAuthErrorCode::InvalidTarget)
                    })
                    .transpose()?,
            },
        )),
        "refresh_token" => Ok(TokenRequest::RefreshToken(RefreshTokenRequest {
            client_authentication,
            refresh_token: required(fields, "refresh_token")
                .map_err(|()| OAuthErrorCode::InvalidRequest)?
                .to_owned(),
            scopes: fields
                .get("scope")
                .map(|scope| {
                    scope
                        .split_ascii_whitespace()
                        .map(|scope| {
                            Scope::new(scope.to_owned()).map_err(|_| OAuthErrorCode::InvalidScope)
                        })
                        .collect()
                })
                .transpose()?,
            resource: fields
                .get("resource")
                .map(|resource| {
                    ResourceUri::parse(resource.clone(), false)
                        .map_err(|_| OAuthErrorCode::InvalidTarget)
                })
                .transpose()?,
        })),
        _ => Err(OAuthErrorCode::InvalidRequest),
    }
}

fn client_authentication(
    headers: &HeaderMap,
    fields: &BTreeMap<String, String>,
) -> Result<ClientAuthentication, OAuthErrorCode> {
    let basic = basic_authentication(headers)?;
    let body_client_id = fields
        .get("client_id")
        .map(|value| ClientId::parse(value.clone()).map_err(|_| OAuthErrorCode::InvalidClient))
        .transpose()?;
    let assertion = match fields.get("client_assertion") {
        Some(token) => {
            if fields.get("client_assertion_type").map(String::as_str)
                != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            {
                return Err(OAuthErrorCode::InvalidClient);
            }
            let client_id = body_client_id
                .clone()
                .ok_or(OAuthErrorCode::InvalidClient)?;
            Some((client_id, parse_private_key_assertion(token.clone())?))
        }
        None if fields.contains_key("client_assertion_type") => {
            return Err(OAuthErrorCode::InvalidClient);
        }
        None => None,
    };
    ClientAuthentication::try_from(ClientAuthenticationParts {
        public_client_id: if assertion.is_none() {
            body_client_id
        } else {
            None
        },
        basic,
        private_key_jwt: assertion,
    })
    .map_err(|_| OAuthErrorCode::InvalidClient)
}

fn basic_authentication(
    headers: &HeaderMap,
) -> Result<Option<(ClientId, omnius_auth_oauth_server::ClientSecret)>, OAuthErrorCode> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(OAuthErrorCode::InvalidClient);
    }
    let value = value.to_str().map_err(|_| OAuthErrorCode::InvalidClient)?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
        .ok_or(OAuthErrorCode::InvalidClient)?;
    if encoded.is_empty() || encoded.len() > MAX_BASIC_BYTES {
        return Err(OAuthErrorCode::InvalidClient);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| OAuthErrorCode::InvalidClient)?;
    let decoded = std::str::from_utf8(&decoded).map_err(|_| OAuthErrorCode::InvalidClient)?;
    let (client_id, secret) = decoded
        .split_once(':')
        .ok_or(OAuthErrorCode::InvalidClient)?;
    let client_id = decode_form_component(client_id).ok_or(OAuthErrorCode::InvalidClient)?;
    let secret = decode_form_component(secret).ok_or(OAuthErrorCode::InvalidClient)?;
    Ok(Some((
        ClientId::parse(client_id).map_err(|_| OAuthErrorCode::InvalidClient)?,
        omnius_auth_oauth_server::ClientSecret::parse(secret)
            .map_err(|_| OAuthErrorCode::InvalidClient)?,
    )))
}

fn parse_private_key_assertion(token: String) -> Result<PrivateKeyJwtAssertion, OAuthErrorCode> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Claims {
        iss: String,
        sub: String,
        aud: Audience,
        iat: i64,
        exp: i64,
        jti: String,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }
    let mut segments = token.split('.');
    let _header = segments.next().ok_or(OAuthErrorCode::InvalidClient)?;
    let payload = segments.next().ok_or(OAuthErrorCode::InvalidClient)?;
    let _signature = segments.next().ok_or(OAuthErrorCode::InvalidClient)?;
    if segments.next().is_some() || payload.len() > MAX_FORM_BYTES {
        return Err(OAuthErrorCode::InvalidClient);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| OAuthErrorCode::InvalidClient)?;
    let claims: Claims =
        serde_json::from_slice(&payload).map_err(|_| OAuthErrorCode::InvalidClient)?;
    let audience = match claims.aud {
        Audience::One(value) => value,
        Audience::Many(mut values) if values.len() == 1 => values.remove(0),
        Audience::Many(_) => return Err(OAuthErrorCode::InvalidClient),
    };
    PrivateKeyJwtAssertion::new(
        token,
        ClientId::parse(claims.iss).map_err(|_| OAuthErrorCode::InvalidClient)?,
        ClientId::parse(claims.sub).map_err(|_| OAuthErrorCode::InvalidClient)?,
        audience,
        claims.jti,
        OffsetDateTime::from_unix_timestamp(claims.iat)
            .map_err(|_| OAuthErrorCode::InvalidClient)?,
        OffsetDateTime::from_unix_timestamp(claims.exp)
            .map_err(|_| OAuthErrorCode::InvalidClient)?,
    )
    .map_err(|_| OAuthErrorCode::InvalidClient)
}

fn untrusted_id_token_hint(token: String) -> Result<IdTokenHint, ()> {
    #[derive(Deserialize)]
    struct Claims {
        aud: Audience,
        #[serde(default)]
        nonce: Option<String>,
    }
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Audience {
        One(String),
        Many(Vec<String>),
    }
    let mut segments = token.split('.');
    let _header = segments.next().ok_or(())?;
    let payload = segments.next().ok_or(())?;
    let _signature = segments.next().ok_or(())?;
    if segments.next().is_some() || payload.len() > MAX_FORM_BYTES {
        return Err(());
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
    let claims: Claims = serde_json::from_slice(&payload).map_err(|_| ())?;
    let audience = match claims.aud {
        Audience::One(value) => value,
        Audience::Many(mut values) if values.len() == 1 => values.remove(0),
        Audience::Many(_) => return Err(()),
    };
    IdTokenHint::new(
        token,
        ClientId::parse(audience).map_err(|_| ())?,
        claims.nonce,
    )
    .map_err(|_| ())
}

async fn optional_session_candidate(
    state: &BrowserAuthState,
    auth: &mut BrowserAuthSession,
) -> Result<Option<SessionCandidate>, BrowserSessionError> {
    if auth.user.is_none() {
        return Ok(None);
    }
    require_active_session(state, auth).await.map(|session| {
        Some(SessionCandidate {
            subject_id: session.principal.subject_id,
            authenticated_at: session.principal.authenticated_at,
        })
    })
}

#[derive(Clone, Copy)]
enum RequiredSessionError {
    Unavailable,
    Required,
}

async fn required_session_candidate(
    state: &BrowserAuthState,
    auth: &mut BrowserAuthSession,
) -> Result<SessionCandidate, RequiredSessionError> {
    optional_session_candidate(state, auth)
        .await
        .map_err(|error| match error {
            BrowserSessionError::Unavailable => RequiredSessionError::Unavailable,
            _ => RequiredSessionError::Required,
        })?
        .ok_or(RequiredSessionError::Required)
}

fn required_session_error_response(error: RequiredSessionError, request_id: RequestId) -> Response {
    match error {
        RequiredSessionError::Unavailable => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            request_id,
            "Browser session authority is unavailable",
        ),
        RequiredSessionError::Required => problem_response(
            StatusCode::UNAUTHORIZED,
            request_id,
            "An active browser session is required",
        ),
    }
}

fn parse_form_request(
    headers: &HeaderMap,
    body: &[u8],
    max_bytes: usize,
) -> Result<BTreeMap<String, String>, ()> {
    if !is_form_content_type(headers) || body.len() > max_bytes {
        return Err(());
    }
    parse_unique_form(body)
}

fn parse_unique_form(input: &[u8]) -> Result<BTreeMap<String, String>, ()> {
    let mut fields = BTreeMap::new();
    for (key, value) in url::form_urlencoded::parse(input) {
        if key.is_empty()
            || fields
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(());
        }
    }
    Ok(fields)
}

fn required<'a>(fields: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, ()> {
    fields
        .get(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(())
}

fn decode_form_component(input: &str) -> Option<String> {
    let encoded = format!("value={input}");
    url::form_urlencoded::parse(encoded.as_bytes())
        .next()
        .filter(|(key, _)| key == "value")
        .map(|(_, value)| value.into_owned())
}

fn is_form_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| {
            value
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        })
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn sole_bearer(headers: &HeaderMap) -> Result<&str, ()> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(())?;
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    let (scheme, token) = value.split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.starts_with(' ')
        || token.ends_with(' ')
        || token.contains(',')
    {
        return Err(());
    }
    Ok(token)
}

fn authorization_redirect(redirect: AuthorizationRedirect) -> Response {
    let Ok(mut target) = Url::parse(redirect.redirect_uri.as_str()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    {
        let mut query = target.query_pairs_mut();
        if let Some(code) = redirect.code {
            query.append_pair("code", &code);
        }
        if let Some(error) = redirect.error {
            query.append_pair("error", oauth_code(error));
        }
        if let Some(state) = redirect.state {
            query.append_pair("state", &state);
        }
        query.append_pair("iss", redirect.issuer.as_str());
    }
    no_store_redirect(StatusCode::SEE_OTHER, target.as_str())
}

fn protocol_error_response(error: &ProtocolError, request_id: RequestId) -> Response {
    if let Some(redirect) = error.redirect() {
        let Ok(mut target) = Url::parse(redirect.redirect_uri.as_str()) else {
            return oauth_endpoint_error(OAuthErrorCode::ServerError, request_id);
        };
        {
            let mut query = target.query_pairs_mut();
            query.append_pair("error", oauth_code(error.code()));
            if let Some(state) = redirect.state.as_ref() {
                query.append_pair("state", state);
            }
            query.append_pair("iss", redirect.issuer.as_str());
        }
        return no_store_redirect(StatusCode::SEE_OTHER, target.as_str());
    }
    oauth_endpoint_error(error.code(), request_id)
}

fn oauth_endpoint_error(code: OAuthErrorCode, request_id: RequestId) -> Response {
    let status = if code == OAuthErrorCode::InvalidClient {
        StatusCode::UNAUTHORIZED
    } else if code == OAuthErrorCode::ServerError {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    let mut response = (
        status,
        Json(OAuthErrorResponseSchema {
            error: oauth_code(code),
        }),
    )
        .into_response();
    set_no_store(&mut response);
    if code == OAuthErrorCode::InvalidClient {
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"oauth-token\""),
        );
    }
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

fn userinfo_invalid_token_response(request_id: RequestId) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(OAuthErrorResponseSchema {
            error: oauth_code(OAuthErrorCode::InvalidToken),
        }),
    )
        .into_response();
    set_no_store(&mut response);
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

const fn oauth_code(code: OAuthErrorCode) -> &'static str {
    match code {
        OAuthErrorCode::InvalidRequest => "invalid_request",
        OAuthErrorCode::InvalidClient => "invalid_client",
        OAuthErrorCode::UnauthorizedClient => "unauthorized_client",
        OAuthErrorCode::AccessDenied => "access_denied",
        OAuthErrorCode::UnsupportedResponseType => "unsupported_response_type",
        OAuthErrorCode::InvalidScope => "invalid_scope",
        OAuthErrorCode::InvalidTarget => "invalid_target",
        OAuthErrorCode::InvalidGrant => "invalid_grant",
        OAuthErrorCode::InvalidToken => "invalid_token",
        OAuthErrorCode::LoginRequired => "login_required",
        OAuthErrorCode::ConsentRequired => "consent_required",
        OAuthErrorCode::UnsupportedTokenType => "unsupported_token_type",
        OAuthErrorCode::ServerError => "server_error",
    }
}

fn cached_json<T: Serialize>(value: &T, cache_control: &'static str) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );
    response
}

fn no_store_json<T: Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    set_no_store(&mut response);
    response
}

fn no_store_redirect(status: StatusCode, location: &str) -> Response {
    let mut response = match HeaderValue::from_str(location) {
        Ok(location) => {
            let mut response = status.into_response();
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    set_no_store(&mut response);
    response
}

fn set_no_store(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

fn problem_response(status: StatusCode, request_id: RequestId, detail: &'static str) -> Response {
    let Ok(problem) = ProblemDetails::try_for_status(status, request_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = (status, Json(problem.with_detail(detail))).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct OAuthErrorResponseSchema {
    error: &'static str,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct OAuthTokenResponseSchema {
    access_token: String,
    token_type: String,
    expires_in: u64,
    scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct OAuthClientRegistrationResponseSchema {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    post_logout_redirect_uris: Vec<String>,
    token_endpoint_auth_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<String>,
}
#[expect(
    dead_code,
    reason = "OpenAPI-only representation of consent scope display data"
)]
#[derive(utoipa::ToSchema)]
pub struct OAuthInteractionScopeSchema {
    name: String,
    description: String,
    newly_requested: bool,
}

#[expect(
    dead_code,
    reason = "OpenAPI-only representation of validated consent display data"
)]
#[derive(utoipa::ToSchema)]
pub struct OAuthAuthorizationInteractionSchema {
    client_name: String,
    client_origin: String,
    redirect_host: String,
    resource: String,
    resource_name: String,
    resource_description: String,
    minimum_assurance: String,
    scopes: Vec<OAuthInteractionScopeSchema>,
    requirement: String,
}

#[expect(
    dead_code,
    reason = "OpenAPI-only representation of safe connected grants"
)]
#[derive(utoipa::ToSchema)]
pub struct OAuthConnectedGrantSchema {
    #[schema(format = Uuid)]
    grant_id: String,
    client_name: String,
    resource: String,
    scopes: Vec<String>,
    #[schema(format = DateTime)]
    consented_at: String,
}

#[expect(
    dead_code,
    reason = "OpenAPI-only representation of OIDC UserInfo claims"
)]
#[derive(utoipa::ToSchema)]
pub struct OAuthUserInfoResponseSchema {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
}

impl OAuthClientRegistrationResponseSchema {
    fn from_client(
        client: omnius_auth_oauth_server::store::RegisteredClient,
        client_secret: Option<String>,
    ) -> Self {
        Self {
            client_id: client.client_id.as_str().to_owned(),
            client_name: client.display_name,
            redirect_uris: client
                .redirect_uris
                .iter()
                .map(|uri| uri.as_str().to_owned())
                .collect(),
            post_logout_redirect_uris: client
                .post_logout_redirect_uris
                .iter()
                .map(|uri| uri.as_str().to_owned())
                .collect(),
            token_endpoint_auth_method: match client.token_endpoint_auth_method {
                TokenEndpointAuthMethod::None => "none",
                TokenEndpointAuthMethod::ClientSecretBasic => "client_secret_basic",
                TokenEndpointAuthMethod::PrivateKeyJwt => "private_key_jwt",
            }
            .to_owned(),
            client_secret,
        }
    }
}

#[derive(Clone)]
pub struct OAuthSessionAuthorityBridge {
    pool: PostgresPool,
    session_config: omnius_auth_core::SessionConfig,
}

impl OAuthSessionAuthorityBridge {
    fn new(pool: PostgresPool, session_config: omnius_auth_core::SessionConfig) -> Self {
        Self {
            pool,
            session_config,
        }
    }

    async fn has_active_session(
        &self,
        subject_id: SubjectId,
        authenticated_at: Option<OffsetDateTime>,
    ) -> Result<bool, SessionAuthorityError> {
        let idle = time::Duration::try_from(self.session_config.idle_timeout)
            .map_err(|_| SessionAuthorityError)?;
        let now = OffsetDateTime::now_utc();
        let idle_cutoff = now.checked_sub(idle).ok_or(SessionAuthorityError)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| SessionAuthorityError)?;
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (SELECT 1 FROM sessions s \
             JOIN tower_sessions.session p ON p.id = s.session_id \
             JOIN users u ON u.id = s.user_id \
             WHERE s.user_id = $1 AND u.status = 'active' AND s.revoked_at IS NULL \
               AND s.absolute_expires_at > $2 AND s.last_seen_at > $3 AND p.expiry_date > $2 \
               AND ($4::timestamptz IS NULL OR s.created_at = $4))",
        )
        .bind(subject_id.as_uuid())
        .bind(now)
        .bind(idle_cutoff)
        .bind(authenticated_at)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| SessionAuthorityError)
    }
}

impl OAuthSessionAuthority for OAuthSessionAuthorityBridge {
    fn authorize_session(
        &self,
        candidate: SessionCandidate,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<AuthorizedBrowserSession>, SessionAuthorityError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            if !self
                .has_active_session(candidate.subject_id, Some(candidate.authenticated_at))
                .await?
            {
                return Ok(None);
            }
            let principal = Principal::new(
                candidate.subject_id,
                PrincipalKind::User,
                None,
                AuthMethod::Session,
                candidate.authenticated_at,
                AssuranceLevel::Aal1,
                Vec::new(),
            )
            .map_err(|_| SessionAuthorityError)?;
            Ok(Some(AuthorizedBrowserSession {
                principal,
                authentication_methods: vec![AuthMethod::Password],
            }))
        })
    }

    fn validate_logout_binding(
        &self,
        command: LogoutSession,
    ) -> Pin<Box<dyn Future<Output = Result<bool, SessionAuthorityError>> + Send + '_>> {
        Box::pin(async move { self.has_active_session(command.subject_id, None).await })
    }
}

#[derive(Clone)]
pub struct OAuthAuditBridge {
    sink: PostgresAuditSink,
    clock: Arc<SystemClock>,
}

impl OAuthAuditBridge {
    fn new(clock: Arc<SystemClock>) -> Self {
        Self {
            sink: PostgresAuditSink::new(AuditConfig { enabled: true }),
            clock,
        }
    }
}

impl OAuthAuditSink for OAuthAuditBridge {
    fn append<'a>(
        &'a self,
        transaction: &'a mut Transaction<'_, Postgres>,
        event: OAuthAuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), OAuthAuditError>> + Send + 'a>> {
        Box::pin(async move {
            let mapped =
                safe_audit_event(&event, self.clock.now_utc()).map_err(|()| OAuthAuditError)?;
            self.sink
                .append_with(transaction, &mapped)
                .await
                .map(|_| ())
                .map_err(|_| OAuthAuditError)
        })
    }
}

type SafeAuditMapping = (
    SecurityEventName,
    AuditActor,
    Option<SubjectId>,
    &'static str,
    &'static str,
    Option<String>,
    AuditOutcome,
);

fn safe_audit_event(event: &OAuthAuditEvent, now: OffsetDateTime) -> Result<AuditEvent, ()> {
    let (name, actor, subject, action, resource_kind, resource_id, outcome) =
        authorization_audit_mapping(event)
            .or_else(|| token_audit_mapping(event))
            .or_else(|| client_audit_mapping(event))
            .ok_or(())?;
    let action = Action::new(action).map_err(|_| ())?;
    let resource_kind = ResourceKind::new(resource_kind).map_err(|_| ())?;
    let mut builder = AuditEvent::builder(
        name,
        now,
        actor,
        AuditScope::Global,
        action,
        resource_kind,
        outcome,
    );
    if let Some(subject) = subject {
        builder = builder.subject_id(subject);
    }
    if let Some(resource_id) = resource_id {
        builder = builder.resource_id(AuditResourceId::new(resource_id).map_err(|_| ())?);
    }
    Ok(builder.build())
}

fn authorization_audit_mapping(event: &OAuthAuditEvent) -> Option<SafeAuditMapping> {
    match event {
        OAuthAuditEvent::AuthorizationRequestCreated { .. } => Some((
            SecurityEventName::OAuthConsentDecision,
            AuditActor::Anonymous,
            None,
            "oauth:authorize",
            "oauth_authorization",
            None,
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::AuthorizationApproved {
            subject_id,
            grant_id,
            ..
        } => Some((
            SecurityEventName::OAuthConsentDecision,
            AuditActor::User(*subject_id),
            Some(*subject_id),
            "oauth:consent:approve",
            "oauth_grant",
            Some(grant_id.as_uuid().to_string()),
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::AuthorizationDenied { subject_id, .. } => Some((
            SecurityEventName::OAuthConsentDecision,
            AuditActor::User(*subject_id),
            Some(*subject_id),
            "oauth:consent:deny",
            "oauth_authorization",
            None,
            AuditOutcome::Denied,
        )),
        _ => None,
    }
}

fn token_audit_mapping(event: &OAuthAuditEvent) -> Option<SafeAuditMapping> {
    match event {
        OAuthAuditEvent::ClientAssertionAccepted { .. } => Some((
            SecurityEventName::OAuthAuthorizationCodeExchange,
            AuditActor::System,
            None,
            "oauth:client:authenticate",
            "oauth_client",
            None,
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::AuthorizationCodeExchanged {
            subject_id,
            grant_id,
            ..
        } => Some((
            SecurityEventName::OAuthAuthorizationCodeExchange,
            AuditActor::System,
            Some(*subject_id),
            "oauth:code:exchange",
            "oauth_grant",
            Some(grant_id.as_uuid().to_string()),
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::RefreshRotated {
            subject_id,
            grant_id,
            ..
        } => Some((
            SecurityEventName::OAuthRefreshTokenRotated,
            AuditActor::System,
            Some(*subject_id),
            "oauth:refresh:rotate",
            "oauth_grant",
            Some(grant_id.as_uuid().to_string()),
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::RefreshReuseDetected { grant_id } => Some((
            SecurityEventName::RefreshReuseDetected,
            AuditActor::System,
            None,
            "oauth:refresh:reject_reuse",
            "oauth_grant",
            Some(grant_id.as_uuid().to_string()),
            AuditOutcome::Denied,
        )),
        OAuthAuditEvent::TokenRevoked { grant_id, .. } => Some((
            SecurityEventName::OAuthTokenRevocation,
            AuditActor::System,
            None,
            "oauth:token:revoke",
            "oauth_grant",
            grant_id.as_ref().map(|id| id.as_uuid().to_string()),
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::ConnectedGrantRevoked {
            subject_id,
            grant_id,
        } => Some((
            SecurityEventName::OAuthConsentRevoked,
            AuditActor::User(*subject_id),
            Some(*subject_id),
            "oauth:grant:revoke",
            "oauth_grant",
            Some(grant_id.as_uuid().to_string()),
            AuditOutcome::Succeeded,
        )),
        _ => None,
    }
}

fn client_audit_mapping(event: &OAuthAuditEvent) -> Option<SafeAuditMapping> {
    match event {
        OAuthAuditEvent::ClientRegistered { .. } => Some((
            SecurityEventName::OAuthDynamicClientRegistration,
            AuditActor::System,
            None,
            "oauth:client:register",
            "oauth_client",
            None,
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::ClientMetadataAccepted => Some((
            SecurityEventName::OAuthClientMetadataResolved,
            AuditActor::System,
            None,
            "oauth:client_metadata:accept",
            "oauth_client",
            None,
            AuditOutcome::Succeeded,
        )),
        OAuthAuditEvent::ClientMetadataRejected => Some((
            SecurityEventName::OAuthClientMetadataResolved,
            AuditActor::System,
            None,
            "oauth:client_metadata:reject",
            "oauth_client",
            None,
            AuditOutcome::Denied,
        )),
        OAuthAuditEvent::ClientDisabled { .. } => Some((
            SecurityEventName::OAuthConsentRevoked,
            AuditActor::System,
            None,
            "oauth:client:disable",
            "oauth_client",
            None,
            AuditOutcome::Succeeded,
        )),
        _ => None,
    }
}

fn oauth_cleanup_task(cleanup: OAuthCleanup) -> Result<TaskSpec, OAuthProviderBuildError> {
    let code = ErrorCode::try_new("OAUTH_CLEANUP_FAILED")
        .map_err(|_| OAuthProviderBuildError::CleanupCode)?;
    Ok(TaskSpec::new(
        "oauth-cleanup",
        "auth-oauth-server",
        Criticality::Degraded,
        OAUTH_CLEANUP_SHUTDOWN,
        move |context| {
            let cleanup = cleanup.clone();
            async move {
                let mut interval = tokio::time::interval(OAUTH_CLEANUP_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = context.draining() => return Ok(()),
                        _ = interval.tick() => {
                            cleanup
                                .run_bounded(OffsetDateTime::now_utc(), MAX_CLEANUP_BATCH)
                                .await
                                .map_err(|error| ServiceError::new(code, "OAuth cleanup failed").with_source(error))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn form_parser_rejects_duplicate_security_fields() {
        assert!(parse_unique_form(b"client_id=one&client_id=two").is_err());
        assert!(parse_unique_form(b"token=one&token=two").is_err());
    }

    #[test]
    fn provider_route_surface_has_only_root_metadata_and_no_mcp() {
        let routes = [
            AUTHORIZATION_SERVER_METADATA_PATH,
            OPENID_CONFIGURATION_PATH,
            PROTECTED_RESOURCE_METADATA_PATH,
            OAUTH_JWKS_PATH,
            OAUTH_AUTHORIZE_PATH,
            OAUTH_INTERACTION_PATH,
            OAUTH_DECISION_PATH,
            OAUTH_TOKEN_PATH,
            OAUTH_REGISTER_PATH,
            OAUTH_REVOKE_PATH,
            OAUTH_GRANTS_PATH,
            OAUTH_GRANT_PATH,
            OAUTH_USERINFO_PATH,
            OAUTH_LOGOUT_PATH,
        ];
        assert_eq!(
            routes
                .iter()
                .filter(|route| route.starts_with("/.well-known/"))
                .count(),
            3
        );
        assert!(routes.iter().all(|route| !route.contains("mcp")));
        assert!(
            !routes
                .iter()
                .any(|route| route.starts_with("/.well-known/oauth-protected-resource/"))
        );
    }
    #[test]
    fn authorization_parser_enforces_configured_limit_exactly() {
        let base = concat!(
            "client_id=client-1",
            "&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback",
            "&response_type=code",
            "&scope=records%3Aread",
            "&resource=https%3A%2F%2Fissuer.example.test",
            "&code_challenge=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "&code_challenge_method=S256"
        );
        let configured_limit = base.len() + 32;
        let padding_prefix = "&padding=";
        let exact = format!(
            "{base}{padding_prefix}{}",
            "x".repeat(configured_limit - base.len() - padding_prefix.len())
        );
        assert_eq!(exact.len(), configured_limit);
        assert!(parse_authorization_request(&exact, configured_limit).is_ok());

        let oversized = format!("{exact}x");
        assert_eq!(oversized.len(), configured_limit + 1);
        assert!(matches!(
            parse_authorization_request(&oversized, configured_limit),
            Err(AuthorizationRequestParseError::Endpoint(
                OAuthErrorCode::InvalidRequest
            ))
        ));
    }

    #[test]
    fn authorization_parser_preserves_redirect_context_for_protocol_errors() {
        let unsupported = concat!(
            "client_id=client-1",
            "&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback",
            "&response_type=token",
            "&response_mode=query",
            "&state=correlation-state"
        );
        let Err(AuthorizationRequestParseError::Redirectable { state, code, .. }) =
            parse_authorization_request(unsupported, unsupported.len())
        else {
            panic!("unsupported response type did not remain redirectable");
        };
        assert_eq!(code, OAuthErrorCode::UnsupportedResponseType);
        assert_eq!(state.as_deref(), Some("correlation-state"));

        let invalid_mode = unsupported.replace("response_type=token", "response_type=code");
        let invalid_mode = invalid_mode.replace("response_mode=query", "response_mode=fragment");
        let Err(AuthorizationRequestParseError::Redirectable { code, .. }) =
            parse_authorization_request(&invalid_mode, invalid_mode.len())
        else {
            panic!("invalid response mode did not remain redirectable");
        };
        assert_eq!(code, OAuthErrorCode::InvalidRequest);
    }

    #[test]
    fn userinfo_invalid_token_response_has_rfc6750_challenge() {
        let response = userinfo_invalid_token_response(RequestId::new());
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static("Bearer error=\"invalid_token\""))
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let unavailable = oauth_endpoint_error(OAuthErrorCode::ServerError, RequestId::new());
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn sensitive_json_and_redirect_responses_are_not_cacheable()
    -> Result<(), Box<dyn std::error::Error>> {
        let json = no_store_json(serde_json::json!({"token": "redacted"}));
        assert_eq!(
            json.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            json.headers().get(header::PRAGMA),
            Some(&HeaderValue::from_static("no-cache"))
        );

        let cached = cached_json(
            &serde_json::json!({"issuer": "https://issuer.example.test"}),
            DISCOVERY_CACHE_CONTROL,
        );
        assert_eq!(
            cached.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static(DISCOVERY_CACHE_CONTROL))
        );
        let redirect = authorization_redirect(AuthorizationRedirect {
            redirect_uri: RedirectUri::parse("https://client.example.test/callback?fixed=1")?,
            state: Some("opaque-state".to_owned()),
            issuer: IssuerUri::parse("https://issuer.example.test", true)?,
            code: Some("opaque-code".to_owned()),
            error: None,
        });
        assert_eq!(redirect.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            redirect.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        let location = redirect
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .ok_or("redirect location is missing")?;
        let location = Url::parse(location)?;
        let fields = location.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(fields.get("fixed").map(AsRef::as_ref), Some("1"));
        assert_eq!(fields.get("code").map(AsRef::as_ref), Some("opaque-code"));
        assert_eq!(fields.get("state").map(AsRef::as_ref), Some("opaque-state"));
        assert_eq!(
            fields.get("iss").map(AsRef::as_ref),
            Some("https://issuer.example.test")
        );
        Ok(())
    }

    #[test]
    fn source_openapi_covers_every_declared_oauth_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let document = crate::openapi_json()?;
        let document: serde_json::Value = serde_json::from_slice(&document)?;
        for path in [
            AUTHORIZATION_SERVER_METADATA_PATH,
            OPENID_CONFIGURATION_PATH,
            PROTECTED_RESOURCE_METADATA_PATH,
            OAUTH_JWKS_PATH,
            OAUTH_AUTHORIZE_PATH,
            OAUTH_INTERACTION_PATH,
            OAUTH_DECISION_PATH,
            OAUTH_TOKEN_PATH,
            OAUTH_REVOKE_PATH,
            OAUTH_GRANTS_PATH,
            OAUTH_GRANT_PATH,
            OAUTH_USERINFO_PATH,
            OAUTH_LOGOUT_PATH,
        ] {
            assert!(
                document["paths"].get(path).is_some(),
                "missing source OpenAPI path {path}"
            );
        }
        assert!(
            document["paths"].get(OAUTH_REGISTER_PATH).is_none(),
            "disabled DCR must not be advertised in the source OpenAPI"
        );
        assert!(document["paths"].get("/mcp").is_none());
        assert!(
            document["paths"]
                .get("/.well-known/oauth-protected-resource/mcp")
                .is_none()
        );
        Ok(())
    }
}
