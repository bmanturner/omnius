//! Typed composition stages for authenticated and hosted OAuth reference APIs.

use std::{sync::Arc, time::Duration};

use axum::Router;
use omnius_auth_api_key::{ApiKeyConfig, ApiKeyStore, ApiKeyStoreError};
use omnius_auth_core::SessionConfig;
use omnius_auth_jwt::JwtVerifier;
use omnius_auth_oauth_server::ValidatedAuthorizationServerConfig;
use omnius_auth_password::{InvitationTokenPepper, PasswordWorker, RegistrationPolicy};
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, IdentifierError, PolicyError, PolicyMatrix,
    ResourceKind,
};
use omnius_config::DeploymentEnvironment;
use omnius_core::SystemClock;
use omnius_email::EmailService;
use omnius_idempotency::PostgresIdempotencyStore;
use omnius_outbound_http::OutboundHttpClients;
use omnius_pagination::CursorCodec;
use omnius_postgres::PostgresPool;
use omnius_runtime::TaskSpec;
use omnius_tenancy::{TenancyConfig, TenancyStore, TenancyStoreError};
use thiserror::Error;
use url::Url;

use crate::{
    ReferenceApiState,
    account_auth::{
        AccountAuthBuildError, AccountAuthState, AccountAuthStateInput, AccountMailPresentation,
        account_auth_router, account_invitation_router,
    },
    api_key_auth::{
        ApiKeyManagementBuildError, ApiKeyManagementState, AuthenticatedIdentityBuildError,
        CanonicalPrincipalState, api_key_management_router, canonical_identity_route,
        protected_principal_router,
    },
    browser_auth::{
        BrowserAuthBuildError, BrowserAuthState, BrowserAuthorization, PasswordLoginProvider,
        browser_auth_router,
    },
    browser_tenancy::{BrowserTenancyState, browser_tenancy_router},
    oauth_provider::{
        OAuthAdapter, OAuthProviderBuildInput, OAuthProviderRuntime, OAuthRateLimiters,
        build_oauth_provider,
    },
    optional_identity::OptionalIdentityContext,
    reference_router,
};

/// Resources and validated policy required to assemble the authenticated API stage.
pub struct AuthenticatedApiInput {
    /// Shared PostgreSQL pool for all durable reference and authentication state.
    pub pool: PostgresPool,
    /// Validated browser-session policy.
    pub session_config: SessionConfig,
    /// Optional JWT verifier; `None` keeps bearer JWT authentication unavailable.
    pub jwt_verifier: Option<JwtVerifier>,
    /// Validated API-key persistence and verification policy.
    pub api_key_config: ApiKeyConfig,
    /// Bounded password hashing and verification worker.
    pub password_worker: PasswordWorker,
    /// Validated password identity-provider namespace.
    pub password_login_provider: PasswordLoginProvider,
    /// Validated local-account registration policy.
    pub registration: RegistrationPolicy,
    /// Secret used to digest invitation tokens.
    pub invitation_pepper: InvitationTokenPepper,
    /// Minimum duration for enumeration-safe account responses.
    pub account_response_floor: Duration,
    /// Account email delivery service.
    pub email: EmailService,
    /// Fixed account email presentation.
    pub account_mail: AccountMailPresentation,
    /// Exact trusted browser origins.
    pub trusted_origins: Vec<String>,
    /// Transactional idempotency store for reference-record creation.
    pub idempotency_store: PostgresIdempotencyStore,
    /// Cursor codec shared by reference and API-key pagination.
    pub cursor_codec: CursorCodec,
    /// Deployment policy used for secure session construction.
    pub deployment: DeploymentEnvironment,
    /// Canonical local provider persisted by registration and later OAuth grants.
    pub local_identity_provider: String,
}

/// Fully assembled authenticated API, ready to mount directly or extend with OAuth.
pub struct AuthenticatedApi {
    routes: Router,
    public_routes: Router,
    protected_routes: Router,
    principal_state: CanonicalPrincipalState,
    browser_auth: BrowserAuthState,
    api_key_store: ApiKeyStore,
    cursor_codec: CursorCodec,
    pool: PostgresPool,
    session_config: SessionConfig,
    email: EmailService,
    deployment: DeploymentEnvironment,
    local_identity_provider: String,
}

impl AuthenticatedApi {
    /// Returns a cloneable router containing only authenticated-stage routes.
    #[must_use]
    pub fn router(&self) -> Router {
        self.routes.clone()
    }

    /// Consumes the stage and returns its mounted router.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.routes
    }

    /// Returns the account email service owned by this stage.
    #[must_use]
    pub const fn email(&self) -> &EmailService {
        &self.email
    }

    /// Returns the canonical stores and principal lifecycle used to add optional identity routes.
    #[must_use]
    pub fn optional_identity_context(&self) -> OptionalIdentityContext {
        OptionalIdentityContext::new(
            self.pool.clone(),
            self.principal_state.clone(),
            self.browser_auth.clone(),
            self.deployment,
        )
    }
}

/// Stable construction failures for [`build_authenticated_api`].
#[derive(Debug, Error)]
pub enum AuthenticatedApiBuildError {
    /// Password and registration provider namespaces differ.
    #[error("registration identity provider must exactly match the password login provider")]
    LocalIdentityProviderMismatch,
    /// The local identity provider is URL-shaped rather than a local namespace.
    #[error("local identity provider namespaces must not be URL-shaped")]
    LocalIdentityProviderUrl,
    /// A compiled browser authorization identifier is invalid.
    #[error("browser authorization identifier is invalid: {0}")]
    BrowserAuthorizationIdentifier(#[from] IdentifierError),
    /// The fail-closed browser authorization policy is invalid.
    #[error("browser authorization policy is invalid: {0}")]
    BrowserAuthorizationPolicy(#[from] PolicyError),
    /// API-key persistence could not be constructed.
    #[error("API-key store construction failed: {0}")]
    ApiKeyStore(#[from] ApiKeyStoreError),
    /// Browser authentication routes or session layers could not be constructed.
    #[error("browser authentication composition failed: {0}")]
    BrowserAuth(#[from] BrowserAuthBuildError),
    /// Account lifecycle state could not be constructed.
    #[error("account authentication composition failed: {0}")]
    AccountAuth(#[from] AccountAuthBuildError),
    /// The canonical protected-principal boundary could not be constructed.
    #[error("authenticated identity composition failed: {0}")]
    Identity(#[from] AuthenticatedIdentityBuildError),
}

/// Builds password/session/API-key authorization, account, and protected reference routes.
///
/// # Errors
///
/// Returns [`AuthenticatedApiBuildError`] when provider namespaces, stores, fixed policies,
/// account state, or maintained session layers cannot be assembled.
pub fn build_authenticated_api(
    input: AuthenticatedApiInput,
) -> Result<AuthenticatedApi, AuthenticatedApiBuildError> {
    let AuthenticatedApiInput {
        pool,
        session_config,
        jwt_verifier,
        api_key_config,
        password_worker,
        password_login_provider,
        registration,
        invitation_pepper,
        account_response_floor,
        email,
        account_mail,
        trusted_origins,
        idempotency_store,
        cursor_codec,
        deployment,
        local_identity_provider,
    } = input;

    validate_local_identity_provider(password_login_provider.as_str(), &local_identity_provider)?;

    let api_key_store = ApiKeyStore::new(pool.clone(), &api_key_config)?;
    let browser_auth = BrowserAuthState::new(
        pool.clone(),
        session_config.clone(),
        password_worker.clone(),
        password_login_provider,
        build_browser_authorization()?,
        trusted_origins.clone(),
    );
    let account_state = AccountAuthState::new(AccountAuthStateInput {
        pool: pool.clone(),
        session_config: session_config.clone(),
        password_worker,
        registration,
        invitation_pepper,
        response_floor: account_response_floor,
        email: email.clone(),
        mail: account_mail,
    })?;
    let invitation_routes = account_invitation_router(account_state.clone());
    let account_routes = account_auth_router(account_state, &browser_auth, deployment)?;
    let reference_state = ReferenceApiState::new(
        pool.clone(),
        cursor_codec.clone(),
        idempotency_store,
        Arc::new(SystemClock),
    );
    let protected_routes = canonical_identity_route()
        .merge(invitation_routes)
        .merge(reference_router(reference_state));
    let principal_state = CanonicalPrincipalState::new(
        pool.clone(),
        session_config.clone(),
        jwt_verifier,
        Some(api_key_store.clone()),
    )
    .with_trusted_origins(trusted_origins);
    let public_routes =
        browser_auth_router(browser_auth.clone(), deployment)?.merge(account_routes);
    let routes = public_routes.clone().merge(protected_principal_router(
        principal_state.clone(),
        deployment,
        protected_routes.clone(),
    )?);

    Ok(AuthenticatedApi {
        routes,
        public_routes,
        protected_routes,
        principal_state,
        browser_auth,
        api_key_store,
        cursor_codec,
        pool,
        session_config,
        email,
        deployment,
        local_identity_provider,
    })
}

/// OAuth/OIDC resources layered onto an [`AuthenticatedApi`].
pub struct OAuthProviderInput {
    /// Validated hosted authorization-server policy.
    pub authorization_server: ValidatedAuthorizationServerConfig,
    /// Restricted outbound clients used for OAuth client metadata resolution.
    pub outbound_http: Arc<OutboundHttpClients>,
    /// Bounded per-operation OAuth rate limiters.
    pub rate_limits: OAuthRateLimiters,
    /// Same-origin browser authorization UI.
    pub authorization_ui: Url,
    /// Validated tenancy persistence policy for tenant selection and API-key ownership checks.
    pub tenancy_config: TenancyConfig,
}

/// Fully assembled hosted OAuth/OIDC API and its lifecycle resources.
pub struct OAuthProviderApi {
    routes: Router,
    email: EmailService,
    cleanup_task: TaskSpec,
    _adapter: Arc<OAuthAdapter>,
}

impl OAuthProviderApi {
    /// Returns a cloneable router containing every mounted authenticated and OAuth route.
    #[must_use]
    pub fn router(&self) -> Router {
        self.routes.clone()
    }

    /// Consumes the stage into the router, account email service, and OAuth cleanup task.
    #[must_use]
    pub fn into_parts(self) -> OAuthProviderApiParts {
        OAuthProviderApiParts {
            routes: self.routes,
            email: self.email,
            cleanup_task: self.cleanup_task,
        }
    }
}

/// Application-owned lifecycle resources returned by [`OAuthProviderApi::into_parts`].
pub struct OAuthProviderApiParts {
    /// Router containing every route mounted by both composition stages.
    pub routes: Router,
    /// Account email service that must be drained during shutdown.
    pub email: EmailService,
    /// Hosted OAuth cleanup task registered with the runtime supervisor.
    pub cleanup_task: TaskSpec,
}

/// Stable construction failures for [`extend_oauth_provider`].
#[derive(Debug, Error)]
pub enum OAuthProviderBuildError {
    /// Tenancy persistence could not be constructed.
    #[error("tenancy store construction failed: {0}")]
    TenancyStore(#[from] TenancyStoreError),
    /// API-key management policy construction failed.
    #[error("API-key management policy construction failed: {0}")]
    ApiKeyManagement(#[from] ApiKeyManagementBuildError),
    /// Hosted OAuth/OIDC state or routes could not be constructed.
    #[error("OAuth provider composition failed: {0}")]
    Provider(#[from] crate::oauth_provider::OAuthProviderBuildError),
    /// The OAuth-aware canonical principal boundary could not be constructed.
    #[error("OAuth-aware identity composition failed: {0}")]
    Identity(#[from] AuthenticatedIdentityBuildError),
}

/// Extends an authenticated API with tenancy selection and hosted OAuth/OIDC routes.
///
/// # Errors
///
/// Returns [`OAuthProviderBuildError`] if OAuth state, session layers, cleanup, or the
/// OAuth-aware protected-principal boundary cannot be constructed.
pub fn extend_oauth_provider(
    authenticated: AuthenticatedApi,
    input: OAuthProviderInput,
) -> Result<OAuthProviderApi, OAuthProviderBuildError> {
    let AuthenticatedApi {
        routes: _,
        public_routes,
        protected_routes,
        principal_state,
        browser_auth,
        api_key_store,
        cursor_codec,
        pool,
        session_config,
        email,
        deployment,
        local_identity_provider,
    } = authenticated;
    let OAuthProviderInput {
        authorization_server,
        outbound_http,
        rate_limits,
        authorization_ui,
        tenancy_config,
    } = input;
    let tenancy_store = TenancyStore::new(pool.clone(), &tenancy_config)?;
    let api_key_management =
        ApiKeyManagementState::new(api_key_store, tenancy_store.clone(), cursor_codec)?;
    let OAuthProviderRuntime {
        routes: oauth_routes,
        resource_verifier,
        cleanup_task,
        adapter,
    } = build_oauth_provider(OAuthProviderBuildInput {
        config: authorization_server,
        pool,
        outbound_http,
        session_config,
        browser_auth,
        local_identity_provider,
        authorization_ui,
        deployment,
        rate_limits,
    })?;
    let principal_state = principal_state.with_oauth_resource_verifier(resource_verifier);
    let protected_routes = protected_routes
        .merge(api_key_management_router(api_key_management))
        .merge(browser_tenancy_router(BrowserTenancyState::new(
            tenancy_store,
        )));
    let routes = public_routes
        .merge(oauth_routes)
        .merge(protected_principal_router(
            principal_state,
            deployment,
            protected_routes,
        )?);

    Ok(OAuthProviderApi {
        routes,
        email,
        cleanup_task,
        _adapter: adapter,
    })
}

fn build_browser_authorization() -> Result<BrowserAuthorization, AuthenticatedApiBuildError> {
    let action = Action::new("browser:privileged")?;
    let resource_kind = ResourceKind::new("browser_session")?;
    let deny_unless_explicit =
        AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(Vec::new())?));
    Ok(BrowserAuthorization::new(
        deny_unless_explicit,
        action,
        resource_kind,
    ))
}

fn validate_local_identity_provider(
    password_provider: &str,
    registration_provider: &str,
) -> Result<(), AuthenticatedApiBuildError> {
    if password_provider != registration_provider {
        return Err(AuthenticatedApiBuildError::LocalIdentityProviderMismatch);
    }
    if Url::parse(password_provider).is_ok()
        || password_provider.starts_with("//")
        || password_provider.contains("://")
    {
        return Err(AuthenticatedApiBuildError::LocalIdentityProviderUrl);
    }
    Ok(())
}
