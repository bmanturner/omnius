use std::{sync::Arc, time::Duration};

use axum::Router;
#[cfg(feature = "api-key")]
use omnius_auth_api_key::{ApiKeyStore, ApiKeyStoreError};
use omnius_auth_core::SessionConfig;
#[cfg(feature = "jwt")]
use omnius_auth_jwt::{JwtBuildError, JwtVerifier};
use omnius_auth_session_postgres::PostgresSessionLifecycle;
use omnius_authz_basic::{
    Action, AuthorizationService, BasicPolicy, IdentifierError, PolicyError, PolicyMatrix,
    ResourceKind,
};
use omnius_config::DeploymentEnvironment;
use omnius_core::{ErrorCode, ServiceError};
use omnius_email::{EmailService, SendEmailHandler, SendEmailJob, email_provider_health_check};
use omnius_health::HealthCheckSpec;
use omnius_jobs_core::{JobHandler, TypedJobHandlerAdapter};
use omnius_outbound_http::OutboundHttpClients;
use omnius_postgres::PostgresPool;
use omnius_runtime::{Criticality, TaskSpec};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AUTH_HTTP_OPERATIONS, AccountEmailConfig, AuthenticatedHttpConfig,
    AuthenticatedHttpConfigError,
    account_auth::{
        AccountAuthBuildError, AccountAuthState, AccountAuthStateInput, account_auth_router,
        account_invitation_router,
    },
    api_key_auth::{
        AuthenticatedIdentityBuildError, CanonicalPrincipalState, canonical_identity_route,
        protected_principal_router,
    },
    auth_openapi_contribution,
    browser_auth::{
        BrowserAuthBuildError, BrowserAuthState, BrowserAuthorization, browser_auth_router,
    },
};

const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const SESSION_CLEANUP_SHUTDOWN: Duration = Duration::from_secs(5);
const EMAIL_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Resources required to build the reusable authenticated HTTP runtime.
pub struct AuthenticatedHttpInput {
    /// Shared PostgreSQL pool for accounts, sessions, and optional API keys.
    pub pool: PostgresPool,
    /// Validated authentication policy and provider configuration.
    pub config: AuthenticatedHttpConfig,
    /// Account email provider, presentation, and template configuration.
    pub account_email: AccountEmailConfig,
    /// Exact origins accepted for unsafe browser-session requests.
    pub trusted_origins: Vec<String>,
    /// Shared outbound clients used by optional remote JWT verification.
    pub outbound_http: Arc<OutboundHttpClients>,
    /// Deployment boundary used for security validation.
    pub deployment: DeploymentEnvironment,
}

/// Reusable account and canonical-principal HTTP runtime.
pub struct AuthenticatedHttpRuntime {
    router: Router,
    public_router: Router,
    protected_auth_routes: Router,
    principal_state: CanonicalPrincipalState,
    browser_auth: BrowserAuthState,
    #[cfg(feature = "api-key")]
    api_key_store: ApiKeyStore,
    pool: PostgresPool,
    session_config: SessionConfig,
    email: EmailService,
    deployment: DeploymentEnvironment,
    local_identity_provider: String,
    session_cleanup_task: TaskSpec,
    openapi: serde_json::Value,
}

impl AuthenticatedHttpRuntime {
    /// Returns the complete public authentication router.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Returns the exact route paths owned by this runtime.
    #[must_use]
    pub fn route_ids(&self) -> &'static [&'static str] {
        crate::openapi::AUTH_HTTP_ROUTE_IDS
    }

    /// Returns the exact method, path, operation ID, and tag contracts.
    #[must_use]
    pub fn expected_operations(&self) -> &'static [omnius_http::ExpectedOperation] {
        AUTH_HTTP_OPERATIONS
    }

    /// Returns the validated auth-only `OpenAPI` document.
    #[must_use]
    pub fn openapi(&self) -> &serde_json::Value {
        &self.openapi
    }

    /// Wraps application routes with canonical principal and session enforcement.
    ///
    /// # Errors
    /// Returns an error when the session manager or revocation guard cannot be built.
    pub fn protect_application_router<S>(
        &self,
        router: Router<S>,
    ) -> Result<Router<S>, AuthenticatedIdentityBuildError>
    where
        S: Clone + Send + Sync + 'static,
    {
        protected_principal_router(self.principal_state.clone(), self.deployment, router)
    }

    /// Builds the PostgreSQL session-store health contribution.
    #[must_use]
    pub fn session_health_check(&self, timeout: Duration) -> HealthCheckSpec {
        omnius_auth_session_postgres::session_store_health_check(self.pool.clone(), timeout)
    }

    /// Builds the configured email-provider health contribution.
    #[must_use]
    pub fn email_health_check(&self) -> HealthCheckSpec {
        email_provider_health_check(self.email.clone(), EMAIL_HEALTH_TIMEOUT)
    }

    /// Builds the real typed email job handler.
    #[must_use]
    pub fn email_job_handler(&self) -> Arc<dyn JobHandler> {
        Arc::new(
            TypedJobHandlerAdapter::<SendEmailJob, SendEmailHandler>::new(SendEmailHandler::new(
                Arc::new(self.email.clone()),
            )),
        )
    }

    /// Borrows the configured email service for graceful shutdown.
    #[must_use]
    pub fn email(&self) -> &EmailService {
        &self.email
    }

    /// Consumes the runtime into application-extension and lifecycle resources.
    #[must_use]
    pub fn into_parts(self) -> AuthenticatedHttpRuntimeParts {
        AuthenticatedHttpRuntimeParts {
            router: self.router,
            public_router: self.public_router,
            protected_auth_routes: self.protected_auth_routes,
            principal_state: self.principal_state,
            browser_auth: self.browser_auth,
            #[cfg(feature = "api-key")]
            api_key_store: self.api_key_store,
            pool: self.pool,
            session_config: self.session_config,
            email: self.email,
            deployment: self.deployment,
            local_identity_provider: self.local_identity_provider,
            session_cleanup_task: self.session_cleanup_task,
            openapi: self.openapi,
        }
    }
}

/// Owned runtime resources used by application-specific extensions such as OAuth.
pub struct AuthenticatedHttpRuntimeParts {
    /// Complete authentication router.
    pub router: Router,
    /// Anonymous login, account, and recovery routes.
    pub public_router: Router,
    /// Routes that must pass canonical-principal enforcement.
    pub protected_auth_routes: Router,
    /// Reusable canonical-principal middleware state.
    pub principal_state: CanonicalPrincipalState,
    /// Browser-session authentication state.
    pub browser_auth: BrowserAuthState,
    #[cfg(feature = "api-key")]
    /// Validated API-key store when that feature is selected.
    pub api_key_store: ApiKeyStore,
    /// Shared PostgreSQL pool.
    pub pool: PostgresPool,
    /// Validated browser-session policy.
    pub session_config: SessionConfig,
    /// Configured email service.
    pub email: EmailService,
    /// Validated deployment environment.
    pub deployment: DeploymentEnvironment,
    /// Canonical local identity provider name.
    pub local_identity_provider: String,
    /// Required supervised session-cleanup task.
    pub session_cleanup_task: TaskSpec,
    /// Validated auth-only `OpenAPI` document.
    pub openapi: serde_json::Value,
}

#[derive(Debug, Error)]
/// Stable construction failures for [`build_authenticated_http`].
pub enum AuthenticatedHttpBuildError {
    /// Authentication configuration is invalid.
    #[error("authenticated HTTP configuration failed: {0}")]
    Config(#[from] AuthenticatedHttpConfigError),
    /// JWT verifier initialization failed.
    #[cfg(feature = "jwt")]
    #[error("JWT verifier initialization failed: {0}")]
    Jwt(#[from] JwtBuildError),
    /// API-key store construction failed.
    #[cfg(feature = "api-key")]
    #[error("API-key store construction failed: {0}")]
    ApiKeyStore(#[from] ApiKeyStoreError),
    /// A fixed browser authorization identifier is invalid.
    #[error("browser authorization identifier is invalid: {0}")]
    BrowserAuthorizationIdentifier(#[from] IdentifierError),
    /// The fixed browser authorization policy is invalid.
    #[error("browser authorization policy is invalid: {0}")]
    BrowserAuthorizationPolicy(#[from] PolicyError),
    /// Browser session routes could not be built.
    #[error("browser authentication composition failed: {0}")]
    BrowserAuth(#[from] BrowserAuthBuildError),
    /// Account routes could not be built.
    #[error("account authentication composition failed: {0}")]
    AccountAuth(#[from] AccountAuthBuildError),
    /// Canonical-principal middleware could not be built.
    #[error("authenticated identity composition failed: {0}")]
    Identity(#[from] AuthenticatedIdentityBuildError),
    /// Auth-only `OpenAPI` generation or validation failed.
    #[error("auth OpenAPI composition failed: {0}")]
    OpenApi(#[from] omnius_openapi::OpenApiError),
    /// The fixed cleanup task error code is invalid.
    #[error("session cleanup task error code is invalid")]
    SessionCleanupCode,
}

/// Builds the reusable authenticated HTTP runtime and lifecycle outputs.
///
/// # Errors
/// Returns [`AuthenticatedHttpBuildError`] when configuration, a provider, routing, lifecycle,
/// or the exact `OpenAPI` contract cannot be built safely.
pub async fn build_authenticated_http(
    input: AuthenticatedHttpInput,
) -> Result<AuthenticatedHttpRuntime, AuthenticatedHttpBuildError> {
    let AuthenticatedHttpInput {
        pool,
        config,
        account_email,
        trusted_origins,
        outbound_http,
        deployment,
    } = input;
    #[cfg(not(feature = "jwt"))]
    let _ = outbound_http;
    config.validate_for(&account_email, deployment)?;
    let AuthenticatedHttpConfig {
        session,
        #[cfg(feature = "jwt")]
        jwt,
        password,
        registration,
        #[cfg(feature = "api-key")]
        api_key,
    } = config;
    let local_identity_provider = registration.local_identity_provider.clone();
    let (password_worker, password_login_provider, password_policy) = password.build()?;
    let (registration, invitation_pepper, account_response_floor) =
        registration.build(deployment, &password_policy)?;
    let (email, account_mail) = account_email.build(deployment)?;
    #[cfg(feature = "jwt")]
    let jwt_verifier = if jwt.enabled {
        Some(JwtVerifier::initialize(&jwt, deployment, outbound_http.as_ref().clone()).await?)
    } else {
        None
    };
    #[cfg(feature = "api-key")]
    let api_key_store = ApiKeyStore::new(pool.clone(), &api_key.build()?)?;
    let browser_auth = BrowserAuthState::new(
        pool.clone(),
        session.clone(),
        password_worker.clone(),
        password_login_provider,
        build_browser_authorization()?,
        trusted_origins.clone(),
    );
    let account_state = AccountAuthState::new(AccountAuthStateInput {
        pool: pool.clone(),
        session_config: session.clone(),
        password_worker,
        registration,
        invitation_pepper,
        response_floor: account_response_floor,
        email: email.clone(),
        mail: account_mail,
    })?;
    let public = browser_auth_router(browser_auth.clone(), deployment)?.merge(account_auth_router(
        account_state.clone(),
        &browser_auth,
        deployment,
    )?);
    let principal_state = CanonicalPrincipalState::new(
        pool.clone(),
        session.clone(),
        #[cfg(feature = "jwt")]
        jwt_verifier,
        #[cfg(feature = "api-key")]
        Some(api_key_store.clone()),
    )
    .with_trusted_origins(trusted_origins);
    let protected_auth_routes =
        canonical_identity_route().merge(account_invitation_router(account_state));
    let router = public.clone().merge(protected_principal_router(
        principal_state.clone(),
        deployment,
        protected_auth_routes.clone(),
    )?);
    let session_cleanup_task = session_cleanup_task(pool.clone())?;
    let openapi = auth_openapi_contribution()?;
    Ok(AuthenticatedHttpRuntime {
        router,
        public_router: public,
        protected_auth_routes,
        principal_state,
        browser_auth,
        #[cfg(feature = "api-key")]
        api_key_store,
        pool,
        session_config: session,
        email,
        deployment,
        local_identity_provider,
        session_cleanup_task,
        openapi,
    })
}

fn build_browser_authorization() -> Result<BrowserAuthorization, AuthenticatedHttpBuildError> {
    let action = Action::new("browser:privileged")?;
    let resource_kind = ResourceKind::new("browser_session")?;
    let authorization = AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(Vec::new())?));
    Ok(BrowserAuthorization::new(
        authorization,
        action,
        resource_kind,
    ))
}

fn session_cleanup_task(pool: PostgresPool) -> Result<TaskSpec, AuthenticatedHttpBuildError> {
    let code = ErrorCode::try_new("SESSION_CLEANUP_FAILED")
        .map_err(|_| AuthenticatedHttpBuildError::SessionCleanupCode)?;
    Ok(TaskSpec::new(
        "session-cleanup",
        "auth-session-postgres",
        Criticality::Required,
        SESSION_CLEANUP_SHUTDOWN,
        move |context| {
            let pool = pool.clone();
            async move {
                let mut interval = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        () = context.draining() => return Ok(()),
                        _ = interval.tick() => {
                            let mut transaction = pool.sqlx_pool().begin().await
                                .map_err(|error| ServiceError::new(code, "session cleanup failed").with_source(error))?;
                            PostgresSessionLifecycle.cleanup_with(&mut transaction, OffsetDateTime::now_utc()).await
                                .map_err(|error| ServiceError::new(code, "session cleanup failed").with_source(error))?;
                            transaction.commit().await
                                .map_err(|error| ServiceError::new(code, "session cleanup failed").with_source(error))?;
                        }
                    }
                }
            }
        },
    ))
}
