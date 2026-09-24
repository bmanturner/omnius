//! Hosted OAuth extension over the reusable authenticated HTTP runtime.

use std::sync::Arc;

use axum::Router;
use futures::future::BoxFuture;
use omnius_auth_http::{
    AuthenticatedHttpRuntime, AuthenticatedHttpRuntimeParts,
    api_key_auth::{
        ApiKeyManagementBuildError, ApiKeyManagementState, AuthenticatedIdentityBuildError,
        BearerTokenVerifier, BearerTokenVerifyError, api_key_management_router,
        protected_principal_router,
    },
};
use omnius_auth_oauth_server::ValidatedAuthorizationServerConfig;
use omnius_email::EmailService;
use omnius_outbound_http::OutboundHttpClients;
use omnius_pagination::CursorCodec;
use omnius_runtime::TaskSpec;
use omnius_tenancy::{TenancyConfig, TenancyStore, TenancyStoreError};
use thiserror::Error;
use url::Url;

use crate::{
    browser_tenancy::{BrowserTenancyState, browser_tenancy_router},
    oauth_provider::{
        OAuthAdapter, OAuthProviderBuildInput, OAuthProviderRuntime, OAuthRateLimiters,
        OAuthResourceTokenVerifier, OAuthResourceVerifyError, build_oauth_provider,
    },
};

impl BearerTokenVerifier for OAuthResourceTokenVerifier {
    fn verify<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<omnius_auth_core::Principal, BearerTokenVerifyError>> {
        Box::pin(async move {
            self.verify(token).await.map_err(|error| match error {
                OAuthResourceVerifyError::Rejected => BearerTokenVerifyError::Rejected,
                OAuthResourceVerifyError::Unavailable => BearerTokenVerifyError::Unavailable,
            })
        })
    }
}

/// OAuth/OIDC resources layered onto an [`AuthenticatedHttpRuntime`].
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
    /// Cursor codec used by service-account and API-key pagination.
    pub cursor_codec: CursorCodec,
    /// Application-owned routes protected by the final OAuth-aware principal boundary.
    pub application_router: Router,
}

/// Fully assembled hosted OAuth/OIDC API and its lifecycle resources.
pub struct OAuthProviderApi {
    routes: Router,
    email: EmailService,
    cleanup_task: TaskSpec,
    session_cleanup_task: TaskSpec,
    _adapter: Arc<OAuthAdapter>,
    api_key_management_openapi: serde_json::Value,
}

impl OAuthProviderApi {
    /// Returns a cloneable router containing every mounted authenticated and OAuth route.
    pub fn router(&self) -> Router {
        self.routes.clone()
    }
    /// Returns the exact API-key management contract mounted by this extension.
    #[must_use]
    pub const fn api_key_management_openapi(&self) -> &serde_json::Value {
        &self.api_key_management_openapi
    }

    /// Consumes the stage into the router, account email service, and OAuth cleanup task.
    #[must_use]
    pub fn into_parts(self) -> OAuthProviderApiParts {
        OAuthProviderApiParts {
            routes: self.routes,
            email: self.email,
            cleanup_task: self.cleanup_task,
            session_cleanup_task: self.session_cleanup_task,
            api_key_management_openapi: self.api_key_management_openapi,
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
    /// Authenticated browser-session cleanup task registered with the runtime supervisor.
    pub session_cleanup_task: TaskSpec,
    /// Exact typed API-key management `OpenAPI` contribution.
    pub api_key_management_openapi: serde_json::Value,
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
    /// The exact API-key management `OpenAPI` contribution is invalid.
    #[error("API-key management OpenAPI composition failed: {0}")]
    ApiKeyManagementOpenApi(omnius_openapi::OpenApiError),
}

/// Extends an authenticated API with tenancy selection and hosted OAuth/OIDC routes.
///
/// # Errors
///
/// Returns [`OAuthProviderBuildError`] if OAuth state, session layers, cleanup, or the
/// OAuth-aware protected-principal boundary cannot be constructed.
pub fn extend_oauth_provider(
    authenticated: AuthenticatedHttpRuntime,
    input: OAuthProviderInput,
) -> Result<OAuthProviderApi, OAuthProviderBuildError> {
    let AuthenticatedHttpRuntimeParts {
        router: _,
        public_router,
        protected_auth_routes,
        principal_state,
        browser_auth,
        api_key_store,
        pool,
        session_config,
        email,
        deployment,
        local_identity_provider,
        session_cleanup_task,
        openapi: _,
    } = authenticated.into_parts();
    let OAuthProviderInput {
        authorization_server,
        outbound_http,
        rate_limits,
        authorization_ui,
        tenancy_config,
        cursor_codec,
        application_router,
    } = input;
    let tenancy_store = TenancyStore::new(pool.clone(), &tenancy_config)?;
    let api_key_management =
        ApiKeyManagementState::new(api_key_store, tenancy_store.clone(), cursor_codec)?;
    let api_key_management_openapi = omnius_auth_http::api_key_management_openapi_contribution()
        .map_err(OAuthProviderBuildError::ApiKeyManagementOpenApi)?;
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
    let principal_state = principal_state.with_bearer_token_verifier(Arc::new(resource_verifier));
    let protected_routes = protected_auth_routes
        .merge(api_key_management_router(api_key_management))
        .merge(application_router)
        .merge(browser_tenancy_router(BrowserTenancyState::new(
            tenancy_store,
        )));
    let routes = public_router
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
        session_cleanup_task,
        api_key_management_openapi,
        _adapter: adapter,
    })
}
