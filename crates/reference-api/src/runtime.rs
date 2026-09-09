#![expect(
    missing_docs,
    reason = "raw configuration fields mirror provider contracts"
)]

use std::{sync::Arc, time::Duration};

use axum::Router;
use omnius_auth_http::{
    AccountEmailConfig, AuthenticatedHttpConfig, AuthenticatedHttpConfigError,
    AuthenticatedHttpRuntime,
};
use omnius_auth_oauth_server::{
    AuthorizationServerConfig, AuthorizationServerConfigError, ValidatedAuthorizationServerConfig,
};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_outbound_http::OutboundHttpClients;
use omnius_pagination::{CursorCodec, CursorSigningKey, CursorSigningKeyError};
use omnius_rate_limit_local::{
    LocalRateLimitConfigError, LocalRateLimitPolicy, LocalRateLimiter, RateLimitIdentityKind,
    RateLimitOperation,
};
use omnius_tenancy::{TenancyConfig, TenancyConfigError};
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

use crate::{
    OAuthProviderApi, OAuthProviderBuildError, OAuthProviderInput, extend_oauth_provider,
    oauth_provider::{
        OAuthRateLimiters, OAuthResourceVerifierBuildError, validate_reference_oauth_resources,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    #[serde(flatten)]
    pub http: AuthenticatedHttpConfig,
    pub authorization_server: AuthorizationServerConfig,
    pub oauth_rate_limit: OAuthRateLimitConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationConfig {
    cursor_signing_key: SecretString,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRateLimitConfig {
    pub authorize: OAuthRateLimitPolicyConfig,
    pub token: OAuthRateLimitPolicyConfig,
    pub register: OAuthRateLimitPolicyConfig,
    pub revoke: OAuthRateLimitPolicyConfig,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthRateLimitPolicyConfig {
    #[serde(with = "humantime_serde")]
    pub replenish_every: Duration,
    pub burst_size: u32,
    pub identity_buckets: u32,
}

#[derive(Debug, Error)]
pub enum ReferenceRuntimeConfigError {
    #[error("authenticated HTTP configuration failed: {0}")]
    AuthenticatedHttp(#[from] AuthenticatedHttpConfigError),
    #[error("pagination configuration failed: {0}")]
    Pagination(#[from] CursorSigningKeyError),
    #[error("browser tenancy configuration failed: {0}")]
    Tenancy(#[from] TenancyConfigError),
    #[error("hosted OAuth requires browser tenancy support to be enabled")]
    TenancyDisabled,
    #[error("authorization-server configuration failed: {0}")]
    AuthorizationServer(#[from] AuthorizationServerConfigError),
    #[error("oauth-provider profile requires the authorization server to be enabled")]
    AuthorizationServerDisabled,
    #[error("reference OAuth resources are invalid: {0}")]
    OAuthResources(#[from] OAuthResourceVerifierBuildError),
    #[error("authorization UI origin must exactly match the configured issuer origin")]
    AuthorizationUiOrigin,
    #[error("authorization-server rate-limit configuration failed: {0}")]
    OAuthRateLimit(#[from] LocalRateLimitConfigError),
}

impl AuthConfig {
    /// Validates the authenticated HTTP and email configuration.
    ///
    /// # Errors
    /// Returns an error when the selected authentication or email policy is invalid.
    pub fn validate_authenticated_for(
        &self,
        email: &AccountEmailConfig,
        _pagination: &PaginationConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<(), ReferenceRuntimeConfigError> {
        self.http.validate_for(email, deployment)?;
        Ok(())
    }

    /// Validates and builds the hosted OAuth configuration.
    ///
    /// # Errors
    /// Returns an error when OAuth, tenancy, resource, or rate-limit policy is invalid.
    pub fn validate_oauth_for(
        &self,
        tenancy: &TenancyConfig,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthorizationServerConfig, ReferenceRuntimeConfigError> {
        validate_oauth_configuration(
            &self.authorization_server,
            &self.oauth_rate_limit,
            self.http.registration.public_app_url.as_ref(),
            tenancy,
            deployment,
            now,
        )
    }

    /// Builds the validated hosted authorization-server configuration.
    ///
    /// # Errors
    /// Returns an error when the server is disabled or its resource declarations are invalid.
    pub fn validated_authorization_server(
        &self,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthorizationServerConfig, ReferenceRuntimeConfigError> {
        let validated = self
            .authorization_server
            .build_for(deployment, now)?
            .ok_or(ReferenceRuntimeConfigError::AuthorizationServerDisabled)?;
        validate_reference_oauth_resources(&validated)?;
        Ok(validated)
    }
}

impl OAuthRateLimitConfig {
    /// Builds the bounded OAuth endpoint rate limiters.
    ///
    /// # Errors
    /// Returns an error when any limiter policy is invalid.
    pub fn build(self) -> Result<OAuthRateLimiters, LocalRateLimitConfigError> {
        Ok(OAuthRateLimiters {
            authorize: self.authorize.build(RateLimitOperation::OAuthAuthorize)?,
            token: self.token.build(RateLimitOperation::OAuthToken)?,
            register: self
                .register
                .build(RateLimitOperation::OAuthClientRegistration)?,
            revoke: self.revoke.build(RateLimitOperation::OAuthRevoke)?,
        })
    }
}

impl OAuthRateLimitPolicyConfig {
    fn build(
        self,
        operation: RateLimitOperation,
    ) -> Result<LocalRateLimiter, LocalRateLimitConfigError> {
        LocalRateLimiter::new(
            operation,
            RateLimitIdentityKind::OAuthClientIp,
            LocalRateLimitPolicy {
                replenish_every: self.replenish_every,
                burst_size: self.burst_size,
                identity_buckets: self.identity_buckets,
            },
        )
    }
}

impl PaginationConfig {
    /// Builds the authenticated pagination cursor codec.
    ///
    /// # Errors
    /// Returns an error when the cursor signing key is invalid.
    pub fn cursor_codec(&self) -> Result<CursorCodec, ReferenceRuntimeConfigError> {
        Ok(CursorCodec::new(CursorSigningKey::from_slice(
            self.cursor_signing_key.expose_secret().as_bytes(),
        )?))
    }
}

pub struct OAuthRuntimeInput {
    pub authorization_server: AuthorizationServerConfig,
    pub rate_limits: OAuthRateLimitConfig,
    pub authorization_ui: Option<Url>,
    pub outbound_http: Arc<OutboundHttpClients>,
    pub deployment: DeploymentEnvironment,
    pub tenancy: TenancyConfig,
    pub cursor_codec: CursorCodec,
    pub application_router: Router,
}

#[derive(Debug, Error)]
pub enum OAuthRuntimeBuildError {
    #[error("OAuth runtime configuration failed: {0}")]
    Config(#[from] ReferenceRuntimeConfigError),
    #[error("OAuth API extension failed: {0}")]
    OAuthProvider(#[from] OAuthProviderBuildError),
}

/// Extends the authenticated runtime with hosted OAuth and application routes.
///
/// # Errors
/// Returns an error when configuration validation or OAuth composition fails.
pub fn extend_oauth_runtime(
    authenticated: AuthenticatedHttpRuntime,
    input: OAuthRuntimeInput,
) -> Result<OAuthProviderApi, OAuthRuntimeBuildError> {
    let validated = validate_oauth_configuration(
        &input.authorization_server,
        &input.rate_limits,
        input.authorization_ui.as_ref(),
        &input.tenancy,
        input.deployment,
        OffsetDateTime::now_utc(),
    )?;
    Ok(extend_oauth_provider(
        authenticated,
        OAuthProviderInput {
            authorization_server: validated,
            outbound_http: input.outbound_http,
            rate_limits: input
                .rate_limits
                .build()
                .map_err(ReferenceRuntimeConfigError::from)?,
            authorization_ui: input
                .authorization_ui
                .ok_or(ReferenceRuntimeConfigError::AuthorizationUiOrigin)?,
            tenancy_config: input.tenancy,
            cursor_codec: input.cursor_codec,
            application_router: input.application_router,
        },
    )?)
}

fn validate_oauth_configuration(
    config: &AuthorizationServerConfig,
    rate_limits: &OAuthRateLimitConfig,
    authorization_ui: Option<&Url>,
    tenancy: &TenancyConfig,
    deployment: DeploymentEnvironment,
    now: OffsetDateTime,
) -> Result<ValidatedAuthorizationServerConfig, ReferenceRuntimeConfigError> {
    tenancy.validate()?;
    if !tenancy.enabled {
        return Err(ReferenceRuntimeConfigError::TenancyDisabled);
    }
    let validated = config
        .build_for(deployment, now)?
        .ok_or(ReferenceRuntimeConfigError::AuthorizationServerDisabled)?;
    validate_reference_oauth_resources(&validated)?;
    let authorization_ui =
        authorization_ui.ok_or(ReferenceRuntimeConfigError::AuthorizationUiOrigin)?;
    let issuer = Url::parse(validated.issuer().as_str())
        .map_err(|_| ReferenceRuntimeConfigError::AuthorizationUiOrigin)?;
    if authorization_ui.origin() != issuer.origin() {
        return Err(ReferenceRuntimeConfigError::AuthorizationUiOrigin);
    }
    let _limiters = rate_limits.build()?;
    Ok(validated)
}
