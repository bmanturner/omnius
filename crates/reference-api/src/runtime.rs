//! Strict raw configuration and staged authenticated/OAuth runtime construction.
#![expect(
    missing_docs,
    reason = "raw configuration fields mirror their owning provider contracts"
)]

use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_api_key::{ApiKeyConfig, ApiKeyConfigError};
use omnius_auth_core::{SessionConfig, SessionConfigError};
use omnius_auth_jwt::{JwtBuildError, JwtConfig, JwtConfigError, JwtVerifier};
use omnius_auth_oauth_server::{
    AuthorizationServerConfig, AuthorizationServerConfigError, ValidatedAuthorizationServerConfig,
};
use omnius_auth_password::{
    InvitationTokenError, InvitationTokenPepper, PasswordEngine, PasswordError, PasswordPepper,
    PasswordPolicy, PasswordPolicyConfig, PasswordPolicyError, PasswordWorker, RegistrationMode,
    RegistrationPolicy, RegistrationPolicyConfig, RegistrationPolicyError,
};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_email::{
    CustomHeaderPolicy, EmailConfig, EmailError, EmailLimits, EmailProviderConfig, EmailService,
    MailboxAddress, TemplateConfig,
};
use omnius_idempotency::{IdempotencyConfig, IdempotencyConfigError, PostgresIdempotencyStore};
use omnius_outbound_http::OutboundHttpClients;
use omnius_pagination::{CursorCodec, CursorSigningKey, CursorSigningKeyError};
use omnius_postgres::PostgresPool;
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
    AuthenticatedApi, AuthenticatedApiBuildError, AuthenticatedApiInput, OAuthProviderApi,
    OAuthProviderBuildError, OAuthProviderInput,
    account_auth::{AccountAuthBuildError, AccountMailPresentation},
    browser_auth::{PasswordLoginProvider, PasswordLoginProviderError},
    build_authenticated_api, extend_oauth_provider,
    oauth_provider::OAuthRateLimiters,
};

const MAX_PASSWORD_WORKER_CONCURRENCY: usize = 16;
const MAX_PASSWORD_WORKER_MEMORY_KIB: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub session: SessionConfig,
    pub jwt: JwtConfig,
    pub password: PasswordConfig,
    pub registration: RegistrationConfig,
    pub api_key: ApiKeyApplicationConfig,
    pub authorization_server: AuthorizationServerConfig,
    pub oauth_rate_limit: OAuthRateLimitConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationConfig {
    cursor_signing_key: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfig {
    pub login_provider: String,
    pub max_concurrency: NonZeroUsize,
    pub policy: PasswordPolicyConfig,
    pub pepper: PasswordPepperConfig,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPepperConfig {
    pub version: u32,
    pub secret: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyApplicationConfig {
    pub enabled: bool,
    pub pepper: SecretString,
    pub max_scopes: usize,
    #[serde(with = "humantime_serde")]
    pub max_key_lifetime: Duration,
    #[serde(with = "humantime_serde")]
    pub last_used_write_interval: Duration,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationConfig {
    pub mode: Option<RegistrationMode>,
    #[serde(default = "default_local_identity_provider")]
    pub local_identity_provider: String,
    #[serde(default = "default_invitation_ttl", with = "humantime_serde")]
    pub invitation_ttl: Duration,
    pub public_app_url: Option<Url>,
    pub invitation_token_pepper: SecretString,
    #[serde(default = "default_account_response_floor", with = "humantime_serde")]
    pub response_floor: Duration,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEmailConfig {
    pub from: MailboxAddress,
    pub provider: EmailProviderConfig,
    pub templates: TemplateConfig,
    #[serde(default)]
    pub custom_headers: CustomHeaderPolicy,
    #[serde(default)]
    pub limits: EmailLimits,
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
    #[error("browser session support must be enabled")]
    SessionDisabled,
    #[error("browser session configuration failed: {0}")]
    Session(#[from] SessionConfigError),
    #[error("JWT verifier configuration failed: {0}")]
    Jwt(#[from] JwtConfigError),
    #[error("API-key configuration failed: {0}")]
    ApiKey(#[from] ApiKeyConfigError),
    #[error("API-key pepper must be canonical unpadded base64url encoding of exactly 32 bytes")]
    ApiKeyPepper,
    #[error("password policy configuration failed: {0}")]
    PasswordPolicy(#[from] PasswordPolicyError),
    #[error("password worker initialization failed: {0}")]
    Password(#[from] PasswordError),
    #[error("password worker concurrency or aggregate memory exceeds its hard bound")]
    PasswordWorkerConcurrency,
    #[error("password login provider configuration failed: {0}")]
    PasswordLoginProvider(#[from] PasswordLoginProviderError),
    #[error("account registration policy configuration failed: {0}")]
    RegistrationPolicy(#[from] RegistrationPolicyError),
    #[error("registration invitation secret configuration failed: {0}")]
    InvitationToken(#[from] InvitationTokenError),
    #[error("account discovery response floor is invalid")]
    AccountResponseFloor,
    #[error("registration identity provider must exactly match the password login provider")]
    LocalIdentityProviderMismatch,
    #[error("local identity provider namespaces must not be URL-shaped")]
    LocalIdentityProviderUrl,
    #[error("account email configuration or construction failed: {0}")]
    AccountEmail(#[from] EmailError),
    #[error("account email template allowlist must contain exactly the three account templates")]
    AccountEmailTemplates,
    #[error("account email presentation is invalid: {0}")]
    AccountMail(#[from] AccountAuthBuildError),
    #[error("idempotency configuration failed: {0}")]
    Idempotency(#[from] IdempotencyConfigError),
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
    #[error("authorization UI origin must exactly match the configured issuer origin")]
    AuthorizationUiOrigin,
    #[error("authorization-server rate-limit configuration failed: {0}")]
    OAuthRateLimit(#[from] LocalRateLimitConfigError),
}

pub struct AuthenticatedRuntimeInput {
    pub pool: PostgresPool,
    pub auth: AuthConfig,
    pub account_email: AccountEmailConfig,
    pub trusted_origins: Vec<String>,
    pub idempotency: IdempotencyConfig,
    pub pagination: PaginationConfig,
    pub outbound_http: Arc<OutboundHttpClients>,
    pub deployment: DeploymentEnvironment,
}

pub struct AuthenticatedRuntime {
    api: AuthenticatedApi,
    oauth: PendingOAuthRuntime,
}

struct PendingOAuthRuntime {
    authorization_server: AuthorizationServerConfig,
    rate_limits: OAuthRateLimitConfig,
    authorization_ui: Option<Url>,
    outbound_http: Arc<OutboundHttpClients>,
    deployment: DeploymentEnvironment,
}

impl AuthenticatedRuntime {
    #[must_use]
    pub fn router(&self) -> axum::Router {
        self.api.router()
    }

    #[must_use]
    pub fn into_api(self) -> AuthenticatedApi {
        self.api
    }
}

#[derive(Debug, Error)]
pub enum AuthenticatedRuntimeBuildError {
    #[error("authenticated runtime configuration failed: {0}")]
    Config(#[from] ReferenceRuntimeConfigError),
    #[error("JWT verifier initialization failed: {0}")]
    Jwt(#[from] JwtBuildError),
    #[error("authenticated API composition failed: {0}")]
    AuthenticatedApi(#[from] AuthenticatedApiBuildError),
}

pub async fn build_authenticated_runtime(
    input: AuthenticatedRuntimeInput,
) -> Result<AuthenticatedRuntime, AuthenticatedRuntimeBuildError> {
    let AuthenticatedRuntimeInput {
        pool,
        auth,
        account_email,
        trusted_origins,
        idempotency,
        pagination,
        outbound_http,
        deployment,
    } = input;
    auth.validate_authenticated_for(&account_email, &pagination, deployment)?;
    let AuthConfig {
        session,
        jwt,
        password,
        registration,
        api_key,
        authorization_server,
        oauth_rate_limit,
    } = auth;
    let authorization_ui = registration.public_app_url.clone();
    let local_identity_provider = registration.local_identity_provider.clone();
    let (password_worker, password_login_provider, password_policy) = password.build()?;
    let (registration, invitation_pepper, account_response_floor) =
        registration.build(deployment, &password_policy)?;
    let (email, account_mail) = account_email.build(deployment)?;
    let jwt_verifier = if jwt.enabled {
        Some(JwtVerifier::initialize(&jwt, deployment, outbound_http.as_ref().clone()).await?)
    } else {
        None
    };
    let api = build_authenticated_api(AuthenticatedApiInput {
        pool,
        session_config: session,
        jwt_verifier,
        api_key_config: api_key.build()?,
        password_worker,
        password_login_provider,
        registration,
        invitation_pepper,
        account_response_floor,
        email,
        account_mail,
        trusted_origins,
        idempotency_store: PostgresIdempotencyStore::new(idempotency)
            .map_err(ReferenceRuntimeConfigError::from)?,
        cursor_codec: CursorCodec::new(
            pagination
                .signing_key()
                .map_err(ReferenceRuntimeConfigError::from)?,
        ),
        deployment,
        local_identity_provider,
    })?;
    Ok(AuthenticatedRuntime {
        api,
        oauth: PendingOAuthRuntime {
            authorization_server,
            rate_limits: oauth_rate_limit,
            authorization_ui,
            outbound_http,
            deployment,
        },
    })
}

pub struct OAuthRuntimeInput {
    pub tenancy: TenancyConfig,
}

#[derive(Debug, Error)]
pub enum OAuthRuntimeBuildError {
    #[error("OAuth runtime configuration failed: {0}")]
    Config(#[from] ReferenceRuntimeConfigError),
    #[error("OAuth API extension failed: {0}")]
    OAuthProvider(#[from] OAuthProviderBuildError),
}

pub fn extend_oauth_runtime(
    authenticated: AuthenticatedRuntime,
    input: OAuthRuntimeInput,
) -> Result<OAuthProviderApi, OAuthRuntimeBuildError> {
    let PendingOAuthRuntime {
        authorization_server,
        rate_limits,
        authorization_ui,
        outbound_http,
        deployment,
    } = authenticated.oauth;
    let validated = validate_oauth_configuration(
        &authorization_server,
        &rate_limits,
        authorization_ui.as_ref(),
        &input.tenancy,
        deployment,
        OffsetDateTime::now_utc(),
    )?;
    Ok(extend_oauth_provider(
        authenticated.api,
        OAuthProviderInput {
            authorization_server: validated,
            outbound_http,
            rate_limits: rate_limits
                .build()
                .map_err(ReferenceRuntimeConfigError::from)?,
            authorization_ui: authorization_ui
                .ok_or(ReferenceRuntimeConfigError::AuthorizationUiOrigin)?,
            tenancy_config: input.tenancy,
        },
    )?)
}

impl AuthConfig {
    pub fn validate_authenticated_for(
        &self,
        email: &AccountEmailConfig,
        pagination: &PaginationConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<(), ReferenceRuntimeConfigError> {
        if !self.session.enabled {
            return Err(ReferenceRuntimeConfigError::SessionDisabled);
        }
        self.session.validate_for(deployment)?;
        if self.jwt.enabled {
            self.jwt.validate_for(deployment)?;
        }
        self.api_key.validate()?;
        let password_policy = self.password.validate()?;
        let _registration = self.registration.validate(deployment, &password_policy)?;
        validate_local_identity_provider(
            &self.password.login_provider,
            &self.registration.local_identity_provider,
        )?;
        email.validate_templates()?;
        let _mail = AccountMailPresentation::new(email.from.clone())?;
        let _cursor = pagination.signing_key()?;
        Ok(())
    }

    pub fn validate_oauth_for(
        &self,
        tenancy: &TenancyConfig,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthorizationServerConfig, ReferenceRuntimeConfigError> {
        validate_oauth_configuration(
            &self.authorization_server,
            &self.oauth_rate_limit,
            self.registration.public_app_url.as_ref(),
            tenancy,
            deployment,
            now,
        )
    }

    pub fn validated_authorization_server(
        &self,
        deployment: DeploymentEnvironment,
        now: OffsetDateTime,
    ) -> Result<ValidatedAuthorizationServerConfig, ReferenceRuntimeConfigError> {
        self.authorization_server
            .build_for(deployment, now)?
            .ok_or(ReferenceRuntimeConfigError::AuthorizationServerDisabled)
    }
}

impl ApiKeyApplicationConfig {
    pub fn validate(&self) -> Result<(), ReferenceRuntimeConfigError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(ReferenceRuntimeConfigError::ApiKeyPepper);
        }
        self.store_config().validate()?;
        Ok(())
    }

    fn build(self) -> Result<ApiKeyConfig, ReferenceRuntimeConfigError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(ReferenceRuntimeConfigError::ApiKeyPepper);
        }
        let config = ApiKeyConfig {
            enabled: self.enabled,
            pepper: self.pepper,
            max_scopes: self.max_scopes,
            max_key_lifetime: self.max_key_lifetime,
            last_used_write_interval: self.last_used_write_interval,
        };
        config.validate()?;
        Ok(config)
    }

    fn store_config(&self) -> ApiKeyConfig {
        ApiKeyConfig {
            enabled: self.enabled,
            pepper: self.pepper.clone(),
            max_scopes: self.max_scopes,
            max_key_lifetime: self.max_key_lifetime,
            last_used_write_interval: self.last_used_write_interval,
        }
    }
}

impl PasswordConfig {
    pub fn validate(&self) -> Result<PasswordPolicy, ReferenceRuntimeConfigError> {
        let _max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let _provider = PasswordLoginProvider::new(self.login_provider.clone())?;
        Ok(policy)
    }

    pub fn build(
        self,
    ) -> Result<(PasswordWorker, PasswordLoginProvider, PasswordPolicy), ReferenceRuntimeConfigError>
    {
        let max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let login_provider = PasswordLoginProvider::new(self.login_provider)?;
        let worker = PasswordWorker::new(PasswordEngine::new(policy.clone())?, max_concurrency);
        Ok((worker, login_provider, policy))
    }

    fn worker_concurrency(&self) -> Result<NonZeroUsize, ReferenceRuntimeConfigError> {
        let concurrency = self.max_concurrency.get();
        if concurrency > MAX_PASSWORD_WORKER_CONCURRENCY {
            return Err(ReferenceRuntimeConfigError::PasswordWorkerConcurrency);
        }
        let aggregate_memory_kib = u64::from(self.policy.memory_kib)
            .checked_mul(
                u64::try_from(concurrency)
                    .map_err(|_| ReferenceRuntimeConfigError::PasswordWorkerConcurrency)?,
            )
            .ok_or(ReferenceRuntimeConfigError::PasswordWorkerConcurrency)?;
        if aggregate_memory_kib > MAX_PASSWORD_WORKER_MEMORY_KIB {
            return Err(ReferenceRuntimeConfigError::PasswordWorkerConcurrency);
        }
        Ok(self.max_concurrency)
    }

    fn policy(&self) -> Result<PasswordPolicy, ReferenceRuntimeConfigError> {
        let pepper = PasswordPepper::new(self.pepper.version, self.pepper.secret.clone())?;
        Ok(PasswordPolicy::new(self.policy, pepper, Vec::new())?)
    }
}

impl RegistrationConfig {
    pub fn validate(
        &self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<RegistrationPolicy, ReferenceRuntimeConfigError> {
        let policy = self
            .policy_config()
            .validate_for(deployment, password_policy)?;
        let _pepper = InvitationTokenPepper::parse(self.invitation_token_pepper.clone())?;
        validate_response_floor(self.response_floor)?;
        Ok(policy)
    }

    pub fn build(
        self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<(RegistrationPolicy, InvitationTokenPepper, Duration), ReferenceRuntimeConfigError>
    {
        let policy = self
            .policy_config()
            .validate_for(deployment, password_policy)?;
        let pepper = InvitationTokenPepper::parse(self.invitation_token_pepper)?;
        validate_response_floor(self.response_floor)?;
        Ok((policy, pepper, self.response_floor))
    }

    fn policy_config(&self) -> RegistrationPolicyConfig {
        RegistrationPolicyConfig {
            mode: self.mode,
            local_identity_provider: self.local_identity_provider.clone(),
            invitation_ttl: self.invitation_ttl,
            public_app_url: self.public_app_url.clone(),
        }
    }
}

impl AccountEmailConfig {
    pub fn validate_templates(&self) -> Result<(), ReferenceRuntimeConfigError> {
        let configured: BTreeSet<&str> = self
            .templates
            .allowed_templates
            .iter()
            .map(omnius_email::TemplateName::as_str)
            .collect();
        let required: BTreeSet<&str> = AccountMailPresentation::required_templates()
            .into_iter()
            .collect();
        if configured != required {
            return Err(ReferenceRuntimeConfigError::AccountEmailTemplates);
        }
        Ok(())
    }

    pub fn build(
        self,
        deployment: DeploymentEnvironment,
    ) -> Result<(EmailService, AccountMailPresentation), ReferenceRuntimeConfigError> {
        self.validate_templates()?;
        let from = self.from;
        let service = EmailService::build(
            EmailConfig {
                provider: self.provider,
                templates: self.templates,
                custom_headers: self.custom_headers,
                limits: self.limits,
            },
            deployment,
        )?;
        Ok((service, AccountMailPresentation::new(from)?))
    }
}

impl OAuthRateLimitConfig {
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
    fn signing_key(&self) -> Result<CursorSigningKey, CursorSigningKeyError> {
        CursorSigningKey::from_slice(self.cursor_signing_key.expose_secret().as_bytes())
    }
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

fn canonical_api_key_pepper(pepper: &SecretString) -> bool {
    let source = pepper.expose_secret().as_bytes();
    let mut decoded = [0_u8; 33];
    let decoded_len = URL_SAFE_NO_PAD.decode_slice(source, &mut decoded).ok();
    let mut canonical = [0_u8; 44];
    let encoded_len = decoded_len.and_then(|length| {
        (length == 32)
            .then(|| {
                URL_SAFE_NO_PAD
                    .encode_slice(&decoded[..length], &mut canonical)
                    .ok()
            })
            .flatten()
    });
    let valid = encoded_len == Some(source.len()) && &canonical[..source.len()] == source;
    decoded.fill(0);
    canonical.fill(0);
    valid
}

fn validate_local_identity_provider(
    password: &str,
    registration: &str,
) -> Result<(), ReferenceRuntimeConfigError> {
    if password != registration {
        return Err(ReferenceRuntimeConfigError::LocalIdentityProviderMismatch);
    }
    if Url::parse(password).is_ok() || password.starts_with("//") || password.contains("://") {
        return Err(ReferenceRuntimeConfigError::LocalIdentityProviderUrl);
    }
    Ok(())
}

fn validate_response_floor(value: Duration) -> Result<(), ReferenceRuntimeConfigError> {
    if !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&value) {
        return Err(ReferenceRuntimeConfigError::AccountResponseFloor);
    }
    Ok(())
}

fn default_local_identity_provider() -> String {
    "email".to_owned()
}
const fn default_invitation_ttl() -> Duration {
    Duration::from_hours(168)
}
const fn default_account_response_floor() -> Duration {
    Duration::from_millis(500)
}
