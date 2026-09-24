//! Strict configuration for reusable authenticated HTTP composition.

use std::{collections::BTreeSet, num::NonZeroUsize, time::Duration};

#[cfg(feature = "api-key")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "api-key")]
use omnius_auth_api_key::{ApiKeyConfig, ApiKeyConfigError};
use omnius_auth_core::{SessionConfig, SessionConfigError};
#[cfg(feature = "jwt")]
use omnius_auth_jwt::{JwtConfig, JwtConfigError};
use omnius_auth_password::{
    InvitationTokenError, InvitationTokenPepper, PasswordEngine, PasswordError, PasswordPepper,
    PasswordPolicy, PasswordPolicyConfig, PasswordPolicyError, PasswordWorker, RegistrationMode,
    RegistrationPolicy, RegistrationPolicyConfig, RegistrationPolicyError,
};
#[cfg(feature = "api-key")]
use omnius_config::ExposeSecret as _;
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_email::{
    CustomHeaderPolicy, EmailConfig, EmailError, EmailLimits, EmailProviderConfig, EmailService,
    MailboxAddress, TemplateConfig,
};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::{
    account_auth::{AccountAuthBuildError, AccountMailPresentation},
    browser_auth::{PasswordLoginProvider, PasswordLoginProviderError},
};

const MAX_PASSWORD_WORKER_CONCURRENCY: usize = 16;
const MAX_PASSWORD_WORKER_MEMORY_KIB: u64 = 1024 * 1024;

/// Application-neutral account, browser-session, JWT, and API-key configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedHttpConfig {
    /// Browser session cookie, lifetime, and persistence policy.
    pub session: SessionConfig,
    /// Optional JWT verifier configuration.
    #[cfg(feature = "jwt")]
    pub jwt: JwtConfig,
    /// Password worker, policy, and login-provider configuration.
    pub password: PasswordConfig,
    /// Registration, invitation, and public application policy.
    pub registration: RegistrationConfig,
    /// Optional API-key store policy.
    #[cfg(feature = "api-key")]
    pub api_key: ApiKeyApplicationConfig,
}

/// Password authentication worker and policy configuration.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordConfig {
    /// Local identity-provider namespace accepted by password login.
    pub login_provider: String,
    /// Maximum concurrent password hashing operations.
    pub max_concurrency: NonZeroUsize,
    /// Password strength and hashing policy.
    pub policy: PasswordPolicyConfig,
    /// Versioned password pepper.
    pub pepper: PasswordPepperConfig,
}

/// Versioned secret used by password hashing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordPepperConfig {
    /// Active pepper version stored with password hashes.
    pub version: u32,
    /// Secret pepper material.
    pub secret: SecretString,
}

/// Application-owned API-key store limits and pepper.
#[cfg(feature = "api-key")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyApplicationConfig {
    /// Whether API-key authentication is enabled.
    pub enabled: bool,
    /// Canonical base64url API-key pepper.
    pub pepper: SecretString,
    /// Maximum scopes accepted on one key.
    pub max_scopes: usize,
    #[serde(with = "humantime_serde")]
    /// Maximum permitted API-key lifetime.
    pub max_key_lifetime: Duration,
    #[serde(with = "humantime_serde")]
    /// Minimum interval between persisted last-used updates.
    pub last_used_write_interval: Duration,
}

/// Self-service or invite-only account registration policy.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationConfig {
    /// Explicit registration mode, or the secure provider default.
    pub mode: Option<RegistrationMode>,
    #[serde(default = "default_local_identity_provider")]
    /// Local identity-provider namespace.
    pub local_identity_provider: String,
    #[serde(default = "default_invitation_ttl", with = "humantime_serde")]
    /// Lifetime of a one-time registration invitation.
    pub invitation_ttl: Duration,
    /// Public base URL used in account email links.
    pub public_app_url: Option<Url>,
    /// Secret used to authenticate invitation tokens.
    pub invitation_token_pepper: SecretString,
    #[serde(default = "default_account_response_floor", with = "humantime_serde")]
    /// Minimum enumeration-safe account response time.
    pub response_floor: Duration,
}

/// Account email provider, sender, templates, and delivery limits.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountEmailConfig {
    /// Public sender mailbox.
    pub from: MailboxAddress,
    /// Selected email transport provider.
    pub provider: EmailProviderConfig,
    /// Account email template directory and allowlist.
    pub templates: TemplateConfig,
    #[serde(default)]
    /// Validated custom-header policy.
    pub custom_headers: CustomHeaderPolicy,
    #[serde(default)]
    /// Bounded email rendering and delivery limits.
    pub limits: EmailLimits,
}

/// Stable authenticated HTTP configuration failures.
#[derive(Debug, Error)]
pub enum AuthenticatedHttpConfigError {
    /// Browser session support was disabled.
    #[error("browser session support must be enabled")]
    SessionDisabled,
    /// Browser session policy is invalid.
    #[error("browser session configuration failed: {0}")]
    Session(#[from] SessionConfigError),
    /// JWT verifier policy is invalid.
    #[cfg(feature = "jwt")]
    #[error("JWT verifier configuration failed: {0}")]
    Jwt(#[from] JwtConfigError),
    /// API-key store policy is invalid.
    #[cfg(feature = "api-key")]
    #[error("API-key configuration failed: {0}")]
    ApiKey(#[from] ApiKeyConfigError),
    /// API-key pepper is malformed or non-canonical.
    #[cfg(feature = "api-key")]
    #[error("API-key pepper must be canonical unpadded base64url encoding of exactly 32 bytes")]
    ApiKeyPepper,
    /// Password policy is invalid.
    #[error("password policy configuration failed: {0}")]
    PasswordPolicy(#[from] PasswordPolicyError),
    /// Password worker initialization failed.
    #[error("password worker initialization failed: {0}")]
    Password(#[from] PasswordError),
    /// Password worker resource bounds are exceeded.
    #[error("password worker concurrency or aggregate memory exceeds its hard bound")]
    PasswordWorkerConcurrency,
    /// Password login-provider namespace is invalid.
    #[error("password login provider configuration failed: {0}")]
    PasswordLoginProvider(#[from] PasswordLoginProviderError),
    /// Registration policy is invalid.
    #[error("account registration policy configuration failed: {0}")]
    RegistrationPolicy(#[from] RegistrationPolicyError),
    /// Invitation-token secret is invalid.
    #[error("registration invitation secret configuration failed: {0}")]
    InvitationToken(#[from] InvitationTokenError),
    /// Enumeration-safe response floor is outside its bound.
    #[error("account discovery response floor is invalid")]
    AccountResponseFloor,
    /// Registration and password identity-provider names differ.
    #[error("registration identity provider must exactly match the password login provider")]
    LocalIdentityProviderMismatch,
    /// A local provider name was URL-shaped.
    #[error("local identity provider namespaces must not be URL-shaped")]
    LocalIdentityProviderUrl,
    /// Email provider configuration or construction failed.
    #[error("account email configuration or construction failed: {0}")]
    AccountEmail(#[from] EmailError),
    /// Account email template allowlist is incomplete or contains extras.
    #[error("account email template allowlist must contain exactly the three account templates")]
    AccountEmailTemplates,
    /// Account email presentation is invalid.
    #[error("account email presentation is invalid: {0}")]
    AccountMail(#[from] AccountAuthBuildError),
}

impl AuthenticatedHttpConfig {
    /// Validates every configuration input required by the authenticated runtime.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when any authentication, email, or deployment
    /// constraint is invalid.
    pub fn validate_for(
        &self,
        email: &AccountEmailConfig,
        deployment: DeploymentEnvironment,
    ) -> Result<(), AuthenticatedHttpConfigError> {
        if !self.session.enabled {
            return Err(AuthenticatedHttpConfigError::SessionDisabled);
        }
        self.session.validate_for(deployment)?;
        #[cfg(feature = "jwt")]
        if self.jwt.enabled {
            self.jwt.validate_for(deployment)?;
        }
        #[cfg(feature = "api-key")]
        self.api_key.validate()?;
        let password_policy = self.password.validate()?;
        let _registration = self.registration.validate(deployment, &password_policy)?;
        validate_local_identity_provider(
            &self.password.login_provider,
            &self.registration.local_identity_provider,
        )?;
        email.validate_templates()?;
        let _mail = AccountMailPresentation::new(email.from.clone())?;
        Ok(())
    }
}

#[cfg(feature = "api-key")]
impl ApiKeyApplicationConfig {
    /// Validates the selected API-key configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when API keys are disabled or their pepper or
    /// store limits are invalid.
    pub fn validate(&self) -> Result<(), AuthenticatedHttpConfigError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(AuthenticatedHttpConfigError::ApiKeyPepper);
        }
        self.store_config().validate()?;
        Ok(())
    }

    pub(crate) fn build(self) -> Result<ApiKeyConfig, AuthenticatedHttpConfigError> {
        if !self.enabled || !canonical_api_key_pepper(&self.pepper) {
            return Err(AuthenticatedHttpConfigError::ApiKeyPepper);
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
    /// Validates password policy, worker capacity, and login-provider configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when any password runtime constraint is invalid.
    pub fn validate(&self) -> Result<PasswordPolicy, AuthenticatedHttpConfigError> {
        let _max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let _provider = PasswordLoginProvider::new(self.login_provider.clone())?;
        Ok(policy)
    }

    /// Builds the password worker, login provider, and validated policy.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when worker capacity, policy, pepper, or provider
    /// configuration is invalid.
    pub fn build(
        self,
    ) -> Result<(PasswordWorker, PasswordLoginProvider, PasswordPolicy), AuthenticatedHttpConfigError>
    {
        let max_concurrency = self.worker_concurrency()?;
        let policy = self.policy()?;
        let login_provider = PasswordLoginProvider::new(self.login_provider)?;
        let worker = PasswordWorker::new(PasswordEngine::new(policy.clone())?, max_concurrency);
        Ok((worker, login_provider, policy))
    }

    fn worker_concurrency(&self) -> Result<NonZeroUsize, AuthenticatedHttpConfigError> {
        let concurrency = self.max_concurrency.get();
        if concurrency > MAX_PASSWORD_WORKER_CONCURRENCY {
            return Err(AuthenticatedHttpConfigError::PasswordWorkerConcurrency);
        }
        let aggregate_memory_kib = u64::from(self.policy.memory_kib)
            .checked_mul(
                u64::try_from(concurrency)
                    .map_err(|_| AuthenticatedHttpConfigError::PasswordWorkerConcurrency)?,
            )
            .ok_or(AuthenticatedHttpConfigError::PasswordWorkerConcurrency)?;
        if aggregate_memory_kib > MAX_PASSWORD_WORKER_MEMORY_KIB {
            return Err(AuthenticatedHttpConfigError::PasswordWorkerConcurrency);
        }
        Ok(self.max_concurrency)
    }

    fn policy(&self) -> Result<PasswordPolicy, AuthenticatedHttpConfigError> {
        let pepper = PasswordPepper::new(self.pepper.version, self.pepper.secret.clone())?;
        Ok(PasswordPolicy::new(self.policy, pepper, Vec::new())?)
    }
}

impl RegistrationConfig {
    /// Validates registration policy and invitation-token configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when registration policy, token pepper, or response
    /// timing is invalid.
    pub fn validate(
        &self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<RegistrationPolicy, AuthenticatedHttpConfigError> {
        let policy = self
            .policy_config()
            .validate_for(deployment, password_policy)?;
        let _pepper = InvitationTokenPepper::parse(self.invitation_token_pepper.clone())?;
        validate_response_floor(self.response_floor)?;
        Ok(policy)
    }

    /// Builds registration policy, invitation-token pepper, and response floor.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when registration policy, token pepper, or response
    /// timing is invalid.
    pub fn build(
        self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<(RegistrationPolicy, InvitationTokenPepper, Duration), AuthenticatedHttpConfigError>
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
    /// Validates that configured templates exactly cover account-email workflows.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when the configured template inventory differs
    /// from the required account-email inventory.
    pub fn validate_templates(&self) -> Result<(), AuthenticatedHttpConfigError> {
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
            return Err(AuthenticatedHttpConfigError::AccountEmailTemplates);
        }
        Ok(())
    }

    /// Builds the account email service and presentation contract.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticatedHttpConfigError`] when templates, provider configuration, or sender
    /// presentation is invalid.
    pub fn build(
        self,
        deployment: DeploymentEnvironment,
    ) -> Result<(EmailService, AccountMailPresentation), AuthenticatedHttpConfigError> {
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

#[cfg(feature = "api-key")]
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
) -> Result<(), AuthenticatedHttpConfigError> {
    if password != registration {
        return Err(AuthenticatedHttpConfigError::LocalIdentityProviderMismatch);
    }
    if Url::parse(password).is_ok() || password.starts_with("//") || password.contains("://") {
        return Err(AuthenticatedHttpConfigError::LocalIdentityProviderUrl);
    }
    Ok(())
}

fn validate_response_floor(value: Duration) -> Result<(), AuthenticatedHttpConfigError> {
    if !(Duration::from_millis(500)..=Duration::from_secs(5)).contains(&value) {
        return Err(AuthenticatedHttpConfigError::AccountResponseFloor);
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

#[cfg(feature = "api-key")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_api_key_pepper_rejects_non_canonical_secret() {
        let pepper = SecretString::from("not-a-key");
        assert!(!canonical_api_key_pepper(&pepper));
    }
}
