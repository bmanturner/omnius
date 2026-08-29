use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use rand_core::{OsRng, RngCore as _};
use serde::Deserialize;
use sha2::Sha256;
use thiserror::Error;
use url::Url;
use zeroize::Zeroize as _;

use crate::{PasswordPolicy, VerificationToken};

const INVITATION_TOKEN_BYTES: usize = 32;
const INVITATION_TOKEN_TEXT_BYTES: usize = 43;
const INVITATION_DIGEST_DOMAIN: &[u8] = b"omnius.auth.registration-invitation.v1\0";
const MIN_INVITATION_TTL: Duration = Duration::from_hours(1);
const MAX_INVITATION_TTL: Duration = Duration::from_hours(720);
const DEFAULT_INVITATION_TTL: Duration = Duration::from_hours(168);
const MAX_PROVIDER_BYTES: usize = 2_048;
const MAX_PUBLIC_APP_URL_BYTES: usize = 2_048;

/// Configured account-registration availability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RegistrationMode {
    /// No public registration or invitation lifecycle is available.
    Disabled,
    /// Any canonical email identity may request registration.
    SelfService,
    /// Registration requires a live invitation bound to the email identity.
    InviteOnly,
}

/// Strict, environment-aware registration configuration.
///
/// `mode` remains optional at deserialization time so validation can distinguish
/// a development default from a production operator decision.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RegistrationPolicyConfig {
    /// Explicit registration mode. Omission defaults to disabled outside production.
    pub mode: Option<RegistrationMode>,
    /// Provider used for locally password-owned email identities.
    pub local_identity_provider: String,
    /// Lifetime of one registration invitation.
    #[serde(with = "humantime_serde")]
    pub invitation_ttl: Duration,
    /// Browser application base URL used for secret-bearing fragment links.
    pub public_app_url: Option<Url>,
}

impl Default for RegistrationPolicyConfig {
    fn default() -> Self {
        Self {
            mode: None,
            local_identity_provider: "email".to_owned(),
            invitation_ttl: DEFAULT_INVITATION_TTL,
            public_app_url: None,
        }
    }
}

impl RegistrationPolicyConfig {
    /// Validates deployment trust requirements and reuses the password policy's
    /// verification and recovery lifetimes.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for omitted production decisions or invalid bounds.
    pub fn validate_for(
        &self,
        deployment: DeploymentEnvironment,
        password_policy: &PasswordPolicy,
    ) -> Result<RegistrationPolicy, RegistrationPolicyError> {
        let mode = match (self.mode, deployment) {
            (Some(mode), _) => mode,
            (None, DeploymentEnvironment::Production) => {
                return Err(RegistrationPolicyError::ProductionModeRequired);
            }
            (None, _) => RegistrationMode::Disabled,
        };
        if !valid_provider(&self.local_identity_provider) {
            return Err(RegistrationPolicyError::InvalidLocalIdentityProvider);
        }
        if !(MIN_INVITATION_TTL..=MAX_INVITATION_TTL).contains(&self.invitation_ttl) {
            return Err(RegistrationPolicyError::InvalidInvitationTtl);
        }
        let public_app_url = match (&self.public_app_url, deployment) {
            (None, DeploymentEnvironment::Production) => {
                return Err(RegistrationPolicyError::ProductionPublicAppUrlRequired);
            }
            (None, _) => None,
            (Some(url), _) if !valid_public_app_url(url, deployment) => {
                return Err(RegistrationPolicyError::InvalidPublicAppUrl);
            }
            (Some(url), _) => Some(url.clone()),
        };
        let password = password_policy.config();
        Ok(RegistrationPolicy {
            mode,
            local_identity_provider: self.local_identity_provider.clone(),
            invitation_ttl: self.invitation_ttl,
            verification_ttl: password.verification_ttl,
            recovery_ttl: password.recovery_ttl,
            public_app_url,
        })
    }
}

/// Validated registration policy safe for runtime use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationPolicy {
    mode: RegistrationMode,
    local_identity_provider: String,
    invitation_ttl: Duration,
    verification_ttl: Duration,
    recovery_ttl: Duration,
    public_app_url: Option<Url>,
}

impl RegistrationPolicy {
    /// Effective registration mode.
    #[must_use]
    pub const fn mode(&self) -> RegistrationMode {
        self.mode
    }

    /// Configured local identity provider.
    #[must_use]
    pub fn local_identity_provider(&self) -> &str {
        &self.local_identity_provider
    }

    /// Validated invitation lifetime.
    #[must_use]
    pub const fn invitation_ttl(&self) -> Duration {
        self.invitation_ttl
    }

    /// Verification lifetime inherited from [`PasswordPolicy`].
    #[must_use]
    pub const fn verification_ttl(&self) -> Duration {
        self.verification_ttl
    }

    /// Recovery lifetime inherited from [`PasswordPolicy`].
    #[must_use]
    pub const fn recovery_ttl(&self) -> Duration {
        self.recovery_ttl
    }

    /// Validated browser application base URL, when configured.
    #[must_use]
    pub const fn public_app_url(&self) -> Option<&Url> {
        self.public_app_url.as_ref()
    }

    /// Derives a verification URL with the bearer secret only in its fragment.
    ///
    /// # Errors
    ///
    /// Returns an error when no public application URL was configured.
    pub fn email_verification_link(
        &self,
        token: &VerificationToken,
    ) -> Result<SecretAccountLink, RegistrationPolicyError> {
        self.secret_link("verify-email", token.expose_for_delivery())
    }

    /// Derives a password-reset URL with the bearer secret only in its fragment.
    ///
    /// # Errors
    ///
    /// Returns an error when no public application URL was configured.
    pub fn password_reset_link(
        &self,
        token: &VerificationToken,
    ) -> Result<SecretAccountLink, RegistrationPolicyError> {
        self.secret_link("reset-password", token.expose_for_delivery())
    }

    /// Derives an invitation URL with the bearer secret only in its fragment.
    ///
    /// # Errors
    ///
    /// Returns an error when no public application URL was configured.
    pub fn invitation_link(
        &self,
        token: &InvitationToken,
    ) -> Result<SecretAccountLink, RegistrationPolicyError> {
        self.secret_link("register", token.expose_for_delivery())
    }

    fn secret_link(
        &self,
        route: &str,
        secret: &str,
    ) -> Result<SecretAccountLink, RegistrationPolicyError> {
        let mut url = self
            .public_app_url
            .clone()
            .ok_or(RegistrationPolicyError::PublicAppUrlRequired)?;
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| RegistrationPolicyError::InvalidPublicAppUrl)?;
        segments.pop_if_empty().push(route);
        drop(segments);
        url.set_fragment(Some(&format!("token={secret}")));
        Ok(SecretAccountLink(SecretString::from(url.to_string())))
    }
}

/// Secret-bearing account link intended for exactly one delivery boundary.
pub struct SecretAccountLink(SecretString);

impl SecretAccountLink {
    /// Exposes the complete URL to trusted delivery code.
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretAccountLink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretAccountLink([REDACTED])")
    }
}

/// Exact 256-bit HMAC key dedicated to invitation lookup digests.
pub struct InvitationTokenPepper(SecretString);

impl InvitationTokenPepper {
    /// Parses an exact canonical unpadded `base64url`-encoded 256-bit key.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for malformed key material.
    pub fn parse(value: SecretString) -> Result<Self, InvitationTokenError> {
        if !is_canonical_32(value.expose_secret().as_bytes()) {
            return Err(InvitationTokenError::InvalidPepper);
        }
        Ok(Self(value))
    }

    fn decoded(&self) -> Result<[u8; INVITATION_TOKEN_BYTES], InvitationTokenError> {
        let mut decoded = [0_u8; INVITATION_TOKEN_BYTES];
        let length = URL_SAFE_NO_PAD
            .decode_slice(self.0.expose_secret().as_bytes(), &mut decoded)
            .map_err(|_| InvitationTokenError::InvalidPepper)?;
        if length != INVITATION_TOKEN_BYTES {
            decoded.zeroize();
            return Err(InvitationTokenError::InvalidPepper);
        }
        Ok(decoded)
    }
}

impl fmt::Debug for InvitationTokenPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationTokenPepper([REDACTED])")
    }
}

/// Canonical 256-bit invitation bearer presentation.
pub struct InvitationToken(SecretString);

impl InvitationToken {
    /// Parses exactly 43 canonical unpadded base64url characters.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for malformed presentations.
    pub fn parse(value: SecretString) -> Result<Self, InvitationTokenError> {
        if !is_canonical_32(value.expose_secret().as_bytes()) {
            return Err(InvitationTokenError::InvalidPresentation);
        }
        Ok(Self(value))
    }

    /// Exposes the bearer presentation to trusted delivery code.
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        self.0.expose_secret()
    }

    /// Computes the domain-separated persistence digest.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid pepper material.
    pub fn digest(
        &self,
        pepper: &InvitationTokenPepper,
    ) -> Result<InvitationTokenDigest, InvitationTokenError> {
        let mut key = pepper.decoded()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|_| InvitationTokenError::InvalidPepper)?;
        key.zeroize();
        mac.update(INVITATION_DIGEST_DOMAIN);
        mac.update(self.0.expose_secret().as_bytes());
        Ok(InvitationTokenDigest(mac.finalize().into_bytes().into()))
    }
}

impl fmt::Debug for InvitationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationToken([REDACTED])")
    }
}

/// Persistence-safe `HMAC-SHA-256` invitation digest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct InvitationTokenDigest([u8; INVITATION_TOKEN_BYTES]);

impl InvitationTokenDigest {
    pub(crate) const fn as_bytes(&self) -> &[u8; INVITATION_TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for InvitationTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationTokenDigest([REDACTED])")
    }
}

/// Newly generated invitation presentation and persistence digest.
#[derive(Debug)]
pub struct IssuedInvitationToken {
    /// Bearer secret returned only after the issuance transaction commits.
    pub token: InvitationToken,
    /// Digest safe to persist.
    pub digest: InvitationTokenDigest,
}

/// Injectable secure invitation-token source.
pub trait InvitationTokenGenerator: Send + Sync {
    /// Generates one independent 256-bit token and keyed digest.
    ///
    /// # Errors
    ///
    /// Returns a value-free entropy or key-validation error.
    fn generate(
        &self,
        pepper: &InvitationTokenPepper,
    ) -> Result<IssuedInvitationToken, InvitationTokenError>;
}

/// Operating-system `CSPRNG` invitation-token source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsInvitationTokenGenerator;

impl InvitationTokenGenerator for OsInvitationTokenGenerator {
    fn generate(
        &self,
        pepper: &InvitationTokenPepper,
    ) -> Result<IssuedInvitationToken, InvitationTokenError> {
        let mut material = [0_u8; INVITATION_TOKEN_BYTES];
        if OsRng.try_fill_bytes(&mut material).is_err() {
            material.zeroize();
            return Err(InvitationTokenError::EntropyUnavailable);
        }
        let encoded = URL_SAFE_NO_PAD.encode(material);
        material.zeroize();
        let token = InvitationToken::parse(SecretString::from(encoded))?;
        let digest = token.digest(pepper)?;
        Ok(IssuedInvitationToken { token, digest })
    }
}

/// Value-free registration-policy failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RegistrationPolicyError {
    /// Production must explicitly select registration availability.
    #[error("production registration mode must be explicit")]
    ProductionModeRequired,
    /// The configured provider is empty, non-canonical, or oversized.
    #[error("local identity provider is invalid")]
    InvalidLocalIdentityProvider,
    /// The invitation lifetime is outside one hour through thirty days.
    #[error("registration invitation lifetime is invalid")]
    InvalidInvitationTtl,
    /// Production must explicitly configure its public browser URL.
    #[error("production public application URL is required")]
    ProductionPublicAppUrlRequired,
    /// The public browser URL is not a safe absolute application base URL.
    #[error("public application URL is invalid")]
    InvalidPublicAppUrl,
    /// Link derivation requires a configured public browser URL.
    #[error("public application URL is required")]
    PublicAppUrlRequired,
}

/// Value-free invitation-token processing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum InvitationTokenError {
    /// Presented text was not exact canonical unpadded `base64url`.
    #[error("registration invitation token is invalid")]
    InvalidPresentation,
    /// The operating system could not provide secure entropy.
    #[error("secure registration invitation entropy is unavailable")]
    EntropyUnavailable,
    /// The invitation digest key was invalid.
    #[error("registration invitation digest configuration is invalid")]
    InvalidPepper,
}

fn valid_provider(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROVIDER_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_public_app_url(url: &Url, deployment: DeploymentEnvironment) -> bool {
    url.as_str().len() <= MAX_PUBLIC_APP_URL_BYTES
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.scheme(), "http" | "https")
        && (url.scheme() == "https" || deployment != DeploymentEnvironment::Production)
}

fn is_canonical_32(value: &[u8]) -> bool {
    if value.len() != INVITATION_TOKEN_TEXT_BYTES {
        return false;
    }
    let mut decoded = [0_u8; INVITATION_TOKEN_BYTES];
    let Ok(decoded_len) = URL_SAFE_NO_PAD.decode_slice(value, &mut decoded) else {
        decoded.zeroize();
        return false;
    };
    if decoded_len != INVITATION_TOKEN_BYTES {
        decoded.zeroize();
        return false;
    }
    let mut canonical = [0_u8; INVITATION_TOKEN_TEXT_BYTES];
    let Ok(encoded_len) = URL_SAFE_NO_PAD.encode_slice(decoded, &mut canonical) else {
        decoded.zeroize();
        canonical.zeroize();
        return false;
    };
    let matches = encoded_len == value.len() && canonical[..encoded_len] == *value;
    decoded.zeroize();
    canonical.zeroize();
    matches
}
