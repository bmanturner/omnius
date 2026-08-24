use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore as _};
use rsk_auth_core::SubjectId;
use rsk_postgres::{RetryableSqlState, RetryableTransactionError};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

const HANDLE_BYTES: usize = 32;
const HANDLE_ENCODED_BYTES: usize = 43;

/// Opaque, single-use reference to server-side `WebAuthn` ceremony state.
///
/// The handle carries 256 bits of operating-system randomness. Its debug representation is always
/// redacted, and PostgreSQL stores only its SHA-256 digest.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CeremonyHandle(String);

impl CeremonyHandle {
    pub(crate) fn generate() -> Self {
        let mut bytes = [0_u8; HANDLE_BYTES];
        let mut rng = OsRng;
        rng.fill_bytes(&mut bytes);
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Validates a client-returned opaque handle.
    ///
    /// # Errors
    ///
    /// Returns [`CeremonyHandleError`] unless the value is a canonical, unpadded base64url
    /// encoding of exactly 32 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, CeremonyHandleError> {
        let value = value.into();
        if value.len() != HANDLE_ENCODED_BYTES {
            return Err(CeremonyHandleError);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| CeremonyHandleError)?;
        if decoded.len() != HANDLE_BYTES || URL_SAFE_NO_PAD.encode(decoded) != value {
            return Err(CeremonyHandleError);
        }
        Ok(Self(value))
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }

    #[cfg(test)]
    pub(crate) fn exposed_for_test(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CeremonyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CeremonyHandle([REDACTED])")
    }
}

impl Serialize for CeremonyHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CeremonyHandle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// Stable malformed-ceremony-handle error with no rejected value attached.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("WebAuthn ceremony handle is invalid")]
pub struct CeremonyHandleError;

/// Browser challenge and opaque state handle for passkey registration.
#[derive(Debug, Serialize)]
pub struct RegistrationStart {
    /// Official `webauthn-rs` registration options to serialize to the browser.
    pub public_key: CreationChallengeResponse,
    /// Single-use reference to the matching server-side registration state.
    pub ceremony_handle: CeremonyHandle,
}

/// Browser challenge and opaque state handle for passkey authentication.
#[derive(Debug, Serialize)]
pub struct AuthenticationStart {
    /// Official `webauthn-rs` authentication options to serialize to the browser.
    pub public_key: RequestChallengeResponse,
    /// Single-use reference to the matching server-side authentication state.
    pub ceremony_handle: CeremonyHandle,
}

/// Safe passkey lifecycle metadata; credential IDs and public-key material are excluded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyMetadata {
    /// Internal `UUIDv7` lifecycle identifier.
    pub id: Uuid,
    /// Canonical user that owns the credential.
    pub user_id: SubjectId,
    /// User-controlled credential label.
    pub name: String,
    /// Browser-provided authenticator transport hints.
    pub transports: Vec<String>,
    /// Last accepted authenticator signature counter.
    pub sign_count: u32,
    /// Whether user verification was established at registration or last authentication.
    pub user_verified: bool,
    /// Whether the credential may be synchronized or backed up.
    pub backup_eligible: bool,
    /// Whether the credential is currently reported as backed up.
    pub backup_state: bool,
    /// UTC creation time.
    pub created_at: OffsetDateTime,
    /// UTC time of the latest metadata change.
    pub updated_at: OffsetDateTime,
    /// UTC time of the latest successful authentication, when present.
    pub last_used_at: Option<OffsetDateTime>,
    /// UTC time at which the credential was disabled, when present.
    pub disabled_at: Option<OffsetDateTime>,
}

/// Stable, value-free `WebAuthn` ceremony and persistence errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum WebAuthnServiceError {
    /// Optional capability is disabled.
    #[error("WebAuthn authentication is disabled")]
    Disabled,
    /// Enabled configuration is invalid.
    #[error("WebAuthn service configuration is invalid")]
    InvalidConfiguration,
    /// PostgreSQL is unavailable.
    #[error("WebAuthn persistence is unavailable")]
    Unavailable,
    /// Safe-to-retry transaction conflict.
    #[error("WebAuthn transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted state conflicts with a requested lifecycle transition.
    #[error("WebAuthn state conflicts with persisted state")]
    Conflict,
    /// Random ceremony handle collided with an existing digest.
    #[error("WebAuthn ceremony handle collision")]
    CeremonyHandleCollision,
    /// Ceremony handle is absent or was already consumed.
    #[error("WebAuthn ceremony was not found")]
    CeremonyNotFound,
    /// Ceremony state expired before it was consumed.
    #[error("WebAuthn ceremony expired")]
    CeremonyExpired,
    /// Global or per-user pending ceremony capacity has been reached.
    #[error("WebAuthn ceremony capacity is exhausted")]
    CeremonyCapacityReached,
    /// Ceremony state did not match the requested operation.
    #[error("WebAuthn ceremony type is invalid")]
    WrongCeremonyType,
    /// Recent user authentication is required for this lifecycle operation.
    #[error("WebAuthn lifecycle operation requires recent user authentication")]
    RecentAuthenticationRequired,
    /// User does not exist.
    #[error("WebAuthn user was not found")]
    UserNotFound,
    /// User-controlled name is malformed or unbounded.
    #[error("WebAuthn credential name is invalid")]
    InvalidName,
    /// User has reached the configured retained-credential limit.
    #[error("WebAuthn credential limit reached")]
    CredentialLimitReached,
    /// User has no active credentials available for authentication.
    #[error("WebAuthn user has no active credentials")]
    NoActiveCredentials,
    /// Credential lifecycle row does not exist for the user.
    #[error("WebAuthn credential was not found")]
    CredentialNotFound,
    /// Official `WebAuthn` ceremony validation rejected the response.
    #[error("WebAuthn ceremony validation failed")]
    VerificationFailed,
    /// Authenticator signature counter did not advance when counter semantics apply.
    #[error("WebAuthn authenticator counter replay was detected")]
    CounterReplay,
    /// Persisted protocol or lifecycle state is malformed.
    #[error("WebAuthn persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for WebAuthnServiceError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl WebAuthnServiceError {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::Conflict => "conflict",
            Self::CeremonyHandleCollision => "handle_collision",
            Self::CeremonyNotFound => "ceremony_not_found",
            Self::CeremonyExpired => "ceremony_expired",
            Self::CeremonyCapacityReached => "ceremony_capacity_reached",
            Self::WrongCeremonyType => "wrong_ceremony_type",
            Self::RecentAuthenticationRequired => "recent_authentication_required",
            Self::UserNotFound => "user_not_found",
            Self::InvalidName => "invalid_name",
            Self::CredentialLimitReached => "credential_limit_reached",
            Self::NoActiveCredentials => "no_active_credentials",
            Self::CredentialNotFound => "credential_not_found",
            Self::VerificationFailed => "verification_failed",
            Self::CounterReplay => "counter_replay",
            Self::CorruptData => "corrupt_data",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_handles_are_canonical_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let handle = CeremonyHandle::generate();
        let restored: CeremonyHandle = serde_json::from_str(&serde_json::to_string(&handle)?)?;
        assert_eq!(restored, handle);
        assert_eq!(handle.exposed_for_test().len(), HANDLE_ENCODED_BYTES);
        assert!(!format!("{handle:?}").contains(handle.exposed_for_test()));
        assert_eq!(handle.digest().len(), HANDLE_BYTES);
        Ok(())
    }

    #[test]
    fn ceremony_handles_reject_noncanonical_or_wrong_size_values() {
        assert_eq!(CeremonyHandle::parse("short"), Err(CeremonyHandleError));
        assert_eq!(
            CeremonyHandle::parse("!".repeat(HANDLE_ENCODED_BYTES)),
            Err(CeremonyHandleError)
        );
    }
}
