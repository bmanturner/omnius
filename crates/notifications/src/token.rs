use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use rand_core::{OsRng, RngCore as _};
use omnius_config::{ExposeSecret as _, SecretString};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize as _;

const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = 43;
const DIGEST_BYTES: usize = 32;
const MAX_PEPPER_BYTES: usize = 4096;
const DIGEST_DOMAIN: &[u8] = b"omnius.notifications.unsubscribe.v1\0";

/// Canonical 256-bit opaque unsubscribe capability in zeroizing storage.
pub struct UnsubscribeToken(SecretString);

impl UnsubscribeToken {
    /// Parses exactly 43 canonical unpadded base64url characters.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`UnsubscribeTokenError::InvalidPresentation`] for malformed input.
    pub fn parse(value: SecretString) -> Result<Self, UnsubscribeTokenError> {
        if value.expose_secret().len() != TOKEN_TEXT_BYTES
            || !is_canonical(value.expose_secret().as_bytes())
        {
            return Err(UnsubscribeTokenError::InvalidPresentation);
        }
        Ok(Self(value))
    }

    /// Computes a purpose- and version-bound HMAC-SHA256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`UnsubscribeTokenError::InvalidPepper`] for an empty or oversized pepper.
    pub fn digest(
        &self,
        pepper: &SecretString,
    ) -> Result<UnsubscribeTokenDigest, UnsubscribeTokenError> {
        let mut mac = keyed_mac(pepper)?;
        mac.update(DIGEST_DOMAIN);
        mac.update(self.0.expose_secret().as_bytes());
        Ok(UnsubscribeTokenDigest(mac.finalize().into_bytes().into()))
    }

    /// Constant-time comparison with a persisted digest.
    ///
    /// # Errors
    ///
    /// Returns [`UnsubscribeTokenError::InvalidPepper`] for invalid digest configuration.
    pub fn matches_digest(
        &self,
        pepper: &SecretString,
        expected: &[u8],
    ) -> Result<bool, UnsubscribeTokenError> {
        let mut mac = keyed_mac(pepper)?;
        mac.update(DIGEST_DOMAIN);
        mac.update(self.0.expose_secret().as_bytes());
        Ok(mac.verify_slice(expected).is_ok())
    }

    /// Consumes the presentation for exactly one post-commit response.
    #[must_use]
    pub fn expose_once(self) -> SecretString {
        self.0
    }
}

impl fmt::Debug for UnsubscribeToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnsubscribeToken([REDACTED])")
    }
}

/// Persistence-safe, domain-separated token digest.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct UnsubscribeTokenDigest([u8; DIGEST_BYTES]);

impl UnsubscribeTokenDigest {
    /// Fixed digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for UnsubscribeTokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnsubscribeTokenDigest([REDACTED])")
    }
}

/// Newly generated presentation and persistence-safe digest.
#[derive(Debug)]
pub struct GeneratedUnsubscribeToken {
    /// Presentation returned only after the issuance transaction commits.
    pub token: UnsubscribeToken,
    /// Digest written inside the issuance transaction.
    pub digest: UnsubscribeTokenDigest,
}

/// Injectable secure token generation seam.
pub trait UnsubscribeTokenGenerator: Send + Sync {
    /// Generates 256 independent CSPRNG bits and their purpose-bound keyed digest.
    ///
    /// # Errors
    ///
    /// Returns [`UnsubscribeTokenError::EntropyUnavailable`] when secure randomness fails or
    /// [`UnsubscribeTokenError::InvalidPepper`] when digest configuration is invalid.
    fn generate(
        &self,
        pepper: &SecretString,
    ) -> Result<GeneratedUnsubscribeToken, UnsubscribeTokenError>;
}

/// Operating-system CSPRNG token generator.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsUnsubscribeTokenGenerator;

impl UnsubscribeTokenGenerator for OsUnsubscribeTokenGenerator {
    fn generate(
        &self,
        pepper: &SecretString,
    ) -> Result<GeneratedUnsubscribeToken, UnsubscribeTokenError> {
        let mut material = [0_u8; TOKEN_BYTES];
        if OsRng.try_fill_bytes(&mut material).is_err() {
            material.zeroize();
            return Err(UnsubscribeTokenError::EntropyUnavailable);
        }
        issue_from_material(material, pepper)
    }
}

pub(crate) fn issue_from_material(
    mut material: [u8; TOKEN_BYTES],
    pepper: &SecretString,
) -> Result<GeneratedUnsubscribeToken, UnsubscribeTokenError> {
    let encoded = URL_SAFE_NO_PAD.encode(material.as_slice());
    material.zeroize();
    let token = UnsubscribeToken::parse(SecretString::from(encoded))?;
    let digest = token.digest(pepper)?;
    Ok(GeneratedUnsubscribeToken { token, digest })
}

fn keyed_mac(pepper: &SecretString) -> Result<Hmac<Sha256>, UnsubscribeTokenError> {
    let value = pepper.expose_secret().as_bytes();
    if value.is_empty() || value.len() > MAX_PEPPER_BYTES {
        return Err(UnsubscribeTokenError::InvalidPepper);
    }
    Hmac::<Sha256>::new_from_slice(value).map_err(|_| UnsubscribeTokenError::InvalidPepper)
}

fn is_canonical(value: &[u8]) -> bool {
    let mut decoded = [0_u8; TOKEN_BYTES];
    let Ok(decoded_len) = URL_SAFE_NO_PAD.decode_slice(value, &mut decoded) else {
        decoded.zeroize();
        return false;
    };
    if decoded_len != TOKEN_BYTES {
        decoded.zeroize();
        return false;
    }
    let mut canonical = [0_u8; TOKEN_TEXT_BYTES];
    let Ok(encoded_len) = URL_SAFE_NO_PAD.encode_slice(decoded.as_slice(), &mut canonical) else {
        decoded.zeroize();
        canonical.zeroize();
        return false;
    };
    let matches = encoded_len == value.len() && canonical[..encoded_len] == *value;
    decoded.zeroize();
    canonical.zeroize();
    matches
}

/// Value-free unsubscribe capability failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum UnsubscribeTokenError {
    /// Presented text was not exact canonical base64url.
    #[error("unsubscribe capability is invalid")]
    InvalidPresentation,
    /// The operating system could not supply secure entropy.
    #[error("secure unsubscribe entropy is unavailable")]
    EntropyUnavailable,
    /// The HMAC pepper was empty or oversized.
    #[error("unsubscribe digest configuration is invalid")]
    InvalidPepper,
}

#[cfg(test)]
mod tests {
    use omnius_config::{ExposeSecret as _, SecretString};

    use super::{UnsubscribeToken, issue_from_material};

    #[test]
    fn token_and_digest_debug_never_expose_presentation() -> Result<(), Box<dyn std::error::Error>>
    {
        let pepper = SecretString::from("unit-test-notification-pepper-with-32-bytes".to_owned());
        let generated = issue_from_material([7_u8; 32], &pepper)?;
        let token_debug = format!("{:?}", generated.token);
        let digest_debug = format!("{:?}", generated.digest);
        assert!(!token_debug.contains("BwcHBwcH"));
        assert!(!digest_debug.contains("BwcHBwcH"));
        assert!(token_debug.contains("[REDACTED]"));
        assert!(digest_debug.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn malformed_or_noncanonical_presentations_are_rejected_without_reflection() {
        let result = UnsubscribeToken::parse(SecretString::from("secret-token".to_owned()));
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.to_string(), "unsubscribe capability is invalid");
            assert!(!error.to_string().contains("secret-token"));
        }
    }

    #[test]
    fn purpose_bound_digest_matches_in_constant_time_path() -> Result<(), Box<dyn std::error::Error>>
    {
        let pepper = SecretString::from("unit-test-notification-pepper-with-32-bytes".to_owned());
        let generated = issue_from_material([9_u8; 32], &pepper)?;
        assert!(
            generated
                .token
                .matches_digest(&pepper, generated.digest.as_bytes())?
        );
        let exposed = generated.token.expose_once();
        assert_eq!(exposed.expose_secret().len(), 43);
        Ok(())
    }
}
