use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand_core::{OsRng, RngCore as _};
use rsk_config::{ExposeSecret as _, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroize as _;

const TOKEN_BYTES: usize = 32;
const TOKEN_TEXT_BYTES: usize = 43;

/// Purpose bound into a stored single-use token.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenPurpose {
    /// Proves control of an identity verification channel.
    EmailVerification,
    /// Authorizes one password recovery operation.
    PasswordRecovery,
}

impl TokenPurpose {
    pub(crate) const fn as_db(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::PasswordRecovery => "password_recovery",
        }
    }
}

/// Opaque bearer token returned only for delivery after a transaction commits.
pub struct VerificationToken(SecretString);

impl VerificationToken {
    /// Parses a canonical 256-bit base64url token.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::InvalidPresentation`] for malformed or non-canonical input.
    pub fn parse(value: SecretString) -> Result<Self, TokenError> {
        let encoded = value.expose_secret();
        if encoded.len() != TOKEN_TEXT_BYTES {
            return Err(TokenError::InvalidPresentation);
        }
        let mut decoded = [0_u8; TOKEN_BYTES];
        let Ok(decoded_len) = URL_SAFE_NO_PAD.decode_slice(encoded.as_bytes(), &mut decoded) else {
            decoded.zeroize();
            return Err(TokenError::InvalidPresentation);
        };
        let is_canonical =
            decoded_len == TOKEN_BYTES && URL_SAFE_NO_PAD.encode(decoded.as_slice()) == encoded;
        decoded.zeroize();
        if !is_canonical {
            return Err(TokenError::InvalidPresentation);
        }
        Ok(Self(value))
    }

    /// Explicitly exposes the bearer token for post-commit delivery.
    #[must_use]
    pub fn expose_for_delivery(&self) -> &str {
        self.0.expose_secret()
    }

    /// Computes the persisted one-way lookup digest.
    #[must_use]
    pub fn digest(&self) -> TokenDigest {
        let digest: [u8; TOKEN_BYTES] = Sha256::digest(self.0.expose_secret().as_bytes()).into();
        TokenDigest(digest)
    }
}

impl fmt::Debug for VerificationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationToken([REDACTED])")
    }
}

/// SHA-256 lookup digest for a canonical verification token.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct TokenDigest([u8; TOKEN_BYTES]);

impl TokenDigest {
    pub(crate) const fn as_bytes(&self) -> &[u8; TOKEN_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TokenDigest([REDACTED])")
    }
}

/// Newly issued token and its safe persistence digest.
#[derive(Debug)]
pub struct IssuedToken {
    /// Bearer secret intended for one post-commit delivery.
    pub token: VerificationToken,
    /// Digest safe to persist.
    pub digest: TokenDigest,
}

/// Injectable secure token source.
pub trait TokenGenerator: Send + Sync {
    /// Generates one independent 256-bit token.
    ///
    /// # Errors
    ///
    /// Returns [`TokenError::EntropyUnavailable`] if the OS CSPRNG fails.
    fn generate(&self) -> Result<IssuedToken, TokenError>;
}

/// Operating-system CSPRNG token source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsTokenGenerator;

impl TokenGenerator for OsTokenGenerator {
    fn generate(&self) -> Result<IssuedToken, TokenError> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| TokenError::EntropyUnavailable)?;
        let encoded = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        let token = VerificationToken(SecretString::from(encoded));
        let digest = token.digest();
        Ok(IssuedToken { token, digest })
    }
}

/// Value-free token processing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TokenError {
    /// A presented bearer token was malformed.
    #[error("verification token is invalid")]
    InvalidPresentation,
    /// Secure random generation failed.
    #[error("secure token entropy is unavailable")]
    EntropyUnavailable,
}

#[cfg(any(test, feature = "test-support"))]
mod test_support {
    use std::sync::Mutex;

    use super::*;

    /// Deterministic token source for explicit test fixtures only.
    #[derive(Debug)]
    pub struct DeterministicTokenGenerator {
        next: Mutex<u64>,
    }

    impl DeterministicTokenGenerator {
        /// Starts the deterministic sequence at `seed`.
        #[must_use]
        pub const fn new(seed: u64) -> Self {
            Self {
                next: Mutex::new(seed),
            }
        }
    }

    impl TokenGenerator for DeterministicTokenGenerator {
        fn generate(&self) -> Result<IssuedToken, TokenError> {
            let mut counter = self
                .next
                .lock()
                .map_err(|_| TokenError::EntropyUnavailable)?;
            let value = *counter;
            *counter = counter.wrapping_add(1);
            let mut bytes = [0_u8; TOKEN_BYTES];
            for (index, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
                chunk.copy_from_slice(&value.wrapping_add(index as u64).to_be_bytes());
            }
            let encoded = URL_SAFE_NO_PAD.encode(bytes);
            bytes.zeroize();
            let token = VerificationToken(SecretString::from(encoded));

            let digest = token.digest();
            Ok(IssuedToken { token, digest })
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use test_support::DeterministicTokenGenerator;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_canonical_distinct_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let generator = OsTokenGenerator;
        let first = generator.generate()?;
        let second = generator.generate()?;
        assert_ne!(first.digest, second.digest);
        assert_eq!(first.token.expose_for_delivery().len(), TOKEN_TEXT_BYTES);
        assert_eq!(
            first.token.digest(),
            VerificationToken::parse(SecretString::from(
                first.token.expose_for_delivery().to_owned()
            ))?
            .digest()
        );
        assert_eq!(
            format!("{:?}", first.token),
            "VerificationToken([REDACTED])"
        );
        assert!(!format!("{:?}", first.digest).contains(first.token.expose_for_delivery()));
        Ok(())
    }

    #[test]
    fn rejects_noncanonical_presentations() {
        assert!(matches!(
            VerificationToken::parse(SecretString::from("short".to_owned())),
            Err(TokenError::InvalidPresentation)
        ));
        assert!(matches!(
            VerificationToken::parse(SecretString::from("!".repeat(TOKEN_TEXT_BYTES))),
            Err(TokenError::InvalidPresentation)
        ));
        let issued = OsTokenGenerator
            .generate()
            .unwrap_or_else(|error| panic!("token generation failed: {error}"));
        let mut noncanonical = issued.token.expose_for_delivery().to_owned();
        let final_character = noncanonical
            .pop()
            .unwrap_or_else(|| panic!("generated token was empty"));
        noncanonical.push(match final_character {
            'A' => 'B',
            'E' => 'F',
            'I' => 'J',
            'M' => 'N',
            'Q' => 'R',
            'U' => 'V',
            'Y' => 'Z',
            'c' => 'd',
            'g' => 'h',
            'k' => 'l',
            'o' => 'p',
            's' => 't',
            'w' => 'x',
            '0' => '1',
            '4' => '5',
            '8' => '9',
            _ => panic!("generated token had a noncanonical final character"),
        });
        assert!(matches!(
            VerificationToken::parse(SecretString::from(noncanonical)),
            Err(TokenError::InvalidPresentation)
        ));
    }
}
