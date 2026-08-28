use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use omnius_config::{ExposeSecret as _, SecretString};
use rand_core::{OsRng, RngCore as _};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize as _;

const MARKER: &[u8; 7] = b"omnius_";
const PREFIX_BYTES: usize = 9;
const PREFIX_TEXT_BYTES: usize = 12;
const VISIBLE_PREFIX_BYTES: usize = MARKER.len() + PREFIX_TEXT_BYTES;
const SECRET_BYTES: usize = 32;
const SECRET_TEXT_BYTES: usize = 43;
const PRESENTATION_BYTES: usize = VISIBLE_PREFIX_BYTES + 1 + SECRET_TEXT_BYTES;
const MATERIAL_BYTES: usize = PREFIX_BYTES + SECRET_BYTES;
const DIGEST_BYTES: usize = 32;
const MAX_PEPPER_BYTES: usize = 4_096;

/// A canonical API-key presentation retained in redacted, zeroizing storage.
pub struct ApiKeyCredential(SecretString);

impl ApiKeyCredential {
    /// Parses `omnius_<12 base64url characters>.<43 base64url characters>` exactly.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyTokenError::InvalidPresentation`] without reflecting the
    /// presented value when the marker, length, separator, alphabet, or canonical
    /// encoding is invalid.
    pub fn parse(value: SecretString) -> Result<Self, ApiKeyTokenError> {
        let presentation = value.expose_secret().as_bytes();
        if presentation.len() != PRESENTATION_BYTES
            || &presentation[..MARKER.len()] != MARKER
            || presentation[VISIBLE_PREFIX_BYTES] != b'.'
            || !is_canonical_component(
                &presentation[MARKER.len()..VISIBLE_PREFIX_BYTES],
                PREFIX_BYTES,
            )
            || !is_canonical_component(&presentation[VISIBLE_PREFIX_BYTES + 1..], SECRET_BYTES)
        {
            return Err(ApiKeyTokenError::InvalidPresentation);
        }
        Ok(Self(value))
    }

    /// Returns the non-secret lookup prefix, including the `omnius_` marker.
    #[must_use]
    pub fn prefix(&self) -> &str {
        &self.0.expose_secret()[..VISIBLE_PREFIX_BYTES]
    }

    /// Consumes and explicitly exposes the credential for one-time delivery.
    ///
    /// Lifecycle code must call this only after the issuance transaction commits
    /// and must not retain or log the returned value.
    #[must_use]
    pub fn expose_once(self) -> SecretString {
        self.0
    }

    /// Computes a keyed digest over the full canonical presentation.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyTokenError::InvalidPepper`] for an empty or oversized key.
    pub fn digest(&self, pepper: &SecretString) -> Result<ApiKeyDigest, ApiKeyTokenError> {
        let mut mac = keyed_mac(pepper)?;
        mac.update(self.0.expose_secret().as_bytes());
        let digest = mac.finalize().into_bytes().into();
        Ok(ApiKeyDigest(digest))
    }

    /// Compares the credential with a persisted digest in constant time.
    ///
    /// A digest with the wrong length does not match.
    ///
    /// # Errors
    ///
    /// Returns [`ApiKeyTokenError::InvalidPepper`] for an empty or oversized key.
    pub fn matches_digest(
        &self,
        pepper: &SecretString,
        expected: &[u8],
    ) -> Result<bool, ApiKeyTokenError> {
        let mut mac = keyed_mac(pepper)?;
        mac.update(self.0.expose_secret().as_bytes());
        Ok(mac.verify_slice(expected).is_ok())
    }
}

impl fmt::Debug for ApiKeyCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyCredential([REDACTED])")
    }
}

/// HMAC-SHA256 digest binding a canonical presentation under the configured pepper.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ApiKeyDigest([u8; DIGEST_BYTES]);

impl ApiKeyDigest {
    /// Borrows the fixed-size digest for persistence.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; DIGEST_BYTES] {
        &self.0
    }
}

impl fmt::Debug for ApiKeyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApiKeyDigest([REDACTED])")
    }
}

/// Newly issued API key and its persistence-safe digest.
#[derive(Debug)]
pub struct IssuedApiKey {
    /// Credential intended for one post-commit delivery.
    pub credential: ApiKeyCredential,
    /// Keyed digest safe to persist.
    pub digest: ApiKeyDigest,
}

/// Injectable source of independent API-key credentials.
pub trait ApiKeyGenerator: Send + Sync {
    /// Generates a random visible prefix and 256-bit secret, then computes its digest.
    ///
    /// # Errors
    ///
    /// Returns a value-free error if secure entropy is unavailable or the pepper is invalid.
    fn generate(&self, pepper: &SecretString) -> Result<IssuedApiKey, ApiKeyTokenError>;
}

/// Operating-system CSPRNG API-key source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsApiKeyGenerator;

impl ApiKeyGenerator for OsApiKeyGenerator {
    fn generate(&self, pepper: &SecretString) -> Result<IssuedApiKey, ApiKeyTokenError> {
        let mut material = [0_u8; MATERIAL_BYTES];
        if OsRng.try_fill_bytes(&mut material).is_err() {
            material.zeroize();
            return Err(ApiKeyTokenError::EntropyUnavailable);
        }
        issue_from_material(material, pepper)
    }
}

fn issue_from_material(
    mut material: [u8; MATERIAL_BYTES],
    pepper: &SecretString,
) -> Result<IssuedApiKey, ApiKeyTokenError> {
    let prefix_encoded = URL_SAFE_NO_PAD.encode(&material[..PREFIX_BYTES]);
    let mut secret_encoded = URL_SAFE_NO_PAD.encode(&material[PREFIX_BYTES..]);
    material.zeroize();

    let mut presentation = String::with_capacity(PRESENTATION_BYTES);
    presentation.push_str("omnius_");
    presentation.push_str(&prefix_encoded);
    presentation.push('.');
    presentation.push_str(&secret_encoded);
    secret_encoded.zeroize();

    let credential = ApiKeyCredential::parse(SecretString::from(presentation))?;
    let digest = credential.digest(pepper)?;
    Ok(IssuedApiKey { credential, digest })
}

fn keyed_mac(pepper: &SecretString) -> Result<Hmac<Sha256>, ApiKeyTokenError> {
    let secret = pepper.expose_secret().as_bytes();
    if secret.is_empty() || secret.len() > MAX_PEPPER_BYTES {
        return Err(ApiKeyTokenError::InvalidPepper);
    }
    Hmac::<Sha256>::new_from_slice(secret).map_err(|_| ApiKeyTokenError::InvalidPepper)
}

fn is_canonical_component(encoded: &[u8], decoded_len: usize) -> bool {
    let mut decoded = [0_u8; SECRET_BYTES];
    let Ok(actual_decoded_len) = URL_SAFE_NO_PAD.decode_slice(encoded, &mut decoded[..decoded_len])
    else {
        decoded.zeroize();
        return false;
    };
    if actual_decoded_len != decoded_len {
        decoded.zeroize();
        return false;
    }

    let mut canonical = [0_u8; SECRET_TEXT_BYTES];
    let Ok(actual_encoded_len) =
        URL_SAFE_NO_PAD.encode_slice(&decoded[..decoded_len], &mut canonical)
    else {
        decoded.zeroize();
        canonical.zeroize();
        return false;
    };
    let is_canonical =
        actual_encoded_len == encoded.len() && canonical[..actual_encoded_len] == *encoded;
    decoded.zeroize();
    canonical.zeroize();
    is_canonical
}

/// Value-free API-key credential processing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ApiKeyTokenError {
    /// A presented credential was malformed or non-canonical.
    #[error("API-key credential is invalid")]
    InvalidPresentation,
    /// The OS could not supply secure random bytes.
    #[error("secure API-key entropy is unavailable")]
    EntropyUnavailable,
    /// The digest pepper was empty or exceeded its fixed bound.
    #[error("API-key digest configuration is invalid")]
    InvalidPepper,
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug)]
    struct DeterministicApiKeyGenerator {
        next: Mutex<u64>,
    }

    impl DeterministicApiKeyGenerator {
        const fn new(seed: u64) -> Self {
            Self {
                next: Mutex::new(seed),
            }
        }
    }

    impl ApiKeyGenerator for DeterministicApiKeyGenerator {
        fn generate(&self, pepper: &SecretString) -> Result<IssuedApiKey, ApiKeyTokenError> {
            let mut next = self
                .next
                .lock()
                .map_err(|_| ApiKeyTokenError::EntropyUnavailable)?;
            let seed = *next;
            *next = next.wrapping_add(1);
            let mut material = [0_u8; MATERIAL_BYTES];
            for (index, chunk) in material.chunks_mut(8).enumerate() {
                let block = seed.wrapping_add(index as u64).to_be_bytes();
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
            issue_from_material(material, pepper)
        }
    }

    fn pepper(value: u8) -> SecretString {
        SecretString::from(char::from(value).to_string().repeat(32))
    }

    #[test]
    fn generated_credentials_have_exact_canonical_components()
    -> Result<(), Box<dyn std::error::Error>> {
        let generator = DeterministicApiKeyGenerator::new(7);
        let issued = generator.generate(&pepper(b'p'))?;
        let prefix = issued.credential.prefix().to_owned();
        let digest = issued.digest;
        let presentation_secret = issued.credential.expose_once();
        let presentation = presentation_secret.expose_secret();
        assert_eq!(presentation.len(), PRESENTATION_BYTES);
        assert_eq!(prefix.len(), VISIBLE_PREFIX_BYTES);
        assert_eq!(VISIBLE_PREFIX_BYTES, 19);
        assert_eq!(PRESENTATION_BYTES, 63);
        assert!(presentation.starts_with("omnius_"));
        assert_eq!(
            &presentation[VISIBLE_PREFIX_BYTES..=VISIBLE_PREFIX_BYTES],
            "."
        );

        let parsed = ApiKeyCredential::parse(SecretString::from(presentation.to_owned()))?;
        assert_eq!(parsed.prefix(), prefix);
        assert_eq!(parsed.digest(&pepper(b'p'))?, digest);
        Ok(())
    }

    #[test]
    fn digest_binds_the_prefix_secret_and_pepper() -> Result<(), Box<dyn std::error::Error>> {
        let generator = DeterministicApiKeyGenerator::new(11);
        let first = generator.generate(&pepper(b'a'))?;
        let second = generator.generate(&pepper(b'a'))?;
        let other_pepper_digest = first.credential.digest(&pepper(b'b'))?;
        assert_ne!(first.digest, second.digest);
        assert_ne!(first.digest, other_pepper_digest);
        assert!(
            first
                .credential
                .matches_digest(&pepper(b'a'), first.digest.as_bytes())?
        );
        assert!(
            !first
                .credential
                .matches_digest(&pepper(b'b'), first.digest.as_bytes())?
        );
        assert!(
            !first
                .credential
                .matches_digest(&pepper(b'a'), &[0_u8; 31])?
        );

        let presentation = first.credential.expose_once();
        let mut rebound_prefix = presentation.expose_secret().to_owned();
        let replacement = if rebound_prefix.as_bytes()[MARKER.len()] == b'A' {
            "B"
        } else {
            "A"
        };
        rebound_prefix.replace_range(MARKER.len()..=MARKER.len(), replacement);
        let rebound = ApiKeyCredential::parse(SecretString::from(rebound_prefix))?;
        assert_ne!(rebound.digest(&pepper(b'a'))?, first.digest);
        Ok(())
    }

    #[test]
    fn malformed_presentations_are_rejected_without_value_reflection()
    -> Result<(), Box<dyn std::error::Error>> {
        let generator = DeterministicApiKeyGenerator::new(19);
        let issued = generator.generate(&pepper(b'p'))?;
        let valid_secret = issued.credential.expose_once();
        let valid = valid_secret.expose_secret();
        let mut noncanonical = valid.to_owned();
        let last = noncanonical
            .pop()
            .ok_or("deterministic presentation was empty")?;
        noncanonical.push(match last {
            'A' => 'B',
            'Q' => 'R',
            'g' => 'h',
            'w' => 'x',
            _ => return Err("unexpected canonical final character".into()),
        });

        let malformed = [
            "short".to_owned(),
            valid.replacen("omnius_", "legacy_", 1),
            valid.replacen('.', "_", 1),
            format!("{}=", &valid[..valid.len() - 1]),
            noncanonical,
        ];
        for value in malformed {
            let Err(error) = ApiKeyCredential::parse(SecretString::from(value.clone())) else {
                return Err("malformed credential was accepted".into());
            };
            assert_eq!(error, ApiKeyTokenError::InvalidPresentation);
            assert!(!error.to_string().contains(&value));
        }
        Ok(())
    }

    #[test]
    fn credential_and_digest_debug_are_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let issued = DeterministicApiKeyGenerator::new(23).generate(&pepper(b'p'))?;
        let credential_debug = format!("{:?}", issued.credential);
        let digest_debug = format!("{:?}", issued.digest);
        let presentation = issued.credential.expose_once();
        assert_eq!(credential_debug, "ApiKeyCredential([REDACTED])");
        assert!(!credential_debug.contains(presentation.expose_secret()));
        assert_eq!(digest_debug, "ApiKeyDigest([REDACTED])");
        Ok(())
    }
}
