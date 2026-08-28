use std::{fmt, sync::Arc};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_config::{ExposeSecret as _, SecretString};
use password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use rand_core::{OsRng, RngCore as _};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::TotpStoreError;

const LOOKUP_BYTES: usize = 8;
const LOOKUP_CHARS: usize = 11;
const RECOVERY_SECRET_BYTES: usize = 24;
const RECOVERY_SECRET_CHARS: usize = 32;
const PRESENTATION_CHARS: usize = LOOKUP_CHARS + 1 + RECOVERY_SECRET_CHARS;
const SALT_BYTES: usize = 16;
const HASH_OUTPUT_BYTES: usize = 32;
const MAX_HASH_BYTES: usize = 255;
const WORKER_CONCURRENCY: usize = 2;

/// A set of recovery codes that can be exposed only by consuming the value.
///
/// Debug output is always redacted. Each contained code has a non-secret lookup
/// identifier followed by a dot and a 192-bit secret.
pub struct RecoveryCodeSet {
    codes: Vec<SecretString>,
}

impl RecoveryCodeSet {
    pub(crate) fn new(codes: Vec<SecretString>) -> Self {
        Self { codes }
    }

    /// Returns how many one-time codes are present without exposing them.
    #[must_use]
    pub fn len(&self) -> usize {
        self.codes.len()
    }

    /// Returns whether no codes are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    /// Consumes the set and releases each plaintext code for its single delivery.
    #[must_use]
    pub fn expose_once(self) -> Vec<SecretString> {
        self.codes
    }
}

impl fmt::Debug for RecoveryCodeSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryCodeSet")
            .field("count", &self.codes.len())
            .field("codes", &"[REDACTED]")
            .finish()
    }
}

pub(crate) struct GeneratedRecoveryCode {
    lookup_id: String,
    presentation: SecretString,
}

impl GeneratedRecoveryCode {
    fn generate() -> Result<Self, TotpStoreError> {
        let mut lookup = Zeroizing::new([0_u8; LOOKUP_BYTES]);
        let mut secret = Zeroizing::new([0_u8; RECOVERY_SECRET_BYTES]);
        OsRng
            .try_fill_bytes(&mut *lookup)
            .map_err(|_| TotpStoreError::EntropyUnavailable)?;
        OsRng
            .try_fill_bytes(&mut *secret)
            .map_err(|_| TotpStoreError::EntropyUnavailable)?;
        let lookup_id = URL_SAFE_NO_PAD.encode(*lookup);
        let secret_value = Zeroizing::new(URL_SAFE_NO_PAD.encode(*secret));
        let presentation = SecretString::from(format!("{lookup_id}.{}", secret_value.as_str()));
        Ok(Self {
            lookup_id,
            presentation,
        })
    }

    fn secret(&self) -> Result<&str, TotpStoreError> {
        self.presentation
            .expose_secret()
            .split_once('.')
            .map(|(_, secret)| secret)
            .filter(|secret| secret.len() == RECOVERY_SECRET_CHARS)
            .ok_or(TotpStoreError::Cryptography)
    }
}

pub(crate) struct HashedRecoveryCode {
    pub(crate) lookup_id: String,
    pub(crate) phc: String,
    pub(crate) presentation: SecretString,
}

#[derive(Clone)]
pub(crate) struct RecoveryWorker {
    pepper: Arc<Zeroizing<[u8; 32]>>,
    permits: Arc<Semaphore>,
}

impl RecoveryWorker {
    pub(crate) fn new(pepper: Arc<Zeroizing<[u8; 32]>>) -> Self {
        Self {
            pepper,
            permits: Arc::new(Semaphore::new(WORKER_CONCURRENCY)),
        }
    }

    pub(crate) async fn generate_and_hash(
        &self,
        count: usize,
    ) -> Result<Vec<HashedRecoveryCode>, TotpStoreError> {
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| TotpStoreError::WorkerUnavailable)?;
        let pepper = Arc::clone(&self.pepper);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut generated = Vec::with_capacity(count);
            for _ in 0..count {
                generated.push(GeneratedRecoveryCode::generate()?);
            }
            hash_generated(&pepper, generated)
        })
        .await
        .map_err(|_| TotpStoreError::WorkerUnavailable)?
    }

    pub(crate) async fn verify(
        &self,
        phc: String,
        candidate: SecretString,
    ) -> Result<bool, TotpStoreError> {
        let permit = Arc::clone(&self.permits)
            .try_acquire_owned()
            .map_err(|_| TotpStoreError::WorkerUnavailable)?;
        let pepper = Arc::clone(&self.pepper);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_hash(&pepper, &phc, &candidate)
        })
        .await
        .map_err(|_| TotpStoreError::WorkerUnavailable)?
    }
}

pub(crate) struct ParsedRecoveryCode {
    pub(crate) lookup_id: String,
    pub(crate) secret: SecretString,
}

pub(crate) fn parse_recovery_code(
    presentation: &SecretString,
) -> Result<ParsedRecoveryCode, TotpStoreError> {
    let exposed = presentation.expose_secret();
    if exposed.len() != PRESENTATION_CHARS {
        return Err(TotpStoreError::VerificationFailed);
    }
    let Some((lookup, secret)) = exposed.split_once('.') else {
        return Err(TotpStoreError::VerificationFailed);
    };
    if lookup.len() != LOOKUP_CHARS
        || secret.len() != RECOVERY_SECRET_CHARS
        || !lookup
            .bytes()
            .chain(secret.bytes())
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(TotpStoreError::VerificationFailed);
    }
    Ok(ParsedRecoveryCode {
        lookup_id: lookup.to_owned(),
        secret: SecretString::from(secret.to_owned()),
    })
}

pub(crate) fn valid_lookup_id(value: &str) -> bool {
    value.len() == LOOKUP_CHARS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn hash_generated(
    pepper: &[u8; 32],
    generated: Vec<GeneratedRecoveryCode>,
) -> Result<Vec<HashedRecoveryCode>, TotpStoreError> {
    let hasher = argon2(pepper)?;
    let mut results = Vec::with_capacity(generated.len());
    for code in generated {
        let mut salt_bytes = Zeroizing::new([0_u8; SALT_BYTES]);
        OsRng
            .try_fill_bytes(&mut *salt_bytes)
            .map_err(|_| TotpStoreError::EntropyUnavailable)?;
        let salt = SaltString::encode_b64(salt_bytes.as_ref())
            .map_err(|_| TotpStoreError::Cryptography)?;
        let phc = hasher
            .hash_password(code.secret()?.as_bytes(), &salt)
            .map_err(|_| TotpStoreError::Cryptography)?
            .to_string();
        validate_phc(&phc)?;
        results.push(HashedRecoveryCode {
            lookup_id: code.lookup_id,
            phc,
            presentation: code.presentation,
        });
    }
    Ok(results)
}

fn verify_hash(
    pepper: &[u8; 32],
    phc: &str,
    candidate: &SecretString,
) -> Result<bool, TotpStoreError> {
    validate_phc(phc)?;
    let parsed = PasswordHash::new(phc).map_err(|_| TotpStoreError::CorruptData)?;
    let verifier = argon2(pepper)?;
    Ok(verifier
        .verify_password(candidate.expose_secret().as_bytes(), &parsed)
        .is_ok())
}

fn argon2(pepper: &[u8; 32]) -> Result<Argon2<'_>, TotpStoreError> {
    Argon2::new_with_secret(
        pepper,
        Algorithm::Argon2id,
        Version::V0x13,
        recovery_params()?,
    )
    .map_err(|_| TotpStoreError::Cryptography)
}

fn recovery_params() -> Result<Params, TotpStoreError> {
    Params::new(
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
        Some(HASH_OUTPUT_BYTES),
    )
    .map_err(|_| TotpStoreError::Cryptography)
}

fn validate_phc(phc: &str) -> Result<(), TotpStoreError> {
    if phc.len() > MAX_HASH_BYTES {
        return Err(TotpStoreError::CorruptData);
    }
    let parsed = PasswordHash::new(phc).map_err(|_| TotpStoreError::CorruptData)?;
    let params = Params::try_from(&parsed).map_err(|_| TotpStoreError::CorruptData)?;
    let expected = recovery_params().map_err(|_| TotpStoreError::CorruptData)?;
    if parsed.algorithm != Algorithm::Argon2id.ident()
        || parsed.version != Some(Version::V0x13.into())
        || params != expected
        || params.output_len() != Some(HASH_OUTPUT_BYTES)
    {
        return Err(TotpStoreError::CorruptData);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn recovery_presentations_are_high_entropy_redacted_hashes() -> Result<(), TotpStoreError>
    {
        let worker = RecoveryWorker::new(Arc::new(Zeroizing::new([29_u8; 32])));
        let mut codes = worker.generate_and_hash(2).await?;
        let first = codes.remove(0);
        let debug_set = format!(
            "{:?}",
            RecoveryCodeSet::new(vec![first.presentation.clone()])
        );
        let parsed = parse_recovery_code(&first.presentation)?;

        assert_eq!(parsed.lookup_id, first.lookup_id);
        assert!(first.phc.starts_with("$argon2id$v=19$"));
        assert!(!first.phc.contains(parsed.secret.expose_secret()));
        assert!(debug_set.contains("[REDACTED]"));
        Ok(())
    }

    #[tokio::test]
    async fn recovery_worker_rejects_work_instead_of_queueing() -> Result<(), TotpStoreError> {
        let worker = RecoveryWorker::new(Arc::new(Zeroizing::new([31_u8; 32])));
        let first = Arc::clone(&worker.permits)
            .acquire_owned()
            .await
            .map_err(|_| TotpStoreError::WorkerUnavailable)?;
        let second = Arc::clone(&worker.permits)
            .acquire_owned()
            .await
            .map_err(|_| TotpStoreError::WorkerUnavailable)?;

        assert!(matches!(
            worker.generate_and_hash(1).await,
            Err(TotpStoreError::WorkerUnavailable)
        ));
        drop((first, second));
        Ok(())
    }
}
