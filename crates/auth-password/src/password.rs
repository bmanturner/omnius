use std::{fmt, num::NonZeroUsize, sync::Arc};

use argon2::{
    Algorithm, Argon2, PasswordHash, PasswordHasher as _, PasswordVerifier as _, Version,
};
use password_hash::SaltString;
use rand_core::{OsRng, RngCore as _};
use rsk_config::{ExposeSecret as _, SecretString};
use thiserror::Error;
use tokio::sync::Semaphore;
use zeroize::Zeroize as _;

use crate::{PasswordPepper, PasswordPolicy};

const HARD_MAX_PASSWORD_BYTES: usize = 1024;
const DUMMY_PASSWORD: &str = "rsk-dummy-password-not-a-credential";
const MAX_PHC_BYTES: usize = 1024;

/// A bounded password candidate whose contents remain redacted and zeroized.
pub struct PasswordInput(SecretString);

impl PasswordInput {
    /// Validates a non-empty password candidate no larger than 1024 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidPasswordInput`] for an empty or oversized value.
    pub fn new(value: SecretString) -> Result<Self, PasswordError> {
        let length = value.expose_secret().len();
        if length == 0 || length > HARD_MAX_PASSWORD_BYTES {
            return Err(PasswordError::InvalidPasswordInput);
        }
        Ok(Self(value))
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.expose_secret().as_bytes()
    }
}

impl fmt::Debug for PasswordInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PasswordInput([REDACTED])")
    }
}

/// A validated PHC password verifier retained as redacted memory.
pub struct StoredPasswordHash(SecretString);

impl StoredPasswordHash {
    /// Parses and stores a bounded PHC string.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidStoredCredential`] unless the value is a
    /// bounded Argon2id v19 PHC verifier with bounded work parameters.
    pub fn new(value: String) -> Result<Self, PasswordError> {
        if value.is_empty() || value.len() > MAX_PHC_BYTES {
            return Err(PasswordError::InvalidStoredCredential);
        }
        let parsed =
            PasswordHash::new(&value).map_err(|_| PasswordError::InvalidStoredCredential)?;
        validate_persisted_phc(&parsed)?;
        Ok(Self(SecretString::from(value)))
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.expose_secret()
    }
}

impl Clone for StoredPasswordHash {
    fn clone(&self) -> Self {
        Self(SecretString::from(self.as_str().to_owned()))
    }
}

impl fmt::Debug for StoredPasswordHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StoredPasswordHash([REDACTED])")
    }
}

/// Persistable password verifier and the pepper epoch required to verify it.
#[derive(Clone, Debug)]
pub struct PersistedPasswordCredential {
    hash: StoredPasswordHash,
    pepper_version: u32,
}

impl PersistedPasswordCredential {
    /// Restores a credential from persistence after validating its PHC representation.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::InvalidStoredCredential`] for invalid PHC data.
    pub fn restore(hash: String, pepper_version: u32) -> Result<Self, PasswordError> {
        Ok(Self {
            hash: StoredPasswordHash::new(hash)?,
            pepper_version,
        })
    }

    /// Returns the non-secret pepper epoch.
    #[must_use]
    pub const fn pepper_version(&self) -> u32 {
        self.pepper_version
    }

    pub(crate) fn hash(&self) -> &StoredPasswordHash {
        &self.hash
    }

    pub(crate) fn phc(&self) -> &str {
        self.hash.as_str()
    }
}

/// Public authentication result. Every invalid or absent credential is rejected identically.
#[derive(Clone, Debug)]
pub enum PasswordVerification {
    /// The credential did not authenticate.
    Rejected,
    /// The credential authenticated; a replacement is supplied only when policy changed.
    Verified {
        /// A freshly salted policy-compliant verifier to persist after successful authentication.
        replacement: Option<PersistedPasswordCredential>,
    },
}

/// Argon2id password hashing and verification service.
#[derive(Clone, Debug)]
pub struct PasswordEngine {
    policy: PasswordPolicy,
    dummy: PersistedPasswordCredential,
}

impl PasswordEngine {
    /// Builds an engine and one random policy-compliant dummy verifier.
    ///
    /// # Errors
    ///
    /// Returns a safe cryptographic setup error if secure entropy or Argon2 fails.
    pub fn new(policy: PasswordPolicy) -> Result<Self, PasswordError> {
        let dummy_input = PasswordInput::new(SecretString::from(DUMMY_PASSWORD.to_owned()))?;
        let dummy = hash_with_active(&policy, &dummy_input)?;
        Ok(Self { policy, dummy })
    }

    /// Hashes a new password with the active Argon2id policy and a fresh random salt.
    ///
    /// This operation is memory-hard and blocking. Async callers must use
    /// [`PasswordWorker`] to avoid blocking runtime workers.
    ///
    /// # Errors
    ///
    /// Returns a safe validation or cryptographic error.
    pub fn hash_password(
        &self,
        password: &PasswordInput,
    ) -> Result<PersistedPasswordCredential, PasswordError> {
        if password.bytes().len() < self.policy.config().min_password_bytes
            || password.bytes().len() > self.policy.config().max_password_bytes
        {
            return Err(PasswordError::InvalidPasswordInput);
        }
        hash_with_active(&self.policy, password)
    }

    /// Verifies a candidate using `RustCrypto`'s constant-time hash-output comparison.
    ///
    /// This operation is memory-hard and blocking. Async callers must use
    /// [`PasswordWorker`] to bound concurrency away from runtime workers.
    ///
    /// A missing credential still performs one policy-compliant dummy verification.
    /// A successful old-policy or old-pepper verification returns a replacement hash.
    ///
    /// # Errors
    ///
    /// Returns a value-free corruption or cryptographic error. Callers must map all
    /// authentication failures to the same external response.
    pub fn verify(
        &self,
        stored: Option<&PersistedPasswordCredential>,
        candidate: &PasswordInput,
    ) -> Result<PasswordVerification, PasswordError> {
        if candidate.bytes().len() > self.policy.config().max_password_bytes {
            return Ok(PasswordVerification::Rejected);
        }
        let credential = stored.unwrap_or(&self.dummy);
        let Some(pepper) = self.policy.pepper(credential.pepper_version) else {
            self.perform_dummy_verification(candidate)?;
            return Ok(PasswordVerification::Rejected);
        };
        let parsed = PasswordHash::new(credential.hash().as_str())
            .map_err(|_| PasswordError::InvalidStoredCredential)?;
        let verifier = argon2_for(pepper, self.policy.params())?;
        let password_matches = verifier.verify_password(candidate.bytes(), &parsed).is_ok();
        if stored.is_none() || !password_matches {
            return Ok(PasswordVerification::Rejected);
        }

        let parsed_params = argon2::Params::try_from(&parsed)
            .map_err(|_| PasswordError::InvalidStoredCredential)?;
        let needs_rehash = parsed.algorithm != Algorithm::Argon2id.ident()
            || parsed.version != Some(Version::V0x13.into())
            || parsed_params != *self.policy.params()
            || credential.pepper_version != self.policy.active_pepper().version();
        let replacement = needs_rehash
            .then(|| hash_with_active(&self.policy, candidate))
            .transpose()?;
        Ok(PasswordVerification::Verified { replacement })
    }

    /// Returns the validated policy.
    #[must_use]
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    fn perform_dummy_verification(&self, candidate: &PasswordInput) -> Result<(), PasswordError> {
        let parsed = PasswordHash::new(self.dummy.hash().as_str())
            .map_err(|_| PasswordError::InvalidStoredCredential)?;
        let verifier = argon2_for(self.policy.active_pepper(), self.policy.params())?;
        let _password_matches = verifier.verify_password(candidate.bytes(), &parsed).is_ok();
        Ok(())
    }
}

/// Concurrency-bounded blocking worker for memory-hard password operations.
///
/// Async request handlers should use this type rather than invoking [`PasswordEngine`]
/// directly on a runtime worker. The permit bound must be sized from the configured
/// memory cost and the service's dedicated hashing capacity.
#[derive(Clone, Debug)]
pub struct PasswordWorker {
    engine: Arc<PasswordEngine>,
    permits: Arc<Semaphore>,
}

impl PasswordWorker {
    /// Creates a worker with an explicit non-zero memory/CPU concurrency limit.
    #[must_use]
    pub fn new(engine: PasswordEngine, max_concurrency: NonZeroUsize) -> Self {
        Self {
            engine: Arc::new(engine),
            permits: Arc::new(Semaphore::new(max_concurrency.get())),
        }
    }

    /// Hashes a new password on the bounded blocking pool.
    ///
    /// # Errors
    ///
    /// Returns a value-free password or blocking-worker failure.
    pub async fn hash_password(
        &self,
        password: PasswordInput,
    ) -> Result<PersistedPasswordCredential, PasswordError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| PasswordError::WorkerUnavailable)?;
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.hash_password(&password)
        })
        .await
        .map_err(|_| PasswordError::WorkerUnavailable)?
    }

    /// Verifies a candidate on the bounded blocking pool.
    ///
    /// # Errors
    ///
    /// Returns a value-free password or blocking-worker failure.
    pub async fn verify(
        &self,
        stored: Option<PersistedPasswordCredential>,
        candidate: PasswordInput,
    ) -> Result<PasswordVerification, PasswordError> {
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(|_| PasswordError::WorkerUnavailable)?;
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            engine.verify(stored.as_ref(), &candidate)
        })
        .await
        .map_err(|_| PasswordError::WorkerUnavailable)?
    }

    /// Returns the validated password policy.
    #[must_use]
    pub fn policy(&self) -> &PasswordPolicy {
        self.engine.policy()
    }
}

/// Value-free password processing failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PasswordError {
    /// A candidate was empty, too short for enrollment, or too large.
    #[error("password input is invalid")]
    InvalidPasswordInput,
    /// Persisted PHC data was malformed or unsupported.
    #[error("stored password credential is invalid")]
    InvalidStoredCredential,
    /// The bounded blocking password worker was unavailable.
    #[error("password worker is unavailable")]
    WorkerUnavailable,
    /// Secure random generation failed.
    #[error("secure password entropy is unavailable")]
    EntropyUnavailable,
    /// Argon2 rejected an operation without exposing credential material.
    #[error("password hashing operation failed")]
    HashingFailed,
}

fn validate_persisted_phc(hash: &PasswordHash<'_>) -> Result<(), PasswordError> {
    if hash.algorithm != Algorithm::Argon2id.ident() || hash.version != Some(Version::V0x13.into())
    {
        return Err(PasswordError::InvalidStoredCredential);
    }
    let params =
        argon2::Params::try_from(hash).map_err(|_| PasswordError::InvalidStoredCredential)?;
    if params.m_cost() > 1024 * 1024
        || params.t_cost() > 10
        || params.p_cost() > 16
        || params.output_len() != Some(32)
    {
        return Err(PasswordError::InvalidStoredCredential);
    }
    Ok(())
}

fn hash_with_active(
    policy: &PasswordPolicy,
    password: &PasswordInput,
) -> Result<PersistedPasswordCredential, PasswordError> {
    let mut salt_bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut salt_bytes)
        .map_err(|_| PasswordError::EntropyUnavailable)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| PasswordError::HashingFailed)?;
    salt_bytes.zeroize();
    let pepper = policy.active_pepper();
    let hasher = argon2_for(pepper, policy.params())?;
    let hash = hasher
        .hash_password(password.bytes(), &salt)
        .map_err(|_| PasswordError::HashingFailed)?
        .to_string();
    Ok(PersistedPasswordCredential {
        hash: StoredPasswordHash::new(hash)?,
        pepper_version: pepper.version(),
    })
}

fn argon2_for<'pepper>(
    pepper: &'pepper PasswordPepper,
    params: &argon2::Params,
) -> Result<Argon2<'pepper>, PasswordError> {
    match pepper.secret() {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params.clone())
                .map_err(|_| PasswordError::HashingFailed)
        }
        None => Ok(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            params.clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PasswordPepper, PasswordPolicyConfig};

    fn input(value: &str) -> PasswordInput {
        PasswordInput::new(SecretString::from(value.to_owned()))
            .unwrap_or_else(|error| panic!("valid test password rejected: {error}"))
    }

    #[test]
    fn verifies_passwords_and_redacts_secret_types() -> Result<(), Box<dyn std::error::Error>> {
        let engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
        let password = input("correct horse battery staple");
        let credential = engine.hash_password(&password)?;

        assert!(matches!(
            engine.verify(Some(&credential), &password)?,
            PasswordVerification::Verified { replacement: None }
        ));
        assert!(matches!(
            engine.verify(Some(&credential), &input("incorrect password"))?,
            PasswordVerification::Rejected
        ));
        assert!(matches!(
            engine.verify(None, &input("incorrect password"))?,
            PasswordVerification::Rejected
        ));
        assert_eq!(format!("{password:?}"), "PasswordInput([REDACTED])");
        assert!(!format!("{credential:?}").contains("correct horse"));
        Ok(())
    }

    #[test]
    fn successful_old_pepper_verification_requests_rehash() -> Result<(), Box<dyn std::error::Error>>
    {
        let old_pepper = PasswordPepper::new(1, SecretString::from("old-pepper".to_owned()))?;
        let old_policy = PasswordPolicy::new(
            PasswordPolicyConfig::default(),
            old_pepper.clone(),
            Vec::new(),
        )?;
        let old_engine = PasswordEngine::new(old_policy)?;
        let password = input("correct horse battery staple");
        let old_credential = old_engine.hash_password(&password)?;

        let active = PasswordPepper::new(2, SecretString::from("active-pepper".to_owned()))?;
        let policy =
            PasswordPolicy::new(PasswordPolicyConfig::default(), active, vec![old_pepper])?;
        let engine = PasswordEngine::new(policy)?;
        let verification = engine.verify(Some(&old_credential), &password)?;
        let PasswordVerification::Verified {
            replacement: Some(replacement),
        } = verification
        else {
            return Err("old pepper did not request a rehash".into());
        };
        assert_eq!(replacement.pepper_version(), 2);
        assert!(matches!(
            engine.verify(Some(&replacement), &password)?,
            PasswordVerification::Verified { replacement: None }
        ));
        Ok(())
    }

    #[test]
    fn missing_pepper_epoch_is_normalized_to_rejection() -> Result<(), Box<dyn std::error::Error>> {
        let old_policy = PasswordPolicy::new(
            PasswordPolicyConfig::default(),
            PasswordPepper::new(7, SecretString::from("retired-pepper".to_owned()))?,
            Vec::new(),
        )?;
        let old_engine = PasswordEngine::new(old_policy)?;
        let password = input("correct horse battery staple");
        let credential = old_engine.hash_password(&password)?;
        let current_engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
        assert!(matches!(
            current_engine.verify(Some(&credential), &password)?,
            PasswordVerification::Rejected
        ));
        Ok(())
    }

    #[test]
    fn rejects_weak_enrollment_and_hostile_policy() -> Result<(), Box<dyn std::error::Error>> {
        let engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
        assert!(matches!(
            engine.hash_password(&input("short")),
            Err(PasswordError::InvalidPasswordInput)
        ));
        let hostile = PasswordPolicyConfig {
            memory_kib: 1024,
            ..PasswordPolicyConfig::default()
        };
        assert!(PasswordPolicy::new(hostile, PasswordPepper::unpeppered(0), Vec::new()).is_err());
        let bounded = PasswordPolicyConfig {
            max_password_bytes: 16,
            ..PasswordPolicyConfig::default()
        };
        let bounded_engine = PasswordEngine::new(PasswordPolicy::new(
            bounded,
            PasswordPepper::unpeppered(0),
            Vec::new(),
        )?)?;
        let oversized = input("seventeen-bytes!!!");
        assert!(matches!(
            bounded_engine.hash_password(&oversized),
            Err(PasswordError::InvalidPasswordInput)
        ));
        assert!(matches!(
            bounded_engine.verify(None, &oversized)?,
            PasswordVerification::Rejected
        ));
        Ok(())
    }

    #[test]
    fn rejects_non_argon2id_and_hostile_persisted_work_factors()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = PasswordEngine::new(PasswordPolicy::default_unpeppered()?)?;
        let credential = engine.hash_password(&input("correct horse battery staple"))?;
        let wrong_algorithm = credential.phc().replacen("$argon2id$", "$argon2i$", 1);
        assert!(matches!(
            StoredPasswordHash::new(wrong_algorithm),
            Err(PasswordError::InvalidStoredCredential)
        ));
        let hostile_memory = credential.phc().replacen("m=19456", "m=1048577", 1);
        assert!(matches!(
            StoredPasswordHash::new(hostile_memory),
            Err(PasswordError::InvalidStoredCredential)
        ));
        Ok(())
    }
}
