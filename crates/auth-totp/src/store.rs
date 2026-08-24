use std::{
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use aws_lc_rs::aead::NONCE_LEN;
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_config::SecretString;
use rsk_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::{Connection as _, Postgres, Row as _, Transaction};
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime, UtcOffset};
use totp_rs::{Algorithm, Builder, Totp};
use uuid::{Uuid, Variant, Version};

use crate::{
    TOTP_DIGITS, TOTP_STEP_SECONDS, TotpConfig,
    crypto::{
        KeyMaterial, SEED_CIPHERTEXT_BYTES, SEED_ENCRYPTION_VERSION, SeedCipher, generate_seed,
    },
    recovery::{RecoveryCodeSet, RecoveryWorker, parse_recovery_code, valid_lookup_id},
};

const MAX_ACCOUNT_NAME_BYTES: usize = 128;
const MAX_FAILURE_COUNT: u32 = 1_000_000;

/// Non-secret TOTP credential lifecycle metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TotpCredentialMetadata {
    /// Credential row identifier.
    pub id: Uuid,
    /// Canonical human-user subject.
    pub user_id: SubjectId,
    /// Authenticator-visible account label.
    pub account_name: String,
    /// Enrollment creation time.
    pub created_at: OffsetDateTime,
    /// Confirmation time, when enrollment completed.
    pub confirmed_at: Option<OffsetDateTime>,
    /// Current durable lock expiry, when verification is locked.
    pub locked_until: Option<OffsetDateTime>,
    /// Disable time, when the credential became inactive.
    pub disabled_at: Option<OffsetDateTime>,
}

/// Persisted enrollment plus an otpauth URI available for one explicit delivery.
pub struct PendingTotpEnrollment {
    metadata: TotpCredentialMetadata,
    otpauth_uri: SecretString,
}

impl PendingTotpEnrollment {
    /// Borrows non-secret credential metadata.
    #[must_use]
    pub const fn metadata(&self) -> &TotpCredentialMetadata {
        &self.metadata
    }

    /// Consumes the enrollment and releases the secret-bearing otpauth URI once.
    #[must_use]
    pub fn expose_once(self) -> SecretString {
        self.otpauth_uri
    }
}

impl fmt::Debug for PendingTotpEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingTotpEnrollment")
            .field("metadata", &self.metadata)
            .field("otpauth_uri", &"[REDACTED]")
            .finish()
    }
}

/// Confirmed enrollment metadata plus one-time recovery-code delivery.
pub struct ConfirmedTotpEnrollment {
    metadata: TotpCredentialMetadata,
    recovery_codes: RecoveryCodeSet,
}

impl ConfirmedTotpEnrollment {
    /// Borrows non-secret credential metadata.
    #[must_use]
    pub const fn metadata(&self) -> &TotpCredentialMetadata {
        &self.metadata
    }

    /// Consumes the result and releases every plaintext recovery code once.
    #[must_use]
    pub fn expose_recovery_codes_once(self) -> Vec<SecretString> {
        self.recovery_codes.expose_once()
    }
}

impl fmt::Debug for ConfirmedTotpEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfirmedTotpEnrollment")
            .field("metadata", &self.metadata)
            .field("recovery_codes", &self.recovery_codes)
            .finish()
    }
}

/// PostgreSQL-backed encrypted TOTP and recovery-code lifecycle service.
#[derive(Clone)]
pub struct TotpStore {
    pool: PostgresPool,
    seed_cipher: SeedCipher,
    recovery_worker: RecoveryWorker,
    issuer: Arc<str>,
    skew: u16,
    recent_auth_max_age: TimeDuration,
    failure_window: TimeDuration,
    failure_threshold: u32,
    lock_duration: TimeDuration,
    recovery_code_count: usize,
}

impl fmt::Debug for TotpStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpStore")
            .field("seed_cipher", &"[REDACTED]")
            .field("recovery_pepper", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("digits", &TOTP_DIGITS)
            .field("step_seconds", &TOTP_STEP_SECONDS)
            .field("skew", &self.skew)
            .field("recent_auth_max_age", &self.recent_auth_max_age)
            .field("failure_window", &self.failure_window)
            .field("failure_threshold", &self.failure_threshold)
            .field("lock_duration", &self.lock_duration)
            .field("recovery_code_count", &self.recovery_code_count)
            .finish_non_exhaustive()
    }
}

impl TotpStore {
    /// Creates an enabled store and derives domain-separated seed and recovery subkeys.
    ///
    /// # Errors
    ///
    /// Returns a stable disabled, configuration, or cryptographic setup error.
    pub fn new(pool: PostgresPool, config: &TotpConfig) -> Result<Self, TotpStoreError> {
        config
            .validate()
            .map_err(|_| TotpStoreError::InvalidConfiguration)?;
        if !config.enabled {
            return Err(TotpStoreError::Disabled);
        }
        let master = config
            .decoded_master_key()
            .map_err(|_| TotpStoreError::InvalidConfiguration)?;
        let keys = KeyMaterial::derive(&master)?;
        Ok(Self {
            pool,
            seed_cipher: keys.seed_cipher,
            recovery_worker: RecoveryWorker::new(keys.recovery_pepper),
            issuer: Arc::from(config.issuer.as_str()),
            skew: config.skew,
            recent_auth_max_age: duration(config.recent_auth_max_age)?,
            failure_window: duration(config.verification_failure_window)?,
            failure_threshold: config.verification_failure_threshold,
            lock_duration: duration(config.verification_lock_duration)?,
            recovery_code_count: config.recovery_code_count,
        })
    }

    /// Starts a new unconfirmed enrollment for a recently authenticated human user.
    ///
    /// The encrypted seed is committed before the returned otpauth URI can be exposed.
    ///
    /// # Errors
    ///
    /// Returns a stable principal, recent-auth, lifecycle, entropy, crypto, or persistence error.
    pub async fn enroll(
        &self,
        principal: &Principal,
        account_name: &str,
    ) -> Result<PendingTotpEnrollment, TotpStoreError> {
        let started = Instant::now();
        let result = self.enroll_inner(principal, account_name).await;
        record("enroll", label(&result, "enrolled"), started.elapsed());
        result
    }

    /// Confirms enrollment with a TOTP code and creates hashed one-time recovery codes.
    ///
    /// The matched TOTP step is persisted so the confirmation code cannot be replayed.
    /// Recovery codes are returned only after their Argon2id hashes commit.
    ///
    /// # Errors
    ///
    /// Returns stable recent-auth, verification, lock, crypto, worker, or persistence errors.
    pub async fn confirm(
        &self,
        principal: &Principal,
        token: &str,
    ) -> Result<ConfirmedTotpEnrollment, TotpStoreError> {
        let started = Instant::now();
        let result = self.confirm_inner(principal, token).await;
        record("confirm", label(&result, "confirmed"), started.elapsed());
        result
    }

    /// Verifies a single-use TOTP step and returns an AAL2 canonical principal.
    ///
    /// Subject, tenant, and scopes are preserved from the first-factor principal.
    /// The credential row is locked while replay and durable failure state are updated.
    ///
    /// # Errors
    ///
    /// Returns stable principal, verification, lock, crypto, or persistence errors.
    pub async fn verify(
        &self,
        principal: &Principal,
        token: &str,
    ) -> Result<Principal, TotpStoreError> {
        let started = Instant::now();
        let result = self.verify_inner(principal, token).await;
        record("verify", label(&result, "verified"), started.elapsed());
        result
    }

    /// Consumes one recovery-code presentation and returns an AAL2 canonical principal.
    ///
    /// The presentation must be supplied as a secret value. Lookup uses only its
    /// visible identifier; Argon2id verification runs on a bounded blocking worker,
    /// and the matching row is marked used in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns stable principal, verification, lock, worker, corruption, or persistence errors.
    pub async fn verify_recovery(
        &self,
        principal: &Principal,
        presentation: SecretString,
    ) -> Result<Principal, TotpStoreError> {
        let started = Instant::now();
        let result = self.verify_recovery_inner(principal, presentation).await;
        record(
            "verify_recovery",
            label(&result, "verified"),
            started.elapsed(),
        );
        result
    }

    /// Disables the latest credential for a recently authenticated human user.
    ///
    /// Disable is idempotent, invalidates unused recovery codes, and advances the
    /// user's authentication version so existing sessions become stale.
    ///
    /// # Errors
    ///
    /// Returns stable recent-auth, lifecycle, conflict, corruption, or persistence errors.
    pub async fn disable(
        &self,
        principal: &Principal,
    ) -> Result<TotpCredentialMetadata, TotpStoreError> {
        let started = Instant::now();
        let result = self.disable_inner(principal).await;
        record("disable", label(&result, "disabled"), started.elapsed());
        result
    }

    /// Reads latest safe credential metadata without selecting seed or hash columns.
    ///
    /// # Errors
    ///
    /// Returns a stable corruption or persistence error.
    pub async fn credential_metadata(
        &self,
        user_id: SubjectId,
    ) -> Result<Option<TotpCredentialMetadata>, TotpStoreError> {
        let started = Instant::now();
        let result = self.metadata_inner(user_id).await;
        let outcome = match &result {
            Ok(Some(_)) => "found",
            Ok(None) => "not_found",
            Err(error) => error.metric_label(),
        };
        record("read_metadata", outcome, started.elapsed());
        result
    }

    async fn enroll_inner(
        &self,
        principal: &Principal,
        account_name: &str,
    ) -> Result<PendingTotpEnrollment, TotpStoreError> {
        let now = OffsetDateTime::now_utc();
        self.require_recent_human(principal, now)?;
        validate_account_name(account_name)?;

        let seed = generate_seed()?;
        let enrollment_totp = self.enrollment_totp(seed.as_ref(), account_name)?;
        let otpauth_uri = SecretString::from(
            enrollment_totp
                .to_url()
                .map_err(|_| TotpStoreError::Cryptography)?,
        );
        let encrypted = self
            .seed_cipher
            .encrypt(principal.subject_id.as_uuid(), &seed)?;
        let id = Uuid::now_v7();

        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let user_exists = sqlx::query("SELECT 1 FROM users WHERE id = $1 FOR KEY SHARE")
                .bind(principal.subject_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?
                .is_some();
            if !user_exists {
                return Err(TotpStoreError::InvalidPrincipal);
            }
            if active_credential_exists(&mut tx, principal.subject_id).await? {
                return Err(TotpStoreError::AlreadyEnrolled);
            }
            let now = OffsetDateTime::now_utc();
            self.require_recent_human(principal, now)?;
            sqlx::query(
                "INSERT INTO totp_credentials \
                 (id, user_id, account_name, seed_ciphertext, seed_nonce, seed_encryption_version, \
                  created_at, confirmed_at, last_used_step, failure_window_started_at, \
                  failure_count, locked_until, updated_at, disabled_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, 0, NULL, $7, NULL)",
            )
            .bind(id)
            .bind(principal.subject_id.as_uuid())
            .bind(account_name)
            .bind(&encrypted.ciphertext)
            .bind(encrypted.nonce.as_slice())
            .bind(SEED_ENCRYPTION_VERSION)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            Ok(PendingTotpEnrollment {
                metadata: TotpCredentialMetadata {
                    id,
                    user_id: principal.subject_id,
                    account_name: account_name.to_owned(),
                    created_at: utc(now),
                    confirmed_at: None,
                    locked_until: None,
                    disabled_at: None,
                },
                otpauth_uri,
            })
        }
        .await;
        finish(tx, result).await
    }

    async fn confirm_inner(
        &self,
        principal: &Principal,
        token: &str,
    ) -> Result<ConfirmedTotpEnrollment, TotpStoreError> {
        self.require_recent_human(principal, OffsetDateTime::now_utc())?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let validation = async {
            let credential = lock_active_credential(&mut tx, principal.subject_id)
                .await?
                .ok_or(TotpStoreError::NotEnrolled)?;
            let now = OffsetDateTime::now_utc();
            self.require_recent_human(principal, now)?;
            if credential.confirmed_at.is_some() {
                return Ok(Decision::Rejected(TotpStoreError::AlreadyConfirmed));
            }
            if credential.is_locked(now)? {
                return Ok(Decision::Rejected(TotpStoreError::Locked));
            }
            if !valid_totp_token(token) {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            }
            let seed = self.seed_cipher.decrypt(
                credential.user_id.as_uuid(),
                credential.seed_nonce,
                &credential.seed_ciphertext,
            )?;
            let totp = self.verification_totp(&seed)?;
            let Some(step) = totp.check(token, unix_seconds(now)?) else {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            };
            let step = i64::try_from(step).map_err(|_| TotpStoreError::CorruptData)?;
            Ok(Decision::Success((credential.id, step, now)))
        }
        .await;
        let (credential_id, step, confirmed_at) = finish_decision(tx, validation).await?;
        drop(connection);

        let recovery = self
            .recovery_worker
            .generate_and_hash(self.recovery_code_count)
            .await?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let credential = lock_active_credential(&mut tx, principal.subject_id)
                .await?
                .ok_or(TotpStoreError::NotEnrolled)?;
            if credential.id != credential_id {
                return Err(TotpStoreError::Conflict);
            }
            if credential.confirmed_at.is_some() {
                return Ok(Decision::Rejected(TotpStoreError::AlreadyConfirmed));
            }
            let persisted_at = OffsetDateTime::now_utc();
            let row = sqlx::query(
                "UPDATE totp_credentials SET confirmed_at = $2, last_used_step = $3, \
                 failure_window_started_at = NULL, failure_count = 0, locked_until = NULL, \
                 updated_at = $4 WHERE id = $1 AND confirmed_at IS NULL AND disabled_at IS NULL \
                 RETURNING id, user_id, account_name, created_at, confirmed_at, locked_until, \
                           disabled_at",
            )
            .bind(credential.id)
            .bind(confirmed_at)
            .bind(step)
            .bind(persisted_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            let metadata = metadata_from_row(&row)?;
            let mut presentations = Vec::with_capacity(recovery.len());
            for code in recovery {
                sqlx::query(
                    "INSERT INTO recovery_codes \
                     (id, credential_id, lookup_id, code_hash, created_at, used_at, invalidated_at) \
                     VALUES ($1, $2, $3, $4, $5, NULL, NULL)",
                )
                .bind(Uuid::now_v7())
                .bind(credential.id)
                .bind(&code.lookup_id)
                .bind(&code.phc)
                .bind(persisted_at)
                .execute(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?;
                presentations.push(code.presentation);
            }
            advance_authentication_version(&mut tx, principal.subject_id).await?;
            Ok(Decision::Success(ConfirmedTotpEnrollment {
                metadata,
                recovery_codes: RecoveryCodeSet::new(presentations),
            }))
        }
        .await;
        finish_decision(tx, result).await
    }

    async fn verify_inner(
        &self,
        principal: &Principal,
        token: &str,
    ) -> Result<Principal, TotpStoreError> {
        require_human(principal)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let credential = lock_active_credential(&mut tx, principal.subject_id)
                .await?
                .ok_or(TotpStoreError::VerificationFailed)?;
            let now = OffsetDateTime::now_utc();
            if credential.is_locked(now)? {
                return Ok(Decision::Rejected(TotpStoreError::Locked));
            }
            let Some(confirmed_at) = credential.confirmed_at else {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            };
            if confirmed_at > now {
                return Err(TotpStoreError::CorruptData);
            }
            if !valid_totp_token(token) {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            }
            let seed = self.seed_cipher.decrypt(
                credential.user_id.as_uuid(),
                credential.seed_nonce,
                &credential.seed_ciphertext,
            )?;
            let totp = self.verification_totp(&seed)?;
            let Some(step) = totp.check(token, unix_seconds(now)?) else {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            };
            let step = i64::try_from(step).map_err(|_| TotpStoreError::CorruptData)?;
            if credential
                .last_used_step
                .is_some_and(|last_used| step <= last_used)
            {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            }
            let updated = sqlx::query(
                "UPDATE totp_credentials SET last_used_step = $2, \
                 failure_window_started_at = NULL, failure_count = 0, locked_until = NULL, \
                 updated_at = $3 WHERE id = $1 AND confirmed_at IS NOT NULL \
                 AND disabled_at IS NULL",
            )
            .bind(credential.id)
            .bind(step)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            if updated.rows_affected() != 1 {
                return Err(TotpStoreError::Conflict);
            }
            Ok(Decision::Success(step_up(principal, now)?))
        }
        .await;
        finish_decision(tx, result).await
    }

    async fn verify_recovery_inner(
        &self,
        principal: &Principal,
        presentation: SecretString,
    ) -> Result<Principal, TotpStoreError> {
        require_human(principal)?;
        let Ok(candidate) = parse_recovery_code(&presentation) else {
            return self.reject_attempt(principal.subject_id).await;
        };
        let lookup_id = candidate.lookup_id;
        let Some(RecoveryLookup {
            recovery_id,
            credential_id,
            phc,
        }) = lookup_recovery_code(&self.pool, principal.subject_id, &lookup_id).await?
        else {
            return self.reject_attempt(principal.subject_id).await;
        };
        if !self
            .recovery_worker
            .verify(phc.clone(), candidate.secret)
            .await?
        {
            return self.reject_attempt(principal.subject_id).await;
        }

        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let credential = lock_active_credential(&mut tx, principal.subject_id)
                .await?
                .ok_or(TotpStoreError::VerificationFailed)?;
            let now = OffsetDateTime::now_utc();
            if credential.id != credential_id {
                return Err(TotpStoreError::VerificationFailed);
            }
            if credential.is_locked(now)? {
                return Ok(Decision::Rejected(TotpStoreError::Locked));
            }
            if credential.confirmed_at.is_none() {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            }
            let row = sqlx::query(
                "SELECT lookup_id, code_hash FROM recovery_codes \
                 WHERE id = $1 AND credential_id = $2 AND lookup_id = $3 \
                   AND used_at IS NULL AND invalidated_at IS NULL FOR UPDATE",
            )
            .bind(recovery_id)
            .bind(credential.id)
            .bind(&lookup_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            let Some(row) = row else {
                return reject_with_failure(&mut tx, &credential, now, self).await;
            };
            let persisted_lookup: String = row
                .try_get("lookup_id")
                .map_err(|_| TotpStoreError::CorruptData)?;
            let persisted_phc: String = row
                .try_get("code_hash")
                .map_err(|_| TotpStoreError::CorruptData)?;
            if persisted_lookup != lookup_id
                || !valid_lookup_id(&persisted_lookup)
                || persisted_phc != phc
            {
                return Err(TotpStoreError::CorruptData);
            }
            let consumed = sqlx::query(
                "UPDATE recovery_codes SET used_at = $2 \
                 WHERE id = $1 AND used_at IS NULL AND invalidated_at IS NULL",
            )
            .bind(recovery_id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            if consumed.rows_affected() != 1 {
                return Err(TotpStoreError::Conflict);
            }
            clear_failures(&mut tx, credential.id, now).await?;
            advance_authentication_version(&mut tx, principal.subject_id).await?;
            Ok(Decision::Success(step_up(principal, now)?))
        }
        .await;
        finish_decision(tx, result).await
    }

    async fn reject_attempt<T>(&self, user_id: SubjectId) -> Result<T, TotpStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let credential = lock_active_credential(&mut tx, user_id)
                .await?
                .ok_or(TotpStoreError::VerificationFailed)?;
            let now = OffsetDateTime::now_utc();
            if credential.is_locked(now)? {
                Ok(Decision::Rejected(TotpStoreError::Locked))
            } else {
                reject_with_failure(&mut tx, &credential, now, self).await
            }
        }
        .await;
        finish_decision(tx, result).await
    }

    async fn disable_inner(
        &self,
        principal: &Principal,
    ) -> Result<TotpCredentialMetadata, TotpStoreError> {
        let now = OffsetDateTime::now_utc();
        self.require_recent_human(principal, now)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let row = sqlx::query(
                "SELECT id, user_id, account_name, created_at, confirmed_at, locked_until, disabled_at \
                 FROM totp_credentials WHERE user_id = $1 \
                 ORDER BY (disabled_at IS NULL) DESC, created_at DESC LIMIT 1 FOR UPDATE",
            )
            .bind(principal.subject_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TotpStoreError::NotEnrolled)?;
            let metadata = metadata_from_row(&row)?;
            let now = OffsetDateTime::now_utc();
            self.require_recent_human(principal, now)?;
            if metadata.disabled_at.is_some() {
                return Ok(metadata);
            }
            let updated = sqlx::query(
                "UPDATE totp_credentials SET disabled_at = $2, updated_at = $2, \
                 failure_window_started_at = NULL, failure_count = 0, locked_until = NULL \
                 WHERE id = $1 AND disabled_at IS NULL",
            )
            .bind(metadata.id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            if updated.rows_affected() != 1 {
                return Err(TotpStoreError::Conflict);
            }
            sqlx::query(
                "UPDATE recovery_codes SET invalidated_at = $2 \
                 WHERE credential_id = $1 AND used_at IS NULL AND invalidated_at IS NULL",
            )
            .bind(metadata.id)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            advance_authentication_version(&mut tx, principal.subject_id).await?;
            Ok(TotpCredentialMetadata {
                locked_until: None,
                disabled_at: Some(utc(now)),
                ..metadata
            })
        }
        .await;
        finish(tx, result).await
    }

    async fn metadata_inner(
        &self,
        user_id: SubjectId,
    ) -> Result<Option<TotpCredentialMetadata>, TotpStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| TotpStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT id, user_id, account_name, created_at, confirmed_at, locked_until, disabled_at \
             FROM totp_credentials WHERE user_id = $1 \
             ORDER BY (disabled_at IS NULL) DESC, created_at DESC LIMIT 1",
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        row.as_ref().map(metadata_from_row).transpose()
    }

    fn require_recent_human(
        &self,
        principal: &Principal,
        now: OffsetDateTime,
    ) -> Result<(), TotpStoreError> {
        require_human(principal)?;
        let authenticated_at = utc(principal.authenticated_at);
        if authenticated_at > now || now - authenticated_at > self.recent_auth_max_age {
            return Err(TotpStoreError::RecentAuthenticationRequired);
        }
        Ok(())
    }

    fn enrollment_totp(&self, seed: &[u8], account_name: &str) -> Result<Totp, TotpStoreError> {
        Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(TOTP_DIGITS)
            .with_secret(seed)
            .with_skew(self.skew)
            .with_step_duration(TOTP_STEP_SECONDS)
            .with_account_name(account_name)
            .with_issuer(Some(self.issuer.as_ref()))
            .build()
            .map_err(|_| TotpStoreError::Cryptography)
    }

    fn verification_totp(&self, seed: &[u8]) -> Result<Totp, TotpStoreError> {
        Builder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(TOTP_DIGITS)
            .with_secret(seed)
            .with_skew(self.skew)
            .with_step_duration(TOTP_STEP_SECONDS)
            .build()
            .map_err(|_| TotpStoreError::CorruptData)
    }
}

struct CredentialRecord {
    id: Uuid,
    user_id: SubjectId,
    seed_ciphertext: Vec<u8>,
    seed_nonce: [u8; NONCE_LEN],
    created_at: OffsetDateTime,
    confirmed_at: Option<OffsetDateTime>,
    last_used_step: Option<i64>,
    failure_window_started_at: Option<OffsetDateTime>,
    failure_count: u32,
    locked_until: Option<OffsetDateTime>,
}

struct RecoveryLookup {
    recovery_id: Uuid,
    credential_id: Uuid,
    phc: String,
}

impl CredentialRecord {
    fn is_locked(&self, now: OffsetDateTime) -> Result<bool, TotpStoreError> {
        if now < self.created_at
            || self
                .confirmed_at
                .is_some_and(|confirmed_at| confirmed_at > now)
            || self
                .failure_window_started_at
                .is_some_and(|started_at| started_at > now)
        {
            return Err(TotpStoreError::CorruptData);
        }
        Ok(self
            .locked_until
            .is_some_and(|locked_until| locked_until > now))
    }
}

async fn lookup_recovery_code(
    pool: &PostgresPool,
    user_id: SubjectId,
    lookup_id: &str,
) -> Result<Option<RecoveryLookup>, TotpStoreError> {
    let mut connection = pool
        .acquire()
        .await
        .map_err(|_| TotpStoreError::Unavailable)?;
    let row = sqlx::query(
        "SELECT recovery.id AS recovery_id, recovery.code_hash, \
                credential.id AS credential_id \
         FROM recovery_codes AS recovery \
         JOIN totp_credentials AS credential ON credential.id = recovery.credential_id \
         WHERE credential.user_id = $1 AND credential.confirmed_at IS NOT NULL \
           AND credential.disabled_at IS NULL AND recovery.lookup_id = $2 \
           AND recovery.used_at IS NULL AND recovery.invalidated_at IS NULL",
    )
    .bind(user_id.as_uuid())
    .bind(lookup_id)
    .fetch_optional(&mut *connection)
    .await
    .map_err(|error| map_db(&error))?;
    row.map(|row| {
        let recovery_id: Uuid = row
            .try_get("recovery_id")
            .map_err(|_| TotpStoreError::CorruptData)?;
        validate_uuid_v7(recovery_id).map_err(|_| TotpStoreError::CorruptData)?;
        let credential_id: Uuid = row
            .try_get("credential_id")
            .map_err(|_| TotpStoreError::CorruptData)?;
        validate_uuid_v7(credential_id).map_err(|_| TotpStoreError::CorruptData)?;
        let phc = row
            .try_get("code_hash")
            .map_err(|_| TotpStoreError::CorruptData)?;
        Ok(RecoveryLookup {
            recovery_id,
            credential_id,
            phc,
        })
    })
    .transpose()
}

enum Decision<T> {
    Success(T),
    Rejected(TotpStoreError),
}

async fn active_credential_exists(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
) -> Result<bool, TotpStoreError> {
    sqlx::query(
        "SELECT 1 FROM totp_credentials WHERE user_id = $1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map(|row| row.is_some())
    .map_err(|error| map_db(&error))
}

async fn advance_authentication_version(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
) -> Result<(), TotpStoreError> {
    let updated = sqlx::query(
        "UPDATE users SET authentication_version = authentication_version + 1 \
         WHERE id = $1 AND authentication_version < 9223372036854775807",
    )
    .bind(user_id.as_uuid())
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if updated.rows_affected() == 1 {
        Ok(())
    } else {
        Err(TotpStoreError::Conflict)
    }
}

async fn lock_active_credential(
    tx: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
) -> Result<Option<CredentialRecord>, TotpStoreError> {
    let row = sqlx::query(
        "SELECT id, user_id, account_name, seed_ciphertext, seed_nonce, \
         seed_encryption_version, created_at, confirmed_at, last_used_step, \
         failure_window_started_at, failure_count, locked_until, updated_at, disabled_at \
         FROM totp_credentials WHERE user_id = $1 AND disabled_at IS NULL FOR UPDATE",
    )
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    row.as_ref().map(credential_from_row).transpose()
}

fn credential_from_row(row: &sqlx::postgres::PgRow) -> Result<CredentialRecord, TotpStoreError> {
    let id: Uuid = row.try_get("id").map_err(|_| TotpStoreError::CorruptData)?;
    validate_uuid_v7(id).map_err(|_| TotpStoreError::CorruptData)?;
    let user_id = SubjectId::from_uuid(
        row.try_get("user_id")
            .map_err(|_| TotpStoreError::CorruptData)?,
    )
    .map_err(|_| TotpStoreError::CorruptData)?;
    let account_name: String = row
        .try_get("account_name")
        .map_err(|_| TotpStoreError::CorruptData)?;
    validate_account_name(&account_name).map_err(|_| TotpStoreError::CorruptData)?;
    let seed_ciphertext: Vec<u8> = row
        .try_get("seed_ciphertext")
        .map_err(|_| TotpStoreError::CorruptData)?;
    let nonce: Vec<u8> = row
        .try_get("seed_nonce")
        .map_err(|_| TotpStoreError::CorruptData)?;
    let encryption_version: i16 = row
        .try_get("seed_encryption_version")
        .map_err(|_| TotpStoreError::CorruptData)?;
    if seed_ciphertext.len() != SEED_CIPHERTEXT_BYTES
        || nonce.len() != NONCE_LEN
        || encryption_version != SEED_ENCRYPTION_VERSION
    {
        return Err(TotpStoreError::CorruptData);
    }
    let mut seed_nonce = [0_u8; NONCE_LEN];
    seed_nonce.copy_from_slice(&nonce);
    let created_at = utc(row
        .try_get("created_at")
        .map_err(|_| TotpStoreError::CorruptData)?);
    let confirmed_at = row
        .try_get::<Option<OffsetDateTime>, _>("confirmed_at")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    let last_used_step: Option<i64> = row
        .try_get("last_used_step")
        .map_err(|_| TotpStoreError::CorruptData)?;
    let failure_window_started_at = row
        .try_get::<Option<OffsetDateTime>, _>("failure_window_started_at")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    let failure_count = u32::try_from(
        row.try_get::<i32, _>("failure_count")
            .map_err(|_| TotpStoreError::CorruptData)?,
    )
    .map_err(|_| TotpStoreError::CorruptData)?;
    let locked_until = row
        .try_get::<Option<OffsetDateTime>, _>("locked_until")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    let updated_at = utc(row
        .try_get("updated_at")
        .map_err(|_| TotpStoreError::CorruptData)?);
    let disabled_at: Option<OffsetDateTime> = row
        .try_get("disabled_at")
        .map_err(|_| TotpStoreError::CorruptData)?;
    if disabled_at.is_some()
        || updated_at < created_at
        || confirmed_at.is_some_and(|value| value < created_at)
        || last_used_step.is_some_and(|value| value < 0)
        || confirmed_at.is_none() != last_used_step.is_none()
        || failure_count > MAX_FAILURE_COUNT
        || (failure_count == 0) != failure_window_started_at.is_none()
        || locked_until.is_some() && failure_count == 0
        || failure_window_started_at.is_some_and(|value| value < created_at)
        || locked_until.is_some_and(|value| value < created_at)
    {
        return Err(TotpStoreError::CorruptData);
    }
    Ok(CredentialRecord {
        id,
        user_id,
        seed_ciphertext,
        seed_nonce,
        created_at,
        confirmed_at,
        last_used_step,
        failure_window_started_at,
        failure_count,
        locked_until,
    })
}

async fn reject_with_failure<T>(
    tx: &mut Transaction<'_, Postgres>,
    credential: &CredentialRecord,
    now: OffsetDateTime,
    store: &TotpStore,
) -> Result<Decision<T>, TotpStoreError> {
    let lock_expired = credential
        .locked_until
        .is_some_and(|locked_until| locked_until <= now);
    let within_window = !lock_expired
        && credential
            .failure_window_started_at
            .is_some_and(|started_at| started_at <= now && now - started_at < store.failure_window);
    let failure_count = if within_window {
        credential
            .failure_count
            .checked_add(1)
            .ok_or(TotpStoreError::CorruptData)?
    } else {
        1
    };
    if failure_count > MAX_FAILURE_COUNT {
        return Err(TotpStoreError::CorruptData);
    }
    let window_started_at = if within_window {
        credential
            .failure_window_started_at
            .ok_or(TotpStoreError::CorruptData)?
    } else {
        now
    };
    let locked_until = if failure_count >= store.failure_threshold {
        Some(
            now.checked_add(store.lock_duration)
                .ok_or(TotpStoreError::InvalidConfiguration)?,
        )
    } else {
        None
    };
    let updated = sqlx::query(
        "UPDATE totp_credentials SET failure_window_started_at = $2, failure_count = $3, \
         locked_until = $4, updated_at = $5 WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(credential.id)
    .bind(window_started_at)
    .bind(i32::try_from(failure_count).map_err(|_| TotpStoreError::CorruptData)?)
    .bind(locked_until)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if updated.rows_affected() != 1 {
        return Err(TotpStoreError::Conflict);
    }
    Ok(Decision::Rejected(if locked_until.is_some() {
        TotpStoreError::Locked
    } else {
        TotpStoreError::VerificationFailed
    }))
}

fn valid_totp_token(token: &str) -> bool {
    token.len() == usize::from(TOTP_DIGITS) && token.as_bytes().iter().all(u8::is_ascii_digit)
}

async fn clear_failures(
    tx: &mut Transaction<'_, Postgres>,
    credential_id: Uuid,
    now: OffsetDateTime,
) -> Result<(), TotpStoreError> {
    let updated = sqlx::query(
        "UPDATE totp_credentials SET failure_window_started_at = NULL, failure_count = 0, \
         locked_until = NULL, updated_at = $2 WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(credential_id)
    .bind(now)
    .execute(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if updated.rows_affected() != 1 {
        return Err(TotpStoreError::Conflict);
    }
    Ok(())
}

fn metadata_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<TotpCredentialMetadata, TotpStoreError> {
    let id: Uuid = row.try_get("id").map_err(|_| TotpStoreError::CorruptData)?;
    validate_uuid_v7(id).map_err(|_| TotpStoreError::CorruptData)?;
    let user_id = SubjectId::from_uuid(
        row.try_get("user_id")
            .map_err(|_| TotpStoreError::CorruptData)?,
    )
    .map_err(|_| TotpStoreError::CorruptData)?;
    let account_name: String = row
        .try_get("account_name")
        .map_err(|_| TotpStoreError::CorruptData)?;
    validate_account_name(&account_name).map_err(|_| TotpStoreError::CorruptData)?;
    let created_at = utc(row
        .try_get("created_at")
        .map_err(|_| TotpStoreError::CorruptData)?);
    let confirmed_at = row
        .try_get::<Option<OffsetDateTime>, _>("confirmed_at")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    let locked_until = row
        .try_get::<Option<OffsetDateTime>, _>("locked_until")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    let disabled_at = row
        .try_get::<Option<OffsetDateTime>, _>("disabled_at")
        .map_err(|_| TotpStoreError::CorruptData)?
        .map(utc);
    if confirmed_at.is_some_and(|value| value < created_at)
        || locked_until.is_some_and(|value| value < created_at)
        || disabled_at.is_some_and(|value| value < created_at)
    {
        return Err(TotpStoreError::CorruptData);
    }
    Ok(TotpCredentialMetadata {
        id,
        user_id,
        account_name,
        created_at,
        confirmed_at,
        locked_until,
        disabled_at,
    })
}

fn require_human(principal: &Principal) -> Result<(), TotpStoreError> {
    if principal.kind == PrincipalKind::User {
        Ok(())
    } else {
        Err(TotpStoreError::InvalidPrincipal)
    }
}

fn step_up(
    principal: &Principal,
    authenticated_at: OffsetDateTime,
) -> Result<Principal, TotpStoreError> {
    Principal::new(
        principal.subject_id,
        PrincipalKind::User,
        principal.tenant_id,
        AuthMethod::Totp,
        authenticated_at,
        AssuranceLevel::Aal2,
        principal.scopes.clone(),
    )
    .map_err(|_| TotpStoreError::InvalidPrincipal)
}

fn validate_account_name(account_name: &str) -> Result<(), TotpStoreError> {
    if account_name.is_empty()
        || account_name.len() > MAX_ACCOUNT_NAME_BYTES
        || account_name.trim() != account_name
        || account_name.contains(':')
        || account_name.chars().any(char::is_control)
    {
        Err(TotpStoreError::InvalidAccountName)
    } else {
        Ok(())
    }
}

fn duration(value: Duration) -> Result<TimeDuration, TotpStoreError> {
    TimeDuration::try_from(value).map_err(|_| TotpStoreError::InvalidConfiguration)
}

fn unix_seconds(value: OffsetDateTime) -> Result<u64, TotpStoreError> {
    u64::try_from(value.unix_timestamp()).map_err(|_| TotpStoreError::InvalidConfiguration)
}

fn utc(value: OffsetDateTime) -> OffsetDateTime {
    value.to_offset(UtcOffset::UTC)
}

fn validate_uuid_v7(value: Uuid) -> Result<(), TotpStoreError> {
    if value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122 {
        Ok(())
    } else {
        Err(TotpStoreError::InvalidIdentifier)
    }
}

async fn finish<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, TotpStoreError>,
) -> Result<T, TotpStoreError> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(|error| map_db(&error))?;
            Ok(value)
        }
        Err(operation) => {
            tx.rollback().await.map_err(|error| map_db(&error))?;
            Err(operation)
        }
    }
}

async fn finish_decision<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<Decision<T>, TotpStoreError>,
) -> Result<T, TotpStoreError> {
    match result {
        Ok(decision) => {
            tx.commit().await.map_err(|error| map_db(&error))?;
            match decision {
                Decision::Success(value) => Ok(value),
                Decision::Rejected(error) => Err(error),
            }
        }
        Err(operation) => {
            tx.rollback().await.map_err(|error| map_db(&error))?;
            Err(operation)
        }
    }
}

/// Stable, value-free TOTP lifecycle and verification errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TotpStoreError {
    /// The optional capability is disabled.
    #[error("TOTP authentication is disabled")]
    Disabled,
    /// Configuration or fixed policy conversion was invalid.
    #[error("TOTP configuration is invalid")]
    InvalidConfiguration,
    /// A non-human or otherwise unusable principal was supplied.
    #[error("TOTP principal is invalid")]
    InvalidPrincipal,
    /// Enrollment or disable requires a newer first-factor authentication.
    #[error("TOTP operation requires recent authentication")]
    RecentAuthenticationRequired,
    /// Authenticator-visible account metadata was invalid.
    #[error("TOTP account name is invalid")]
    InvalidAccountName,
    /// An active credential already exists for the user.
    #[error("TOTP credential is already enrolled")]
    AlreadyEnrolled,
    /// No credential has ever been enrolled for the user.
    #[error("TOTP credential is not enrolled")]
    NotEnrolled,
    /// The active enrollment was already confirmed.
    #[error("TOTP enrollment is already confirmed")]
    AlreadyConfirmed,
    /// The token, recovery code, lifecycle state, or replay check was rejected.
    #[error("TOTP verification failed")]
    VerificationFailed,
    /// Durable failure policy currently locks verification.
    #[error("TOTP verification is locked")]
    Locked,
    /// Operating-system cryptographic entropy was unavailable.
    #[error("TOTP secure entropy is unavailable")]
    EntropyUnavailable,
    /// A cryptographic generation or encryption operation failed.
    #[error("TOTP cryptographic operation failed")]
    Cryptography,
    /// The bounded recovery-code worker was unavailable.
    #[error("TOTP recovery-code worker is unavailable")]
    WorkerUnavailable,
    /// PostgreSQL is unavailable.
    #[error("TOTP persistence is unavailable")]
    Unavailable,
    /// A retryable PostgreSQL transaction conflict occurred.
    #[error("TOTP transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted state conflicts with the requested lifecycle transition.
    #[error("TOTP state conflicts with persisted state")]
    Conflict,
    /// A public row identifier was malformed.
    #[error("TOTP identifier is invalid")]
    InvalidIdentifier,
    /// Persisted credential, encryption, or recovery data was malformed.
    #[error("TOTP persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for TotpStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl TotpStoreError {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::InvalidPrincipal => "invalid_principal",
            Self::RecentAuthenticationRequired => "recent_authentication_required",
            Self::InvalidAccountName => "invalid_account_name",
            Self::AlreadyEnrolled => "already_enrolled",
            Self::NotEnrolled => "not_enrolled",
            Self::AlreadyConfirmed => "already_confirmed",
            Self::VerificationFailed => "verification_failed",
            Self::Locked => "locked",
            Self::EntropyUnavailable => "entropy_unavailable",
            Self::Cryptography => "cryptography",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::Conflict => "conflict",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::CorruptData => "corrupt_data",
        }
    }
}

fn map_db(error: &sqlx::Error) -> TotpStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return TotpStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23502" | "23503" | "23505" | "23514") => {
            TotpStoreError::Conflict
        }
        _ => TotpStoreError::Unavailable,
    }
}

fn label<T>(result: &Result<T, TotpStoreError>, success: &'static str) -> &'static str {
    match result {
        Ok(_) => success,
        Err(error) => error.metric_label(),
    }
}

fn record(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!(
        "rsk_auth_totp_operations_total",
        "operation" => operation,
        "result" => result
    )
    .increment(1);
    metrics::histogram!(
        "rsk_auth_totp_operation_duration_seconds",
        "operation" => operation
    )
    .record(elapsed.as_secs_f64());
}
