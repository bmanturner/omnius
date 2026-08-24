use std::{fmt, time::Duration};

use rsk_auth_core::SubjectId;
use rsk_postgres::{RetryableSqlState, RetryableTransactionError};
use sqlx::{PgConnection, Postgres, Row as _, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    IssuedToken, PasswordError, PasswordInput, PasswordVerification, PasswordWorker,
    PersistedPasswordCredential, TokenError, TokenGenerator, TokenPurpose, VerificationToken,
};

const MIN_ENUMERATION_RESPONSE_FLOOR: Duration = Duration::from_millis(500);
const MAX_ENUMERATION_RESPONSE_FLOOR: Duration = Duration::from_secs(5);

/// Delivery payload released to trusted application code only after its transaction commits.
#[derive(Debug)]
pub struct TokenDispatch {
    /// Subject that owns the token.
    pub subject_id: SubjectId,
    /// Purpose bound to the token.
    pub purpose: TokenPurpose,
    /// Opaque bearer credential.
    pub token: VerificationToken,
    /// Absolute expiry persisted with the token.
    pub expires_at: OffsetDateTime,
}

/// Pending enumeration-resistant result that cannot be observed before padding.
pub struct VerificationRequestOutcome {
    dispatch: Option<TokenDispatch>,
    not_before: tokio::time::Instant,
}

impl VerificationRequestOutcome {
    /// Completes response padding after the caller commits its transaction.
    ///
    /// The returned value exposes the constant public status and the trusted
    /// post-commit dispatch decision. Calling this before commit violates the API contract.
    pub async fn complete_after_commit(self) -> CompletedVerificationRequest {
        tokio::time::sleep_until(self.not_before).await;
        CompletedVerificationRequest {
            dispatch: self.dispatch,
        }
    }
}

impl fmt::Debug for VerificationRequestOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerificationRequestOutcome([PENDING])")
    }
}

/// Enumeration-padded result safe to map into an external response.
#[derive(Debug)]
pub struct CompletedVerificationRequest {
    dispatch: Option<TokenDispatch>,
}

impl CompletedVerificationRequest {
    /// Returns the only public-facing request status.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        true
    }

    /// Releases the trusted dispatch decision after response padding completed.
    #[must_use]
    pub fn into_post_commit_dispatch(self) -> Option<TokenDispatch> {
        self.dispatch
    }
}

/// Result of consuming a single-use token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenConsumption {
    /// The token was invalid, expired, replayed, invalidated, or security-version stale.
    Rejected,
    /// The token was consumed exactly once for this subject.
    Consumed(SubjectId),
}

/// Bounded inputs for an enumeration-resistant identity token request.
#[derive(Clone, Copy)]
pub struct IdentityTokenRequest<'a> {
    /// Opaque identity provider identifier.
    pub provider: &'a str,
    /// Opaque provider-scoped subject identifier.
    pub provider_subject: &'a str,
    /// Purpose bound to the issued token.
    pub purpose: TokenPurpose,
    /// Current application time.
    pub now: OffsetDateTime,
    /// Validity period.
    pub ttl: Duration,
    /// Minimum externally observable response duration.
    pub response_floor: Duration,
}

impl fmt::Debug for IdentityTokenRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityTokenRequest")
            .field("provider", &self.provider)
            .field("provider_subject", &"[REDACTED]")
            .field("purpose", &self.purpose)
            .field("now", &self.now)
            .field("ttl", &self.ttl)
            .field("response_floor", &self.response_floor)
            .finish()
    }
}

/// Stateless PostgreSQL adapter. Every method uses a caller-owned connection or transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct PostgresPasswordStore;

impl PostgresPasswordStore {
    /// Loads and validates the password credential for a subject.
    ///
    /// # Errors
    ///
    /// Returns a stable store error for unavailable or corrupt persistence.
    pub async fn load_credential_with(
        &self,
        connection: &mut PgConnection,
        subject_id: SubjectId,
    ) -> Result<Option<PersistedPasswordCredential>, PasswordStoreError> {
        let row = sqlx::query(
            "SELECT password_hash, pepper_version FROM password_credentials WHERE user_id = $1",
        )
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        row.map(|row| {
            let hash: String = row
                .try_get("password_hash")
                .map_err(|_| PasswordStoreError::CorruptData)?;
            let version: i64 = row
                .try_get("pepper_version")
                .map_err(|_| PasswordStoreError::CorruptData)?;
            let version = u32::try_from(version).map_err(|_| PasswordStoreError::CorruptData)?;
            PersistedPasswordCredential::restore(hash, version)
                .map_err(|_| PasswordStoreError::CorruptData)
        })
        .transpose()
    }

    /// Verifies a password and atomically persists a successful policy rehash.
    ///
    /// The caller owns transaction begin, retry, commit, and rollback.
    ///
    /// # Errors
    ///
    /// Returns stable password or persistence failures without exposing secrets.
    pub async fn verify_password_with(
        &self,
        connection: &mut PgConnection,
        subject_id: SubjectId,
        candidate: PasswordInput,
        worker: &PasswordWorker,
        now: OffsetDateTime,
    ) -> Result<PasswordVerification, PasswordStoreError> {
        let credential = self.load_credential_with(connection, subject_id).await?;
        let result = worker
            .verify(credential.clone(), candidate)
            .await
            .map_err(map_password_error)?;
        if let PasswordVerification::Verified {
            replacement: Some(replacement),
        } = &result
        {
            let current = credential.as_ref().ok_or(PasswordStoreError::CorruptData)?;
            let updated = sqlx::query(
                "UPDATE password_credentials SET password_hash = $2, pepper_version = $3, \
                 updated_at = $4 WHERE user_id = $1 \
                 AND password_hash = $5 AND pepper_version = $6",
            )
            .bind(subject_id.as_uuid())
            .bind(replacement.phc())
            .bind(i64::from(replacement.pepper_version()))
            .bind(now)
            .bind(current.phc())
            .bind(i64::from(current.pepper_version()))
            .execute(&mut *connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
            if updated.rows_affected() != 1 {
                return Err(PasswordStoreError::Conflict);
            }
        }
        Ok(result)
    }

    /// Replaces a password, advances the subject security version, and invalidates
    /// every outstanding verification/recovery token in the caller's transaction.
    ///
    /// # Errors
    ///
    /// Returns a stable store error for missing users, conflicts, or unavailability.
    pub async fn replace_password_with(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        subject_id: SubjectId,
        credential: &PersistedPasswordCredential,
        now: OffsetDateTime,
    ) -> Result<(), PasswordStoreError> {
        let locked = sqlx::query("SELECT id FROM users WHERE id = $1 FOR UPDATE")
            .bind(subject_id.as_uuid())
            .fetch_optional(&mut **connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
        if locked.is_none() {
            return Err(PasswordStoreError::NotFound);
        }
        upsert_credential(connection, subject_id, credential, now).await?;
        advance_security_version(connection, subject_id, now).await
    }

    /// Issues a verification token for a known subject in the caller's transaction.
    /// Existing active tokens for the same purpose are invalidated first.
    ///
    /// # Errors
    ///
    /// Returns stable validation, entropy, conflict, or availability failures.
    pub async fn issue_for_subject_with<G: TokenGenerator + ?Sized>(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        subject_id: SubjectId,
        purpose: TokenPurpose,
        now: OffsetDateTime,
        ttl: Duration,
        generator: &G,
    ) -> Result<TokenDispatch, PasswordStoreError> {
        let expires_at = checked_expiry(now, ttl)?;
        let issued = generator.generate().map_err(map_token_error)?;
        let version = lock_security_version(connection, subject_id)
            .await?
            .ok_or(PasswordStoreError::NotFound)?;
        persist_issued_token(
            connection, subject_id, purpose, version, now, expires_at, &issued,
        )
        .await?;
        Ok(TokenDispatch {
            subject_id,
            purpose,
            token: issued.token,
            expires_at,
        })
    }

    /// Requests a token by opaque identity provider and subject.
    ///
    /// Token generation and a database lookup happen for known and unknown identities;
    /// the externally visible outcome is always accepted. Only trusted post-commit code
    /// observes whether a dispatch exists.
    ///
    /// # Errors
    ///
    /// Returns an operational failure that callers must map independently of identity presence.
    pub async fn request_for_identity_with<G: TokenGenerator + ?Sized>(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        request: IdentityTokenRequest<'_>,
        generator: &G,
    ) -> Result<VerificationRequestOutcome, PasswordStoreError> {
        let not_before = tokio::time::Instant::now() + request.response_floor;
        validate_identity_request(request)?;
        let expires_at = checked_expiry(request.now, request.ttl)?;
        let issued = generator.generate().map_err(map_token_error)?;
        let subject_row = sqlx::query(
            "SELECT u.id, u.authentication_version FROM identities i \
             JOIN users u ON u.id = i.user_id \
             WHERE i.provider = $1 AND i.provider_subject = $2 FOR UPDATE OF u",
        )
        .bind(request.provider)
        .bind(request.provider_subject)
        .fetch_optional(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let (user_id, security_version) = match subject_row {
            Some(row) => {
                let user_id: Uuid = row
                    .try_get("id")
                    .map_err(|_| PasswordStoreError::CorruptData)?;
                let security_version: i64 = row
                    .try_get("authentication_version")
                    .map_err(|_| PasswordStoreError::CorruptData)?;
                if security_version <= 0 {
                    return Err(PasswordStoreError::CorruptData);
                }
                (Some(user_id), Some(security_version))
            }
            None => (None, None),
        };
        let row = sqlx::query(
            "WITH subject AS ( \
                 SELECT $1::uuid AS id, $2::bigint AS authentication_version \
                 WHERE $1 IS NOT NULL AND $2 > 0 \
             ), invalidated AS ( \
                 UPDATE verification_tokens vt SET invalidated_at = $6 FROM subject s \
                 WHERE vt.user_id = s.id AND vt.purpose = $3 \
                   AND vt.consumed_at IS NULL AND vt.invalidated_at IS NULL \
                 RETURNING vt.id \
             ), inserted AS ( \
                 INSERT INTO verification_tokens \
                   (id, user_id, purpose, token_hash, security_version, created_at, expires_at) \
                 SELECT $7, s.id, $3, $4, s.authentication_version, $6, $5 \
                 FROM subject s \
                 CROSS JOIN (SELECT count(*) FROM invalidated) completed \
                 RETURNING user_id \
             ) SELECT user_id FROM inserted",
        )
        .bind(user_id)
        .bind(security_version)
        .bind(request.purpose.as_db())
        .bind(issued.digest.as_bytes().as_slice())
        .bind(expires_at)
        .bind(request.now)
        .bind(Uuid::now_v7())
        .fetch_optional(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let dispatch = row
            .map(|row| {
                let user_id: Uuid = row
                    .try_get("user_id")
                    .map_err(|_| PasswordStoreError::CorruptData)?;
                let subject_id =
                    SubjectId::from_uuid(user_id).map_err(|_| PasswordStoreError::CorruptData)?;
                Ok(TokenDispatch {
                    subject_id,
                    purpose: request.purpose,
                    token: issued.token,
                    expires_at,
                })
            })
            .transpose()?;
        Ok(VerificationRequestOutcome {
            dispatch,
            not_before,
        })
    }

    /// Atomically consumes a valid token for the requested purpose.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure. Invalid presentations return `Rejected`.
    pub async fn consume_token_with(
        &self,
        connection: &mut PgConnection,
        token: &VerificationToken,
        purpose: TokenPurpose,
        now: OffsetDateTime,
    ) -> Result<TokenConsumption, PasswordStoreError> {
        let row = sqlx::query(
            "UPDATE verification_tokens vt SET consumed_at = $3 FROM users u \
             WHERE vt.user_id = u.id AND vt.token_hash = $1 AND vt.purpose = $2 \
               AND vt.consumed_at IS NULL AND vt.invalidated_at IS NULL \
               AND vt.expires_at > $3 AND vt.security_version = u.authentication_version \
             RETURNING vt.user_id",
        )
        .bind(token.digest().as_bytes().as_slice())
        .bind(purpose.as_db())
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        consumed_subject(row)
    }

    /// Consumes a recovery token and replaces the password in one caller-owned transaction.
    /// A concurrent replay can win at most once.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure. Invalid or replayed tokens return `Rejected`.
    pub async fn recover_password_with(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        token: &VerificationToken,
        credential: &PersistedPasswordCredential,
        now: OffsetDateTime,
    ) -> Result<TokenConsumption, PasswordStoreError> {
        let row = sqlx::query(
            "SELECT vt.user_id FROM verification_tokens vt \
             JOIN users u ON u.id = vt.user_id \
             WHERE vt.token_hash = $1 AND vt.purpose = 'password_recovery' \
               AND vt.consumed_at IS NULL AND vt.invalidated_at IS NULL \
               AND vt.expires_at > $2 AND vt.security_version = u.authentication_version \
             FOR UPDATE OF vt, u",
        )
        .bind(token.digest().as_bytes().as_slice())
        .bind(now)
        .fetch_optional(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let Some(row) = row else {
            return Ok(TokenConsumption::Rejected);
        };
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| PasswordStoreError::CorruptData)?;
        let subject_id =
            SubjectId::from_uuid(user_id).map_err(|_| PasswordStoreError::CorruptData)?;
        let consumed = sqlx::query(
            "UPDATE verification_tokens SET consumed_at = $2 \
             WHERE token_hash = $1 AND consumed_at IS NULL AND invalidated_at IS NULL",
        )
        .bind(token.digest().as_bytes().as_slice())
        .bind(now)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if consumed.rows_affected() != 1 {
            return Ok(TokenConsumption::Rejected);
        }
        upsert_credential(connection, subject_id, credential, now).await?;
        advance_security_version(connection, subject_id, now).await?;
        Ok(TokenConsumption::Consumed(subject_id))
    }
}

async fn lock_security_version(
    connection: &mut PgConnection,
    subject_id: SubjectId,
) -> Result<Option<i64>, PasswordStoreError> {
    let row = sqlx::query("SELECT authentication_version FROM users WHERE id = $1 FOR UPDATE")
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
    row.map(|row| {
        let version: i64 = row
            .try_get("authentication_version")
            .map_err(|_| PasswordStoreError::CorruptData)?;
        (version > 0)
            .then_some(version)
            .ok_or(PasswordStoreError::CorruptData)
    })
    .transpose()
}

async fn persist_issued_token(
    connection: &mut PgConnection,
    subject_id: SubjectId,
    purpose: TokenPurpose,
    security_version: i64,
    now: OffsetDateTime,
    expires_at: OffsetDateTime,
    issued: &IssuedToken,
) -> Result<(), PasswordStoreError> {
    sqlx::query(
        "UPDATE verification_tokens SET invalidated_at = $3 \
         WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL AND invalidated_at IS NULL",
    )
    .bind(subject_id.as_uuid())
    .bind(purpose.as_db())
    .bind(now)
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    sqlx::query(
        "INSERT INTO verification_tokens \
         (id, user_id, purpose, token_hash, security_version, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(purpose.as_db())
    .bind(issued.digest.as_bytes().as_slice())
    .bind(security_version)
    .bind(now)
    .bind(expires_at)
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    Ok(())
}

async fn upsert_credential(
    connection: &mut PgConnection,
    subject_id: SubjectId,
    credential: &PersistedPasswordCredential,
    now: OffsetDateTime,
) -> Result<(), PasswordStoreError> {
    sqlx::query(
        "INSERT INTO password_credentials \
         (user_id, password_hash, pepper_version, created_at, changed_at, updated_at) \
         VALUES ($1, $2, $3, $4, $4, $4) \
         ON CONFLICT (user_id) DO UPDATE SET \
           password_hash = EXCLUDED.password_hash, pepper_version = EXCLUDED.pepper_version, \
           changed_at = EXCLUDED.changed_at, updated_at = EXCLUDED.updated_at",
    )
    .bind(subject_id.as_uuid())
    .bind(credential.phc())
    .bind(i64::from(credential.pepper_version()))
    .bind(now)
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    Ok(())
}

async fn advance_security_version(
    connection: &mut PgConnection,
    subject_id: SubjectId,
    now: OffsetDateTime,
) -> Result<(), PasswordStoreError> {
    let updated = sqlx::query(
        "UPDATE users SET authentication_version = authentication_version + 1 \
         WHERE id = $1 AND authentication_version < 9223372036854775807",
    )
    .bind(subject_id.as_uuid())
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    if updated.rows_affected() != 1 {
        return Err(PasswordStoreError::Conflict);
    }
    sqlx::query(
        "UPDATE verification_tokens SET invalidated_at = $2 \
         WHERE user_id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL",
    )
    .bind(subject_id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    Ok(())
}

fn validate_identity_request(request: IdentityTokenRequest<'_>) -> Result<(), PasswordStoreError> {
    let provider_len = request.provider.len();
    let subject_len = request.provider_subject.len();
    if provider_len == 0
        || provider_len > 2048
        || subject_len == 0
        || subject_len > 255
        || provider_len + subject_len > 2303
        || request.provider.trim() != request.provider
        || request.provider_subject.trim() != request.provider_subject
        || !(MIN_ENUMERATION_RESPONSE_FLOOR..=MAX_ENUMERATION_RESPONSE_FLOOR)
            .contains(&request.response_floor)
    {
        return Err(PasswordStoreError::InvalidRequest);
    }
    Ok(())
}

fn checked_expiry(
    now: OffsetDateTime,
    ttl: Duration,
) -> Result<OffsetDateTime, PasswordStoreError> {
    if !(Duration::from_mins(5)..=Duration::from_hours(24)).contains(&ttl) {
        return Err(PasswordStoreError::InvalidRequest);
    }
    let ttl = time::Duration::try_from(ttl).map_err(|_| PasswordStoreError::InvalidRequest)?;
    now.checked_add(ttl)
        .filter(|expires_at| *expires_at > now)
        .ok_or(PasswordStoreError::InvalidRequest)
}

fn consumed_subject(
    row: Option<sqlx::postgres::PgRow>,
) -> Result<TokenConsumption, PasswordStoreError> {
    let Some(row) = row else {
        return Ok(TokenConsumption::Rejected);
    };
    let user_id: Uuid = row
        .try_get("user_id")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    let subject_id = SubjectId::from_uuid(user_id).map_err(|_| PasswordStoreError::CorruptData)?;
    Ok(TokenConsumption::Consumed(subject_id))
}

/// Stable, value-free password persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PasswordStoreError {
    /// PostgreSQL is unavailable.
    #[error("password persistence is unavailable")]
    Unavailable,
    /// The caller may replay the whole transaction after a safe SQL transient.
    #[error("password transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted state or a uniqueness constraint conflicts with the operation.
    #[error("password state conflicts with persisted state")]
    Conflict,
    /// The requested subject does not exist.
    #[error("password subject was not found")]
    NotFound,
    /// Persisted password state violated the module contract.
    #[error("password persistence contains invalid state")]
    CorruptData,
    /// A request lifetime or time calculation was invalid.
    #[error("password request is invalid")]
    InvalidRequest,
    /// Password processing failed without exposing secret material.
    #[error("password processing failed")]
    Password,
    /// Secure token processing failed.
    #[error("verification token processing failed")]
    Token,
}

impl RetryableTransactionError for PasswordStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> PasswordStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return PasswordStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23503" | "23505" | "23514" | "23502") => {
            PasswordStoreError::Conflict
        }
        _ => PasswordStoreError::Unavailable,
    }
}

const fn map_password_error(_error: PasswordError) -> PasswordStoreError {
    PasswordStoreError::Password
}

const fn map_token_error(_error: TokenError) -> PasswordStoreError {
    PasswordStoreError::Token
}
