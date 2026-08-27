//! PostgreSQL-backed OIDC identity resolution, linking, and unlinking.

use std::{
    fmt,
    time::{Duration, Instant},
};

use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::{Connection as _, PgConnection, Postgres, Row as _, Transaction};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{CompletedAuthorization, FlowPurpose, OidcConfig, VerifiedIdentity};

const MAX_PROVIDER_BYTES: usize = 2_048;
const MAX_PROVIDER_SUBJECT_BYTES: usize = 255;
const MAX_IDENTITY_KEY_BYTES: usize = MAX_PROVIDER_BYTES + MAX_PROVIDER_SUBJECT_BYTES;

/// The account operation completed from a verified OIDC authorization.
#[derive(Clone, Eq, PartialEq)]
pub enum AccountOutcome {
    /// An existing external identity authenticated its linked user.
    Login(Principal),
    /// A verified external identity authenticated the target user and was linked.
    Link {
        /// The canonical authenticated user.
        principal: Principal,
        /// Whether this call created the link or observed the same existing link.
        outcome: IdentityLinkOutcome,
    },
}

impl AccountOutcome {
    /// Returns the canonical principal established by the authorization.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        match self {
            Self::Login(principal) | Self::Link { principal, .. } => principal,
        }
    }

    /// Consumes the outcome and returns its canonical principal.
    #[must_use]
    pub fn into_principal(self) -> Principal {
        match self {
            Self::Login(principal) | Self::Link { principal, .. } => principal,
        }
    }

    /// Returns the link result for a link authorization.
    #[must_use]
    pub const fn link_outcome(&self) -> Option<IdentityLinkOutcome> {
        match self {
            Self::Login(_) => None,
            Self::Link { outcome, .. } => Some(*outcome),
        }
    }
}

impl fmt::Debug for AccountOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Login(_) => formatter.write_str("Login([REDACTED])"),
            Self::Link { outcome, .. } => formatter
                .debug_struct("Link")
                .field("principal", &"[REDACTED]")
                .field("outcome", outcome)
                .finish(),
        }
    }
}

/// Result of linking an external identity to its requested user.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityLinkOutcome {
    /// A new identity row was created.
    Linked,
    /// The exact external identity was already linked to the same user.
    AlreadyLinked,
}

/// Result of requesting removal of an exact external identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnlinkOutcome {
    /// The identity was removed and the user's authentication version advanced.
    Unlinked,
    /// The exact external identity was not linked to the requested user.
    NotLinked,
}

/// OIDC identity persistence backed by a managed PostgreSQL pool.
///
/// Each public operation owns its transaction boundary so account-linking and
/// recovery-method invariants cannot be committed partially by a caller.
#[derive(Clone, Debug)]
pub struct OidcIdentityStore {
    pool: PostgresPool,
    link_proof_max_age: Duration,
}

impl OidcIdentityStore {
    /// Creates an identity store that shares the managed PostgreSQL pool and link-proof policy.
    #[must_use]
    pub const fn new(pool: PostgresPool, config: &OidcConfig) -> Self {
        Self {
            pool,
            link_proof_max_age: config.link_proof_max_age,
        }
    }

    /// Resolves a verified login or links a verified identity to its authorized user.
    ///
    /// Login never creates an account or links by email. Link authorizations are
    /// idempotent only when the existing external identity belongs to the same user.
    ///
    /// # Errors
    ///
    /// Returns [`OidcStoreError::IdentityNotLinked`] for an unknown login identity,
    /// [`OidcStoreError::IdentityConflict`] for a cross-user link, or another stable,
    /// value-free error for invalid or unavailable persistence state.
    pub async fn complete(
        &self,
        authorization: CompletedAuthorization,
    ) -> Result<AccountOutcome, OidcStoreError> {
        let started = Instant::now();
        let operation = match &authorization.purpose {
            FlowPurpose::Login => "login",
            FlowPurpose::Link { .. } => "link",
        };
        let result = match validate_identity(&authorization.identity) {
            Ok(()) => self.complete_transaction(authorization).await,
            Err(error) => Err(error),
        };
        record_operation(operation, account_result_label(&result), started.elapsed());
        result
    }

    /// Removes an exact external identity after recent authenticated-user proof.
    ///
    /// A missing or differently owned identity returns [`UnlinkOutcome::NotLinked`].
    /// Removal is rejected unless a password credential or another external identity
    /// remains. A successful removal advances `users.authentication_version` in the
    /// same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`OidcStoreError::RecentAuthenticationRequired`] for stale or non-user proof,
    /// [`OidcStoreError::LastRecoveryMethod`] when removal would strand the account, or
    /// another stable, value-free validation or persistence error.
    pub async fn unlink(
        &self,
        principal: &Principal,
        provider: &str,
        provider_subject: &str,
    ) -> Result<UnlinkOutcome, OidcStoreError> {
        let started = Instant::now();
        let result = if recent_user_proof(principal, self.link_proof_max_age) {
            match validate_identity_parts(provider, provider_subject) {
                Ok(()) => {
                    self.unlink_transaction(principal.subject_id, provider, provider_subject)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            Err(OidcStoreError::RecentAuthenticationRequired)
        };
        record_operation("unlink", unlink_result_label(result), started.elapsed());
        result
    }
    async fn complete_transaction(
        &self,
        authorization: CompletedAuthorization,
    ) -> Result<AccountOutcome, OidcStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OidcStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|error| map_sqlx_error(&error))?;
        let CompletedAuthorization { identity, purpose } = authorization;
        let result = match purpose {
            FlowPurpose::Login => login_with(&mut transaction, identity)
                .await
                .map(AccountOutcome::Login),
            FlowPurpose::Link {
                subject_id,
                proof_expires_at,
            } => link_with(&mut transaction, subject_id, proof_expires_at, identity)
                .await
                .map(|(principal, outcome)| AccountOutcome::Link { principal, outcome }),
        };
        finish_transaction(transaction, result).await
    }

    async fn unlink_transaction(
        &self,
        subject_id: SubjectId,
        provider: &str,
        provider_subject: &str,
    ) -> Result<UnlinkOutcome, OidcStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OidcStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|error| map_sqlx_error(&error))?;
        let result = unlink_with(&mut transaction, subject_id, provider, provider_subject).await;
        finish_transaction(transaction, result).await
    }
}

async fn finish_transaction<T>(
    transaction: Transaction<'_, Postgres>,
    result: Result<T, OidcStoreError>,
) -> Result<T, OidcStoreError> {
    match result {
        Ok(value) => {
            transaction
                .commit()
                .await
                .map_err(|error| map_sqlx_error(&error))?;
            Ok(value)
        }
        Err(operation_error) => {
            transaction
                .rollback()
                .await
                .map_err(|error| map_sqlx_error(&error))?;
            Err(operation_error)
        }
    }
}

async fn login_with(
    transaction: &mut Transaction<'_, Postgres>,
    identity: VerifiedIdentity,
) -> Result<Principal, OidcStoreError> {
    let VerifiedIdentity {
        provider,
        provider_subject,
        authenticated_at,
    } = identity;
    let row = sqlx::query(
        "SELECT u.id FROM identities i \
         JOIN users u ON u.id = i.user_id \
         WHERE i.provider = $1 AND i.provider_subject = $2",
    )
    .bind(&provider)
    .bind(&provider_subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    let row = row.ok_or(OidcStoreError::IdentityNotLinked)?;
    let user_id: Uuid = row.try_get("id").map_err(|_| OidcStoreError::CorruptData)?;
    let subject_id = SubjectId::from_uuid(user_id).map_err(|_| OidcStoreError::CorruptData)?;
    principal(subject_id, authenticated_at)
}

async fn link_with(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: SubjectId,
    proof_expires_at: OffsetDateTime,
    identity: VerifiedIdentity,
) -> Result<(Principal, IdentityLinkOutcome), OidcStoreError> {
    let VerifiedIdentity {
        provider,
        provider_subject,
        authenticated_at,
    } = identity;
    lock_user(transaction, subject_id)
        .await?
        .ok_or(OidcStoreError::UserNotFound)?;
    if OffsetDateTime::now_utc() >= proof_expires_at {
        return Err(OidcStoreError::RecentAuthenticationRequired);
    }

    let inserted = sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) \
         VALUES ($1, $2, $3, $4, $5) \
         ON CONFLICT (provider, provider_subject) DO NOTHING \
         RETURNING id",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(&provider)
    .bind(&provider_subject)
    .bind(authenticated_at)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx_error(&error))?;

    let outcome = if inserted.is_some() {
        IdentityLinkOutcome::Linked
    } else {
        let owner = sqlx::query(
            "SELECT user_id FROM identities WHERE provider = $1 AND provider_subject = $2",
        )
        .bind(&provider)
        .bind(&provider_subject)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let Some(owner) = owner else {
            return Err(OidcStoreError::IdentityConflict);
        };
        let owner_id: Uuid = owner
            .try_get("user_id")
            .map_err(|_| OidcStoreError::CorruptData)?;
        if owner_id != subject_id.as_uuid() {
            return Err(OidcStoreError::IdentityConflict);
        }
        IdentityLinkOutcome::AlreadyLinked
    };

    Ok((principal(subject_id, authenticated_at)?, outcome))
}

async fn unlink_with(
    transaction: &mut Transaction<'_, Postgres>,
    subject_id: SubjectId,
    provider: &str,
    provider_subject: &str,
) -> Result<UnlinkOutcome, OidcStoreError> {
    let authentication_version = lock_user(transaction, subject_id)
        .await?
        .ok_or(OidcStoreError::UserNotFound)?;
    let identity = sqlx::query(
        "SELECT id FROM identities \
         WHERE user_id = $1 AND provider = $2 AND provider_subject = $3 \
         FOR UPDATE",
    )
    .bind(subject_id.as_uuid())
    .bind(provider)
    .bind(provider_subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    let Some(identity) = identity else {
        return Ok(UnlinkOutcome::NotLinked);
    };
    let identity_id: Uuid = identity
        .try_get("id")
        .map_err(|_| OidcStoreError::CorruptData)?;
    if authentication_version == i64::MAX {
        return Err(OidcStoreError::Conflict);
    }

    let another_identity =
        sqlx::query("SELECT 1 FROM identities WHERE user_id = $1 AND id <> $2 LIMIT 1 FOR UPDATE")
            .bind(subject_id.as_uuid())
            .bind(identity_id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
    let password_credential = if another_identity.is_none() {
        sqlx::query("SELECT 1 FROM password_credentials WHERE user_id = $1 FOR SHARE")
            .bind(subject_id.as_uuid())
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| map_sqlx_error(&error))?
    } else {
        None
    };
    if another_identity.is_none() && password_credential.is_none() {
        return Err(OidcStoreError::LastRecoveryMethod);
    }

    let unlinked = sqlx::query(
        "WITH deleted AS ( \
             DELETE FROM identities WHERE id = $1 AND user_id = $2 RETURNING user_id \
         ) \
         UPDATE users AS u \
         SET authentication_version = u.authentication_version + 1 \
         FROM deleted \
         WHERE u.id = deleted.user_id AND u.authentication_version = $3 \
         RETURNING u.id",
    )
    .bind(identity_id)
    .bind(subject_id.as_uuid())
    .bind(authentication_version)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    if unlinked.is_none() {
        return Err(OidcStoreError::Conflict);
    }
    Ok(UnlinkOutcome::Unlinked)
}

async fn lock_user(
    connection: &mut PgConnection,
    subject_id: SubjectId,
) -> Result<Option<i64>, OidcStoreError> {
    let row = sqlx::query("SELECT authentication_version FROM users WHERE id = $1 FOR UPDATE")
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
    row.map(|row| {
        let version: i64 = row
            .try_get("authentication_version")
            .map_err(|_| OidcStoreError::CorruptData)?;
        (version > 0)
            .then_some(version)
            .ok_or(OidcStoreError::CorruptData)
    })
    .transpose()
}

fn principal(
    subject_id: SubjectId,
    authenticated_at: OffsetDateTime,
) -> Result<Principal, OidcStoreError> {
    Principal::new(
        subject_id,
        PrincipalKind::User,
        None,
        AuthMethod::Oidc,
        authenticated_at,
        AssuranceLevel::Aal1,
        Vec::new(),
    )
    .map_err(|_| OidcStoreError::CorruptData)
}

fn validate_identity(identity: &VerifiedIdentity) -> Result<(), OidcStoreError> {
    validate_identity_parts(&identity.provider, &identity.provider_subject)
}

fn validate_identity_parts(provider: &str, provider_subject: &str) -> Result<(), OidcStoreError> {
    let provider_bytes = provider.len();
    let subject_bytes = provider_subject.len();
    if provider_bytes == 0
        || provider_bytes > MAX_PROVIDER_BYTES
        || subject_bytes == 0
        || subject_bytes > MAX_PROVIDER_SUBJECT_BYTES
        || provider_bytes + subject_bytes > MAX_IDENTITY_KEY_BYTES
        || provider.trim() != provider
        || provider_subject.trim() != provider_subject
        || provider.contains('\0')
        || provider_subject.contains('\0')
    {
        return Err(OidcStoreError::InvalidIdentity);
    }
    Ok(())
}

fn recent_user_proof(principal: &Principal, max_age: Duration) -> bool {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let authenticated_at = principal.authenticated_at.unix_timestamp();
    principal.kind == PrincipalKind::User
        && authenticated_at <= now.saturating_add(30)
        && u64::try_from(now.saturating_sub(authenticated_at))
            .is_ok_and(|age| age <= max_age.as_secs())
}

/// Stable, value-free OIDC identity persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum OidcStoreError {
    /// PostgreSQL is unavailable.
    #[error("OIDC identity persistence is unavailable")]
    Unavailable,
    /// The operation encountered a safe-to-retry SQL transaction conflict.
    #[error("OIDC identity transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted state conflicts with the requested operation.
    #[error("OIDC identity state conflicts with persisted state")]
    Conflict,
    /// No user exists for the requested account operation.
    #[error("OIDC identity user was not found")]
    UserNotFound,
    /// A login identity has no explicit account link.
    #[error("OIDC identity is not linked")]
    IdentityNotLinked,
    /// The external identity belongs to a different user.
    #[error("OIDC identity conflicts with another account")]
    IdentityConflict,
    /// The external identity was empty, oversized, non-canonical, or not persistable.
    #[error("OIDC identity input is invalid")]
    InvalidIdentity,
    /// Persisted identity state violated the module contract.
    #[error("OIDC identity persistence contains invalid state")]
    CorruptData,
    /// Unlinking would leave the user without another authentication method.
    #[error("OIDC identity is the last recovery method")]
    LastRecoveryMethod,
    /// The unlink request lacked recent authenticated-user proof.
    #[error("OIDC identity unlink requires recent authentication")]
    RecentAuthenticationRequired,
}

impl RetryableTransactionError for OidcStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl OidcStoreError {
    const fn label(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::Conflict => "conflict",
            Self::UserNotFound => "user_not_found",
            Self::IdentityNotLinked => "identity_not_linked",
            Self::IdentityConflict => "identity_conflict",
            Self::InvalidIdentity => "invalid_identity",
            Self::CorruptData => "corrupt_data",
            Self::LastRecoveryMethod => "last_recovery_method",
            Self::RecentAuthenticationRequired => "recent_authentication_required",
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> OidcStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return OidcStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23502" | "23503" | "23505" | "23514") => {
            OidcStoreError::Conflict
        }
        _ => OidcStoreError::Unavailable,
    }
}

fn account_result_label(result: &Result<AccountOutcome, OidcStoreError>) -> &'static str {
    match result {
        Ok(AccountOutcome::Login(_)) => "authenticated",
        Ok(AccountOutcome::Link {
            outcome: IdentityLinkOutcome::Linked,
            ..
        }) => "linked",
        Ok(AccountOutcome::Link {
            outcome: IdentityLinkOutcome::AlreadyLinked,
            ..
        }) => "already_linked",
        Err(error) => (*error).label(),
    }
}

fn unlink_result_label(result: Result<UnlinkOutcome, OidcStoreError>) -> &'static str {
    match result {
        Ok(UnlinkOutcome::Unlinked) => "unlinked",
        Ok(UnlinkOutcome::NotLinked) => "not_linked",
        Err(error) => error.label(),
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "omnius_auth_oidc_identity_operations_total",
        "operation" => operation,
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_auth_oidc_identity_operation_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}
