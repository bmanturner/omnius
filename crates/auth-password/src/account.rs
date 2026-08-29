use std::{fmt, time::Duration};

use omnius_auth_core::SubjectId;
use sqlx::{Acquire as _, PgConnection, Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::postgres::{map_sqlx_error, map_token_error, persist_issued_token};
use crate::{
    InvitationToken, InvitationTokenGenerator, InvitationTokenPepper, PasswordStoreError,
    PersistedPasswordCredential, RegistrationMode, RegistrationPolicy, TokenDispatch,
    TokenGenerator, TokenPurpose,
};

const MAX_CANONICAL_EMAIL_BYTES: usize = 320;
const MAX_PROVIDER_BYTES: usize = 2_048;
const MAX_INVITATION_LIST_LIMIT: u16 = 100;
const MAX_INVITATION_CLEANUP_LIMIT: u16 = 500;

/// Durable local-account authentication state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UserStatus {
    /// Account exists but its local email identity is not yet verified.
    PendingVerification,
    /// Account may authenticate.
    Active,
    /// Account is administratively disabled and may not authenticate.
    Disabled,
}

impl UserStatus {
    fn from_db(value: &str) -> Result<Self, PasswordStoreError> {
        match value {
            "pending_verification" => Ok(Self::PendingVerification),
            "active" => Ok(Self::Active),
            "disabled" => Ok(Self::Disabled),
            _ => Err(PasswordStoreError::CorruptData),
        }
    }
}

/// Authentication state returned only for an active local account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActivePasswordUser {
    /// Canonical user subject.
    pub subject_id: SubjectId,
    /// Version that invalidates previously established authentication.
    pub authentication_version: i64,
}

/// Bounded inputs for one atomic local-account registration attempt.
pub struct RegistrationRequest<'a> {
    /// Canonical lower-case email identity.
    pub canonical_email: &'a str,
    /// Fresh `Argon2id` credential created outside the transaction.
    pub credential: &'a PersistedPasswordCredential,
    /// Invitation bearer required only by invite-only policy.
    pub invitation: Option<&'a InvitationToken>,
    /// Current application time.
    pub now: OffsetDateTime,
}

impl fmt::Debug for RegistrationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationRequest")
            .field("canonical_email", &"[REDACTED]")
            .field("credential", &"[REDACTED]")
            .field(
                "invitation",
                &self.invitation.as_ref().map(|_| "[REDACTED]"),
            )
            .field("now", &self.now)
            .finish()
    }
}

/// Enumeration-safe registration result.
pub struct RegistrationRequestOutcome {
    dispatch: Option<TokenDispatch>,
}

impl RegistrationRequestOutcome {
    /// Returns the only status safe to expose for a syntactically valid request.
    #[must_use]
    pub const fn accepted(&self) -> bool {
        true
    }

    /// Releases a verification dispatch after the caller commits its transaction.
    #[must_use]
    pub fn into_post_commit_dispatch(self) -> Option<TokenDispatch> {
        self.dispatch
    }
}

impl fmt::Debug for RegistrationRequestOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RegistrationRequestOutcome([ACCEPTED])")
    }
}

/// Actor recorded for an invitation issuance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationIssuer {
    /// Bootstrap or other trusted system issuance.
    System,
    /// Authenticated human issuer.
    User(SubjectId),
    /// Authenticated service-account issuer.
    ServiceAccount(SubjectId),
}

impl InvitationIssuer {
    const fn kind(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User(_) => "user",
            Self::ServiceAccount(_) => "service_account",
        }
    }

    const fn user_id(self) -> Option<Uuid> {
        match self {
            Self::User(subject_id) => Some(subject_id.as_uuid()),
            Self::System | Self::ServiceAccount(_) => None,
        }
    }

    const fn service_account_id(self) -> Option<Uuid> {
        match self {
            Self::ServiceAccount(subject_id) => Some(subject_id.as_uuid()),
            Self::System | Self::User(_) => None,
        }
    }
}

/// Non-secret invitation state safe for management surfaces.
#[derive(Clone, Eq, PartialEq)]
pub struct RegistrationInvitationMetadata {
    /// Stable invitation identifier.
    pub id: Uuid,
    identity_provider: String,
    canonical_email: String,
    /// Issuance actor without any bearer material.
    pub issuer: InvitationIssuer,
    /// Creation time.
    pub created_at: OffsetDateTime,
    /// Expiration time.
    pub expires_at: OffsetDateTime,
    /// Single-use consumption time.
    pub consumed_at: Option<OffsetDateTime>,
    /// Administrative revocation time.
    pub revoked_at: Option<OffsetDateTime>,
}

impl RegistrationInvitationMetadata {
    /// Provider bound into this invitation.
    #[must_use]
    pub fn identity_provider(&self) -> &str {
        &self.identity_provider
    }

    /// Canonical email bound into this invitation.
    #[must_use]
    pub fn canonical_email(&self) -> &str {
        &self.canonical_email
    }

    /// Whether this invitation can no longer be presented.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.consumed_at.is_some() || self.revoked_at.is_some()
    }
}

impl fmt::Debug for RegistrationInvitationMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegistrationInvitationMetadata")
            .field("id", &self.id)
            .field("identity_provider", &self.identity_provider)
            .field("canonical_email", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("consumed_at", &self.consumed_at)
            .field("revoked_at", &self.revoked_at)
            .finish()
    }
}

/// Invitation issuance result carrying the bearer secret exactly once.
#[derive(Debug)]
pub struct IssuedRegistrationInvitation {
    /// Safe persisted invitation metadata.
    pub metadata: RegistrationInvitationMetadata,
    /// Bearer presentation returned only to post-commit delivery code.
    pub token: InvitationToken,
}

/// Bounded invitation issuance request.
pub struct InvitationIssueRequest<'a> {
    /// Provider configured for local identities.
    pub identity_provider: &'a str,
    /// Canonical lower-case email identity.
    pub canonical_email: &'a str,
    /// Trusted actor responsible for issuance.
    pub issuer: InvitationIssuer,
    /// Current application time.
    pub now: OffsetDateTime,
    /// Configured lifetime, constrained to one hour through thirty days.
    pub ttl: Duration,
}

impl fmt::Debug for InvitationIssueRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvitationIssueRequest")
            .field("identity_provider", &self.identity_provider)
            .field("canonical_email", &"[REDACTED]")
            .field("issuer", &self.issuer)
            .field("now", &self.now)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// Validated bounded list window for invitation management.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvitationListRequest {
    limit: u16,
    before: Option<(OffsetDateTime, Uuid)>,
}

impl InvitationListRequest {
    /// Creates a list request with a limit from one through one hundred.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when the limit is outside the bound.
    pub fn new(limit: u16) -> Result<Self, PasswordStoreError> {
        if limit == 0 || limit > MAX_INVITATION_LIST_LIMIT {
            return Err(PasswordStoreError::InvalidRequest);
        }
        Ok(Self {
            limit,
            before: None,
        })
    }

    /// Applies an exclusive stable keyset cursor.
    #[must_use]
    pub const fn before(mut self, created_at: OffsetDateTime, id: Uuid) -> Self {
        self.before = Some((created_at, id));
        self
    }
}

/// Outcome of a single-use invitation presentation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationConsumption {
    /// Presentation was malformed, mismatched, expired, replayed, or revoked.
    Rejected,
    /// Invitation was consumed exactly once.
    Consumed(Uuid),
}

/// Outcome of an idempotent invitation mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InvitationMutation {
    /// No live matching row could be changed.
    Rejected,
    /// The matching row transitioned exactly once.
    Applied,
}

impl super::PostgresPasswordStore {
    /// Loads authentication state only when the account is exactly active.
    ///
    /// # Errors
    ///
    /// Returns a stable store error for unavailable or corrupt persistence.
    pub async fn load_active_user_with(
        &self,
        connection: &mut PgConnection,
        subject_id: SubjectId,
    ) -> Result<Option<ActivePasswordUser>, PasswordStoreError> {
        let row = sqlx::query(
            "SELECT id, authentication_version FROM users \
             WHERE id = $1 AND status = 'active'",
        )
        .bind(subject_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        row.as_ref().map(active_user_from_row).transpose()
    }
    /// Loads the durable status for account-management decisions.
    ///
    /// # Errors
    ///
    /// Returns a stable store error for unavailable or corrupt persistence.
    pub async fn load_user_status_with(
        &self,
        connection: &mut PgConnection,
        subject_id: SubjectId,
    ) -> Result<Option<UserStatus>, PasswordStoreError> {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
            .bind(subject_id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
        status.as_deref().map(UserStatus::from_db).transpose()
    }

    /// Disables a pending or active account and advances authentication state through
    /// the schema trigger in the caller-owned transaction.
    ///
    /// # Errors
    ///
    /// Returns a stable error for persistence failures. Missing/already-disabled users return
    /// [`InvitationMutation::Rejected`] without distinguishing those states.
    pub async fn disable_user_with(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        subject_id: SubjectId,
    ) -> Result<InvitationMutation, PasswordStoreError> {
        let updated = sqlx::query(
            "UPDATE users SET status = 'disabled' \
             WHERE id = $1 AND status IN ('pending_verification', 'active')",
        )
        .bind(subject_id.as_uuid())
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        Ok(if updated.rows_affected() == 1 {
            InvitationMutation::Applied
        } else {
            InvitationMutation::Rejected
        })
    }

    /// Atomically creates a pending user, local identity, password credential, and
    /// email-verification token. Invite-only policy consumes its bound invitation in
    /// the same savepoint. Every syntactically valid attempt returns accepted.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, token, or persistence failure without identity values.
    pub async fn register_with<G: TokenGenerator + ?Sized>(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        policy: &RegistrationPolicy,
        request: RegistrationRequest<'_>,
        invitation_pepper: &InvitationTokenPepper,
        verification_generator: &G,
    ) -> Result<RegistrationRequestOutcome, PasswordStoreError> {
        validate_identity(policy.local_identity_provider(), request.canonical_email)?;
        match policy.mode() {
            RegistrationMode::Disabled => {
                return Ok(RegistrationRequestOutcome { dispatch: None });
            }
            RegistrationMode::SelfService if request.invitation.is_some() => {
                return Ok(RegistrationRequestOutcome { dispatch: None });
            }
            RegistrationMode::InviteOnly if request.invitation.is_none() => {
                return Ok(RegistrationRequestOutcome { dispatch: None });
            }
            RegistrationMode::SelfService | RegistrationMode::InviteOnly => {}
        }
        let expires_at = checked_std_expiry(request.now, policy.verification_ttl(), false)?;
        let issued = verification_generator.generate().map_err(map_token_error)?;
        let invitation_digest = request
            .invitation
            .map(|token| token.digest(invitation_pepper))
            .transpose()
            .map_err(|_| PasswordStoreError::Token)?;

        let mut savepoint = connection
            .begin()
            .await
            .map_err(|error| map_sqlx_error(&error))?;
        let result = register_in_savepoint(
            &mut savepoint,
            policy,
            request,
            invitation_digest
                .as_ref()
                .map(|digest| digest.as_bytes().as_slice()),
            expires_at,
            &issued,
        )
        .await;
        match result {
            Ok(Some(subject_id)) => {
                savepoint
                    .commit()
                    .await
                    .map_err(|error| map_sqlx_error(&error))?;
                Ok(RegistrationRequestOutcome {
                    dispatch: Some(TokenDispatch {
                        subject_id,
                        purpose: TokenPurpose::EmailVerification,
                        token: issued.token,
                        expires_at,
                    }),
                })
            }
            Ok(None) | Err(PasswordStoreError::Conflict) => {
                savepoint
                    .rollback()
                    .await
                    .map_err(|error| map_sqlx_error(&error))?;
                Ok(RegistrationRequestOutcome { dispatch: None })
            }
            Err(error) => {
                savepoint
                    .rollback()
                    .await
                    .map_err(|rollback| map_sqlx_error(&rollback))?;
                Err(error)
            }
        }
    }

    /// Completes email verification exactly once, marks the configured local identity
    /// verified, and activates its pending user in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure. Invalid/replayed tokens return `Rejected`.
    pub async fn complete_email_verification_with(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        token: &crate::VerificationToken,
        local_identity_provider: &str,
        now: OffsetDateTime,
    ) -> Result<crate::TokenConsumption, PasswordStoreError> {
        if !valid_provider(local_identity_provider) {
            return Err(PasswordStoreError::InvalidRequest);
        }
        let row = sqlx::query(
            "SELECT vt.id AS token_id, vt.user_id FROM verification_tokens vt \
             JOIN users u ON u.id = vt.user_id \
             WHERE vt.token_hash = $1 AND vt.purpose = 'email_verification' \
               AND vt.consumed_at IS NULL AND vt.invalidated_at IS NULL \
               AND vt.expires_at > $2 AND vt.security_version = u.authentication_version \
               AND u.status = 'pending_verification' \
               AND EXISTS (SELECT 1 FROM identities i WHERE i.user_id = u.id \
                           AND i.provider = $3 AND i.verified_at IS NULL) \
             FOR UPDATE OF vt, u",
        )
        .bind(token.digest().as_bytes().as_slice())
        .bind(now)
        .bind(local_identity_provider)
        .fetch_optional(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let Some(row) = row else {
            return Ok(crate::TokenConsumption::Rejected);
        };
        let token_id: Uuid = row
            .try_get("token_id")
            .map_err(|_| PasswordStoreError::CorruptData)?;
        let user_id: Uuid = row
            .try_get("user_id")
            .map_err(|_| PasswordStoreError::CorruptData)?;
        let subject_id =
            SubjectId::from_uuid(user_id).map_err(|_| PasswordStoreError::CorruptData)?;
        let consumed = sqlx::query(
            "UPDATE verification_tokens SET consumed_at = $2 \
             WHERE id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL",
        )
        .bind(token_id)
        .bind(now)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if consumed.rows_affected() != 1 {
            return Ok(crate::TokenConsumption::Rejected);
        }
        let verified = sqlx::query(
            "UPDATE identities SET verified_at = $3 WHERE user_id = $1 AND provider = $2 \
             AND verified_at IS NULL",
        )
        .bind(user_id)
        .bind(local_identity_provider)
        .bind(now)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let activated = sqlx::query(
            "UPDATE users SET status = 'active' WHERE id = $1 AND status = 'pending_verification'",
        )
        .bind(user_id)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if verified.rows_affected() == 0 || activated.rows_affected() != 1 {
            return Err(PasswordStoreError::Conflict);
        }
        Ok(crate::TokenConsumption::Consumed(subject_id))
    }

    /// Issues one provider/email-bound invitation and returns its secret once.
    /// Any prior active invitation for the same identity is revoked before insertion,
    /// making reissue the recovery path after a delivery failure.
    ///
    /// # Errors
    ///
    /// Returns a stable validation, entropy, conflict, or persistence failure.
    pub async fn issue_invitation_with<G: InvitationTokenGenerator + ?Sized>(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        request: InvitationIssueRequest<'_>,
        pepper: &InvitationTokenPepper,
        generator: &G,
    ) -> Result<IssuedRegistrationInvitation, PasswordStoreError> {
        validate_identity(request.identity_provider, request.canonical_email)?;
        let expires_at = checked_std_expiry(request.now, request.ttl, true)?;
        let issued = generator
            .generate(pepper)
            .map_err(|_| PasswordStoreError::Token)?;
        sqlx::query(
            "UPDATE registration_invitations SET revoked_at = $3 \
             WHERE identity_provider = $1 AND identity_subject = $2 \
               AND consumed_at IS NULL AND revoked_at IS NULL",
        )
        .bind(request.identity_provider)
        .bind(request.canonical_email)
        .bind(request.now)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO registration_invitations \
             (id, identity_provider, identity_subject, token_digest, issuer_kind, \
              issued_by_user_id, issued_by_service_account_id, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(request.identity_provider)
        .bind(request.canonical_email)
        .bind(issued.digest.as_bytes().as_slice())
        .bind(request.issuer.kind())
        .bind(request.issuer.user_id())
        .bind(request.issuer.service_account_id())
        .bind(request.now)
        .bind(expires_at)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        Ok(IssuedRegistrationInvitation {
            metadata: RegistrationInvitationMetadata {
                id,
                identity_provider: request.identity_provider.to_owned(),
                canonical_email: request.canonical_email.to_owned(),
                issuer: request.issuer,
                created_at: request.now,
                expires_at,
                consumed_at: None,
                revoked_at: None,
            },
            token: issued.token,
        })
    }

    /// Lists invitation metadata in stable newest-first keyset order.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence or corrupt-data failure.
    pub async fn list_invitations_with(
        &self,
        connection: &mut PgConnection,
        request: InvitationListRequest,
    ) -> Result<Vec<RegistrationInvitationMetadata>, PasswordStoreError> {
        let (before_created_at, before_id) =
            request.before.map_or((None, None), |(created_at, id)| {
                (Some(created_at), Some(id))
            });
        let rows = sqlx::query(
            "SELECT id, identity_provider, identity_subject, issuer_kind, issued_by_user_id, \
                    issued_by_service_account_id, created_at, expires_at, consumed_at, revoked_at \
             FROM registration_invitations \
             WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2)) \
             ORDER BY created_at DESC, id DESC LIMIT $3",
        )
        .bind(before_created_at)
        .bind(before_id)
        .bind(i64::from(request.limit))
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        rows.iter().map(invitation_metadata_from_row).collect()
    }

    /// Atomically consumes an invitation only when token, provider, canonical email,
    /// lifetime, and terminal state all match.
    ///
    /// # Errors
    ///
    /// Returns a stable validation or persistence failure.
    pub async fn consume_invitation_with(
        &self,
        connection: &mut PgConnection,
        token: &InvitationToken,
        pepper: &InvitationTokenPepper,
        identity_provider: &str,
        canonical_email: &str,
        now: OffsetDateTime,
    ) -> Result<InvitationConsumption, PasswordStoreError> {
        validate_identity(identity_provider, canonical_email)?;
        let digest = token
            .digest(pepper)
            .map_err(|_| PasswordStoreError::Token)?;
        let row = sqlx::query(
            "UPDATE registration_invitations SET consumed_at = $4 \
             WHERE token_digest = $1 AND identity_provider = $2 AND identity_subject = $3 \
               AND consumed_at IS NULL AND revoked_at IS NULL \
               AND created_at <= $4 AND expires_at > $4 \
             RETURNING id",
        )
        .bind(digest.as_bytes().as_slice())
        .bind(identity_provider)
        .bind(canonical_email)
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        match row {
            Some(row) => Ok(InvitationConsumption::Consumed(
                row.try_get("id")
                    .map_err(|_| PasswordStoreError::CorruptData)?,
            )),
            None => Ok(InvitationConsumption::Rejected),
        }
    }

    /// Revokes one live invitation by stable identifier.
    ///
    /// # Errors
    ///
    /// Returns a stable persistence failure.
    pub async fn revoke_invitation_with(
        &self,
        connection: &mut PgConnection,
        invitation_id: Uuid,
        now: OffsetDateTime,
    ) -> Result<InvitationMutation, PasswordStoreError> {
        let updated = sqlx::query(
            "UPDATE registration_invitations SET revoked_at = $2 \
             WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND created_at <= $2",
        )
        .bind(invitation_id)
        .bind(now)
        .execute(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        Ok(if updated.rows_affected() == 1 {
            InvitationMutation::Applied
        } else {
            InvitationMutation::Rejected
        })
    }

    /// Deletes a bounded batch of expired, otherwise-live invitation rows using
    /// skip-locked coordination.
    ///
    /// # Errors
    ///
    /// Returns a stable validation or persistence failure.
    pub async fn cleanup_expired_invitations_with(
        &self,
        connection: &mut Transaction<'_, Postgres>,
        now: OffsetDateTime,
        limit: u16,
    ) -> Result<u64, PasswordStoreError> {
        if limit == 0 || limit > MAX_INVITATION_CLEANUP_LIMIT {
            return Err(PasswordStoreError::InvalidRequest);
        }
        let result = sqlx::query(
            "WITH expired AS ( \
                 SELECT id FROM registration_invitations \
                 WHERE consumed_at IS NULL AND revoked_at IS NULL AND expires_at <= $1 \
                 ORDER BY expires_at, id LIMIT $2 FOR UPDATE SKIP LOCKED \
             ) DELETE FROM registration_invitations ri USING expired \
               WHERE ri.id = expired.id",
        )
        .bind(now)
        .bind(i64::from(limit))
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        Ok(result.rows_affected())
    }
}

async fn register_in_savepoint(
    connection: &mut Transaction<'_, Postgres>,
    policy: &RegistrationPolicy,
    request: RegistrationRequest<'_>,
    invitation_digest: Option<&[u8]>,
    verification_expires_at: OffsetDateTime,
    verification: &crate::IssuedToken,
) -> Result<Option<SubjectId>, PasswordStoreError> {
    let existing =
        sqlx::query("SELECT 1 FROM identities WHERE provider = $1 AND provider_subject = $2")
            .bind(policy.local_identity_provider())
            .bind(request.canonical_email)
            .fetch_optional(&mut **connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
    if existing.is_some() {
        return Ok(None);
    }

    let invitation_id = if policy.mode() == RegistrationMode::InviteOnly {
        let row = sqlx::query(
            "SELECT id FROM registration_invitations \
             WHERE token_digest = $1 AND identity_provider = $2 AND identity_subject = $3 \
               AND consumed_at IS NULL AND revoked_at IS NULL \
               AND created_at <= $4 AND expires_at > $4 \
             FOR UPDATE",
        )
        .bind(invitation_digest)
        .bind(policy.local_identity_provider())
        .bind(request.canonical_email)
        .bind(request.now)
        .fetch_optional(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        match row {
            Some(row) => Some(
                row.try_get::<Uuid, _>("id")
                    .map_err(|_| PasswordStoreError::CorruptData)?,
            ),
            None => return Ok(None),
        }
    } else {
        None
    };

    let subject_id = SubjectId::from_uuid(Uuid::now_v7()).map_err(|_| PasswordStoreError::Token)?;
    sqlx::query(
        "INSERT INTO users (id, status, created_at) VALUES ($1, 'pending_verification', $2)",
    )
    .bind(subject_id.as_uuid())
    .bind(request.now)
    .execute(&mut **connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    sqlx::query(
        "INSERT INTO identities \
         (id, user_id, provider, provider_subject, created_at, verified_at) \
         VALUES ($1, $2, $3, $4, $5, NULL)",
    )
    .bind(Uuid::now_v7())
    .bind(subject_id.as_uuid())
    .bind(policy.local_identity_provider())
    .bind(request.canonical_email)
    .bind(request.now)
    .execute(&mut **connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    sqlx::query(
        "INSERT INTO password_credentials \
         (user_id, password_hash, pepper_version, created_at, changed_at, updated_at) \
         VALUES ($1, $2, $3, $4, $4, $4)",
    )
    .bind(subject_id.as_uuid())
    .bind(request.credential.phc())
    .bind(i64::from(request.credential.pepper_version()))
    .bind(request.now)
    .execute(&mut **connection)
    .await
    .map_err(|error| map_sqlx_error(&error))?;
    persist_issued_token(
        connection,
        subject_id,
        TokenPurpose::EmailVerification,
        1,
        request.now,
        verification_expires_at,
        verification,
    )
    .await?;
    if let Some(invitation_id) = invitation_id {
        let consumed = sqlx::query(
            "UPDATE registration_invitations SET consumed_at = $2 \
             WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL \
               AND created_at <= $2 AND expires_at > $2",
        )
        .bind(invitation_id)
        .bind(request.now)
        .execute(&mut **connection)
        .await
        .map_err(|error| map_sqlx_error(&error))?;
        if consumed.rows_affected() != 1 {
            return Ok(None);
        }
    }
    Ok(Some(subject_id))
}

fn active_user_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<ActivePasswordUser, PasswordStoreError> {
    let user_id: Uuid = row
        .try_get("id")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    let authentication_version: i64 = row
        .try_get("authentication_version")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    if authentication_version <= 0 {
        return Err(PasswordStoreError::CorruptData);
    }
    Ok(ActivePasswordUser {
        subject_id: SubjectId::from_uuid(user_id).map_err(|_| PasswordStoreError::CorruptData)?,
        authentication_version,
    })
}

fn invitation_metadata_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<RegistrationInvitationMetadata, PasswordStoreError> {
    let issuer_kind: &str = row
        .try_get("issuer_kind")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    let user_id: Option<Uuid> = row
        .try_get("issued_by_user_id")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    let service_account_id: Option<Uuid> = row
        .try_get("issued_by_service_account_id")
        .map_err(|_| PasswordStoreError::CorruptData)?;
    let issuer = match (issuer_kind, user_id, service_account_id) {
        ("system", None, None) => InvitationIssuer::System,
        ("user", Some(id), None) => InvitationIssuer::User(
            SubjectId::from_uuid(id).map_err(|_| PasswordStoreError::CorruptData)?,
        ),
        ("service_account", None, Some(id)) => InvitationIssuer::ServiceAccount(
            SubjectId::from_uuid(id).map_err(|_| PasswordStoreError::CorruptData)?,
        ),
        _ => return Err(PasswordStoreError::CorruptData),
    };
    Ok(RegistrationInvitationMetadata {
        id: row
            .try_get("id")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        identity_provider: row
            .try_get("identity_provider")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        canonical_email: row
            .try_get("identity_subject")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        issuer,
        created_at: row
            .try_get("created_at")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        consumed_at: row
            .try_get("consumed_at")
            .map_err(|_| PasswordStoreError::CorruptData)?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| PasswordStoreError::CorruptData)?,
    })
}

fn validate_identity(provider: &str, canonical_email: &str) -> Result<(), PasswordStoreError> {
    if !valid_provider(provider)
        || canonical_email.len() < 3
        || canonical_email.len() > MAX_CANONICAL_EMAIL_BYTES
        || canonical_email != canonical_email.to_ascii_lowercase()
        || canonical_email.trim() != canonical_email
        || canonical_email.chars().any(char::is_control)
        || canonical_email.matches('@').count() != 1
        || canonical_email.starts_with('@')
        || canonical_email.ends_with('@')
        || provider.len() + canonical_email.len() > 2_368
    {
        return Err(PasswordStoreError::InvalidRequest);
    }
    Ok(())
}

fn valid_provider(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= MAX_PROVIDER_BYTES
        && provider.trim() == provider
        && !provider.chars().any(char::is_control)
}

fn checked_std_expiry(
    now: OffsetDateTime,
    ttl: Duration,
    invitation: bool,
) -> Result<OffsetDateTime, PasswordStoreError> {
    let valid = if invitation {
        (Duration::from_hours(1)..=Duration::from_hours(720)).contains(&ttl)
    } else {
        (Duration::from_mins(5)..=Duration::from_hours(24)).contains(&ttl)
    };
    if !valid {
        return Err(PasswordStoreError::InvalidRequest);
    }
    let ttl = time::Duration::try_from(ttl).map_err(|_| PasswordStoreError::InvalidRequest)?;
    now.checked_add(ttl)
        .filter(|expires_at| *expires_at > now)
        .ok_or(PasswordStoreError::InvalidRequest)
}
