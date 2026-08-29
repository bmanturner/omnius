use std::fmt;

use axum_login::{AuthUser, AuthnBackend, UserId};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_postgres::PostgresPool;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

const SESSION_AUTH_HASH_DOMAIN: &[u8] = b"omnius.session-auth-hash.v1\0";

/// User state restored by `axum-login` from a server-side session.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionUser {
    subject_id: SubjectId,
    authentication_version: i64,
    session_auth_hash: [u8; 32],
}

impl SessionUser {
    fn new(subject_id: SubjectId, authentication_version: i64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SESSION_AUTH_HASH_DOMAIN);
        hasher.update(subject_id.as_uuid().as_bytes());
        hasher.update(authentication_version.to_be_bytes());
        let session_auth_hash = hasher.finalize().into();
        Self {
            subject_id,
            authentication_version,
            session_auth_hash,
        }
    }

    /// Returns the canonical user subject identifier.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.subject_id
    }

    /// Returns the identity row's authentication version used for invalidation.
    #[must_use]
    pub const fn authentication_version(&self) -> i64 {
        self.authentication_version
    }

    /// Maps this authenticated browser session to the canonical principal.
    #[must_use]
    pub fn principal(&self, authenticated_at: OffsetDateTime) -> Principal {
        Principal {
            subject_id: self.subject_id,
            kind: PrincipalKind::User,
            tenant_id: None,
            auth_method: AuthMethod::Session,
            authenticated_at: authenticated_at.to_offset(UtcOffset::UTC),
            assurance: AssuranceLevel::Aal1,
            scopes: Vec::new(),
        }
    }
}

impl fmt::Debug for SessionUser {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionUser")
            .field("subject_id", &self.subject_id)
            .field("authentication_version", &self.authentication_version)
            .field("session_auth_hash", &"[REDACTED]")
            .finish()
    }
}

impl AuthUser for SessionUser {
    type Id = SubjectId;

    fn id(&self) -> Self::Id {
        self.subject_id
    }

    fn session_auth_hash(&self) -> &[u8] {
        &self.session_auth_hash
    }
}

/// Private-constructor marker: this backend restores sessions but never verifies
/// primary authentication credentials.
#[derive(Debug)]
pub struct SessionCredentials(());

/// `axum-login` backend loading the current authentication version from the
/// managed PostgreSQL pool.
#[derive(Clone)]
pub struct SessionBackend {
    pool: PostgresPool,
}

impl SessionBackend {
    /// Creates a session backend sharing the configured managed pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }
}

impl AuthnBackend for SessionBackend {
    type User = SessionUser;
    type Credentials = SessionCredentials;
    type Error = SessionBackendError;

    fn authenticate(
        &self,
        _credentials: Self::Credentials,
    ) -> impl Future<Output = Result<Option<Self::User>, Self::Error>> + Send {
        std::future::ready(Ok(None))
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        let authentication_version = sqlx::query_scalar::<_, i64>(
            "SELECT authentication_version FROM users WHERE id = $1 AND status = 'active'",
        )
        .bind(user_id.as_uuid())
        .fetch_optional(&self.pool.sqlx_pool())
        .await
        .map_err(|_| SessionBackendError::UserLookup)?;

        Ok(authentication_version.map(|version| SessionUser::new(*user_id, version)))
    }
}

/// Stable, value-free backend failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SessionBackendError {
    /// The identity row could not be loaded.
    #[error("session user lookup failed")]
    UserLookup,
}

#[cfg(test)]
mod tests {
    use omnius_auth_core::{AssuranceLevel, AuthMethod, IdentityIdError, PrincipalKind};
    use time::macros::datetime;
    use uuid::Uuid;

    use super::*;

    fn subject() -> Result<SubjectId, IdentityIdError> {
        SubjectId::from_uuid(Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001))
    }

    #[test]
    fn authentication_hash_is_stable_and_version_sensitive() -> Result<(), IdentityIdError> {
        let first = SessionUser::new(subject()?, 1);
        let same = SessionUser::new(subject()?, 1);
        let changed = SessionUser::new(subject()?, 2);

        assert_eq!(first.session_auth_hash(), same.session_auth_hash());
        assert_ne!(first.session_auth_hash(), changed.session_auth_hash());
        assert!(format!("{first:?}").contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn principal_mapping_uses_session_and_aal1() -> Result<(), IdentityIdError> {
        let principal =
            SessionUser::new(subject()?, 1).principal(datetime!(2026-08-24 12:00:00 +05:30));

        assert_eq!(principal.subject_id, subject()?);
        assert_eq!(principal.kind, PrincipalKind::User);
        assert_eq!(principal.auth_method, AuthMethod::Session);
        assert_eq!(principal.assurance, AssuranceLevel::Aal1);
        assert_eq!(
            principal.authenticated_at,
            datetime!(2026-08-24 06:30:00 UTC)
        );
        Ok(())
    }
}
