//! Access-token and refresh-token revocation.

use super::{OAuthPostgresStore, OAuthStoreError, finish, map_db};
use crate::crypto::BearerDigest;
use crate::types::{ClientId, GrantId, JwtId};
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::{Postgres, Transaction};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Access-token revocation reason represented by the schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessRevocationReason {
    /// Client was disabled.
    ClientDisabled,
    /// Grant was revoked.
    GrantRevoked,
    /// Logout invalidated the access token.
    Logout,
    /// Administrator or owner manually revoked it.
    Manual,
    /// RFC 7009 token revocation.
    TokenRevoked,
    /// User was disabled.
    UserDisabled,
}

impl AccessRevocationReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ClientDisabled => "client_disabled",
            Self::GrantRevoked => "grant_revoked",
            Self::Logout => "logout",
            Self::Manual => "manual",
            Self::TokenRevoked => "token_revoked",
            Self::UserDisabled => "user_disabled",
        }
    }
}

/// Persisted access-token revocation input.
#[derive(Clone, Debug)]
pub struct AccessTokenRevocation {
    /// Access token `jti`.
    pub jti: JwtId,
    /// Bound grant.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Access token issuance time.
    pub issued_at: OffsetDateTime,
    /// Access token expiry.
    pub expires_at: OffsetDateTime,
    /// Revocation time.
    pub revoked_at: OffsetDateTime,
    /// Revocation reason.
    pub reason: AccessRevocationReason,
}

impl OAuthPostgresStore {
    /// RFC 7009 refresh-token revocation. Unknown digests remain a successful no-op.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored refresh state is corrupt or PostgreSQL cannot
    /// complete the transaction.
    pub async fn revoke_refresh_token(
        &self,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = revoke_refresh_token_with(&mut transaction, digest, None, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_refresh_token`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored refresh state is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn revoke_refresh_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_refresh_token_with(transaction, digest, None, now).await
    }

    /// Revokes a refresh family only when it belongs to the authenticated client.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored refresh state is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn revoke_refresh_token_for_client_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_refresh_token_with(transaction, digest, Some(client_id), now).await
    }

    /// Records one access-token `jti` revocation idempotently through token expiry.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if revocation input violates its invariants or PostgreSQL
    /// cannot complete the transaction.
    pub async fn revoke_access_token(
        &self,
        input: &AccessTokenRevocation,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.revoke_access_token_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_access_token`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if revocation input violates its invariants or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn revoke_access_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AccessTokenRevocation,
    ) -> Result<bool, OAuthStoreError> {
        if input.revoked_at < input.issued_at || input.expires_at <= input.revoked_at {
            return Err(OAuthStoreError::InvalidInput);
        }
        let result = sqlx::query(
            "INSERT INTO oauth_access_token_revocations \
             (jti, grant_id, client_id, issued_at, expires_at, revoked_at, reason) \
             SELECT $1, grant_row.id, client.id, $4, $5, $6, $7 \
             FROM oauth_grants grant_row JOIN oauth_clients client ON client.id = grant_row.client_id \
             WHERE grant_row.id = $2 AND client.client_id = $3 \
             ON CONFLICT (jti) DO NOTHING",
        )
        .bind(input.jti.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .bind(input.revoked_at)
        .bind(input.reason.as_str())
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(result.rows_affected() == 1)
    }

    /// Revokes a verified issuer JTI for the configured maximum one-hour token lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if the derived revocation interval is invalid or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn revoke_access_token_jti_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        jti: JwtId,
        grant_id: GrantId,
        client_id: &ClientId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        self.revoke_access_token_with(
            transaction,
            &AccessTokenRevocation {
                jti,
                grant_id,
                client_id: client_id.clone(),
                issued_at: now,
                expires_at: now + Duration::hours(1),
                revoked_at: now,
                reason: AccessRevocationReason::TokenRevoked,
            },
        )
        .await
    }
}

async fn revoke_refresh_token_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    client_id: Option<&ClientId>,
    now: OffsetDateTime,
) -> Result<bool, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT token.family_id, token.grant_id FROM oauth_refresh_tokens token \
         JOIN oauth_refresh_token_families family ON family.id = token.family_id \
         JOIN oauth_clients client ON client.id = family.client_id \
         WHERE token.token_digest = $1 AND ($2::text IS NULL OR client.client_id = $2) \
         FOR UPDATE OF token, family",
    )
    .bind(digest.as_bytes().as_slice())
    .bind(client_id.map(ClientId::as_str))
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(false);
    };
    let family_id: Uuid = row
        .try_get("family_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    let grant_id: Uuid = row
        .try_get("grant_id")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
         revocation_reason = 'token_revoked', version = version + 1 \
         WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2 \
         WHERE family_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, $2), updated_at = $2, \
         version = version + 1 WHERE id = $1",
    )
    .bind(grant_id)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(true)
}
