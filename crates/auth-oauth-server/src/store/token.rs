//! Authorization-code and refresh-token persistence.

use super::{
    ClientStatus, LiveGrant, MAX_NONCE_BYTES, OAuthPostgresStore, OAuthStoreError, RefreshFamilyId,
    RefreshTokenId, finish, grant_id, load_live_grant, map_db, parse_resources, parse_scopes,
    resource_values, scope_values, valid_visible_text,
};
use crate::crypto::BearerDigest;
use crate::types::{ClientId, GrantId, PkceChallenge, PkceVerifier, RedirectUri, ResourceUri};
use omnius_auth_core::Scope;
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Transaction};
use std::fmt;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Authorization code persistence input.
#[derive(Clone)]
pub struct AuthorizationCodeCreate {
    /// Exact code digest.
    pub code_digest: BearerDigest,
    /// Live grant receiving the code.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Bound exact redirect.
    pub redirect_uri: RedirectUri,
    /// Bound resources.
    pub resource_uris: Vec<ResourceUri>,
    /// Bound scopes.
    pub granted_scopes: Vec<Scope>,
    /// Bound S256 challenge.
    pub pkce_code_challenge: PkceChallenge,
    /// Bound OIDC nonce.
    pub nonce: Option<String>,
    /// Issuance time.
    pub issued_at: OffsetDateTime,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AuthorizationCodeCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeCreate")
            .field("code_digest", &"[REDACTED]")
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

/// Exact token-endpoint bindings supplied with a code.
pub struct AuthorizationCodeBinding {
    /// Authenticated client.
    pub client_id: ClientId,
    /// Exact redirect URI.
    pub redirect_uri: RedirectUri,
    /// Exact resource set.
    pub resource_uris: Vec<ResourceUri>,
    /// PKCE verifier whose S256 result must match.
    pub pkce_verifier: PkceVerifier,
}

impl fmt::Debug for AuthorizationCodeBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeBinding")
            .field("client_id", &self.client_id)
            .field("redirect_uri", &"[REDACTED]")
            .field("resource_count", &self.resource_uris.len())
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Successfully consumed code state used for token issuance.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConsumedAuthorizationCode {
    /// Live grant.
    pub grant: LiveGrant,
    /// Bound redirect.
    pub redirect_uri: RedirectUri,
    /// Bound resources.
    pub resource_uris: Vec<ResourceUri>,
    /// Bound scopes.
    pub granted_scopes: Vec<Scope>,
    /// OIDC nonce.
    pub nonce: Option<String>,
}

/// Rejection classification after consuming a recognized code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationCodeRejection {
    /// The recognized code expired.
    Expired,
    /// A client, redirect, resource, or PKCE binding failed.
    BindingMismatch,
    /// Stored code resources or scopes exceed its grant, proving durable corruption.
    StoredBindingViolation,
    /// User, client, grant, or tenant membership is no longer active.
    Inactive,
}

/// Atomic code-exchange result.
#[derive(Clone, Debug)]
pub enum AuthorizationCodeExchange {
    /// Code consumed and its live grant returned.
    Issued(Box<ConsumedAuthorizationCode>),
    /// Recognized code consumed with a rejected outcome.
    Rejected(AuthorizationCodeRejection),
    /// Digest is unknown or was already consumed.
    Unavailable,
}

/// Initial refresh family and token input.
pub struct RefreshFamilyIssue {
    /// Live grant.
    pub grant_id: GrantId,
    /// Bound client.
    pub client_id: ClientId,
    /// Exact resource bound at authorization-code exchange.
    pub resource: ResourceUri,
    /// Exact scope subset bound at authorization-code exchange.
    pub granted_scopes: Vec<Scope>,
    /// First refresh-token digest.
    pub token_digest: BearerDigest,
    /// Family creation time.
    pub issued_at: OffsetDateTime,
    /// Family and token expiry.
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for RefreshFamilyIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshFamilyIssue")
            .field("grant_id", &self.grant_id)
            .field("client_id", &self.client_id)
            .field("token_digest", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Persisted refresh-token coordinates returned without bearer material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct IssuedRefreshToken {
    /// Family identifier.
    pub family_id: RefreshFamilyId,
    /// Token row identifier.
    pub token_id: RefreshTokenId,
    /// Rotation sequence, beginning at zero.
    pub rotation_sequence: i64,
    /// Expiry time.
    pub expires_at: OffsetDateTime,
}

/// Successful refresh rotation state.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RotatedRefreshToken {
    /// Live grant for token issuance.
    pub grant: LiveGrant,
    /// Exact resource inherited from the refresh family.
    pub resource: ResourceUri,
    /// Maximum scopes inherited from the refresh family.
    pub granted_scopes: Vec<Scope>,
    /// Family identifier.
    pub family_id: RefreshFamilyId,
    /// Replacement token identifier.
    pub token_id: RefreshTokenId,
    /// Replacement rotation sequence.
    pub rotation_sequence: i64,
    /// Replacement expiry.
    pub expires_at: OffsetDateTime,
}

/// Refresh rejection without a reuse signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshRejection {
    /// Digest is not recognized.
    Unknown,
    /// Token or family expired.
    Expired,
    /// Client binding failed.
    ClientMismatch,
    /// User, client, grant, or tenant is inactive.
    Inactive,
}

/// Atomic refresh rotation result.
#[derive(Clone, Debug)]
pub enum RefreshRotation {
    /// Successful mandatory rotation.
    Rotated(Box<RotatedRefreshToken>),
    /// Any consumed or revoked family member was reused; family and grant are revoked.
    ReuseDetected {
        /// Compromised family.
        family_id: RefreshFamilyId,
        /// Revoked grant.
        grant_id: GrantId,
    },
    /// Request rejected without changing the token.
    Rejected(RefreshRejection),
}

impl OAuthPostgresStore {
    /// Persists a short-lived authorization code using only its digest.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if code input violates protocol invariants or PostgreSQL
    /// cannot complete the transaction.
    pub async fn persist_authorization_code(
        &self,
        input: &AuthorizationCodeCreate,
    ) -> Result<(), OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .persist_authorization_code_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::persist_authorization_code`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if code input violates protocol invariants or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn persist_authorization_code_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &AuthorizationCodeCreate,
    ) -> Result<(), OAuthStoreError> {
        validate_authorization_code(input)?;
        let resources = resource_values(&input.resource_uris)?;
        let scopes = scope_values(&input.granted_scopes)?;
        let result = sqlx::query(
            "INSERT INTO oauth_authorization_codes \
             (id, code_digest, grant_id, client_id, redirect_uri, resource_uris, granted_scopes, \
              pkce_code_challenge, nonce, issued_at, expires_at, consumed_at, exchange_outcome) \
             SELECT $1, $2, grant_row.id, client.id, $5, $6, $7, $8, $9, $10, $11, NULL, NULL \
             FROM oauth_grants grant_row JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE grant_row.id = $3 AND client.client_id = $4 AND grant_row.revoked_at IS NULL \
               AND client.status = 'active' AND user_account.status = 'active' \
               AND grant_row.resources @> $6 AND grant_row.granted_scopes @> $7 \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF grant_row, client, subject, user_account",
        )
        .bind(Uuid::now_v7())
        .bind(input.code_digest.as_bytes().as_slice())
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .bind(input.redirect_uri.as_str())
        .bind(&resources)
        .bind(&scopes)
        .bind(input.pkce_code_challenge.as_str())
        .bind(input.nonce.as_deref())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(OAuthStoreError::Inactive)
        }
    }

    /// Atomically consumes a recognized code before reporting any binding or liveness failure.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if code bindings or stored authorization state are corrupt,
    /// or if PostgreSQL cannot complete the transaction.
    pub async fn consume_authorization_code(
        &self,
        digest: &BearerDigest,
        binding: &AuthorizationCodeBinding,
        now: OffsetDateTime,
    ) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
        let resources = resource_values(&binding.resource_uris)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result =
            consume_authorization_code_with(&mut transaction, digest, binding, &resources, now)
                .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::consume_authorization_code`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if code bindings or stored authorization state are corrupt,
    /// or if PostgreSQL cannot complete the caller-owned transaction.
    pub async fn consume_authorization_code_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        binding: &AuthorizationCodeBinding,
        now: OffsetDateTime,
    ) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
        let resources = resource_values(&binding.resource_uris)?;
        consume_authorization_code_with(transaction, digest, binding, &resources, now).await
    }

    /// Issues the first refresh token in a new family atomically.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if refresh-family input violates authorization invariants
    /// or PostgreSQL cannot complete the transaction.
    pub async fn issue_refresh_family(
        &self,
        input: &RefreshFamilyIssue,
    ) -> Result<IssuedRefreshToken, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .issue_refresh_family_with(&mut transaction, input)
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::issue_refresh_family`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if refresh-family input violates authorization invariants
    /// or PostgreSQL cannot complete the caller-owned transaction.
    pub async fn issue_refresh_family_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &RefreshFamilyIssue,
    ) -> Result<IssuedRefreshToken, OAuthStoreError> {
        if input.expires_at <= input.issued_at
            || input.expires_at > input.issued_at + Duration::days(90)
            || input.granted_scopes.is_empty()
        {
            return Err(OAuthStoreError::InvalidInput);
        }
        let granted_scopes = scope_values(&input.granted_scopes)?;
        let family_id = RefreshFamilyId::new();
        let token_id = RefreshTokenId::new();
        let coordinates = sqlx::query(
            "SELECT grant_row.resources, grant_row.granted_scopes \
             FROM oauth_grants grant_row \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE grant_row.id = $1 AND client.client_id = $2 AND grant_row.revoked_at IS NULL \
               AND client.status = 'active' AND user_account.status = 'active' \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF grant_row, client, subject, user_account",
        )
        .bind(input.grant_id.as_uuid())
        .bind(input.client_id.as_str())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let Some(coordinates) = coordinates else {
            return Err(OAuthStoreError::Inactive);
        };
        let resources = parse_resources(
            coordinates
                .try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        let grant_scopes = parse_scopes(
            coordinates
                .try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        if !resources.contains(&input.resource)
            || input
                .granted_scopes
                .iter()
                .any(|scope| grant_scopes.binary_search(scope).is_err())
        {
            return Err(OAuthStoreError::Inactive);
        }
        let client_internal_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM oauth_clients WHERE client_id = $1 AND status = 'active'",
        )
        .bind(input.client_id.as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        sqlx::query(
            "INSERT INTO oauth_refresh_token_families \
             (id, grant_id, client_id, resource_uri, granted_scopes, created_at, expires_at, \
              revoked_at, revocation_reason, reuse_detected_at, version) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, 1)",
        )
        .bind(family_id.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(client_internal_id)
        .bind(input.resource.as_str())
        .bind(&granted_scopes)
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        sqlx::query(
            "INSERT INTO oauth_refresh_tokens \
             (id, family_id, grant_id, token_digest, rotation_sequence, issued_at, expires_at, \
              consumed_at, replaced_by_id, revoked_at, reuse_detected_at) \
             VALUES ($1, $2, $3, $4, 0, $5, $6, NULL, NULL, NULL, NULL)",
        )
        .bind(token_id.as_uuid())
        .bind(family_id.as_uuid())
        .bind(input.grant_id.as_uuid())
        .bind(input.token_digest.as_bytes().as_slice())
        .bind(input.issued_at)
        .bind(input.expires_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(IssuedRefreshToken {
            family_id,
            token_id,
            rotation_sequence: 0,
            expires_at: input.expires_at,
        })
    }

    /// Rotates a refresh token, or atomically revokes its family and grant on reuse.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if refresh state violates its invariants or PostgreSQL
    /// cannot complete the transaction.
    pub async fn rotate_refresh_token(
        &self,
        digest: &BearerDigest,
        client_id: &ClientId,
        replacement_digest: &BearerDigest,
        now: OffsetDateTime,
        replacement_expires_at: OffsetDateTime,
    ) -> Result<RefreshRotation, OAuthStoreError> {
        if replacement_expires_at <= now {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = rotate_refresh_token_with(
            &mut transaction,
            digest,
            client_id,
            replacement_digest,
            now,
            replacement_expires_at,
        )
        .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::rotate_refresh_token`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if refresh state violates its invariants or PostgreSQL
    /// cannot complete the caller-owned transaction.
    pub async fn rotate_refresh_token_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        digest: &BearerDigest,
        client_id: &ClientId,
        replacement_digest: &BearerDigest,
        now: OffsetDateTime,
        replacement_expires_at: OffsetDateTime,
    ) -> Result<RefreshRotation, OAuthStoreError> {
        if replacement_expires_at <= now {
            return Err(OAuthStoreError::InvalidInput);
        }
        rotate_refresh_token_with(
            transaction,
            digest,
            client_id,
            replacement_digest,
            now,
            replacement_expires_at,
        )
        .await
    }
}

struct StoredAuthorizationCode {
    id: Uuid,
    grant_id: GrantId,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    client_id: String,
    redirect_uri: String,
    resources: Vec<String>,
    challenge: String,
    client_status: ClientStatus,
    scopes: Vec<String>,
    grant_resources: Vec<String>,
    grant_scopes: Vec<String>,
    nonce: Option<String>,
}

fn stored_authorization_code_from_row(
    row: &PgRow,
) -> Result<StoredAuthorizationCode, OAuthStoreError> {
    Ok(StoredAuthorizationCode {
        id: row
            .try_get("id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        grant_id: grant_id(
            row.try_get("grant_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_id: row
            .try_get("client_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        redirect_uri: row
            .try_get("redirect_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        resources: row
            .try_get("resource_uris")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        challenge: row
            .try_get("pkce_code_challenge")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_status: ClientStatus::from_db(
            &row.try_get::<String, _>("client_status")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        scopes: row
            .try_get("granted_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        grant_resources: row
            .try_get("grant_resources")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        grant_scopes: row
            .try_get("grant_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        nonce: row
            .try_get("nonce")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

async fn consume_authorization_code_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    binding: &AuthorizationCodeBinding,
    resource_values: &[String],
    now: OffsetDateTime,
) -> Result<AuthorizationCodeExchange, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT code.id, code.grant_id, code.redirect_uri, code.resource_uris, \
                code.granted_scopes, code.pkce_code_challenge, code.nonce, code.issued_at, \
                code.expires_at, client.client_id, client.status AS client_status, \
                grant_row.resources AS grant_resources, \
                grant_row.granted_scopes AS grant_scopes \
         FROM oauth_authorization_codes code JOIN oauth_clients client ON client.id = code.client_id \
         JOIN oauth_grants grant_row ON grant_row.id = code.grant_id \
         WHERE code.code_digest = $1 AND code.consumed_at IS NULL FOR UPDATE OF code",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(AuthorizationCodeExchange::Unavailable);
    };
    let stored = stored_authorization_code_from_row(&row)?;
    if now < stored.issued_at {
        return Err(OAuthStoreError::InvalidInput);
    }
    let stored_binding_within_grant = sorted_subset(&stored.resources, &stored.grant_resources)
        && sorted_subset(&stored.scopes, &stored.grant_scopes);
    let binding_matches = stored.client_id == binding.client_id.as_str()
        && stored.redirect_uri == binding.redirect_uri.as_str()
        && stored.resources == resource_values
        && stored.challenge == binding.pkce_verifier.challenge().as_str();
    let live_grant = if stored.client_status == ClientStatus::Active {
        load_live_grant(transaction, stored.grant_id).await?
    } else {
        None
    };
    let rejection = if now >= stored.expires_at {
        Some(AuthorizationCodeRejection::Expired)
    } else if !stored_binding_within_grant {
        Some(AuthorizationCodeRejection::StoredBindingViolation)
    } else if !binding_matches {
        Some(AuthorizationCodeRejection::BindingMismatch)
    } else if live_grant.is_none() {
        Some(AuthorizationCodeRejection::Inactive)
    } else {
        None
    };
    sqlx::query(
        "UPDATE oauth_authorization_codes SET consumed_at = $2, exchange_outcome = $3 WHERE id = $1",
    )
    .bind(stored.id)
    .bind(now)
    .bind(if rejection.is_some() { "rejected" } else { "issued" })
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    if let Some(rejection) = rejection {
        return Ok(AuthorizationCodeExchange::Rejected(rejection));
    }
    Ok(AuthorizationCodeExchange::Issued(Box::new(
        ConsumedAuthorizationCode {
            grant: live_grant.ok_or(OAuthStoreError::CorruptData)?,
            redirect_uri: RedirectUri::parse(stored.redirect_uri)
                .map_err(|_| OAuthStoreError::CorruptData)?,
            resource_uris: parse_resources(stored.resources)?,
            granted_scopes: parse_scopes(stored.scopes)?,
            nonce: stored.nonce,
        },
    )))
}

struct StoredRefreshToken {
    token_id: RefreshTokenId,
    family_id: RefreshFamilyId,
    grant_id: GrantId,
    rotation_sequence: i64,
    issued_at: OffsetDateTime,
    token_expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    token_revoked_at: Option<OffsetDateTime>,
    resource_uri: String,
    granted_scopes: Vec<String>,
    family_expires_at: OffsetDateTime,
    family_revoked_at: Option<OffsetDateTime>,
    client_id: String,
}

#[derive(Clone, Copy)]
struct RefreshReplacementCoordinates {
    token_id: RefreshTokenId,
    family_id: RefreshFamilyId,
    grant_id: GrantId,
    rotation_sequence: i64,
    family_expires_at: OffsetDateTime,
}

fn stored_refresh_token_from_row(row: &PgRow) -> Result<StoredRefreshToken, OAuthStoreError> {
    Ok(StoredRefreshToken {
        token_id: refresh_token_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        family_id: refresh_family_id(
            row.try_get("family_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        grant_id: grant_id(
            row.try_get("grant_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        rotation_sequence: row
            .try_get("rotation_sequence")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        issued_at: row
            .try_get("issued_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        token_expires_at: row
            .try_get("token_expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        consumed_at: row
            .try_get("consumed_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        token_revoked_at: row
            .try_get("revoked_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        resource_uri: row
            .try_get("resource_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        granted_scopes: row
            .try_get("granted_scopes")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        family_expires_at: row
            .try_get("family_expires_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        family_revoked_at: row
            .try_get("family_revoked_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_id: row
            .try_get("client_id")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

async fn persist_refresh_replacement(
    transaction: &mut Transaction<'_, Postgres>,
    coordinates: RefreshReplacementCoordinates,
    replacement_digest: &BearerDigest,
    now: OffsetDateTime,
    requested_expires_at: OffsetDateTime,
) -> Result<(RefreshTokenId, i64, OffsetDateTime), OAuthStoreError> {
    let expires_at = requested_expires_at.min(coordinates.family_expires_at);
    let sequence = coordinates
        .rotation_sequence
        .checked_add(1)
        .ok_or(OAuthStoreError::CorruptData)?;
    let replacement_id = RefreshTokenId::new();
    sqlx::query(
        "INSERT INTO oauth_refresh_tokens \
         (id, family_id, grant_id, token_digest, rotation_sequence, issued_at, expires_at, \
          consumed_at, replaced_by_id, revoked_at, reuse_detected_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL, NULL, NULL)",
    )
    .bind(replacement_id.as_uuid())
    .bind(coordinates.family_id.as_uuid())
    .bind(coordinates.grant_id.as_uuid())
    .bind(replacement_digest.as_bytes().as_slice())
    .bind(sequence)
    .bind(now)
    .bind(expires_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET consumed_at = $2, replaced_by_id = $3 WHERE id = $1",
    )
    .bind(coordinates.token_id.as_uuid())
    .bind(now)
    .bind(replacement_id.as_uuid())
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query("UPDATE oauth_refresh_token_families SET version = version + 1 WHERE id = $1")
        .bind(coordinates.family_id.as_uuid())
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    Ok((replacement_id, sequence, expires_at))
}

async fn rotate_refresh_token_with(
    transaction: &mut Transaction<'_, Postgres>,
    digest: &BearerDigest,
    client_id: &ClientId,
    replacement_digest: &BearerDigest,
    now: OffsetDateTime,
    replacement_expires_at: OffsetDateTime,
) -> Result<RefreshRotation, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT token.id, token.family_id, token.grant_id, token.rotation_sequence, token.issued_at, \
                token.expires_at AS token_expires_at, token.consumed_at, token.revoked_at, \
                family.resource_uri, family.granted_scopes, family.expires_at AS family_expires_at, \
                family.revoked_at AS family_revoked_at, client.client_id \
         FROM oauth_refresh_tokens token \
         JOIN oauth_refresh_token_families family ON family.id = token.family_id \
         JOIN oauth_clients client ON client.id = family.client_id \
         WHERE token.token_digest = $1 FOR UPDATE OF token, family",
    )
    .bind(digest.as_bytes().as_slice())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Unknown));
    };
    let stored = stored_refresh_token_from_row(&row)?;
    if stored.consumed_at.is_some()
        || stored.token_revoked_at.is_some()
        || stored.family_revoked_at.is_some()
    {
        revoke_reused_family(
            transaction,
            stored.token_id,
            stored.family_id,
            stored.grant_id,
            stored.consumed_at.is_some(),
            now,
        )
        .await?;
        return Ok(RefreshRotation::ReuseDetected {
            family_id: stored.family_id,
            grant_id: stored.grant_id,
        });
    }
    if stored.client_id != client_id.as_str() {
        return Ok(RefreshRotation::Rejected(RefreshRejection::ClientMismatch));
    }
    if now < stored.issued_at {
        return Err(OAuthStoreError::InvalidInput);
    }
    if now >= stored.token_expires_at || now >= stored.family_expires_at {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Expired));
    }
    let Some(grant) = load_live_grant(transaction, stored.grant_id).await? else {
        return Ok(RefreshRotation::Rejected(RefreshRejection::Inactive));
    };
    let coordinates = RefreshReplacementCoordinates {
        token_id: stored.token_id,
        family_id: stored.family_id,
        grant_id: stored.grant_id,
        rotation_sequence: stored.rotation_sequence,
        family_expires_at: stored.family_expires_at,
    };
    let resource =
        ResourceUri::parse(stored.resource_uri, false).map_err(|_| OAuthStoreError::CorruptData)?;
    let granted_scopes = parse_scopes(stored.granted_scopes)?;
    if granted_scopes
        .iter()
        .any(|scope| grant.granted_scopes.binary_search(scope).is_err())
        || !grant.resources.contains(&resource)
    {
        return Err(OAuthStoreError::CorruptData);
    }
    let (replacement_id, replacement_sequence, replacement_expires_at) =
        persist_refresh_replacement(
            transaction,
            coordinates,
            replacement_digest,
            now,
            replacement_expires_at,
        )
        .await?;
    Ok(RefreshRotation::Rotated(Box::new(RotatedRefreshToken {
        grant,
        resource,
        granted_scopes,
        family_id: stored.family_id,
        token_id: replacement_id,
        rotation_sequence: replacement_sequence,
        expires_at: replacement_expires_at,
    })))
}

async fn revoke_reused_family(
    transaction: &mut Transaction<'_, Postgres>,
    presented_token_id: RefreshTokenId,
    family_id: RefreshFamilyId,
    grant_id: GrantId,
    token_was_consumed: bool,
    now: OffsetDateTime,
) -> Result<(), OAuthStoreError> {
    if token_was_consumed {
        sqlx::query("UPDATE oauth_refresh_tokens SET reuse_detected_at = $2 WHERE id = $1")
            .bind(presented_token_id.as_uuid())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(|error| map_db(&error))?;
    }
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = COALESCE(revoked_at, $2), \
         revocation_reason = 'refresh_reuse', reuse_detected_at = $2, version = version + 1 \
         WHERE id = $1",
    )
    .bind(family_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_refresh_tokens SET revoked_at = $2 \
         WHERE family_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(family_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    sqlx::query(
        "UPDATE oauth_grants SET revoked_at = COALESCE(revoked_at, $2), updated_at = $2, \
         version = version + 1 WHERE id = $1",
    )
    .bind(grant_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(())
}

fn validate_authorization_code(input: &AuthorizationCodeCreate) -> Result<(), OAuthStoreError> {
    if input.expires_at <= input.issued_at
        || input.expires_at > input.issued_at + Duration::minutes(10)
        || input
            .nonce
            .as_ref()
            .is_some_and(|value| !valid_visible_text(value, MAX_NONCE_BYTES))
        || input.granted_scopes.is_empty()
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    resource_values(&input.resource_uris)?;
    scope_values(&input.granted_scopes)?;
    Ok(())
}

fn sorted_subset(candidate: &[String], allowed: &[String]) -> bool {
    candidate
        .iter()
        .all(|value| allowed.binary_search(value).is_ok())
}

fn refresh_family_id(value: Uuid) -> Result<RefreshFamilyId, OAuthStoreError> {
    RefreshFamilyId::from_uuid(value)
}

fn refresh_token_id(value: Uuid) -> Result<RefreshTokenId, OAuthStoreError> {
    RefreshTokenId::from_uuid(value)
}
