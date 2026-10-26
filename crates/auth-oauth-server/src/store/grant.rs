//! Subject, grant, and live access-token state persistence.

use super::{
    OAuthPostgresStore, OAuthStoreError, OAuthSubjectId, PublicSubject, assurance_value, finish,
    grant_id, live_grant_from_row, load_live_grant, map_db, parse_resources, parse_scopes,
    resource_values, scope_values, subject_id, tenant_id, valid_visible_text,
};
use crate::types::{ClientId, GrantId, JwtId, ResourceUri};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Scope, SubjectId, TenantId};
use sqlx::Connection as _;
use sqlx::Row as _;
use sqlx::postgres::PgRow;
use sqlx::{Postgres, Transaction};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

const MAX_LIST_LIMIT: u16 = 100;

const MAX_AUTH_METHODS: usize = 16;

/// Stable issuer subject allocation result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OAuthSubject {
    /// Internal subject row identifier.
    pub id: OAuthSubjectId,
    /// Internal user identifier.
    pub user_id: SubjectId,
    /// Stable issuer public subject.
    pub public_subject: PublicSubject,
    /// Allocation time.
    pub created_at: OffsetDateTime,
}

/// Input for a durable consent grant.
#[derive(Clone, Debug)]
pub struct GrantCreate {
    /// Active user receiving the grant.
    pub user_id: SubjectId,
    /// Optional active tenant membership binding.
    pub tenant_id: Option<TenantId>,
    /// Active client receiving consent.
    pub client_id: ClientId,
    /// Exact resource set.
    pub resources: Vec<ResourceUri>,
    /// Exact granted scope set.
    pub granted_scopes: Vec<Scope>,
    /// Time of user authentication.
    pub authenticated_at: OffsetDateTime,
    /// Authentication assurance.
    pub assurance_level: AssuranceLevel,
    /// Authentication methods.
    pub authentication_methods: Vec<AuthMethod>,
    /// Explicit consent time.
    pub consented_at: OffsetDateTime,
}

/// Live grant state used by token issuance and verification.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LiveGrant {
    /// Grant identifier.
    pub id: GrantId,
    /// Issuer-local public subject.
    pub public_subject: PublicSubject,
    /// Internal user identifier, retained only inside the issuer.
    pub user_id: SubjectId,
    /// Optional tenant binding.
    pub tenant_id: Option<TenantId>,
    /// Client identifier.
    pub client_id: ClientId,
    /// Resource set.
    pub resources: Vec<ResourceUri>,
    /// Granted scopes.
    pub granted_scopes: Vec<Scope>,
    /// Authentication time.
    pub authenticated_at: OffsetDateTime,
    /// Authentication assurance.
    pub assurance_level: AssuranceLevel,
    /// Authentication methods.
    pub authentication_methods: Vec<AuthMethod>,
    /// Consent time.
    pub consented_at: OffsetDateTime,
    /// Grant version.
    pub version: i64,
}

/// Pagination cursor for connected grants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct GrantCursor {
    /// Creation timestamp of the preceding row.
    pub created_at: OffsetDateTime,
    /// Grant identifier of the preceding row.
    pub id: GrantId,
}

/// Safe connected-application metadata.
#[derive(Clone, Debug)]
pub struct ConnectedGrant {
    /// Grant identifier exposed for owner revocation.
    pub grant_id: GrantId,
    /// Protocol client identifier.
    pub client_id: ClientId,
    /// Safe display name.
    pub client_name: String,
    /// Optional client home page.
    pub client_uri: Option<String>,
    /// Optional logo URL.
    pub logo_uri: Option<String>,
    /// Optional tenant binding.
    pub tenant_id: Option<TenantId>,
    /// Resource set.
    pub resources: Vec<ResourceUri>,
    /// Granted scopes.
    pub granted_scopes: Vec<Scope>,
    /// Consent time.
    pub consented_at: OffsetDateTime,
    /// Creation time used by pagination.
    pub created_at: OffsetDateTime,
}

/// Bounded connected-grant page.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ConnectedGrantPage {
    /// Safe grant rows.
    pub grants: Vec<ConnectedGrant>,
    /// Cursor for the next page.
    pub next: Option<GrantCursor>,
}

/// Untrusted token claims reduced to the fields required for a live-state check.
#[derive(Clone, Debug)]
pub struct AccessTokenLiveCheck {
    /// Access token `jti`.
    pub jti: JwtId,
    /// Grant claim.
    pub grant_id: GrantId,
    /// Public subject claim.
    pub public_subject: PublicSubject,
    /// Client claim.
    pub client_id: ClientId,
    /// Resource audience being used.
    pub resource: ResourceUri,
    /// Token scopes, which must remain a subset of the grant.
    pub scopes: Vec<Scope>,
}

/// Verified local email value. Debug output never reveals it.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedEmail(String);

impl VerifiedEmail {
    /// Returns the verified address for the claims boundary.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for VerifiedEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedEmail([REDACTED])")
    }
}

/// Stable subject and current verified identity allocated for an active user.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct AuthorizedSubjectState {
    /// Issuer-local stable subject.
    pub subject: OAuthSubject,
    /// Current verified local email, when present.
    pub verified_email: Option<VerifiedEmail>,
}

/// One-snapshot live authorization result for an issuer access token.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LiveAccessIdentity {
    /// Current live grant, including resolved tenant membership.
    pub grant: LiveGrant,
    /// Current verified local email, when present.
    pub verified_email: Option<VerifiedEmail>,
}

impl OAuthPostgresStore {
    /// Allocates one stable public subject for an active user under concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if user or subject state violates its invariants or
    /// PostgreSQL cannot complete the transaction.
    pub async fn allocate_subject(
        &self,
        user_id: SubjectId,
        candidate: PublicSubject,
        now: OffsetDateTime,
    ) -> Result<OAuthSubject, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let row = sqlx::query(
            "INSERT INTO oauth_subjects (id, user_id, public_subject, created_at) \
             SELECT $1, id, $3, $4 FROM users WHERE id = $2 AND status = 'active' \
             ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id \
             RETURNING id, user_id, public_subject, created_at",
        )
        .bind(Uuid::now_v7())
        .bind(user_id.as_uuid())
        .bind(candidate.as_str())
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(OAuthStoreError::Inactive)?;
        subject_from_row(&row)
    }

    /// Allocates a stable public subject and reads current verified identity in one snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if identity state violates its invariants or PostgreSQL
    /// cannot complete the transaction.
    pub async fn authorize_subject(
        &self,
        user_id: SubjectId,
        candidate: PublicSubject,
        local_identity_provider: &str,
        now: OffsetDateTime,
    ) -> Result<AuthorizedSubjectState, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let row = sqlx::query(
                "INSERT INTO oauth_subjects (id, user_id, public_subject, created_at) \
                 SELECT $1, id, $3, $4 FROM users WHERE id = $2 AND status = 'active' \
                 ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id \
                 RETURNING id, user_id, public_subject, created_at",
            )
            .bind(Uuid::now_v7())
            .bind(user_id.as_uuid())
            .bind(candidate.as_str())
            .bind(now)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(OAuthStoreError::Inactive)?;
            let subject = subject_from_row(&row)?;
            let verified_email =
                verified_email_with(&mut transaction, user_id, local_identity_provider).await?;
            Ok(AuthorizedSubjectState {
                subject,
                verified_email,
            })
        }
        .await;
        finish(transaction, result).await
    }

    /// Creates a consent grant after atomically rechecking user, client, and tenant membership.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if grant input or durable authorization state violates
    /// its invariants, or if PostgreSQL cannot complete the transaction.
    pub async fn create_grant(&self, input: &GrantCreate) -> Result<LiveGrant, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self.create_grant_with(&mut transaction, input).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::create_grant`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if grant input or durable authorization state violates
    /// its invariants, or if PostgreSQL cannot complete the caller-owned transaction.
    pub async fn create_grant_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        input: &GrantCreate,
    ) -> Result<LiveGrant, OAuthStoreError> {
        validate_grant_create(input)?;
        let resources = resource_values(&input.resources)?;
        let scopes = scope_values(&input.granted_scopes)?;
        let methods = auth_method_values(&input.authentication_methods)?;
        let grant_id = GrantId::new();
        let row = sqlx::query(
            "INSERT INTO oauth_grants \
             (id, subject_id, tenant_id, client_id, resources, granted_scopes, authenticated_at, \
              assurance_level, authentication_methods, consented_at, created_at, updated_at, \
              revoked_at, version) \
             SELECT $1, subject.id, $3, client.id, $5, $6, $7, $8, $9, $10, $10, $10, NULL, 1 \
             FROM oauth_subjects subject \
             JOIN users user_account ON user_account.id = subject.user_id \
             CROSS JOIN oauth_clients client \
             WHERE subject.user_id = $2 AND user_account.status = 'active' \
               AND client.client_id = $4 AND client.status = 'active' \
               AND ($3::uuid IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = $3 AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             FOR SHARE OF subject, user_account, client \
             RETURNING id",
        )
        .bind(grant_id.as_uuid())
        .bind(input.user_id.as_uuid())
        .bind(input.tenant_id.map(TenantId::as_uuid))
        .bind(input.client_id.as_str())
        .bind(&resources)
        .bind(&scopes)
        .bind(input.authenticated_at)
        .bind(assurance_value(input.assurance_level))
        .bind(&methods)
        .bind(input.consented_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        if row.is_none() {
            return Err(OAuthStoreError::Inactive);
        }
        load_live_grant(transaction, grant_id)
            .await?
            .ok_or(OAuthStoreError::CorruptData)
    }

    /// Finds the newest live covering grant without broadening resources or scopes.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if requested resources or scopes are invalid, stored grant
    /// data is corrupt, or PostgreSQL cannot complete the transaction.
    pub async fn find_reusable_grant(
        &self,
        user_id: SubjectId,
        tenant_id: Option<TenantId>,
        client_id: &ClientId,
        resources: &[ResourceUri],
        scopes: &[Scope],
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = self
            .find_reusable_grant_in_transaction(
                &mut transaction,
                user_id,
                tenant_id,
                client_id,
                resources,
                scopes,
            )
            .await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::find_reusable_grant`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if requested resources or scopes are invalid, stored grant
    /// data is corrupt, or PostgreSQL cannot complete the caller-owned transaction.
    pub async fn find_reusable_grant_in_transaction(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        tenant_id: Option<TenantId>,
        client_id: &ClientId,
        resources: &[ResourceUri],
        scopes: &[Scope],
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        let resources = resource_values(resources)?;
        let scopes = scope_values(scopes)?;
        let row = sqlx::query(
            "SELECT grant_row.id FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             WHERE subject.user_id = $1 AND grant_row.tenant_id IS NOT DISTINCT FROM $2 \
               AND client.client_id = $3 AND user_account.status = 'active' \
               AND client.status = 'active' AND grant_row.revoked_at IS NULL \
               AND grant_row.resources @> $4 AND grant_row.granted_scopes @> $5 \
               AND ($2::uuid IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = $2 AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             ORDER BY grant_row.created_at DESC, grant_row.id DESC LIMIT 1 FOR SHARE OF grant_row",
        )
        .bind(user_id.as_uuid())
        .bind(tenant_id.map(TenantId::as_uuid))
        .bind(client_id.as_str())
        .bind(&resources)
        .bind(&scopes)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let grant_id = grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?;
        load_live_grant(transaction, grant_id).await
    }

    /// Revokes an owned grant and every active refresh family atomically.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored grant state is corrupt or PostgreSQL cannot
    /// complete the transaction.
    pub async fn revoke_grant(
        &self,
        user_id: SubjectId,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = revoke_grant_with(&mut transaction, user_id, grant_id, now).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::revoke_grant`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored grant state is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn revoke_grant_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        grant_id: GrantId,
        now: OffsetDateTime,
    ) -> Result<bool, OAuthStoreError> {
        revoke_grant_with(transaction, user_id, grant_id, now).await
    }

    /// Lists bounded safe connected-application metadata for one active user.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if pagination is invalid, stored grant data is corrupt, or
    /// PostgreSQL cannot complete the query.
    pub async fn list_connected_grants(
        &self,
        user_id: SubjectId,
        cursor: Option<GrantCursor>,
        limit: u16,
    ) -> Result<ConnectedGrantPage, OAuthStoreError> {
        if limit == 0 || limit > MAX_LIST_LIMIT {
            return Err(OAuthStoreError::InvalidInput);
        }
        let fetch_limit = i64::from(limit) + 1;
        let (cursor_created_at, cursor_id) = cursor.map_or((None, None), |cursor| {
            (Some(cursor.created_at), Some(cursor.id.as_uuid()))
        });
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let rows = sqlx::query(
            "SELECT grant_row.id, grant_row.tenant_id, grant_row.resources, \
                    grant_row.granted_scopes, grant_row.consented_at, grant_row.created_at, \
                    client.client_id, client.display_name, client.client_uri, client.logo_uri \
             FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             WHERE subject.user_id = $1 AND user_account.status = 'active' \
               AND grant_row.revoked_at IS NULL AND client.status = 'active' \
               AND ($2::timestamptz IS NULL OR (grant_row.created_at, grant_row.id) < ($2, $3)) \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active')) \
             ORDER BY grant_row.created_at DESC, grant_row.id DESC LIMIT $4",
        )
        .bind(user_id.as_uuid())
        .bind(cursor_created_at)
        .bind(cursor_id)
        .bind(fetch_limit)
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        let mut grants = rows
            .iter()
            .map(connected_grant_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = grants.len() > usize::from(limit);
        if has_more {
            grants.truncate(usize::from(limit));
        }
        let next = if has_more {
            grants.last().map(|grant| GrantCursor {
                created_at: grant.created_at,
                id: grant.grant_id,
            })
        } else {
            None
        };
        Ok(ConnectedGrantPage { grants, next })
    }

    /// Rechecks live authorization state and returns the durable grant.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if token or stored grant state violates its invariants, or
    /// if PostgreSQL cannot complete the query.
    pub async fn verify_access_token_live(
        &self,
        check: &AccessTokenLiveCheck,
        now: OffsetDateTime,
    ) -> Result<Option<LiveGrant>, OAuthStoreError> {
        self.verify_access_token_live_identity(check, "local", now)
            .await
            .map(|identity| identity.map(|identity| identity.grant))
    }

    /// One-snapshot live authorization and verified local-identity read.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if token, grant, or identity state violates its invariants,
    /// or if PostgreSQL cannot complete the transaction.
    pub async fn verify_access_token_live_identity(
        &self,
        check: &AccessTokenLiveCheck,
        local_identity_provider: &str,
        now: OffsetDateTime,
    ) -> Result<Option<LiveAccessIdentity>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let scopes = scope_values(&check.scopes)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT grant_row.id, subject.public_subject, subject.user_id, grant_row.tenant_id, \
                    client.client_id, grant_row.resources, grant_row.granted_scopes, \
                    grant_row.authenticated_at, grant_row.assurance_level, \
                    grant_row.authentication_methods, grant_row.consented_at, grant_row.version, \
                    verified_identity.provider_subject AS verified_email \
             FROM oauth_grants grant_row \
             JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
             JOIN users user_account ON user_account.id = subject.user_id \
             JOIN oauth_clients client ON client.id = grant_row.client_id \
             LEFT JOIN LATERAL ( \
                 SELECT identity.provider_subject FROM identities identity \
                 WHERE identity.user_id = subject.user_id AND identity.provider = $7 \
                   AND identity.verified_at IS NOT NULL \
                 ORDER BY identity.created_at, identity.id LIMIT 1 \
             ) verified_identity ON true \
             WHERE grant_row.id = $1 AND subject.public_subject = $2 AND client.client_id = $3 \
               AND $4 = ANY(grant_row.resources) AND grant_row.granted_scopes @> $5 \
               AND grant_row.revoked_at IS NULL AND user_account.status = 'active' \
               AND client.status = 'active' \
               AND NOT EXISTS (SELECT 1 FROM oauth_access_token_revocations revocation \
                               WHERE revocation.jti = $6 AND revocation.expires_at > $8) \
               AND (grant_row.tenant_id IS NULL OR EXISTS ( \
                   SELECT 1 FROM organizations organization \
                   JOIN memberships membership ON membership.organization_id = organization.id \
                   WHERE organization.id = grant_row.tenant_id AND organization.status = 'active' \
                     AND membership.user_id = subject.user_id AND membership.status = 'active'))",
        )
        .bind(check.grant_id.as_uuid())
        .bind(check.public_subject.as_str())
        .bind(check.client_id.as_str())
        .bind(check.resource.as_str())
        .bind(&scopes)
        .bind(check.jti.as_uuid())
        .bind(local_identity_provider)
        .bind(now)
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        row.as_ref()
            .map(|row| {
                Ok(LiveAccessIdentity {
                    grant: live_grant_from_row(row)?,
                    verified_email: row
                        .try_get::<Option<String>, _>("verified_email")
                        .map_err(|_| OAuthStoreError::CorruptData)?
                        .map(VerifiedEmail),
                })
            })
            .transpose()
    }

    /// Returns a verified local email only for an active user.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored identity data is corrupt or PostgreSQL cannot
    /// complete the query.
    pub async fn verified_email(
        &self,
        user_id: SubjectId,
        local_identity_provider: &str,
    ) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let mut transaction = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = verified_email_with(&mut transaction, user_id, local_identity_provider).await;
        finish(transaction, result).await
    }

    /// Caller-owned transaction variant of [`Self::verified_email`].
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored identity data is corrupt or PostgreSQL cannot
    /// complete the caller-owned transaction.
    pub async fn verified_email_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        user_id: SubjectId,
        local_identity_provider: &str,
    ) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
        if !valid_visible_text(local_identity_provider, 255) {
            return Err(OAuthStoreError::InvalidInput);
        }
        verified_email_with(transaction, user_id, local_identity_provider).await
    }

    /// Confirms that an active internal user owns an issuer-local public subject.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthStoreError`] if stored subject data is corrupt or PostgreSQL cannot
    /// complete the query.
    pub async fn public_subject_matches(
        &self,
        user_id: SubjectId,
        public_subject: &str,
    ) -> Result<bool, OAuthStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| OAuthStoreError::Unavailable)?;
        let matched: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM oauth_subjects subject \
                 JOIN users user_account ON user_account.id = subject.user_id \
                 WHERE subject.user_id = $1 AND subject.public_subject = $2 \
                   AND user_account.status = 'active')",
        )
        .bind(user_id.as_uuid())
        .bind(public_subject)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        Ok(matched)
    }
}

async fn verified_email_with(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
    local_identity_provider: &str,
) -> Result<Option<VerifiedEmail>, OAuthStoreError> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT identity.provider_subject FROM identities identity \
         JOIN users user_account ON user_account.id = identity.user_id \
         WHERE identity.user_id = $1 AND identity.provider = $2 \
           AND identity.verified_at IS NOT NULL AND user_account.status = 'active' \
         ORDER BY identity.created_at, identity.id LIMIT 1",
    )
    .bind(user_id.as_uuid())
    .bind(local_identity_provider)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(value.map(VerifiedEmail))
}

async fn revoke_grant_with(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: SubjectId,
    grant_id: GrantId,
    now: OffsetDateTime,
) -> Result<bool, OAuthStoreError> {
    let row = sqlx::query(
        "SELECT grant_row.revoked_at FROM oauth_grants grant_row \
         JOIN oauth_subjects subject ON subject.id = grant_row.subject_id \
         WHERE grant_row.id = $1 AND subject.user_id = $2 FOR UPDATE OF grant_row",
    )
    .bind(grant_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revoked_at: Option<OffsetDateTime> = row
        .try_get("revoked_at")
        .map_err(|_| OAuthStoreError::CorruptData)?;
    if revoked_at.is_none() {
        sqlx::query(
            "UPDATE oauth_grants SET revoked_at = $2, updated_at = $2, version = version + 1 \
             WHERE id = $1",
        )
        .bind(grant_id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_db(&error))?;
    }
    sqlx::query(
        "UPDATE oauth_refresh_token_families SET revoked_at = $2, \
         revocation_reason = 'grant_revoked', version = version + 1 \
         WHERE grant_id = $1 AND revoked_at IS NULL",
    )
    .bind(grant_id.as_uuid())
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_db(&error))?;
    Ok(true)
}

fn subject_from_row(row: &PgRow) -> Result<OAuthSubject, OAuthStoreError> {
    Ok(OAuthSubject {
        id: oauth_subject_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        user_id: subject_id(
            row.try_get("user_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        public_subject: PublicSubject::parse(
            row.try_get::<String, _>("public_subject")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn connected_grant_from_row(row: &PgRow) -> Result<ConnectedGrant, OAuthStoreError> {
    Ok(ConnectedGrant {
        grant_id: grant_id(
            row.try_get("id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        client_id: ClientId::parse(
            row.try_get::<String, _>("client_id")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )
        .map_err(|_| OAuthStoreError::CorruptData)?,
        client_name: row
            .try_get("display_name")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        client_uri: row
            .try_get("client_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        logo_uri: row
            .try_get("logo_uri")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        tenant_id: row
            .try_get::<Option<Uuid>, _>("tenant_id")
            .map_err(|_| OAuthStoreError::CorruptData)?
            .map(tenant_id)
            .transpose()?,
        resources: parse_resources(
            row.try_get("resources")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        granted_scopes: parse_scopes(
            row.try_get("granted_scopes")
                .map_err(|_| OAuthStoreError::CorruptData)?,
        )?,
        consented_at: row
            .try_get("consented_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| OAuthStoreError::CorruptData)?,
    })
}

fn validate_grant_create(input: &GrantCreate) -> Result<(), OAuthStoreError> {
    if input.authenticated_at > input.consented_at
        || input.authentication_methods.is_empty()
        || input.authentication_methods.len() > MAX_AUTH_METHODS
        || input.granted_scopes.is_empty()
    {
        return Err(OAuthStoreError::InvalidInput);
    }
    resource_values(&input.resources)?;
    scope_values(&input.granted_scopes)?;
    auth_method_values(&input.authentication_methods)?;
    Ok(())
}

fn auth_method_values(values: &[AuthMethod]) -> Result<Vec<String>, OAuthStoreError> {
    if values.is_empty() || values.len() > MAX_AUTH_METHODS {
        return Err(OAuthStoreError::InvalidInput);
    }
    let result = values
        .iter()
        .copied()
        .map(auth_method_value)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if result.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(OAuthStoreError::InvalidInput);
    }
    Ok(result)
}

const fn auth_method_value(value: AuthMethod) -> &'static str {
    match value {
        AuthMethod::Password => "password",
        AuthMethod::Session => "session",
        AuthMethod::Jwt => "jwt",
        AuthMethod::Oidc => "oidc",
        AuthMethod::ApiKey => "api_key",
        AuthMethod::WebAuthn => "web_authn",
        AuthMethod::Totp => "totp",
    }
}

fn oauth_subject_id(value: Uuid) -> Result<OAuthSubjectId, OAuthStoreError> {
    OAuthSubjectId::from_uuid(value)
}
