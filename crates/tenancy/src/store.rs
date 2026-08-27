//! PostgreSQL tenancy lifecycle persistence and canonical context resolution.

use std::{fmt, str::FromStr as _, time::Instant};

use omnius_auth_core::{Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::{AuthorizationContext, Role};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::Uuid;

use crate::{
    config::TenancyConfig,
    types::{
        CreatedOrganization, Invitation, InvitationId, InvitationRole, InvitationStatus,
        Membership, MembershipRole, MembershipStatus, Organization, OrganizationName,
        OrganizationStatus, OwnershipTransfer, utc,
    },
};

/// Canonical principal, authorization facts, and membership for one active tenant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TenantContext {
    principal: Principal,
    authorization_context: AuthorizationContext,
    membership: Membership,
}

impl TenantContext {
    /// Returns the cloned canonical principal bound to the resolved tenant.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the authoritative authorization context for the tenant.
    #[must_use]
    pub const fn authorization_context(&self) -> &AuthorizationContext {
        &self.authorization_context
    }

    /// Returns the authoritative active membership used during resolution.
    #[must_use]
    pub const fn membership(&self) -> &Membership {
        &self.membership
    }

    /// Consumes the context into its canonical parts.
    #[must_use]
    pub fn into_parts(self) -> (Principal, AuthorizationContext, Membership) {
        (self.principal, self.authorization_context, self.membership)
    }
}

/// PostgreSQL-backed organization, membership, invitation, and tenant-context store.
#[derive(Clone)]
pub struct TenancyStore {
    pool: PostgresPool,
    max_list_items: usize,
}

impl fmt::Debug for TenancyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenancyStore")
            .field("max_list_items", &self.max_list_items)
            .finish_non_exhaustive()
    }
}

impl TenancyStore {
    /// Creates an enabled tenancy store from validated configuration.
    ///
    /// # Errors
    ///
    /// Returns a stable error when configuration is invalid or tenancy is disabled.
    pub fn new(pool: PostgresPool, config: &TenancyConfig) -> Result<Self, TenancyStoreError> {
        config
            .validate()
            .map_err(|_| TenancyStoreError::InvalidConfiguration)?;
        if !config.enabled {
            return Err(TenancyStoreError::Disabled);
        }
        Ok(Self {
            pool,
            max_list_items: usize::from(config.max_list_items),
        })
    }

    /// Atomically creates an active organization and its initial active owner grant.
    ///
    /// # Errors
    ///
    /// Returns a stable missing-user, conflict, or persistence error.
    pub async fn create_organization(
        &self,
        owner_user_id: SubjectId,
        name: OrganizationName,
    ) -> Result<CreatedOrganization, TenancyStoreError> {
        let started = Instant::now();
        let result = self.create_organization_inner(owner_user_id, name).await;
        record(
            "create_organization",
            result_label(&result, "created"),
            started.elapsed(),
        );
        result
    }

    /// Gets one active organization only when `user_id` has an active membership in it.
    ///
    /// Missing, inactive, and cross-tenant organizations all return the same denial.
    ///
    /// # Errors
    ///
    /// Returns a stable access-denied or persistence error.
    pub async fn get_organization(
        &self,
        organization_id: TenantId,
        user_id: SubjectId,
    ) -> Result<Organization, TenancyStoreError> {
        let started = Instant::now();
        let result = self.get_organization_inner(organization_id, user_id).await;
        record(
            "get_organization",
            result_label(&result, "found"),
            started.elapsed(),
        );
        result
    }

    /// Lists active organizations for which `user_id` has an active membership.
    ///
    /// The query is bounded by `TenancyConfig::max_list_items`
    /// and errors rather than returning a truncated list.
    ///
    /// # Errors
    ///
    /// Returns a stable list-limit or persistence error.
    pub async fn list_organizations(
        &self,
        user_id: SubjectId,
    ) -> Result<Vec<Organization>, TenancyStoreError> {
        let started = Instant::now();
        let result = self.list_organizations_inner(user_id).await;
        record(
            "list_organizations",
            result_label(&result, "listed"),
            started.elapsed(),
        );
        result
    }

    /// Renames an active organization as one of its active owners.
    ///
    /// # Errors
    ///
    /// Returns the same denial for missing, inactive, and unauthorized organizations.
    pub async fn rename_organization(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        name: &OrganizationName,
    ) -> Result<Organization, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .rename_organization_inner(organization_id, actor_user_id, name)
            .await;
        record(
            "rename_organization",
            result_label(&result, "renamed"),
            started.elapsed(),
        );
        result
    }

    /// Moves a non-deleted organization between active, suspended, and deleted states.
    ///
    /// Only an active owner membership may change status. Deleted organizations are terminal.
    /// Suspending and deleting immediately remove the organization from ordinary reads and tenant
    /// resolution; reactivating a suspended organization restores those paths.
    ///
    /// # Errors
    ///
    /// Returns the same denial for missing, deleted, and unauthorized organizations.
    pub async fn set_organization_status(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        status: OrganizationStatus,
    ) -> Result<Organization, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .set_organization_status_inner(organization_id, actor_user_id, status)
            .await;
        record(
            "set_organization_status",
            result_label(&result, "updated"),
            started.elapsed(),
        );
        result
    }

    /// Lists grants in an active organization for an active owner or administrator.
    ///
    /// # Errors
    ///
    /// Returns a stable denial, list-limit, corrupt-data, or persistence error.
    pub async fn list_memberships(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
    ) -> Result<Vec<Membership>, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .list_memberships_inner(organization_id, actor_user_id)
            .await;
        record(
            "list_memberships",
            result_label(&result, "listed"),
            started.elapsed(),
        );
        result
    }

    /// Atomically changes one membership's role and status as an active owner.
    ///
    /// A changed grant increments its `grant_version` and the organization version. An identical
    /// update is idempotent. PostgreSQL's deferred invariant rejects removal of the final active
    /// owner at commit.
    ///
    /// # Errors
    ///
    /// Returns a stable denial, missing-membership, last-owner, conflict, or persistence error.
    pub async fn update_membership(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        member_user_id: SubjectId,
        role: MembershipRole,
        status: MembershipStatus,
    ) -> Result<Membership, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .update_membership_inner(organization_id, actor_user_id, member_user_id, role, status)
            .await;
        record(
            "update_membership",
            result_label(&result, "updated"),
            started.elapsed(),
        );
        result
    }

    /// Atomically demotes the acting owner to administrator and promotes an active member.
    ///
    /// Both grants increment their `grant_version`; the organization version increments once.
    ///
    /// # Errors
    ///
    /// Returns a stable denial, invalid-target, last-owner, conflict, or persistence error.
    pub async fn transfer_ownership(
        &self,
        organization_id: TenantId,
        current_owner_user_id: SubjectId,
        new_owner_user_id: SubjectId,
    ) -> Result<OwnershipTransfer, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .transfer_ownership_inner(organization_id, current_owner_user_id, new_owner_user_id)
            .await;
        record(
            "transfer_ownership",
            result_label(&result, "transferred"),
            started.elapsed(),
        );
        result
    }

    /// Creates a pending invitation bound to an existing user and a non-owner role.
    ///
    /// # Errors
    ///
    /// Returns a stable denial, missing-user, invalid-expiry, duplicate, or persistence error.
    pub async fn create_invitation(
        &self,
        organization_id: TenantId,
        invited_by_user_id: SubjectId,
        invited_user_id: SubjectId,
        role: InvitationRole,
        expires_at: OffsetDateTime,
    ) -> Result<Invitation, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .create_invitation_inner(
                organization_id,
                invited_by_user_id,
                invited_user_id,
                role,
                expires_at,
            )
            .await;
        record(
            "create_invitation",
            result_label(&result, "created"),
            started.elapsed(),
        );
        result
    }

    /// Lists invitations in an active organization for an active owner or administrator.
    ///
    /// Every invitation query is scoped by `organization_id` in addition to invitation identity.
    ///
    /// # Errors
    ///
    /// Returns a stable denial, list-limit, corrupt-data, or persistence error.
    pub async fn list_invitations(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
    ) -> Result<Vec<Invitation>, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .list_invitations_inner(organization_id, actor_user_id)
            .await;
        record(
            "list_invitations",
            result_label(&result, "listed"),
            started.elapsed(),
        );
        result
    }

    /// Accepts an invitation as its authenticated existing user.
    ///
    /// No invitation secret exists: the invitation row is bound to `principal.subject_id`.
    /// Acceptance creates or reactivates the membership, increments the grant version where a row
    /// already exists, and increments the organization version. Observation after expiry commits
    /// the expired terminal state before returning [`TenancyStoreError::InvitationExpired`].
    ///
    /// # Errors
    ///
    /// Returns uniform invitation unavailability for missing, wrong-tenant, wrong-user, accepted,
    /// or revoked rows, plus stable expiry, membership-state, and persistence errors.
    pub async fn accept_invitation(
        &self,
        organization_id: TenantId,
        invitation_id: InvitationId,
        principal: &Principal,
    ) -> Result<Membership, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .accept_invitation_inner(organization_id, invitation_id, principal)
            .await;
        record(
            "accept_invitation",
            result_label(&result, "accepted"),
            started.elapsed(),
        );
        result
    }

    /// Revokes one pending organization-scoped invitation as an active owner or administrator.
    ///
    /// Revocation is idempotent for an already revoked row. An expired pending row is committed as
    /// expired rather than being rewritten as revoked.
    ///
    /// # Errors
    ///
    /// Returns uniform invitation unavailability for missing, cross-tenant, or accepted rows.
    pub async fn revoke_invitation(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        invitation_id: InvitationId,
    ) -> Result<Invitation, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .revoke_invitation_inner(organization_id, actor_user_id, invitation_id)
            .await;
        record(
            "revoke_invitation",
            result_label(&result, "revoked"),
            started.elapsed(),
        );
        result
    }

    /// Resolves an active authoritative membership into a canonical tenant context.
    ///
    /// Tenantless principals are cloned and bound after the database lookup. A principal already
    /// bound to another tenant is rejected before lookup. A principal already bound to the same
    /// tenant is still revalidated. The authorization context contains exactly the authoritative
    /// `organization:<role>` role and requested tenant membership.
    ///
    /// # Errors
    ///
    /// Returns the same access denial for a missing organization, an inactive organization, or an
    /// inactive/missing membership. A different active tenant returns a stable mismatch error.
    pub async fn resolve_tenant_context(
        &self,
        principal: &Principal,
        organization_id: TenantId,
    ) -> Result<TenantContext, TenancyStoreError> {
        let started = Instant::now();
        let result = self
            .resolve_tenant_context_inner(principal, organization_id)
            .await;
        record(
            "resolve_tenant_context",
            result_label(&result, "resolved"),
            started.elapsed(),
        );
        result
    }

    async fn create_organization_inner(
        &self,
        owner_user_id: SubjectId,
        name: OrganizationName,
    ) -> Result<CreatedOrganization, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let user = sqlx::query("SELECT id FROM users WHERE id = $1 FOR KEY SHARE")
                .bind(owner_user_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?;
            if user.is_none() {
                return Err(TenancyStoreError::UserNotFound);
            }

            let organization_id = TenantId::new();
            let now = OffsetDateTime::now_utc();
            let organization_row = sqlx::query(
                "INSERT INTO organizations \
                 (id, name, status, version, created_at, updated_at, deleted_at) \
                 VALUES ($1, $2, 'active', 1, $3, $3, NULL) \
                 RETURNING id, name, status AS organization_status, version, created_at, \
                           updated_at, deleted_at",
            )
            .bind(organization_id.as_uuid())
            .bind(name.as_str())
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            let membership_row = sqlx::query(
                "INSERT INTO memberships \
                 (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
                 VALUES ($1, $2, 'owner', 'active', 1, $3, $3) \
                 RETURNING organization_id, user_id, role AS membership_role, \
                           status AS membership_status, grant_version, created_at, updated_at",
            )
            .bind(organization_id.as_uuid())
            .bind(owner_user_id.as_uuid())
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            Ok(CreatedOrganization {
                organization: organization_from_row(&organization_row)?,
                owner_membership: membership_from_row(&membership_row)?,
            })
        }
        .await;
        finish(tx, result).await
    }

    async fn get_organization_inner(
        &self,
        organization_id: TenantId,
        user_id: SubjectId,
    ) -> Result<Organization, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let row = sqlx::query(
            "SELECT o.id, o.name, o.status AS organization_status, o.version, o.created_at, \
                    o.updated_at, o.deleted_at \
             FROM organizations o \
             JOIN memberships m ON m.organization_id = o.id \
             WHERE o.id = $1 AND m.organization_id = $1 AND m.user_id = $2 \
               AND o.status = 'active' AND m.status = 'active'",
        )
        .bind(organization_id.as_uuid())
        .bind(user_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(TenancyStoreError::AccessDenied)?;
        organization_from_row(&row)
    }

    async fn list_organizations_inner(
        &self,
        user_id: SubjectId,
    ) -> Result<Vec<Organization>, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let rows = sqlx::query(
            "SELECT o.id, o.name, o.status AS organization_status, o.version, o.created_at, \
                    o.updated_at, o.deleted_at \
             FROM memberships m \
             JOIN organizations o ON o.id = m.organization_id \
             WHERE m.user_id = $1 AND m.status = 'active' AND o.status = 'active' \
             ORDER BY o.created_at, o.id \
             LIMIT $2",
        )
        .bind(user_id.as_uuid())
        .bind(self.sentinel_limit())
        .fetch_all(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?;
        self.ensure_bounded(&rows)?;
        rows.iter().map(organization_from_row).collect()
    }

    async fn rename_organization_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        name: &OrganizationName,
    ) -> Result<Organization, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (organization, role) =
                lock_actor(&mut tx, organization_id, actor_user_id, true).await?;
            require_owner(role)?;
            if organization.name.eq(name) {
                return Ok(organization);
            }
            let now = OffsetDateTime::now_utc();
            let row = sqlx::query(
                "UPDATE organizations SET name = $3, version = version + 1, updated_at = $4 \
                 WHERE id = $1 AND id = $2 AND status = 'active' \
                 RETURNING id, name, status AS organization_status, version, created_at, \
                           updated_at, deleted_at",
            )
            .bind(organization_id.as_uuid())
            .bind(organization.id.as_uuid())
            .bind(name.as_str())
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::AccessDenied)?;
            organization_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn set_organization_status_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        status: OrganizationStatus,
    ) -> Result<Organization, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (organization, role) =
                lock_actor(&mut tx, organization_id, actor_user_id, false).await?;
            require_owner(role)?;
            if organization.status == status {
                return Ok(organization);
            }
            let now = OffsetDateTime::now_utc();
            let deleted_at = (status == OrganizationStatus::Deleted).then_some(now);
            let row = sqlx::query(
                "UPDATE organizations \
                 SET status = $2, version = version + 1, updated_at = $3, deleted_at = $4 \
                 WHERE id = $1 AND status <> 'deleted' \
                 RETURNING id, name, status AS organization_status, version, created_at, \
                           updated_at, deleted_at",
            )
            .bind(organization_id.as_uuid())
            .bind(status.as_str())
            .bind(now)
            .bind(deleted_at)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::AccessDenied)?;
            organization_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn list_memberships_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
    ) -> Result<Vec<Membership>, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) = lock_actor(&mut tx, organization_id, actor_user_id, true).await?;
            require_administrator(actor_role)?;
            let rows = sqlx::query(
                "SELECT organization_id, user_id, role AS membership_role, \
                        status AS membership_status, grant_version, created_at, updated_at \
                 FROM memberships \
                 WHERE organization_id = $1 \
                 ORDER BY created_at, user_id \
                 LIMIT $2",
            )
            .bind(organization_id.as_uuid())
            .bind(self.sentinel_limit())
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            self.ensure_bounded(&rows)?;
            rows.iter().map(membership_from_row).collect()
        }
        .await;
        finish(tx, result).await
    }

    async fn update_membership_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        member_user_id: SubjectId,
        role: MembershipRole,
        status: MembershipStatus,
    ) -> Result<Membership, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) = lock_actor(&mut tx, organization_id, actor_user_id, true).await?;
            require_owner(actor_role)?;
            let row = lock_membership(&mut tx, organization_id, member_user_id)
                .await?
                .ok_or(TenancyStoreError::MembershipNotFound)?;
            let membership = membership_from_row(&row)?;
            if membership.role == role && membership.status == status {
                return Ok(membership);
            }
            let now = OffsetDateTime::now_utc();
            let row = sqlx::query(
                "UPDATE memberships \
                 SET role = $3, status = $4, grant_version = grant_version + 1, updated_at = $5 \
                 WHERE organization_id = $1 AND user_id = $2 \
                 RETURNING organization_id, user_id, role AS membership_role, \
                           status AS membership_status, grant_version, created_at, updated_at",
            )
            .bind(organization_id.as_uuid())
            .bind(member_user_id.as_uuid())
            .bind(role.as_str())
            .bind(status.as_str())
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::MembershipNotFound)?;
            bump_organization(&mut tx, organization_id, now).await?;
            membership_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn transfer_ownership_inner(
        &self,
        organization_id: TenantId,
        current_owner_user_id: SubjectId,
        new_owner_user_id: SubjectId,
    ) -> Result<OwnershipTransfer, TenancyStoreError> {
        if current_owner_user_id == new_owner_user_id {
            return Err(TenancyStoreError::InvalidMembershipTransition);
        }
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) =
                lock_actor(&mut tx, organization_id, current_owner_user_id, true).await?;
            require_owner(actor_role)?;
            let target_row = lock_membership(&mut tx, organization_id, new_owner_user_id)
                .await?
                .ok_or(TenancyStoreError::MembershipNotFound)?;
            let target = membership_from_row(&target_row)?;
            if target.status != MembershipStatus::Active {
                return Err(TenancyStoreError::InvalidMembershipTransition);
            }
            let now = OffsetDateTime::now_utc();
            let previous_row = sqlx::query(
                "UPDATE memberships \
                 SET role = 'admin', grant_version = grant_version + 1, updated_at = $3 \
                 WHERE organization_id = $1 AND user_id = $2 \
                   AND role = 'owner' AND status = 'active' \
                 RETURNING organization_id, user_id, role AS membership_role, \
                           status AS membership_status, grant_version, created_at, updated_at",
            )
            .bind(organization_id.as_uuid())
            .bind(current_owner_user_id.as_uuid())
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::AccessDenied)?;
            let new_row = sqlx::query(
                "UPDATE memberships \
                 SET role = 'owner', grant_version = grant_version + 1, updated_at = $3 \
                 WHERE organization_id = $1 AND user_id = $2 AND status = 'active' \
                 RETURNING organization_id, user_id, role AS membership_role, \
                           status AS membership_status, grant_version, created_at, updated_at",
            )
            .bind(organization_id.as_uuid())
            .bind(new_owner_user_id.as_uuid())
            .bind(now)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::InvalidMembershipTransition)?;
            let organization_version = bump_organization(&mut tx, organization_id, now).await?;
            Ok(OwnershipTransfer {
                previous_owner: membership_from_row(&previous_row)?,
                new_owner: membership_from_row(&new_row)?,
                organization_version,
            })
        }
        .await;
        finish(tx, result).await
    }

    async fn create_invitation_inner(
        &self,
        organization_id: TenantId,
        invited_by_user_id: SubjectId,
        invited_user_id: SubjectId,
        role: InvitationRole,
        expires_at: OffsetDateTime,
    ) -> Result<Invitation, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) =
                lock_actor(&mut tx, organization_id, invited_by_user_id, true).await?;
            require_administrator(actor_role)?;
            let now = OffsetDateTime::now_utc();
            let expires_at = expires_at.to_offset(UtcOffset::UTC);
            if expires_at <= now {
                return Err(TenancyStoreError::InvalidInvitationExpiry);
            }
            let user = sqlx::query("SELECT id FROM users WHERE id = $1 FOR KEY SHARE")
                .bind(invited_user_id.as_uuid())
                .fetch_optional(&mut *tx)
                .await
                .map_err(|error| map_db(&error))?;
            if user.is_none() {
                return Err(TenancyStoreError::UserNotFound);
            }
            let active_membership = sqlx::query(
                "SELECT 1 FROM memberships \
                 WHERE organization_id = $1 AND user_id = $2 AND status = 'active'",
            )
            .bind(organization_id.as_uuid())
            .bind(invited_user_id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            if active_membership.is_some() {
                return Err(TenancyStoreError::MembershipAlreadyActive);
            }
            sqlx::query(
                "WITH decision AS (SELECT clock_timestamp() AS decided_at) \
                 UPDATE invitations AS invitation \
                 SET status = 'expired', updated_at = decision.decided_at \
                 FROM decision \
                 WHERE invitation.organization_id = $1 AND invitation.invited_user_id = $2 \
                   AND invitation.status = 'pending' \
                   AND invitation.expires_at <= decision.decided_at",
            )
            .bind(organization_id.as_uuid())
            .bind(invited_user_id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            let row = sqlx::query(
                "INSERT INTO invitations \
                 (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
                  expires_at, created_at, updated_at, accepted_at, revoked_at) \
                 VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7, $7, NULL, NULL) \
                 RETURNING id, organization_id, invited_user_id, invited_by_user_id, \
                           role AS invitation_role, status AS invitation_status, expires_at, \
                           created_at, updated_at, accepted_at, revoked_at",
            )
            .bind(InvitationId::new().as_uuid())
            .bind(organization_id.as_uuid())
            .bind(invited_user_id.as_uuid())
            .bind(invited_by_user_id.as_uuid())
            .bind(role.as_str())
            .bind(expires_at)
            .bind(now)
            .fetch_one(&mut *tx)
            .await
            .map_err(|error| map_invitation_insert(&error))?;
            bump_organization(&mut tx, organization_id, now).await?;
            invitation_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn list_invitations_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
    ) -> Result<Vec<Invitation>, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) = lock_actor(&mut tx, organization_id, actor_user_id, true).await?;
            require_administrator(actor_role)?;
            let rows = sqlx::query(
                "SELECT id, organization_id, invited_user_id, invited_by_user_id, \
                        role AS invitation_role, status AS invitation_status, expires_at, \
                        created_at, updated_at, accepted_at, revoked_at \
                 FROM invitations \
                 WHERE organization_id = $1 \
                 ORDER BY created_at DESC, id DESC \
                 LIMIT $2",
            )
            .bind(organization_id.as_uuid())
            .bind(self.sentinel_limit())
            .fetch_all(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?;
            self.ensure_bounded(&rows)?;
            rows.iter().map(invitation_from_row).collect()
        }
        .await;
        finish(tx, result).await
    }

    async fn accept_invitation_inner(
        &self,
        organization_id: TenantId,
        invitation_id: InvitationId,
        principal: &Principal,
    ) -> Result<Membership, TenancyStoreError> {
        if principal.kind != PrincipalKind::User {
            return Err(TenancyStoreError::InvitationUnavailable);
        }
        if principal
            .tenant_id
            .is_some_and(|tenant_id| tenant_id != organization_id)
        {
            return Err(TenancyStoreError::InvitationUnavailable);
        }
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = accept_invitation_with(
            &mut tx,
            organization_id,
            invitation_id,
            principal.subject_id,
        )
        .await;
        let outcome = finish(tx, result).await?;
        match outcome {
            InvitationAcceptance::Accepted(membership) => Ok(membership),
            InvitationAcceptance::Expired => Err(TenancyStoreError::InvitationExpired),
        }
    }

    async fn revoke_invitation_inner(
        &self,
        organization_id: TenantId,
        actor_user_id: SubjectId,
        invitation_id: InvitationId,
    ) -> Result<Invitation, TenancyStoreError> {
        let mut connection = self.acquire().await?;
        let mut tx = connection.begin().await.map_err(|error| map_db(&error))?;
        let result = async {
            let (_, actor_role) = lock_actor(&mut tx, organization_id, actor_user_id, true).await?;
            require_administrator(actor_role)?;
            let row = lock_invitation(&mut tx, organization_id, invitation_id)
                .await?
                .ok_or(TenancyStoreError::InvitationUnavailable)?;
            let invitation = invitation_from_row(&row)?;
            if invitation.status == InvitationStatus::Revoked {
                return Ok(invitation);
            }
            if invitation.status != InvitationStatus::Pending {
                return Err(TenancyStoreError::InvitationUnavailable);
            }
            let now = OffsetDateTime::now_utc();
            let (status, revoked_at) = if invitation.expires_at <= now {
                (InvitationStatus::Expired, None)
            } else {
                (InvitationStatus::Revoked, Some(now))
            };
            let row = sqlx::query(
                "UPDATE invitations \
                 SET status = $3, updated_at = $4, revoked_at = $5 \
                 WHERE organization_id = $1 AND id = $2 AND status = 'pending' \
                 RETURNING id, organization_id, invited_user_id, invited_by_user_id, \
                           role AS invitation_role, status AS invitation_status, expires_at, \
                           created_at, updated_at, accepted_at, revoked_at",
            )
            .bind(organization_id.as_uuid())
            .bind(invitation_id.as_uuid())
            .bind(status.as_str())
            .bind(now)
            .bind(revoked_at)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| map_db(&error))?
            .ok_or(TenancyStoreError::InvitationUnavailable)?;
            bump_organization(&mut tx, organization_id, now).await?;
            invitation_from_row(&row)
        }
        .await;
        finish(tx, result).await
    }

    async fn resolve_tenant_context_inner(
        &self,
        principal: &Principal,
        organization_id: TenantId,
    ) -> Result<TenantContext, TenancyStoreError> {
        if principal.kind != PrincipalKind::User {
            return Err(TenancyStoreError::AccessDenied);
        }
        if principal
            .tenant_id
            .is_some_and(|tenant_id| tenant_id != organization_id)
        {
            return Err(TenancyStoreError::TenantMismatch);
        }
        let mut connection = self.acquire().await?;
        let row = sqlx::query(
            "SELECT m.organization_id, m.user_id, m.role AS membership_role, \
                    m.status AS membership_status, m.grant_version, m.created_at, m.updated_at \
             FROM memberships m \
             JOIN organizations o ON o.id = m.organization_id \
             WHERE m.organization_id = $1 AND o.id = $1 AND m.user_id = $2 \
               AND m.status = 'active' AND o.status = 'active'",
        )
        .bind(organization_id.as_uuid())
        .bind(principal.subject_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(TenancyStoreError::AccessDenied)?;
        let membership = membership_from_row(&row)?;
        let role = authorization_role(membership.role)?;
        let authorization_context =
            AuthorizationContext::new(vec![role], vec![organization_id], Vec::new(), Vec::new())
                .map_err(|_| TenancyStoreError::CorruptData)?;
        let mut canonical_principal = principal.clone();
        canonical_principal.tenant_id = Some(organization_id);
        Ok(TenantContext {
            principal: canonical_principal,
            authorization_context,
            membership,
        })
    }

    async fn acquire(&self) -> Result<omnius_postgres::PostgresConnection, TenancyStoreError> {
        self.pool
            .acquire()
            .await
            .map_err(|_| TenancyStoreError::Unavailable)
    }

    fn sentinel_limit(&self) -> i64 {
        i64::try_from(self.max_list_items + 1).unwrap_or(i64::MAX)
    }

    fn ensure_bounded<T>(&self, rows: &[T]) -> Result<(), TenancyStoreError> {
        if rows.len() > self.max_list_items {
            Err(TenancyStoreError::ListLimitExceeded)
        } else {
            Ok(())
        }
    }
}

enum InvitationAcceptance {
    Accepted(Membership),
    Expired,
}

async fn accept_invitation_with(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    invitation_id: InvitationId,
    invited_user_id: SubjectId,
) -> Result<InvitationAcceptance, TenancyStoreError> {
    let organization =
        sqlx::query("SELECT id FROM organizations WHERE id = $1 AND status = 'active' FOR UPDATE")
            .bind(organization_id.as_uuid())
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| map_db(&error))?;
    if organization.is_none() {
        return Err(TenancyStoreError::InvitationUnavailable);
    }
    let row = sqlx::query(
        "SELECT id, organization_id, invited_user_id, invited_by_user_id, \
                role AS invitation_role, status AS invitation_status, expires_at, created_at, \
                updated_at, accepted_at, revoked_at \
         FROM invitations \
         WHERE organization_id = $1 AND id = $2 AND invited_user_id = $3 \
         FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .bind(invitation_id.as_uuid())
    .bind(invited_user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?
    .ok_or(TenancyStoreError::InvitationUnavailable)?;
    let invitation = invitation_from_row(&row)?;
    if invitation.status == InvitationStatus::Expired {
        return Ok(InvitationAcceptance::Expired);
    }
    if invitation.status != InvitationStatus::Pending {
        return Err(TenancyStoreError::InvitationUnavailable);
    }
    let active = sqlx::query(
        "SELECT 1 FROM memberships \
         WHERE organization_id = $1 AND user_id = $2 AND status = 'active' \
         FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .bind(invited_user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if active.is_some() {
        return Err(TenancyStoreError::MembershipAlreadyActive);
    }

    let Some(accepted_at) =
        claim_pending_invitation(tx, organization_id, invitation_id, invited_user_id).await?
    else {
        return Ok(InvitationAcceptance::Expired);
    };

    let membership_row = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, $3, 'active', 1, $4, $4) \
         ON CONFLICT (organization_id, user_id) DO UPDATE \
         SET role = EXCLUDED.role, status = 'active', \
             grant_version = memberships.grant_version + 1, updated_at = EXCLUDED.updated_at \
         RETURNING organization_id, user_id, role AS membership_role, \
                   status AS membership_status, grant_version, created_at, updated_at",
    )
    .bind(organization_id.as_uuid())
    .bind(invited_user_id.as_uuid())
    .bind(invitation.role.as_str())
    .bind(accepted_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    bump_organization(tx, organization_id, accepted_at).await?;
    Ok(InvitationAcceptance::Accepted(membership_from_row(
        &membership_row,
    )?))
}

async fn claim_pending_invitation(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    invitation_id: InvitationId,
    invited_user_id: SubjectId,
) -> Result<Option<OffsetDateTime>, TenancyStoreError> {
    let accepted_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "WITH decision AS (SELECT clock_timestamp() AS decided_at) \
         UPDATE invitations AS invitation \
         SET status = 'accepted', updated_at = decision.decided_at, \
             accepted_at = decision.decided_at \
         FROM decision \
         WHERE invitation.organization_id = $1 AND invitation.id = $2 \
           AND invitation.invited_user_id = $3 AND invitation.status = 'pending' \
           AND invitation.expires_at > decision.decided_at \
         RETURNING invitation.accepted_at",
    )
    .bind(organization_id.as_uuid())
    .bind(invitation_id.as_uuid())
    .bind(invited_user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?;
    if accepted_at.is_some() {
        return Ok(accepted_at);
    }

    let expired_at = sqlx::query_scalar::<_, OffsetDateTime>(
        "WITH decision AS (SELECT clock_timestamp() AS decided_at) \
         UPDATE invitations AS invitation \
         SET status = 'expired', updated_at = decision.decided_at \
         FROM decision \
         WHERE invitation.organization_id = $1 AND invitation.id = $2 \
           AND invitation.invited_user_id = $3 AND invitation.status = 'pending' \
           AND invitation.expires_at <= decision.decided_at \
         RETURNING invitation.updated_at",
    )
    .bind(organization_id.as_uuid())
    .bind(invitation_id.as_uuid())
    .bind(invited_user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?
    .ok_or(TenancyStoreError::InvitationUnavailable)?;
    bump_organization(tx, organization_id, expired_at).await?;
    Ok(None)
}

async fn lock_actor(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    actor_user_id: SubjectId,
    require_active_organization: bool,
) -> Result<(Organization, MembershipRole), TenancyStoreError> {
    let query = if require_active_organization {
        "SELECT o.id, o.name, o.status AS organization_status, o.version, o.created_at, \
                o.updated_at, o.deleted_at, m.role AS actor_role \
         FROM organizations o \
         JOIN memberships m ON m.organization_id = o.id \
         WHERE o.id = $1 AND m.organization_id = $1 AND m.user_id = $2 \
           AND o.status = 'active' AND m.status = 'active' \
         FOR UPDATE OF o, m"
    } else {
        "SELECT o.id, o.name, o.status AS organization_status, o.version, o.created_at, \
                o.updated_at, o.deleted_at, m.role AS actor_role \
         FROM organizations o \
         JOIN memberships m ON m.organization_id = o.id \
         WHERE o.id = $1 AND m.organization_id = $1 AND m.user_id = $2 \
           AND o.status <> 'deleted' AND m.status = 'active' \
         FOR UPDATE OF o, m"
    };
    let row = sqlx::query(query)
        .bind(organization_id.as_uuid())
        .bind(actor_user_id.as_uuid())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| map_db(&error))?
        .ok_or(TenancyStoreError::AccessDenied)?;
    let role_value: String = row
        .try_get("actor_role")
        .map_err(|_| TenancyStoreError::CorruptData)?;
    let role = MembershipRole::from_str(&role_value).map_err(|_| TenancyStoreError::CorruptData)?;
    Ok((organization_from_row(&row)?, role))
}

async fn lock_membership(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    user_id: SubjectId,
) -> Result<Option<PgRow>, TenancyStoreError> {
    sqlx::query(
        "SELECT organization_id, user_id, role AS membership_role, \
                status AS membership_status, grant_version, created_at, updated_at \
         FROM memberships \
         WHERE organization_id = $1 AND user_id = $2 \
         FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .bind(user_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))
}

async fn lock_invitation(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    invitation_id: InvitationId,
) -> Result<Option<PgRow>, TenancyStoreError> {
    sqlx::query(
        "SELECT id, organization_id, invited_user_id, invited_by_user_id, \
                role AS invitation_role, status AS invitation_status, expires_at, created_at, \
                updated_at, accepted_at, revoked_at \
         FROM invitations \
         WHERE organization_id = $1 AND id = $2 \
         FOR UPDATE",
    )
    .bind(organization_id.as_uuid())
    .bind(invitation_id.as_uuid())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))
}

async fn bump_organization(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: TenantId,
    updated_at: OffsetDateTime,
) -> Result<i64, TenancyStoreError> {
    let row = sqlx::query(
        "UPDATE organizations SET version = version + 1, updated_at = $2 \
         WHERE id = $1 \
         RETURNING version",
    )
    .bind(organization_id.as_uuid())
    .bind(updated_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| map_db(&error))?
    .ok_or(TenancyStoreError::AccessDenied)?;
    positive_version(&row, "version")
}

fn require_owner(role: MembershipRole) -> Result<(), TenancyStoreError> {
    if role == MembershipRole::Owner {
        Ok(())
    } else {
        Err(TenancyStoreError::AccessDenied)
    }
}

fn require_administrator(role: MembershipRole) -> Result<(), TenancyStoreError> {
    if matches!(role, MembershipRole::Owner | MembershipRole::Admin) {
        Ok(())
    } else {
        Err(TenancyStoreError::AccessDenied)
    }
}

fn authorization_role(role: MembershipRole) -> Result<Role, TenancyStoreError> {
    let value = match role {
        MembershipRole::Owner => "organization:owner",
        MembershipRole::Admin => "organization:admin",
        MembershipRole::Member => "organization:member",
    };
    Role::new(value).map_err(|_| TenancyStoreError::CorruptData)
}

fn organization_from_row(row: &PgRow) -> Result<Organization, TenancyStoreError> {
    let id = tenant_id(
        row.try_get("id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let name = OrganizationName::new(
        row.try_get::<String, _>("name")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let status = OrganizationStatus::from_str(
        &row.try_get::<String, _>("organization_status")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let version = positive_version(row, "version")?;
    let created_at = timestamp(row, "created_at")?;
    let updated_at = timestamp(row, "updated_at")?;
    let deleted_at = optional_timestamp(row, "deleted_at")?;
    if created_at > updated_at
        || (status == OrganizationStatus::Deleted) != deleted_at.is_some()
        || deleted_at.is_some_and(|value| value < created_at || value > updated_at)
    {
        return Err(TenancyStoreError::CorruptData);
    }
    Ok(Organization {
        id,
        name,
        status,
        version,
        created_at,
        updated_at,
        deleted_at,
    })
}

fn membership_from_row(row: &PgRow) -> Result<Membership, TenancyStoreError> {
    let organization_id = tenant_id(
        row.try_get("organization_id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let user_id = subject_id(
        row.try_get("user_id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let role = MembershipRole::from_str(
        &row.try_get::<String, _>("membership_role")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let status = MembershipStatus::from_str(
        &row.try_get::<String, _>("membership_status")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let grant_version = positive_version(row, "grant_version")?;
    let created_at = timestamp(row, "created_at")?;
    let updated_at = timestamp(row, "updated_at")?;
    if created_at > updated_at {
        return Err(TenancyStoreError::CorruptData);
    }
    Ok(Membership {
        organization_id,
        user_id,
        role,
        status,
        grant_version,
        created_at,
        updated_at,
    })
}

fn invitation_from_row(row: &PgRow) -> Result<Invitation, TenancyStoreError> {
    let id = InvitationId::from_uuid(
        row.try_get("id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let organization_id = tenant_id(
        row.try_get("organization_id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let invited_user_id = subject_id(
        row.try_get("invited_user_id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let invited_by_user_id = subject_id(
        row.try_get("invited_by_user_id")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )?;
    let role = InvitationRole::from_str(
        &row.try_get::<String, _>("invitation_role")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let status = InvitationStatus::from_str(
        &row.try_get::<String, _>("invitation_status")
            .map_err(|_| TenancyStoreError::CorruptData)?,
    )
    .map_err(|_| TenancyStoreError::CorruptData)?;
    let expires_at = timestamp(row, "expires_at")?;
    let created_at = timestamp(row, "created_at")?;
    let updated_at = timestamp(row, "updated_at")?;
    let accepted_at = optional_timestamp(row, "accepted_at")?;
    let revoked_at = optional_timestamp(row, "revoked_at")?;
    let terminal_consistent = match status {
        InvitationStatus::Pending | InvitationStatus::Expired => {
            accepted_at.is_none() && revoked_at.is_none()
        }
        InvitationStatus::Accepted => accepted_at.is_some() && revoked_at.is_none(),
        InvitationStatus::Revoked => accepted_at.is_none() && revoked_at.is_some(),
    };
    if !terminal_consistent
        || expires_at <= created_at
        || created_at > updated_at
        || accepted_at
            .is_some_and(|value| value < created_at || value > updated_at || value > expires_at)
        || revoked_at.is_some_and(|value| value < created_at || value > updated_at)
    {
        return Err(TenancyStoreError::CorruptData);
    }
    Ok(Invitation {
        id,
        organization_id,
        invited_user_id,
        invited_by_user_id,
        role,
        status,
        expires_at,
        created_at,
        updated_at,
        accepted_at,
        revoked_at,
    })
}

fn tenant_id(value: Uuid) -> Result<TenantId, TenancyStoreError> {
    TenantId::from_uuid(value).map_err(|_| TenancyStoreError::CorruptData)
}

fn subject_id(value: Uuid) -> Result<SubjectId, TenancyStoreError> {
    SubjectId::from_uuid(value).map_err(|_| TenancyStoreError::CorruptData)
}

fn positive_version(row: &PgRow, column: &str) -> Result<i64, TenancyStoreError> {
    let version = row
        .try_get(column)
        .map_err(|_| TenancyStoreError::CorruptData)?;
    if version < 1 {
        Err(TenancyStoreError::CorruptData)
    } else {
        Ok(version)
    }
}

fn timestamp(row: &PgRow, column: &str) -> Result<OffsetDateTime, TenancyStoreError> {
    row.try_get::<OffsetDateTime, _>(column)
        .map(utc)
        .map_err(|_| TenancyStoreError::CorruptData)
}

fn optional_timestamp(
    row: &PgRow,
    column: &str,
) -> Result<Option<OffsetDateTime>, TenancyStoreError> {
    row.try_get::<Option<OffsetDateTime>, _>(column)
        .map(|value| value.map(utc))
        .map_err(|_| TenancyStoreError::CorruptData)
}

async fn finish<T>(
    tx: Transaction<'_, Postgres>,
    result: Result<T, TenancyStoreError>,
) -> Result<T, TenancyStoreError> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(|error| map_db(&error))?;
            Ok(value)
        }
        Err(operation_error) => {
            tx.rollback().await.map_err(|error| map_db(&error))?;
            Err(operation_error)
        }
    }
}

/// Stable, value-free tenancy lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TenancyStoreError {
    /// Tenancy is disabled by runtime configuration.
    #[error("tenancy is disabled")]
    Disabled,
    /// Tenancy configuration is invalid.
    #[error("tenancy configuration is invalid")]
    InvalidConfiguration,
    /// PostgreSQL tenancy persistence is unavailable.
    #[error("tenancy persistence is unavailable")]
    Unavailable,
    /// A safe-to-retry serialization or deadlock conflict occurred.
    #[error("tenancy transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// Persisted constraints conflict with the requested state.
    #[error("tenancy state conflicts with persisted state")]
    Conflict,
    /// A referenced user does not exist.
    #[error("tenancy user was not found")]
    UserNotFound,
    /// Access is denied without disclosing organization existence.
    #[error("tenant access is denied")]
    AccessDenied,
    /// The principal is already bound to a different tenant.
    #[error("principal tenant does not match the requested tenant")]
    TenantMismatch,
    /// An organization-scoped membership was not found.
    #[error("organization membership was not found")]
    MembershipNotFound,
    /// The requested membership transition is not valid.
    #[error("organization membership transition is invalid")]
    InvalidMembershipTransition,
    /// The target user already has an active membership.
    #[error("organization membership is already active")]
    MembershipAlreadyActive,
    /// The mutation would leave an active organization without an active owner.
    #[error("active organization must retain an active owner")]
    LastOwner,
    /// Invitation expiry is not after creation.
    #[error("organization invitation expiry is invalid")]
    InvalidInvitationExpiry,
    /// A pending invitation already exists for the organization and user.
    #[error("a pending organization invitation already exists")]
    InvitationAlreadyPending,
    /// The invitation cannot be used without disclosing why it is unavailable.
    #[error("organization invitation is unavailable")]
    InvitationUnavailable,
    /// The invitation has expired.
    #[error("organization invitation has expired")]
    InvitationExpired,
    /// A bounded list contains more rows than configured.
    #[error("tenancy list exceeds its configured result limit")]
    ListLimitExceeded,
    /// Persisted tenancy state violates an application invariant.
    #[error("tenancy persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for TenancyStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

impl TenancyStoreError {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::InvalidConfiguration => "invalid_configuration",
            Self::Unavailable => "unavailable",
            Self::Transient(_) => "transient",
            Self::Conflict => "conflict",
            Self::UserNotFound => "user_not_found",
            Self::AccessDenied => "access_denied",
            Self::TenantMismatch => "tenant_mismatch",
            Self::MembershipNotFound => "membership_not_found",
            Self::InvalidMembershipTransition => "invalid_membership_transition",
            Self::MembershipAlreadyActive => "membership_already_active",
            Self::LastOwner => "last_owner",
            Self::InvalidInvitationExpiry => "invalid_invitation_expiry",
            Self::InvitationAlreadyPending => "invitation_already_pending",
            Self::InvitationUnavailable => "invitation_unavailable",
            Self::InvitationExpired => "invitation_expired",
            Self::ListLimitExceeded => "list_limit_exceeded",
            Self::CorruptData => "corrupt_data",
        }
    }
}

fn map_invitation_insert(error: &sqlx::Error) -> TenancyStoreError {
    if constraint(error) == Some("invitations_pending_organization_invited_user_key") {
        TenancyStoreError::InvitationAlreadyPending
    } else {
        map_db(error)
    }
}

fn map_db(error: &sqlx::Error) -> TenancyStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return TenancyStoreError::Transient(state);
    }
    if constraint(error) == Some("organizations_active_owner_required") {
        return TenancyStoreError::LastOwner;
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23502" | "23503" | "23505" | "23514") => {
            TenancyStoreError::Conflict
        }
        _ => TenancyStoreError::Unavailable,
    }
}

fn constraint(error: &sqlx::Error) -> Option<&str> {
    error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint)
}

fn result_label<T>(result: &Result<T, TenancyStoreError>, success: &'static str) -> &'static str {
    match result {
        Ok(_) => success,
        Err(error) => (*error).metric_label(),
    }
}

fn record(operation: &'static str, result: &'static str, elapsed: std::time::Duration) {
    metrics::counter!(
        "omnius_tenancy_operations_total",
        "operation" => operation,
        "result" => result,
    )
    .increment(1);
    metrics::histogram!(
        "omnius_tenancy_operation_duration_seconds",
        "operation" => operation,
    )
    .record(elapsed.as_secs_f64());
}
