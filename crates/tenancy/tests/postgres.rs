//! PostgreSQL proof for explicit tenant isolation and organization lifecycle invariants.

use std::{error::Error, time::Duration};

use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_tenancy::{
    InvitationRole, InvitationStatus, MembershipRole, MembershipStatus, OrganizationName,
    OrganizationNameError, OrganizationStatus, TenancyConfig, TenancyStore, TenancyStoreError,
};
use rsk_test_support::PostgresFixture;
use sqlx::Connection as _;
use time::{Duration as TimeDuration, OffsetDateTime};

const FIRST_MIGRATION: i64 = 2_026_082_301;
const TENANCY_HEAD: i64 = 2_026_082_314;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-tenancy-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

const fn migration_config() -> MigrationConfig {
    MigrationConfig {
        run_on_startup: false,
        operation_timeout: Duration::from_secs(10),
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, TENANCY_HEAD)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

async fn seed_users(pool: &PostgresPool, count: usize) -> Result<Vec<SubjectId>, Box<dyn Error>> {
    let mut users = Vec::with_capacity(count);
    let mut connection = pool.acquire().await?;
    for _ in 0..count {
        let user = SubjectId::new();
        sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
            .bind(user.as_uuid())
            .bind(OffsetDateTime::now_utc())
            .execute(&mut *connection)
            .await?;
        users.push(user);
    }
    Ok(users)
}

fn principal(
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        subject_id,
        PrincipalKind::User,
        tenant_id,
        AuthMethod::Session,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn store_error<T>(
    result: &Result<T, TenancyStoreError>,
) -> Result<TenancyStoreError, Box<dyn Error>> {
    match result {
        Ok(_) => Err("tenancy operation unexpectedly succeeded".into()),
        Err(error) => Ok(*error),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves isolation, canonical binding, lifecycle denial, and input bounds"
)]
#[tokio::test]
async fn organizations_are_isolated_and_tenant_context_is_authoritative()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let users = seed_users(&database.pool, 2).await?;
    let user_a = users[0];
    let user_b = users[1];
    let store = TenancyStore::new(database.pool.clone(), &TenancyConfig::default())?;

    let created_a = store
        .create_organization(user_a, OrganizationName::new("Organization A")?)
        .await?;
    let second_a = store
        .create_organization(user_a, OrganizationName::new("Organization A2")?)
        .await?;
    let created_b = store
        .create_organization(user_b, OrganizationName::new("Organization B")?)
        .await?;
    assert_eq!(created_a.organization.version, 1);
    assert_eq!(created_a.owner_membership.role, MembershipRole::Owner);
    assert_eq!(created_a.owner_membership.grant_version, 1);

    assert_eq!(
        store_error(
            &store
                .get_organization(created_a.organization.id, user_b)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    let organizations_b = store.list_organizations(user_b).await?;
    assert_eq!(
        organizations_b
            .iter()
            .map(|organization| organization.id)
            .collect::<Vec<_>>(),
        vec![created_b.organization.id]
    );
    assert!(
        !organizations_b
            .iter()
            .any(|organization| organization.id == created_a.organization.id)
    );

    let tenantless_a = principal(user_a, None)?;
    let context = store
        .resolve_tenant_context(&tenantless_a, created_a.organization.id)
        .await?;
    assert_eq!(
        context.principal().tenant_id,
        Some(created_a.organization.id)
    );
    assert_eq!(tenantless_a.tenant_id, None);
    assert_eq!(
        context
            .authorization_context()
            .roles()
            .iter()
            .map(rsk_authz_basic::Role::as_str)
            .collect::<Vec<_>>(),
        vec!["organization:owner"]
    );
    assert_eq!(
        context.authorization_context().tenant_memberships(),
        &[created_a.organization.id]
    );
    assert_eq!(context.membership(), &created_a.owner_membership);
    assert_eq!(
        store_error(
            &store
                .resolve_tenant_context(&tenantless_a, created_b.organization.id)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    let bound_elsewhere = principal(user_a, Some(second_a.organization.id))?;
    assert_eq!(
        store_error(
            &store
                .resolve_tenant_context(&bound_elsewhere, created_a.organization.id)
                .await
        )?,
        TenancyStoreError::TenantMismatch
    );

    let suspended = store
        .set_organization_status(
            created_a.organization.id,
            user_a,
            OrganizationStatus::Suspended,
        )
        .await?;
    assert_eq!(suspended.status, OrganizationStatus::Suspended);
    assert_eq!(suspended.version, 2);
    assert_eq!(
        store_error(
            &store
                .resolve_tenant_context(&tenantless_a, created_a.organization.id)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    assert_eq!(
        store_error(
            &store
                .get_organization(created_a.organization.id, user_a)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    assert!(
        !store
            .list_organizations(user_a)
            .await?
            .iter()
            .any(|organization| organization.id == created_a.organization.id)
    );

    let active = store
        .set_organization_status(
            created_a.organization.id,
            user_a,
            OrganizationStatus::Active,
        )
        .await?;
    assert_eq!(active.version, 3);
    let deleted = store
        .set_organization_status(
            created_a.organization.id,
            user_a,
            OrganizationStatus::Deleted,
        )
        .await?;
    assert_eq!(deleted.status, OrganizationStatus::Deleted);
    assert!(deleted.deleted_at.is_some());
    assert_eq!(
        store_error(
            &store
                .resolve_tenant_context(&tenantless_a, created_a.organization.id)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    let third_a = store
        .create_organization(user_a, OrganizationName::new("Organization A3")?)
        .await?;
    assert_ne!(third_a.organization.id, second_a.organization.id);

    assert_eq!(
        OrganizationName::new("   "),
        Err(OrganizationNameError::Blank)
    );
    assert_eq!(
        OrganizationName::new(" trailing "),
        Err(OrganizationNameError::NotTrimmed)
    );
    assert_eq!(
        OrganizationName::new("n".repeat(256)),
        Err(OrganizationNameError::TooLong)
    );
    assert_eq!(
        OrganizationName::new("line\nbreak"),
        Err(OrganizationNameError::ControlCharacter)
    );
    let invalid_config = TenancyConfig {
        enabled: true,
        max_list_items: 0,
    };
    assert_eq!(
        store_error(&TenancyStore::new(database.pool.clone(), &invalid_config))?,
        TenancyStoreError::InvalidConfiguration
    );
    let disabled_config = TenancyConfig {
        enabled: false,
        ..TenancyConfig::default()
    };
    assert_eq!(
        store_error(&TenancyStore::new(database.pool.clone(), &disabled_config))?,
        TenancyStoreError::Disabled
    );
    let limited_store = TenancyStore::new(
        database.pool.clone(),
        &TenancyConfig {
            enabled: true,
            max_list_items: 1,
        },
    )?;
    assert_eq!(
        store_error(&limited_store.list_organizations(user_a).await)?,
        TenancyStoreError::ListLimitExceeded
    );

    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves the invitation state machine and grant-version transitions"
)]
#[tokio::test]
async fn invitations_are_user_bound_expirable_revocable_and_versioned() -> Result<(), Box<dyn Error>>
{
    let database = test_database().await?;
    let users = seed_users(&database.pool, 4).await?;
    let owner = users[0];
    let invitee = users[1];
    let revoked_user = users[2];
    let expired_user = users[3];
    let store = TenancyStore::new(database.pool.clone(), &TenancyConfig::default())?;
    let created = store
        .create_organization(owner, OrganizationName::new("Invitation lifecycle")?)
        .await?;
    let organization_id = created.organization.id;

    let invitation = store
        .create_invitation(
            organization_id,
            owner,
            invitee,
            InvitationRole::Member,
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )
        .await?;
    assert_eq!(invitation.status, InvitationStatus::Pending);
    assert_eq!(invitation.role, InvitationRole::Member);
    assert_eq!(
        store.list_invitations(organization_id, owner).await?,
        vec![invitation.clone()]
    );
    assert_eq!(
        store_error(
            &store
                .accept_invitation(
                    organization_id,
                    invitation.id,
                    &principal(revoked_user, None)?
                )
                .await
        )?,
        TenancyStoreError::InvitationUnavailable
    );
    let membership = store
        .accept_invitation(organization_id, invitation.id, &principal(invitee, None)?)
        .await?;
    assert_eq!(
        (membership.role, membership.status, membership.grant_version),
        (MembershipRole::Member, MembershipStatus::Active, 1)
    );
    assert_eq!(
        store_error(
            &store
                .accept_invitation(organization_id, invitation.id, &principal(invitee, None)?)
                .await
        )?,
        TenancyStoreError::InvitationUnavailable
    );

    let admin = store
        .update_membership(
            organization_id,
            owner,
            invitee,
            MembershipRole::Admin,
            MembershipStatus::Active,
        )
        .await?;
    assert_eq!(admin.grant_version, 2);
    let suspended = store
        .update_membership(
            organization_id,
            owner,
            invitee,
            MembershipRole::Admin,
            MembershipStatus::Suspended,
        )
        .await?;
    assert_eq!(suspended.grant_version, 3);
    assert_eq!(
        store_error(
            &store
                .resolve_tenant_context(&principal(invitee, None)?, organization_id)
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    let reactivated = store
        .update_membership(
            organization_id,
            owner,
            invitee,
            MembershipRole::Member,
            MembershipStatus::Active,
        )
        .await?;
    assert_eq!(reactivated.grant_version, 4);
    let invitee_context = store
        .resolve_tenant_context(&principal(invitee, None)?, organization_id)
        .await?;
    assert_eq!(
        invitee_context.authorization_context().roles()[0].as_str(),
        "organization:member"
    );

    let revoked = store
        .create_invitation(
            organization_id,
            owner,
            revoked_user,
            InvitationRole::Admin,
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )
        .await?;
    let revoked = store
        .revoke_invitation(organization_id, owner, revoked.id)
        .await?;
    assert_eq!(revoked.status, InvitationStatus::Revoked);
    assert!(revoked.revoked_at.is_some());
    assert_eq!(
        store_error(
            &store
                .accept_invitation(organization_id, revoked.id, &principal(revoked_user, None)?)
                .await
        )?,
        TenancyStoreError::InvitationUnavailable
    );

    let expiring = store
        .create_invitation(
            organization_id,
            owner,
            expired_user,
            InvitationRole::Member,
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )
        .await?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE invitations SET expires_at = created_at + INTERVAL '1 microsecond' \
         WHERE organization_id = $1 AND id = $2",
    )
    .bind(organization_id.as_uuid())
    .bind(expiring.id.as_uuid())
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let replacement_invitation = store
        .create_invitation(
            organization_id,
            owner,
            expired_user,
            InvitationRole::Member,
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )
        .await?;
    assert_ne!(replacement_invitation.id, expiring.id);
    assert_eq!(
        store_error(
            &store
                .accept_invitation(
                    organization_id,
                    expiring.id,
                    &principal(expired_user, None)?
                )
                .await
        )?,
        TenancyStoreError::InvitationExpired
    );
    let invitations = store.list_invitations(organization_id, owner).await?;
    assert!(invitations.iter().any(|candidate| {
        candidate.id == expiring.id && candidate.status == InvitationStatus::Expired
    }));
    assert!(invitations.iter().any(|candidate| {
        candidate.id == replacement_invitation.id && candidate.status == InvitationStatus::Pending
    }));

    let other = store
        .create_organization(revoked_user, OrganizationName::new("Other tenant")?)
        .await?;
    assert_eq!(
        store_error(
            &store
                .revoke_invitation(other.organization.id, revoked_user, expiring.id)
                .await
        )?,
        TenancyStoreError::InvitationUnavailable
    );

    Ok(())
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one fixture proves the ownership transfer and commit-time invariant"
)]
async fn ownership_transfer_is_atomic_and_last_owner_is_protected_at_commit()
-> Result<(), Box<dyn Error>> {
    let database = test_database().await?;
    let users = seed_users(&database.pool, 2).await?;
    let original_owner = users[0];
    let successor = users[1];
    let store = TenancyStore::new(database.pool.clone(), &TenancyConfig::default())?;
    let created = store
        .create_organization(original_owner, OrganizationName::new("Ownership")?)
        .await?;
    let organization_id = created.organization.id;

    assert_eq!(
        store_error(
            &store
                .update_membership(
                    organization_id,
                    original_owner,
                    original_owner,
                    MembershipRole::Member,
                    MembershipStatus::Active,
                )
                .await
        )?,
        TenancyStoreError::LastOwner
    );
    let invitation = store
        .create_invitation(
            organization_id,
            original_owner,
            successor,
            InvitationRole::Member,
            OffsetDateTime::now_utc() + TimeDuration::hours(1),
        )
        .await?;
    store
        .accept_invitation(organization_id, invitation.id, &principal(successor, None)?)
        .await?;

    let transfer = store
        .transfer_ownership(organization_id, original_owner, successor)
        .await?;
    assert_eq!(
        (
            transfer.previous_owner.role,
            transfer.previous_owner.grant_version,
            transfer.new_owner.role,
            transfer.new_owner.grant_version,
        ),
        (MembershipRole::Admin, 2, MembershipRole::Owner, 2,)
    );
    assert_eq!(transfer.organization_version, 4);
    assert_eq!(
        store_error(
            &store
                .update_membership(
                    organization_id,
                    original_owner,
                    successor,
                    MembershipRole::Member,
                    MembershipStatus::Active,
                )
                .await
        )?,
        TenancyStoreError::AccessDenied
    );
    assert_eq!(
        store_error(
            &store
                .update_membership(
                    organization_id,
                    successor,
                    successor,
                    MembershipRole::Admin,
                    MembershipStatus::Active,
                )
                .await
        )?,
        TenancyStoreError::LastOwner
    );

    let mut connection = database.pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query(
        "UPDATE memberships SET role = 'member', grant_version = grant_version + 1, \
         updated_at = $3 WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id.as_uuid())
    .bind(successor.as_uuid())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *transaction)
    .await?;
    let commit_error = transaction
        .commit()
        .await
        .err()
        .ok_or("direct SQL sole-owner demotion unexpectedly committed")?;
    let constraint = commit_error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::constraint);
    assert_eq!(constraint, Some("organizations_active_owner_required"));

    let memberships = store.list_memberships(organization_id, successor).await?;
    let persisted_owner = memberships
        .iter()
        .find(|membership| membership.user_id == successor)
        .ok_or("successor membership must remain after rejected transaction")?;
    assert_eq!(
        (persisted_owner.role, persisted_owner.grant_version),
        (MembershipRole::Owner, 2)
    );

    Ok(())
}
