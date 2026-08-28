//! Organizations, memberships, invitations, and tenant ownership schema contract.

use std::{error::Error, fs, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{CleanDirectory, PostgresFixture, TestIds};
use sqlx::{migrate::Migrator, postgres::PgQueryResult};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const CREATED_AT: &str = "2026-08-23 12:00:00+00";
const UPDATED_AT: &str = "2026-08-23 12:01:00+00";
const EXPIRES_AT: &str = "2026-08-24 12:00:00+00";

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-tenancy-schema-test".to_owned(),
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

fn assert_database_constraint(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_code: &str,
    expected_constraint: &str,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err(format!("constraint {expected_constraint} accepted an invalid row").into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("constraint {expected_constraint} returned {error}").into());
    };

    assert_eq!(database_error.code().as_deref(), Some(expected_code));
    assert_eq!(database_error.constraint(), Some(expected_constraint));
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one isolated fixture keeps the complete tenancy schema contract and cleanup visible"
)]
async fn exercise_tenancy_schema(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let head = runner.run().await?;
    assert_eq!(
        head.current_version,
        Some(omnius_migrations::CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(
        head.target_version,
        omnius_migrations::CURRENT_SCHEMA_VERSION
    );
    assert!(head.pending_versions.is_empty());

    let mut connection = pool.acquire().await?;
    let tenancy_tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() \
         AND table_name IN ('organizations', 'memberships', 'invitations') \
         ORDER BY table_name",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        tenancy_tables,
        ["invitations", "memberships", "organizations"]
    );

    let organization_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
         AND table_name = 'organizations' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        organization_columns,
        [
            "id:uuid:NO",
            "name:text:NO",
            "status:text:NO",
            "version:bigint:NO",
            "owner_guard_version:bigint:NO",
            "created_at:timestamp with time zone:NO",
            "updated_at:timestamp with time zone:NO",
            "deleted_at:timestamp with time zone:YES",
        ]
    );

    let membership_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
         AND table_name = 'memberships' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        membership_columns,
        [
            "organization_id:uuid:NO",
            "user_id:uuid:NO",
            "role:text:NO",
            "status:text:NO",
            "grant_version:bigint:NO",
            "created_at:timestamp with time zone:NO",
            "updated_at:timestamp with time zone:NO",
        ]
    );

    let invitation_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
         AND table_name = 'invitations' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        invitation_columns,
        [
            "id:uuid:NO",
            "organization_id:uuid:NO",
            "invited_user_id:uuid:NO",
            "invited_by_user_id:uuid:NO",
            "role:text:NO",
            "status:text:NO",
            "expires_at:timestamp with time zone:NO",
            "created_at:timestamp with time zone:NO",
            "updated_at:timestamp with time zone:NO",
            "accepted_at:timestamp with time zone:YES",
            "revoked_at:timestamp with time zone:YES",
        ]
    );

    let organization_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'organizations'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        organization_constraints,
        [
            "organizations_active_owner_check:t",
            "organizations_deleted_state:c",
            "organizations_id_uuid_v7:c",
            "organizations_name_length:c",
            "organizations_name_nonblank:c",
            "organizations_name_trimmed:c",
            "organizations_owner_guard_version_nonnegative:c",
            "organizations_pkey:p",
            "organizations_status_check:c",
            "organizations_updated_order:c",
            "organizations_version_positive:c",
        ]
    );

    let membership_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'memberships'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        membership_constraints,
        [
            "memberships_active_owner_check:t",
            "memberships_grant_version_positive:c",
            "memberships_organization_id_fkey:f",
            "memberships_pkey:p",
            "memberships_role_check:c",
            "memberships_status_check:c",
            "memberships_updated_order:c",
            "memberships_user_id_fkey:f",
        ]
    );

    let invitation_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'invitations'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        invitation_constraints,
        [
            "invitations_expiry_order:c",
            "invitations_id_uuid_v7:c",
            "invitations_invited_by_user_id_fkey:f",
            "invitations_invited_user_id_fkey:f",
            "invitations_organization_id_fkey:f",
            "invitations_pkey:p",
            "invitations_role_check:c",
            "invitations_status_check:c",
            "invitations_terminal_state:c",
            "invitations_updated_order:c",
        ]
    );

    let membership_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() \
         AND tablename = 'memberships' ORDER BY indexname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        membership_indexes,
        [
            "memberships_organization_status_idx",
            "memberships_pkey",
            "memberships_user_status_idx",
        ]
    );

    let invitation_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() \
         AND tablename = 'invitations' ORDER BY indexname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        invitation_indexes,
        [
            "invitations_invited_user_status_idx",
            "invitations_organization_status_idx",
            "invitations_pending_organization_invited_user_key",
            "invitations_pkey",
        ]
    );

    let organization_membership_index: (bool, i32, String, String, String, String) =
        sqlx::query_as(
            "SELECT i.indisunique, i.indnkeyatts::integer, \
             pg_get_indexdef(i.indexrelid, 1, TRUE), \
             pg_get_indexdef(i.indexrelid, 2, TRUE), \
             pg_get_indexdef(i.indexrelid, 3, TRUE), \
             pg_get_indexdef(i.indexrelid, 4, TRUE) \
             FROM pg_index AS i \
             JOIN pg_class AS index_relation ON index_relation.oid = i.indexrelid \
             WHERE i.indrelid = 'memberships'::regclass \
             AND index_relation.relname = 'memberships_organization_status_idx'",
        )
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(
        organization_membership_index,
        (
            false,
            4,
            "organization_id".to_owned(),
            "status".to_owned(),
            "role".to_owned(),
            "user_id".to_owned(),
        )
    );

    let user_membership_index: (bool, i32, String, String, String) = sqlx::query_as(
        "SELECT i.indisunique, i.indnkeyatts::integer, \
         pg_get_indexdef(i.indexrelid, 1, TRUE), \
         pg_get_indexdef(i.indexrelid, 2, TRUE), \
         pg_get_indexdef(i.indexrelid, 3, TRUE) \
         FROM pg_index AS i \
         JOIN pg_class AS index_relation ON index_relation.oid = i.indexrelid \
         WHERE i.indrelid = 'memberships'::regclass \
         AND index_relation.relname = 'memberships_user_status_idx'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        user_membership_index,
        (
            false,
            3,
            "user_id".to_owned(),
            "status".to_owned(),
            "organization_id".to_owned(),
        )
    );

    let organization_invitation_index: (bool, i32, String, String) = sqlx::query_as(
        "SELECT i.indisunique, i.indnkeyatts::integer, \
         pg_get_indexdef(i.indexrelid, 1, TRUE), \
         pg_get_indexdef(i.indexrelid, 2, TRUE) \
         FROM pg_index AS i \
         JOIN pg_class AS index_relation ON index_relation.oid = i.indexrelid \
         WHERE i.indrelid = 'invitations'::regclass \
         AND index_relation.relname = 'invitations_organization_status_idx'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        organization_invitation_index,
        (false, 4, "organization_id".to_owned(), "status".to_owned(),)
    );

    let invited_user_invitation_index: (bool, i32, String, String) = sqlx::query_as(
        "SELECT i.indisunique, i.indnkeyatts::integer, \
         pg_get_indexdef(i.indexrelid, 1, TRUE), \
         pg_get_indexdef(i.indexrelid, 2, TRUE) \
         FROM pg_index AS i \
         JOIN pg_class AS index_relation ON index_relation.oid = i.indexrelid \
         WHERE i.indrelid = 'invitations'::regclass \
         AND index_relation.relname = 'invitations_invited_user_status_idx'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        invited_user_invitation_index,
        (false, 4, "invited_user_id".to_owned(), "status".to_owned(),)
    );

    let owner_triggers: Vec<String> = sqlx::query_scalar(
        "SELECT tgname || ':' || tgdeferrable::text || ':' || tginitdeferred::text \
         FROM pg_trigger WHERE NOT tgisinternal \
         AND tgrelid IN ('organizations'::regclass, 'memberships'::regclass) \
         ORDER BY tgname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        owner_triggers,
        [
            "memberships_active_owner_check:true:true",
            "organizations_active_owner_check:true:true",
        ]
    );

    let service_account_tenant_fk: String = sqlx::query_scalar(
        "SELECT conname || ':' || confdeltype::text FROM pg_constraint \
         WHERE conrelid = 'service_accounts'::regclass \
         AND conname = 'service_accounts_tenant_id_fkey'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        service_account_tenant_fk,
        "service_accounts_tenant_id_fkey:r"
    );

    let ids = TestIds::default();
    let owner_id = ids.uuid_v7()?;
    let successor_id = ids.uuid_v7()?;
    let invitee_id = ids.uuid_v7()?;
    for user_id in [owner_id, successor_id, invitee_id] {
        sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2::timestamptz)")
            .bind(user_id)
            .bind(CREATED_AT)
            .execute(&mut *connection)
            .await?;
    }

    let organization_id = ids.uuid_v7()?;
    sqlx::query("BEGIN").execute(&mut *connection).await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Canonical Organization', 'active', 1, \
         $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(organization_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(owner_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await?;
    sqlx::query("COMMIT").execute(&mut *connection).await?;

    let invalid_organization_uuid = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Invalid UUID', 'active', 1, $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(Uuid::nil())
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_organization_uuid,
        "23514",
        "organizations_id_uuid_v7",
    )?;

    let blank_organization_name = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, '', 'active', 1, $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        blank_organization_name,
        "23514",
        "organizations_name_nonblank",
    )?;

    let oversized_name = "x".repeat(256);
    let oversized_organization_name = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, $2, 'active', 1, $3::timestamptz, $4::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(oversized_name)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        oversized_organization_name,
        "23514",
        "organizations_name_length",
    )?;

    let invalid_organization_status = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Invalid Status', 'archived', 1, \
         $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_organization_status,
        "23514",
        "organizations_status_check",
    )?;

    let invalid_organization_version = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Invalid Version', 'active', 0, \
         $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_organization_version,
        "23514",
        "organizations_version_positive",
    )?;

    let inconsistent_deleted_organization = sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Invalid Deleted State', 'deleted', 1, \
         $2::timestamptz, $3::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        inconsistent_deleted_organization,
        "23514",
        "organizations_deleted_state",
    )?;

    let missing_organization_membership = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(ids.uuid_v7()?)
    .bind(invitee_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        missing_organization_membership,
        "23503",
        "memberships_organization_id_fkey",
    )?;

    let missing_user_membership = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(ids.uuid_v7()?)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(missing_user_membership, "23503", "memberships_user_id_fkey")?;

    let invalid_membership_role = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'operator', 'active', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(successor_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_membership_role, "23514", "memberships_role_check")?;

    let invalid_membership_status = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'revoked', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(successor_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_membership_status,
        "23514",
        "memberships_status_check",
    )?;

    let invalid_grant_version = sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 0, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(successor_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_grant_version,
        "23514",
        "memberships_grant_version_positive",
    )?;

    let missing_invitation_organization = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(ids.uuid_v7()?)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        missing_invitation_organization,
        "23503",
        "invitations_organization_id_fkey",
    )?;

    let missing_invited_user = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(ids.uuid_v7()?)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        missing_invited_user,
        "23503",
        "invitations_invited_user_id_fkey",
    )?;

    let missing_inviter = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(ids.uuid_v7()?)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        missing_inviter,
        "23503",
        "invitations_invited_by_user_id_fkey",
    )?;

    let invalid_invitation_uuid = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(Uuid::nil())
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_invitation_uuid, "23514", "invitations_id_uuid_v7")?;

    let invalid_invitation_role = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'owner', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_invitation_role, "23514", "invitations_role_check")?;

    let invalid_invitation_status = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'cancelled', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_invitation_status,
        "23514",
        "invitations_status_check",
    )?;

    let accepted_without_timestamp = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'accepted', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        accepted_without_timestamp,
        "23514",
        "invitations_terminal_state",
    )?;

    let pending_with_terminal_timestamp = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, $7::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        pending_with_terminal_timestamp,
        "23514",
        "invitations_terminal_state",
    )?;

    let invalid_expiry = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $5::timestamptz, $6::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_expiry, "23514", "invitations_expiry_order")?;

    sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await?;
    let duplicate_pending_invitation = sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'admin', 'pending', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, NULL, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        duplicate_pending_invitation,
        "23505",
        "invitations_pending_organization_invited_user_key",
    )?;

    sqlx::query(
        "INSERT INTO invitations \
         (id, organization_id, invited_user_id, invited_by_user_id, role, status, \
          expires_at, created_at, updated_at, accepted_at, revoked_at) \
         VALUES ($1, $2, $3, $4, 'member', 'accepted', $5::timestamptz, \
         $6::timestamptz, $7::timestamptz, $7::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(invitee_id)
    .bind(owner_id)
    .bind(EXPIRES_AT)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await?;

    let missing_service_account_tenant = sqlx::query(
        "INSERT INTO service_accounts \
         (id, name, tenant_id, created_by_user_id, created_at, disabled_at) \
         VALUES ($1, 'Tenant FK Probe', $2, $3, $4::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(ids.uuid_v7()?)
    .bind(owner_id)
    .bind(CREATED_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        missing_service_account_tenant,
        "23503",
        "service_accounts_tenant_id_fkey",
    )?;

    sqlx::query(
        "INSERT INTO service_accounts \
         (id, name, tenant_id, created_by_user_id, created_at, disabled_at) \
         VALUES ($1, 'Tenant Bound Account', $2, $3, $4::timestamptz, NULL)",
    )
    .bind(ids.uuid_v7()?)
    .bind(organization_id)
    .bind(owner_id)
    .bind(CREATED_AT)
    .execute(&mut *connection)
    .await?;

    sqlx::query("BEGIN").execute(&mut *connection).await?;
    sqlx::query(
        "UPDATE memberships SET role = 'admin', grant_version = grant_version + 1, \
         updated_at = $3::timestamptz WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(owner_id)
    .bind("2026-08-23 12:02:00+00")
    .execute(&mut *connection)
    .await?;
    let rejected_commit = sqlx::query("COMMIT").execute(&mut *connection).await;
    assert_database_constraint(
        rejected_commit,
        "23514",
        "organizations_active_owner_required",
    )?;
    sqlx::query("ROLLBACK").execute(&mut *connection).await?;
    let retained_owner_role: String = sqlx::query_scalar(
        "SELECT role FROM memberships WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(owner_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(retained_owner_role, "owner");

    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'member', 'active', 1, $3::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(successor_id)
    .bind(CREATED_AT)
    .bind(UPDATED_AT)
    .execute(&mut *connection)
    .await?;
    sqlx::query("BEGIN").execute(&mut *connection).await?;
    sqlx::query(
        "UPDATE memberships SET role = 'admin', grant_version = grant_version + 1, \
         updated_at = $3::timestamptz WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(owner_id)
    .bind("2026-08-23 12:03:00+00")
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE memberships SET role = 'owner', grant_version = grant_version + 1, \
         updated_at = $3::timestamptz WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(successor_id)
    .bind("2026-08-23 12:03:00+00")
    .execute(&mut *connection)
    .await?;
    sqlx::query("COMMIT").execute(&mut *connection).await?;
    let transferred_roles: Vec<String> = sqlx::query_scalar(
        "SELECT role FROM memberships WHERE organization_id = $1 \
         ORDER BY user_id",
    )
    .bind(organization_id)
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(transferred_roles, ["admin", "owner"]);

    drop(connection);
    Ok(())
}

#[tokio::test]
async fn embedded_head_enforces_tenancy_schema() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_tenancy_schema(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}

async fn exercise_legacy_tenant_backfill(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let legacy_source = CleanDirectory::new("tenancy-legacy-migrations")?;
    for entry in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".sql") && name.as_ref() < "2026082311_" {
            fs::copy(entry.path(), legacy_source.path().join(name.as_ref()))?;
        }
    }
    let legacy_migrator = Migrator::new(legacy_source.path()).await?;
    let legacy_runner = MigrationRunner::new(
        pool.clone(),
        &legacy_migrator,
        SchemaVersionRange::new(FIRST_MIGRATION, 2_026_082_310)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    legacy_runner.run().await?;

    let ids = TestIds::default();
    let owner_id = ids.uuid_v7()?;
    let tenant_id = ids.uuid_v7()?;
    let service_account_id = ids.uuid_v7()?;
    let mut connection = pool.acquire().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2::timestamptz)")
        .bind(owner_id)
        .bind(CREATED_AT)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "INSERT INTO service_accounts \
         (id, name, tenant_id, created_by_user_id, created_at, disabled_at) \
         VALUES ($1, 'Legacy tenant account', $2, $3, $4::timestamptz, NULL)",
    )
    .bind(service_account_id)
    .bind(tenant_id)
    .bind(owner_id)
    .bind(CREATED_AT)
    .execute(&mut *connection)
    .await?;
    drop(connection);

    let tenancy_runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let head = tenancy_runner.run().await?;
    assert_eq!(
        head.current_version,
        Some(omnius_migrations::CURRENT_SCHEMA_VERSION)
    );

    let mut connection = pool.acquire().await?;
    let organization_status: String =
        sqlx::query_scalar("SELECT status FROM organizations WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(organization_status, "suspended");
    let membership_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships \
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(tenant_id)
    .bind(owner_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(membership_count, 0);
    Ok(())
}

#[tokio::test]
async fn legacy_tenant_bound_service_accounts_are_backfilled_before_fk_validation()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_legacy_tenant_backfill(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps both concurrent transactions and their invariant visible"
)]
async fn exercise_concurrent_owner_guard(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;

    let ids = TestIds::default();
    let first_owner = ids.uuid_v7()?;
    let second_owner = ids.uuid_v7()?;
    let organization_id = ids.uuid_v7()?;
    let mut setup = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO users (id, created_at) \
         VALUES ($1, $3::timestamptz), ($2, $3::timestamptz)",
    )
    .bind(first_owner)
    .bind(second_owner)
    .bind(CREATED_AT)
    .execute(&mut *setup)
    .await?;
    sqlx::query("BEGIN").execute(&mut *setup).await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Concurrent ownership', 'active', 1, \
                 $2::timestamptz, $2::timestamptz, NULL)",
    )
    .bind(organization_id)
    .bind(CREATED_AT)
    .execute(&mut *setup)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES \
         ($1, $2, 'owner', 'active', 1, $4::timestamptz, $4::timestamptz), \
         ($1, $3, 'owner', 'active', 1, $4::timestamptz, $4::timestamptz)",
    )
    .bind(organization_id)
    .bind(first_owner)
    .bind(second_owner)
    .bind(CREATED_AT)
    .execute(&mut *setup)
    .await?;
    sqlx::query("COMMIT").execute(&mut *setup).await?;
    drop(setup);

    let mut first = pool.acquire().await?;
    let mut second = pool.acquire().await?;
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *first)
        .await?;
    sqlx::query("BEGIN ISOLATION LEVEL REPEATABLE READ")
        .execute(&mut *second)
        .await?;
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memberships WHERE organization_id = $1")
        .bind(organization_id)
        .fetch_one(&mut *first)
        .await?;
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memberships WHERE organization_id = $1")
        .bind(organization_id)
        .fetch_one(&mut *second)
        .await?;
    sqlx::query(
        "UPDATE memberships SET role = 'admin', grant_version = grant_version + 1 \
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(first_owner)
    .execute(&mut *first)
    .await?;
    sqlx::query(
        "UPDATE memberships SET role = 'admin', grant_version = grant_version + 1 \
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(second_owner)
    .execute(&mut *second)
    .await?;

    let (first_commit, second_commit) = tokio::join!(
        sqlx::query("COMMIT").execute(&mut *first),
        sqlx::query("COMMIT").execute(&mut *second),
    );
    let commits = [first_commit, second_commit];
    assert_eq!(commits.iter().filter(|result| result.is_ok()).count(), 1);
    let failure = commits
        .iter()
        .find_map(|result| result.as_ref().err())
        .ok_or("one concurrent owner demotion must fail")?;
    assert_eq!(
        failure
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .as_deref(),
        Some("40001")
    );
    drop(first);
    drop(second);

    let mut connection = pool.acquire().await?;
    let active_owners: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memberships \
         WHERE organization_id = $1 AND role = 'owner' AND status = 'active'",
    )
    .bind(organization_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(active_owners, 1);
    Ok(())
}

#[tokio::test]
async fn concurrent_repeatable_read_demotions_cannot_remove_every_owner()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_concurrent_owner_guard(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
