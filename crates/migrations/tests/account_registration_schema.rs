//! Durable account-registration state and invitation schema contracts.

use std::{error::Error, fs, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{CleanDirectory, PostgresFixture};
use sqlx::{migrate::Migrator, postgres::PgQueryResult};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const PREVIOUS_SCHEMA_VERSION: i64 = 2_026_082_701;
const CREATED_AT: &str = "2026-08-28 00:00:00+00";
const EXPIRES_AT: &str = "2026-09-04 00:00:00+00";
const INSERT_SYSTEM_INVITATION: &str = r"
    INSERT INTO registration_invitations
        (id, identity_provider, identity_subject, token_digest, issuer_kind,
         issued_by_user_id, issued_by_service_account_id, created_at, expires_at,
         consumed_at, revoked_at)
    VALUES ($1, 'local', $2, $3, 'system', NULL, NULL,
            TIMESTAMPTZ '2026-08-28 00:00:00+00',
            TIMESTAMPTZ '2026-09-04 00:00:00+00', NULL, NULL)
";

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
        application_name: "omnius-account-registration-schema-test".to_owned(),
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

async fn migrate_to_head(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
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
    assert!(head.pending_versions.is_empty());
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps invitation constraints and their exact failures visible"
)]
async fn exercise_fresh_schema(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    migrate_to_head(pool).await?;
    let mut connection = pool.acquire().await?;

    let invitation_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'registration_invitations' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        invitation_columns,
        [
            "id:uuid:NO",
            "identity_provider:text:NO",
            "identity_subject:text:NO",
            "token_digest:bytea:NO",
            "issuer_kind:text:NO",
            "issued_by_user_id:uuid:YES",
            "issued_by_service_account_id:uuid:YES",
            "created_at:timestamp with time zone:NO",
            "expires_at:timestamp with time zone:NO",
            "consumed_at:timestamp with time zone:YES",
            "revoked_at:timestamp with time zone:YES",
        ]
    );

    let invitation_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'registration_invitations'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        invitation_constraints,
        [
            "registration_invitations_expiry_valid:c",
            "registration_invitations_id_uuid_v7:c",
            "registration_invitations_identity_key_bytes:c",
            "registration_invitations_identity_provider_length:c",
            "registration_invitations_identity_provider_nonblank:c",
            "registration_invitations_identity_provider_trimmed:c",
            "registration_invitations_identity_subject_canonical_email:c",
            "registration_invitations_issued_by_service_account_id_fkey:f",
            "registration_invitations_issued_by_user_id_fkey:f",
            "registration_invitations_issuer_actor_valid:c",
            "registration_invitations_issuer_kind_known:c",
            "registration_invitations_pkey:p",
            "registration_invitations_terminal_state_valid:c",
            "registration_invitations_token_digest_key:u",
            "registration_invitations_token_digest_length:c",
        ]
    );

    let delete_actions: Vec<String> = sqlx::query_scalar(
        "SELECT confdeltype::text FROM pg_constraint \
         WHERE conname IN ('registration_invitations_issued_by_user_id_fkey', \
                           'registration_invitations_issued_by_service_account_id_fkey') \
         ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(delete_actions, ["r", "r"]);

    let expiry_index: (bool, i32, String, String, String) = sqlx::query_as(
        "SELECT i.indisunique, i.indnkeyatts::integer, \
                pg_get_indexdef(i.indexrelid, 1, TRUE), \
                pg_get_indexdef(i.indexrelid, 2, TRUE), \
                pg_get_expr(i.indpred, i.indrelid) \
         FROM pg_index AS i JOIN pg_class AS c ON c.oid = i.indexrelid \
         WHERE c.relname = 'registration_invitations_expiry_idx'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert!(!expiry_index.0);
    assert_eq!(expiry_index.1, 2);
    assert_eq!(expiry_index.2, "expires_at");
    assert_eq!(expiry_index.3, "id");
    assert!(expiry_index.4.contains("consumed_at IS NULL"));
    assert!(expiry_index.4.contains("revoked_at IS NULL"));

    let user_id = Uuid::now_v7();
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2::timestamptz)")
        .bind(user_id)
        .bind(CREATED_AT)
        .execute(&mut *connection)
        .await?;
    let initial_state: (String, i64) =
        sqlx::query_as("SELECT status, authentication_version FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(initial_state, ("pending_verification".to_owned(), 1));

    let invalid_status = sqlx::query("UPDATE users SET status = 'unknown' WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_status, "23514", "users_status_known")?;

    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await?;
    let first_disabled_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(first_disabled_version, 2);
    sqlx::query("UPDATE users SET status = 'active' WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await?;
    sqlx::query(
        "UPDATE users SET status = 'disabled', \
         authentication_version = authentication_version + 1 WHERE id = $1",
    )
    .bind(user_id)
    .execute(&mut *connection)
    .await?;
    let caller_advanced_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(caller_advanced_version, 3);

    let invalid_email = sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(Uuid::now_v7())
        .bind("Invitee@Example.com")
        .bind(vec![1_u8; 32])
        .execute(&mut *connection)
        .await;
    assert_database_constraint(
        invalid_email,
        "23514",
        "registration_invitations_identity_subject_canonical_email",
    )?;

    let invalid_digest = sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(Uuid::now_v7())
        .bind("digest@example.com")
        .bind(vec![2_u8; 31])
        .execute(&mut *connection)
        .await;
    assert_database_constraint(
        invalid_digest,
        "23514",
        "registration_invitations_token_digest_length",
    )?;

    let invalid_actor = sqlx::query(
        "INSERT INTO registration_invitations \
         (id, identity_provider, identity_subject, token_digest, issuer_kind, \
          issued_by_user_id, issued_by_service_account_id, created_at, expires_at) \
         VALUES ($1, 'local', 'actor@example.com', $2, 'system', $3, NULL, \
                 $4::timestamptz, $5::timestamptz)",
    )
    .bind(Uuid::now_v7())
    .bind(vec![3_u8; 32])
    .bind(user_id)
    .bind(CREATED_AT)
    .bind(EXPIRES_AT)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_actor,
        "23514",
        "registration_invitations_issuer_actor_valid",
    )?;

    let invalid_timeline = sqlx::query(
        "INSERT INTO registration_invitations \
         (id, identity_provider, identity_subject, token_digest, issuer_kind, \
          created_at, expires_at) \
         VALUES ($1, 'local', 'expiry@example.com', $2, 'system', \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-28 00:30:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(vec![4_u8; 32])
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_timeline,
        "23514",
        "registration_invitations_expiry_valid",
    )?;

    let invalid_terminal_state = sqlx::query(
        "INSERT INTO registration_invitations \
         (id, identity_provider, identity_subject, token_digest, issuer_kind, \
          created_at, expires_at, consumed_at, revoked_at) \
         VALUES ($1, 'local', 'state@example.com', $2, 'system', \
                 TIMESTAMPTZ '2026-08-28 00:00:00+00', \
                 TIMESTAMPTZ '2026-09-04 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-29 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-29 00:00:00+00')",
    )
    .bind(Uuid::now_v7())
    .bind(vec![5_u8; 32])
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        invalid_terminal_state,
        "23514",
        "registration_invitations_terminal_state_valid",
    )?;

    let invalid_id = sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(Uuid::nil())
        .bind("uuid@example.com")
        .bind(vec![6_u8; 32])
        .execute(&mut *connection)
        .await;
    assert_database_constraint(invalid_id, "23514", "registration_invitations_id_uuid_v7")?;

    let first_invitation_id = Uuid::now_v7();
    sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(first_invitation_id)
        .bind("single@example.com")
        .bind(vec![7_u8; 32])
        .execute(&mut *connection)
        .await?;
    let duplicate_active_identity = sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(Uuid::now_v7())
        .bind("single@example.com")
        .bind(vec![8_u8; 32])
        .execute(&mut *connection)
        .await;
    assert_database_constraint(
        duplicate_active_identity,
        "23505",
        "registration_invitations_active_identity_idx",
    )?;
    sqlx::query(
        "UPDATE registration_invitations \
         SET consumed_at = TIMESTAMPTZ '2026-08-29 00:00:00+00' WHERE id = $1",
    )
    .bind(first_invitation_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(INSERT_SYSTEM_INVITATION)
        .bind(Uuid::now_v7())
        .bind("single@example.com")
        .bind(vec![8_u8; 32])
        .execute(&mut *connection)
        .await?;

    Ok(())
}

#[tokio::test]
async fn fresh_database_migrates_to_account_registration_head() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_fresh_schema(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}

async fn exercise_upgrade_backfill(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let legacy_source = CleanDirectory::new("account-registration-legacy-migrations")?;
    for entry in fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".sql") && name.as_ref() < "2026082801_" {
            fs::copy(entry.path(), legacy_source.path().join(name.as_ref()))?;
        }
    }
    let legacy_runner = MigrationRunner::new(
        pool.clone(),
        Migrator::new(legacy_source.path()).await?,
        SchemaVersionRange::new(FIRST_MIGRATION, PREVIOUS_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let legacy_head = legacy_runner.run().await?;
    assert_eq!(legacy_head.current_version, Some(PREVIOUS_SCHEMA_VERSION));

    let password_user_id = Uuid::now_v7();
    let passwordless_user_id = Uuid::now_v7();
    let local_identity_id = Uuid::now_v7();
    let oidc_identity_id = Uuid::now_v7();
    let linked_github_identity_id = Uuid::now_v7();
    let passwordless_identity_id = Uuid::now_v7();
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO users (id, created_at) VALUES \
         ($1, TIMESTAMPTZ '2026-08-27 00:00:00+00'), \
         ($2, TIMESTAMPTZ '2026-08-27 00:00:00+00')",
    )
    .bind(password_user_id)
    .bind(passwordless_user_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO identities (id, user_id, provider, provider_subject, created_at) VALUES \
         ($1, $2, 'email', 'owner@example.com', TIMESTAMPTZ '2026-08-27 00:01:00+00'), \
         ($3, $2, 'https://issuer.example', 'oidc-subject', \
          TIMESTAMPTZ '2026-08-27 00:02:00+00'), \
         ($4, $5, 'email', 'passwordless@example.com', \
          TIMESTAMPTZ '2026-08-27 00:03:00+00'), \
         ($6, $2, 'github', 'github-subject', TIMESTAMPTZ '2026-08-27 00:04:00+00')",
    )
    .bind(local_identity_id)
    .bind(password_user_id)
    .bind(oidc_identity_id)
    .bind(passwordless_identity_id)
    .bind(passwordless_user_id)
    .bind(linked_github_identity_id)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO password_credentials \
         (user_id, password_hash, pepper_version, created_at, changed_at, updated_at) \
         VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA', 0, \
                 TIMESTAMPTZ '2026-08-27 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-27 00:00:00+00', \
                 TIMESTAMPTZ '2026-08-27 00:00:00+00')",
    )
    .bind(password_user_id)
    .execute(&mut *connection)
    .await?;
    drop(connection);

    migrate_to_head(pool).await?;
    let mut connection = pool.acquire().await?;
    let existing_statuses: Vec<String> = sqlx::query_scalar("SELECT status FROM users ORDER BY id")
        .fetch_all(&mut *connection)
        .await?;
    assert_eq!(existing_statuses, ["active", "active"]);

    let verification_backfill: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT \
         (SELECT verified_at = created_at FROM identities WHERE id = $1), \
         (SELECT verified_at IS NULL FROM identities WHERE id = $2), \
         (SELECT verified_at IS NULL FROM identities WHERE id = $3), \
         (SELECT verified_at IS NULL FROM identities WHERE id = $4)",
    )
    .bind(local_identity_id)
    .bind(oidc_identity_id)
    .bind(passwordless_identity_id)
    .bind(linked_github_identity_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(verification_backfill, (true, true, true, true));

    let new_user_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO users (id, created_at) \
         VALUES ($1, TIMESTAMPTZ '2026-08-28 00:00:00+00')",
    )
    .bind(new_user_id)
    .execute(&mut *connection)
    .await?;
    let new_status: String = sqlx::query_scalar("SELECT status FROM users WHERE id = $1")
        .bind(new_user_id)
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(new_status, "pending_verification");
    Ok(())
}

#[tokio::test]
async fn previous_head_upgrades_without_locking_out_existing_accounts() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_upgrade_backfill(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
