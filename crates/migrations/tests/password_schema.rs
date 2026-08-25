//! Password credential and single-use verification-token schema contract.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use time::OffsetDateTime;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const PASSWORD_HEAD: i64 = 2_026_082_314;

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
        application_name: "rsk-password-schema-test".to_owned(),
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

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps the complete password schema contract and cleanup visible"
)]
#[tokio::test]
async fn password_schema_enforces_secret_and_token_invariants() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, PASSWORD_HEAD)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    let mut connection = pool.acquire().await?;

    let credential_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'password_credentials' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        credential_columns,
        [
            "user_id:uuid:NO",
            "password_hash:text:NO",
            "pepper_version:bigint:NO",
            "created_at:timestamp with time zone:NO",
            "changed_at:timestamp with time zone:NO",
            "updated_at:timestamp with time zone:NO",
        ]
    );
    let token_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'verification_tokens' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        token_columns,
        [
            "id:uuid:NO",
            "user_id:uuid:NO",
            "purpose:text:NO",
            "token_hash:bytea:NO",
            "security_version:bigint:NO",
            "created_at:timestamp with time zone:NO",
            "expires_at:timestamp with time zone:NO",
            "consumed_at:timestamp with time zone:YES",
            "invalidated_at:timestamp with time zone:YES",
        ]
    );

    let credential_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'password_credentials'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        credential_constraints,
        [
            "password_credentials_hash_algorithm:c",
            "password_credentials_hash_length:c",
            "password_credentials_hash_nonblank:c",
            "password_credentials_hash_trimmed:c",
            "password_credentials_pepper_version_nonnegative:c",
            "password_credentials_pkey:p",
            "password_credentials_timeline:c",
            "password_credentials_user_id_fkey:f",
        ]
    );
    let token_constraints: Vec<String> = sqlx::query_scalar(
        "SELECT conname || ':' || contype::text FROM pg_constraint \
         WHERE conrelid = 'verification_tokens'::regclass ORDER BY conname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        token_constraints,
        [
            "verification_tokens_expiry_valid:c",
            "verification_tokens_hash_key:u",
            "verification_tokens_hash_length:c",
            "verification_tokens_id_uuid_v7:c",
            "verification_tokens_pkey:p",
            "verification_tokens_purpose_known:c",
            "verification_tokens_security_version_positive:c",
            "verification_tokens_terminal_state_valid:c",
            "verification_tokens_user_id_fkey:f",
        ]
    );

    let active_index: (bool, String) = sqlx::query_as(
        "SELECT i.indisunique, pg_get_expr(i.indpred, i.indrelid) \
         FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = 'verification_tokens_active_subject_purpose_idx'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert!(active_index.0);
    assert!(active_index.1.contains("consumed_at IS NULL"));
    assert!(active_index.1.contains("invalidated_at IS NULL"));

    let user_id = Uuid::now_v7();
    let now = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, $2)")
        .bind(user_id)
        .bind(now)
        .execute(&mut *connection)
        .await?;
    let auth_version: i64 =
        sqlx::query_scalar("SELECT authentication_version FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(auth_version, 1);

    let invalid_hash = sqlx::query(
        "INSERT INTO password_credentials \
         (user_id, password_hash, pepper_version, created_at, changed_at, updated_at) \
         VALUES ($1, '$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA ', 0, $2, $2, $2)",
    )
    .bind(user_id)
    .bind(now)
    .execute(&mut *connection)
    .await;
    let Err(sqlx::Error::Database(invalid_hash_error)) = invalid_hash else {
        return Err("padded PHC was accepted or returned a non-database error".into());
    };
    assert_eq!(
        invalid_hash_error.constraint(),
        Some("password_credentials_hash_trimmed")
    );

    let first_token_id = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO verification_tokens \
         (id, user_id, purpose, token_hash, security_version, created_at, expires_at) \
         VALUES ($1, $2, 'password_recovery', $3, 1, $4, $5)",
    )
    .bind(first_token_id)
    .bind(user_id)
    .bind([7_u8; 32].as_slice())
    .bind(now)
    .bind(now + time::Duration::minutes(15))
    .execute(&mut *connection)
    .await?;
    let duplicate_active = sqlx::query(
        "INSERT INTO verification_tokens \
         (id, user_id, purpose, token_hash, security_version, created_at, expires_at) \
         VALUES ($1, $2, 'password_recovery', $3, 1, $4, $5)",
    )
    .bind(Uuid::now_v7())
    .bind(user_id)
    .bind([8_u8; 32].as_slice())
    .bind(now)
    .bind(now + time::Duration::minutes(15))
    .execute(&mut *connection)
    .await;
    let Err(sqlx::Error::Database(duplicate_error)) = duplicate_active else {
        return Err(
            "duplicate active purpose was accepted or returned a non-database error".into(),
        );
    };
    assert_eq!(
        duplicate_error.constraint(),
        Some("verification_tokens_active_subject_purpose_idx")
    );

    sqlx::query("UPDATE verification_tokens SET consumed_at = $2 WHERE id = $1")
        .bind(first_token_id)
        .bind(now + time::Duration::minutes(1))
        .execute(&mut *connection)
        .await?;
    let terminal_conflict =
        sqlx::query("UPDATE verification_tokens SET invalidated_at = $2 WHERE id = $1")
            .bind(first_token_id)
            .bind(now + time::Duration::minutes(2))
            .execute(&mut *connection)
            .await;
    let Err(sqlx::Error::Database(terminal_error)) = terminal_conflict else {
        return Err("dual terminal state was accepted or returned a non-database error".into());
    };
    assert_eq!(
        terminal_error.constraint(),
        Some("verification_tokens_terminal_state_valid")
    );

    drop(connection);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}
