//! Canonical users and external-identity schema contract.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{PostgresFixture, TestIds};
use sqlx::postgres::PgQueryResult;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const INSERT_IDENTITY: &str = r"
    INSERT INTO identities (id, user_id, provider, provider_subject, created_at)
    VALUES ($1, $2, $3, $4, TIMESTAMPTZ '2026-08-23 00:01:00+00')
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
        application_name: "rsk-identity-schema-test".to_owned(),
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
    reason = "one fixture keeps the complete forward-only schema contract and cleanup visible"
)]
async fn exercise_identity_schema(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let head = runner.run().await?;
    assert_eq!(
        head.current_version,
        Some(rsk_migrations::CURRENT_SCHEMA_VERSION)
    );
    assert_eq!(head.target_version, rsk_migrations::CURRENT_SCHEMA_VERSION);
    assert!(head.pending_versions.is_empty());

    let mut connection = pool.acquire().await?;
    let user_columns: Vec<String> = sqlx::query_scalar(
        r"
        SELECT column_name || ':' || data_type || ':' || is_nullable
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'users'
        ORDER BY ordinal_position
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        user_columns,
        [
            "id:uuid:NO",
            "created_at:timestamp with time zone:NO",
            "authentication_version:bigint:NO",
        ]
    );

    let identity_columns: Vec<String> = sqlx::query_scalar(
        r"
        SELECT column_name || ':' || data_type || ':' || is_nullable
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'identities'
        ORDER BY ordinal_position
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        identity_columns,
        [
            "id:uuid:NO",
            "user_id:uuid:NO",
            "provider:text:NO",
            "provider_subject:text:NO",
            "created_at:timestamp with time zone:NO",
        ]
    );

    let user_constraints: Vec<String> = sqlx::query_scalar(
        r"
        SELECT conname || ':' || contype::text
        FROM pg_constraint
        WHERE conrelid = 'users'::regclass
        ORDER BY conname
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        user_constraints,
        [
            "users_authentication_version_positive:c",
            "users_id_uuid_v7:c",
            "users_pkey:p",
        ]
    );

    let identity_constraints: Vec<String> = sqlx::query_scalar(
        r"
        SELECT conname || ':' || contype::text
        FROM pg_constraint
        WHERE conrelid = 'identities'::regclass
        ORDER BY conname
        ",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        identity_constraints,
        [
            "identities_id_uuid_v7:c",
            "identities_pkey:p",
            "identities_provider_length:c",
            "identities_provider_nonblank:c",
            "identities_provider_provider_subject_key:u",
            "identities_provider_subject_key_bytes:c",
            "identities_provider_subject_length:c",
            "identities_provider_subject_nonblank:c",
            "identities_provider_subject_trimmed:c",
            "identities_provider_trimmed:c",
            "identities_user_id_fkey:f",
        ]
    );

    let foreign_key_delete_action: String = sqlx::query_scalar(
        "SELECT confdeltype::text FROM pg_constraint WHERE conname = 'identities_user_id_fkey'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(foreign_key_delete_action, "r");

    let user_index: (bool, bool, i32, String) = sqlx::query_as(
        r"
        SELECT i.indisunique, i.indisprimary, i.indnkeyatts::integer,
               pg_get_indexdef(i.indexrelid, 1, TRUE)
        FROM pg_index AS i
        JOIN pg_class AS index_relation ON index_relation.oid = i.indexrelid
        JOIN pg_class AS table_relation ON table_relation.oid = i.indrelid
        WHERE table_relation.oid = 'identities'::regclass
          AND index_relation.relname = 'identities_user_id_idx'
        ",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(user_index, (false, false, 1, "user_id".to_owned()));

    let ids = TestIds::default();
    let user_id = ids.uuid_v7()?;
    sqlx::query(
        r"
        INSERT INTO users (id, created_at)
        VALUES ($1, TIMESTAMPTZ '2026-08-23 00:00:00+00')
        ",
    )
    .bind(user_id)
    .execute(&mut *connection)
    .await?;

    let first_identity_id = ids.uuid_v7()?;
    sqlx::query(INSERT_IDENTITY)
        .bind(first_identity_id)
        .bind(user_id)
        .bind("https://issuer.example")
        .bind("shared-subject")
        .execute(&mut *connection)
        .await?;
    let second_identity_id = ids.uuid_v7()?;
    sqlx::query(INSERT_IDENTITY)
        .bind(second_identity_id)
        .bind(user_id)
        .bind("urn:issuer:workforce")
        .bind("shared-subject")
        .execute(&mut *connection)
        .await?;

    let identity_shape: (i64, i64, i64) = sqlx::query_as(
        r"
        SELECT count(*)::bigint,
               count(DISTINCT provider)::bigint,
               count(DISTINCT provider_subject)::bigint
        FROM identities
        WHERE user_id = $1
        ",
    )
    .bind(user_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(identity_shape, (2, 2, 1));

    let duplicate_result = sqlx::query(INSERT_IDENTITY)
        .bind(ids.uuid_v7()?)
        .bind(user_id)
        .bind("https://issuer.example")
        .bind("shared-subject")
        .execute(&mut *connection)
        .await;
    assert_database_constraint(
        duplicate_result,
        "23505",
        "identities_provider_provider_subject_key",
    )?;

    let foreign_key_result = sqlx::query(
        r"
        INSERT INTO identities (id, user_id, provider, provider_subject, created_at)
        VALUES (
            $1,
            '00000000-0000-7000-8000-000000000001'::uuid,
            'https://issuer.example',
            'missing-user',
            TIMESTAMPTZ '2026-08-23 00:01:00+00'
        )
        ",
    )
    .bind(ids.uuid_v7()?)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(foreign_key_result, "23503", "identities_user_id_fkey")?;

    let invalid_user_id_result = sqlx::query(
        r"
        INSERT INTO users (id, created_at)
        VALUES (
            '00000000-0000-4000-8000-000000000000'::uuid,
            TIMESTAMPTZ '2026-08-23 00:00:00+00'
        )
        ",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_user_id_result, "23514", "users_id_uuid_v7")?;

    let invalid_identity_id_result = sqlx::query(
        r"
        INSERT INTO identities (id, user_id, provider, provider_subject, created_at)
        VALUES (
            '00000000-0000-4000-8000-000000000000'::uuid,
            $1,
            'https://issuer.example',
            'invalid-identity-id',
            TIMESTAMPTZ '2026-08-23 00:01:00+00'
        )
        ",
    )
    .bind(user_id)
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_identity_id_result, "23514", "identities_id_uuid_v7")?;

    let provider_at_limit = "p".repeat(2048);
    let subject_at_limit = "s".repeat(255);
    sqlx::query(INSERT_IDENTITY)
        .bind(ids.uuid_v7()?)
        .bind(user_id)
        .bind(provider_at_limit)
        .bind(subject_at_limit)
        .execute(&mut *connection)
        .await?;

    let provider_too_long = "é".repeat(1025);
    let subject_too_long = "é".repeat(128);
    let invalid_text_values = [
        ("", "empty-provider", "identities_provider_nonblank"),
        ("\t", "whitespace-provider", "identities_provider_nonblank"),
        (
            " padded-provider",
            "padded-provider",
            "identities_provider_trimmed",
        ),
        (
            "\ttrimmed-provider\t",
            "tab-padded-provider",
            "identities_provider_trimmed",
        ),
        (
            provider_too_long.as_str(),
            "long-provider",
            "identities_provider_length",
        ),
        ("empty-subject", "", "identities_provider_subject_nonblank"),
        (
            "whitespace-subject",
            "\t",
            "identities_provider_subject_nonblank",
        ),
        (
            "padded-subject",
            "padded-subject ",
            "identities_provider_subject_trimmed",
        ),
        (
            "newline-padded-subject",
            "\ntrimmed-subject\n",
            "identities_provider_subject_trimmed",
        ),
        (
            "long-subject",
            subject_too_long.as_str(),
            "identities_provider_subject_length",
        ),
    ];
    for (provider, provider_subject, constraint) in invalid_text_values {
        let result = sqlx::query(INSERT_IDENTITY)
            .bind(ids.uuid_v7()?)
            .bind(user_id)
            .bind(provider)
            .bind(provider_subject)
            .execute(&mut *connection)
            .await;
        assert_database_constraint(result, "23514", constraint)?;
    }

    let restricted_delete = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await;
    assert_database_constraint(restricted_delete, "23503", "identities_user_id_fkey")?;

    let deleted_identities = sqlx::query("DELETE FROM identities WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await?;
    assert_eq!(deleted_identities.rows_affected(), 3);
    let deleted_users = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *connection)
        .await?;
    assert_eq!(deleted_users.rows_affected(), 1);
    drop(connection);

    Ok(())
}

#[tokio::test]
async fn embedded_head_enforces_canonical_identity_storage() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_identity_schema(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
