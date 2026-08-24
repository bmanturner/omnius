//! Released reference-schema rolling compatibility contract.

use std::{error::Error, fs, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{
    MIGRATOR, MigrationConfig, MigrationError, MigrationRunner, SchemaVersionRange,
};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::{CleanDirectory, PostgresFixture, TestIds};
use sqlx::{Connection as _, Row as _, migrate::Migrator};

const REFERENCE_V1: i64 = 2_026_082_301;
const PREVIOUS_REFERENCE_HEAD: i64 = 2_026_082_305;
const REFERENCE_HEAD: i64 = 2_026_082_308;
const RELEASED_REFERENCE_V1: &[u8] =
    include_bytes!("../../../migrations/2026082301_create_reference_records.sql");
const RELEASED_REFERENCE_V2: &[u8] =
    include_bytes!("../../../migrations/2026082302_add_idempotency_and_versions.sql");
const RELEASED_REFERENCE_V3: &[u8] =
    include_bytes!("../../../migrations/2026082303_add_reference_pagination_index.sql");
const RELEASED_REFERENCE_V4: &[u8] =
    include_bytes!("../../../migrations/2026082304_create_users_and_identities.sql");
const RELEASED_REFERENCE_V5: &[u8] = include_bytes!(
    "../../../migrations/2026082305_add_password_credentials_and_verification_tokens.sql"
);

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
        application_name: "rsk-reference-rolling-test".to_owned(),
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
    reason = "this test keeps the released/bridge/new rollout sequence visible"
)]
async fn exercise_released_history(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let old_source = CleanDirectory::new("reference-migrations-old")?;
    for (name, bytes) in [
        (
            "2026082301_create_reference_records.sql",
            RELEASED_REFERENCE_V1,
        ),
        (
            "2026082302_add_idempotency_and_versions.sql",
            RELEASED_REFERENCE_V2,
        ),
        (
            "2026082303_add_reference_pagination_index.sql",
            RELEASED_REFERENCE_V3,
        ),
        (
            "2026082304_create_users_and_identities.sql",
            RELEASED_REFERENCE_V4,
        ),
        (
            "2026082305_add_password_credentials_and_verification_tokens.sql",
            RELEASED_REFERENCE_V5,
        ),
    ] {
        let path = old_source.path().join(name);
        fs::write(&path, bytes)?;
        assert_eq!(fs::read(path)?, bytes);
    }

    let old_migrator = Migrator::new(old_source.path()).await?;
    let released_range = SchemaVersionRange::new(REFERENCE_V1, PREVIOUS_REFERENCE_HEAD)?;
    let expanded_range = SchemaVersionRange::new(REFERENCE_V1, REFERENCE_HEAD)?;
    let old_runner = MigrationRunner::new(
        pool.clone(),
        &old_migrator,
        released_range,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let released_head = old_runner.run().await?;
    assert_eq!(released_head.current_version, Some(PREVIOUS_REFERENCE_HEAD));
    assert_eq!(released_head.target_version, PREVIOUS_REFERENCE_HEAD);
    assert!(released_head.pending_versions.is_empty());
    assert!(released_head.unknown_versions.is_empty());

    let ids = TestIds::default();
    let legacy_id = ids.uuid_v7()?;
    let head_id = ids.uuid_v7()?;
    let fingerprint = [0x5a_u8; 32];
    let response_body = br#"{"result":"updated"}"#;

    let mut connection = pool.acquire().await?;
    sqlx::query(
        r"
        INSERT INTO reference_records (id, name, created_at, updated_at)
        VALUES (
            $1,
            'legacy-created',
            TIMESTAMPTZ '2026-08-23 00:00:00+00',
            TIMESTAMPTZ '2026-08-23 00:00:00+00'
        )
        ",
    )
    .bind(legacy_id)
    .execute(&mut *connection)
    .await?;
    let legacy_row =
        sqlx::query("SELECT id, name, created_at, updated_at FROM reference_records WHERE id = $1")
            .bind(legacy_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(legacy_row.try_get::<String, _>("name")?, "legacy-created");
    let legacy_name: String = sqlx::query_scalar(
        r"
        UPDATE reference_records
        SET name = 'legacy-v1', updated_at = updated_at + INTERVAL '1 second'
        WHERE id = $1
        RETURNING name
        ",
    )
    .bind(legacy_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(legacy_name, "legacy-v1");
    drop(connection);

    let bridge_runner = MigrationRunner::new(
        pool.clone(),
        &old_migrator,
        expanded_range,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;

    let new_runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        expanded_range,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let before_expand = new_runner.verify_compatibility().await?;
    assert_eq!(before_expand.current_version, Some(PREVIOUS_REFERENCE_HEAD));
    assert_eq!(
        before_expand.pending_versions,
        vec![2_026_082_306, 2_026_082_307, REFERENCE_HEAD]
    );
    assert!(before_expand.checksum_mismatches.is_empty());

    let head = new_runner.run().await?;
    assert_eq!(head.current_version, Some(REFERENCE_HEAD));
    assert_eq!(head.target_version, REFERENCE_HEAD);
    assert!(head.pending_versions.is_empty());
    assert!(head.unknown_versions.is_empty());

    assert_eq!(
        old_runner.verify_compatibility().await,
        Err(MigrationError::SchemaTooNew {
            current: REFERENCE_HEAD,
            maximum: PREVIOUS_REFERENCE_HEAD,
        })
    );
    let bridge_at_head = bridge_runner.verify_compatibility().await?;
    assert_eq!(bridge_at_head.current_version, Some(REFERENCE_HEAD));
    assert_eq!(bridge_at_head.target_version, PREVIOUS_REFERENCE_HEAD);
    assert_eq!(
        bridge_at_head.unknown_versions,
        vec![2_026_082_306, 2_026_082_307, REFERENCE_HEAD]
    );
    assert!(bridge_at_head.pending_versions.is_empty());
    assert!(bridge_at_head.checksum_mismatches.is_empty());
    assert!(bridge_at_head.history_gaps.is_empty());

    let mut connection = pool.acquire().await?;
    let restored_legacy = sqlx::query(
        r"
        SELECT id, name, created_at, updated_at, version
        FROM reference_records
        WHERE id = $1
        ",
    )
    .bind(legacy_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(restored_legacy.try_get::<String, _>("name")?, "legacy-v1");
    assert_eq!(restored_legacy.try_get::<i64, _>("version")?, 2);

    sqlx::query(
        r"
        INSERT INTO reference_records (id, name, created_at, updated_at)
        VALUES (
            $1,
            'head-created',
            TIMESTAMPTZ '2026-08-23 00:01:00+00',
            TIMESTAMPTZ '2026-08-23 00:01:00+00'
        )
        ",
    )
    .bind(head_id)
    .execute(&mut *connection)
    .await?;
    let head_row =
        sqlx::query("SELECT id, name, created_at, updated_at FROM reference_records WHERE id = $1")
            .bind(head_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(head_row.try_get::<String, _>("name")?, "head-created");
    let head_name: String = sqlx::query_scalar(
        r"
        UPDATE reference_records
        SET name = 'head-old-update', updated_at = updated_at + INTERVAL '1 second'
        WHERE id = $1
        RETURNING name
        ",
    )
    .bind(head_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(head_name, "head-old-update");
    let triggered_version: i64 =
        sqlx::query_scalar("SELECT version FROM reference_records WHERE id = $1")
            .bind(head_id)
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(triggered_version, 2);

    let repository_restored = sqlx::query(
        r"
        UPDATE reference_records
        SET name = 'head-repository-update', updated_at = updated_at + INTERVAL '1 second'
        WHERE id = $1 AND version = $2
        RETURNING id, name, created_at, updated_at, version
        ",
    )
    .bind(head_id)
    .bind(triggered_version)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(
        repository_restored.try_get::<String, _>("name")?,
        "head-repository-update"
    );
    assert_eq!(repository_restored.try_get::<i64, _>("version")?, 3);

    let first_page_name: String =
        sqlx::query_scalar("SELECT name FROM reference_records ORDER BY created_at, id LIMIT 1")
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(first_page_name, "legacy-v1");
    let second_page_name: String = sqlx::query_scalar(
        r"
        SELECT name
        FROM reference_records
        WHERE (created_at, id) > (
            SELECT created_at, id FROM reference_records WHERE id = $1
        )
        ORDER BY created_at, id
        LIMIT 1
        ",
    )
    .bind(legacy_id)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(second_page_name, "head-repository-update");

    let mut plan_transaction = connection.begin().await?;
    sqlx::query("SET LOCAL enable_seqscan = off")
        .execute(&mut *plan_transaction)
        .await?;
    let pagination_plan: Vec<String> = sqlx::query_scalar(
        r"
        EXPLAIN (COSTS OFF)
        SELECT id, name, created_at, updated_at, version
        FROM reference_records
        ORDER BY created_at, id
        LIMIT 1
        ",
    )
    .fetch_all(&mut *plan_transaction)
    .await?;
    assert!(
        pagination_plan
            .iter()
            .any(|line| line.contains("reference_records_created_at_id_idx")),
        "released pagination query must have a usable matching index"
    );
    plan_transaction.rollback().await?;

    let mut idempotency_transaction = connection.begin().await?;
    let claimed: Option<bool> = sqlx::query_scalar(
        r"
        INSERT INTO idempotency_records (
            principal_scope, tenant_scope, operation, idempotency_key, request_hash,
            status, expires_at, created_at
        )
        VALUES (
            'rolling-principal', NULL, 'reference.update', 'rolling-key', $1,
            'in_progress', clock_timestamp() + INTERVAL '1 minute', clock_timestamp()
        )
        ON CONFLICT (principal_scope, tenant_scope, operation, idempotency_key) DO NOTHING
        RETURNING TRUE
        ",
    )
    .bind(fingerprint.as_slice())
    .fetch_optional(&mut *idempotency_transaction)
    .await?;
    assert_eq!(claimed, Some(true));

    let completed: Option<String> = sqlx::query_scalar(
        r"
        UPDATE idempotency_records
        SET status = 'completed', response_status = 200,
            response_content_type = 'application/json', response_body = $2,
            completed_at = clock_timestamp()
        WHERE principal_scope = 'rolling-principal'
          AND tenant_scope IS NULL
          AND operation = 'reference.update'
          AND idempotency_key = 'rolling-key'
          AND request_hash = $1
          AND status = 'in_progress'
          AND expires_at > clock_timestamp()
        RETURNING status
        ",
    )
    .bind(fingerprint.as_slice())
    .bind(response_body.as_slice())
    .fetch_optional(&mut *idempotency_transaction)
    .await?;
    assert_eq!(completed.as_deref(), Some("completed"));

    let stored_response = sqlx::query(
        r"
        SELECT status, response_status, response_content_type, response_body
        FROM idempotency_records
        WHERE principal_scope = 'rolling-principal'
          AND tenant_scope IS NULL
          AND operation = 'reference.update'
          AND idempotency_key = 'rolling-key'
        ",
    )
    .fetch_one(&mut *idempotency_transaction)
    .await?;
    assert_eq!(stored_response.try_get::<String, _>("status")?, "completed");
    assert_eq!(stored_response.try_get::<i16, _>("response_status")?, 200);
    assert_eq!(
        stored_response.try_get::<Option<String>, _>("response_content_type")?,
        Some("application/json".to_owned())
    );
    assert_eq!(
        stored_response.try_get::<Vec<u8>, _>("response_body")?,
        response_body
    );

    let duplicate_claim: Option<bool> = sqlx::query_scalar(
        r"
        INSERT INTO idempotency_records (
            principal_scope, tenant_scope, operation, idempotency_key, request_hash,
            status, expires_at, created_at
        )
        VALUES (
            'rolling-principal', NULL, 'reference.update', 'rolling-key', $1,
            'in_progress', clock_timestamp() + INTERVAL '1 minute', clock_timestamp()
        )
        ON CONFLICT (principal_scope, tenant_scope, operation, idempotency_key) DO NOTHING
        RETURNING TRUE
        ",
    )
    .bind(fingerprint.as_slice())
    .fetch_optional(&mut *idempotency_transaction)
    .await?;
    assert_eq!(duplicate_claim, None);
    idempotency_transaction.commit().await?;

    let deleted_idempotency = sqlx::query("DELETE FROM idempotency_records")
        .execute(&mut *connection)
        .await?;
    assert_eq!(deleted_idempotency.rows_affected(), 1);
    let deleted_references = sqlx::query("DELETE FROM reference_records")
        .execute(&mut *connection)
        .await?;
    assert_eq!(deleted_references.rows_affected(), 2);
    drop(connection);

    Ok(())
}

#[tokio::test]
async fn reference_expand_requires_compatible_bridge_before_migration() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_released_history(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
