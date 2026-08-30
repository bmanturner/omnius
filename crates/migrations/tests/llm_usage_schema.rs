//! Persistent LLM budget reservation and append-only accounting schema contracts.

use std::{error::Error, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{PostgresFixture, TestIds};
use sqlx::postgres::PgQueryResult;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const INSERT_RESERVED_HEADER: &str = r#"
    INSERT INTO llm_budget_reservations (
        tenant_id, reservation_id, idempotency_key, request_fingerprint,
        api_key_id, operation_id, scope_snapshot, estimate_snapshot, policy_snapshot,
        state_snapshot, state, usage_status, version,
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    ) VALUES (
        $1, $2, $3, decode(repeat('01', 32), 'hex'),
        'api-key', 'responses.create',
        jsonb_build_object(
            'tenant', $1::text, 'principal', NULL, 'api_key', 'api-key',
            'provider', NULL, 'model', NULL, 'route', NULL, 'tool', NULL,
            'operation', 'responses.create', 'job', NULL
        ),
        '{
            "primary":{"requests":1,"concurrent_streams":1,"tokens":0,"units":0,"tool_calls":0,"media_bytes":0,"cost_microunits":0},
            "retry":{"requests":0,"concurrent_streams":0,"tokens":0,"units":0,"tool_calls":0,"media_bytes":0,"cost_microunits":0},
            "repair":{"requests":0,"concurrent_streams":0,"tokens":0,"units":0,"tool_calls":0,"media_bytes":0,"cost_microunits":0},
            "tool":{"requests":0,"concurrent_streams":0,"tokens":0,"units":0,"tool_calls":0,"media_bytes":0,"cost_microunits":0}
        }'::jsonb,
        '[]'::jsonb, '"reserved"'::jsonb, 'reserved', 'estimated', 0,
        1, 1, 0, 0, 0, 0, 0
    )
"#;

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
        application_name: "omnius-llm-usage-schema-test".to_owned(),
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

fn assert_database_error(
    result: Result<PgQueryResult, sqlx::Error>,
    expected_code: &str,
    expected_constraint: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let Err(sqlx::Error::Database(error)) = result else {
        return Err("database accepted an invalid LLM usage mutation".into());
    };
    assert_eq!(error.code().as_deref(), Some(expected_code));
    if let Some(constraint) = expected_constraint {
        assert_eq!(error.constraint(), Some(constraint));
    }
    Ok(())
}

async fn insert_tenant(
    connection: &mut omnius_postgres::PostgresConnection,
    tenant_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO organizations \
         (id, name, status, version, owner_guard_version, created_at, updated_at) \
         VALUES ($1, 'LLM usage schema fixture', 'suspended', 1, 0, \
         TIMESTAMPTZ '2026-08-30 00:00:00+00', TIMESTAMPTZ '2026-08-30 00:00:00+00')",
    )
    .bind(tenant_id)
    .execute(&mut **connection)
    .await
    .map(|_| ())
}

#[expect(
    clippy::too_many_lines,
    reason = "one fixture keeps schema, tenant isolation, lifecycle, and append-only evidence visible"
)]
async fn exercise_llm_usage_schema(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let head = runner.run().await?;
    assert_eq!(head.current_version, Some(omnius_migrations::CURRENT_SCHEMA_VERSION));

    let ids = TestIds::default();
    let tenant_a = ids.uuid_v7()?;
    let tenant_b = ids.uuid_v7()?;
    let mut connection = pool.acquire().await?;
    insert_tenant(&mut connection, tenant_a).await?;
    insert_tenant(&mut connection, tenant_b).await?;

    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = current_schema() \
         AND table_name IN ('llm_budget_reservations','llm_usage_ledger','llm_cost_adjustments') \
         ORDER BY table_name",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        tables,
        [
            "llm_budget_reservations",
            "llm_cost_adjustments",
            "llm_usage_ledger"
        ]
    );

    let aggregate_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes \
         WHERE schemaname = current_schema() \
         AND tablename = 'llm_budget_reservations' \
         AND indexname LIKE '%_active_totals_idx' ORDER BY indexname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(aggregate_indexes.len(), 9);
    assert!(aggregate_indexes.iter().any(|name| name.contains("api_key")));
    assert!(aggregate_indexes.iter().any(|name| name.contains("operation")));

    sqlx::query(INSERT_RESERVED_HEADER)
        .bind(tenant_a)
        .bind("reservation-shared")
        .bind("idempotency-shared")
        .execute(&mut *connection)
        .await?;
    sqlx::query(INSERT_RESERVED_HEADER)
        .bind(tenant_b)
        .bind("reservation-shared")
        .bind("idempotency-shared")
        .execute(&mut *connection)
        .await?;

    let tenant_isolated_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM llm_budget_reservations \
         WHERE reservation_id = 'reservation-shared'",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(tenant_isolated_count, 2);

    let duplicate_idempotency = sqlx::query(INSERT_RESERVED_HEADER)
        .bind(tenant_a)
        .bind("reservation-other")
        .bind("idempotency-shared")
        .execute(&mut *connection)
        .await;
    assert_database_error(
        duplicate_idempotency,
        "23505",
        Some("llm_budget_reservations_tenant_idempotency_key"),
    )?;

    let negative_total = sqlx::query(INSERT_RESERVED_HEADER)
        .bind(tenant_a)
        .bind("reservation-negative")
        .bind("idempotency-negative")
        .execute(&mut *connection)
        .await?;
    assert_eq!(negative_total.rows_affected(), 1);
    let invalid_total = sqlx::query(
        "UPDATE llm_budget_reservations SET version = 1, state = 'released', \
         state_snapshot = '\"released\"'::jsonb, effective_requests = -1, \
         effective_concurrent_streams = 0, effective_tokens = 0, effective_units = 0, \
         effective_tool_calls = 0, effective_media_bytes = 0, effective_cost_microunits = 0, \
         updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-negative'",
    )
    .bind(tenant_a)
    .execute(&mut *connection)
    .await;
    assert_database_error(
        invalid_total,
        "23514",
        Some("llm_budget_reservations_effective_values_valid"),
    )?;

    let lifecycle = sqlx::query(
        "UPDATE llm_budget_reservations SET version = 1, state = 'released', \
         state_snapshot = '\"released\"'::jsonb, \
         effective_requests = 0, effective_concurrent_streams = 0, effective_tokens = 0, \
         effective_units = 0, effective_tool_calls = 0, effective_media_bytes = 0, \
         effective_cost_microunits = 0, updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-shared' AND version = 0",
    )
    .bind(tenant_a)
    .execute(&mut *connection)
    .await?;
    assert_eq!(lifecycle.rows_affected(), 1);
    let stale = sqlx::query(
        "UPDATE llm_budget_reservations SET updated_at = clock_timestamp() \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-shared' AND version = 0",
    )
    .bind(tenant_a)
    .execute(&mut *connection)
    .await?;
    assert_eq!(stale.rows_affected(), 0);

    sqlx::query(
        "INSERT INTO llm_usage_ledger (
            tenant_id,reservation_id,version,attribution,event_kind,state,usage_status,event_snapshot,
            effective_requests,effective_concurrent_streams,effective_tokens,effective_units,
            effective_tool_calls,effective_media_bytes,effective_cost_microunits,
            delta_requests,delta_concurrent_streams,delta_tokens,delta_units,
            delta_tool_calls,delta_media_bytes,delta_cost_microunits
         ) VALUES ($1,'reservation-shared',0,'primary','reserved','reserved','estimated','{}'::jsonb,
            1,1,0,0,0,0,0,1,1,0,0,0,0,0)",
    )
    .bind(tenant_b)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "INSERT INTO llm_cost_adjustments (
            tenant_id,reservation_id,version,attribution,basis,
            previous_cost_microunits,new_cost_microunits,delta_cost_microunits
         ) VALUES ($1,'reservation-shared',0,'primary','reservation',0,0,0)",
    )
    .bind(tenant_b)
    .execute(&mut *connection)
    .await?;

    let mutate_fact = sqlx::query(
        "UPDATE llm_usage_ledger SET effective_requests = 2 \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-shared'",
    )
    .bind(tenant_b)
    .execute(&mut *connection)
    .await;
    assert_database_error(mutate_fact, "55000", None)?;
    let delete_cost = sqlx::query(
        "DELETE FROM llm_cost_adjustments \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-shared'",
    )
    .bind(tenant_b)
    .execute(&mut *connection)
    .await;
    assert_database_error(delete_cost, "55000", None)?;
    let delete_header = sqlx::query(
        "DELETE FROM llm_budget_reservations \
         WHERE tenant_id = $1 AND reservation_id = 'reservation-shared'",
    )
    .bind(tenant_b)
    .execute(&mut *connection)
    .await;
    assert_database_error(delete_header, "55000", None)?;

    drop(connection);
    Ok(())
}

#[tokio::test]
async fn embedded_head_enforces_llm_usage_accounting_invariants() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_llm_usage_schema(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
