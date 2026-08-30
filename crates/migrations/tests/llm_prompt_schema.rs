//! PostgreSQL prompt-catalog allocation, schema, digest, and immutability contracts.

use std::{error::Error, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use sqlx::{Connection as _, PgConnection, postgres::PgQueryResult};

const FIRST_MIGRATION: i64 = 2_026_082_301;
const PROMPT_CATALOG_SCHEMA_VERSION: i64 = 2_026_082_804;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 4,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-llm-prompt-schema-test".to_owned(),
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
    expected_constraint: &str,
) -> Result<(), Box<dyn Error>> {
    let Err(error) = result else {
        return Err(format!("constraint {expected_constraint} accepted an invalid write").into());
    };
    let sqlx::Error::Database(database_error) = error else {
        return Err(format!("constraint {expected_constraint} returned {error}").into());
    };
    assert_eq!(database_error.code().as_deref(), Some("23514"));
    assert_eq!(database_error.constraint(), Some(expected_constraint));
    Ok(())
}

async fn insert_prompt_head(
    connection: &mut PgConnection,
    prompt_id: &str,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO llm_prompts \
         (prompt_id, latest_revision, row_version, created_at, updated_at) \
         VALUES ($1, 1, 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(prompt_id)
    .execute(connection)
    .await
}

async fn insert_revision(
    connection: &mut PgConnection,
    prompt_id: &str,
    revision: i64,
    status: &str,
    digest: &[u8],
    schema: &str,
    user_template: &str,
) -> Result<PgQueryResult, sqlx::Error> {
    sqlx::query(
        "INSERT INTO llm_prompt_revisions \
         (prompt_id, revision, status, content_digest, input_schema, system_template, \
          developer_template, user_template, owner_id, allowed_routes, allowed_tools, \
          data_classification, evaluation_sets, rollout_metadata, created_at, updated_at, \
          published_at, deprecated_at) \
         VALUES ($1, $2, $3, $4, $5::jsonb, 'Trusted system instruction', NULL, $6, 'omnius/ai', \
                 ARRAY['assistant.default']::text[], ARRAY['search']::text[], 'confidential', \
                 ARRAY['prompt-regression']::text[], '{\"cohort\": \"stable\"}'::jsonb, \
                 clock_timestamp(), clock_timestamp(), \
                 CASE WHEN $3 IN ('published', 'deprecated') THEN clock_timestamp() END, \
                 CASE WHEN $3 = 'deprecated' THEN clock_timestamp() END)",
    )
    .bind(prompt_id)
    .bind(revision)
    .bind(status)
    .bind(digest)
    .bind(schema)
    .bind(user_template)
    .execute(connection)
    .await
}

async fn migrate_to_prompt_catalog(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, PROMPT_CATALOG_SCHEMA_VERSION)?,
        migration_config(),
        DeploymentEnvironment::Test,
    )?;
    let head = runner.run().await?;
    assert_eq!(head.current_version, Some(PROMPT_CATALOG_SCHEMA_VERSION));
    assert!(head.pending_versions.is_empty());
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "one database fixture keeps prompt allocation and immutability transitions visible"
)]
async fn exercise_prompt_catalog_schema(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    migrate_to_prompt_catalog(pool).await?;
    let mut connection = pool.acquire().await?;

    let revision_columns: Vec<String> = sqlx::query_scalar(
        "SELECT column_name || ':' || data_type || ':' || is_nullable \
         FROM information_schema.columns WHERE table_schema = current_schema() \
           AND table_name = 'llm_prompt_revisions' ORDER BY ordinal_position",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert_eq!(
        revision_columns,
        [
            "prompt_id:text:NO",
            "revision:bigint:NO",
            "status:text:NO",
            "content_digest:bytea:NO",
            "input_schema:jsonb:NO",
            "system_template:text:YES",
            "developer_template:text:YES",
            "user_template:text:NO",
            "owner_id:text:NO",
            "allowed_routes:ARRAY:NO",
            "allowed_tools:ARRAY:NO",
            "data_classification:text:NO",
            "evaluation_sets:ARRAY:NO",
            "rollout_metadata:jsonb:NO",
            "created_at:timestamp with time zone:NO",
            "updated_at:timestamp with time zone:NO",
            "published_at:timestamp with time zone:YES",
            "deprecated_at:timestamp with time zone:YES",
        ]
    );

    let indexes: Vec<String> = sqlx::query_scalar(
        "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema() \
         AND tablename = 'llm_prompt_revisions' ORDER BY indexname",
    )
    .fetch_all(&mut *connection)
    .await?;
    assert!(indexes.contains(&"llm_prompt_revisions_owner_idx".to_owned()));
    assert!(indexes.contains(&"llm_prompt_revisions_published_idx".to_owned()));
    assert!(indexes.contains(&"llm_prompt_revisions_routes_idx".to_owned()));
    assert!(indexes.contains(&"llm_prompt_revisions_tools_idx".to_owned()));

    let invalid_initial_version = sqlx::query(
        "INSERT INTO llm_prompts \
         (prompt_id, latest_revision, row_version, created_at, updated_at) \
         VALUES ('invalid.head', 2, 1, clock_timestamp(), clock_timestamp())",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(invalid_initial_version, "llm_prompts_initial_version")?;

    let schema = r#"{
        "type": "object",
        "additionalProperties": false,
        "required": ["request"],
        "properties": {"request": {"type": "string", "maxLength": 64}}
    }"#;
    let digest = vec![7_u8; 32];
    let mut transaction = connection.begin().await?;
    insert_prompt_head(&mut transaction, "support.answer").await?;
    insert_revision(
        &mut transaction,
        "support.answer",
        1,
        "draft",
        &digest,
        schema,
        "Request: {{ request }}",
    )
    .await?;
    transaction.commit().await?;

    {
        let mut transaction = connection.begin().await?;
        insert_prompt_head(&mut transaction, "invalid.publish").await?;
        let result = insert_revision(
            &mut transaction,
            "invalid.publish",
            1,
            "published",
            &digest,
            schema,
            "Request",
        )
        .await;
        assert_database_constraint(result, "llm_prompt_revisions_insert_draft_only")?;
        transaction.rollback().await?;
    }

    {
        let mut transaction = connection.begin().await?;
        insert_prompt_head(&mut transaction, "invalid.schema").await?;
        let result = insert_revision(
            &mut transaction,
            "invalid.schema",
            1,
            "draft",
            &digest,
            r#"{"type":"object","properties":{"request":{"$ref":"https://example.invalid/schema"}}}"#,
            "Request",
        )
        .await;
        assert_database_constraint(result, "llm_prompt_revisions_input_schema_valid")?;
        transaction.rollback().await?;
    }

    {
        let mut transaction = connection.begin().await?;
        insert_prompt_head(&mut transaction, "invalid.required").await?;
        let result = insert_revision(
            &mut transaction,
            "invalid.required",
            1,
            "draft",
            &digest,
            r#"{"type":"object","properties":{"child":{"type":"object","required":"name"}}}"#,
            "Request",
        )
        .await;
        assert_database_constraint(result, "llm_prompt_revisions_input_schema_valid")?;
        transaction.rollback().await?;
    }

    {
        let mut transaction = connection.begin().await?;
        insert_prompt_head(&mut transaction, "invalid.digest").await?;
        let result = insert_revision(
            &mut transaction,
            "invalid.digest",
            1,
            "draft",
            &[9_u8; 31],
            schema,
            "Request",
        )
        .await;
        assert_database_constraint(result, "llm_prompt_revisions_digest_length")?;
        transaction.rollback().await?;
    }

    let skipped_head = sqlx::query(
        "UPDATE llm_prompts SET latest_revision = 3, row_version = row_version + 1, \
         updated_at = clock_timestamp() WHERE prompt_id = 'support.answer'",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(skipped_head, "llm_prompts_revision_progression")?;

    let mut transaction = connection.begin().await?;
    sqlx::query(
        "UPDATE llm_prompts SET latest_revision = 2, row_version = row_version + 1, \
         updated_at = clock_timestamp() WHERE prompt_id = 'support.answer'",
    )
    .execute(&mut *transaction)
    .await?;
    insert_revision(
        &mut transaction,
        "support.answer",
        2,
        "draft",
        &[8_u8; 32],
        schema,
        "Second revision",
    )
    .await?;
    transaction.commit().await?;

    let unbound_draft_change = sqlx::query(
        "UPDATE llm_prompt_revisions SET user_template = 'Missing digest update' \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        unbound_draft_change,
        "llm_prompt_revisions_draft_digest_binding",
    )?;

    sqlx::query(
        "UPDATE llm_prompt_revisions SET user_template = 'Replaced draft', \
         content_digest = $1, updated_at = clock_timestamp() \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .bind(vec![10_u8; 32])
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE llm_prompt_revisions SET status = 'published', \
         published_at = clock_timestamp(), updated_at = clock_timestamp() \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .execute(&mut *connection)
    .await?;

    let published_mutation = sqlx::query(
        "UPDATE llm_prompt_revisions SET user_template = 'Mutation rejected' \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(
        published_mutation,
        "llm_prompt_revisions_published_immutable",
    )?;

    let published_delete = sqlx::query(
        "DELETE FROM llm_prompt_revisions \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .execute(&mut *connection)
    .await;
    assert_database_constraint(published_delete, "llm_prompt_revisions_delete_forbidden")?;

    sqlx::query(
        "UPDATE llm_prompt_revisions SET status = 'deprecated', \
         deprecated_at = clock_timestamp(), updated_at = clock_timestamp() \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .execute(&mut *connection)
    .await?;
    let retained: (String, Vec<u8>, String) = sqlx::query_as(
        "SELECT status, content_digest, user_template FROM llm_prompt_revisions \
         WHERE prompt_id = 'support.answer' AND revision = 1",
    )
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(retained.0, "deprecated");
    assert_eq!(retained.1, vec![10_u8; 32]);
    assert_eq!(retained.2, "Replaced draft");
    Ok(())
}

#[tokio::test]
async fn prompt_catalog_schema_enforces_atomic_immutable_revisions() -> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let exercise_result = exercise_prompt_catalog_schema(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
