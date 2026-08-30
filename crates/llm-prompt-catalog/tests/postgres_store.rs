//! PostgreSQL prompt catalog lifecycle and concurrency contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    time::Duration,
};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_llm_prompt_catalog::{
    DataClassification, EvaluationSetId, OwnerId, PostgresPromptCatalogStore, PromptAccess,
    PromptBody, PromptCatalog, PromptCatalogStore, PromptId, PromptRevision, PromptRevisionNumber,
    PromptStatus, PromptStoreError, PromptTemplates, RouteId, ToolId,
};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use serde_json::json;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const PROMPT_CATALOG_SCHEMA_VERSION: i64 = 2_026_082_804;

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 6,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-llm-prompt-store-test".to_owned(),
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
    Ok(())
}

fn draft(
    prompt_id: &str,
    revision: u64,
    user_template: &str,
) -> Result<PromptRevision, Box<dyn Error>> {
    let templates = PromptTemplates::new(
        Some("Follow trusted policy exactly.".to_owned()),
        Some("Use only admitted tools.".to_owned()),
        user_template.to_owned(),
    )?;
    let access = PromptAccess::new(
        OwnerId::new("omnius/ai")?,
        BTreeSet::from([RouteId::new("assistant.default")?]),
        BTreeSet::from([ToolId::new("search")?]),
        DataClassification::Confidential,
        BTreeSet::from([EvaluationSetId::new("prompt-regression")?]),
        BTreeMap::from([("cohort".to_owned(), "stable".to_owned())]),
    )?;
    let body = PromptBody::new(
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["request"],
            "properties": {"request": {"type": "string", "maxLength": 64}}
        }),
        templates,
        access,
    )?;
    Ok(PromptRevision::new_draft(
        PromptId::new(prompt_id)?,
        PromptRevisionNumber::new(revision)?,
        body,
    )?)
}

async fn exercise_store(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    migrate_to_prompt_catalog(pool).await?;
    let store = PostgresPromptCatalogStore::new(pool.clone());
    let catalog = PromptCatalog::new(store.clone());
    let initial = draft("support.answer", 1, "Request: {{ request }}")?;
    let initial_digest = initial.content_digest();
    catalog.create_draft(initial.clone(), None).await?;
    assert_eq!(
        store.insert_draft(initial.clone(), None).await,
        Err(PromptStoreError::AlreadyExists)
    );

    let replacement = draft("support.answer", 1, "Bounded request: {{ request }}")?;
    let replacement_catalog = PromptCatalog::new(store.clone());
    let publish_catalog = PromptCatalog::new(store.clone());
    let (replace_result, publish_result) = tokio::join!(
        replacement_catalog.replace_draft(replacement, initial_digest),
        publish_catalog.publish(initial.id(), initial.revision(), initial_digest),
    );
    let published = match (replace_result, publish_result) {
        (Ok(replaced), Err(PromptStoreError::RevisionConflict)) => {
            catalog
                .publish(
                    replaced.id(),
                    replaced.revision(),
                    replaced.content_digest(),
                )
                .await?
        }
        (Err(PromptStoreError::Immutable), Ok(published)) => published,
        (replace_result, publish_result) => {
            return Err(format!(
                "unexpected replace/publish race: {replace_result:?}, {publish_result:?}"
            )
            .into());
        }
    };
    assert_eq!(published.status(), PromptStatus::Published);
    assert_eq!(
        catalog
            .replace_draft(
                draft("support.answer", 1, "Mutation after publication")?,
                published.content_digest(),
            )
            .await,
        Err(PromptStoreError::Immutable)
    );
    assert_eq!(
        catalog
            .publish(
                published.id(),
                published.revision(),
                published.content_digest(),
            )
            .await,
        Err(PromptStoreError::RevisionConflict)
    );

    let first_draft = draft("support.answer", 2, "Candidate A")?;
    let second_draft = draft("support.answer", 2, "Candidate B")?;
    let first_digest = first_draft.content_digest();
    let second_digest = second_draft.content_digest();
    let first_catalog = PromptCatalog::new(store.clone());
    let second_catalog = PromptCatalog::new(store.clone());
    let latest = PromptRevisionNumber::new(1)?;
    let (insert_a, insert_b) = tokio::join!(
        first_catalog.create_draft(first_draft, Some(latest)),
        second_catalog.create_draft(second_draft, Some(latest)),
    );
    let winning_digest = match (insert_a, insert_b) {
        (Ok(winner), Err(PromptStoreError::RevisionConflict))
        | (Err(PromptStoreError::RevisionConflict), Ok(winner)) => winner.content_digest(),
        (insert_a, insert_b) => {
            return Err(format!("unexpected revision race: {insert_a:?}, {insert_b:?}").into());
        }
    };
    assert!(winning_digest == first_digest || winning_digest == second_digest);
    let retained_second = store
        .get_revision(published.id(), PromptRevisionNumber::new(2)?)
        .await?;
    assert_eq!(retained_second.content_digest(), winning_digest);

    let deprecated = catalog
        .deprecate(
            published.id(),
            published.revision(),
            published.content_digest(),
        )
        .await?;
    assert_eq!(deprecated.status(), PromptStatus::Deprecated);
    let retained_first = store
        .get_revision(published.id(), published.revision())
        .await?;
    assert_eq!(retained_first, deprecated);

    Ok(())
}

#[tokio::test]
async fn postgres_store_serializes_draft_publish_and_revision_races() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_store(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
