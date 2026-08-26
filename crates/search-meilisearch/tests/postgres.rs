//! PostgreSQL contracts for versioned reindex state and fenced projection replay.

use std::{collections::BTreeMap, error::Error, sync::Arc, time::Duration};

use rsk_auth_core::{SubjectId, TenantId};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_search_meilisearch::{
    FieldName, IndexAlias, IndexSchema, PostgresSearchStore, ProjectionClaim,
    ProjectionClaimContext, ProjectionClaimRequest, ProjectionDocument, ProjectionLedger,
    ProjectionMutation, ProjectionStoreError, ReindexCoordinator, ReindexCursor, ReindexStatus,
    ReindexStore, SearchLimits, SearchMeilisearchConfig, SourceId, SourceRevision,
    testing::FakeSearchProvider,
};
use rsk_test_support::PostgresFixture;
use serde_json::json;
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const SEARCH_HEAD: i64 = 2_026_082_320;

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
    tenant: TenantId,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "rsk-search-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
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

fn search_config() -> Result<SearchMeilisearchConfig, Box<dyn Error>> {
    Ok(SearchMeilisearchConfig {
        endpoint: Url::parse("http://127.0.0.1:7700")?,
        api_key: SecretString::from("postgres-contract-key".to_owned()),
        index_prefix: "postgres_contract".to_owned(),
        provider_timeout: Duration::from_secs(2),
        task_poll_interval: Duration::from_millis(20),
        stale_after: Duration::from_secs(60),
        projection_lease: Duration::from_secs(3),
        limits: SearchLimits::default(),
    })
}

async fn database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, SEARCH_HEAD)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(15),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    let owner = SubjectId::new();
    let tenant = TenantId::new();
    let now = OffsetDateTime::now_utc();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO public.users (id, created_at) VALUES ($1, $2)")
        .bind(owner.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO public.organizations \
         (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, 'Search tenant', 'suspended', 1, $2, $2, NULL)",
    )
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO public.memberships \
         (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(owner.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE public.organizations \
         SET status = 'active', version = 2, updated_at = $2 WHERE id = $1",
    )
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(TestDatabase {
        pool,
        fixture,
        tenant,
    })
}

fn schema() -> Result<IndexSchema, Box<dyn Error>> {
    Ok(IndexSchema::new(
        IndexAlias::new("records")?,
        4,
        vec![FieldName::new("title")?],
        vec![FieldName::new("status")?],
    )?)
}

async fn exercise_reindex_cursor_and_alias(
    store: &PostgresSearchStore,
    schema: &IndexSchema,
) -> Result<(), Box<dyn Error>> {
    let preparing = store.register(schema).await?;
    assert_eq!(preparing.status, ReindexStatus::Preparing);
    assert_eq!(store.register(schema).await?, preparing);
    let backfilling = store.begin_backfill(schema, preparing.generation).await?;
    let cursor = ReindexCursor::new("tenant-page:0001")?;
    let advanced = store
        .advance(schema, backfilling.generation, &cursor, 25)
        .await?;
    assert_eq!(advanced.cursor.as_ref(), Some(&cursor));
    assert_eq!(advanced.projected_count, 25);
    let ready = store.mark_ready(schema, advanced.generation).await?;
    assert_eq!(ready.status, ReindexStatus::Ready);
    let active = store.activate(schema, ready.generation).await?;
    assert_eq!(active.status, ReindexStatus::Active);
    assert!(store.freshness(schema.alias()).await?.activated_at <= OffsetDateTime::now_utc());
    Ok(())
}

async fn exercise_projection_ledger_and_fence(
    database: &TestDatabase,
    store: &PostgresSearchStore,
    schema: &IndexSchema,
) -> Result<(), Box<dyn Error>> {
    let source = SourceId::new("record-one")?;
    let occurred_at = OffsetDateTime::now_utc().replace_nanosecond(0)?;
    let context =
        |event_id| ProjectionClaimContext::new(event_id, database.tenant, schema, occurred_at);
    let event = Uuid::now_v7();
    let first = store
        .claim(ProjectionClaimRequest::upsert(
            &context(event)?,
            &source,
            SourceRevision::new(2)?,
            Duration::from_secs(5),
        )?)
        .await?;
    let lease = acquired_token(first, "initial")?;
    assert_eq!(
        store
            .claim(ProjectionClaimRequest::upsert(
                &context(event)?,
                &source,
                SourceRevision::new(2)?,
                Duration::from_secs(5),
            )?)
            .await?,
        ProjectionClaim::Busy
    );
    store.complete(event, lease).await?;
    assert_eq!(
        store
            .claim(ProjectionClaimRequest::upsert(
                &context(event)?,
                &source,
                SourceRevision::new(2)?,
                Duration::from_secs(5),
            )?)
            .await?,
        ProjectionClaim::AlreadyApplied
    );
    let older_event = Uuid::now_v7();
    assert_eq!(
        store
            .claim(ProjectionClaimRequest::upsert(
                &context(older_event)?,
                &source,
                SourceRevision::new(1)?,
                Duration::from_secs(5),
            )?)
            .await?,
        ProjectionClaim::Superseded
    );
    let conflicting = SourceId::new("another-record")?;
    assert_eq!(
        store
            .claim(ProjectionClaimRequest::delete(
                &context(event)?,
                &conflicting,
                SourceRevision::new(3)?,
                Duration::from_secs(5),
            )?)
            .await,
        Err(ProjectionStoreError::IdentityConflict)
    );
    exercise_repaired_replay(database, store, schema, occurred_at).await?;
    assert_control_state_has_no_document_content(database).await
}

async fn exercise_repaired_replay(
    database: &TestDatabase,
    store: &PostgresSearchStore,
    schema: &IndexSchema,
    occurred_at: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let event = Uuid::now_v7();
    let source = SourceId::new("record-replay")?;
    let context = ProjectionClaimContext::new(event, database.tenant, schema, occurred_at)?;
    let claim = store
        .claim(ProjectionClaimRequest::upsert(
            &context,
            &source,
            SourceRevision::new(1)?,
            Duration::from_secs(5),
        )?)
        .await?;
    store
        .fail(
            event,
            acquired_token(claim, "replay")?,
            "search_provider_unavailable",
        )
        .await?;
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE public.search_projection_events SET attempt_count = 100 \
         WHERE event_id = $1 AND index_alias = $2 AND schema_version = $3",
    )
    .bind(event)
    .bind(schema.alias().as_str())
    .bind(i32::try_from(schema.version())?)
    .execute(&mut *connection)
    .await?;
    drop(connection);
    let replayed = store
        .claim(ProjectionClaimRequest::upsert(
            &context,
            &source,
            SourceRevision::new(1)?,
            Duration::from_secs(5),
        )?)
        .await?;
    store
        .complete(event, acquired_token(replayed, "repaired replay")?)
        .await?;
    Ok(())
}

async fn assert_control_state_has_no_document_content(
    database: &TestDatabase,
) -> Result<(), Box<dyn Error>> {
    let mut connection = database.pool.acquire().await?;
    let control_columns: Vec<String> = sqlx::query(
        "SELECT column_name FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name IN \
             ('search_index_versions', 'search_index_aliases', 'search_projection_events') \
         ORDER BY column_name",
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .map(|row| row.try_get("column_name"))
    .collect::<Result<_, _>>()?;
    assert!(!control_columns.iter().any(|column| {
        column.contains("payload") || column.contains("document") || column.contains("fields")
    }));
    drop(connection);
    Ok(())
}

fn acquired_token(claim: ProjectionClaim, phase: &str) -> Result<Uuid, Box<dyn Error>> {
    match claim {
        ProjectionClaim::Acquired { lease_token } => Ok(lease_token),
        other => Err(format!("unexpected {phase} claim: {other:?}").into()),
    }
}

#[tokio::test]
async fn reindex_cursor_alias_and_projection_ledger_are_restartable_and_fenced()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let store = PostgresSearchStore::new(database.pool.clone());
    let schema = schema()?;
    exercise_reindex_cursor_and_alias(&store, &schema).await?;
    exercise_projection_ledger_and_fence(&database, &store, &schema).await?;
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn fresh_alias_accepts_backfill_before_activation() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let store = Arc::new(PostgresSearchStore::new(database.pool.clone()));
    let provider = Arc::new(FakeSearchProvider::default());
    let schema = IndexSchema::new(
        IndexAlias::new("fresh_records")?,
        1,
        vec![FieldName::new("title")?],
        Vec::new(),
    )?;
    let coordinator =
        ReindexCoordinator::new(provider, store.clone(), store.clone(), &search_config()?)?;
    let backfilling = coordinator.begin(&schema).await?;
    assert_eq!(backfilling.status, ReindexStatus::Backfilling);
    let mut fields = BTreeMap::new();
    fields.insert(
        "title".to_owned(),
        json!("backfilled before alias activation"),
    );
    coordinator
        .project_backfill(
            &schema,
            database.tenant,
            &ProjectionMutation::Upsert(ProjectionDocument::new(
                SourceId::new("fresh-record")?,
                SourceRevision::new(1)?,
                fields,
            )?),
        )
        .await?;
    let ready = coordinator
        .mark_ready(&schema, backfilling.generation)
        .await?;
    let active = coordinator.activate(&schema).await?;
    assert_eq!(ready.status, ReindexStatus::Ready);
    assert_eq!(active.status, ReindexStatus::Active);
    database.fixture.cleanup().await?;
    Ok(())
}
