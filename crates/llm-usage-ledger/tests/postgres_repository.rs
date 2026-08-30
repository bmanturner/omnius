//! PostgreSQL usage-ledger atomicity and tenant-boundary contracts.

use std::{error::Error, sync::Arc, time::Duration};

use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_llm_usage_ledger::{
    BudgetCeilings, BudgetDimension, BudgetPolicy, BudgetScope, CostMicrounits, IdempotencyKey,
    LedgerError, LedgerVersion, PostgresUsageLedgerRepository, RequestFingerprint, ReservationId,
    ReservationRequest, TenantId, UsageAmount, UsageBreakdown, UsageEvidence, UsageLedger,
    UsageLedgerRepository, UsageVector,
};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::{PostgresFixture, TestIds};
use uuid::Uuid;

const FIRST_MIGRATION: i64 = 2_026_082_301;

fn retry_config() -> TransactionRetryConfig {
    TransactionRetryConfig {
        max_attempts: 5,
        base_delay: Duration::from_millis(5),
        max_delay: Duration::from_millis(50),
        max_jitter: Duration::from_millis(5),
        isolation: TransactionIsolation::Serializable,
    }
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 8,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-llm-usage-repository-test".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: retry_config(),
    }
}

fn request(
    tenant: Uuid,
    id: &str,
    key: &str,
    fingerprint: u8,
    maximum_requests: u64,
) -> Result<ReservationRequest, Box<dyn Error>> {
    Ok(ReservationRequest::new(
        ReservationId::new(id)?,
        IdempotencyKey::new(key)?,
        RequestFingerprint::new([fingerprint; 32]),
        BudgetScope::new(TenantId::new(&tenant.to_string())?),
        UsageBreakdown::primary(
            UsageVector::zero()
                .with_requests(UsageAmount::ONE)
                .with_concurrent_streams(UsageAmount::ONE)
                .with_tokens(UsageAmount::new(10))
                .with_cost(CostMicrounits::new(25)),
        ),
        vec![BudgetPolicy::new(
            BudgetDimension::Tenant,
            BudgetCeilings::none().with_requests(UsageAmount::new(maximum_requests)),
        )],
    )?)
}

async fn insert_tenant(pool: &PostgresPool, tenant: Uuid) -> Result<(), Box<dyn Error>> {
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO organizations \
         (id,name,status,version,owner_guard_version,created_at,updated_at) \
         VALUES ($1,'LLM repository fixture','suspended',1,0,clock_timestamp(),clock_timestamp())",
    )
    .bind(tenant)
    .execute(&mut *connection)
    .await?;
    Ok(())
}

async fn exercise_repository(pool: &PostgresPool) -> Result<(), Box<dyn Error>> {
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;

    let ids = TestIds::default();
    let tenant_a = ids.uuid_v7()?;
    let tenant_b = ids.uuid_v7()?;
    let quota_tenant = ids.uuid_v7()?;
    insert_tenant(pool, tenant_a).await?;
    insert_tenant(pool, tenant_b).await?;
    insert_tenant(pool, quota_tenant).await?;

    let repository = Arc::new(PostgresUsageLedgerRepository::new(
        pool.clone(),
        retry_config(),
    )?);
    let ledger = UsageLedger::new(Arc::clone(&repository));

    let isolated_a = request(tenant_a, "shared-reservation", "shared-key", 1, 1)?;
    let isolated_b = request(tenant_b, "shared-reservation", "shared-key", 1, 1)?;
    assert!(!ledger.reserve(&isolated_a).await?.replayed());
    assert!(!ledger.reserve(&isolated_b).await?.replayed());
    assert!(ledger.reserve(&isolated_a).await?.replayed());
    assert!(
        repository
            .load(isolated_a.scope().tenant(), isolated_a.id())
            .await?
            .is_some()
    );

    let quota_a = request(quota_tenant, "quota-a", "quota-key-a", 2, 1)?;
    let quota_b = request(quota_tenant, "quota-b", "quota-key-b", 3, 1)?;
    let (left, right) = tokio::join!(ledger.reserve(&quota_a), ledger.reserve(&quota_b));
    assert_ne!(left.is_ok(), right.is_ok());
    assert!(matches!(
        left.as_ref().err().or_else(|| right.as_ref().err()),
        Some(LedgerError::BudgetExhausted(_))
    ));

    let lifecycle = request(tenant_a, "lifecycle", "lifecycle-key", 4, 5)?;
    ledger.reserve(&lifecycle).await?;
    let committed = ledger
        .commit(
            lifecycle.scope().tenant(),
            lifecycle.id(),
            UsageEvidence::Missing,
        )
        .await?;
    assert_eq!(committed.reservation().version(), LedgerVersion::new(1));
    assert!(matches!(
        ledger
            .release(lifecycle.scope().tenant(), lifecycle.id())
            .await,
        Err(LedgerError::TransitionConflict)
    ));
    assert!(
        repository
            .event_at(
                lifecycle.scope().tenant(),
                lifecycle.id(),
                LedgerVersion::new(1),
            )
            .await?
            .is_some()
    );

    let mut connection = pool.acquire().await?;
    let fact_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM llm_usage_ledger \
         WHERE tenant_id = $1 AND reservation_id = 'lifecycle'",
    )
    .bind(tenant_a)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(fact_count, 8);
    let cost_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM llm_cost_adjustments \
         WHERE tenant_id = $1 AND reservation_id = 'lifecycle'",
    )
    .bind(tenant_a)
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(cost_count, 8);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_repository_enforces_atomic_tenant_quota_and_cas_contracts()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let exercise_result = exercise_repository(&pool).await;
    let close_result = pool.close().await;
    let cleanup_result = fixture.cleanup().await;

    exercise_result?;
    close_result?;
    cleanup_result?;
    Ok(())
}
