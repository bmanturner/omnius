//! PostgreSQL concurrency, replay, monotonic fence, reconciliation, audit, and entitlement proof.

use std::{error::Error, sync::Arc, time::Duration};

use omnius_audit::{AuditConfig, PostgresAuditSink};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_billing::{
    BillingConfig, BillingReconciler, BillingStanding, EntitlementGrant, EntitlementKey,
    EntitlementValue, EventEnqueueOutcome, FakeBillingAdapter, MeterKey, NewUsageRecord,
    PlanDefinition, PlanKey, PostgresBillingStore, ProviderCustomer, ProviderEvent,
    ProviderEventId, ProviderEventSequence, ProviderId, ProviderObjectId, ProviderPriceMapping,
    ProviderRevision, ProviderSnapshot, ProviderStateFacts, ProviderStateKey, ProviderStateText,
    ProviderStateValue, ProviderSubscription, RepairEnqueueOutcome, RepairIdempotencyKey,
    SnapshotApplyOutcome, UsageIdempotencyKey, UsageRecordOutcome, WebhookHandler,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_outbox::{OutboxConfig, PostgresOutbox};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_runtime::Supervisor;
use omnius_tenancy::{TenancyConfig, TenancyStore, TenantContext};
use omnius_test_support::PostgresFixture;
use omnius_webhooks_inbound::{PostgresReceiptStore, ReceiptId};
use serde_json::json;
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

const FIRST_MIGRATION: i64 = 2_026_082_301;

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
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
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "omnius-billing-test".to_owned(),
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
        SchemaVersionRange::new(FIRST_MIGRATION, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(30),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

fn billing_store(pool: PostgresPool) -> Result<PostgresBillingStore, Box<dyn Error>> {
    let config = BillingConfig {
        enabled: true,
        ..BillingConfig::default()
    };
    Ok(PostgresBillingStore::new(
        pool.clone(),
        PostgresAuditSink::new(AuditConfig::default()),
        PostgresOutbox::new(pool, OutboxConfig::default())?,
        config,
    )?)
}

async fn tenant_context(pool: &PostgresPool, name: &str) -> Result<TenantContext, Box<dyn Error>> {
    let subject_id = SubjectId::new();
    let tenant_id = TenantId::new();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO users (id, created_at) VALUES ($1, clock_timestamp())")
        .bind(subject_id.as_uuid())
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO organizations \
            (id, name, status, version, created_at, updated_at, deleted_at) \
         VALUES ($1, $2, 'suspended', 1, clock_timestamp(), clock_timestamp(), NULL)",
    )
    .bind(tenant_id.as_uuid())
    .bind(name)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO memberships \
            (organization_id, user_id, role, status, grant_version, created_at, updated_at) \
         VALUES ($1, $2, 'owner', 'active', 1, clock_timestamp(), clock_timestamp())",
    )
    .bind(tenant_id.as_uuid())
    .bind(subject_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE organizations SET status = 'active', updated_at = clock_timestamp() WHERE id = $1",
    )
    .bind(tenant_id.as_uuid())
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let tenancy = TenancyStore::new(pool.clone(), &TenancyConfig::default())?;
    let principal = Principal::new(
        subject_id,
        PrincipalKind::User,
        None,
        AuthMethod::Session,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal1,
        Vec::new(),
    )?;
    Ok(tenancy
        .resolve_tenant_context(&principal, tenant_id)
        .await?)
}

fn provider() -> Result<ProviderId, Box<dyn Error>> {
    Ok(ProviderId::parse("fixture")?)
}

fn active_snapshot(
    tenant_id: TenantId,
    provider: ProviderId,
    revision: u64,
    observed_at: OffsetDateTime,
    customer_state: ProviderStateFacts,
) -> Result<ProviderSnapshot, Box<dyn Error>> {
    let customer_id = ProviderObjectId::parse("customer_one")?;
    let customer = ProviderCustomer::new(customer_id.clone(), customer_state);
    let subscription = ProviderSubscription::new(
        ProviderObjectId::parse("subscription_one")?,
        customer_id,
        ProviderObjectId::parse("price_pro")?,
        BillingStanding::InGoodStanding,
        None,
        None,
        ProviderStateFacts::default(),
    )?;
    Ok(ProviderSnapshot::new(
        tenant_id,
        provider,
        ProviderRevision::new(revision)?,
        observed_at,
        customer,
        vec![subscription],
        Vec::new(),
    )?)
}

async fn seed_customer(
    store: &PostgresBillingStore,
    context: &TenantContext,
    provider: ProviderId,
) -> Result<(), Box<dyn Error>> {
    store
        .put_plan(&PlanDefinition::new(
            PlanKey::parse("pro")?,
            true,
            vec![EntitlementGrant::new(
                EntitlementKey::parse("projects.enabled")?,
                EntitlementValue::Boolean(true),
            )?],
        )?)
        .await?;
    store
        .put_price_mapping(&ProviderPriceMapping::new(
            provider.clone(),
            ProviderObjectId::parse("price_pro")?,
            PlanKey::parse("pro")?,
        ))
        .await?;
    let task = match store
        .request_repair(
            context,
            &provider,
            &RepairIdempotencyKey::parse("initial-reconcile")?,
        )
        .await?
    {
        RepairEnqueueOutcome::Enqueued(id) | RepairEnqueueOutcome::Duplicate(id) => id,
    };
    let claim = store
        .claim_task(task)
        .await?
        .ok_or("initial reconciliation was not claimable")?;
    let snapshot = active_snapshot(
        context.membership().organization_id,
        provider,
        1,
        OffsetDateTime::now_utc() - time::Duration::seconds(1),
        ProviderStateFacts::default(),
    )?;
    assert!(matches!(
        store.apply_snapshot(&claim, &snapshot).await?,
        SnapshotApplyOutcome::Applied { .. }
    ));
    Ok(())
}

async fn insert_receipt(
    pool: &PostgresPool,
    tenant_id: TenantId,
    event_id: &str,
    marker: u8,
) -> Result<ReceiptId, Box<dyn Error>> {
    let id = ReceiptId::new();
    let now = OffsetDateTime::now_utc();
    let retain_until = now + time::Duration::days(1);
    let mut connection = pool.acquire().await?;
    sqlx::query(
        "INSERT INTO webhook_receipts ( \
            id, provider, provider_scope, event_id, content_digest, event_type, event_version, \
            parsed_payload, verified_at, provider_timestamp, status, available_at, retain_until, \
            created_at, updated_at \
         ) VALUES ($1, 'fixture', $2, $3, $4, 'billing.changed', 1, $5, \
            clock_timestamp(), $6, 'pending', clock_timestamp(), $7, \
            clock_timestamp(), clock_timestamp())",
    )
    .bind(id.as_uuid())
    .bind(tenant_id.to_string())
    .bind(event_id)
    .bind(vec![marker; 32])
    .bind(json!({"tenant_id": tenant_id, "event_sequence": u64::from(marker)}))
    .bind(now)
    .bind(retain_until)
    .execute(&mut *connection)
    .await?;
    Ok(id)
}

#[tokio::test]
async fn concurrent_webhook_replay_commits_one_task_and_conflicts_fail_closed()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let context = tenant_context(&database.pool, "Billing replay tenant").await?;
    let tenant_id = context.membership().organization_id;
    let store = billing_store(database.pool.clone())?;
    let provider = provider()?;
    let receipt = insert_receipt(&database.pool, tenant_id, "event_ten", 10).await?;
    let event = ProviderEvent::new(
        tenant_id,
        ProviderEventId::parse("event_ten")?,
        ProviderEventSequence::new(10)?,
    );
    let first_store = store.clone();
    let second_store = store.clone();
    let first_provider = provider.clone();
    let second_provider = provider.clone();
    let first_event = event.clone();
    let second_event = event.clone();
    let (first, second) = tokio::join!(
        first_store.enqueue_verified_event(&first_provider, &first_event, receipt, [7; 32]),
        second_store.enqueue_verified_event(&second_provider, &second_event, receipt, [7; 32]),
    );
    let outcomes = [first?, second?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EventEnqueueOutcome::Enqueued(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EventEnqueueOutcome::Duplicate(_)))
            .count(),
        1
    );

    assert_eq!(
        store
            .enqueue_verified_event(&provider, &event, receipt, [8; 32])
            .await?,
        EventEnqueueOutcome::Conflict
    );
    let old_receipt = insert_receipt(&database.pool, tenant_id, "event_nine", 9).await?;
    assert_eq!(
        store
            .enqueue_verified_event(
                &provider,
                &ProviderEvent::new(
                    tenant_id,
                    ProviderEventId::parse("event_nine")?,
                    ProviderEventSequence::new(9)?,
                ),
                old_receipt,
                [9; 32],
            )
            .await?,
        EventEnqueueOutcome::OutOfOrder
    );

    let mut connection = database.pool.acquire().await?;
    let task_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM billing_reconciliation_tasks \
         WHERE tenant_id = $1 AND reason = 'webhook'",
    )
    .bind(tenant_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(task_count, 1);
    Ok(())
}

#[tokio::test]
async fn concurrent_usage_replay_is_idempotent_and_conflicting_reuse_does_not_mutate()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let context = tenant_context(&database.pool, "Billing usage tenant").await?;
    let store = billing_store(database.pool.clone())?;
    let provider = provider()?;
    seed_customer(&store, &context, provider.clone()).await?;
    let occurred_at = OffsetDateTime::now_utc();
    let usage = NewUsageRecord::new(
        MeterKey::parse("api.requests")?,
        UsageIdempotencyKey::parse("usage-concurrent")?,
        10,
        occurred_at,
    )?;
    let first_store = store.clone();
    let second_store = store.clone();
    let first_context = context.clone();
    let second_context = context.clone();
    let first_provider = provider.clone();
    let second_provider = provider.clone();
    let first_usage = usage.clone();
    let second_usage = usage.clone();
    let (first, second) = tokio::join!(
        first_store.record_usage(&first_context, &first_provider, &first_usage),
        second_store.record_usage(&second_context, &second_provider, &second_usage),
    );
    let outcomes = [first?, second?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, UsageRecordOutcome::Recorded(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, UsageRecordOutcome::Duplicate(_)))
            .count(),
        1
    );
    let conflict = NewUsageRecord::new(
        MeterKey::parse("api.requests")?,
        UsageIdempotencyKey::parse("usage-concurrent")?,
        11,
        occurred_at,
    )?;
    assert_eq!(
        store.record_usage(&context, &provider, &conflict).await?,
        UsageRecordOutcome::Conflict
    );
    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query(
        "SELECT count(*) AS count, max(quantity) AS quantity FROM billing_usage \
         WHERE tenant_id = $1 AND meter_key = 'api.requests'",
    )
    .bind(context.membership().organization_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.try_get::<i64, _>("count")?, 1);
    assert_eq!(row.try_get::<i64, _>("quantity")?, 10);
    Ok(())
}

#[tokio::test]
async fn snapshot_revision_conflict_preserves_reconciled_entitlements_and_audits_publish()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let context = tenant_context(&database.pool, "Billing entitlement tenant").await?;
    let tenant_id = context.membership().organization_id;
    let store = billing_store(database.pool.clone())?;
    let provider = provider()?;
    seed_customer(&store, &context, provider.clone()).await?;
    let entitlements = store.entitlements(&context).await?;
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].value(), EntitlementValue::Boolean(true));

    let second_task = match store
        .request_repair(
            &context,
            &provider,
            &RepairIdempotencyKey::parse("conflicting-reconcile")?,
        )
        .await?
    {
        RepairEnqueueOutcome::Enqueued(id) | RepairEnqueueOutcome::Duplicate(id) => id,
    };
    let second_claim = store
        .claim_task(second_task)
        .await?
        .ok_or("conflicting reconciliation was not claimable")?;
    let changed_state = ProviderStateFacts::new([(
        ProviderStateKey::parse("fixture.status")?,
        ProviderStateValue::Text(ProviderStateText::parse("changed")?),
    )])?;
    let conflict = active_snapshot(
        tenant_id,
        provider,
        1,
        OffsetDateTime::now_utc(),
        changed_state,
    )?;
    assert_eq!(
        store.apply_snapshot(&second_claim, &conflict).await?,
        SnapshotApplyOutcome::Conflict
    );
    assert_eq!(store.entitlements(&context).await?, entitlements);

    let mut connection = database.pool.acquire().await?;
    let published_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE effective_tenant_id = $1 \
         AND event_type = 'billing.reconciliation.published'",
    )
    .bind(tenant_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    let outbox_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM outbox_events WHERE tenant_id = $1 \
         AND event_type = 'billing.entitlements_reconciled.v1'",
    )
    .bind(tenant_id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(published_audits, 1);
    assert_eq!(outbox_events, 1);
    Ok(())
}

#[tokio::test]
async fn verified_inbound_receipt_reconciles_through_webhook_handler_contract()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let context = tenant_context(&database.pool, "Billing webhook tenant").await?;
    let tenant_id = context.membership().organization_id;
    let store = billing_store(database.pool.clone())?;
    let provider = provider()?;
    store
        .put_plan(&PlanDefinition::new(
            PlanKey::parse("pro")?,
            true,
            vec![EntitlementGrant::new(
                EntitlementKey::parse("projects.enabled")?,
                EntitlementValue::Boolean(true),
            )?],
        )?)
        .await?;
    store
        .put_price_mapping(&ProviderPriceMapping::new(
            provider.clone(),
            ProviderObjectId::parse("price_pro")?,
            PlanKey::parse("pro")?,
        ))
        .await?;
    let observed_at = OffsetDateTime::now_utc();
    let fake = Arc::new(FakeBillingAdapter::new(provider.clone()));
    fake.put_snapshot(active_snapshot(
        tenant_id,
        provider,
        12,
        observed_at,
        ProviderStateFacts::default(),
    )?)?;
    insert_receipt(&database.pool, tenant_id, "event_twelve", 12).await?;
    let receipt_store = PostgresReceiptStore::new(database.pool.clone());
    let receipts = receipt_store
        .claim_ready(1, 10, Duration::from_secs(30))
        .await?;
    let receipt = receipts
        .first()
        .ok_or("verified receipt was not claimable")?;
    let reconciler = BillingReconciler::new(fake, store.clone());
    WebhookHandler::handle(&reconciler, receipt, &CancellationToken::new()).await?;
    receipt_store.complete(receipt).await?;

    let entitlements = store.entitlements(&context).await?;
    assert_eq!(entitlements.len(), 1);
    assert_eq!(entitlements[0].value(), EntitlementValue::Boolean(true));
    Ok(())
}

#[tokio::test]
async fn supervised_recovery_redrives_pending_usage_and_honors_drain() -> Result<(), Box<dyn Error>>
{
    let database = database().await?;
    let context = tenant_context(&database.pool, "Billing scanner tenant").await?;
    let store = billing_store(database.pool.clone())?;
    let provider = provider()?;
    seed_customer(&store, &context, provider.clone()).await?;
    let usage = NewUsageRecord::new(
        MeterKey::parse("api.requests")?,
        UsageIdempotencyKey::parse("scanner-redrive")?,
        1,
        OffsetDateTime::now_utc(),
    )?;
    let record_id = match store.record_usage(&context, &provider, &usage).await? {
        UsageRecordOutcome::Recorded(id) | UsageRecordOutcome::Duplicate(id) => id,
        UsageRecordOutcome::Conflict => return Err("scanner usage identity conflicted".into()),
    };
    let reconciler = BillingReconciler::new(Arc::new(FakeBillingAdapter::new(provider)), store);
    let mut supervisor = Supervisor::new();
    supervisor.register(reconciler.recovery_task())?;
    let handle = supervisor.start()?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let mut connection = database.pool.acquire().await?;
            let status: String =
                sqlx::query_scalar("SELECT status FROM billing_usage WHERE id = $1")
                    .bind(record_id.as_uuid())
                    .fetch_one(&mut *connection)
                    .await?;
            if status == "accepted" {
                return Ok::<(), Box<dyn Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    handle.begin_drain();
    let report = handle.shutdown().await;
    assert!(!report.fatal);
    Ok(())
}
