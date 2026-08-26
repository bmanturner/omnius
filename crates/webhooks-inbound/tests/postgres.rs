//! PostgreSQL contracts for replay fencing, concurrent dedupe, and leased processing recovery.

use std::{error::Error, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;
use rsk_webhooks_inbound::{
    FailureClass, FixtureHmacProviderConfig, InboundWebhookService, PostgresReceiptStore,
    RawWebhookRequest, ReceiptRepository, ReceiptStoreError, ReceiveLimits, WebhookConfig,
    sign_fixture_request,
};
use serde_json::json;
use sqlx::Row as _;
use time::OffsetDateTime;

const FIRST_MIGRATION: i64 = 2_026_082_301;
const SECRET: &str = "fixture-secret-material-with-at-least-thirty-two-bytes";

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 5,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "rsk-webhooks-inbound-test".to_owned(),
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
        SchemaVersionRange::new(FIRST_MIGRATION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(20),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase { pool, fixture })
}

fn webhook_config() -> WebhookConfig {
    WebhookConfig {
        enabled: true,
        fixture_hmac_providers: vec![FixtureHmacProviderConfig {
            provider: "fixture".to_owned(),
            signature_header: "x-fixture-signature".to_owned(),
            timestamp_header: "x-fixture-timestamp".to_owned(),
            scope_header: "x-fixture-scope".to_owned(),
            event_id_header: "x-fixture-event-id".to_owned(),
            secrets: vec![SecretString::from(SECRET.to_owned())],
            replay_window: Duration::from_mins(5),
            future_tolerance: Duration::from_secs(30),
        }],
        ..WebhookConfig::default()
    }
}

fn service(pool: PostgresPool) -> Result<InboundWebhookService, Box<dyn Error>> {
    let config = webhook_config();
    let repository: Arc<dyn ReceiptRepository> = Arc::new(PostgresReceiptStore::new(pool));
    Ok(InboundWebhookService::new(
        config.build_registry()?,
        repository,
        ReceiveLimits {
            max_body_bytes: config.max_body_bytes,
            max_header_count: config.max_header_count,
            max_header_bytes: config.max_header_bytes,
            max_safe_payload_bytes: config.max_safe_payload_bytes,
        },
        config.retention,
    )?)
}

fn request(event_id: &str, marker: &str) -> Result<RawWebhookRequest, Box<dyn Error>> {
    let body = Bytes::from(serde_json::to_vec(&json!({
        "version": 1,
        "type": "invoice.paid",
        "data": {"marker": marker}
    }))?);
    let timestamp = OffsetDateTime::now_utc().unix_timestamp();
    let signature = sign_fixture_request(
        SECRET.as_bytes(),
        "fixture",
        timestamp,
        "tenant/one",
        event_id,
        &body,
    )?;
    let mut headers = HeaderMap::new();
    headers.insert("x-fixture-signature", HeaderValue::from_str(&signature)?);
    headers.insert(
        "x-fixture-timestamp",
        HeaderValue::from_str(&timestamp.to_string())?,
    );
    headers.insert("x-fixture-scope", HeaderValue::from_static("tenant/one"));
    headers.insert("x-fixture-event-id", HeaderValue::from_str(event_id)?);
    Ok(RawWebhookRequest {
        provider: "fixture".to_owned(),
        headers,
        body,
    })
}

#[tokio::test]
async fn concurrent_identity_uses_unique_constraint_for_dedupe_and_digest_conflict()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let first_service = service(database.pool.clone())?;
    let second_service = first_service.clone();
    let now = OffsetDateTime::now_utc();
    let (first, second) = tokio::join!(
        first_service.receive(request("evt_concurrent", "same")?, now),
        second_service.receive(request("evt_concurrent", "same")?, now),
    );
    assert_eq!(first?.status, StatusCode::ACCEPTED);
    assert_eq!(second?.status, StatusCode::ACCEPTED);

    let conflict = first_service
        .receive(
            request("evt_concurrent", "different")?,
            OffsetDateTime::now_utc(),
        )
        .await?;
    assert_eq!(conflict.status, StatusCode::CONFLICT);
    let mut connection = database.pool.acquire().await?;
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM webhook_receipts \
         WHERE provider = 'fixture' AND provider_scope = 'tenant/one' \
           AND event_id = 'evt_concurrent'",
    )
    .fetch_one(&mut *connection)
    .await?;
    drop(connection);
    assert_eq!(count, 1);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn reduced_attempt_cap_dead_letters_previously_retryable_pending_receipts()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    service(database.pool.clone())?
        .receive(
            request("evt_attempt_cap", "cap")?,
            OffsetDateTime::now_utc(),
        )
        .await?;
    let store = PostgresReceiptStore::new(database.pool.clone());
    let claimed = store
        .claim_ready(1, 3, Duration::from_secs(2))
        .await?
        .pop()
        .ok_or("receipt was not claimed")?;
    store
        .retry(
            &claimed,
            &FailureClass::parse("transient")?,
            Duration::from_millis(1),
        )
        .await?;
    assert_eq!(store.dead_letter_pending_over_attempt_cap(1, 1).await?, 1);

    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query("SELECT status, last_error_class FROM webhook_receipts WHERE id = $1")
        .bind(claimed.id().as_uuid())
        .fetch_one(&mut *connection)
        .await?;
    assert_eq!(row.try_get::<String, _>("status")?, "dead_letter");
    assert_eq!(
        row.try_get::<Option<String>, _>("last_error_class")?
            .as_deref(),
        Some("attempt_limit_reduced")
    );
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn expired_lease_is_fenced_then_retry_and_dead_letter_are_durable()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let receive = service(database.pool.clone())?;
    receive
        .receive(request("evt_lease", "lease")?, OffsetDateTime::now_utc())
        .await?;
    let store = PostgresReceiptStore::new(database.pool.clone());
    let first = store
        .claim_ready(1, 3, Duration::from_millis(40))
        .await?
        .pop()
        .ok_or("receipt was not claimed")?;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(store.recover_expired(1, 3).await?, 1);
    assert_eq!(
        store.complete(&first).await,
        Err(ReceiptStoreError::LostLease)
    );

    let second = store
        .claim_ready(1, 3, Duration::from_secs(2))
        .await?
        .pop()
        .ok_or("recovered receipt was not claimed")?;
    let transient = FailureClass::parse("provider_unavailable")?;
    store
        .retry(&second, &transient, Duration::from_millis(1))
        .await?;
    tokio::time::sleep(Duration::from_millis(5)).await;
    let third = store
        .claim_ready(1, 3, Duration::from_secs(2))
        .await?
        .pop()
        .ok_or("retried receipt was not claimed")?;
    let permanent = FailureClass::parse("unsupported_contract")?;
    store.dead_letter(&third, &permanent).await?;

    let mut connection = database.pool.acquire().await?;
    let row = sqlx::query(
        "SELECT status, attempt_count, last_error_class, lease_token \
         FROM webhook_receipts WHERE id = $1",
    )
    .bind(third.id().as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(row.try_get::<String, _>("status")?, "dead_letter");
    assert_eq!(row.try_get::<i32, _>("attempt_count")?, 3);
    assert_eq!(
        row.try_get::<Option<String>, _>("last_error_class")?
            .as_deref(),
        Some("unsupported_contract")
    );
    assert!(
        row.try_get::<Option<uuid::Uuid>, _>("lease_token")?
            .is_none()
    );
    drop(connection);
    database.fixture.cleanup().await?;
    Ok(())
}
