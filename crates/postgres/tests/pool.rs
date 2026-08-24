//! Real PostgreSQL pool saturation, health, initialization, and shutdown contracts.

use std::{error::Error, time::Duration};

use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_core::{BuildMetadata, BuildMetadataInput, SchemaCompatibility};
use rsk_health::{HealthBuilder, HealthConfig};
use rsk_postgres::{
    PostgresConfig, PostgresError, PostgresPool, PostgresTlsMode, TransactionIsolation,
    TransactionRetryConfig,
};
use rsk_test_support::PostgresFixture;

fn config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 2,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "rsk-postgres-test".to_owned(),
        initialization_sql: vec![
            "SELECT set_config('rsk.test_initialized', 'yes', false)".to_owned(),
        ],
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_millis(200),
        shutdown_timeout: Duration::from_secs(2),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

fn metadata() -> Result<BuildMetadata, rsk_core::InvalidBuildMetadata> {
    BuildMetadata::current(BuildMetadataInput {
        service: "postgres-test",
        profile: "api",
        modules: &["core", "health", "postgres"],
        schema: SchemaCompatibility {
            minimum: "0",
            maximum: "0",
        },
    })
}

#[tokio::test]
async fn postgres_pool_applies_session_policy_and_hides_credentials() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;

    let mut connection = pool.acquire().await?;
    let initialized =
        sqlx::query_scalar::<_, String>("SELECT current_setting('rsk.test_initialized')")
            .fetch_one(&mut *connection)
            .await?;
    let application_name =
        sqlx::query_scalar::<_, String>("SELECT current_setting('application_name')")
            .fetch_one(&mut *connection)
            .await?;
    let timezone = sqlx::query_scalar::<_, String>("SELECT current_setting('TimeZone')")
        .fetch_one(&mut *connection)
        .await?;
    drop(connection);
    assert_eq!(initialized, "yes");
    assert_eq!(application_name, "rsk-postgres-test");
    assert_eq!(timezone, "UTC");
    assert!(pool.stats().size >= 1);
    assert!(!format!("{pool:?}").contains("password"));

    pool.close().await?;
    assert_eq!(pool.acquire().await.err(), Some(PostgresError::Closed));
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn postgres_pool_saturation_is_bounded_and_required_health_recovers()
-> Result<(), Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let mut settings = config(fixture.database_url().clone());
    settings.max_connections = 1;
    settings.acquire_timeout = Duration::from_millis(200);
    settings.health_timeout = Duration::from_millis(300);
    let pool = PostgresPool::connect(&settings, DeploymentEnvironment::Test).await?;
    let lease = pool.acquire().await?;
    assert!(pool.stats().saturated());
    assert_eq!(
        pool.acquire().await.err(),
        Some(PostgresError::AcquireTimeout)
    );

    let mut health_builder = HealthBuilder::new(metadata()?, HealthConfig::default())?;
    health_builder.register(pool.health_check())?;
    let health = health_builder.build();
    health.mark_started();
    health.refresh_once().await;
    assert!(!health.is_ready());

    drop(lease);
    health.refresh_once().await;
    assert!(health.is_ready());
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn postgres_pool_close_is_bounded_and_rejects_new_acquisitions() -> Result<(), Box<dyn Error>>
{
    let fixture = PostgresFixture::start().await?;
    let mut settings = config(fixture.database_url().clone());
    settings.max_connections = 1;
    settings.shutdown_timeout = Duration::from_millis(100);
    let pool = PostgresPool::connect(&settings, DeploymentEnvironment::Test).await?;
    let lease = pool.acquire().await?;

    assert_eq!(pool.close().await, Err(PostgresError::CloseTimeout));
    assert!(pool.stats().closed);
    assert_eq!(pool.acquire().await.err(), Some(PostgresError::Closed));

    drop(lease);
    pool.close().await?;
    fixture.cleanup().await?;
    Ok(())
}

#[test]
fn postgres_connection_release_survives_runtime_shutdown() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let (fixture, pool, lease) = runtime.block_on(async {
        let fixture = PostgresFixture::start().await?;
        let pool = PostgresPool::connect(
            &config(fixture.database_url().clone()),
            DeploymentEnvironment::Test,
        )
        .await?;
        let lease = pool.acquire().await?;
        Ok::<_, Box<dyn Error>>((fixture, pool, lease))
    })?;
    drop(runtime);

    drop(lease);

    let cleanup_runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    cleanup_runtime.block_on(async {
        pool.close().await?;
        assert_eq!(pool.stats().in_use, 0);
        fixture.cleanup().await?;
        Ok::<_, Box<dyn Error>>(())
    })
}
