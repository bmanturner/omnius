//! Real authenticated Redis manager, naming, namespace, dedicated connection, and health contracts.

use std::{error::Error, time::Duration};

use omnius_config::DeploymentEnvironment;
use omnius_core::{BuildMetadata, BuildMetadataInput, SchemaCompatibility};
use omnius_health::{HealthBuilder, HealthConfig};
use omnius_redis_core::{
    DedicatedConnectionKind, RedisCommandFamily, RedisConfig, RedisCore, RedisCoreError,
};
use omnius_test_support::RedisFixture;

fn config(fixture: &RedisFixture) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(3),
        startup_timeout: Duration::from_secs(10),
        command_timeout: Duration::from_secs(2),
        health_timeout: Duration::from_secs(3),
        client_name: "omnius-redis-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v1".to_owned(),
        max_value_bytes: 16,
        reconnect: omnius_redis_core::RedisReconnectConfig::default(),
    }
}

fn metadata() -> Result<BuildMetadata, omnius_core::InvalidBuildMetadata> {
    BuildMetadata::current(BuildMetadataInput {
        service: "redis-test",
        profile: "api",
        modules: &["core", "health", "redis-core"],
        providers: &[],
        schema: SchemaCompatibility {
            minimum: "0",
            maximum: "0",
        },
    })
}

#[tokio::test]
async fn redis_manager_is_authenticated_multiplexed_named_and_namespaced()
-> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let Some(redis) = RedisCore::connect(&config(&fixture), DeploymentEnvironment::Test).await?
    else {
        return Err(std::io::Error::other(
            "enabled Redis unexpectedly produced a disabled outcome",
        )
        .into());
    };

    let key = redis.key(&["record", "1"])?;
    let mut set = redis::cmd("SET");
    set.arg(&key).arg("value");
    redis.query::<()>(RedisCommandFamily::Cache, set).await?;
    let mut get = redis::cmd("GET");
    get.arg(&key);
    assert_eq!(
        redis
            .query::<Option<String>>(RedisCommandFamily::Cache, get)
            .await?,
        Some("value".to_owned())
    );

    let mut get_name = redis::cmd("CLIENT");
    get_name.arg("GETNAME");
    assert_eq!(
        redis
            .query::<Option<String>>(RedisCommandFamily::Health, get_name)
            .await?,
        Some("omnius-redis-integration".to_owned())
    );

    let mut dedicated = redis
        .dedicated_connection(DedicatedConnectionKind::Provider)
        .await?;
    let dedicated_name = redis::cmd("CLIENT")
        .arg("GETNAME")
        .query_async::<Option<String>>(&mut dedicated)
        .await?;
    assert_eq!(
        dedicated_name,
        Some("omnius-redis-integration-provider".to_owned())
    );

    assert_eq!(redis.ensure_value_size(b"0123456789abcdef"), Ok(()));
    assert_eq!(
        redis.ensure_value_size(b"0123456789abcdefg"),
        Err(RedisCoreError::ValueTooLarge)
    );

    let mut health_builder = HealthBuilder::new(metadata()?, HealthConfig::default())?;
    health_builder.register(redis.health_check())?;
    let health = health_builder.build();
    health.mark_started();
    health.refresh_once().await;
    assert!(health.is_ready());

    drop(dedicated);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}
#[tokio::test]
async fn command_deadline_includes_server_stall() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let mut settings = config(&fixture);
    settings.command_timeout = Duration::from_millis(50);
    settings.health_timeout = Duration::from_millis(100);
    let Some(redis) = RedisCore::connect(&settings, DeploymentEnvironment::Test).await? else {
        return Err(std::io::Error::other(
            "enabled Redis unexpectedly produced a disabled outcome",
        )
        .into());
    };

    let mut pause = redis::cmd("CLIENT");
    pause.arg("PAUSE").arg(500).arg("ALL");
    redis.query::<()>(RedisCommandFamily::Health, pause).await?;
    let started = std::time::Instant::now();
    assert_eq!(
        redis
            .query::<String>(RedisCommandFamily::Health, redis::cmd("PING"))
            .await,
        Err(RedisCoreError::Command)
    );
    assert!(started.elapsed() < Duration::from_millis(300));

    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn disabled_redis_does_not_open_a_connection() -> Result<(), Box<dyn Error>> {
    assert!(
        RedisCore::connect(&RedisConfig::default(), DeploymentEnvironment::Production)
            .await?
            .is_none()
    );
    Ok(())
}
