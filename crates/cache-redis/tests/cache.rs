//! Real Redis cache expiry, envelope, invalidation, and degraded-mode contracts.

use std::{convert::Infallible, error::Error, time::Duration};

use rsk_cache_local::{
    CacheAside, CacheAsidePolicy, CacheKey, CacheLookup, CachePolicy, CacheProvider, CacheRecord,
    CacheTtl, CacheValue,
};
use rsk_cache_redis::{RedisCache, RedisCacheConfig, RedisCacheError};
use rsk_config::DeploymentEnvironment;
use rsk_redis_core::{RedisCommandFamily, RedisConfig, RedisCore};
use rsk_test_support::RedisFixture;

fn redis_config(fixture: &RedisFixture, command_timeout: Duration) -> RedisConfig {
    RedisConfig {
        enabled: true,
        url: Some(fixture.redis_url().clone()),
        connection_timeout: Duration::from_secs(3),
        startup_timeout: Duration::from_secs(10),
        command_timeout,
        health_timeout: Duration::from_secs(3),
        client_name: "rsk-cache-integration".to_owned(),
        key_prefix: fixture.namespace().replace(':', "-"),
        schema_version: "v7".to_owned(),
        max_value_bytes: 1024,
        reconnect: rsk_redis_core::RedisReconnectConfig::default(),
    }
}

async fn connected(
    fixture: &RedisFixture,
    command_timeout: Duration,
) -> Result<RedisCore, Box<dyn Error>> {
    RedisCore::connect(
        &redis_config(fixture, command_timeout),
        DeploymentEnvironment::Test,
    )
    .await?
    .ok_or_else(|| std::io::Error::other("enabled Redis cache unexpectedly disabled").into())
}

fn key() -> Result<CacheKey, Box<dyn Error>> {
    Ok(CacheKey::versioned("tenant-1", "widgets-42", "7")?)
}

fn value() -> Result<CacheValue, Box<dyn Error>> {
    Ok(CacheValue::new(b"serialized-widget".to_vec())?)
}

fn ttl(duration: Duration) -> Result<CacheTtl, Box<dyn Error>> {
    Ok(CacheTtl::new(duration)?)
}

#[tokio::test]
async fn redis_cache_versions_expires_and_invalidates_records() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let cache = RedisCache::new(
        redis.clone(),
        RedisCacheConfig {
            ttl_jitter_percent: 0,
        },
    )?;
    let policy = CachePolicy::new(
        ttl(Duration::from_millis(80))?,
        Some(Duration::from_millis(100)),
    )?;

    assert_eq!(cache.get(&key()?).await?, CacheLookup::Miss);
    cache
        .put(key()?, CacheRecord::Value(value()?), policy)
        .await?;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Hit(CacheRecord::Value(value()?))
    );

    let versioned_key = redis.key(&["cache", key()?.as_str()])?;
    assert!(versioned_key.contains(":v7:cache:"));
    let mut raw_get = redis::cmd("GET");
    raw_get.arg(versioned_key);
    let encoded = redis
        .query::<Option<Vec<u8>>>(RedisCommandFamily::Cache, raw_get)
        .await?
        .ok_or_else(|| std::io::Error::other("Redis cache record missing"))?;
    assert!(encoded.starts_with(b"RSKC\x01"));

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Stale(CacheRecord::Value(value()?))
    );
    cache.invalidate(&key()?).await?;
    assert_eq!(cache.get(&key()?).await?, CacheLookup::Miss);

    cache
        .put(
            key()?,
            CacheRecord::Negative,
            CachePolicy::fresh(ttl(Duration::from_millis(40))?),
        )
        .await?;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Hit(CacheRecord::Negative)
    );
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(cache.get(&key()?).await?, CacheLookup::Miss);

    drop(cache);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn corrupt_value_is_an_error_not_a_miss() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_secs(2)).await?;
    let cache = RedisCache::new(redis.clone(), RedisCacheConfig::default())?;
    let redis_key = redis.key(&["cache", key()?.as_str()])?;
    let mut set = redis::cmd("SET");
    set.arg(&redis_key).arg("not-an-envelope");
    redis.query::<()>(RedisCommandFamily::Cache, set).await?;

    assert_eq!(cache.get(&key()?).await, Err(RedisCacheError::CorruptValue));

    let mut poison = redis::cmd("SET");
    poison.arg(&redis_key).arg(vec![0_u8; 1025]);
    redis.query::<()>(RedisCommandFamily::Cache, poison).await?;
    assert_eq!(
        cache.get(&key()?).await,
        Err(RedisCacheError::ValueTooLarge)
    );
    assert_eq!(
        cache
            .put(
                key()?,
                CacheRecord::Value(CacheValue::new(vec![0_u8; 1011])?),
                CachePolicy::fresh(ttl(Duration::from_secs(1))?),
            )
            .await,
        Err(RedisCacheError::ValueTooLarge)
    );

    drop(cache);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn redis_outage_fails_open_to_authoritative_loader() -> Result<(), Box<dyn Error>> {
    let fixture = RedisFixture::start().await?;
    let redis = connected(&fixture, Duration::from_millis(50)).await?;
    let cache = RedisCache::new(redis.clone(), RedisCacheConfig::default())?;
    let aside = CacheAside::new(
        cache.clone(),
        CacheAsidePolicy {
            positive: CachePolicy::fresh(ttl(Duration::from_secs(1))?),
            negative_ttl: Some(ttl(Duration::from_secs(1))?),
            max_concurrent_loads: 16,
        },
    )?;

    let mut pause = redis::cmd("CLIENT");
    pause.arg("PAUSE").arg(500).arg("ALL");
    redis.query::<()>(RedisCommandFamily::Health, pause).await?;
    assert_eq!(cache.get(&key()?).await, Err(RedisCacheError::Unavailable));

    let authoritative = CacheValue::new(b"authoritative".to_vec())?;
    let loaded_value = authoritative.clone();
    assert_eq!(
        aside
            .get_or_load(key()?, move || async move {
                Ok::<_, Infallible>(Some(loaded_value))
            })
            .await?,
        Some(authoritative)
    );

    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(aside);
    drop(cache);
    drop(redis);
    fixture.cleanup().await?;
    Ok(())
}
