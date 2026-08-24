//! Observable local cache provider and cache-aside contracts.

use std::{
    convert::Infallible,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rsk_cache_local::{
    CacheAside, CacheAsidePolicy, CacheKey, CacheLoadError, CacheLookup, CachePolicy,
    CacheProvider, CacheProviderKind, CacheRecord, CacheTtl, CacheValue, MokaCache,
    MokaCacheConfig, MokaCacheError, NoopCache,
};

fn key() -> Result<CacheKey, Box<dyn Error>> {
    Ok(CacheKey::versioned("tenant-1", "widgets-42", "7")?)
}

fn value() -> Result<CacheValue, Box<dyn Error>> {
    Ok(CacheValue::new(b"serialized-widget".to_vec())?)
}

fn ttl(duration: Duration) -> Result<CacheTtl, Box<dyn Error>> {
    Ok(CacheTtl::new(duration)?)
}

fn moka_config() -> MokaCacheConfig {
    MokaCacheConfig {
        max_capacity_bytes: 4096,
        max_value_bytes: 1024,
        time_to_idle: None,
        ttl_jitter_percent: 0,
    }
}

#[tokio::test]
async fn noop_miss_is_not_a_provider_error() -> Result<(), Box<dyn Error>> {
    let cache = NoopCache;
    assert_eq!(cache.get(&key()?).await, Ok(CacheLookup::Miss));
    cache
        .put(
            key()?,
            CacheRecord::Value(value()?),
            CachePolicy::fresh(ttl(Duration::from_secs(1))?),
        )
        .await?;
    assert_eq!(cache.get(&key()?).await, Ok(CacheLookup::Miss));
    Ok(())
}

#[tokio::test]
async fn moka_supports_hit_stale_expiry_and_invalidation() -> Result<(), Box<dyn Error>> {
    let cache = MokaCache::new(moka_config())?;
    let policy = CachePolicy::new(
        ttl(Duration::from_millis(30))?,
        Some(Duration::from_millis(80)),
    )?;
    cache
        .put(key()?, CacheRecord::Value(value()?), policy)
        .await?;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Hit(CacheRecord::Value(value()?))
    );

    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Stale(CacheRecord::Value(value()?))
    );

    let refreshed = CacheValue::new(b"refreshed-widget".to_vec())?;
    cache
        .put(
            key()?,
            CacheRecord::Value(refreshed.clone()),
            CachePolicy::fresh(ttl(Duration::from_millis(150))?),
        )
        .await?;
    tokio::time::sleep(Duration::from_millis(90)).await;
    assert_eq!(
        cache.get(&key()?).await?,
        CacheLookup::Hit(CacheRecord::Value(refreshed))
    );

    cache.invalidate(&key()?).await?;
    assert_eq!(cache.get(&key()?).await?, CacheLookup::Miss);

    cache.put(key()?, CacheRecord::Negative, policy).await?;
    tokio::time::sleep(Duration::from_millis(120)).await;
    cache.run_pending_tasks().await;
    assert_eq!(cache.get(&key()?).await?, CacheLookup::Miss);
    Ok(())
}

#[tokio::test]
async fn moka_rejects_values_above_its_admission_bound() -> Result<(), Box<dyn Error>> {
    let cache = MokaCache::new(MokaCacheConfig {
        max_value_bytes: 4,
        ..moka_config()
    })?;
    assert_eq!(
        cache
            .put(
                key()?,
                CacheRecord::Value(CacheValue::new(vec![0; 5])?),
                CachePolicy::fresh(ttl(Duration::from_secs(1))?),
            )
            .await,
        Err(MokaCacheError::ValueTooLarge)
    );
    Ok(())
}

fn aside_policy() -> Result<CacheAsidePolicy, Box<dyn Error>> {
    Ok(CacheAsidePolicy {
        positive: CachePolicy::fresh(ttl(Duration::from_secs(1))?),
        negative_ttl: Some(ttl(Duration::from_millis(100))?),
        max_concurrent_loads: 64,
    })
}

#[tokio::test]
async fn cache_aside_coalesces_same_key_loads() -> Result<(), Box<dyn Error>> {
    let cache = Arc::new(CacheAside::new(
        MokaCache::new(moka_config())?,
        aside_policy()?,
    )?);
    let loads = Arc::new(AtomicUsize::new(0));
    let expected = CacheValue::new(b"loaded".to_vec())?;
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let cache = Arc::clone(&cache);
        let loads = Arc::clone(&loads);
        let key = key()?;
        let loaded_value = expected.clone();
        tasks.push(tokio::spawn(async move {
            cache
                .get_or_load(key, move || async move {
                    loads.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Ok::<_, Infallible>(Some(loaded_value))
                })
                .await
        }));
    }
    for task in tasks {
        let loaded = task.await??;
        assert_eq!(loaded, Some(expected.clone()));
    }
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn negative_cache_is_explicit_and_short_lived() -> Result<(), Box<dyn Error>> {
    let cache = CacheAside::new(MokaCache::new(moka_config())?, aside_policy()?)?;
    let loads = Arc::new(AtomicUsize::new(0));

    for _ in 0..2 {
        let loads = Arc::clone(&loads);
        assert_eq!(
            cache
                .get_or_load(key()?, move || async move {
                    loads.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, Infallible>(None)
                })
                .await?,
            None
        );
    }
    assert_eq!(loads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct FailingCache;

impl CacheProvider for FailingCache {
    type Error = &'static str;

    const KIND: CacheProviderKind = CacheProviderKind::Moka;

    fn get(
        &self,
        _key: &CacheKey,
    ) -> impl Future<Output = Result<CacheLookup, Self::Error>> + Send {
        std::future::ready(Err("cache unavailable"))
    }

    fn put(
        &self,
        _key: CacheKey,
        _record: CacheRecord,
        _policy: CachePolicy,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Err("cache unavailable"))
    }

    fn invalidate(&self, _key: &CacheKey) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Err("cache unavailable"))
    }
}

#[tokio::test]
async fn provider_error_fails_open_without_becoming_a_miss() -> Result<(), Box<dyn Error>> {
    assert_eq!(FailingCache.get(&key()?).await, Err("cache unavailable"));
    let cache = CacheAside::new(FailingCache, aside_policy()?)?;
    let authoritative = CacheValue::new(b"authoritative".to_vec())?;
    let loaded_value = authoritative.clone();
    let loaded = cache
        .get_or_load(key()?, move || async move {
            Ok::<_, Infallible>(Some(loaded_value))
        })
        .await?;
    assert_eq!(loaded, Some(authoritative));
    Ok(())
}

#[tokio::test]
async fn loader_errors_are_not_cached() -> Result<(), Box<dyn Error>> {
    let cache = CacheAside::new(MokaCache::new(moka_config())?, aside_policy()?)?;
    let failed = cache
        .get_or_load(key()?, || async {
            Err::<Option<CacheValue>, _>("origin failed")
        })
        .await;
    assert!(matches!(
        failed,
        Err(error)
            if matches!(
                error.as_ref(),
                CacheLoadError::Authoritative("origin failed")
            )
    ));
    let recovered = cache
        .get_or_load(key()?, || async {
            Ok::<_, &'static str>(Some(
                CacheValue::new(b"recovered".to_vec()).map_err(|_| "value failed")?,
            ))
        })
        .await
        .map_err(|_| std::io::Error::other("unexpected second loader failure"))?;
    assert_eq!(recovered, Some(CacheValue::new(b"recovered".to_vec())?));
    Ok(())
}

#[tokio::test]
async fn distinct_authoritative_loads_have_a_hard_concurrency_limit() -> Result<(), Box<dyn Error>>
{
    let cache = Arc::new(CacheAside::new(
        MokaCache::new(moka_config())?,
        CacheAsidePolicy {
            positive: CachePolicy::fresh(ttl(Duration::from_secs(1))?),
            negative_ttl: None,
            max_concurrent_loads: 1,
        },
    )?);
    let first_key = CacheKey::new("first.rev-1")?;
    let first_value = CacheValue::new(b"first".to_vec())?;
    let expected_first = first_value.clone();
    let second_key = CacheKey::new("second.rev-1")?;
    let second_value = CacheValue::new(b"second".to_vec())?;
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let first_cache = Arc::clone(&cache);
    let first_release = Arc::clone(&release);
    let first = tokio::spawn(async move {
        first_cache
            .get_or_load(first_key, move || async move {
                let _ = started_tx.send(());
                first_release.notified().await;
                Ok::<_, Infallible>(Some(first_value))
            })
            .await
            .map_err(|_| std::io::Error::other("first loader unexpectedly failed"))
    });
    started_rx.await?;

    let second = cache
        .get_or_load(second_key, move || async move {
            Ok::<_, Infallible>(Some(second_value))
        })
        .await;
    assert!(matches!(
        second,
        Err(error) if matches!(error.as_ref(), CacheLoadError::Overloaded)
    ));

    release.notify_one();
    assert_eq!(first.await??, Some(expected_first));
    Ok(())
}

#[test]
fn key_ttl_and_policy_bounds_are_enforced() -> Result<(), Box<dyn Error>> {
    assert!(CacheKey::new("").is_err());
    assert!(CacheKey::new("contains space").is_err());
    assert!(CacheKey::new("a".repeat(65)).is_err());
    assert!(CacheTtl::new(Duration::ZERO).is_err());
    assert!(CacheTtl::new(Duration::from_secs(86_401)).is_err());
    assert!(
        CachePolicy::new(ttl(Duration::from_secs(1))?, Some(Duration::from_secs(301))).is_err()
    );
    assert!(
        CacheAsidePolicy {
            positive: CachePolicy::fresh(ttl(Duration::from_secs(1))?),
            negative_ttl: Some(ttl(Duration::from_secs(31))?),
            max_concurrent_loads: 1,
        }
        .validate()
        .is_err()
    );
    Ok(())
}
