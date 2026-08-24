//! Bounded in-process caching and the shared cache-aside provider contract.
//!
//! [`MokaCache`] is process-local: warmup is optional and invalidation is not coherent across
//! instances. Mutable records must use immutable keys containing their authoritative revision;
//! unfenced after-commit deletion alone can race an older in-flight load. [`NoopCache`] provides
//! an explicit disabled provider.

use metrics::counter;
use moka::{future::Cache, policy::Expiry};
use std::{
    collections::hash_map::DefaultHasher,
    convert::Infallible,
    fmt,
    future::Future,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::sync::Semaphore;

const MAX_KEY_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TTL: Duration = Duration::from_hours(24);
const MAX_STALE_TTL: Duration = Duration::from_mins(5);
const MAX_NEGATIVE_TTL: Duration = Duration::from_secs(30);
const MAX_JITTER_PERCENT: u8 = 25;

/// A fixed provider identity used only for low-cardinality telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheProviderKind {
    /// Explicitly disabled cache.
    Noop,
    /// Process-local Moka cache.
    Moka,
    /// Shared Redis cache.
    Redis,
}

impl CacheProviderKind {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::Moka => "moka",
            Self::Redis => "redis",
        }
    }
}

/// A bounded, portable cache key component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CacheKey(String);

impl CacheKey {
    /// Validates and owns an immutable or already-versioned cache key.
    ///
    /// Mutable records must include their authoritative revision. Deletion-only invalidation can
    /// race an older in-flight loader and is not a correctness fence.
    ///
    /// # Errors
    ///
    /// Returns [`CacheKeyError`] for an empty, oversized, or non-portable key.
    pub fn new(value: impl Into<String>) -> Result<Self, CacheKeyError> {
        let value = value.into();
        if value.is_empty() {
            return Err(CacheKeyError::Empty);
        }
        if value.len() > MAX_KEY_BYTES {
            return Err(CacheKeyError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(CacheKeyError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Builds an immutable key for a mutable record from bounded portable components.
    ///
    /// # Errors
    ///
    /// Returns [`CacheKeyError`] when a component or the combined key violates key bounds.
    pub fn versioned(
        scope: &str,
        identity: &str,
        authoritative_revision: &str,
    ) -> Result<Self, CacheKeyError> {
        validate_key_component(scope)?;
        validate_key_component(identity)?;
        validate_key_component(authoritative_revision)?;
        let mut key = String::with_capacity(
            scope
                .len()
                .saturating_add(identity.len())
                .saturating_add(authoritative_revision.len())
                .saturating_add(6),
        );
        key.push_str(scope);
        key.push('.');
        key.push_str(identity);
        key.push_str(".rev-");
        key.push_str(authoritative_revision);
        Self::new(key)
    }

    /// Returns the validated key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_key_component(value: &str) -> Result<(), CacheKeyError> {
    if value.is_empty() {
        return Err(CacheKeyError::Empty);
    }
    if value.len() > MAX_KEY_BYTES {
        return Err(CacheKeyError::TooLong);
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(CacheKeyError::InvalidCharacter)
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Cache key validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheKeyError {
    /// The key was empty.
    #[error("cache key must not be empty")]
    Empty,
    /// The key exceeded 64 bytes.
    #[error("cache key exceeds 64 bytes")]
    TooLong,
    /// The key contained a non-portable character.
    #[error("cache key contains an invalid character")]
    InvalidCharacter,
}

/// Cheaply cloned, bounded serialized cache bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheValue(Arc<[u8]>);

impl CacheValue {
    /// Validates and owns serialized cache bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CacheValueError::TooLarge`] above the global 16 MiB safety bound.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, CacheValueError> {
        let value = value.into();
        if value.len() > MAX_VALUE_BYTES {
            return Err(CacheValueError::TooLarge);
        }
        Ok(Self(value.into()))
    }

    /// Returns the serialized bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the serialized byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the serialized value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Serialized cache value validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheValueError {
    /// The serialized value exceeded 16 MiB.
    #[error("serialized cache value exceeds 16 MiB")]
    TooLarge,
}

/// A non-zero, bounded cache duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheTtl(Duration);

impl CacheTtl {
    /// Validates a cache duration up to 24 hours.
    ///
    /// # Errors
    ///
    /// Returns [`CacheTtlError`] when the duration is zero or exceeds 24 hours.
    pub fn new(duration: Duration) -> Result<Self, CacheTtlError> {
        if duration.is_zero() {
            return Err(CacheTtlError::Zero);
        }
        if duration > MAX_TTL {
            return Err(CacheTtlError::TooLong);
        }
        Ok(Self(duration))
    }

    /// Returns the validated duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// Cache duration validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheTtlError {
    /// A zero TTL would make cache behavior ambiguous.
    #[error("cache TTL must be greater than zero")]
    Zero,
    /// The TTL exceeded the 24-hour policy bound.
    #[error("cache TTL exceeds 24 hours")]
    TooLong,
}

/// Fresh and optional stale-retention durations for one write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CachePolicy {
    fresh_ttl: CacheTtl,
    stale_ttl: Option<Duration>,
}

impl CachePolicy {
    /// Creates a write policy. Stale retention is bounded to five minutes.
    ///
    /// # Errors
    ///
    /// Returns [`CachePolicyError`] when stale retention exceeds five minutes.
    pub fn new(fresh_ttl: CacheTtl, stale_ttl: Option<Duration>) -> Result<Self, CachePolicyError> {
        if stale_ttl.is_some_and(|ttl| ttl > MAX_STALE_TTL) {
            return Err(CachePolicyError::StaleTooLong);
        }
        Ok(Self {
            fresh_ttl,
            stale_ttl: stale_ttl.filter(|ttl| !ttl.is_zero()),
        })
    }

    /// Creates a policy without stale retention.
    #[must_use]
    pub const fn fresh(fresh_ttl: CacheTtl) -> Self {
        Self {
            fresh_ttl,
            stale_ttl: None,
        }
    }

    /// Returns the fresh TTL.
    #[must_use]
    pub const fn fresh_ttl(self) -> CacheTtl {
        self.fresh_ttl
    }

    /// Returns the stale-retention duration.
    #[must_use]
    pub const fn stale_ttl(self) -> Option<Duration> {
        self.stale_ttl
    }
}

/// Cache write-policy validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CachePolicyError {
    /// Stale retention exceeded five minutes.
    #[error("cache stale retention exceeds five minutes")]
    StaleTooLong,
}

/// A positive or explicit negative cache record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheRecord {
    /// Serialized authoritative value.
    Value(CacheValue),
    /// Short-lived authoritative absence.
    Negative,
}

/// Result of a successful provider lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CacheLookup {
    /// A fresh record was found.
    Hit(CacheRecord),
    /// A retained record is stale and should be refreshed.
    Stale(CacheRecord),
    /// No record was present. This is distinct from a provider error.
    Miss,
}

/// Static cache provider contract used by [`CacheAside`].
pub trait CacheProvider: Clone + Send + Sync + 'static {
    /// Provider-specific failure type.
    type Error: Send + Sync + 'static;

    /// Fixed telemetry identity.
    const KIND: CacheProviderKind;

    /// Looks up one key.
    fn get(&self, key: &CacheKey) -> impl Future<Output = Result<CacheLookup, Self::Error>> + Send;

    /// Writes one bounded record under an explicit TTL policy.
    fn put(
        &self,
        key: CacheKey,
        record: CacheRecord,
        policy: CachePolicy,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Invalidates one key. Call this only after the authoritative commit succeeds.
    fn invalidate(&self, key: &CacheKey) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Explicit disabled cache provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopCache;

impl CacheProvider for NoopCache {
    type Error = Infallible;

    const KIND: CacheProviderKind = CacheProviderKind::Noop;

    fn get(
        &self,
        _key: &CacheKey,
    ) -> impl Future<Output = Result<CacheLookup, Self::Error>> + Send {
        record_provider(Self::KIND, "miss");
        std::future::ready(Ok(CacheLookup::Miss))
    }

    fn put(
        &self,
        _key: CacheKey,
        _record: CacheRecord,
        _policy: CachePolicy,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Ok(()))
    }

    fn invalidate(&self, _key: &CacheKey) -> impl Future<Output = Result<(), Self::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

/// Bounded Moka provider configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MokaCacheConfig {
    /// Weighted per-process capacity in bytes.
    pub max_capacity_bytes: u64,
    /// Largest admitted serialized value.
    pub max_value_bytes: usize,
    /// Optional idle expiry, in addition to per-entry hard TTL.
    pub time_to_idle: Option<Duration>,
    /// Maximum downward TTL jitter percentage.
    pub ttl_jitter_percent: u8,
}

impl Default for MokaCacheConfig {
    fn default() -> Self {
        Self {
            max_capacity_bytes: 64 * 1024 * 1024,
            max_value_bytes: 1024 * 1024,
            time_to_idle: Some(Duration::from_mins(5)),
            ttl_jitter_percent: 10,
        }
    }
}

impl MokaCacheConfig {
    /// Validates capacity, value, idle, and jitter bounds.
    ///
    /// # Errors
    ///
    /// Returns [`MokaCacheConfigError`] for an unsafe or ineffective bound.
    pub fn validate(self) -> Result<Self, MokaCacheConfigError> {
        if self.max_capacity_bytes == 0 {
            return Err(MokaCacheConfigError::ZeroCapacity);
        }
        if self.max_value_bytes == 0
            || self.max_value_bytes > MAX_VALUE_BYTES
            || u64::try_from(self.max_value_bytes)
                .map_or(true, |value| value > self.max_capacity_bytes)
        {
            return Err(MokaCacheConfigError::InvalidValueBound);
        }
        if self
            .time_to_idle
            .is_some_and(|ttl| ttl.is_zero() || ttl > MAX_TTL)
        {
            return Err(MokaCacheConfigError::InvalidIdleTtl);
        }
        if self.ttl_jitter_percent > MAX_JITTER_PERCENT {
            return Err(MokaCacheConfigError::InvalidJitter);
        }
        Ok(self)
    }
}

/// Invalid Moka cache configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MokaCacheConfigError {
    /// Capacity must be non-zero.
    #[error("Moka cache capacity must be greater than zero")]
    ZeroCapacity,
    /// Value bound was zero, globally oversized, or larger than capacity.
    #[error("Moka cache value bound is invalid")]
    InvalidValueBound,
    /// Idle TTL was zero or exceeded 24 hours.
    #[error("Moka cache idle TTL is invalid")]
    InvalidIdleTtl,
    /// TTL jitter exceeded 25 percent.
    #[error("Moka cache TTL jitter exceeds 25 percent")]
    InvalidJitter,
}

/// Moka provider operation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MokaCacheError {
    /// The serialized value exceeded the configured provider bound.
    #[error("serialized cache value exceeds configured Moka bound")]
    ValueTooLarge,
}

#[derive(Clone, Debug)]
struct LocalEntry {
    record: CacheRecord,
    inserted_at: Instant,
    fresh_for: Duration,
    hard_ttl: Duration,
}

#[derive(Clone, Copy, Debug)]
struct LocalExpiry;

impl Expiry<CacheKey, LocalEntry> for LocalExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &LocalEntry,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.hard_ttl)
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &LocalEntry,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.hard_ttl)
    }
}

/// Bounded, weighted, process-local Moka cache.
#[derive(Clone)]
pub struct MokaCache {
    cache: Cache<CacheKey, LocalEntry>,
    max_value_bytes: usize,
    jitter: TtlJitter,
}

impl fmt::Debug for MokaCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MokaCache")
            .field("max_value_bytes", &self.max_value_bytes)
            .field("ttl_jitter_percent", &self.jitter.percent)
            .finish_non_exhaustive()
    }
}

impl MokaCache {
    /// Builds a bounded local cache.
    ///
    /// # Errors
    ///
    /// Returns [`MokaCacheConfigError`] when configuration violates policy bounds.
    pub fn new(config: MokaCacheConfig) -> Result<Self, MokaCacheConfigError> {
        let config = config.validate()?;
        let mut builder = Cache::builder()
            .max_capacity(config.max_capacity_bytes)
            .weigher(|key: &CacheKey, entry: &LocalEntry| {
                let value_bytes = match &entry.record {
                    CacheRecord::Value(value) => value.len(),
                    CacheRecord::Negative => 0,
                };
                u32::try_from(
                    key.as_str()
                        .len()
                        .saturating_add(value_bytes)
                        .saturating_add(64),
                )
                .unwrap_or(u32::MAX)
            })
            .expire_after(LocalExpiry);
        if let Some(time_to_idle) = config.time_to_idle {
            builder = builder.time_to_idle(time_to_idle);
        }
        Ok(Self {
            cache: builder.build(),
            max_value_bytes: config.max_value_bytes,
            jitter: TtlJitter::new(config.ttl_jitter_percent),
        })
    }

    /// Invalidates every local entry.
    ///
    /// This is process-local and is not a cross-instance coherence mechanism.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Runs pending cache maintenance. Primarily useful for deterministic tests and shutdown hooks.
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

impl CacheProvider for MokaCache {
    type Error = MokaCacheError;

    const KIND: CacheProviderKind = CacheProviderKind::Moka;

    async fn get(&self, key: &CacheKey) -> Result<CacheLookup, Self::Error> {
        let Some(entry) = self.cache.get(key).await else {
            record_provider(Self::KIND, "miss");
            return Ok(CacheLookup::Miss);
        };
        if entry.inserted_at.elapsed() >= entry.fresh_for {
            record_provider(Self::KIND, "stale");
            Ok(CacheLookup::Stale(entry.record))
        } else {
            record_provider(Self::KIND, "hit");
            Ok(CacheLookup::Hit(entry.record))
        }
    }

    async fn put(
        &self,
        key: CacheKey,
        record: CacheRecord,
        policy: CachePolicy,
    ) -> Result<(), Self::Error> {
        if matches!(&record, CacheRecord::Value(value) if value.len() > self.max_value_bytes) {
            record_provider(Self::KIND, "error");
            return Err(MokaCacheError::ValueTooLarge);
        }
        let fresh_for = self.jitter.apply(policy.fresh_ttl(), &key);
        let hard_ttl = fresh_for.saturating_add(policy.stale_ttl().unwrap_or_default());
        self.cache
            .insert(
                key,
                LocalEntry {
                    record,
                    inserted_at: Instant::now(),
                    fresh_for,
                    hard_ttl,
                },
            )
            .await;
        Ok(())
    }

    async fn invalidate(&self, key: &CacheKey) -> Result<(), Self::Error> {
        self.cache.invalidate(key).await;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TtlJitter {
    percent: u8,
    nonce: Arc<AtomicU64>,
}

impl TtlJitter {
    fn new(percent: u8) -> Self {
        Self {
            percent,
            nonce: Arc::new(AtomicU64::new(0)),
        }
    }

    fn apply(&self, ttl: CacheTtl, key: &CacheKey) -> Duration {
        let ttl_millis = u64::try_from(ttl.get().as_millis()).unwrap_or(u64::MAX);
        let window = ttl_millis.saturating_mul(u64::from(self.percent)) / 100;
        if window == 0 {
            return ttl.get();
        }
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        self.nonce.fetch_add(1, Ordering::Relaxed).hash(&mut hasher);
        let reduction = hasher.finish() % (window + 1);
        Duration::from_millis(ttl_millis.saturating_sub(reduction).max(1))
    }
}

/// Validated cache-aside policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheAsidePolicy {
    /// Positive-value cache policy.
    pub positive: CachePolicy,
    /// Explicit short TTL for authoritative absence. `None` disables negative caching.
    pub negative_ttl: Option<CacheTtl>,
    /// Hard limit on distinct authoritative loads executing concurrently.
    pub max_concurrent_loads: usize,
}

impl CacheAsidePolicy {
    /// Validates negative-cache and load-concurrency bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAsidePolicyError`] when negative TTL or load concurrency is out of bounds.
    pub fn validate(self) -> Result<Self, CacheAsidePolicyError> {
        if self
            .negative_ttl
            .is_some_and(|ttl| ttl.get() > MAX_NEGATIVE_TTL)
        {
            return Err(CacheAsidePolicyError::NegativeTtlTooLong);
        }
        if self.max_concurrent_loads == 0 || self.max_concurrent_loads > 4096 {
            return Err(CacheAsidePolicyError::InvalidLoadConcurrency);
        }
        Ok(self)
    }
}

/// Invalid cache-aside policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CacheAsidePolicyError {
    /// Negative cache entries must remain short-lived.
    #[error("negative cache TTL exceeds 30 seconds")]
    NegativeTtlTooLong,
    /// Concurrent authoritative loads must remain between one and 4096.
    #[error("cache authoritative-load concurrency must be between one and 4096")]
    InvalidLoadConcurrency,
}

/// Failure from the authoritative cache-aside loading boundary.
#[derive(Debug, Error)]
pub enum CacheLoadError<E> {
    /// The authoritative loader failed. This result is never cached.
    #[error("authoritative cache loader failed")]
    Authoritative(#[source] E),
    /// The hard distinct-load concurrency bound was exhausted.
    #[error("authoritative cache loader is overloaded")]
    Overloaded,
}

/// Cache-aside boundary with per-instance same-key request coalescing.
///
/// Provider read/write failures fail open: the authoritative loader still runs and its result is
/// returned. Loader failures are never cached. Redis deployments get per-instance coalescing; this
/// deliberately does not pretend that an unfenced Redis lock provides distributed singleflight.
#[derive(Clone)]
pub struct CacheAside<P>
where
    P: CacheProvider,
{
    provider: P,
    policy: CacheAsidePolicy,
    in_flight: Cache<CacheKey, Option<CacheValue>>,
    load_permits: Arc<Semaphore>,
}

impl<P> fmt::Debug for CacheAside<P>
where
    P: CacheProvider + fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CacheAside")
            .field("provider", &self.provider)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<P> CacheAside<P>
where
    P: CacheProvider,
{
    /// Creates a cache-aside boundary with bounded coalescing state.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAsidePolicyError`] when policy bounds are invalid.
    pub fn new(provider: P, policy: CacheAsidePolicy) -> Result<Self, CacheAsidePolicyError> {
        let policy = policy.validate()?;
        Ok(Self {
            provider,
            policy,
            in_flight: Cache::builder()
                .max_capacity(u64::try_from(policy.max_concurrent_loads).unwrap_or(u64::MAX))
                .build(),
            load_permits: Arc::new(Semaphore::new(policy.max_concurrent_loads)),
        })
    }

    /// Returns the provider for administrative invalidation or warmup.
    #[must_use]
    pub const fn provider(&self) -> &P {
        &self.provider
    }

    /// Gets a record or coalesces an authoritative load for the same key.
    ///
    /// A provider error is an explicit degraded bypass, never an authoritative miss. The loader is
    /// called once per same-key in-process burst. `Ok(None)` may be cached only when a short
    /// `negative_ttl` was configured. Cache write failures do not replace authoritative results.
    ///
    /// # Errors
    ///
    /// Returns a shared [`CacheLoadError`]. Authoritative errors are never cached; overload starts
    /// no authoritative work.
    pub async fn get_or_load<F, Fut, E>(
        &self,
        key: CacheKey,
        loader: F,
    ) -> Result<Option<CacheValue>, Arc<CacheLoadError<E>>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Option<CacheValue>, E>> + Send + 'static,
        E: Send + Sync + 'static,
    {
        match self.provider.get(&key).await {
            Ok(CacheLookup::Hit(record)) => return Ok(record.into_value()),
            Ok(CacheLookup::Stale(_)) => record_provider(P::KIND, "stale"),
            Ok(CacheLookup::Miss) => {}
            Err(_) => record_provider(P::KIND, "error"),
        }

        let provider = self.provider.clone();
        let policy = self.policy;
        let load_key = key.clone();
        let load_permits = Arc::clone(&self.load_permits);
        let result = self
            .in_flight
            .try_get_with(key.clone(), async move {
                let _permit = load_permits
                    .try_acquire_owned()
                    .map_err(|_| CacheLoadError::Overloaded)?;
                match provider.get(&load_key).await {
                    Ok(CacheLookup::Hit(record)) => return Ok(record.into_value()),
                    Ok(CacheLookup::Stale(_) | CacheLookup::Miss) | Err(_) => {}
                }
                record_provider(P::KIND, "load");
                let value = loader().await.map_err(CacheLoadError::Authoritative)?;
                match &value {
                    Some(value) => {
                        let _ = provider
                            .put(load_key, CacheRecord::Value(value.clone()), policy.positive)
                            .await;
                    }
                    None => {
                        if let Some(negative_ttl) = policy.negative_ttl {
                            let _ = provider
                                .put(
                                    load_key,
                                    CacheRecord::Negative,
                                    CachePolicy::fresh(negative_ttl),
                                )
                                .await;
                        }
                    }
                }
                Ok(value)
            })
            .await;
        if result.is_ok() {
            self.in_flight.invalidate(&key).await;
        }
        result
    }
}

impl CacheRecord {
    fn into_value(self) -> Option<CacheValue> {
        match self {
            Self::Value(value) => Some(value),
            Self::Negative => None,
        }
    }
}

fn record_provider(provider: CacheProviderKind, outcome: &'static str) {
    counter!(
        "rsk_cache_local_operations_total",
        "provider" => provider.metric_label(),
        "outcome" => outcome
    )
    .increment(1);
}
