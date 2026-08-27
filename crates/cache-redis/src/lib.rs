//! Shared Redis cache provider over [`omnius_redis_core::RedisCore`].
//!
//! Values use a bounded versioned binary envelope so stale retention and negative records remain
//! distinguishable across instances. Connectivity failures remain explicit provider errors;
//! [`omnius_cache_local::CacheAside`] converts them into a degraded authoritative-load bypass.

use metrics::counter;
use redis::cmd;
use omnius_cache_local::{
    CacheKey, CacheLookup, CachePolicy, CacheProvider, CacheProviderKind, CacheRecord, CacheTtl,
    CacheValue, CacheValueError,
};
use omnius_redis_core::{RedisCommandFamily, RedisConfigError, RedisCore};
use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
const BOUNDED_GET_SCRIPT: &str = r"
local length = redis.call('STRLEN', KEYS[1])
if length > tonumber(ARGV[1]) then
    return {0, false}
end
local value = redis.call('GET', KEYS[1])
if not value then
    return {1, false}
end
return {2, value}
";

const ENVELOPE_MAGIC: &[u8; 4] = b"OMNC";
const ENVELOPE_VERSION: u8 = 1;
const ENVELOPE_HEADER_BYTES: usize = 14;
const VALUE_KIND: u8 = 1;
const NEGATIVE_KIND: u8 = 2;
const MAX_JITTER_PERCENT: u8 = 25;

/// Redis cache provider configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisCacheConfig {
    /// Maximum downward TTL jitter percentage.
    pub ttl_jitter_percent: u8,
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self {
            ttl_jitter_percent: 10,
        }
    }
}

impl RedisCacheConfig {
    /// Validates the TTL jitter bound.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCacheConfigError`] above 25 percent.
    pub fn validate(self) -> Result<Self, RedisCacheConfigError> {
        if self.ttl_jitter_percent > MAX_JITTER_PERCENT {
            Err(RedisCacheConfigError::InvalidJitter)
        } else {
            Ok(self)
        }
    }
}

/// Invalid Redis cache configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedisCacheConfigError {
    /// TTL jitter exceeded 25 percent.
    #[error("Redis cache TTL jitter exceeds 25 percent")]
    InvalidJitter,
}

/// Redis cache operation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedisCacheError {
    /// Redis connectivity, timeout, authentication, or command execution failed.
    #[error("Redis cache is unavailable")]
    Unavailable,
    /// The provider could not build a bounded versioned key.
    #[error("Redis cache key is invalid")]
    InvalidKey,
    /// The serialized envelope exceeded the configured Redis value bound.
    #[error("serialized cache value exceeds configured Redis bound")]
    ValueTooLarge,
    /// A stored value did not use the supported bounded envelope.
    #[error("Redis cache value is corrupt or unsupported")]
    CorruptValue,
    /// The system clock could not produce a safe expiration timestamp.
    #[error("Redis cache expiration timestamp is unavailable")]
    Clock,
}

/// Redis-backed cache provider with versioned keys and jittered TTLs.
#[derive(Clone)]
pub struct RedisCache {
    redis: RedisCore,
    jitter_percent: u8,
    nonce: Arc<AtomicU64>,
}

impl fmt::Debug for RedisCache {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisCache")
            .field("redis", &self.redis)
            .field("ttl_jitter_percent", &self.jitter_percent)
            .finish_non_exhaustive()
    }
}

impl RedisCache {
    /// Creates a Redis cache provider from enabled Redis connectivity.
    ///
    /// # Errors
    ///
    /// Returns [`RedisCacheConfigError`] when jitter violates the policy bound.
    pub fn new(redis: RedisCore, config: RedisCacheConfig) -> Result<Self, RedisCacheConfigError> {
        let config = config.validate()?;
        Ok(Self {
            redis,
            jitter_percent: config.ttl_jitter_percent,
            nonce: Arc::new(AtomicU64::new(0)),
        })
    }

    fn redis_key(&self, key: &CacheKey) -> Result<String, RedisCacheError> {
        self.redis
            .key(&["cache", key.as_str()])
            .map_err(map_key_error)
    }

    fn jittered_ttl(&self, ttl: CacheTtl, key: &CacheKey) -> Duration {
        let ttl_millis = u64::try_from(ttl.get().as_millis()).unwrap_or(u64::MAX);
        let window = ttl_millis.saturating_mul(u64::from(self.jitter_percent)) / 100;
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

impl CacheProvider for RedisCache {
    type Error = RedisCacheError;

    const KIND: CacheProviderKind = CacheProviderKind::Redis;

    async fn get(&self, key: &CacheKey) -> Result<CacheLookup, Self::Error> {
        let redis_key = self.redis_key(key)?;
        let mut command = cmd("EVAL");
        command
            .arg(BOUNDED_GET_SCRIPT)
            .arg(1)
            .arg(redis_key)
            .arg(self.redis.max_value_bytes());
        let (status, encoded) = self
            .redis
            .query::<(u8, Option<Vec<u8>>)>(RedisCommandFamily::Cache, command)
            .await
            .map_err(|_| {
                record("error");
                RedisCacheError::Unavailable
            })?;
        let encoded = match (status, encoded) {
            (0, _) => {
                record("error");
                return Err(RedisCacheError::ValueTooLarge);
            }
            (1, None) => {
                record("miss");
                return Ok(CacheLookup::Miss);
            }
            (2, Some(encoded)) => encoded,
            _ => {
                record("error");
                return Err(RedisCacheError::CorruptValue);
            }
        };
        let (record, fresh_until) = decode(encoded)?;
        let lookup = if SystemTime::now() >= fresh_until {
            record_metric("stale", CacheLookup::Stale(record))
        } else {
            record_metric("hit", CacheLookup::Hit(record))
        };
        Ok(lookup)
    }

    async fn put(
        &self,
        key: CacheKey,
        record_value: CacheRecord,
        policy: CachePolicy,
    ) -> Result<(), Self::Error> {
        let redis_key = self.redis_key(&key)?;
        let fresh_for = self.jittered_ttl(policy.fresh_ttl(), &key);
        let fresh_until = SystemTime::now()
            .checked_add(fresh_for)
            .ok_or(RedisCacheError::Clock)?;
        let serialized_len = ENVELOPE_HEADER_BYTES
            .checked_add(record_len(&record_value))
            .ok_or(RedisCacheError::ValueTooLarge)?;
        if serialized_len > self.redis.max_value_bytes() {
            record("error");
            return Err(RedisCacheError::ValueTooLarge);
        }
        let encoded = encode(record_value, fresh_until)?;
        let hard_ttl = fresh_for.saturating_add(policy.stale_ttl().unwrap_or_default());
        let hard_ttl_millis = u64::try_from(hard_ttl.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let mut command = cmd("SET");
        command
            .arg(redis_key)
            .arg(encoded)
            .arg("PX")
            .arg(hard_ttl_millis);
        self.redis
            .query::<()>(RedisCommandFamily::Cache, command)
            .await
            .map_err(|_| {
                record("error");
                RedisCacheError::Unavailable
            })
    }

    async fn invalidate(&self, key: &CacheKey) -> Result<(), Self::Error> {
        let redis_key = self.redis_key(key)?;
        let mut command = cmd("UNLINK");
        command.arg(redis_key);
        self.redis
            .query::<u64>(RedisCommandFamily::Cache, command)
            .await
            .map(|_| ())
            .map_err(|_| {
                record("error");
                RedisCacheError::Unavailable
            })
    }
}

fn encode(record: CacheRecord, fresh_until: SystemTime) -> Result<Vec<u8>, RedisCacheError> {
    let fresh_until_millis = fresh_until
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RedisCacheError::Clock)?
        .as_millis();
    let fresh_until_millis =
        u64::try_from(fresh_until_millis).map_err(|_| RedisCacheError::Clock)?;
    let (kind, value) = match record {
        CacheRecord::Value(value) => (VALUE_KIND, Some(value)),
        CacheRecord::Negative => (NEGATIVE_KIND, None),
    };
    let value_len = value.as_ref().map_or(0, CacheValue::len);
    let mut encoded = Vec::with_capacity(ENVELOPE_HEADER_BYTES.saturating_add(value_len));
    encoded.extend_from_slice(ENVELOPE_MAGIC);
    encoded.push(ENVELOPE_VERSION);
    encoded.push(kind);
    encoded.extend_from_slice(&fresh_until_millis.to_be_bytes());
    if let Some(value) = value {
        encoded.extend_from_slice(value.as_bytes());
    }
    Ok(encoded)
}

fn decode(mut encoded: Vec<u8>) -> Result<(CacheRecord, SystemTime), RedisCacheError> {
    if encoded.len() < ENVELOPE_HEADER_BYTES
        || &encoded[..4] != ENVELOPE_MAGIC
        || encoded[4] != ENVELOPE_VERSION
    {
        record("error");
        return Err(RedisCacheError::CorruptValue);
    }
    let timestamp = encoded[6..14]
        .try_into()
        .map(u64::from_be_bytes)
        .map_err(|_| RedisCacheError::CorruptValue)?;
    let fresh_until = UNIX_EPOCH
        .checked_add(Duration::from_millis(timestamp))
        .ok_or(RedisCacheError::Clock)?;
    let kind = encoded[5];
    let record_value = match kind {
        VALUE_KIND => {
            encoded.drain(..ENVELOPE_HEADER_BYTES);
            CacheRecord::Value(CacheValue::new(encoded).map_err(map_decode_value)?)
        }
        NEGATIVE_KIND if encoded.len() == ENVELOPE_HEADER_BYTES => CacheRecord::Negative,
        _ => {
            record("error");
            return Err(RedisCacheError::CorruptValue);
        }
    };
    Ok((record_value, fresh_until))
}

fn record_len(record: &CacheRecord) -> usize {
    match record {
        CacheRecord::Value(value) => value.len(),
        CacheRecord::Negative => 0,
    }
}

fn map_key_error(_error: RedisConfigError) -> RedisCacheError {
    record("error");
    RedisCacheError::InvalidKey
}

fn map_decode_value(_error: CacheValueError) -> RedisCacheError {
    record("error");
    RedisCacheError::CorruptValue
}

fn record_metric(outcome: &'static str, lookup: CacheLookup) -> CacheLookup {
    record(outcome);
    lookup
}

fn record(outcome: &'static str) {
    counter!("omnius_cache_redis_operations_total", "outcome" => outcome).increment(1);
}
