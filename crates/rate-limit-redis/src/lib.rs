//! Atomic distributed rate limiting over [`omnius_redis_core::RedisCore`].
//!
//! One versioned Lua invocation owns every decision. Keys are fixed-size hashes of canonical
//! tenant, principal, resource, and policy inputs, then mapped into a configured number of
//! buckets. Collisions can only make limits stricter; they cannot grant extra capacity. Every
//! state key receives a bounded TTL. The default backend-failure policy is fail closed.

use std::{
    collections::VecDeque,
    fmt,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use metrics::counter;
use redis::cmd;
use omnius_health::HealthCheckSpec;
use omnius_redis_core::{RedisCommandFamily, RedisCore};
use omnius_runtime::Criticality;
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Version included in every Redis state key and covered by integration contracts.
pub const REDIS_RATE_LIMIT_SCRIPT_VERSION: &str = "v1";

const RATE_LIMIT_SCRIPT: &str = include_str!("rate_limit.lua");
const MAX_ID_BYTES: usize = 256;
const MAX_RESOURCE_BYTES: usize = 64;
const MAX_LIMIT: u32 = 100_000;
const MAX_BURST: u32 = 100_000;
const MAX_KEY_BUCKETS: u32 = 1_000_000;
const MAX_FAKE_CAPACITY: usize = 10_000;
const MAX_PERIOD: Duration = Duration::from_hours(24);
const MAX_STATE_TTL: Duration = Duration::from_hours(168);
const MAX_STATE_TTL_MILLIS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// Stable principal dimension included in the canonical rate-limit key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PrincipalKind {
    /// Human or service account identifier.
    Account,
    /// Stable non-secret API-key identifier.
    ApiKey,
    /// Trusted client IP resolved before the limiter.
    Ip,
    /// Authenticated versus anonymous state.
    AuthState,
    /// Internal service principal.
    Service,
}

impl PrincipalKind {
    const fn domain_byte(self) -> u8 {
        match self {
            Self::Account => 1,
            Self::ApiKey => 2,
            Self::Ip => 3,
            Self::AuthState => 4,
            Self::Service => 5,
        }
    }

    const fn metric_label(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::ApiKey => "api_key",
            Self::Ip => "ip",
            Self::AuthState => "auth_state",
            Self::Service => "service",
        }
    }
}

/// Canonical tenant/principal/resource identity represented only by a fixed-size digest.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RateLimitKey {
    fingerprint: [u8; 32],
    principal_kind: PrincipalKind,
}

impl RateLimitKey {
    /// Builds a key from bounded tenant, principal, and resource identifiers.
    ///
    /// Tenant and principal inputs may be opaque identifiers but must not be credentials or raw API
    /// keys. The resource is a stable operation or route-family identifier using portable key
    /// characters. Inputs are hashed immediately and are never retained or rendered.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitKeyError`] for empty, oversized, or non-portable components.
    pub fn new(
        tenant: &str,
        principal_kind: PrincipalKind,
        principal: &str,
        resource: &str,
    ) -> Result<Self, RateLimitKeyError> {
        validate_opaque_id(tenant, RateLimitKeyError::InvalidTenant)?;
        validate_opaque_id(principal, RateLimitKeyError::InvalidPrincipal)?;
        validate_resource(resource)?;

        let tenant_digest = digest_component(b"tenant", tenant.as_bytes());
        let principal_digest = digest_component(b"principal", principal.as_bytes());
        let resource_digest = digest_component(b"resource", resource.as_bytes());
        let mut digest = Sha256::new();
        digest.update(b"omnius-rate-limit-key-v1\0");
        digest.update(tenant_digest);
        digest.update([principal_kind.domain_byte()]);
        digest.update(principal_digest);
        digest.update(resource_digest);
        Ok(Self {
            fingerprint: digest.finalize().into(),
            principal_kind,
        })
    }

    /// Returns the fixed-size, non-reversible canonical fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Returns the principal dimension without revealing its identifier.
    #[must_use]
    pub const fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }
}

impl fmt::Debug for RateLimitKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitKey")
            .field("principal_kind", &self.principal_kind)
            .field("fingerprint", &"[REDACTED]")
            .finish()
    }
}

/// Invalid canonical rate-limit key input.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitKeyError {
    /// Tenant identity was empty or exceeded 256 bytes.
    #[error("rate-limit tenant identifier is invalid")]
    InvalidTenant,
    /// Principal identity was empty or exceeded 256 bytes.
    #[error("rate-limit principal identifier is invalid")]
    InvalidPrincipal,
    /// Resource was empty, exceeded 64 bytes, or used non-portable characters.
    #[error("rate-limit resource identifier is invalid")]
    InvalidResource,
}

/// Atomic algorithm selected for one policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RateLimitAlgorithm {
    /// Counter reset at an aligned window boundary.
    FixedWindow,
    /// Weighted current/previous counters approximate an exact sliding window.
    SlidingWindow,
    /// Generic cell rate algorithm with an explicit immediate burst.
    Gcra,
}

impl RateLimitAlgorithm {
    const fn script_code(self) -> u8 {
        match self {
            Self::FixedWindow => 1,
            Self::SlidingWindow => 2,
            Self::Gcra => 3,
        }
    }

    const fn metric_label(self) -> &'static str {
        match self {
            Self::FixedWindow => "fixed_window",
            Self::SlidingWindow => "sliding_window",
            Self::Gcra => "gcra",
        }
    }
}

/// Validated fixed-window, sliding-window, or GCRA policy.
#[derive(Clone, Eq, PartialEq)]
pub struct RateLimitPolicy {
    algorithm: RateLimitAlgorithm,
    limit: u32,
    period_us: u64,
    burst: u32,
    storage_token: String,
}

impl RateLimitPolicy {
    /// Creates a fixed-window policy.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitPolicyError`] for a zero/excessive limit or period.
    pub fn fixed_window(limit: u32, period: Duration) -> Result<Self, RateLimitPolicyError> {
        Self::new(RateLimitAlgorithm::FixedWindow, limit, period, limit)
    }

    /// Creates a weighted sliding-window counter policy.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitPolicyError`] for a zero/excessive limit or period.
    pub fn sliding_window(limit: u32, period: Duration) -> Result<Self, RateLimitPolicyError> {
        Self::new(RateLimitAlgorithm::SlidingWindow, limit, period, limit)
    }

    /// Creates a GCRA policy with `rate` arrivals per period and an immediate burst capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitPolicyError`] for invalid bounds or a theoretical-arrival retention
    /// horizon above seven days.
    pub fn gcra(rate: u32, period: Duration, burst: u32) -> Result<Self, RateLimitPolicyError> {
        Self::new(RateLimitAlgorithm::Gcra, rate, period, burst)
    }

    /// Returns the selected atomic algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> RateLimitAlgorithm {
        self.algorithm
    }

    /// Returns the fixed/sliding limit or GCRA arrival rate.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Returns the policy period.
    #[must_use]
    pub const fn period(&self) -> Duration {
        Duration::from_micros(self.period_us)
    }

    /// Returns the immediate GCRA burst or the window limit for counter policies.
    #[must_use]
    pub const fn burst(&self) -> u32 {
        self.burst
    }

    fn new(
        algorithm: RateLimitAlgorithm,
        limit: u32,
        period: Duration,
        burst: u32,
    ) -> Result<Self, RateLimitPolicyError> {
        if limit == 0 || limit > MAX_LIMIT {
            return Err(RateLimitPolicyError::InvalidLimit);
        }
        if burst == 0 || burst > MAX_BURST {
            return Err(RateLimitPolicyError::InvalidBurst);
        }
        let period_us = duration_micros(period)?;
        if algorithm == RateLimitAlgorithm::Gcra && u64::from(limit) > period_us {
            return Err(RateLimitPolicyError::RateExceedsClockResolution);
        }
        let retention_us = match algorithm {
            RateLimitAlgorithm::FixedWindow => period_us,
            RateLimitAlgorithm::SlidingWindow => period_us
                .checked_mul(2)
                .ok_or(RateLimitPolicyError::RetentionTooLong)?,
            RateLimitAlgorithm::Gcra => period_us
                .div_ceil(u64::from(limit))
                .checked_mul(u64::from(burst))
                .ok_or(RateLimitPolicyError::RetentionTooLong)?,
        };
        if retention_us > duration_as_micros(MAX_STATE_TTL) {
            return Err(RateLimitPolicyError::RetentionTooLong);
        }
        let storage_token = policy_storage_token(algorithm, limit, period_us, burst);
        Ok(Self {
            algorithm,
            limit,
            period_us,
            burst,
            storage_token,
        })
    }

    const fn max_cost(&self) -> u32 {
        match self.algorithm {
            RateLimitAlgorithm::FixedWindow | RateLimitAlgorithm::SlidingWindow => self.limit,
            RateLimitAlgorithm::Gcra => self.burst,
        }
    }

    const fn capacity(&self) -> u32 {
        self.max_cost()
    }
}

impl fmt::Debug for RateLimitPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitPolicy")
            .field("algorithm", &self.algorithm)
            .field("limit", &self.limit)
            .field("period_us", &self.period_us)
            .field("burst", &self.burst)
            .finish_non_exhaustive()
    }
}

/// Invalid distributed rate-limit policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitPolicyError {
    /// Limit/rate was zero or exceeded 100,000.
    #[error("rate-limit limit is invalid")]
    InvalidLimit,
    /// Period was below one millisecond, above one day, or not whole microseconds.
    #[error("rate-limit period is invalid")]
    InvalidPeriod,
    /// GCRA required an emission interval below Redis's microsecond clock resolution.
    #[error("GCRA rate exceeds Redis clock resolution")]
    RateExceedsClockResolution,
    /// Burst was zero or exceeded 100,000.
    #[error("rate-limit burst is invalid")]
    InvalidBurst,
    /// Maximum retained state would exceed seven days.
    #[error("rate-limit state retention exceeds seven days")]
    RetentionTooLong,
}

/// One validated quota decision request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitRequest {
    key: RateLimitKey,
    policy: RateLimitPolicy,
    cost: u32,
}

impl RateLimitRequest {
    /// Creates a request with a positive cost no larger than one full policy capacity.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitRequestError`] for an invalid cost.
    pub fn new(
        key: RateLimitKey,
        policy: RateLimitPolicy,
        cost: u32,
    ) -> Result<Self, RateLimitRequestError> {
        if cost == 0 || cost > policy.max_cost() {
            return Err(RateLimitRequestError::InvalidCost);
        }
        Ok(Self { key, policy, cost })
    }

    /// Returns the canonical key.
    #[must_use]
    pub const fn key(&self) -> &RateLimitKey {
        &self.key
    }

    /// Returns the validated policy.
    #[must_use]
    pub const fn policy(&self) -> &RateLimitPolicy {
        &self.policy
    }

    /// Returns the charged capacity units.
    #[must_use]
    pub const fn cost(&self) -> u32 {
        self.cost
    }
}

/// Invalid rate-limit request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitRequestError {
    /// Cost was zero or exceeded the policy's full capacity.
    #[error("rate-limit request cost is invalid")]
    InvalidCost,
}

/// Explicit backend failure behavior.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FailurePolicy {
    /// Deny when Redis is unavailable, times out, or contains invalid state.
    #[default]
    Closed,
    /// Allow on backend failure. This requires an explicit application security decision.
    Open,
}

/// Stable reason for a limiter decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionReason {
    /// Capacity remained under the limit.
    WithinLimit,
    /// Atomic state was already exhausted.
    LimitExceeded,
    /// Redis timed out, failed, or returned invalid script state.
    BackendUnavailable,
}

/// A complete enforcement decision with bounded retry metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitDecision {
    allowed: bool,
    reason: DecisionReason,
    remaining: Option<u32>,
    retry_after: Option<Duration>,
    reset_after: Option<Duration>,
}

impl RateLimitDecision {
    /// Builds an allowed decision for deterministic fakes.
    #[must_use]
    pub const fn allow(remaining: u32, reset_after: Duration) -> Self {
        Self {
            allowed: true,
            reason: DecisionReason::WithinLimit,
            remaining: Some(remaining),
            retry_after: None,
            reset_after: Some(reset_after),
        }
    }

    /// Builds a quota-exhausted decision for deterministic fakes.
    #[must_use]
    pub const fn deny(remaining: u32, retry_after: Duration, reset_after: Duration) -> Self {
        Self {
            allowed: false,
            reason: DecisionReason::LimitExceeded,
            remaining: Some(remaining),
            retry_after: Some(retry_after),
            reset_after: Some(reset_after),
        }
    }

    /// Reports whether the caller may proceed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// Returns the stable decision reason.
    #[must_use]
    pub const fn reason(&self) -> DecisionReason {
        self.reason
    }

    /// Returns immediately available capacity when Redis supplied authoritative state.
    #[must_use]
    pub const fn remaining(&self) -> Option<u32> {
        self.remaining
    }

    /// Returns a bounded retry delay for quota denial.
    #[must_use]
    pub const fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }

    /// Returns bounded state reset/drain time when authoritative state was available.
    #[must_use]
    pub const fn reset_after(&self) -> Option<Duration> {
        self.reset_after
    }

    const fn unavailable(policy: FailurePolicy) -> Self {
        Self {
            allowed: matches!(policy, FailurePolicy::Open),
            reason: DecisionReason::BackendUnavailable,
            remaining: None,
            retry_after: None,
            reset_after: None,
        }
    }
}

/// Fixed low-cardinality provider class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RateLimiterKind {
    /// Atomic Redis provider.
    Redis,
    /// Deterministic in-memory fake.
    Fake,
}

/// Static rate-limiter port shared by the Redis provider and deterministic fake.
pub trait RateLimiter: Clone + Send + Sync + 'static {
    /// Fixed telemetry/provider identity.
    const KIND: RateLimiterKind;

    /// Atomically evaluates one request and applies the provider's explicit failure policy.
    fn check(&self, request: &RateLimitRequest) -> impl Future<Output = RateLimitDecision> + Send;
}

/// Redis limiter configuration with a hard live-key bucket bound per policy and algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisRateLimiterConfig {
    /// Maximum possible Redis keys for any one policy/algorithm combination.
    pub key_buckets: u32,
    /// Enforcement action when Redis cannot authoritatively decide.
    pub failure_policy: FailurePolicy,
}

impl Default for RedisRateLimiterConfig {
    fn default() -> Self {
        Self {
            key_buckets: MAX_KEY_BUCKETS,
            failure_policy: FailurePolicy::Closed,
        }
    }
}

impl RedisRateLimiterConfig {
    /// Validates the key cardinality bound.
    ///
    /// # Errors
    ///
    /// Returns [`RedisRateLimiterConfigError`] for zero or more than one million buckets.
    pub fn validate(self) -> Result<Self, RedisRateLimiterConfigError> {
        if self.key_buckets == 0 || self.key_buckets > MAX_KEY_BUCKETS {
            Err(RedisRateLimiterConfigError::InvalidKeyBuckets)
        } else {
            Ok(self)
        }
    }
}

/// Invalid Redis limiter configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedisRateLimiterConfigError {
    /// Key buckets were zero or exceeded one million.
    #[error("Redis rate-limit key bucket count is invalid")]
    InvalidKeyBuckets,
}

/// Safe Redis limiter setup/diagnostic failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RedisRateLimitError {
    /// Redis core rejected a supposedly bounded storage key.
    #[error("Redis rate-limit storage key is invalid")]
    InvalidStorageKey,
}

/// Atomic Redis fixed/sliding/GCRA limiter.
#[derive(Clone)]
pub struct RedisRateLimiter {
    redis: RedisCore,
    key_buckets: u32,
    failure_policy: FailurePolicy,
}

impl RedisRateLimiter {
    /// Creates a limiter over enabled Redis connectivity.
    ///
    /// # Errors
    ///
    /// Returns [`RedisRateLimiterConfigError`] for an invalid cardinality bound.
    pub fn new(
        redis: RedisCore,
        config: RedisRateLimiterConfig,
    ) -> Result<Self, RedisRateLimiterConfigError> {
        let config = config.validate()?;
        Ok(Self {
            redis,
            key_buckets: config.key_buckets,
            failure_policy: config.failure_policy,
        })
    }

    /// Returns Redis connectivity health with criticality matching the failure policy.
    ///
    /// Fail-closed providers are required for readiness. An explicitly fail-open provider is
    /// degraded so its configured bypass remains reachable during a Redis outage.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        let criticality = match self.failure_policy {
            FailurePolicy::Closed => Criticality::Required,
            FailurePolicy::Open => Criticality::Degraded,
        };
        self.redis.health_check_with_criticality(criticality)
    }

    /// Builds the opaque versioned Redis key used for a request.
    ///
    /// The returned key contains no tenant, principal, or resource input and is safe for bounded
    /// diagnostics and integration assertions.
    ///
    /// # Errors
    ///
    /// Returns [`RedisRateLimitError`] if Redis core rejects the bounded components.
    pub fn storage_key_for(
        &self,
        request: &RateLimitRequest,
    ) -> Result<String, RedisRateLimitError> {
        let bucket = storage_bucket(&request.key.fingerprint, self.key_buckets).to_string();
        self.redis
            .key(&[
                "rate-limit",
                REDIS_RATE_LIMIT_SCRIPT_VERSION,
                request.policy.algorithm.metric_label(),
                &request.policy.storage_token,
                &bucket,
            ])
            .map_err(|_| RedisRateLimitError::InvalidStorageKey)
    }

    async fn check_inner(&self, request: &RateLimitRequest) -> RateLimitDecision {
        let Ok(storage_key) = self.storage_key_for(request) else {
            return self.unavailable(request);
        };
        let mut command = cmd("EVAL");
        command
            .arg(RATE_LIMIT_SCRIPT)
            .arg(1)
            .arg(storage_key)
            .arg(request.policy.algorithm.script_code())
            .arg(request.policy.limit)
            .arg(request.policy.period_us)
            .arg(request.policy.burst)
            .arg(request.cost)
            .arg(duration_as_micros(MAX_STATE_TTL));
        let result = self
            .redis
            .query::<(i64, i64, i64, i64)>(RedisCommandFamily::RateLimit, command)
            .await;
        let decision = match result {
            Ok(raw) => parse_script_decision(raw, &request.policy)
                .unwrap_or_else(|| RateLimitDecision::unavailable(self.failure_policy)),
            Err(_) => RateLimitDecision::unavailable(self.failure_policy),
        };
        record_decision(request, &decision);
        decision
    }

    fn unavailable(&self, request: &RateLimitRequest) -> RateLimitDecision {
        let decision = RateLimitDecision::unavailable(self.failure_policy);
        record_decision(request, &decision);
        decision
    }
}

impl fmt::Debug for RedisRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisRateLimiter")
            .field("redis", &self.redis)
            .field("key_buckets", &self.key_buckets)
            .field("failure_policy", &self.failure_policy)
            .finish_non_exhaustive()
    }
}

impl RateLimiter for RedisRateLimiter {
    const KIND: RateLimiterKind = RateLimiterKind::Redis;

    async fn check(&self, request: &RateLimitRequest) -> RateLimitDecision {
        self.check_inner(request).await
    }
}

/// Bounded fake configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FakeRateLimiterConfig {
    /// Maximum captured calls and queued decisions.
    pub capacity: usize,
    /// Failure action when the fake is unavailable or full.
    pub failure_policy: FailurePolicy,
}

impl Default for FakeRateLimiterConfig {
    fn default() -> Self {
        Self {
            capacity: 128,
            failure_policy: FailurePolicy::Closed,
        }
    }
}

impl FakeRateLimiterConfig {
    fn validate(self) -> Result<Self, FakeRateLimiterError> {
        if self.capacity == 0 || self.capacity > MAX_FAKE_CAPACITY {
            Err(FakeRateLimiterError::InvalidCapacity)
        } else {
            Ok(self)
        }
    }
}

/// Value-free captured fake call.
#[derive(Clone, Eq, PartialEq)]
pub struct RateLimitCall {
    algorithm: RateLimitAlgorithm,
    principal_kind: PrincipalKind,
    fingerprint: [u8; 32],
    cost: u32,
}

impl RateLimitCall {
    /// Returns the selected algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> RateLimitAlgorithm {
        self.algorithm
    }

    /// Returns the principal dimension.
    #[must_use]
    pub const fn principal_kind(&self) -> PrincipalKind {
        self.principal_kind
    }

    /// Returns the non-reversible canonical key fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    /// Returns charged capacity units.
    #[must_use]
    pub const fn cost(&self) -> u32 {
        self.cost
    }
}

impl fmt::Debug for RateLimitCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RateLimitCall")
            .field("algorithm", &self.algorithm)
            .field("principal_kind", &self.principal_kind)
            .field("fingerprint", &"[REDACTED]")
            .field("cost", &self.cost)
            .finish()
    }
}

#[derive(Debug)]
struct FakeState {
    available: bool,
    planned: VecDeque<RateLimitDecision>,
    calls: Vec<RateLimitCall>,
    fallback: RateLimitDecision,
}

/// Deterministic bounded fake implementing the production rate-limiter port.
#[derive(Clone, Debug)]
pub struct FakeRateLimiter {
    state: Arc<Mutex<FakeState>>,
    capacity: usize,
    failure_policy: FailurePolicy,
}

impl FakeRateLimiter {
    /// Creates a fake with a deterministic fallback after queued decisions are exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`FakeRateLimiterError::InvalidCapacity`] for an invalid bound.
    pub fn new(
        config: FakeRateLimiterConfig,
        fallback: RateLimitDecision,
    ) -> Result<Self, FakeRateLimiterError> {
        let config = config.validate()?;
        Ok(Self {
            state: Arc::new(Mutex::new(FakeState {
                available: true,
                planned: VecDeque::new(),
                calls: Vec::new(),
                fallback,
            })),
            capacity: config.capacity,
            failure_policy: config.failure_policy,
        })
    }

    /// Queues one decision ahead of the fallback.
    ///
    /// # Errors
    ///
    /// Returns [`FakeRateLimiterError`] when state is unavailable or the queue is full.
    pub fn enqueue(&self, decision: RateLimitDecision) -> Result<(), FakeRateLimiterError> {
        let mut state = self.state.lock().map_err(|_| FakeRateLimiterError::State)?;
        if state.planned.len() >= self.capacity {
            return Err(FakeRateLimiterError::Capacity);
        }
        state.planned.push_back(decision);
        Ok(())
    }

    /// Sets deterministic backend availability.
    ///
    /// # Errors
    ///
    /// Returns [`FakeRateLimiterError::State`] if synchronization state is unavailable.
    pub fn set_available(&self, available: bool) -> Result<(), FakeRateLimiterError> {
        let mut state = self.state.lock().map_err(|_| FakeRateLimiterError::State)?;
        state.available = available;
        Ok(())
    }

    /// Returns captured value-free calls.
    ///
    /// # Errors
    ///
    /// Returns [`FakeRateLimiterError::State`] if synchronization state is unavailable.
    pub fn calls(&self) -> Result<Vec<RateLimitCall>, FakeRateLimiterError> {
        self.state
            .lock()
            .map(|state| state.calls.clone())
            .map_err(|_| FakeRateLimiterError::State)
    }

    fn check_now(&self, request: &RateLimitRequest) -> RateLimitDecision {
        let Ok(mut state) = self.state.lock() else {
            return RateLimitDecision::unavailable(self.failure_policy);
        };
        if !state.available || state.calls.len() >= self.capacity {
            return RateLimitDecision::unavailable(self.failure_policy);
        }
        state.calls.push(RateLimitCall {
            algorithm: request.policy.algorithm,
            principal_kind: request.key.principal_kind,
            fingerprint: request.key.fingerprint,
            cost: request.cost,
        });
        if let Some(decision) = state.planned.pop_front() {
            decision
        } else {
            state.fallback.clone()
        }
    }
}

impl RateLimiter for FakeRateLimiter {
    const KIND: RateLimiterKind = RateLimiterKind::Fake;

    fn check(&self, request: &RateLimitRequest) -> impl Future<Output = RateLimitDecision> + Send {
        std::future::ready(self.check_now(request))
    }
}

/// Invalid deterministic fake setup or state.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FakeRateLimiterError {
    /// Capacity was zero or exceeded 10,000.
    #[error("fake rate-limiter capacity is invalid")]
    InvalidCapacity,
    /// Planned decision capacity was exhausted.
    #[error("fake rate-limiter capacity reached")]
    Capacity,
    /// Synchronization state was poisoned.
    #[error("fake rate-limiter state is unavailable")]
    State,
}

fn validate_opaque_id(value: &str, error: RateLimitKeyError) -> Result<(), RateLimitKeyError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_resource(resource: &str) -> Result<(), RateLimitKeyError> {
    if resource.is_empty()
        || resource.len() > MAX_RESOURCE_BYTES
        || !resource
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(RateLimitKeyError::InvalidResource)
    } else {
        Ok(())
    }
}

fn digest_component(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update([0]);
    digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(value);
    digest.finalize().into()
}

fn policy_storage_token(
    algorithm: RateLimitAlgorithm,
    limit: u32,
    period_us: u64,
    burst: u32,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"omnius-rate-limit-policy-v1\0");
    digest.update([algorithm.script_code()]);
    digest.update(limit.to_be_bytes());
    digest.update(period_us.to_be_bytes());
    digest.update(burst.to_be_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

fn duration_micros(duration: Duration) -> Result<u64, RateLimitPolicyError> {
    if duration < Duration::from_millis(1)
        || duration > MAX_PERIOD
        || !duration.subsec_nanos().is_multiple_of(1_000)
    {
        return Err(RateLimitPolicyError::InvalidPeriod);
    }
    u64::try_from(duration.as_micros()).map_err(|_| RateLimitPolicyError::InvalidPeriod)
}

fn duration_as_micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn storage_bucket(fingerprint: &[u8; 32], buckets: u32) -> u32 {
    let prefix = u64::from_be_bytes([
        fingerprint[0],
        fingerprint[1],
        fingerprint[2],
        fingerprint[3],
        fingerprint[4],
        fingerprint[5],
        fingerprint[6],
        fingerprint[7],
    ]);
    u32::try_from(prefix % u64::from(buckets)).unwrap_or_default()
}

fn parse_script_decision(
    raw: (i64, i64, i64, i64),
    policy: &RateLimitPolicy,
) -> Option<RateLimitDecision> {
    let (allowed, remaining, retry_ms, reset_ms) = raw;
    if !matches!(allowed, 0 | 1) || reset_ms <= 0 {
        return None;
    }
    let remaining = u32::try_from(remaining).ok()?;
    let retry_ms = u64::try_from(retry_ms).ok()?;
    let reset_ms = u64::try_from(reset_ms).ok()?;
    if remaining > policy.capacity()
        || retry_ms > MAX_STATE_TTL_MILLIS
        || reset_ms > MAX_STATE_TTL_MILLIS
        || (allowed == 1 && retry_ms != 0)
        || (allowed == 0 && retry_ms == 0)
    {
        return None;
    }
    if allowed == 1 {
        Some(RateLimitDecision::allow(
            remaining,
            Duration::from_millis(reset_ms),
        ))
    } else {
        Some(RateLimitDecision::deny(
            remaining,
            Duration::from_millis(retry_ms),
            Duration::from_millis(reset_ms),
        ))
    }
}

fn record_decision(request: &RateLimitRequest, decision: &RateLimitDecision) {
    let outcome = match (decision.reason, decision.allowed) {
        (DecisionReason::WithinLimit, true) => "allowed",
        (DecisionReason::LimitExceeded, false) => "denied",
        (DecisionReason::BackendUnavailable, false) => "error_closed",
        (DecisionReason::BackendUnavailable, true) => "error_open",
        (DecisionReason::WithinLimit, false) | (DecisionReason::LimitExceeded, true) => "invalid",
    };
    counter!(
        "omnius_rate_limit_redis_decisions_total",
        "algorithm" => request.policy.algorithm.metric_label(),
        "principal" => request.key.principal_kind.metric_label(),
        "outcome" => outcome
    )
    .increment(1);
}
