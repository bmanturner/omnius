use std::{
    collections::{HashMap, VecDeque},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use metrics::counter;
use thiserror::Error;

use crate::exposure::ExposureRecordInput;
use crate::{
    EvaluationContext, EvaluationSource, ExposureRecord, ExposureRecorder, FailureDefaultReason,
    FeatureFlagProvider, Flag, FlagKey, FlagLifecycle, FlagValue, FlagValueKind, FlagValueType,
    OpenFeatureProvider, ProviderError, ProviderEvaluation, ProviderKind, ProviderReason,
    ProviderRequest, StaticProvider, Variant,
};

/// Maximum live provider deadline accepted by [`EvaluationPolicy`].
pub const MAX_PROVIDER_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum cache lifetime accepted by [`EvaluationPolicy`].
pub const MAX_CACHE_TTL: Duration = Duration::from_mins(10);
/// Maximum context-scoped cache entries.
pub const MAX_CACHE_ENTRIES: usize = 10_000;

/// Validated timeout and context-scoped cache policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvaluationPolicy {
    provider_timeout: Duration,
    cache_ttl: Duration,
    cache_capacity: usize,
}

impl EvaluationPolicy {
    /// Creates a fail-safe evaluation policy.
    ///
    /// A zero cache TTL requires zero capacity and disables caching. Failure behavior is fixed:
    /// timeout, provider failure, missing flags, and invalid responses return the typed flag default.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationPolicyError`] for zero/oversized deadlines or inconsistent/unbounded
    /// cache settings.
    pub fn new(
        provider_timeout: Duration,
        cache_ttl: Duration,
        cache_capacity: usize,
    ) -> Result<Self, EvaluationPolicyError> {
        if provider_timeout.is_zero() {
            return Err(EvaluationPolicyError::ZeroTimeout);
        }
        if provider_timeout > MAX_PROVIDER_TIMEOUT {
            return Err(EvaluationPolicyError::TimeoutTooLong);
        }
        if cache_ttl > MAX_CACHE_TTL {
            return Err(EvaluationPolicyError::CacheTtlTooLong);
        }
        if cache_capacity > MAX_CACHE_ENTRIES {
            return Err(EvaluationPolicyError::CacheCapacityTooLarge);
        }
        if cache_ttl.is_zero() != (cache_capacity == 0) {
            return Err(EvaluationPolicyError::InconsistentCache);
        }
        Ok(Self {
            provider_timeout,
            cache_ttl,
            cache_capacity,
        })
    }

    /// Creates a policy with caching disabled.
    ///
    /// # Errors
    ///
    /// Returns [`EvaluationPolicyError`] when the deadline is zero or exceeds 10 seconds.
    pub fn without_cache(provider_timeout: Duration) -> Result<Self, EvaluationPolicyError> {
        Self::new(provider_timeout, Duration::ZERO, 0)
    }

    /// Returns the live provider deadline.
    #[must_use]
    pub const fn provider_timeout(self) -> Duration {
        self.provider_timeout
    }

    /// Returns the successful-response cache lifetime, or zero when disabled.
    #[must_use]
    pub const fn cache_ttl(self) -> Duration {
        self.cache_ttl
    }

    /// Returns the context-scoped cache entry bound.
    #[must_use]
    pub const fn cache_capacity(self) -> usize {
        self.cache_capacity
    }
}

impl Default for EvaluationPolicy {
    fn default() -> Self {
        Self {
            provider_timeout: Duration::from_millis(100),
            cache_ttl: Duration::from_secs(30),
            cache_capacity: 1_024,
        }
    }
}

/// Invalid evaluator timeout/cache policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum EvaluationPolicyError {
    /// Provider calls require a non-zero deadline.
    #[error("feature-flag provider timeout must be non-zero")]
    ZeroTimeout,
    /// Provider calls cannot wait longer than 10 seconds.
    #[error("feature-flag provider timeout exceeds 10 seconds")]
    TimeoutTooLong,
    /// Successful evaluations cannot be cached longer than 10 minutes.
    #[error("feature-flag cache TTL exceeds 10 minutes")]
    CacheTtlTooLong,
    /// The process-local cache cannot exceed 10000 entries.
    #[error("feature-flag cache exceeds 10000 entries")]
    CacheCapacityTooLarge,
    /// TTL and capacity must both enable or both disable caching.
    #[error("feature-flag cache TTL and capacity are inconsistent")]
    InconsistentCache,
}

/// One typed evaluated product value and its bounded provenance.
#[derive(Clone, Debug, PartialEq)]
pub struct Evaluation<T: FlagValueType> {
    value: T,
    source: EvaluationSource,
    provider_reason: Option<ProviderReason>,
    variant: Option<Variant>,
}

impl<T: FlagValueType> Evaluation<T> {
    /// Returns the typed value.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Consumes the details and returns the typed value.
    #[must_use]
    pub fn into_value(self) -> T {
        self.value
    }

    /// Returns whether the value came from a provider, cache, or typed failure default.
    #[must_use]
    pub const fn source(&self) -> EvaluationSource {
        self.source
    }

    /// Returns the normalized provider reason for provider/cache results.
    #[must_use]
    pub const fn provider_reason(&self) -> Option<ProviderReason> {
        self.provider_reason
    }

    /// Returns the bounded provider variation identifier, when supplied.
    #[must_use]
    pub const fn variant(&self) -> Option<&Variant> {
        self.variant.as_ref()
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct CacheKey {
    flag_key: FlagKey,
    value_kind: FlagValueKind,
    context: EvaluationContext,
}

#[derive(Clone)]
struct CacheEntry {
    value: FlagValue,
    provider_reason: ProviderReason,
    variant: Option<Variant>,
    expires_at: Instant,
}

struct EvaluationCache {
    entries: HashMap<CacheKey, CacheEntry>,
    insertion_order: VecDeque<CacheKey>,
}

impl EvaluationCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            insertion_order: VecDeque::with_capacity(capacity),
        }
    }

    fn get(&mut self, key: &CacheKey, now: Instant) -> Option<CacheEntry> {
        if self
            .entries
            .get(key)
            .is_some_and(|entry| entry.expires_at <= now)
        {
            self.entries.remove(key);
            self.insertion_order.retain(|queued| queued != key);
            return None;
        }
        self.entries.get(key).cloned()
    }

    fn insert(&mut self, key: CacheKey, entry: CacheEntry, capacity: usize) {
        if let Some(current) = self.entries.get_mut(&key) {
            *current = entry;
            return;
        }
        while self.entries.len() >= capacity {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.entries.insert(key, entry);
    }
}

/// Composed product feature-flag evaluator.
///
/// This is the exported composition boundary: inject one provider, one exposure recorder, and a
/// validated policy. Every evaluation enforces timeout, context-scoped successful-response caching,
/// typed failure defaults, bounded exposures, and low-cardinality metrics.
pub struct FeatureFlagEvaluator {
    provider: Arc<dyn FeatureFlagProvider>,
    exposure_recorder: Arc<dyn ExposureRecorder>,
    policy: EvaluationPolicy,
    cache: Mutex<EvaluationCache>,
}

impl FeatureFlagEvaluator {
    /// Composes an arbitrary application provider.
    #[must_use]
    pub fn new(
        provider: Arc<dyn FeatureFlagProvider>,
        exposure_recorder: Arc<dyn ExposureRecorder>,
        policy: EvaluationPolicy,
    ) -> Self {
        Self {
            provider,
            exposure_recorder,
            policy,
            cache: Mutex::new(EvaluationCache::new(policy.cache_capacity)),
        }
    }

    /// Composes an official `OpenFeature` SDK provider without admitting SDK global/client context.
    #[must_use]
    pub fn with_open_feature_provider(
        provider: Arc<dyn open_feature::provider::FeatureProvider>,
        exposure_recorder: Arc<dyn ExposureRecorder>,
        policy: EvaluationPolicy,
    ) -> Self {
        Self::new(
            Arc::new(OpenFeatureProvider::new(provider)),
            exposure_recorder,
            policy,
        )
    }

    /// Composes the bounded static provider for tests or a small deployment.
    #[must_use]
    pub fn with_static_provider(
        provider: StaticProvider,
        exposure_recorder: Arc<dyn ExposureRecorder>,
        policy: EvaluationPolicy,
    ) -> Self {
        Self::new(Arc::new(provider), exposure_recorder, policy)
    }

    /// Evaluates one typed product flag.
    ///
    /// Timeout and every safe provider error return `flag.default_value()`. Only successful,
    /// type-matched provider results are cached, and the complete bounded context participates in
    /// the cache key.
    pub async fn evaluate<T: FlagValueType>(
        &self,
        flag: &Flag<T>,
        context: &EvaluationContext,
    ) -> Evaluation<T> {
        let cache_key = CacheKey {
            flag_key: flag.key().clone(),
            value_kind: T::KIND,
            context: context.clone(),
        };
        if self.policy.cache_capacity > 0
            && let Some(entry) = self.cached(&cache_key)
            && let Some(value) = T::from_untyped(&entry.value)
        {
            let evaluation = Evaluation {
                value,
                source: EvaluationSource::Cache,
                provider_reason: Some(entry.provider_reason),
                variant: entry.variant,
            };
            self.emit_exposure(flag, context, &evaluation);
            return evaluation;
        }

        let request = ProviderRequest::new(flag.key(), T::KIND, context);
        let provider_result = tokio::time::timeout(
            self.policy.provider_timeout,
            self.provider.evaluate(request),
        )
        .await;

        let evaluation = match provider_result {
            Err(_) => Self::failure_default(flag, FailureDefaultReason::Timeout),
            Ok(Err(error)) => Self::failure_default(flag, map_provider_error(error)),
            Ok(Ok(details)) => match T::from_untyped(details.value()) {
                None => Self::failure_default(flag, FailureDefaultReason::InvalidResponse),
                Some(value) => {
                    if self.policy.cache_capacity > 0 {
                        self.cache_success(cache_key, &details);
                    }
                    Evaluation {
                        value,
                        source: EvaluationSource::Provider,
                        provider_reason: Some(details.reason()),
                        variant: details.variant().cloned(),
                    }
                }
            },
        };
        self.emit_exposure(flag, context, &evaluation);
        evaluation
    }

    fn cached(&self, key: &CacheKey) -> Option<CacheEntry> {
        self.cache
            .try_lock()
            .ok()
            .and_then(|mut cache| cache.get(key, Instant::now()))
    }

    fn cache_success(&self, key: CacheKey, details: &ProviderEvaluation) {
        let Some(expires_at) = Instant::now().checked_add(self.policy.cache_ttl) else {
            return;
        };
        if let Ok(mut cache) = self.cache.try_lock() {
            cache.insert(
                key,
                CacheEntry {
                    value: details.value().clone(),
                    provider_reason: details.reason(),
                    variant: details.variant().cloned(),
                    expires_at,
                },
                self.policy.cache_capacity,
            );
        }
    }

    fn failure_default<T: FlagValueType>(
        flag: &Flag<T>,
        reason: FailureDefaultReason,
    ) -> Evaluation<T> {
        Evaluation {
            value: flag.default_value().clone(),
            source: EvaluationSource::FailureDefault(reason),
            provider_reason: None,
            variant: None,
        }
    }

    fn emit_exposure<T: FlagValueType>(
        &self,
        flag: &Flag<T>,
        context: &EvaluationContext,
        evaluation: &Evaluation<T>,
    ) {
        let provider = self.provider.kind();
        counter!(
            "omnius_feature_flags_evaluations_total",
            "provider" => provider.metric_label(),
            "value_type" => T::KIND.metric_label(),
            "purpose" => flag.purpose().metric_label(),
            "source" => evaluation.source.metric_label(),
            "failure" => evaluation.source.failure_metric_label(),
        )
        .increment(1);

        let exposure = ExposureRecord::new(ExposureRecordInput {
            flag_key: flag.key().clone(),
            value_kind: T::KIND,
            purpose: flag.purpose(),
            provider,
            source: evaluation.source,
            provider_reason: evaluation.provider_reason,
            variant: evaluation.variant.clone(),
            subject_id: context.subject_id(),
            tenant_id: context.tenant_id(),
            temporary: matches!(flag.lifecycle(), FlagLifecycle::Temporary { .. }),
        });
        if let Err(error) = self.exposure_recorder.try_record(exposure) {
            counter!(
                "omnius_feature_flags_exposure_record_failures_total",
                "provider" => provider.metric_label(),
                "outcome" => error.metric_label(),
            )
            .increment(1);
        }
    }

    /// Returns the active validated evaluation policy.
    #[must_use]
    pub const fn policy(&self) -> EvaluationPolicy {
        self.policy
    }

    /// Returns the low-cardinality configured provider class.
    #[must_use]
    pub fn provider_kind(&self) -> ProviderKind {
        self.provider.kind()
    }
}

impl fmt::Debug for FeatureFlagEvaluator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FeatureFlagEvaluator")
            .field(
                "provider",
                &format_args!("[REDACTED; kind={:?}]", self.provider.kind()),
            )
            .field("exposure_recorder", &"[REDACTED]")
            .field("policy", &self.policy)
            .field("cache", &"[REDACTED]")
            .finish()
    }
}

const fn map_provider_error(error: ProviderError) -> FailureDefaultReason {
    match error {
        ProviderError::Unavailable => FailureDefaultReason::Unavailable,
        ProviderError::NotFound => FailureDefaultReason::NotFound,
        ProviderError::ContextRejected => FailureDefaultReason::ContextRejected,
        ProviderError::InvalidResponse => FailureDefaultReason::InvalidResponse,
    }
}
