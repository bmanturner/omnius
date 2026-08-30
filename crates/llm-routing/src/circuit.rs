use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use omnius_llm_core::{ModelCapabilityKey, ProviderError, ProviderErrorKind};
use thiserror::Error;

use crate::definition::{EndpointId, Region};

const MAX_SCOPE_ID_BYTES: usize = 256;

/// The routing level at which circuit evidence applies.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CircuitScopeKind {
    /// Every endpoint, region, and model for one provider.
    Provider,
    /// One provider endpoint.
    Endpoint,
    /// One provider region.
    Region,
    /// One exact provider model revision.
    Model,
}

/// A bounded, provider-neutral circuit evidence key.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct CircuitScope {
    kind: CircuitScopeKind,
    key: String,
}

impl CircuitScope {
    /// Creates a provider-wide circuit key.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidScope`] when the identifier is empty, oversized, or unsafe.
    pub fn provider(provider: impl Into<String>) -> Result<Self, CircuitError> {
        let provider = provider.into();
        validate_scope_id(&provider)?;
        Ok(Self {
            kind: CircuitScopeKind::Provider,
            key: provider,
        })
    }

    /// Creates an endpoint-scoped circuit key.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidScope`] when an identifier is empty, oversized, or unsafe.
    pub fn endpoint(
        provider: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Result<Self, CircuitError> {
        let provider = provider.into();
        let endpoint = endpoint.into();
        validate_scope_id(&provider)?;
        validate_scope_id(&endpoint)?;
        Ok(Self {
            kind: CircuitScopeKind::Endpoint,
            key: format!("{provider}\u{1f}{endpoint}"),
        })
    }

    /// Creates a region-scoped circuit key.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidScope`] when an identifier is empty, oversized, or unsafe.
    pub fn region(
        provider: impl Into<String>,
        region: impl Into<String>,
    ) -> Result<Self, CircuitError> {
        let provider = provider.into();
        let region = region.into();
        validate_scope_id(&provider)?;
        validate_scope_id(&region)?;
        Ok(Self {
            kind: CircuitScopeKind::Region,
            key: format!("{provider}\u{1f}{region}"),
        })
    }

    /// Creates an exact-model circuit key.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidScope`] when an identifier is empty, oversized, or unsafe.
    pub fn model(
        provider: impl Into<String>,
        model: impl Into<String>,
        revision: impl Into<String>,
    ) -> Result<Self, CircuitError> {
        let provider = provider.into();
        let model = model.into();
        let revision = revision.into();
        validate_scope_id(&provider)?;
        validate_scope_id(&model)?;
        validate_scope_id(&revision)?;
        Ok(Self {
            kind: CircuitScopeKind::Model,
            key: format!("{provider}\u{1f}{model}\u{1f}{revision}"),
        })
    }

    /// Returns the scope category without exposing its identifiers.
    #[must_use]
    pub const fn kind(&self) -> CircuitScopeKind {
        self.kind
    }

    pub(crate) fn for_candidate(
        target: &ModelCapabilityKey,
        endpoint: &EndpointId,
        region: &Region,
    ) -> Result<[Self; 4], CircuitError> {
        Ok([
            Self::provider(target.provider())?,
            Self::endpoint(target.provider(), endpoint.as_str())?,
            Self::region(target.provider(), region.as_str())?,
            Self::model(target.provider(), target.model(), target.revision())?,
        ])
    }
}

impl fmt::Debug for CircuitScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircuitScope")
            .field("kind", &self.kind())
            .field("identity", &"[REDACTED]")
            .finish()
    }
}

/// Visibility boundary for one provider failure observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailureIsolation {
    /// Failure applies to the explicitly supplied shared circuit scope.
    Shared,
    /// Failure belongs only to one credential and cannot affect shared health.
    Credential,
    /// Failure belongs only to one tenant and cannot affect shared health.
    Tenant,
    /// Failure was caused by caller input or cancellation.
    Caller,
}

/// One redacted routing outcome retained as circuit evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitOutcome {
    /// A usable provider response or successful half-open probe.
    Success,
    /// A retryable transport or provider failure.
    TransientFailure,
    /// A deadline or provider timeout.
    Timeout,
    /// Provider throttling.
    Throttled,
    /// A non-tenant-specific provider failure.
    ProviderFailure,
    /// A credential-specific failure that must not affect shared health.
    CredentialFailure,
    /// A tenant-specific failure that must not affect shared health.
    TenantFailure,
    /// A caller request or cancellation failure that must not affect shared health.
    CallerFailure,
}

impl CircuitOutcome {
    const fn counts_toward_health(self) -> bool {
        matches!(
            self,
            Self::TransientFailure | Self::Timeout | Self::Throttled | Self::ProviderFailure
        )
    }
}

impl CircuitOutcome {
    /// Converts a typed redacted provider error into safe circuit evidence.
    ///
    /// Credential and tenant isolation always overrides provider failure category, preventing a
    /// caller from accidentally counting those failures against shared provider health.
    #[must_use]
    pub const fn from_provider_error(error: &ProviderError, isolation: FailureIsolation) -> Self {
        match isolation {
            FailureIsolation::Credential => Self::CredentialFailure,
            FailureIsolation::Tenant => Self::TenantFailure,
            FailureIsolation::Caller => Self::CallerFailure,
            FailureIsolation::Shared => match error.kind() {
                ProviderErrorKind::Transport => Self::TransientFailure,
                ProviderErrorKind::Timeout => Self::Timeout,
                ProviderErrorKind::Throttling => Self::Throttled,
                ProviderErrorKind::Provider => Self::ProviderFailure,
                ProviderErrorKind::Unsupported
                | ProviderErrorKind::Safety
                | ProviderErrorKind::Schema => Self::CallerFailure,
            },
        }
    }
}

/// Current circuit availability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CircuitState {
    /// Normal traffic is admitted.
    Closed,
    /// Traffic is blocked until the recovery interval elapses.
    Open,
    /// A bounded number of recovery probes may run.
    HalfOpen,
}

/// Immutable circuit bounds and transition thresholds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitPolicy {
    max_scopes: usize,
    max_samples_per_scope: usize,
    window: Duration,
    failure_threshold: usize,
    open_duration: Duration,
    half_open_max_probes: usize,
}

impl CircuitPolicy {
    /// Creates bounded rolling circuit policy.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidPolicy`] for zero bounds or an impossible threshold.
    pub const fn new(
        max_scopes: usize,
        max_samples_per_scope: usize,
        window: Duration,
        failure_threshold: usize,
        open_duration: Duration,
        half_open_max_probes: usize,
    ) -> Result<Self, CircuitError> {
        if max_scopes == 0
            || max_samples_per_scope == 0
            || window.is_zero()
            || failure_threshold == 0
            || failure_threshold > max_samples_per_scope
            || open_duration.is_zero()
            || half_open_max_probes == 0
        {
            return Err(CircuitError::InvalidPolicy);
        }
        Ok(Self {
            max_scopes,
            max_samples_per_scope,
            window,
            failure_threshold,
            open_duration,
            half_open_max_probes,
        })
    }
}

impl Default for CircuitPolicy {
    fn default() -> Self {
        Self {
            max_scopes: 1_024,
            max_samples_per_scope: 64,
            window: Duration::from_secs(60),
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            half_open_max_probes: 1,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Evidence {
    observed_at: Instant,
    outcome: CircuitOutcome,
}

#[derive(Debug, Default)]
struct ScopeEntry {
    evidence: VecDeque<Evidence>,
    opened_until: Option<Instant>,
    half_open_probes: usize,
    probe_generation: u64,
}

impl ScopeEntry {
    fn state(&self, now: Instant) -> CircuitState {
        match self.opened_until {
            Some(until) if now < until => CircuitState::Open,
            Some(_) => CircuitState::HalfOpen,
            None => CircuitState::Closed,
        }
    }

    fn open(&mut self, until: Instant) {
        self.opened_until = Some(until);
        self.half_open_probes = 0;
        self.probe_generation = self.probe_generation.wrapping_add(1);
    }

    fn evict_expired(&mut self, now: Instant, window: Duration) {
        while self
            .evidence
            .front()
            .is_some_and(|sample| now.saturating_duration_since(sample.observed_at) > window)
        {
            self.evidence.pop_front();
        }
    }

    fn health_failures(&self) -> usize {
        self.evidence
            .iter()
            .filter(|sample| sample.outcome.counts_toward_health())
            .count()
    }

    fn record_evidence(
        &mut self,
        observed_at: Instant,
        outcome: CircuitOutcome,
        window: Duration,
        max_samples: usize,
    ) -> (Instant, CircuitState) {
        let timeline = self
            .evidence
            .back()
            .map_or(observed_at, |sample| sample.observed_at.max(observed_at));
        self.evict_expired(timeline, window);
        let prior_state = self.state(timeline);
        let position = self
            .evidence
            .partition_point(|sample| sample.observed_at <= observed_at);
        self.evidence.insert(
            position,
            Evidence {
                observed_at,
                outcome,
            },
        );
        self.evict_expired(timeline, window);
        while self.evidence.len() > max_samples {
            self.evidence.pop_front();
        }
        (timeline, prior_state)
    }
}

#[derive(Debug, Default)]
struct CircuitBook {
    scopes: BTreeMap<CircuitScope, ScopeEntry>,
}

/// Thread-safe bounded rolling circuit evidence store.
#[derive(Clone)]
pub struct CircuitBreaker {
    policy: CircuitPolicy,
    inner: Arc<Mutex<CircuitBook>>,
}

#[derive(Clone)]
struct ReservedProbe {
    scope: CircuitScope,
    generation: u64,
}

/// Owned reservation for one or more half-open circuit probes.
///
/// Dropping an incomplete permit releases every reserved slot. Only completing the permit may
/// transition a half-open circuit, preventing unrelated in-flight outcomes from closing it.
pub struct CircuitProbePermit {
    breaker: CircuitBreaker,
    scopes: Vec<ReservedProbe>,
    active: bool,
}

impl CircuitProbePermit {
    /// Returns whether recovery reserved at least one half-open scope.
    #[must_use]
    pub fn is_required(&self) -> bool {
        !self.scopes.is_empty()
    }

    /// Completes every owned half-open probe with one redacted candidate outcome.
    pub fn complete(&mut self, observed_at: Instant, outcome: CircuitOutcome) {
        if self.active {
            self.breaker
                .complete_probe(&self.scopes, observed_at, outcome);
            self.active = false;
        }
    }

    /// Releases every owned half-open probe without recording an outcome.
    pub fn release(&mut self) {
        if self.active {
            self.breaker.release_probes(&self.scopes);
            self.active = false;
        }
    }
}

impl Drop for CircuitProbePermit {
    fn drop(&mut self) {
        self.release();
    }
}

impl fmt::Debug for CircuitProbePermit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircuitProbePermit")
            .field("reserved_scope_count", &self.scopes.len())
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl CircuitBreaker {
    /// Creates an empty circuit evidence store.
    #[must_use]
    pub fn new(policy: CircuitPolicy) -> Self {
        Self {
            policy,
            inner: Arc::new(Mutex::new(CircuitBook::default())),
        }
    }

    /// Records one redacted outcome at exactly one declared scope.
    ///
    /// Credential, tenant, and caller failures remain bounded evidence but never count toward
    /// shared circuit thresholds.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::ScopeCapacityExceeded`] when a new scope would exceed the bound.
    pub fn record(
        &self,
        scope: CircuitScope,
        observed_at: Instant,
        outcome: CircuitOutcome,
    ) -> Result<(), CircuitError> {
        let mut book = self.lock();
        if !book.scopes.contains_key(&scope) && book.scopes.len() >= self.policy.max_scopes {
            return Err(CircuitError::ScopeCapacityExceeded);
        }
        let entry = book.scopes.entry(scope).or_default();
        let (timeline, prior_state) = entry.record_evidence(
            observed_at,
            outcome,
            self.policy.window,
            self.policy.max_samples_per_scope,
        );

        match outcome {
            CircuitOutcome::Success if prior_state == CircuitState::Closed => {
                entry.opened_until = None;
                entry.half_open_probes = 0;
            }
            outcome
                if prior_state == CircuitState::Closed
                    && outcome.counts_toward_health()
                    && entry.health_failures() >= self.policy.failure_threshold =>
            {
                entry.open(timeline + self.policy.open_duration);
            }
            _ => {}
        }
        Ok(())
    }

    /// Returns the current state for one scope.
    #[must_use]
    pub fn state(&self, scope: &CircuitScope, now: Instant) -> CircuitState {
        self.lock()
            .scopes
            .get(scope)
            .map_or(CircuitState::Closed, |entry| entry.state(now))
    }

    /// Returns the four candidate scope states while taking one evidence lock.
    #[must_use]
    pub fn candidate_states(&self, scopes: &[CircuitScope; 4], now: Instant) -> [CircuitState; 4] {
        let book = self.lock();
        std::array::from_fn(|position| {
            book.scopes
                .get(&scopes[position])
                .map_or(CircuitState::Closed, |entry| entry.state(now))
        })
    }

    /// Attempts to reserve one owned, bounded half-open probe slot.
    ///
    /// Returns `None` while the scope is open or every half-open slot is occupied. Dropping the
    /// returned permit releases its slot.
    #[must_use]
    pub fn try_acquire(&self, scope: &CircuitScope, now: Instant) -> Option<CircuitProbePermit> {
        self.acquire_scopes(std::slice::from_ref(scope), now)
    }

    /// Atomically reserves all half-open probe slots required by one candidate.
    ///
    /// Closed scopes need no slot. Any open or saturated half-open scope rejects the whole
    /// candidate without consuming a slot from another scope.
    #[must_use]
    pub fn try_acquire_candidate(
        &self,
        scopes: &[CircuitScope; 4],
        now: Instant,
    ) -> Option<CircuitProbePermit> {
        self.acquire_scopes(scopes, now)
    }

    fn acquire_scopes(&self, scopes: &[CircuitScope], now: Instant) -> Option<CircuitProbePermit> {
        let mut book = self.lock();
        for scope in scopes {
            let Some(entry) = book.scopes.get(scope) else {
                continue;
            };
            match entry.state(now) {
                CircuitState::Open => return None,
                CircuitState::HalfOpen
                    if entry.half_open_probes >= self.policy.half_open_max_probes =>
                {
                    return None;
                }
                CircuitState::Closed | CircuitState::HalfOpen => {}
            }
        }

        let mut reserved = Vec::with_capacity(scopes.len());
        for scope in scopes {
            if let Some(entry) = book.scopes.get_mut(scope)
                && entry.state(now) == CircuitState::HalfOpen
            {
                entry.half_open_probes += 1;
                reserved.push(ReservedProbe {
                    scope: scope.clone(),
                    generation: entry.probe_generation,
                });
            }
        }
        drop(book);
        Some(CircuitProbePermit {
            breaker: self.clone(),
            scopes: reserved,
            active: true,
        })
    }

    /// Returns a value-free evidence summary for one scope.
    #[must_use]
    pub fn evidence_summary(&self, scope: &CircuitScope, now: Instant) -> CircuitEvidenceSummary {
        let mut book = self.lock();
        let Some(entry) = book.scopes.get_mut(scope) else {
            return CircuitEvidenceSummary {
                state: CircuitState::Closed,
                sample_count: 0,
                health_failure_count: 0,
            };
        };
        entry.evict_expired(now, self.policy.window);
        CircuitEvidenceSummary {
            state: entry.state(now),
            sample_count: entry.evidence.len(),
            health_failure_count: entry.health_failures(),
        }
    }

    fn complete_probe(
        &self,
        scopes: &[ReservedProbe],
        observed_at: Instant,
        outcome: CircuitOutcome,
    ) {
        let mut book = self.lock();
        for probe in scopes {
            let Some(entry) = book.scopes.get_mut(&probe.scope) else {
                continue;
            };
            let timeline = entry
                .evidence
                .back()
                .map_or(observed_at, |sample| sample.observed_at.max(observed_at));
            if entry.probe_generation != probe.generation
                || entry.state(timeline) != CircuitState::HalfOpen
            {
                continue;
            }
            let (timeline, _) = entry.record_evidence(
                observed_at,
                outcome,
                self.policy.window,
                self.policy.max_samples_per_scope,
            );
            match outcome {
                CircuitOutcome::Success => {
                    entry.evidence.clear();
                    entry.evidence.push_back(Evidence {
                        observed_at: timeline,
                        outcome,
                    });
                    entry.opened_until = None;
                    entry.half_open_probes = 0;
                }
                outcome if outcome.counts_toward_health() => {
                    entry.open(timeline + self.policy.open_duration);
                }
                _ => {
                    entry.half_open_probes = entry.half_open_probes.saturating_sub(1);
                }
            }
        }
    }

    fn release_probes(&self, scopes: &[ReservedProbe]) {
        let mut book = self.lock();
        for probe in scopes {
            if let Some(entry) = book.scopes.get_mut(&probe.scope)
                && entry.probe_generation == probe.generation
            {
                entry.half_open_probes = entry.half_open_probes.saturating_sub(1);
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, CircuitBook> {
        match self.inner.lock() {
            Ok(book) => book,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl fmt::Debug for CircuitBreaker {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CircuitBreaker")
            .field("policy", &self.policy)
            .field("scope_count", &self.lock().scopes.len())
            .finish_non_exhaustive()
    }
}

/// Value-free bounded evidence summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitEvidenceSummary {
    state: CircuitState,
    sample_count: usize,
    health_failure_count: usize,
}

impl CircuitEvidenceSummary {
    /// Returns the current circuit state.
    #[must_use]
    pub const fn state(self) -> CircuitState {
        self.state
    }

    /// Returns retained samples after count and time eviction.
    #[must_use]
    pub const fn sample_count(self) -> usize {
        self.sample_count
    }

    /// Returns retained failures that count toward shared health.
    #[must_use]
    pub const fn health_failure_count(self) -> usize {
        self.health_failure_count
    }
}

/// Value-free circuit configuration or capacity failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CircuitError {
    /// Circuit policy contains a zero bound or impossible threshold.
    #[error("circuit policy is invalid")]
    InvalidPolicy,
    /// A scope identifier is empty, oversized, or contains unsupported characters.
    #[error("circuit scope is invalid")]
    InvalidScope,
    /// The bounded circuit map cannot admit another distinct scope.
    #[error("circuit scope capacity exceeded")]
    ScopeCapacityExceeded,
}

fn validate_scope_id(value: &str) -> Result<(), CircuitError> {
    if value.is_empty()
        || value.len() > MAX_SCOPE_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(CircuitError::InvalidScope);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> CircuitPolicy {
        CircuitPolicy::new(8, 4, Duration::from_secs(10), 2, Duration::from_secs(5), 1)
            .expect("test circuit policy should be valid")
    }

    #[test]
    fn rolling_window_should_evict_old_failures_before_tripping() {
        let breaker = CircuitBreaker::new(policy());
        let scope = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let started = Instant::now();
        breaker
            .record(scope.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");
        breaker
            .record(
                scope.clone(),
                started + Duration::from_secs(11),
                CircuitOutcome::Timeout,
            )
            .expect("scope should fit");

        let summary = breaker.evidence_summary(&scope, started + Duration::from_secs(11));

        assert_eq!(summary.state(), CircuitState::Closed);
        assert_eq!(summary.sample_count(), 1);
    }

    #[test]
    fn half_open_should_bound_probes_and_close_after_success() {
        let breaker = CircuitBreaker::new(policy());
        let scope = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let started = Instant::now();
        breaker
            .record(scope.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");
        breaker
            .record(scope.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");
        let half_open_at = started + Duration::from_secs(5);

        let abandoned = breaker
            .try_acquire(&scope, half_open_at)
            .expect("one recovery probe should be available");
        assert!(breaker.try_acquire(&scope, half_open_at).is_none());
        drop(abandoned);

        let mut permit = breaker
            .try_acquire(&scope, half_open_at)
            .expect("dropping a permit should release its probe");
        permit.complete(half_open_at, CircuitOutcome::Success);

        assert_eq!(breaker.state(&scope, half_open_at), CircuitState::Closed);
    }

    #[test]
    fn model_and_credential_evidence_should_not_poison_provider_scope() {
        let breaker = CircuitBreaker::new(policy());
        let provider = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let model =
            CircuitScope::model("provider-a", "model-a", "v1").expect("test scope should be valid");
        let now = Instant::now();
        breaker
            .record(provider.clone(), now, CircuitOutcome::CredentialFailure)
            .expect("scope should fit");
        breaker
            .record(provider.clone(), now, CircuitOutcome::TenantFailure)
            .expect("scope should fit");
        breaker
            .record(model.clone(), now, CircuitOutcome::ProviderFailure)
            .expect("scope should fit");
        breaker
            .record(model.clone(), now, CircuitOutcome::ProviderFailure)
            .expect("scope should fit");

        assert_eq!(breaker.state(&provider, now), CircuitState::Closed);
        assert_eq!(breaker.state(&model, now), CircuitState::Open);
        assert_eq!(
            breaker
                .evidence_summary(&provider, now)
                .health_failure_count(),
            0
        );
    }

    #[test]
    fn endpoint_failure_should_not_open_region_or_provider_scope() {
        let breaker = CircuitBreaker::new(policy());
        let provider = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let endpoint =
            CircuitScope::endpoint("provider-a", "endpoint-a").expect("test scope should be valid");
        let region =
            CircuitScope::region("provider-a", "eu-west-1").expect("test scope should be valid");
        let now = Instant::now();
        breaker
            .record(endpoint.clone(), now, CircuitOutcome::ProviderFailure)
            .expect("scope should fit");
        breaker
            .record(endpoint.clone(), now, CircuitOutcome::ProviderFailure)
            .expect("scope should fit");

        assert_eq!(breaker.state(&endpoint, now), CircuitState::Open);
        assert_eq!(breaker.state(&region, now), CircuitState::Closed);
        assert_eq!(breaker.state(&provider, now), CircuitState::Closed);
    }

    #[test]
    fn out_of_order_samples_expire_and_open_success_cannot_short_circuit_recovery() {
        let breaker = CircuitBreaker::new(policy());
        let provider = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let started = Instant::now();
        breaker
            .record(
                provider.clone(),
                started + Duration::from_secs(20),
                CircuitOutcome::Timeout,
            )
            .expect("scope should fit");
        breaker
            .record(provider.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");
        assert_eq!(
            breaker
                .evidence_summary(&provider, started + Duration::from_secs(20))
                .sample_count(),
            1
        );

        breaker
            .record(
                provider.clone(),
                started + Duration::from_secs(20),
                CircuitOutcome::Timeout,
            )
            .expect("scope should fit");
        breaker
            .record(
                provider.clone(),
                started + Duration::from_secs(21),
                CircuitOutcome::Success,
            )
            .expect("scope should fit");
        assert_eq!(
            breaker.state(&provider, started + Duration::from_secs(21)),
            CircuitState::Open
        );

        let scopes = [
            provider.clone(),
            CircuitScope::endpoint("provider-a", "endpoint-a").expect("test scope should be valid"),
            CircuitScope::region("provider-a", "eu-west-1").expect("test scope should be valid"),
            CircuitScope::model("provider-a", "model-a", "v1").expect("test scope should be valid"),
        ];
        let recovery = started + Duration::from_secs(25);
        breaker
            .record(provider.clone(), recovery, CircuitOutcome::Success)
            .expect("scope should fit");
        assert_eq!(breaker.state(&provider, recovery), CircuitState::HalfOpen);

        let mut permit = breaker
            .try_acquire_candidate(&scopes, recovery)
            .expect("one recovery probe should be available");
        assert!(breaker.try_acquire_candidate(&scopes, recovery).is_none());
        permit.complete(recovery, CircuitOutcome::Success);
        assert_eq!(breaker.state(&provider, recovery), CircuitState::Closed);
    }

    #[test]
    fn stale_probe_generation_cannot_mutate_new_recovery_window() {
        let breaker = CircuitBreaker::new(
            CircuitPolicy::new(8, 8, Duration::from_secs(10), 2, Duration::from_secs(5), 2)
                .expect("test circuit policy should be valid"),
        );
        let scope = CircuitScope::provider("provider-a").expect("test scope should be valid");
        let started = Instant::now();
        breaker
            .record(scope.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");
        breaker
            .record(scope.clone(), started, CircuitOutcome::Timeout)
            .expect("scope should fit");

        let first_recovery = started + Duration::from_secs(5);
        let mut first = breaker
            .try_acquire(&scope, first_recovery)
            .expect("first probe should fit");
        let mut stale = breaker
            .try_acquire(&scope, first_recovery)
            .expect("second probe should fit");
        first.complete(first_recovery, CircuitOutcome::Timeout);

        let second_recovery = started + Duration::from_secs(10);
        let current = breaker
            .try_acquire(&scope, second_recovery)
            .expect("new first probe should fit");
        let _current_peer = breaker
            .try_acquire(&scope, second_recovery)
            .expect("new second probe should fit");
        stale.complete(second_recovery, CircuitOutcome::Success);

        assert_eq!(
            breaker.state(&scope, second_recovery),
            CircuitState::HalfOpen
        );
        assert!(breaker.try_acquire(&scope, second_recovery).is_none());
        drop(current);
        assert!(breaker.try_acquire(&scope, second_recovery).is_some());
    }

    #[test]
    fn debug_should_redact_scope_identifiers() {
        let scope = CircuitScope::endpoint("secret-provider", "private-endpoint")
            .expect("test scope should be valid");
        let rendered = format!("{scope:?}");

        assert!(!rendered.contains("secret-provider"));
        assert!(!rendered.contains("private-endpoint"));
    }
}
