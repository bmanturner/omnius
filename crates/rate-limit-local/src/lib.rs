//! Per-instance GCRA rate limiting for trusted request identities.
//!
//! This module deliberately does not inspect forwarding headers. The server adapter must resolve
//! the immediate peer or a verified proxy chain and insert [`TrustedRateLimitContext`] before the
//! route-specific limiter. Identity hashes are mapped into a configured number of buckets, which
//! puts a hard bound on governor's keyed state. Bucket collisions can only make limits stricter.

use axum::{
    Router,
    body::Body,
    extract::Request as AxumRequest,
    http::{HeaderValue, Request},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use governor::{Quota, middleware::StateInformationMiddleware};
use metrics::counter;
use rsk_core::RequestId;
use rsk_http::{ProblemDetails, REQUEST_ID_HEADER};
use std::{
    collections::hash_map::RandomState,
    fmt,
    hash::{BuildHasher, Hash, Hasher},
    net::IpAddr,
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tower_governor::{
    GovernorError, GovernorLayer,
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::KeyExtractor,
};

const MAX_TOKEN_BYTES: usize = 128;
const MAX_BURST_SIZE: u32 = 100_000;
const MAX_REPLENISH_INTERVAL: Duration = Duration::from_hours(1);
const MAX_IDENTITY_BUCKETS: u32 = 1_000_000;

/// Closed classes of operations with independent budgets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RateLimitOperation {
    /// Sign-in attempts.
    Login,
    /// Password or credential recovery.
    Recovery,
    /// Account registration.
    Registration,
    /// Tenant or organization invitations.
    Invitation,
    /// API-key creation, rotation, or revocation.
    ApiKeyManagement,
    /// Upload initiation or completion.
    Upload,
    /// Search or reporting work.
    Search,
    /// Webhook replay or manual delivery.
    WebhookReplay,
    /// Administrative operations.
    Administration,
    /// A declared application-specific route family.
    General,
}

impl RateLimitOperation {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Recovery => "recovery",
            Self::Registration => "registration",
            Self::Invitation => "invitation",
            Self::ApiKeyManagement => "api_key_management",
            Self::Upload => "upload",
            Self::Search => "search",
            Self::WebhookReplay => "webhook_replay",
            Self::Administration => "administration",
            Self::General => "general",
        }
    }
}

/// Trusted identity dimension selected for one limiter layer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RateLimitIdentityKind {
    /// Resolved client IP address.
    Ip,
    /// Authenticated account or service subject.
    Account,
    /// Established tenant context.
    Tenant,
    /// Stable API-key identifier or non-secret prefix.
    ApiKey,
    /// Authenticated versus anonymous state.
    AuthState,
}

impl RateLimitIdentityKind {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Account => "account",
            Self::Tenant => "tenant",
            Self::ApiKey => "api_key",
            Self::AuthState => "auth_state",
        }
    }
}

/// A bounded stable identifier used only as keyed limiter input.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RateLimitToken(String);

impl RateLimitToken {
    /// Validates and owns a stable non-secret identifier.
    ///
    /// # Errors
    ///
    /// Returns [`RateLimitTokenError`] for an empty, oversized, or non-portable token.
    pub fn new(value: impl Into<String>) -> Result<Self, RateLimitTokenError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RateLimitTokenError::Empty);
        }
        if value.len() > MAX_TOKEN_BYTES {
            return Err(RateLimitTokenError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(RateLimitTokenError::InvalidCharacter);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for RateLimitToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RateLimitToken([REDACTED])")
    }
}

/// Invalid stable rate-limit identity token.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RateLimitTokenError {
    /// The token was empty.
    #[error("rate-limit identity token must not be empty")]
    Empty,
    /// The token exceeded 128 bytes.
    #[error("rate-limit identity token exceeds 128 bytes")]
    TooLong,
    /// The token contained a non-portable character.
    #[error("rate-limit identity token contains an invalid character")]
    InvalidCharacter,
}

/// Request identity resolved from a socket peer or verified proxy chain.
///
/// Network clients cannot create request extensions. Application middleware may enrich this value
/// with authenticated account, tenant, and API-key identifiers after those contexts are validated.
#[derive(Clone, Debug)]
pub struct TrustedRateLimitContext {
    client_ip: IpAddr,
    account: Option<RateLimitToken>,
    tenant: Option<RateLimitToken>,
    api_key: Option<RateLimitToken>,
    authenticated: bool,
}

impl TrustedRateLimitContext {
    /// Starts trusted request context from the resolved client address.
    #[must_use]
    pub const fn new(client_ip: IpAddr) -> Self {
        Self {
            client_ip,
            account: None,
            tenant: None,
            api_key: None,
            authenticated: false,
        }
    }

    /// Adds the authenticated account or service identity.
    #[must_use]
    pub fn with_account(mut self, account: RateLimitToken) -> Self {
        self.account = Some(account);
        self.authenticated = true;
        self
    }

    /// Adds the established tenant identity.
    #[must_use]
    pub fn with_tenant(mut self, tenant: RateLimitToken) -> Self {
        self.tenant = Some(tenant);
        self
    }

    /// Adds a stable API-key identifier or non-secret prefix.
    #[must_use]
    pub fn with_api_key(mut self, api_key: RateLimitToken) -> Self {
        self.api_key = Some(api_key);
        self.authenticated = true;
        self
    }
}

/// Bounded local rate-limit policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalRateLimitPolicy {
    /// Time required to replenish one token.
    pub replenish_every: Duration,
    /// Maximum immediately available tokens.
    pub burst_size: u32,
    /// Hard number of identity hash buckets and therefore live governor keys.
    pub identity_buckets: u32,
}

impl LocalRateLimitPolicy {
    /// Validates the policy and returns governor's canonical quota.
    ///
    /// # Errors
    ///
    /// Returns [`LocalRateLimitConfigError`] for zero or excessive bounds.
    pub fn quota(self) -> Result<Quota, LocalRateLimitConfigError> {
        if self.replenish_every.is_zero() || self.replenish_every > MAX_REPLENISH_INTERVAL {
            return Err(LocalRateLimitConfigError::InvalidReplenishInterval);
        }
        let Some(burst_size) = NonZeroU32::new(self.burst_size) else {
            return Err(LocalRateLimitConfigError::InvalidBurstSize);
        };
        if self.burst_size > MAX_BURST_SIZE {
            return Err(LocalRateLimitConfigError::InvalidBurstSize);
        }
        if self.identity_buckets == 0 || self.identity_buckets > MAX_IDENTITY_BUCKETS {
            return Err(LocalRateLimitConfigError::InvalidIdentityBuckets);
        }
        Quota::with_period(self.replenish_every)
            .map(|quota| quota.allow_burst(burst_size))
            .ok_or(LocalRateLimitConfigError::InvalidReplenishInterval)
    }
}

/// Invalid local rate-limit policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LocalRateLimitConfigError {
    /// Replenishment was zero or exceeded one hour.
    #[error("rate-limit replenishment interval is invalid")]
    InvalidReplenishInterval,
    /// Burst size was zero or exceeded 100,000.
    #[error("rate-limit burst size is invalid")]
    InvalidBurstSize,
    /// Identity bucket count was zero or exceeded 1,000,000.
    #[error("rate-limit identity bucket count is invalid")]
    InvalidIdentityBuckets,
    /// Tower-governor rejected a policy already validated by this module.
    #[error("tower-governor rejected the rate-limit policy")]
    Builder,
}

/// Opaque, cardinality-bounded governor key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RateLimitKey {
    operation: RateLimitOperation,
    identity_kind: RateLimitIdentityKind,
    identity_bucket: u32,
}

/// Trusted extension extractor. Raw forwarding headers are never inspected.
#[derive(Clone)]
pub struct TrustedKeyExtractor {
    operation: RateLimitOperation,
    identity_kind: RateLimitIdentityKind,
    identity_buckets: u32,
    hash_builder: RandomState,
}

impl fmt::Debug for TrustedKeyExtractor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedKeyExtractor")
            .field("operation", &self.operation)
            .field("identity_kind", &self.identity_kind)
            .field("identity_buckets", &self.identity_buckets)
            .finish_non_exhaustive()
    }
}

impl TrustedKeyExtractor {
    fn new(
        operation: RateLimitOperation,
        identity_kind: RateLimitIdentityKind,
        identity_buckets: u32,
    ) -> Self {
        Self {
            operation,
            identity_kind,
            identity_buckets,
            hash_builder: RandomState::new(),
        }
    }

    fn selected_hash(&self, context: &TrustedRateLimitContext) -> Option<u64> {
        let mut hasher = self.hash_builder.build_hasher();
        self.identity_kind.hash(&mut hasher);
        match self.identity_kind {
            RateLimitIdentityKind::Ip => context.client_ip.hash(&mut hasher),
            RateLimitIdentityKind::Account => context.account.as_ref()?.hash(&mut hasher),
            RateLimitIdentityKind::Tenant => context.tenant.as_ref()?.hash(&mut hasher),
            RateLimitIdentityKind::ApiKey => context.api_key.as_ref()?.hash(&mut hasher),
            RateLimitIdentityKind::AuthState => context.authenticated.hash(&mut hasher),
        }
        Some(hasher.finish())
    }
}

impl KeyExtractor for TrustedKeyExtractor {
    type Key = RateLimitKey;

    fn extract<T>(&self, request: &Request<T>) -> Result<Self::Key, GovernorError> {
        let context = request
            .extensions()
            .get::<TrustedRateLimitContext>()
            .ok_or_else(|| {
                record_decision(self.operation, self.identity_kind, "extract_error");
                GovernorError::UnableToExtractKey
            })?;
        let hash = self.selected_hash(context).ok_or_else(|| {
            record_decision(self.operation, self.identity_kind, "extract_error");
            GovernorError::UnableToExtractKey
        })?;
        record_decision(self.operation, self.identity_kind, "checked");
        Ok(RateLimitKey {
            operation: self.operation,
            identity_kind: self.identity_kind,
            identity_bucket: u32::try_from(hash % u64::from(self.identity_buckets))
                .unwrap_or_default(),
        })
    }
}

/// Concrete tower-governor configuration used by this module.
pub type LocalGovernorConfig = GovernorConfig<TrustedKeyExtractor, StateInformationMiddleware>;

/// Concrete Axum tower-governor layer used internally by this module.
type LocalGovernorLayer = GovernorLayer<TrustedKeyExtractor, StateInformationMiddleware, Body>;

/// One shared local limiter. Clone this value instead of rebuilding the same policy.
#[derive(Clone)]
pub struct LocalRateLimiter {
    config: Arc<LocalGovernorConfig>,
    operation: RateLimitOperation,
    identity_kind: RateLimitIdentityKind,
    identity_buckets: u32,
}

impl fmt::Debug for LocalRateLimiter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalRateLimiter")
            .field("operation", &self.operation)
            .field("identity_kind", &self.identity_kind)
            .field("identity_buckets", &self.identity_buckets)
            .field("live_keys", &self.len())
            .finish_non_exhaustive()
    }
}

impl LocalRateLimiter {
    /// Builds one shared per-instance governor policy.
    ///
    /// # Errors
    ///
    /// Returns [`LocalRateLimitConfigError`] when a policy bound is invalid.
    pub fn new(
        operation: RateLimitOperation,
        identity_kind: RateLimitIdentityKind,
        policy: LocalRateLimitPolicy,
    ) -> Result<Self, LocalRateLimitConfigError> {
        let quota = policy.quota()?;
        let extractor = TrustedKeyExtractor::new(operation, identity_kind, policy.identity_buckets);
        let mut builder = GovernorConfigBuilder::default();
        builder
            .period(quota.replenish_interval())
            .burst_size(quota.burst_size().get());
        let config = builder
            .key_extractor(extractor)
            .use_headers()
            .finish()
            .ok_or(LocalRateLimitConfigError::Builder)?;
        Ok(Self {
            config: Arc::new(config),
            operation,
            identity_kind,
            identity_buckets: policy.identity_buckets,
        })
    }

    /// Applies a shared governor layer and RFC 9457 error rewriting to an Axum router.
    ///
    /// The rewriting layer preserves governor's bounded retry/quota headers and uses the request
    /// identifier already established by the HTTP shell. When used in isolation it generates and
    /// returns one consistent request identifier.
    pub fn apply<S>(&self, router: Router<S>) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let governor = self.governor_layer();
        router
            .layer(governor)
            .layer(middleware::from_fn(rewrite_rate_limit_error))
    }

    fn governor_layer(&self) -> LocalGovernorLayer {
        let operation = self.operation;
        let identity_kind = self.identity_kind;
        GovernorLayer::new(Arc::clone(&self.config)).error_handler(move |error| {
            let outcome = if matches!(error, GovernorError::TooManyRequests { .. }) {
                "denied"
            } else {
                "extract_error"
            };
            record_decision(operation, identity_kind, outcome);
            let mut response = Response::from(error);
            response
                .headers_mut()
                .insert("x-rsk-rate-limit-error", HeaderValue::from_static("1"));
            response
        })
    }

    /// Removes governor keys whose quota state is equivalent to a fresh bucket.
    pub fn retain_recent(&self) {
        self.config.limiter().retain_recent();
        self.config.limiter().shrink_to_fit();
    }

    /// Returns the number of live keyed states, always bounded by configured identity buckets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.config.limiter().len()
    }

    /// Reports whether no keyed state is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.config.limiter().is_empty()
    }

    /// Returns the hard live-key bound for this limiter.
    #[must_use]
    pub const fn identity_buckets(&self) -> u32 {
        self.identity_buckets
    }
}

async fn rewrite_rate_limit_error(request: AxumRequest, next: Next) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    let mut response = next.run(request).await;
    if response
        .headers_mut()
        .remove("x-rsk-rate-limit-error")
        .is_none()
    {
        return response;
    }

    let status = response.status();
    let Ok(problem) = ProblemDetails::try_for_status(status, request_id) else {
        return response;
    };
    let preserved_headers: Vec<(&'static str, HeaderValue)> = [
        "retry-after",
        "x-ratelimit-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-whitelisted",
    ]
    .into_iter()
    .filter_map(|name| {
        response
            .headers()
            .get(name)
            .cloned()
            .map(|value| (name, value))
    })
    .collect();
    let mut replacement = problem.into_response();
    for (name, value) in preserved_headers {
        replacement.headers_mut().insert(name, value);
    }
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        replacement.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    replacement
}

fn record_decision(
    operation: RateLimitOperation,
    identity_kind: RateLimitIdentityKind,
    outcome: &'static str,
) {
    counter!(
        "rsk_rate_limit_local_decisions_total",
        "operation" => operation.metric_label(),
        "identity" => identity_kind.metric_label(),
        "outcome" => outcome
    )
    .increment(1);
}
