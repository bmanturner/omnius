//! Cached process probes, dependency readiness, safe build metadata, and drain integration.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU8, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use futures::{FutureExt as _, future::join_all};
use omnius_core::{BuildMetadata, ErrorCode, ServiceError};
use omnius_runtime::{Criticality, SupervisorControl, TaskContext, TaskSpec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const STARTING: u8 = 0;
const STARTED: u8 = 1;
const STARTUP_FAILED: u8 = 2;

type CheckFuture = Pin<Box<dyn Future<Output = Result<(), CheckFailure>> + Send + 'static>>;
type CheckFn = dyn Fn() -> CheckFuture + Send + Sync + 'static;

/// Refresh and staleness policy for cached dependency health.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    /// Delay between background cache refreshes.
    #[serde(with = "humantime_serde")]
    pub refresh_interval: Duration,
    /// Maximum cache age accepted by readiness.
    #[serde(with = "humantime_serde")]
    pub stale_after: Duration,
    /// Deadline used when draining the health refresh task.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            refresh_interval: Duration::from_secs(5),
            stale_after: Duration::from_secs(15),
            shutdown_timeout: Duration::from_secs(1),
        }
    }
}

impl HealthConfig {
    fn validate(self) -> Result<Self, HealthBuildError> {
        if self.refresh_interval.is_zero() {
            return Err(HealthBuildError::ZeroDuration("refresh_interval"));
        }
        if self.stale_after < self.refresh_interval {
            return Err(HealthBuildError::StaleBeforeRefresh);
        }
        if self.shutdown_timeout.is_zero() {
            return Err(HealthBuildError::ZeroDuration("shutdown_timeout"));
        }
        Ok(self)
    }
}

/// Safe, stable dependency-check failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("dependency health check failed: {code}")]
pub struct CheckFailure {
    code: ErrorCode,
}

impl CheckFailure {
    /// Creates a failure from a bounded stable code.
    #[must_use]
    pub const fn new(code: ErrorCode) -> Self {
        Self { code }
    }

    /// Returns the operator-safe failure code.
    #[must_use]
    pub const fn code(self) -> ErrorCode {
        self.code
    }
}

/// Declarative cached dependency check.
pub struct HealthCheckSpec {
    name: String,
    module: String,
    criticality: Criticality,
    timeout: Duration,
    run: Arc<CheckFn>,
}

impl HealthCheckSpec {
    /// Creates a dependency check factory.
    pub fn new<F, Fut>(
        name: impl Into<String>,
        module: impl Into<String>,
        criticality: Criticality,
        timeout: Duration,
        run: F,
    ) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), CheckFailure>> + Send + 'static,
    {
        Self {
            name: name.into(),
            module: module.into(),
            criticality,
            timeout,
            run: Arc::new(move || Box::pin(run())),
        }
    }
}

impl fmt::Debug for HealthCheckSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HealthCheckSpec")
            .field("name", &self.name)
            .field("module", &self.module)
            .field("criticality", &self.criticality)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Clone for HealthCheckSpec {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            module: self.module.clone(),
            criticality: self.criticality,
            timeout: self.timeout,
            run: Arc::clone(&self.run),
        }
    }
}

/// Validates and collects health checks before exposing routes.
#[derive(Debug)]
pub struct HealthBuilder {
    metadata: BuildMetadata,
    config: HealthConfig,
    checks: Vec<HealthCheckSpec>,
    names: HashSet<String>,
}

impl HealthBuilder {
    /// Creates a health builder with safe build metadata.
    ///
    /// # Errors
    ///
    /// Returns [`HealthBuildError`] for invalid refresh or shutdown durations.
    pub fn new(metadata: BuildMetadata, config: HealthConfig) -> Result<Self, HealthBuildError> {
        Ok(Self {
            metadata,
            config: config.validate()?,
            checks: Vec::new(),
            names: HashSet::new(),
        })
    }

    /// Registers a uniquely named dependency check.
    ///
    /// # Errors
    ///
    /// Returns [`HealthBuildError`] for empty identities, duplicate names, zero
    /// timeout, or a refresh/check cycle longer than the cache staleness bound.
    pub fn register(&mut self, check: HealthCheckSpec) -> Result<(), HealthBuildError> {
        if check.name.trim().is_empty() || check.module.trim().is_empty() {
            return Err(HealthBuildError::EmptyIdentity);
        }
        if check.timeout.is_zero() {
            return Err(HealthBuildError::ZeroDuration("check.timeout"));
        }
        if self.config.refresh_interval.saturating_add(check.timeout) > self.config.stale_after {
            return Err(HealthBuildError::CheckOutsideStaleWindow);
        }
        if !self.names.insert(check.name.clone()) {
            return Err(HealthBuildError::DuplicateName(check.name));
        }
        self.checks.push(check);
        Ok(())
    }

    /// Builds the cached health service in the starting state.
    #[must_use]
    pub fn build(self) -> HealthService {
        let cache = self
            .checks
            .iter()
            .map(|check| {
                (
                    check.name.clone(),
                    CacheEntry {
                        module: check.module.clone(),
                        criticality: check.criticality,
                        status: CheckStatus::Unknown,
                        checked_at: None,
                        latency: None,
                    },
                )
            })
            .collect();
        HealthService {
            inner: Arc::new(Inner {
                metadata: self.metadata,
                config: self.config,
                checks: self.checks.into(),
                cache: Mutex::new(cache),
                startup: AtomicU8::new(STARTING),
                draining: AtomicBool::new(false),
            }),
        }
    }
}

/// Invalid health composition.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HealthBuildError {
    /// A duration required for safe bounds is zero.
    #[error("health duration must be greater than zero: {0}")]
    ZeroDuration(&'static str),
    /// The cache would become stale before its next scheduled refresh.
    #[error("health stale_after must be at least refresh_interval")]
    StaleBeforeRefresh,
    /// A worst-case refresh/check cycle would outlive the cache.
    #[error("health refresh_interval plus check timeout must not exceed stale_after")]
    CheckOutsideStaleWindow,
    /// Check names and module names must be non-empty.
    #[error("health check name and module must be non-empty")]
    EmptyIdentity,
    /// Check names are unique.
    #[error("duplicate health check name: {0}")]
    DuplicateName(String),
}

#[derive(Debug)]
struct Inner {
    metadata: BuildMetadata,
    config: HealthConfig,
    checks: Arc<[HealthCheckSpec]>,
    cache: Mutex<BTreeMap<String, CacheEntry>>,
    startup: AtomicU8,
    draining: AtomicBool,
}

#[derive(Clone, Copy, Debug)]
enum CheckStatus {
    Unknown,
    Healthy,
    Unhealthy(ErrorCode),
    TimedOut,
    Panicked,
}

#[derive(Clone, Debug)]
struct CacheEntry {
    module: String,
    criticality: Criticality,
    status: CheckStatus,
    checked_at: Option<SystemTime>,
    latency: Option<Duration>,
}

/// Cached health state and route composition.
#[derive(Clone, Debug)]
pub struct HealthService {
    inner: Arc<Inner>,
}

impl HealthService {
    /// Marks application construction and listener startup complete.
    pub fn mark_started(&self) {
        self.inner.startup.store(STARTED, Ordering::Release);
    }

    /// Marks startup failed without exposing its internal cause.
    pub fn mark_startup_failed(&self) {
        self.inner.startup.store(STARTUP_FAILED, Ordering::Release);
    }

    /// Synchronously marks readiness false before an externally coordinated drain signal.
    pub fn mark_draining(&self) {
        self.inner.draining.store(true, Ordering::Release);
    }

    /// Marks readiness false, runs a synchronous intake-closing hook, signals every task to stop
    /// accepting new work, then starts bounded shutdown.
    pub fn begin_drain_with<F>(&self, runtime: &SupervisorControl, close_intake: F)
    where
        F: FnOnce(),
    {
        self.mark_draining();
        close_intake();
        runtime.begin_drain();
        runtime.request_shutdown();
    }

    /// Marks readiness false, signals every task to stop accepting new work, then starts bounded
    /// shutdown.
    pub fn begin_drain(&self, runtime: &SupervisorControl) {
        self.begin_drain_with(runtime, || {});
    }

    /// Returns the cached aggregate readiness decision.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        if self.inner.startup.load(Ordering::Acquire) != STARTED
            || self.inner.draining.load(Ordering::Acquire)
        {
            return false;
        }
        let now = SystemTime::now();
        lock(&self.inner.cache).values().all(|entry| {
            entry.criticality != Criticality::Required
                || (matches!(entry.status, CheckStatus::Healthy)
                    && entry.checked_at.is_some_and(|checked_at| {
                        now.duration_since(checked_at)
                            .is_ok_and(|age| age <= self.inner.config.stale_after)
                    }))
        })
    }

    /// Refreshes every dependency concurrently and atomically replaces the cache.
    pub async fn refresh_once(&self) {
        let updates = join_all(self.inner.checks.iter().cloned().map(run_check)).await;
        let mut cache = lock(&self.inner.cache);
        for (name, entry) in updates {
            cache.insert(name, entry);
        }
    }

    /// Returns the required supervised background cache refresher.
    #[must_use]
    pub fn supervised_refresh_task(&self) -> TaskSpec {
        let service = self.clone();
        TaskSpec::new(
            "health-cache-refresh",
            "health",
            Criticality::Required,
            self.inner.config.shutdown_timeout,
            move |context| {
                let service = service.clone();
                async move { service.refresh_loop(context).await }
            },
        )
    }

    /// Public process probe routes without dependency diagnostics.
    pub fn public_router(&self) -> Router {
        Router::new()
            .route("/live", get(live))
            .route("/ready", get(ready))
            .route("/startup", get(startup))
            .route("/version", get(version))
            .with_state(self.clone())
    }

    /// Detailed health diagnostics guarded by [`ProtectedAdmin`].
    pub fn admin_router(&self) -> Router {
        Router::new()
            .route("/diagnostics/health", get(diagnostics))
            .layer(middleware::from_fn(require_protected_admin))
            .with_state(self.clone())
    }

    fn diagnostics(&self) -> HealthDiagnostics {
        let now = SystemTime::now();
        let checks = lock(&self.inner.cache)
            .iter()
            .map(|(name, entry)| CheckDiagnostic {
                name: name.clone(),
                module: entry.module.clone(),
                criticality: criticality_name(entry.criticality),
                status: status_name(entry.status),
                failure_code: match entry.status {
                    CheckStatus::Unhealthy(code) => Some(code),
                    _ => None,
                },
                age_ms: entry
                    .checked_at
                    .and_then(|checked_at| now.duration_since(checked_at).ok().map(millis)),
                latency_ms: entry.latency.map(millis),
            })
            .collect();
        HealthDiagnostics {
            startup: startup_name(self.inner.startup.load(Ordering::Acquire)),
            draining: self.inner.draining.load(Ordering::Acquire),
            ready: self.is_ready(),
            checks,
        }
    }

    async fn refresh_loop(&self, context: TaskContext) -> Result<(), ServiceError> {
        loop {
            tokio::select! {
                () = context.draining() => {
                    self.finish_pre_drain(&context).await;
                    return Ok(());
                }
                () = context.shutdown_requested() => {
                    self.inner.draining.store(true, Ordering::Release);
                    return Ok(());
                }
                () = context.cancelled() => return Ok(()),
                () = self.refresh_once() => {}
            }
            tokio::select! {
                () = context.draining() => {
                    self.finish_pre_drain(&context).await;
                    return Ok(());
                }
                () = context.shutdown_requested() => {
                    self.inner.draining.store(true, Ordering::Release);
                    return Ok(());
                }
                () = context.cancelled() => return Ok(()),
                () = tokio::time::sleep(self.inner.config.refresh_interval) => {}
            }
        }
    }

    async fn finish_pre_drain(&self, context: &TaskContext) {
        self.inner.draining.store(true, Ordering::Release);
        if !context.is_shutdown_requested() && !context.is_cancelled() {
            tokio::select! {
                () = context.shutdown_requested() => {}
                () = context.cancelled() => {}
            }
        }
    }
}

async fn run_check(check: HealthCheckSpec) -> (String, CacheEntry) {
    let started = Instant::now();
    let status = match catch_unwind(AssertUnwindSafe(|| (check.run)())) {
        Ok(future) => {
            match tokio::time::timeout(check.timeout, AssertUnwindSafe(future).catch_unwind()).await
            {
                Ok(Ok(Ok(()))) => CheckStatus::Healthy,
                Ok(Ok(Err(error))) => CheckStatus::Unhealthy(error.code()),
                Ok(Err(_)) => CheckStatus::Panicked,
                Err(_) => CheckStatus::TimedOut,
            }
        }
        Err(_) => CheckStatus::Panicked,
    };
    if !matches!(status, CheckStatus::Healthy) {
        tracing::warn!(
            check = %check.name,
            module = %check.module,
            status = status_name(status),
            "dependency health check failed"
        );
    }
    (
        check.name,
        CacheEntry {
            module: check.module,
            criticality: check.criticality,
            status,
            checked_at: Some(SystemTime::now()),
            latency: Some(started.elapsed()),
        },
    )
}

/// Marker inserted only by the separately protected admin listener.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtectedAdmin;

async fn require_protected_admin(request: Request, next: Next) -> Response {
    if request.extensions().get::<ProtectedAdmin>().is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

#[derive(Clone, Copy, Debug, Serialize)]
struct ProbeBody {
    status: &'static str,
}

async fn live() -> (StatusCode, Json<ProbeBody>) {
    (StatusCode::OK, Json(ProbeBody { status: "live" }))
}

async fn ready(State(service): State<HealthService>) -> (StatusCode, Json<ProbeBody>) {
    if service.is_ready() {
        (StatusCode::OK, Json(ProbeBody { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProbeBody {
                status: "not_ready",
            }),
        )
    }
}

async fn startup(State(service): State<HealthService>) -> (StatusCode, Json<ProbeBody>) {
    match service.inner.startup.load(Ordering::Acquire) {
        STARTED => (StatusCode::OK, Json(ProbeBody { status: "started" })),
        STARTUP_FAILED => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProbeBody {
                status: "startup_failed",
            }),
        ),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ProbeBody { status: "starting" }),
        ),
    }
}

async fn version(State(service): State<HealthService>) -> Json<BuildMetadata> {
    Json(service.inner.metadata)
}

async fn diagnostics(
    State(service): State<HealthService>,
    Extension(_): Extension<ProtectedAdmin>,
) -> Json<HealthDiagnostics> {
    Json(service.diagnostics())
}

#[derive(Clone, Debug, Serialize)]
struct HealthDiagnostics {
    startup: &'static str,
    draining: bool,
    ready: bool,
    checks: Vec<CheckDiagnostic>,
}

#[derive(Clone, Debug, Serialize)]
struct CheckDiagnostic {
    name: String,
    module: String,
    criticality: &'static str,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<ErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_ms: Option<u64>,
}

fn criticality_name(criticality: Criticality) -> &'static str {
    match criticality {
        Criticality::Required => "required",
        Criticality::Degraded => "degraded",
        Criticality::BestEffort => "best_effort",
    }
}

fn status_name(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Unknown => "unknown",
        CheckStatus::Healthy => "healthy",
        CheckStatus::Unhealthy(_) => "unhealthy",
        CheckStatus::TimedOut => "timed_out",
        CheckStatus::Panicked => "panicked",
    }
}

fn startup_name(startup: u8) -> &'static str {
    match startup {
        STARTED => "started",
        STARTUP_FAILED => "failed",
        _ => "starting",
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use axum::body::{Body, to_bytes};
    use omnius_core::{BuildMetadataInput, SchemaCompatibility};
    use omnius_runtime::Supervisor;
    use tower::ServiceExt as _;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn metadata() -> Result<BuildMetadata, omnius_core::InvalidBuildMetadata> {
        BuildMetadata::current(BuildMetadataInput {
            service: "health-test",
            profile: "minimal",
            modules: &["core", "health"],
            providers: &[],
            schema: SchemaCompatibility {
                minimum: "0",
                maximum: "0",
            },
        })
    }

    fn failure_code() -> ErrorCode {
        match ErrorCode::try_new("DEPENDENCY_UNAVAILABLE") {
            Ok(code) => code,
            Err(_) => unreachable!("static health error code is valid"),
        }
    }

    #[tokio::test]
    async fn probes_use_cached_criticality_without_dependency_stampedes() -> TestResult {
        let required_healthy = Arc::new(AtomicBool::new(true));
        let degraded_healthy = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicU32::new(0));
        let mut builder = HealthBuilder::new(metadata()?, HealthConfig::default())?;
        builder.register(HealthCheckSpec::new(
            "database",
            "postgres",
            Criticality::Required,
            Duration::from_millis(50),
            {
                let healthy = Arc::clone(&required_healthy);
                let calls = Arc::clone(&calls);
                move || {
                    let healthy = healthy.load(Ordering::SeqCst);
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        if healthy {
                            Ok(())
                        } else {
                            Err(CheckFailure::new(failure_code()))
                        }
                    }
                }
            },
        ))?;
        builder.register(HealthCheckSpec::new(
            "cache",
            "redis-cache",
            Criticality::Degraded,
            Duration::from_millis(50),
            {
                let healthy = Arc::clone(&degraded_healthy);
                move || {
                    let healthy = healthy.load(Ordering::SeqCst);
                    async move {
                        if healthy {
                            Ok(())
                        } else {
                            Err(CheckFailure::new(failure_code()))
                        }
                    }
                }
            },
        ))?;
        let service = builder.build();
        let app = service.public_router();

        assert_eq!(
            app.clone().oneshot(request("/live")?).await?.status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(request("/startup")?).await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            app.clone().oneshot(request("/ready")?).await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            app.clone().oneshot(request("/version")?).await?.status(),
            StatusCode::OK
        );

        service.mark_started();
        service.refresh_once().await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for _ in 0..5 {
            assert_eq!(
                app.clone().oneshot(request("/ready")?).await?.status(),
                StatusCode::OK
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        required_healthy.store(false, Ordering::SeqCst);
        service.refresh_once().await;
        assert_eq!(
            app.oneshot(request("/ready")?).await?.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        Ok(())
    }

    #[tokio::test]
    async fn stale_required_cache_is_unready_without_refreshing_on_probe() -> TestResult {
        let calls = Arc::new(AtomicU32::new(0));
        let mut builder = HealthBuilder::new(
            metadata()?,
            HealthConfig {
                refresh_interval: Duration::from_millis(1),
                stale_after: Duration::from_millis(2),
                shutdown_timeout: Duration::from_millis(10),
            },
        )?;
        builder.register(HealthCheckSpec::new(
            "database",
            "postgres",
            Criticality::Required,
            Duration::from_millis(1),
            {
                let calls = Arc::clone(&calls);
                move || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async { Ok(()) }
                }
            },
        ))?;
        let service = builder.build();
        service.mark_started();
        service.refresh_once().await;
        assert!(service.is_ready());
        tokio::time::sleep(Duration::from_millis(4)).await;
        assert!(!service.is_ready());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn diagnostics_are_absent_publicly_and_require_admin_marker() -> TestResult {
        let service = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
        let public = service.public_router();
        assert_eq!(
            public
                .oneshot(request("/diagnostics/health")?)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );

        let admin = service.admin_router();
        assert_eq!(
            admin
                .clone()
                .oneshot(request("/diagnostics/health")?)
                .await?
                .status(),
            StatusCode::NOT_FOUND
        );
        let protected = admin.layer(Extension(ProtectedAdmin));
        let response = protected.oneshot(request("/diagnostics/health")?).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(value["startup"], "starting");
        assert!(value.get("checks").is_some());
        Ok(())
    }

    #[tokio::test]
    async fn supervisor_pre_drain_marks_unready_without_fatal_exit() -> TestResult {
        let service = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
        service.mark_started();
        assert!(service.is_ready());
        let mut supervisor = Supervisor::new();
        supervisor.register(service.supervised_refresh_task())?;
        let handle = supervisor.start()?;
        let control = handle.control();

        control.begin_drain();
        tokio::time::timeout(Duration::from_millis(100), async {
            while service.is_ready() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!control.is_shutdown_requested());
        control.request_shutdown();
        let report = handle.shutdown().await;
        assert!(!report.fatal);
        assert!(report.forced.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn coordinated_drain_marks_unready_before_closing_intake_and_signalling_runtime()
    -> TestResult {
        let service = HealthBuilder::new(metadata()?, HealthConfig::default())?.build();
        service.mark_started();
        let mut supervisor = Supervisor::new();
        supervisor.register(service.supervised_refresh_task())?;
        let handle = supervisor.start()?;
        let control = handle.control();

        service.begin_drain_with(&control, || {
            assert!(!service.is_ready());
            assert!(!control.is_draining());
            assert!(!control.is_shutdown_requested());
        });

        let report = handle.shutdown().await;
        assert!(!report.fatal);
        assert!(report.forced.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn timeout_and_panics_are_cached_without_payloads() -> TestResult {
        fn panicking_check() -> std::future::Ready<Result<(), CheckFailure>> {
            panic!("secret check panic")
        }
        let mut builder = HealthBuilder::new(metadata()?, HealthConfig::default())?;
        builder.register(HealthCheckSpec::new(
            "timeout",
            "provider",
            Criticality::Required,
            Duration::from_millis(1),
            || async {
                futures::future::pending::<()>().await;
                Ok(())
            },
        ))?;
        builder.register(HealthCheckSpec::new(
            "panic",
            "provider",
            Criticality::Degraded,
            Duration::from_millis(10),
            panicking_check,
        ))?;
        let service = builder.build();
        service.mark_started();
        service.refresh_once().await;
        assert!(!service.is_ready());
        let encoded = serde_json::to_string(&service.diagnostics())?;
        assert!(encoded.contains("timed_out"));
        assert!(encoded.contains("panicked"));
        assert!(!encoded.contains("secret check panic"));
        Ok(())
    }

    fn request(uri: &str) -> Result<Request<Body>, axum::http::Error> {
        Request::get(uri).body(Body::empty())
    }
}
