use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use futures::future::BoxFuture;
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, HandlerOutcome, IdempotencyRequirement,
    Jitter, Job, JobPolicy, TypedJobHandler,
};
use omnius_health::HealthCheckSpec;
use omnius_runtime::{Criticality, TaskSpec};
use omnius_worker::TypedJobContribution;
use service_kit::{
    ApplicationContributions, JobsApalisRedisRuntime, JobsHandlersPort, JobsPgmqRuntime,
    JobsRuntime,
};

/// Application-fixture job used by generated profile verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProfileFixtureJob {
    /// Monotonic fixture sequence asserted by the process scenario.
    pub sequence: u64,
}

impl Job for ProfileFixtureJob {
    const NAME: &'static str = "profile.fixture";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = match JobPolicy::new(
        IdempotencyRequirement::Required,
        3,
        20,
        100,
        2,
        Jitter::Full,
        5,
        2,
        Some(600),
        "profile_fixture",
        5,
        3_600,
        DeadLetterPolicy::Retain,
        CompatibilityPolicy::Exact,
        4_096,
    ) {
        Ok(policy) => policy,
        Err(_) => panic!("profile fixture job policy must be valid"),
    };
    const METRICS_PREFIX: &'static str = "profile_fixture";
    const RUNBOOK: &'static str = "fixtures/profile-composition/async_saas";
}

/// Real fixture handler whose observable counter proves provider delivery occurred.
#[derive(Clone, Debug, Default)]
pub struct ProfileFixtureJobHandler {
    processed: Arc<AtomicU64>,
}

impl ProfileFixtureJobHandler {
    /// Returns the number of completed provider deliveries.
    #[must_use]
    pub fn processed(&self) -> u64 {
        self.processed.load(Ordering::Acquire)
    }
}

impl TypedJobHandler<ProfileFixtureJob> for ProfileFixtureJobHandler {
    fn handle(
        &self,
        _job: ProfileFixtureJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        if context.is_cancelled() {
            return Box::pin(async { HandlerOutcome::Cancelled });
        }
        self.processed.fetch_add(1, Ordering::AcqRel);
        Box::pin(async { HandlerOutcome::Succeeded })
    }
}

impl JobsHandlersPort for ProfileFixtureJobHandler {
    fn handles(&self, job_name: &str) -> bool {
        job_name == ProfileFixtureJob::NAME
    }
}

/// Builds the concrete application contribution installed only in generated verification roots.
#[must_use]
pub fn typed_job_contribution(
    handler: ProfileFixtureJobHandler,
) -> TypedJobContribution<ProfileFixtureJobHandler> {
    TypedJobContribution::new(
        handler,
        "profile-fixture-worker",
        Criticality::Required,
        Duration::from_secs(10),
    )
}

/// Installs an already-connected Redis worker and its behavior-bearing handler double.
#[must_use]
pub fn install_redis_worker_fixture(
    contributions: ApplicationContributions,
    handler: ProfileFixtureJobHandler,
    health: HealthCheckSpec,
    task: TaskSpec,
) -> ApplicationContributions {
    contributions
        .with_jobs_runtime(JobsRuntime::default().with_handlers(Arc::new(handler)))
        .with_jobs_apalis_redis(JobsApalisRedisRuntime::new(health, task))
}

/// Installs an already-verified PGMQ worker and its behavior-bearing handler double.
#[must_use]
pub fn install_pgmq_worker_fixture(
    contributions: ApplicationContributions,
    handler: ProfileFixtureJobHandler,
    health: HealthCheckSpec,
    task: TaskSpec,
) -> ApplicationContributions {
    contributions
        .with_jobs_runtime(JobsRuntime::default().with_handlers(Arc::new(handler)))
        .with_jobs_pgmq(JobsPgmqRuntime::new(health, task))
}
