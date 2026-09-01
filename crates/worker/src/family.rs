use std::{fmt, sync::Arc, time::Duration};

use omnius_admin::{AdminAuthorityResolver, AdminOperationHandler};
use omnius_health::HealthCheckSpec;
use omnius_inbox::PostgresInbox;
use omnius_jobs_apalis_redis::{RedisJobConfig, RedisJobProvider, redis_job_health_check};
use omnius_jobs_core::{Job, JobEnqueuer, TypedJobHandler};
use omnius_jobs_pgmq::{PgmqJobConfig, PgmqJobProvider, pgmq_job_health_check};
use omnius_notifications::{
    NotificationOrchestrator, NotificationRecoveryConfig, PostgresNotificationRepository,
};
use omnius_outbox::{OutboxConfig, OutboxPublisher, PostgresOutbox};
use omnius_postgres::PostgresPool;
use omnius_runtime::{Criticality, TaskSpec};
use omnius_scheduler::{PostgresScheduler, ScheduleEnvelopeFactory, SchedulerConfig};
use thiserror::Error;

use crate::{PgmqWorkerJob, RedisWorkerJob, WorkerBuilder, pgmq_worker_task, redis_worker_task};

/// Statically selected typed-job provider family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobProviderKind {
    /// Apalis over Redis.
    Redis,
    /// PostgreSQL Message Queue.
    Pgmq,
}

/// Provider-specific input. Matching one variant never constructs or connects the other provider.
pub enum JobProviderInput {
    /// Redis connection and physical worker identity.
    Redis {
        /// Secret-safe Redis provider configuration.
        config: RedisJobConfig,
        /// Portable logical worker name.
        worker_name: String,
    },
    /// Verification-only PGMQ runtime input.
    Pgmq {
        /// Shared managed PostgreSQL pool.
        pool: PostgresPool,
        /// Bounded PGMQ worker configuration.
        config: PgmqJobConfig,
    },
}

impl fmt::Debug for JobProviderInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Redis { config, .. } => formatter
                .debug_struct("Redis")
                .field("config", config)
                .field("worker_name", &"[REDACTED]")
                .finish(),
            Self::Pgmq { pool, config } => formatter
                .debug_struct("Pgmq")
                .field("pool", pool)
                .field("config", config)
                .finish(),
        }
    }
}

/// Application-owned typed handler and supervisor declaration.
pub struct TypedJobContribution<H> {
    handler: H,
    task_name: String,
    criticality: Criticality,
    shutdown_timeout: Duration,
}

impl<H> TypedJobContribution<H> {
    /// Creates a concrete typed-job contribution.
    #[must_use]
    pub fn new(
        handler: H,
        task_name: impl Into<String>,
        criticality: Criticality,
        shutdown_timeout: Duration,
    ) -> Self {
        Self {
            handler,
            task_name: task_name.into(),
            criticality,
            shutdown_timeout,
        }
    }
}

impl<H> fmt::Debug for TypedJobContribution<H> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedJobContribution")
            .field("handler", &"[REDACTED]")
            .field("task_name", &self.task_name)
            .field("criticality", &self.criticality)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

/// Connected provider, required readiness check, and typed supervised worker task.
pub struct JobProviderAssembly<J: Job> {
    selected: SelectedJobProvider<J>,
    worker_job: SelectedWorkerJob<J>,
    enqueuer: Arc<dyn JobEnqueuer>,
    health_check: HealthCheckSpec,
    task: TaskSpec,
}

impl<J: Job> JobProviderAssembly<J> {
    /// Returns the selected provider kind.
    #[must_use]
    pub const fn kind(&self) -> JobProviderKind {
        self.selected.kind()
    }

    /// Returns the object-safe enqueuer backed by the same exact provider instance.
    #[must_use]
    pub fn enqueuer(&self) -> Arc<dyn JobEnqueuer> {
        Arc::clone(&self.enqueuer)
    }

    /// Returns the required provider health declaration.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        self.health_check.clone()
    }

    /// Registers diagnostics and the worker task into an existing composition.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncFamilyBuildError::InvalidWorker`] when registration violates composition
    /// identity invariants.
    pub fn register(
        self,
        builder: &mut WorkerBuilder,
    ) -> Result<SelectedJobProvider<J>, AsyncFamilyBuildError> {
        match self.worker_job {
            SelectedWorkerJob::Redis(source) => builder.register_redis(source),
            SelectedWorkerJob::Pgmq(source) => builder.register_pgmq(source),
        }
        .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        builder
            .register_task(self.task)
            .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        Ok(self.selected)
    }
}

impl<J: Job> fmt::Debug for JobProviderAssembly<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobProviderAssembly")
            .field("kind", &self.kind())
            .field("health_check", &self.health_check)
            .field("task", &self.task)
            .finish_non_exhaustive()
    }
}

/// Connected typed provider retained for application-owned enqueue and provision commands.
#[allow(clippy::large_enum_variant)] // Boxing would add avoidable allocation and indirection.
pub enum SelectedJobProvider<J: Job> {
    /// Redis provider.
    Redis(RedisJobProvider<J>),
    /// Verification-only PGMQ provider.
    Pgmq(PgmqJobProvider<J>),
}

impl<J: Job> SelectedJobProvider<J> {
    /// Returns the selected provider kind.
    #[must_use]
    pub const fn kind(&self) -> JobProviderKind {
        match self {
            Self::Redis(_) => JobProviderKind::Redis,
            Self::Pgmq(_) => JobProviderKind::Pgmq,
        }
    }
}

impl<J: Job> fmt::Debug for SelectedJobProvider<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SelectedJobProvider")
            .field(&self.kind())
            .finish()
    }
}

#[allow(clippy::large_enum_variant)] // Worker jobs are assembled once and consumed immediately.
enum SelectedWorkerJob<J: Job> {
    Redis(RedisWorkerJob<J>),
    Pgmq(PgmqWorkerJob<J>),
}

/// Connects exactly one selected provider and binds one application-owned typed handler.
///
/// PGMQ construction invokes verification-only [`PgmqJobProvider::connect`]; schema installation
/// and queue creation remain exclusively in [`PgmqJobProvider::provision`].
///
/// # Errors
///
/// Returns [`AsyncFamilyBuildError::ApplicationRequired`] when `jobs.handlers` is absent, and a
/// value-free provider/build error otherwise.
pub async fn assemble_job_provider<J, H>(
    input: JobProviderInput,
    contribution: Option<TypedJobContribution<H>>,
    health_timeout: Duration,
) -> Result<JobProviderAssembly<J>, AsyncFamilyBuildError>
where
    J: Job,
    H: TypedJobHandler<J> + Clone,
{
    let contribution = contribution.ok_or(AsyncFamilyBuildError::ApplicationRequired {
        module: "jobs",
        contribution: "jobs.handlers",
    })?;
    match input {
        JobProviderInput::Redis {
            config,
            worker_name,
        } => {
            let provider = RedisJobProvider::<J>::connect(&config)
                .await
                .map_err(|_| AsyncFamilyBuildError::ProviderUnavailable(JobProviderKind::Redis))?;
            let worker_job = RedisWorkerJob::new(provider.clone())
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
            let health_check = redis_job_health_check(provider.clone(), health_timeout);
            let enqueuer: Arc<dyn JobEnqueuer> = Arc::new(provider.clone());
            let task = redis_worker_task(
                provider.clone(),
                contribution.task_name,
                worker_name,
                contribution.handler,
                contribution.criticality,
                contribution.shutdown_timeout,
            );
            Ok(JobProviderAssembly {
                selected: SelectedJobProvider::Redis(provider),
                worker_job: SelectedWorkerJob::Redis(worker_job),
                enqueuer,
                health_check,
                task,
            })
        }
        JobProviderInput::Pgmq { pool, config } => {
            let provider = PgmqJobProvider::<J>::connect(pool, config)
                .await
                .map_err(|_| AsyncFamilyBuildError::ProviderUnavailable(JobProviderKind::Pgmq))?;
            let worker_job = PgmqWorkerJob::new(provider.clone())
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
            let health_check = pgmq_job_health_check(provider.clone(), health_timeout);
            let enqueuer: Arc<dyn JobEnqueuer> = Arc::new(provider.clone());
            let task = pgmq_worker_task(
                provider.clone(),
                contribution.task_name,
                contribution.handler,
                contribution.criticality,
                contribution.shutdown_timeout,
            );
            Ok(JobProviderAssembly {
                selected: SelectedJobProvider::Pgmq(provider),
                worker_job: SelectedWorkerJob::Pgmq(worker_job),
                enqueuer,
                health_check,
                task,
            })
        }
    }
}

/// Existing PostgreSQL-backed async/SaaS repositories constructed from one shared pool.
#[derive(Clone, Debug)]
pub struct PostgresAsyncInfrastructure {
    /// General transactional outbox and relay.
    pub outbox: PostgresOutbox,
    /// Transaction-scoped event inbox helper.
    pub inbox: PostgresInbox,
    /// Durable scheduler repository.
    pub scheduler: PostgresScheduler,
    /// PostgreSQL-authoritative notification repository.
    pub notifications: PostgresNotificationRepository,
}

impl PostgresAsyncInfrastructure {
    /// Constructs the existing PostgreSQL repositories without starting tasks.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for invalid outbox or scheduler policy.
    pub fn new(
        pool: PostgresPool,
        outbox_config: OutboxConfig,
        scheduler_config: SchedulerConfig,
    ) -> Result<Self, AsyncFamilyBuildError> {
        let outbox = PostgresOutbox::new(pool.clone(), outbox_config)
            .map_err(|_| AsyncFamilyBuildError::InvalidOutbox)?;
        let scheduler = PostgresScheduler::new(pool.clone(), scheduler_config)
            .map_err(|_| AsyncFamilyBuildError::InvalidScheduler)?;
        Ok(Self {
            outbox,
            inbox: PostgresInbox::new(),
            scheduler,
            notifications: PostgresNotificationRepository::new(pool),
        })
    }

    /// Registers selected relays, scheduler dispatch, inbox consumers, and notification recovery.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncFamilyBuildError::ApplicationRequired`] when an enabled branch lacks its
    /// concrete application port.
    pub fn register_tasks(
        &self,
        builder: &mut WorkerBuilder,
        enqueuer: Arc<dyn JobEnqueuer>,
        mut contributions: AsyncInfrastructureContributions,
        require_inbox_consumers: bool,
        notification_recovery: Option<NotificationRecoveryConfig>,
    ) -> Result<AsyncServices, AsyncFamilyBuildError> {
        if self.outbox.relay_enabled() && contributions.outbox_publisher.is_none() {
            return Err(AsyncFamilyBuildError::ApplicationRequired {
                module: "outbox",
                contribution: "outbox.publisher",
            });
        }
        if self.scheduler.runtime_enabled() && contributions.scheduler_factory.is_none() {
            return Err(AsyncFamilyBuildError::ApplicationRequired {
                module: "scheduler",
                contribution: "scheduler.envelope-factory",
            });
        }
        if require_inbox_consumers && contributions.inbox_consumer_tasks.is_empty() {
            return Err(AsyncFamilyBuildError::ApplicationRequired {
                module: "inbox",
                contribution: "inbox.consumers",
            });
        }

        if let Some(publisher) = contributions.outbox_publisher.take()
            && let Some(task) = self.outbox.relay_task(publisher)
        {
            builder
                .register_task(task)
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        }
        if let Some(factory) = contributions.scheduler_factory.take()
            && let Some(task) = self.scheduler.task(factory, Arc::clone(&enqueuer))
        {
            builder
                .register_task(task)
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        }
        for task in contributions.inbox_consumer_tasks {
            builder
                .register_task(task)
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        }

        let notifications = NotificationOrchestrator::new(self.notifications.clone(), enqueuer);
        if let Some(config) = notification_recovery {
            builder
                .register_task(notifications.recovery_task(config))
                .map_err(|_| AsyncFamilyBuildError::InvalidWorker)?;
        }
        Ok(AsyncServices { notifications })
    }
}

/// Application-owned ports and concrete inbox tasks used by PostgreSQL async infrastructure.
#[derive(Default)]
pub struct AsyncInfrastructureContributions {
    outbox_publisher: Option<Arc<dyn OutboxPublisher>>,
    scheduler_factory: Option<Arc<dyn ScheduleEnvelopeFactory>>,
    inbox_consumer_tasks: Vec<TaskSpec>,
}

impl AsyncInfrastructureContributions {
    /// Creates an empty set that fails closed for every enabled required branch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            outbox_publisher: None,
            scheduler_factory: None,
            inbox_consumer_tasks: Vec::new(),
        }
    }

    /// Supplies the general transactional outbox publisher.
    #[must_use]
    pub fn with_outbox_publisher(mut self, publisher: Arc<dyn OutboxPublisher>) -> Self {
        self.outbox_publisher = Some(publisher);
        self
    }

    /// Supplies the application-owned schedule envelope factory.
    #[must_use]
    pub fn with_scheduler_factory(mut self, factory: Arc<dyn ScheduleEnvelopeFactory>) -> Self {
        self.scheduler_factory = Some(factory);
        self
    }

    /// Adds a concrete application-owned inbox consumer task.
    #[must_use]
    pub fn with_inbox_consumer_task(mut self, task: TaskSpec) -> Self {
        self.inbox_consumer_tasks.push(task);
        self
    }
}

impl fmt::Debug for AsyncInfrastructureContributions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AsyncInfrastructureContributions")
            .field("outbox_publisher", &self.outbox_publisher.is_some())
            .field("scheduler_factory", &self.scheduler_factory.is_some())
            .field("inbox_consumer_count", &self.inbox_consumer_tasks.len())
            .finish()
    }
}

/// Services produced after concrete async tasks are registered.
#[derive(Clone, Debug)]
pub struct AsyncServices {
    /// Durable notification orchestration over the selected jobs provider.
    pub notifications: NotificationOrchestrator,
}

/// Typed application-owned protected-administration ports.
pub struct AdminContributions<R, O> {
    authority: Option<R>,
    operations: Option<O>,
}

impl<R, O> AdminContributions<R, O> {
    /// Creates a possibly incomplete contribution set for fail-closed validation.
    #[must_use]
    pub const fn new(authority: Option<R>, operations: Option<O>) -> Self {
        Self {
            authority,
            operations,
        }
    }

    /// Requires both trusted administration ports when the module is selected.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncFamilyBuildError::ApplicationRequired`] for the first absent stable port.
    pub fn require(
        self,
        selected: bool,
    ) -> Result<Option<RequiredAdminContributions<R, O>>, AsyncFamilyBuildError>
    where
        R: AdminAuthorityResolver,
        O: AdminOperationHandler,
    {
        if !selected {
            return Ok(None);
        }
        let authority = self
            .authority
            .ok_or(AsyncFamilyBuildError::ApplicationRequired {
                module: "admin",
                contribution: "admin.authority-resolver",
            })?;
        let operations = self
            .operations
            .ok_or(AsyncFamilyBuildError::ApplicationRequired {
                module: "admin",
                contribution: "admin.operation-handler",
            })?;
        Ok(Some(RequiredAdminContributions {
            authority,
            operations,
        }))
    }
}

/// Proven complete protected-administration contribution set.
pub struct RequiredAdminContributions<R, O> {
    /// Trusted current-authority resolver.
    pub authority: R,
    /// Closed typed operation backend.
    pub operations: O,
}

/// Value-free async/SaaS family composition failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AsyncFamilyBuildError {
    /// A selected module has no concrete application-owned port.
    #[error("module {module} requires application contribution {contribution}")]
    ApplicationRequired {
        /// Catalog module identifier.
        module: &'static str,
        /// Stable application requirement literal.
        contribution: &'static str,
    },
    /// The selected provider could not connect or verify its exact resources.
    #[error("selected {0:?} job provider is unavailable")]
    ProviderUnavailable(JobProviderKind),
    /// Worker diagnostics or task registration was invalid.
    #[error("worker composition is invalid")]
    InvalidWorker,
    /// Outbox configuration was invalid.
    #[error("outbox composition is invalid")]
    InvalidOutbox,
    /// Scheduler configuration was invalid.
    #[error("scheduler composition is invalid")]
    InvalidScheduler,
}
