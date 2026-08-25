use std::{sync::Arc, time::Duration};

use rsk_core::{ErrorCode, ServiceError};
use rsk_events_nats::NatsJetStreamEvents;
use rsk_health::HealthService;
use rsk_jobs_apalis_redis::RedisJobProvider;
use rsk_jobs_core::{Job, TypedJobHandler};
use rsk_jobs_pgmq::PgmqJobProvider;
use rsk_outbox::PostgresOutbox;
use rsk_runtime::{
    Criticality, RegisterError, ShutdownReport, StartError, Supervisor, SupervisorHandle, TaskSpec,
};
use rsk_scheduler::PostgresScheduler;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    BackendId, PgmqWorkerJob, RedisWorkerJob, WorkerDiagnostics, WorkerDiagnosticsBuildError,
    status::{DiagnosticComponents, JobOperations},
};

/// Worker composition construction or start failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum WorkerBuildError {
    /// A supervisor task registration was invalid or duplicated.
    #[error("worker task registration is invalid")]
    InvalidTask,
    /// A diagnostic component identity was invalid or duplicated.
    #[error("worker diagnostics registration is invalid")]
    InvalidDiagnostics,
    /// A Tokio runtime was not entered when the worker started.
    #[error("worker runtime is unavailable")]
    RuntimeUnavailable,
}

impl From<RegisterError> for WorkerBuildError {
    fn from(_: RegisterError) -> Self {
        Self::InvalidTask
    }
}

impl From<WorkerDiagnosticsBuildError> for WorkerBuildError {
    fn from(_: WorkerDiagnosticsBuildError) -> Self {
        Self::InvalidDiagnostics
    }
}

impl From<StartError> for WorkerBuildError {
    fn from(_: StartError) -> Self {
        Self::RuntimeUnavailable
    }
}

/// Reusable worker profile composition without owning an executable or generator profile.
pub struct WorkerBuilder {
    health: HealthService,
    supervisor: Supervisor,
    diagnostics: DiagnosticComponents,
}

impl std::fmt::Debug for WorkerBuilder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerBuilder")
            .field("supervisor", &self.supervisor)
            .finish_non_exhaustive()
    }
}

impl WorkerBuilder {
    /// Creates a composition and always registers the required health refresh/pre-drain task.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::InvalidTask`] only if the catalog-owned health task declaration
    /// violates supervisor invariants.
    pub fn new(health: HealthService) -> Result<Self, WorkerBuildError> {
        let mut supervisor = Supervisor::new();
        supervisor.register(health.supervised_refresh_task())?;
        Ok(Self {
            health,
            supervisor,
            diagnostics: DiagnosticComponents::new(),
        })
    }

    /// Registers one selected long-lived task.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::InvalidTask`] for an empty or duplicate task identity.
    pub fn register_task(&mut self, task: TaskSpec) -> Result<(), WorkerBuildError> {
        self.supervisor.register(task)?;
        Ok(())
    }

    /// Registers one Redis/Apalis diagnostic and control adapter.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::InvalidDiagnostics`] for a duplicate logical identity.
    pub fn register_redis<J: Job>(
        &mut self,
        source: RedisWorkerJob<J>,
    ) -> Result<(), WorkerBuildError> {
        let source: Arc<dyn JobOperations> = Arc::new(source);
        self.diagnostics.insert_job(source)?;
        Ok(())
    }

    /// Registers one PGMQ diagnostic and control adapter.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::InvalidDiagnostics`] for a duplicate logical identity.
    pub fn register_pgmq<J: Job>(
        &mut self,
        source: PgmqWorkerJob<J>,
    ) -> Result<(), WorkerBuildError> {
        let source: Arc<dyn JobOperations> = Arc::new(source);
        self.diagnostics.insert_job(source)?;
        Ok(())
    }

    /// Selects the durable scheduler status source.
    pub fn select_scheduler(&mut self, scheduler: PostgresScheduler) {
        self.diagnostics.scheduler = Some(scheduler);
    }

    /// Selects the transactional outbox backlog source.
    pub fn select_outbox(&mut self, outbox: PostgresOutbox) {
        self.diagnostics.outbox = Some(outbox);
    }

    /// Registers one selected durable `JetStream` consumer status source.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::InvalidDiagnostics`] for an invalid or duplicate logical ID.
    pub fn register_nats(
        &mut self,
        consumer_id: impl Into<String>,
        runtime: Arc<NatsJetStreamEvents>,
    ) -> Result<(), WorkerBuildError> {
        let consumer_id = BackendId::new(consumer_id)?;
        self.diagnostics.insert_nats(consumer_id, runtime)?;
        Ok(())
    }

    /// Starts every selected task and publishes one shared diagnostics source.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerBuildError::RuntimeUnavailable`] outside an entered Tokio runtime.
    pub fn start(self) -> Result<WorkerRuntime, WorkerBuildError> {
        let fatal_health = self.health.clone();
        match self
            .supervisor
            .start_with_pre_drain_hook(move || fatal_health.mark_draining())
        {
            Ok(handle) => {
                let diagnostics =
                    WorkerDiagnostics::from_components(handle.control(), self.diagnostics);
                self.health.mark_started();
                Ok(WorkerRuntime {
                    health: self.health,
                    diagnostics,
                    handle,
                })
            }
            Err(error) => {
                self.health.mark_startup_failed();
                Err(error.into())
            }
        }
    }
}

/// Running worker lifecycle, diagnostics, and ordered shutdown ownership.
pub struct WorkerRuntime {
    health: HealthService,
    diagnostics: WorkerDiagnostics,
    handle: SupervisorHandle,
}

impl std::fmt::Debug for WorkerRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerRuntime")
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

impl WorkerRuntime {
    /// Returns the protected-admin diagnostics source.
    #[must_use]
    pub const fn diagnostics(&self) -> &WorkerDiagnostics {
        &self.diagnostics
    }

    /// Marks readiness false, then stops every selected task from accepting new work.
    pub fn begin_drain(&self) {
        self.health.begin_drain(&self.handle.control());
    }

    /// Performs readiness-first bounded shutdown and task-specific cancellation/abort.
    #[must_use]
    pub async fn shutdown(self) -> ShutdownReport {
        self.health.begin_drain(&self.handle.control());
        self.handle.shutdown().await
    }
}

/// Creates a supervisor task that stops Redis/Apalis leasing on pre-drain and drains provider work.
#[must_use]
pub fn redis_worker_task<J, H>(
    provider: RedisJobProvider<J>,
    task_name: impl Into<String>,
    worker_name: impl Into<String>,
    handler: H,
    criticality: Criticality,
    shutdown_timeout: Duration,
) -> TaskSpec
where
    J: Job,
    H: TypedJobHandler<J> + Clone,
{
    let task_name = task_name.into();
    let worker_name = worker_name.into();
    TaskSpec::new(
        task_name,
        "jobs-apalis-redis",
        criticality,
        shutdown_timeout,
        move |context| {
            let provider = provider.clone();
            let worker_name = worker_name.clone();
            let handler = handler.clone();
            async move {
                context.heartbeat();
                let cancellation = CancellationToken::new();
                let run = provider.run_worker(&worker_name, handler, cancellation.clone());
                tokio::pin!(run);
                let result = tokio::select! {
                    biased;
                    result = &mut run => result,
                    () = context.draining() => {
                        cancellation.cancel();
                        run.await
                    }
                    () = context.shutdown_requested() => {
                        cancellation.cancel();
                        run.await
                    }
                    () = context.cancelled() => {
                        cancellation.cancel();
                        run.await
                    }
                };
                result.map_err(|_| {
                    provider_service_error(
                        "REDIS_JOB_WORKER_UNAVAILABLE",
                        "Redis job worker is unavailable",
                    )
                })
            }
        },
    )
}

/// Creates a supervisor task that stops PGMQ leasing on pre-drain and drains provider work.
#[must_use]
pub fn pgmq_worker_task<J, H>(
    provider: PgmqJobProvider<J>,
    task_name: impl Into<String>,
    handler: H,
    criticality: Criticality,
    shutdown_timeout: Duration,
) -> TaskSpec
where
    J: Job,
    H: TypedJobHandler<J> + Clone,
{
    let task_name = task_name.into();
    TaskSpec::new(
        task_name,
        "jobs-pgmq",
        criticality,
        shutdown_timeout,
        move |context| {
            let provider = provider.clone();
            let handler = handler.clone();
            async move {
                context.heartbeat();
                let cancellation = CancellationToken::new();
                let run = provider.run_worker(handler, cancellation.clone());
                tokio::pin!(run);
                let result = tokio::select! {
                    biased;
                    result = &mut run => result,
                    () = context.draining() => {
                        cancellation.cancel();
                        run.await
                    }
                    () = context.shutdown_requested() => {
                        cancellation.cancel();
                        run.await
                    }
                    () = context.cancelled() => {
                        cancellation.cancel();
                        run.await
                    }
                };
                result.map_err(|_| {
                    provider_service_error(
                        "PGMQ_JOB_WORKER_UNAVAILABLE",
                        "PGMQ job worker is unavailable",
                    )
                })
            }
        },
    )
}

fn provider_service_error(code: &'static str, message: &'static str) -> ServiceError {
    let Ok(code) = ErrorCode::try_new(code) else {
        unreachable!("worker provider error codes are static and valid");
    };
    ServiceError::new(code, message)
}
