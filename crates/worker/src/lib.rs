//! Reusable worker composition, provider-explicit diagnostics, and protected administration.
//!
//! This crate is an application boundary: jobs-core remains limited to enqueue and delivery while
//! Redis and PGMQ operational semantics stay distinct. It intentionally does not own an executable;
//! generated applications select concrete tasks and adapters.

#![forbid(unsafe_code)]

mod admin;
mod family;
mod lifecycle;
mod providers;
mod status;

pub use admin::{ProtectedWorkerAdmin, WorkerAdminBuildError, WorkerAdminError};
pub use family::{
    AdminContributions, AsyncFamilyBuildError, AsyncInfrastructureContributions, AsyncServices,
    JobProviderAssembly, JobProviderInput, JobProviderKind, PostgresAsyncInfrastructure,
    RequiredAdminContributions, SelectedJobProvider, TypedJobContribution, assemble_job_provider,
};
pub use lifecycle::{
    WorkerBuildError, WorkerBuilder, WorkerRuntime, pgmq_worker_task, redis_worker_task,
};
pub use providers::{PgmqWorkerJob, RedisWorkerJob};
pub use status::{
    BackendId, ControlStatus, DeadRecord, JobProviderStatus, NatsConsumerStatus, OutboxStatus,
    PgmqJobStatus, RedisJobStatus, ReplayReceipt, SchedulerStatus, WorkerDiagnostics,
    WorkerDiagnosticsBuildError, WorkerOperationError, WorkerStatus, WorkerTaskStatus,
};
