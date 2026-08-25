//! Durable PostgreSQL calendar scheduling with fenced dispatch and execution.
//!
//! Calendar expressions are parsed and evaluated only by Croner in their configured IANA time
//! zone. Every zoned result is persisted as its exact UTC instant. During a daylight-saving overlap,
//! distinct UTC instants returned by Croner remain distinct occurrences; during a gap, Croner's
//! documented next-valid-instant behavior is preserved.

#![forbid(unsafe_code)]

mod calendar;
mod handler;
mod repository;
mod types;

pub use calendar::{OccurrencePlan, evaluate_occurrences, next_occurrence};
pub use handler::ScheduledJobHandler;
pub use repository::PostgresScheduler;
pub use types::{
    AuditRecord, DispatchFence, DueSchedule, EnvelopeFactoryError, ExecutionFence, LeasedRun,
    MisfirePolicy, RunStatus, ScheduleActor, ScheduleDefinition, ScheduleEnvelopeFactory,
    ScheduleFence, ScheduleId, ScheduleName, ScheduleReason, ScheduleSnapshot, ScheduledRunId,
    SchedulerConfig, SchedulerConfigError, SchedulerError, SchedulerRestartConfig, SchedulerStatus,
};
