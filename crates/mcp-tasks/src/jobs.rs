use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DomainEvent, IdempotencyRequirement, Jitter, Job,
    JobEnvelope, JobPolicy,
};
use serde::{Deserialize, Serialize};

use crate::{TaskGeneration, TaskId};

const TASK_JOB_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Required,
    10,
    1_000,
    60_000,
    2,
    Jitter::Full,
    3_600,
    256,
    None,
    "mcp-tasks",
    5,
    604_800,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    256,
) {
    Ok(policy) => policy,
    Err(_) => panic!("static MCP task job policy must be valid"),
};

/// At-least-once wake-up trigger for one fenced task execution generation.
///
/// Sensitive capability arguments remain in the authoritative repository and are
/// deliberately absent from the jobs/outbox payload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExecutionJob {
    task_id: TaskId,
    generation: TaskGeneration,
}

impl TaskExecutionJob {
    /// Creates a wake-up trigger for one exact execution generation.
    #[must_use]
    pub const fn new(task_id: TaskId, generation: TaskGeneration) -> Self {
        Self {
            task_id,
            generation,
        }
    }

    /// Returns the authoritative task identifier.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Returns the generation fenced by this delivery.
    #[must_use]
    pub const fn generation(self) -> TaskGeneration {
        self.generation
    }
}

impl Job for TaskExecutionJob {
    const NAME: &'static str = "mcp.task.execute";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = TASK_JOB_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_mcp_task_execute";
    const RUNBOOK: &'static str = "runbooks/mcp-tasks";
}

/// At-least-once wake-up trigger for cooperative cancellation on every worker replica.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCancellationJob {
    task_id: TaskId,
    generation: TaskGeneration,
}

impl TaskCancellationJob {
    /// Creates a cancellation signal fenced to one execution generation.
    #[must_use]
    pub const fn new(task_id: TaskId, generation: TaskGeneration) -> Self {
        Self {
            task_id,
            generation,
        }
    }

    /// Returns the authoritative task identifier.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Returns the generation that may be interrupted.
    #[must_use]
    pub const fn generation(self) -> TaskGeneration {
        self.generation
    }
}

impl Job for TaskCancellationJob {
    const NAME: &'static str = "mcp.task.cancel";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = TASK_JOB_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_mcp_task_cancel";
    const RUNBOOK: &'static str = "runbooks/mcp-tasks";
}

/// Outbox event whose non-sensitive payload carries the exact execution job envelope.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskExecutionRequested {
    job: JobEnvelope<TaskExecutionJob>,
}

impl TaskExecutionRequested {
    /// Wraps the exact jobs-core envelope to enqueue after outbox publication.
    #[must_use]
    pub const fn new(job: JobEnvelope<TaskExecutionJob>) -> Self {
        Self { job }
    }

    /// Returns the exact typed job envelope.
    #[must_use]
    pub const fn job(&self) -> &JobEnvelope<TaskExecutionJob> {
        &self.job
    }
}

impl std::fmt::Debug for TaskExecutionRequested {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskExecutionRequested")
            .field("job_id", &self.job.id())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

impl DomainEvent for TaskExecutionRequested {
    const NAME: &'static str = "mcp.task.execution-requested.v1";
    const VERSION: u16 = 1;
}

/// Outbox event whose payload carries the exact cross-replica cancellation job.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCancellationRequested {
    job: JobEnvelope<TaskCancellationJob>,
}

impl TaskCancellationRequested {
    /// Wraps the exact jobs-core cancellation envelope.
    #[must_use]
    pub const fn new(job: JobEnvelope<TaskCancellationJob>) -> Self {
        Self { job }
    }

    /// Returns the exact typed cancellation envelope.
    #[must_use]
    pub const fn job(&self) -> &JobEnvelope<TaskCancellationJob> {
        &self.job
    }
}

impl std::fmt::Debug for TaskCancellationRequested {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TaskCancellationRequested")
            .field("job_id", &self.job.id())
            .finish_non_exhaustive()
    }
}

impl DomainEvent for TaskCancellationRequested {
    const NAME: &'static str = "mcp.task.cancellation-requested.v1";
    const VERSION: u16 = 1;
}
