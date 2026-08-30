//! Durable, negotiated MCP Tasks extension over existing repository, outbox, inbox, and jobs ports.
//!
//! This crate owns task protocol/state coordination, not a queue. Authoritative state is supplied
//! by [`TaskRepository`]; execution is delivered through typed jobs-core envelopes and always
//! returns the canonical capability result in the exact synchronous MCP projection. The RMCP wire
//! model terminates in [`RmcpTasksAdapter`]. Exact request-scoped identifier and revision
//! negotiation prevents discovery or invocation unless the request activates the official
//! extension.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod domain;
mod jobs;
mod ports;
mod postgres;
mod service;
mod wire;
mod worker;

#[cfg(test)]
mod tests;

pub use domain::{
    BudgetReservationRef, CanonicalTaskResult, InputExchange, InputKey, InputResponses, InputRound,
    InputRoundUpdate, MAX_INPUT_REQUESTS, MAX_TASK_INPUT_BYTES, MAX_TASK_RESULT_BYTES,
    RequestFingerprint, StoredTask, TaskBudget, TaskConfig, TaskExecution, TaskFailureCode,
    TaskGeneration, TaskId, TaskIdError, TaskIdempotency, TaskIdentity, TaskOwner,
    TaskRequestState, TaskSnapshot, TaskState, TaskStatus, TaskTransition, TaskTransitionError,
    TaskValueError, TaskVersion,
};
pub use jobs::{
    TaskCancellationJob, TaskCancellationRequested, TaskExecutionJob, TaskExecutionRequested,
};
pub use ports::{
    AbandonExecution, AbandonOutcome, AtomicCancellation, AtomicCreate, AtomicInputUpdate,
    CancellationOutcome, CancellationRuntime, CancellationRuntimeError, CapabilityExecutionRequest,
    CapabilityExecutor, ClaimOutcome, CreateOutcome, ExecutionClaim, ExpiryBatch, ExpiryReport,
    InputUpdateOutcome, RepositoryError, RequireInput, SettleExecution, SettlementOutcome,
    TaskLease, TaskOutboxIntent, TaskRepository, TerminalSettlement,
};
pub use postgres::{
    PostgresTaskRepository, ProtectedTaskPayload, TaskPayloadProtectionError, TaskPayloadProtector,
};
pub use service::{
    CreateTaskCommand, MCP_TASK_EXPIRY_TASK_NAME, TASKS_CANCEL_METHOD, TASKS_EXTENSION_ID,
    TASKS_EXTENSION_REVISION, TASKS_GET_METHOD, TASKS_UPDATE_METHOD, TaskExpiryRunner,
    TaskInputCoordinator, TaskMethod, TaskService, TaskServiceError, advertised_task_methods,
    advertised_tasks_extension, authorize_task_method,
};
pub use wire::{RmcpTaskError, RmcpTasksAdapter};
pub use worker::{TaskCancellationJobHandler, TaskExecutionJobHandler, TaskOutboxJobRelay};
