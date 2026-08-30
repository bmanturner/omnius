use std::sync::Arc;

use futures::future::BoxFuture;
use omnius_agent_capability_registry::InvocationError;
use omnius_core::Clock;
use omnius_jobs_core::{
    DeliveryContext, EnqueueError, EnqueueReceipt, FailureCode, HandlerFailure, HandlerOutcome,
    JobEnqueuer, JobEnqueuerExt, TypedJobHandler,
};
use omnius_mcp_tools::{CanonicalToolResult, InputRequiredToolResult};

use crate::{
    AbandonExecution, AbandonOutcome, CancellationRuntime, CanonicalTaskResult,
    CapabilityExecutionRequest, CapabilityExecutor, ClaimOutcome, InputRound, RepositoryError,
    RequireInput, SettleExecution, SettlementOutcome, TaskCancellationJob,
    TaskCancellationRequested, TaskExecutionJob, TaskExecutionRequested, TaskFailureCode,
    TaskLease, TaskRepository, TaskValueError, TerminalSettlement,
};

/// jobs-core handler for one authoritative task execution generation.
pub struct TaskExecutionJobHandler<R, C, E, K> {
    repository: Arc<R>,
    cancellation: Arc<C>,
    executor: Arc<E>,
    clock: K,
}

impl<R, C, E, K> TaskExecutionJobHandler<R, C, E, K> {
    /// Creates a handler over authoritative durability, cancellation, registry, and time ports.
    #[must_use]
    pub const fn new(repository: Arc<R>, cancellation: Arc<C>, executor: Arc<E>, clock: K) -> Self {
        Self {
            repository,
            cancellation,
            executor,
            clock,
        }
    }
}

impl<R, C, E, K> TypedJobHandler<TaskExecutionJob> for TaskExecutionJobHandler<R, C, E, K>
where
    R: TaskRepository + 'static,
    C: CancellationRuntime + 'static,
    E: CapabilityExecutor + 'static,
    K: Clock + Send + Sync + 'static,
{
    #[expect(
        clippy::too_many_lines,
        reason = "one handler keeps lease, cancellation, executor, settlement, and abandonment fences visible"
    )]
    fn handle(
        &self,
        job: TaskExecutionJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            let claim = crate::ExecutionClaim::new(
                job.task_id(),
                job.generation(),
                context.effect_identity().job_id(),
                self.clock.now_utc(),
            );
            let lease = match self.repository.claim_execution(claim).await {
                Ok(ClaimOutcome::Leased(lease)) => lease,
                Ok(ClaimOutcome::Inactive | ClaimOutcome::Stale) => {
                    return HandlerOutcome::Succeeded;
                }
                Ok(ClaimOutcome::NotFound) => return permanent("mcp_task_missing"),
                Err(error) => return repository_outcome(error),
            };

            let cancellation = context.cancellation().clone();
            if self
                .cancellation
                .register(job.task_id(), job.generation(), cancellation.clone())
                .await
                .is_err()
            {
                self.cancellation
                    .release(job.task_id(), job.generation())
                    .await;
                let abandon = AbandonExecution::new(
                    job.task_id(),
                    job.generation(),
                    lease.version(),
                    lease.claimed_at(),
                    context.effect_identity().job_id(),
                    self.clock.now_utc(),
                );
                return match self.repository.abandon_execution(abandon).await {
                    Ok(AbandonOutcome::Released) => retryable("mcp_task_cancel_registry"),
                    Ok(AbandonOutcome::Cancelled) => HandlerOutcome::Cancelled,
                    Ok(AbandonOutcome::Stale) => HandlerOutcome::Succeeded,
                    Ok(AbandonOutcome::NotFound) => permanent("mcp_task_missing"),
                    Err(error) => repository_outcome(error),
                };
            }

            let result = self
                .executor
                .execute(CapabilityExecutionRequest::new(lease.clone()), cancellation)
                .await;
            self.cancellation
                .release(job.task_id(), job.generation())
                .await;

            let (settlement, interrupted) = match result {
                Ok(result @ CanonicalToolResult::Complete(_)) => {
                    match CanonicalTaskResult::from_tool_result(result) {
                        Ok(result) => (TerminalSettlement::Completed(result), false),
                        Err(_) => (
                            TerminalSettlement::Failed(TaskFailureCode::InvalidResult),
                            false,
                        ),
                    }
                }
                Ok(CanonicalToolResult::InputRequired(input_required)) => {
                    match project_input_round(&lease, input_required) {
                        Ok(round) => {
                            let request = RequireInput::new(
                                job.task_id(),
                                job.generation(),
                                lease.version(),
                                lease.claimed_at(),
                                context.effect_identity().job_id(),
                                round,
                                self.clock.now_utc(),
                            );
                            match self.repository.require_input(request).await {
                                Ok(SettlementOutcome::Applied(_)) => {
                                    return HandlerOutcome::Succeeded;
                                }
                                Ok(SettlementOutcome::Stale) => {
                                    (TerminalSettlement::Cancelled, true)
                                }
                                Ok(SettlementOutcome::NotFound) => {
                                    return permanent("mcp_task_missing");
                                }
                                Err(error) => return repository_outcome(error),
                            }
                        }
                        Err(_) => (
                            TerminalSettlement::Failed(TaskFailureCode::InvalidResult),
                            false,
                        ),
                    }
                }
                Err(InvocationError::Cancelled) => (TerminalSettlement::Cancelled, true),
                Err(error) => (
                    TerminalSettlement::Failed(failure_for_invocation(error)),
                    false,
                ),
            };
            let settlement = SettleExecution::new(
                job.task_id(),
                job.generation(),
                lease.version(),
                lease.claimed_at(),
                context.effect_identity().job_id(),
                settlement,
                self.clock.now_utc(),
            );
            match self.repository.settle_execution(settlement).await {
                Ok(SettlementOutcome::Applied(_)) if interrupted => HandlerOutcome::Cancelled,
                Ok(SettlementOutcome::Applied(_) | SettlementOutcome::Stale) => {
                    HandlerOutcome::Succeeded
                }
                Ok(SettlementOutcome::NotFound) => permanent("mcp_task_missing"),
                Err(error) => repository_outcome(error),
            }
        })
    }
}

/// jobs-core handler that routes a durable cancellation intent to the owning execution token.
pub struct TaskCancellationJobHandler<C> {
    cancellation: Arc<C>,
}

impl<C> TaskCancellationJobHandler<C> {
    /// Creates a cancellation delivery handler.
    #[must_use]
    pub const fn new(cancellation: Arc<C>) -> Self {
        Self { cancellation }
    }
}

impl<C> TypedJobHandler<TaskCancellationJob> for TaskCancellationJobHandler<C>
where
    C: CancellationRuntime + 'static,
{
    fn handle(
        &self,
        job: TaskCancellationJob,
        _context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            match self
                .cancellation
                .signal(job.task_id(), job.generation())
                .await
            {
                Ok(()) => HandlerOutcome::Succeeded,
                Err(_) => retryable("mcp_task_cancel_registry"),
            }
        })
    }
}

/// Relay adapter from established outbox events to the established jobs provider.
///
/// The PostgreSQL outbox relay is at-least-once. The event consumer must use
/// the established inbox with event ID and immutable payload before invoking
/// this adapter, then complete the receipt after jobs acceptance. Both nested
/// envelopes retain a stable job ID and required jobs-core idempotency key, so
/// a redelivered event requests the same logical job rather than creating a new
/// execution generation.
pub struct TaskOutboxJobRelay<Q: ?Sized> {
    jobs: Arc<Q>,
}

impl<Q: JobEnqueuer + ?Sized> TaskOutboxJobRelay<Q> {
    /// Creates a relay over the object-safe jobs provider port.
    #[must_use]
    pub const fn new(jobs: Arc<Q>) -> Self {
        Self { jobs }
    }

    /// Enqueues the exact execution envelope carried by a claimed outbox event.
    ///
    /// # Errors
    ///
    /// Returns [`EnqueueError`] from the established jobs provider.
    pub async fn relay_execution(
        &self,
        requested: &TaskExecutionRequested,
    ) -> Result<EnqueueReceipt, EnqueueError> {
        self.jobs.enqueue_typed(requested.job()).await
    }

    /// Enqueues the exact cancellation envelope carried by a claimed outbox event.
    ///
    /// # Errors
    ///
    /// Returns [`EnqueueError`] from the established jobs provider.
    pub async fn relay_cancellation(
        &self,
        requested: &TaskCancellationRequested,
    ) -> Result<EnqueueReceipt, EnqueueError> {
        self.jobs.enqueue_typed(requested.job()).await
    }
}

fn project_input_round(
    lease: &TaskLease,
    result: InputRequiredToolResult,
) -> Result<InputRound, TaskValueError> {
    let number = lease
        .input_history()
        .last()
        .map_or(Some(1), |round| round.number().checked_add(1))
        .ok_or(TaskValueError::Invalid)?;
    InputRound::from_tool_input_required(number, result)
}

const fn failure_for_invocation(error: InvocationError) -> TaskFailureCode {
    match error {
        InvocationError::DeadlineExceeded => TaskFailureCode::DeadlineExceeded,
        InvocationError::HandlerFailed(_) | InvocationError::OutputBudgetExceeded => {
            TaskFailureCode::ExecutionFailed
        }
        InvocationError::UnknownCapability
        | InvocationError::Unavailable
        | InvocationError::ExposureNotDeclared
        | InvocationError::Denied
        | InvocationError::TenantModeMismatch
        | InvocationError::ConfirmationRequired
        | InvocationError::IdempotencyMismatch
        | InvocationError::InputBudgetExceeded => TaskFailureCode::CapabilityRejected,
        InvocationError::Cancelled => TaskFailureCode::ExecutionFailed,
    }
}

fn repository_outcome(error: RepositoryError) -> HandlerOutcome {
    match error {
        RepositoryError::Unavailable | RepositoryError::TransactionConflict => {
            retryable("mcp_task_repository")
        }
        RepositoryError::Integrity => permanent("mcp_task_integrity"),
    }
}

fn retryable(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Retryable(HandlerFailure::new(failure_code(code)))
}

fn permanent(code: &'static str) -> HandlerOutcome {
    HandlerOutcome::Permanent(HandlerFailure::new(failure_code(code)))
}

fn failure_code(code: &'static str) -> FailureCode {
    match FailureCode::try_from(code.to_owned()) {
        Ok(code) => code,
        Err(error) => panic!("static MCP task failure code must be valid: {error}"),
    }
}
