use std::{fmt, num::NonZeroUsize};

use async_trait::async_trait;
use omnius_agent_capability_registry::InvocationError;
use omnius_jobs_core::{Destination, DomainEvent, EventEnvelope, JobId};
use omnius_mcp_tools::CanonicalToolResult;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

use crate::{
    CanonicalTaskResult, InputResponses, InputRound, StoredTask, TaskCancellationRequested,
    TaskExecutionRequested, TaskFailureCode, TaskGeneration, TaskId, TaskOwner, TaskSnapshot,
    TaskVersion,
};

/// Safe repository failure without query, content, tenant, or credential details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RepositoryError {
    /// Durable persistence is temporarily unavailable.
    #[error("task repository is unavailable")]
    Unavailable,
    /// Persisted state violated the task schema or state-machine invariant.
    #[error("task repository contains invalid state")]
    Integrity,
    /// The repository could not serialize a transaction after bounded retries.
    #[error("task repository transaction conflicted")]
    TransactionConflict,
}

/// Typed event and destination appended through the established transactional outbox.
pub struct TaskOutboxIntent<E: DomainEvent> {
    event: EventEnvelope<E>,
    destination: Destination,
}

impl<E: DomainEvent> TaskOutboxIntent<E> {
    /// Creates an exact typed outbox append request.
    #[must_use]
    pub const fn new(event: EventEnvelope<E>, destination: Destination) -> Self {
        Self { event, destination }
    }

    /// Returns the typed jobs-core domain event.
    #[must_use]
    pub const fn event(&self) -> &EventEnvelope<E> {
        &self.event
    }

    /// Returns the established relay destination.
    #[must_use]
    pub const fn destination(&self) -> &Destination {
        &self.destination
    }

    /// Splits the intent into typed outbox append arguments.
    #[must_use]
    pub fn into_parts(self) -> (EventEnvelope<E>, Destination) {
        (self.event, self.destination)
    }
}

impl<E: DomainEvent> fmt::Debug for TaskOutboxIntent<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskOutboxIntent")
            .field("event_id", &self.event.id())
            .field("destination", &"[REDACTED]")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// One caller-owned transaction that creates both authoritative state and its outbox intent.
pub struct AtomicCreate {
    task: StoredTask,
    execution_intent: TaskOutboxIntent<TaskExecutionRequested>,
}

impl AtomicCreate {
    /// Joins the authoritative row and typed outbox event that must commit atomically.
    #[must_use]
    pub const fn new(
        task: StoredTask,
        execution_intent: TaskOutboxIntent<TaskExecutionRequested>,
    ) -> Self {
        Self {
            task,
            execution_intent,
        }
    }

    /// Returns the authoritative task material.
    #[must_use]
    pub const fn task(&self) -> &StoredTask {
        &self.task
    }

    /// Returns the typed execution event for transactional outbox append.
    #[must_use]
    pub const fn execution_intent(&self) -> &TaskOutboxIntent<TaskExecutionRequested> {
        &self.execution_intent
    }

    /// Splits the transaction request into owned parts.
    #[must_use]
    pub fn into_parts(self) -> (StoredTask, TaskOutboxIntent<TaskExecutionRequested>) {
        (self.task, self.execution_intent)
    }
}

impl fmt::Debug for AtomicCreate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicCreate")
            .field("task", &self.task)
            .field("execution_intent", &self.execution_intent)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Result of the unique owner/capability/idempotency create transaction.
#[derive(Clone, Debug)]
pub enum CreateOutcome {
    /// The task and outbox intent were committed together.
    Created(TaskSnapshot),
    /// The same identity and fingerprint already committed; no new intent was appended.
    Existing(TaskSnapshot),
    /// The idempotency identity existed with a different normalized fingerprint.
    FingerprintConflict,
}

/// Atomic client input update and conditional resume intent.
pub struct AtomicInputUpdate {
    owner: TaskOwner,
    task_id: TaskId,
    expected_version: TaskVersion,
    expected_generation: TaskGeneration,
    expected_round: u64,
    responses: InputResponses,
    resume_intent: TaskOutboxIntent<TaskExecutionRequested>,
    now: OffsetDateTime,
}

impl AtomicInputUpdate {
    /// Creates a version/round-fenced update transaction.
    #[expect(
        clippy::too_many_arguments,
        reason = "every fence is independent and must be explicit at the repository boundary"
    )]
    #[must_use]
    pub const fn new(
        owner: TaskOwner,
        task_id: TaskId,
        expected_version: TaskVersion,
        expected_generation: TaskGeneration,
        expected_round: u64,
        responses: InputResponses,
        resume_intent: TaskOutboxIntent<TaskExecutionRequested>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            owner,
            task_id,
            expected_version,
            expected_generation,
            expected_round,
            responses,
            resume_intent,
            now,
        }
    }

    /// Returns the owner scope required in the mutation predicate.
    #[must_use]
    pub const fn owner(&self) -> TaskOwner {
        self.owner
    }

    /// Returns the task identifier.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the optimistic-lock version observed by the adapter.
    #[must_use]
    pub const fn expected_version(&self) -> TaskVersion {
        self.expected_version
    }

    /// Returns the expected active generation.
    #[must_use]
    pub const fn expected_generation(&self) -> TaskGeneration {
        self.expected_generation
    }

    /// Returns the expected outstanding round number.
    #[must_use]
    pub const fn expected_round(&self) -> u64 {
        self.expected_round
    }

    /// Borrows the protected response batch.
    #[must_use]
    pub const fn responses(&self) -> &InputResponses {
        &self.responses
    }

    /// Returns the resume event appended only if this update completes the round.
    #[must_use]
    pub const fn resume_intent(&self) -> &TaskOutboxIntent<TaskExecutionRequested> {
        &self.resume_intent
    }

    /// Returns transaction time.
    #[must_use]
    pub const fn now(&self) -> OffsetDateTime {
        self.now
    }

    /// Splits the request into owned parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        TaskOwner,
        TaskId,
        TaskVersion,
        TaskGeneration,
        u64,
        InputResponses,
        TaskOutboxIntent<TaskExecutionRequested>,
        OffsetDateTime,
    ) {
        (
            self.owner,
            self.task_id,
            self.expected_version,
            self.expected_generation,
            self.expected_round,
            self.responses,
            self.resume_intent,
            self.now,
        )
    }
}

impl fmt::Debug for AtomicInputUpdate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicInputUpdate")
            .field("task_id", &self.task_id)
            .field("expected_version", &self.expected_version)
            .field("expected_generation", &self.expected_generation)
            .field("expected_round", &self.expected_round)
            .field("response_count", &self.responses.as_map().len())
            .field("content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Idempotent input-update result. Unknown, replayed, terminal, and stale keys acknowledge safely.
#[derive(Clone, Debug)]
pub enum InputUpdateOutcome {
    /// No owner-scoped row exists.
    NotFound,
    /// The update was a replay, stale, unknown, partial, terminal, or otherwise a safe no-op.
    Acknowledged(TaskSnapshot),
    /// The final outstanding key committed with exactly one resume outbox intent.
    Resumed(TaskSnapshot),
}

/// Atomic cooperative-cancellation request and outbox intent.
pub struct AtomicCancellation {
    owner: TaskOwner,
    task_id: TaskId,
    expected_version: TaskVersion,
    expected_generation: TaskGeneration,
    cancellation_intent: TaskOutboxIntent<TaskCancellationRequested>,
    now: OffsetDateTime,
}

impl AtomicCancellation {
    /// Creates a fenced cancellation request.
    #[must_use]
    pub const fn new(
        owner: TaskOwner,
        task_id: TaskId,
        expected_version: TaskVersion,
        expected_generation: TaskGeneration,
        cancellation_intent: TaskOutboxIntent<TaskCancellationRequested>,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            owner,
            task_id,
            expected_version,
            expected_generation,
            cancellation_intent,
            now,
        }
    }

    /// Returns the owner predicate.
    #[must_use]
    pub const fn owner(&self) -> TaskOwner {
        self.owner
    }

    /// Returns the task identifier.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the observed optimistic version.
    #[must_use]
    pub const fn expected_version(&self) -> TaskVersion {
        self.expected_version
    }

    /// Returns the generation that may be interrupted.
    #[must_use]
    pub const fn expected_generation(&self) -> TaskGeneration {
        self.expected_generation
    }

    /// Returns the cancellation event appended only on the first active request.
    #[must_use]
    pub const fn cancellation_intent(&self) -> &TaskOutboxIntent<TaskCancellationRequested> {
        &self.cancellation_intent
    }

    /// Returns transaction time.
    #[must_use]
    pub const fn now(&self) -> OffsetDateTime {
        self.now
    }
}

impl fmt::Debug for AtomicCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AtomicCancellation")
            .field("task_id", &self.task_id)
            .field("expected_version", &self.expected_version)
            .field("expected_generation", &self.expected_generation)
            .finish_non_exhaustive()
    }
}

/// Cancellation request result.
#[derive(Clone, Debug)]
pub enum CancellationOutcome {
    /// No owner-scoped row exists.
    NotFound,
    /// The observed version or generation was stale; carries the current owner-scoped row.
    Stale(TaskSnapshot),
    /// Terminal state won the race and remains immutable.
    Terminal(TaskSnapshot),
    /// A queued or input-required task was terminalized before execution.
    Cancelled(TaskSnapshot),
    /// Durable intent committed for an active lease and should be signalled cooperatively.
    Signalled(TaskSnapshot),
    /// The same cancellation was already durably requested.
    AlreadyRequested(TaskSnapshot),
}

/// Delivery claim fenced by authoritative job and task generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionClaim {
    task_id: TaskId,
    generation: TaskGeneration,
    job_id: JobId,
    now: OffsetDateTime,
}

impl ExecutionClaim {
    /// Creates an exact worker delivery claim.
    #[must_use]
    pub const fn new(
        task_id: TaskId,
        generation: TaskGeneration,
        job_id: JobId,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            task_id,
            generation,
            job_id,
            now,
        }
    }

    /// Returns task identity.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Returns delivery generation.
    #[must_use]
    pub const fn generation(self) -> TaskGeneration {
        self.generation
    }

    /// Returns immutable jobs-core delivery identity.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Returns claim time.
    #[must_use]
    pub const fn now(self) -> OffsetDateTime {
        self.now
    }
}

/// Exact lease identity used to abandon a claim before any capability effect starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbandonExecution {
    task_id: TaskId,
    generation: TaskGeneration,
    expected_version: TaskVersion,
    lease_claimed_at: OffsetDateTime,
    job_id: JobId,
    now: OffsetDateTime,
}

impl AbandonExecution {
    /// Creates an exact pre-effect lease release.
    #[must_use]
    pub const fn new(
        task_id: TaskId,
        generation: TaskGeneration,
        expected_version: TaskVersion,
        lease_claimed_at: OffsetDateTime,
        job_id: JobId,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            task_id,
            generation,
            expected_version,
            lease_claimed_at,
            job_id,
            now,
        }
    }

    /// Returns task identity.
    #[must_use]
    pub const fn task_id(self) -> TaskId {
        self.task_id
    }

    /// Returns exact generation.
    #[must_use]
    pub const fn generation(self) -> TaskGeneration {
        self.generation
    }

    /// Returns the claim version.
    #[must_use]
    pub const fn expected_version(self) -> TaskVersion {
        self.expected_version
    }

    /// Returns the exact authoritative lease-attempt timestamp.
    #[must_use]
    pub const fn lease_claimed_at(self) -> OffsetDateTime {
        self.lease_claimed_at
    }

    /// Returns immutable jobs-core identity.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }
    /// Returns mutation time for cancellation-successor convergence.
    #[must_use]
    pub const fn now(self) -> OffsetDateTime {
        self.now
    }
}

/// Result of abandoning a pre-effect execution claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbandonOutcome {
    /// The exact claim was released and its inbox receipt made retryable atomically.
    Released,
    /// A same-generation cancellation successor terminalized the pre-effect claim atomically.
    Cancelled,
    /// Another transition fenced the claim and no matching active lease remains held.
    Stale,
    /// No task exists for the claim.
    NotFound,
}

/// Protected execution lease returned only for the current job generation.
#[derive(Clone)]
pub struct TaskLease {
    task: StoredTask,
    version: TaskVersion,
    claimed_at: OffsetDateTime,
    input_history: Vec<InputRound>,
}

impl TaskLease {
    /// Creates a worker lease from authoritative material and persisted input history.
    #[must_use]
    pub const fn new(
        task: StoredTask,
        version: TaskVersion,
        claimed_at: OffsetDateTime,
        input_history: Vec<InputRound>,
    ) -> Self {
        Self {
            task,
            version,
            claimed_at,
            input_history,
        }
    }

    /// Returns the protected authoritative task.
    #[must_use]
    pub const fn task(&self) -> &StoredTask {
        &self.task
    }

    /// Returns the settlement CAS version.
    #[must_use]
    pub const fn version(&self) -> TaskVersion {
        self.version
    }

    /// Returns the exact authoritative lease-attempt timestamp.
    #[must_use]
    pub const fn claimed_at(&self) -> OffsetDateTime {
        self.claimed_at
    }

    /// Returns exactly-once accepted input rounds for canonical execution resumption.
    #[must_use]
    pub fn input_history(&self) -> &[InputRound] {
        &self.input_history
    }
}

impl fmt::Debug for TaskLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskLease")
            .field("task_id", &self.task.snapshot().task_id())
            .field("generation", &self.task.snapshot().generation())
            .field("version", &self.version)
            .field("claimed_at", &self.claimed_at)
            .field("input_round_count", &self.input_history.len())
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Worker claim result under at-least-once delivery.
#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "worker claims are hot-path values and an avoidable heap allocation would add latency"
)]
pub enum ClaimOutcome {
    /// The exact current generation was leased.
    Leased(TaskLease),
    /// Cancellation or expiry terminalized work before the lease.
    Inactive,
    /// A newer job generation, terminal state, or prior inbox receipt fenced this delivery.
    Stale,
    /// No task row exists for the delivery.
    NotFound,
}

/// CAS request to pause the current execution generation for client input.
pub struct RequireInput {
    task_id: TaskId,
    generation: TaskGeneration,
    expected_version: TaskVersion,
    lease_claimed_at: OffsetDateTime,
    job_id: JobId,
    round: InputRound,
    now: OffsetDateTime,
}

impl RequireInput {
    /// Creates a generation-fenced input pause.
    #[must_use]
    pub const fn new(
        task_id: TaskId,
        generation: TaskGeneration,
        expected_version: TaskVersion,
        lease_claimed_at: OffsetDateTime,
        job_id: JobId,
        round: InputRound,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            task_id,
            generation,
            expected_version,
            lease_claimed_at,
            job_id,
            round,
            now,
        }
    }

    /// Returns task identity.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns the exact current generation.
    #[must_use]
    pub const fn generation(&self) -> TaskGeneration {
        self.generation
    }

    /// Returns the settlement CAS version.
    #[must_use]
    pub const fn expected_version(&self) -> TaskVersion {
        self.expected_version
    }

    /// Returns the exact authoritative lease-attempt timestamp.
    #[must_use]
    pub const fn lease_claimed_at(&self) -> OffsetDateTime {
        self.lease_claimed_at
    }
    /// Returns immutable jobs-core delivery identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns the next durable input round.
    #[must_use]
    pub const fn round(&self) -> &InputRound {
        &self.round
    }

    /// Returns transition time.
    #[must_use]
    pub const fn now(&self) -> OffsetDateTime {
        self.now
    }
}

impl fmt::Debug for RequireInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequireInput")
            .field("task_id", &self.task_id)
            .field("generation", &self.generation)
            .field("version", &self.expected_version)
            .field("job_id", &self.job_id)
            .field("round", &self.round.number())
            .field("content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Terminal worker settlement with no parallel capability result wrapper.
pub enum TerminalSettlement {
    /// The bounded synchronous MCP result projected from canonical capability execution.
    Completed(CanonicalTaskResult),
    /// A fixed redacted terminal failure.
    Failed(TaskFailureCode),
    /// Cooperative cancellation interrupted execution.
    Cancelled,
}

impl fmt::Debug for TerminalSettlement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(_) => formatter.write_str("TerminalSettlement::Completed([redacted])"),
            Self::Failed(failure) => formatter
                .debug_tuple("TerminalSettlement::Failed")
                .field(failure)
                .finish(),
            Self::Cancelled => formatter.write_str("TerminalSettlement::Cancelled"),
        }
    }
}

/// Exact generation/version-fenced terminal mutation.
pub struct SettleExecution {
    task_id: TaskId,
    generation: TaskGeneration,
    expected_version: TaskVersion,
    lease_claimed_at: OffsetDateTime,
    job_id: JobId,
    settlement: TerminalSettlement,
    now: OffsetDateTime,
}

impl SettleExecution {
    /// Creates a terminal CAS mutation.
    #[must_use]
    pub const fn new(
        task_id: TaskId,
        generation: TaskGeneration,
        expected_version: TaskVersion,
        lease_claimed_at: OffsetDateTime,
        job_id: JobId,
        settlement: TerminalSettlement,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            task_id,
            generation,
            expected_version,
            lease_claimed_at,
            job_id,
            settlement,
            now,
        }
    }

    /// Returns task identity.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// Returns exact generation.
    #[must_use]
    pub const fn generation(&self) -> TaskGeneration {
        self.generation
    }

    /// Returns optimistic-lock version.
    #[must_use]
    pub const fn expected_version(&self) -> TaskVersion {
        self.expected_version
    }

    /// Returns the exact authoritative lease-attempt timestamp.
    #[must_use]
    pub const fn lease_claimed_at(&self) -> OffsetDateTime {
        self.lease_claimed_at
    }

    /// Returns immutable jobs-core delivery identity.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Returns terminal status-specific payload.
    #[must_use]
    pub const fn settlement(&self) -> &TerminalSettlement {
        &self.settlement
    }

    /// Returns settlement time.
    #[must_use]
    pub const fn now(&self) -> OffsetDateTime {
        self.now
    }
}

impl fmt::Debug for SettleExecution {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SettleExecution")
            .field("task_id", &self.task_id)
            .field("generation", &self.generation)
            .field("version", &self.expected_version)
            .field("job_id", &self.job_id)
            .field("settlement", &self.settlement)
            .finish_non_exhaustive()
    }
}

/// CAS settlement result.
#[derive(Clone, Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "settlements are hot-path values and an avoidable heap allocation would add latency"
)]
pub enum SettlementOutcome {
    /// The terminal mutation and delivery inbox completion committed together.
    Applied(TaskSnapshot),
    /// A newer generation, cancellation, input round, expiry, terminal state, or inbox receipt won.
    Stale,
    /// No task exists for the delivery.
    NotFound,
}

/// Bounded expiry claim plan for `FOR UPDATE SKIP LOCKED` implementations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpiryBatch {
    now: OffsetDateTime,
    limit: NonZeroUsize,
}

impl ExpiryBatch {
    /// Creates a bounded batch plan.
    ///
    /// # Errors
    ///
    /// Returns [`RepositoryError::Integrity`] for zero or more than 1,000 rows.
    pub fn new(now: OffsetDateTime, limit: usize) -> Result<Self, RepositoryError> {
        let limit = NonZeroUsize::new(limit).ok_or(RepositoryError::Integrity)?;
        if limit.get() > 1_000 {
            return Err(RepositoryError::Integrity);
        }
        Ok(Self { now, limit })
    }

    /// Returns database comparison time.
    #[must_use]
    pub const fn now(self) -> OffsetDateTime {
        self.now
    }

    /// Returns maximum locked rows.
    #[must_use]
    pub const fn limit(self) -> NonZeroUsize {
        self.limit
    }
}

/// Expiry transaction report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiryReport {
    expired: Vec<TaskId>,
    saturated: bool,
}

impl ExpiryReport {
    /// Creates a bounded expiry report.
    #[must_use]
    pub const fn new(expired: Vec<TaskId>, saturated: bool) -> Self {
        Self { expired, saturated }
    }
    /// Returns task IDs terminalized as expired.
    #[must_use]
    pub fn expired(&self) -> &[TaskId] {
        &self.expired
    }

    /// Reports whether another immediate batch may be available.
    #[must_use]
    pub const fn saturated(&self) -> bool {
        self.saturated
    }
}

/// Authoritative durability port for MCP Tasks.
///
/// A PostgreSQL implementation must owner-scope every client query by task ID,
/// subject, and tenant; use caller-owned SQL transactions; append the supplied
/// typed job-intent events through `PostgresOutbox` in the same transaction as
/// state; and claim/complete `PostgresInbox` receipts in the same transaction as
/// worker CAS. Terminal rows are immutable. At-least-once relay delivery is fenced
/// by task generation, job ID, optimistic version, and inbox identity.
#[async_trait]
pub trait TaskRepository: Send + Sync {
    /// Atomically inserts the task and execution outbox intent, or resolves idempotently.
    async fn create_atomic(&self, request: AtomicCreate) -> Result<CreateOutcome, RepositoryError>;

    /// Loads one owner-scoped authoritative snapshot without existence disclosure.
    ///
    /// Implementations use the database clock and must not expose an expired row
    /// as non-terminal while the asynchronous expiry sweep catches up.
    async fn get(
        &self,
        owner: TaskOwner,
        task_id: TaskId,
    ) -> Result<Option<TaskSnapshot>, RepositoryError>;

    /// Atomically accepts each current input key once and appends at most one resume intent.
    async fn update_input_atomic(
        &self,
        request: AtomicInputUpdate,
    ) -> Result<InputUpdateOutcome, RepositoryError>;

    /// Atomically binds cancellation to the current live generation and appends its intent.
    ///
    /// An implementation must lock the owner-scoped row, compare both expected version and
    /// generation, and return [`CancellationOutcome::Stale`] with that locked current snapshot
    /// when either differs. It must never translate a generation race into an acknowledged result.
    async fn cancel_atomic(
        &self,
        request: AtomicCancellation,
    ) -> Result<CancellationOutcome, RepositoryError>;

    /// Claims only the current execution generation and its inbox identity.
    async fn claim_execution(&self, claim: ExecutionClaim)
    -> Result<ClaimOutcome, RepositoryError>;

    /// Releases an exact claim before effects when local execution setup fails.
    ///
    /// PostgreSQL adapters must make the inbox delivery retryable in the same transaction as an
    /// exact lease release. If the sole version successor is same-generation cancellation, they
    /// must instead terminalize cancellation, release the lease, and complete the inbox receipt
    /// atomically as [`AbandonOutcome::Cancelled`]. [`AbandonOutcome::Stale`] is valid only when no
    /// matching active lease remains held.
    async fn abandon_execution(
        &self,
        claim: AbandonExecution,
    ) -> Result<AbandonOutcome, RepositoryError>;

    /// Pauses the exact current lease and completes its delivery inbox receipt atomically;
    /// request keys must be unique over all prior rounds.
    async fn require_input(
        &self,
        request: RequireInput,
    ) -> Result<SettlementOutcome, RepositoryError>;

    /// Commits a terminal CAS and delivery inbox completion together.
    ///
    /// The exact lease version is required except for its single same-generation,
    /// same-job cancellation-intent successor. No input, expiry, generation, or
    /// terminal transition may be overwritten.
    async fn settle_execution(
        &self,
        settlement: SettleExecution,
    ) -> Result<SettlementOutcome, RepositoryError>;

    /// Terminalizes expired non-terminal rows in a skip-locked bounded transaction.
    async fn expire_batch(&self, batch: ExpiryBatch) -> Result<ExpiryReport, RepositoryError>;
}

/// Safe cancellation-runtime failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CancellationRuntimeError {
    /// The cancellation routing registry is unavailable.
    #[error("task cancellation runtime is unavailable")]
    Unavailable,
}

/// Execution-owner bridge from durable cancellation to jobs-core cooperative tokens.
///
/// Registration records the worker owning an active generation. Signalling must
/// route across replicas to that owner (or use a shared registry), and a signal
/// that races just before registration remains sticky for that generation.
/// Durable repository state remains authoritative; this port is never used to
/// answer `tasks/get`.
#[async_trait]
pub trait CancellationRuntime: Send + Sync {
    /// Registers the exact active generation and its jobs-core token.
    async fn register(
        &self,
        task_id: TaskId,
        generation: TaskGeneration,
        cancellation: CancellationToken,
    ) -> Result<(), CancellationRuntimeError>;

    /// Routes a signal to the exact owning generation, retaining pre-registration races.
    async fn signal(
        &self,
        task_id: TaskId,
        generation: TaskGeneration,
    ) -> Result<(), CancellationRuntimeError>;

    /// Releases the exact generation after execution converges.
    async fn release(&self, task_id: TaskId, generation: TaskGeneration);
}

/// Protected request delivered only to the canonical capability registry/runtime.
#[derive(Clone)]
pub struct CapabilityExecutionRequest {
    lease: TaskLease,
}

impl CapabilityExecutionRequest {
    /// Wraps the authoritative leased task and accepted input history.
    #[must_use]
    pub const fn new(lease: TaskLease) -> Self {
        Self { lease }
    }

    /// Returns the authoritative lease.
    #[must_use]
    pub const fn lease(&self) -> &TaskLease {
        &self.lease
    }
}

impl fmt::Debug for CapabilityExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapabilityExecutionRequest")
            .field("lease", &self.lease)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Runtime port that revalidates authorization and executes through the canonical tool projection.
///
/// Implementations must rebuild current canonical principal/policy context from the retained owner
/// and capability revision, re-run authorization, invoke the agent capability registry, validate
/// the declared tool output schema, and return the same bounded complete-or-input-required algebra
/// as synchronous tool execution. [`InvocationError::Cancelled`] remains distinct so durable
/// cooperative cancellation can converge.
#[async_trait]
pub trait CapabilityExecutor: Send + Sync {
    /// Executes or resumes one exact generation under fresh authorization.
    async fn execute(
        &self,
        request: CapabilityExecutionRequest,
        cancellation: CancellationToken,
    ) -> Result<CanonicalToolResult, InvocationError>;
}
