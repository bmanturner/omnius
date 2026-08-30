use std::{fmt, sync::Arc};

use omnius_core::{Clock, CorrelationId};
use omnius_jobs_core::{
    Destination, DomainEvent, EventEnvelope, EventEnvelopeOptions, EventLimits,
    IdempotencyKey as JobIdempotencyKey, JobEnvelope, JobEnvelopeOptions, Source, Subject,
    TenantId as JobTenantId,
};
use omnius_mcp_server_core::{McpExtension, McpRequestContext};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AtomicCancellation, AtomicCreate, AtomicInputUpdate, CancellationOutcome, CancellationRuntime,
    CreateOutcome, ExpiryBatch, ExpiryReport, InputResponses, InputRound, InputUpdateOutcome,
    RepositoryError, RequireInput, SettlementOutcome, StoredTask, TaskCancellationJob,
    TaskCancellationRequested, TaskConfig, TaskExecution, TaskExecutionJob, TaskExecutionRequested,
    TaskGeneration, TaskId, TaskIdempotency, TaskIdentity, TaskOutboxIntent, TaskOwner,
    TaskRepository, TaskSnapshot, TaskState, TaskValueError,
};

/// Official negotiated MCP Tasks extension identifier.
pub const TASKS_EXTENSION_ID: &str = rmcp::model::TASKS_EXTENSION_ID;
/// Exact official MCP Tasks extension revision.
pub const TASKS_EXTENSION_REVISION: &str = "2026-07-28";
/// Exact official task query method.
pub const TASKS_GET_METHOD: &str = "tasks/get";
/// Exact official task input-update method.
pub const TASKS_UPDATE_METHOD: &str = "tasks/update";
/// Exact official task cancellation method.
pub const TASKS_CANCEL_METHOD: &str = "tasks/cancel";
/// Required runtime supervisor name for the replica-safe expiry sweep.
pub const MCP_TASK_EXPIRY_TASK_NAME: &str = "mcp-task-expiry";

const TASK_METHODS: [TaskMethod; 3] = [TaskMethod::Get, TaskMethod::Update, TaskMethod::Cancel];
const MAX_CANCELLATION_ATTEMPTS: usize = 3;

/// Exact methods implemented by this extension. `tasks/list` and `tasks/result` do not exist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskMethod {
    /// `tasks/get`.
    Get,
    /// `tasks/update`.
    Update,
    /// `tasks/cancel`.
    Cancel,
}

impl TaskMethod {
    /// Parses only official methods implemented by SEP-2663.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            TASKS_GET_METHOD => Some(Self::Get),
            TASKS_UPDATE_METHOD => Some(Self::Update),
            TASKS_CANCEL_METHOD => Some(Self::Cancel),
            _ => None,
        }
    }

    /// Returns the exact method name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => TASKS_GET_METHOD,
            Self::Update => TASKS_UPDATE_METHOD,
            Self::Cancel => TASKS_CANCEL_METHOD,
        }
    }
}

/// Returns the exact negotiated Tasks extension for request-scoped advertisement.
#[must_use]
pub fn advertised_tasks_extension(request: &McpRequestContext) -> Option<&McpExtension> {
    request
        .negotiated_extensions()
        .extensions()
        .iter()
        .find(|extension| {
            extension.id().as_str() == TASKS_EXTENSION_ID
                && extension.revision().as_str() == TASKS_EXTENSION_REVISION
        })
}

/// Returns only the official methods enabled by exact request-scoped negotiation.
#[must_use]
pub fn advertised_task_methods(request: &McpRequestContext) -> &'static [TaskMethod] {
    if advertised_tasks_extension(request).is_some() {
        &TASK_METHODS
    } else {
        &[]
    }
}

/// Authorizes one exact official method under request-scoped extension negotiation.
///
/// # Errors
///
/// Returns [`TaskServiceError::NotNegotiated`] unless the exact identifier and revision were
/// negotiated, and [`TaskServiceError::UnsupportedMethod`] for every non-official method.
pub fn authorize_task_method(
    request: &McpRequestContext,
    method: &str,
) -> Result<TaskMethod, TaskServiceError> {
    require_tasks_extension(request)?;
    TaskMethod::from_name(method).ok_or(TaskServiceError::UnsupportedMethod)
}

fn require_tasks_extension(request: &McpRequestContext) -> Result<(), TaskServiceError> {
    advertised_tasks_extension(request)
        .map(|_| ())
        .ok_or(TaskServiceError::NotNegotiated)
}

/// Fixed safe service failures suitable for transport mapping.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TaskServiceError {
    /// The request did not negotiate the exact official extension identifier and revision.
    #[error("MCP Tasks extension was not negotiated")]
    NotNegotiated,
    /// The method is not one of `tasks/get`, `tasks/update`, or `tasks/cancel`.
    #[error("MCP task method is unsupported")]
    UnsupportedMethod,
    /// No row exists in the authenticated owner boundary.
    #[error("task was not found")]
    NotFound,
    /// The create key was reused for different normalized arguments.
    #[error("task idempotency key conflicts with an existing request")]
    IdempotencyConflict,
    /// A bounded input, counter, or task configuration was invalid.
    #[error("task request is invalid")]
    InvalidRequest,
    /// Concurrent generation changes prevented cancellation from converging within its fixed bound.
    #[error("task cancellation raced with execution resumption")]
    CancellationRace,
    /// Typed jobs-core envelope construction failed.
    #[error("task job envelope is invalid")]
    InvalidJob,
    /// Authoritative persistence failed safely.
    #[error(transparent)]
    Repository(#[from] RepositoryError),
}

impl From<TaskValueError> for TaskServiceError {
    fn from(_: TaskValueError) -> Self {
        Self::InvalidRequest
    }
}

/// Validated durable task creation command from a canonical capability invocation.
pub struct CreateTaskCommand {
    execution: TaskExecution,
    idempotency: TaskIdempotency,
}

impl CreateTaskCommand {
    /// Builds a command and fingerprints its normalized capability input.
    ///
    /// Per-request owner and identity are derived only from [`McpRequestContext`]; retained tenant
    /// mode and budget bounds are checked against that canonical context by the service.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError::InvalidRequest`] if normalized input exceeds task limits.
    pub fn new(execution: TaskExecution) -> Result<Self, TaskServiceError> {
        let fingerprint =
            crate::RequestFingerprint::for_invocation(execution.capability(), execution.input())?;
        let idempotency = TaskIdempotency::new(execution.idempotency_key().clone(), fingerprint);
        Ok(Self {
            execution,
            idempotency,
        })
    }

    /// Returns protected execution material.
    #[must_use]
    pub const fn execution(&self) -> &TaskExecution {
        &self.execution
    }

    /// Returns create idempotency identity.
    #[must_use]
    pub const fn idempotency(&self) -> &TaskIdempotency {
        &self.idempotency
    }
}

impl fmt::Debug for CreateTaskCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateTaskCommand")
            .field("capability", &self.execution.capability())
            .field("content", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Transport-neutral application service for durable MCP task creation and official routes.
pub struct TaskService<R, C, K> {
    repository: Arc<R>,
    cancellation: Arc<C>,
    clock: K,
    config: TaskConfig,
}

impl<R, C, K> TaskService<R, C, K>
where
    R: TaskRepository,
    C: CancellationRuntime,
    K: Clock,
{
    /// Creates a service over authoritative durability, cooperative cancellation, and time ports.
    #[must_use]
    pub const fn new(
        repository: Arc<R>,
        cancellation: Arc<C>,
        clock: K,
        config: TaskConfig,
    ) -> Self {
        Self {
            repository,
            cancellation,
            clock,
            config,
        }
    }

    /// Transactionally creates an immediately resolvable task and execution outbox intent.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for negotiation, canonical-context mismatch, envelope,
    /// idempotency, or repository failure.
    pub async fn create(
        &self,
        request_context: &McpRequestContext,
        command: CreateTaskCommand,
    ) -> Result<TaskSnapshot, TaskServiceError> {
        require_tasks_extension(request_context)?;
        validate_execution_context(request_context, command.execution())?;
        let invocation = request_context.canonical().invocation();
        let owner = TaskOwner::from_principal(invocation.principal());
        let request_id = invocation.request_id();
        let identity = TaskIdentity::new(
            request_id,
            CorrelationId::from_uuid(request_id.as_uuid()),
            None,
        );
        let task_id = TaskId::new();
        let execution_intent =
            execution_intent(task_id, TaskGeneration::INITIAL, owner, &identity)?;
        let now = self.clock.now_utc();
        let capability = command.execution.capability().clone();
        let budget = command.execution.budget().clone();
        let snapshot = TaskSnapshot::initial(
            task_id,
            owner,
            capability,
            identity,
            command.idempotency,
            budget,
            execution_intent.event().data().job().id(),
            now,
            self.config,
        );
        let request = AtomicCreate::new(
            StoredTask::new(snapshot, command.execution),
            execution_intent,
        );
        match self.repository.create_atomic(request).await? {
            CreateOutcome::Created(snapshot) | CreateOutcome::Existing(snapshot) => Ok(snapshot),
            CreateOutcome::FingerprintConflict => Err(TaskServiceError::IdempotencyConflict),
        }
    }

    /// Returns one owner-scoped authoritative snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for negotiation, absence, or repository failure.
    pub async fn get(
        &self,
        request_context: &McpRequestContext,
        task_id: TaskId,
    ) -> Result<TaskSnapshot, TaskServiceError> {
        require_tasks_extension(request_context)?;
        let owner = owner_from_context(request_context);
        self.repository
            .get(owner, task_id)
            .await?
            .ok_or(TaskServiceError::NotFound)
    }

    /// Accepts current outstanding input keys once and resumes at most one new generation.
    ///
    /// Replays, unknown/stale keys, terminal state, and update races are acknowledged without
    /// reviving execution. Owner mismatch remains indistinguishable from absence.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for negotiation, absence, exhaustion, or repository failure.
    pub async fn update(
        &self,
        request_context: &McpRequestContext,
        task_id: TaskId,
        responses: InputResponses,
    ) -> Result<(), TaskServiceError> {
        require_tasks_extension(request_context)?;
        let owner = owner_from_context(request_context);
        let snapshot = self
            .repository
            .get(owner, task_id)
            .await?
            .ok_or(TaskServiceError::NotFound)?;
        let TaskState::InputRequired { round } = snapshot.state() else {
            return Ok(());
        };
        let next_generation = snapshot
            .generation()
            .next()
            .ok_or(TaskServiceError::InvalidRequest)?;
        let resume_intent = execution_intent(task_id, next_generation, owner, snapshot.identity())?;
        let request = AtomicInputUpdate::new(
            owner,
            task_id,
            snapshot.version(),
            snapshot.generation(),
            round.number(),
            responses,
            resume_intent,
            self.clock.now_utc(),
        );
        match self.repository.update_input_atomic(request).await? {
            InputUpdateOutcome::NotFound => Err(TaskServiceError::NotFound),
            InputUpdateOutcome::Acknowledged(_) | InputUpdateOutcome::Resumed(_) => Ok(()),
        }
    }

    /// Durably binds cancellation to the current live generation before best-effort signalling.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for negotiation, absence, envelope, repository failure, or
    /// repeated concurrent generation changes beyond the strict retry bound.
    pub async fn cancel(
        &self,
        request_context: &McpRequestContext,
        task_id: TaskId,
    ) -> Result<(), TaskServiceError> {
        require_tasks_extension(request_context)?;
        let owner = owner_from_context(request_context);
        let mut snapshot = self
            .repository
            .get(owner, task_id)
            .await?
            .ok_or(TaskServiceError::NotFound)?;
        for _attempt in 0..MAX_CANCELLATION_ATTEMPTS {
            if snapshot.state().is_terminal() {
                return Ok(());
            }
            let cancellation_intent =
                cancellation_intent(task_id, snapshot.generation(), owner, snapshot.identity())?;
            let request = AtomicCancellation::new(
                owner,
                task_id,
                snapshot.version(),
                snapshot.generation(),
                cancellation_intent,
                self.clock.now_utc(),
            );
            match self.repository.cancel_atomic(request).await? {
                CancellationOutcome::NotFound => return Err(TaskServiceError::NotFound),
                CancellationOutcome::Stale(current) => snapshot = current,
                CancellationOutcome::Signalled(cancelled)
                | CancellationOutcome::AlreadyRequested(cancelled) => {
                    let _signal_result = self
                        .cancellation
                        .signal(cancelled.task_id(), cancelled.generation())
                        .await;
                    return Ok(());
                }
                CancellationOutcome::Terminal(_) | CancellationOutcome::Cancelled(_) => {
                    return Ok(());
                }
            }
        }
        Err(TaskServiceError::CancellationRace)
    }
}

fn owner_from_context(request: &McpRequestContext) -> TaskOwner {
    TaskOwner::from_principal(request.canonical().invocation().principal())
}

fn validate_execution_context(
    request: &McpRequestContext,
    execution: &TaskExecution,
) -> Result<(), TaskServiceError> {
    let canonical = request.canonical();
    if execution.tenant_mode() != canonical.tenant_mode()
        || execution.budget().bounds() != canonical.invocation().budget()
    {
        return Err(TaskServiceError::InvalidRequest);
    }
    Ok(())
}

/// Runtime-facing input-pause coordinator using the same authoritative CAS.
pub struct TaskInputCoordinator<R, K> {
    repository: Arc<R>,
    clock: K,
}

impl<R, K> TaskInputCoordinator<R, K>
where
    R: TaskRepository,
    K: Clock,
{
    /// Creates a coordinator over authoritative persistence and time.
    #[must_use]
    pub const fn new(repository: Arc<R>, clock: K) -> Self {
        Self { repository, clock }
    }

    /// Persists an input round only for the exact active worker lease.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for repository failure.
    pub async fn require_input(
        &self,
        task_id: TaskId,
        generation: TaskGeneration,
        version: crate::TaskVersion,
        lease_claimed_at: OffsetDateTime,
        job_id: omnius_jobs_core::JobId,
        round: InputRound,
    ) -> Result<SettlementOutcome, TaskServiceError> {
        Ok(self
            .repository
            .require_input(RequireInput::new(
                task_id,
                generation,
                version,
                lease_claimed_at,
                job_id,
                round,
                self.clock.now_utc(),
            ))
            .await?)
    }
}

/// Replica-safe bounded expiry task (`mcp-task-expiry`).
pub struct TaskExpiryRunner<R, K> {
    repository: Arc<R>,
    clock: K,
    config: TaskConfig,
}

impl<R, K> TaskExpiryRunner<R, K>
where
    R: TaskRepository,
    K: Clock,
{
    /// Creates the expiry runner.
    #[must_use]
    pub const fn new(repository: Arc<R>, clock: K, config: TaskConfig) -> Self {
        Self {
            repository,
            clock,
            config,
        }
    }

    /// Expires one skip-locked bounded batch.
    ///
    /// # Errors
    ///
    /// Returns [`TaskServiceError`] for invalid configuration or repository failure.
    pub async fn run_once(&self) -> Result<ExpiryReport, TaskServiceError> {
        let batch = ExpiryBatch::new(self.clock.now_utc(), self.config.expiry_batch_size())?;
        Ok(self.repository.expire_batch(batch).await?)
    }
}

fn execution_intent(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<TaskOutboxIntent<TaskExecutionRequested>, TaskServiceError> {
    let job = execution_envelope(task_id, generation, owner, identity)?;
    outbox_intent(
        TaskExecutionRequested::new(job),
        "mcp.tasks.execute",
        task_id,
        owner,
        identity,
    )
}

fn cancellation_intent(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<TaskOutboxIntent<TaskCancellationRequested>, TaskServiceError> {
    let job = cancellation_envelope(task_id, generation, owner, identity)?;
    outbox_intent(
        TaskCancellationRequested::new(job),
        "mcp.tasks.cancel",
        task_id,
        owner,
        identity,
    )
}

fn outbox_intent<E: DomainEvent>(
    data: E,
    destination: &'static str,
    task_id: TaskId,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<TaskOutboxIntent<E>, TaskServiceError> {
    let source = Source::try_from("omnius.mcp.tasks".to_owned())
        .map_err(|_| TaskServiceError::InvalidJob)?;
    let subject =
        Subject::try_from(format!("task/{task_id}")).map_err(|_| TaskServiceError::InvalidJob)?;
    let mut options =
        EventEnvelopeOptions::new(source, subject, identity.correlation_id().as_uuid())
            .map_err(|_| TaskServiceError::InvalidJob)?;
    if let Some(tenant_id) = owner.tenant_id() {
        let tenant = JobTenantId::try_from(tenant_id.to_string())
            .map_err(|_| TaskServiceError::InvalidJob)?;
        options = options.with_tenant(tenant);
    }
    if let Some(causation_id) = identity.causation_id() {
        options = options
            .with_causation(causation_id.as_uuid())
            .map_err(|_| TaskServiceError::InvalidJob)?;
    }
    let event = EventEnvelope::new(data, options, EventLimits::default())
        .map_err(|_| TaskServiceError::InvalidJob)?;
    let destination =
        Destination::try_from(destination.to_owned()).map_err(|_| TaskServiceError::InvalidJob)?;
    Ok(TaskOutboxIntent::new(event, destination))
}

fn execution_envelope(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<JobEnvelope<TaskExecutionJob>, TaskServiceError> {
    job_envelope(
        TaskExecutionJob::new(task_id, generation),
        task_id,
        generation,
        owner,
        identity,
    )
}

fn cancellation_envelope(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<JobEnvelope<TaskCancellationJob>, TaskServiceError> {
    job_envelope(
        TaskCancellationJob::new(task_id, generation),
        task_id,
        generation,
        owner,
        identity,
    )
}

fn job_envelope<J: omnius_jobs_core::Job>(
    payload: J,
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<JobEnvelope<J>, TaskServiceError> {
    let mut options = JobEnvelopeOptions::new(identity.correlation_id().as_uuid())
        .map_err(|_| TaskServiceError::InvalidJob)?;
    if let Some(tenant_id) = owner.tenant_id() {
        let tenant = JobTenantId::try_from(tenant_id.to_string())
            .map_err(|_| TaskServiceError::InvalidJob)?;
        options = options.with_tenant(tenant);
    }
    if let Some(causation_id) = identity.causation_id() {
        options = options
            .with_causation(causation_id.as_uuid())
            .map_err(|_| TaskServiceError::InvalidJob)?;
    }
    let job_key = JobIdempotencyKey::try_from(format!(
        "mcp-task:{task_id}:generation:{}",
        generation.get()
    ))
    .map_err(|_| TaskServiceError::InvalidJob)?;
    options = options.with_idempotency_key(job_key);
    JobEnvelope::new(payload, options).map_err(|_| TaskServiceError::InvalidJob)
}
