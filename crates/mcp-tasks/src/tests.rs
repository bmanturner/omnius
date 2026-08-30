use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityId, CapabilityKey, CapabilityVersion, ConfirmationEvidence,
    IdempotencyKey, InvocationContext, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::Decision;
use omnius_core::{Clock, RequestId};
use omnius_jobs_core::{EventId, JobId};
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use omnius_mcp_tools::{
    CanonicalToolResult, InputPrompt, InputRequest as CanonicalInputRequest, InputRequestId,
    InputRequiredToolResult, JsonSchemaDocument, RequestState, ToolFailure, ToolFailureCode,
    ToolRepresentation,
};
use rmcp::model::{CancelTaskParams, GetTaskParams, UpdateTaskParams};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::*;

#[derive(Clone)]
struct ManualClock {
    base: OffsetDateTime,
    millis: Arc<AtomicI64>,
}

impl ManualClock {
    fn new() -> Self {
        Self {
            base: OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000),
            millis: Arc::new(AtomicI64::new(0)),
        }
    }

    fn advance(&self, duration: Duration) {
        let millis = i64::try_from(duration.as_millis()).unwrap_or(i64::MAX);
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> OffsetDateTime {
        let millis = self.millis.fetch_add(1, Ordering::SeqCst);
        self.base + time::Duration::milliseconds(millis)
    }
}

#[derive(Default)]
struct MemoryRepository {
    state: Mutex<MemoryState>,
    fail_create: AtomicUsize,
    resume_before_cancel: AtomicUsize,
}
#[derive(Default)]
struct MemoryState {
    tasks: HashMap<TaskId, MemoryTask>,
    outbox: Vec<EventId>,
    completed_deliveries: HashSet<JobId>,
}

struct MemoryTask {
    stored: StoredTask,
    input_history: Vec<InputRound>,
    lease_claimed_at: Option<OffsetDateTime>,
}

impl MemoryRepository {
    fn fail_next_create(&self) {
        self.fail_create.store(1, Ordering::SeqCst);
    }
    fn resume_before_next_cancel(&self) {
        self.resume_before_cancel.store(1, Ordering::SeqCst);
    }

    async fn task_count(&self) -> usize {
        self.state.lock().await.tasks.len()
    }

    async fn outbox_count(&self) -> usize {
        self.state.lock().await.outbox.len()
    }

    async fn snapshot(&self, task_id: TaskId) -> Option<TaskSnapshot> {
        self.state
            .lock()
            .await
            .tasks
            .get(&task_id)
            .map(|task| task.stored.snapshot().clone())
    }

    async fn expire_active_lease(&self, task_id: TaskId) -> bool {
        self.state
            .lock()
            .await
            .tasks
            .get_mut(&task_id)
            .and_then(|task| task.lease_claimed_at.take())
            .is_some()
    }
}

#[async_trait]
impl TaskRepository for MemoryRepository {
    async fn create_atomic(&self, request: AtomicCreate) -> Result<CreateOutcome, RepositoryError> {
        if self.fail_create.swap(0, Ordering::SeqCst) == 1 {
            return Err(RepositoryError::Unavailable);
        }
        let (stored, intent) = request.into_parts();
        let snapshot = stored.snapshot().clone();
        let execution_job = intent.event().data().job();
        if snapshot.current_job_id() != execution_job.id()
            || snapshot.task_id() != execution_job.payload().task_id()
            || snapshot.generation() != execution_job.payload().generation()
        {
            return Err(RepositoryError::Integrity);
        }
        let mut state = self.state.lock().await;
        let existing = state.tasks.values().find(|candidate| {
            let candidate = candidate.stored.snapshot();
            candidate.owner() == snapshot.owner()
                && candidate.capability() == snapshot.capability()
                && candidate.idempotency().key() == snapshot.idempotency().key()
        });
        if let Some(existing) = existing {
            if existing.stored.snapshot().idempotency().fingerprint()
                == snapshot.idempotency().fingerprint()
            {
                return Ok(CreateOutcome::Existing(existing.stored.snapshot().clone()));
            }
            return Ok(CreateOutcome::FingerprintConflict);
        }
        state.outbox.push(intent.event().id());
        state.tasks.insert(
            snapshot.task_id(),
            MemoryTask {
                stored,
                input_history: Vec::new(),
                lease_claimed_at: None,
            },
        );
        Ok(CreateOutcome::Created(snapshot.clone()))
    }

    async fn get(
        &self,
        owner: TaskOwner,
        task_id: TaskId,
    ) -> Result<Option<TaskSnapshot>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .await
            .tasks
            .get(&task_id)
            .filter(|task| task.stored.snapshot().owner() == owner)
            .map(|task| task.stored.snapshot().clone()))
    }

    async fn update_input_atomic(
        &self,
        request: AtomicInputUpdate,
    ) -> Result<InputUpdateOutcome, RepositoryError> {
        let (
            owner,
            task_id,
            expected_version,
            expected_generation,
            expected_round,
            responses,
            resume_intent,
            now,
        ) = request.into_parts();
        let mut state = self.state.lock().await;
        let Some(task) = state.tasks.get_mut(&task_id) else {
            return Ok(InputUpdateOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot().clone();
        if snapshot.owner() != owner {
            return Ok(InputUpdateOutcome::NotFound);
        }
        if snapshot.version() != expected_version || snapshot.generation() != expected_generation {
            return Ok(InputUpdateOutcome::Acknowledged(snapshot));
        }
        let TaskState::InputRequired { round } = snapshot.state() else {
            return Ok(InputUpdateOutcome::Acknowledged(snapshot));
        };
        if round.number() != expected_round {
            return Ok(InputUpdateOutcome::Acknowledged(snapshot));
        }
        let update = round.apply(&responses);
        if !update.changed() {
            return Ok(InputUpdateOutcome::Acknowledged(snapshot));
        }
        let execution = task.stored.execution().clone();
        if update.complete() {
            let answered_round = update.into_round();
            let resume_job = resume_intent.event().data().job();
            let transition = TaskTransition::Resume {
                answered_round: answered_round.clone(),
                job_id: resume_job.id(),
                generation: resume_job.payload().generation(),
            };
            let next = snapshot
                .transitioned(expected_version, transition, now)
                .map_err(|_| RepositoryError::Integrity)?;
            task.input_history.push(answered_round);
            task.stored = StoredTask::new(next.clone(), execution);
            state.outbox.push(resume_intent.event().id());
            Ok(InputUpdateOutcome::Resumed(next))
        } else {
            let next = snapshot
                .transitioned(
                    expected_version,
                    TaskTransition::RecordInput(update.into_round()),
                    now,
                )
                .map_err(|_| RepositoryError::Integrity)?;
            task.stored = StoredTask::new(next.clone(), execution);
            Ok(InputUpdateOutcome::Acknowledged(next))
        }
    }

    async fn cancel_atomic(
        &self,
        request: AtomicCancellation,
    ) -> Result<CancellationOutcome, RepositoryError> {
        let mut state = self.state.lock().await;
        let Some(task) = state.tasks.get_mut(&request.task_id()) else {
            return Ok(CancellationOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot().clone();
        if snapshot.owner() != request.owner() {
            return Ok(CancellationOutcome::NotFound);
        }
        if self.resume_before_cancel.swap(0, Ordering::SeqCst) == 1 {
            let TaskState::InputRequired { round } = snapshot.state() else {
                return Err(RepositoryError::Integrity);
            };
            let responses = round
                .pending()
                .map(|(key, _)| {
                    (
                        key.as_str().to_owned(),
                        json!({"action": "accept", "content": {"value": "resumed"}}),
                    )
                })
                .collect();
            let answered = round
                .apply(&InputResponses::new(responses).map_err(|_| RepositoryError::Integrity)?)
                .into_round();
            let generation = snapshot
                .generation()
                .next()
                .ok_or(RepositoryError::Integrity)?;
            let next = snapshot
                .transitioned(
                    snapshot.version(),
                    TaskTransition::Resume {
                        answered_round: answered,
                        job_id: JobId::new(),
                        generation,
                    },
                    request.now(),
                )
                .map_err(|_| RepositoryError::Integrity)?;
            task.stored = StoredTask::new(next.clone(), task.stored.execution().clone());
            task.lease_claimed_at = Some(request.now());
            return Ok(CancellationOutcome::Stale(next));
        }
        if snapshot.state().is_terminal() {
            return Ok(CancellationOutcome::Terminal(snapshot));
        }
        if snapshot.version() != request.expected_version()
            || snapshot.generation() != request.expected_generation()
        {
            return Ok(CancellationOutcome::Stale(snapshot));
        }
        if snapshot.cancellation_requested() {
            return Ok(CancellationOutcome::AlreadyRequested(snapshot));
        }
        if request
            .cancellation_intent()
            .event()
            .data()
            .job()
            .payload()
            .generation()
            != snapshot.generation()
        {
            return Err(RepositoryError::Integrity);
        }
        let leased = task.lease_claimed_at.is_some();
        let transition = if leased {
            TaskTransition::RequestCancellation
        } else {
            TaskTransition::Cancel
        };
        let next = snapshot
            .transitioned(snapshot.version(), transition, request.now())
            .map_err(|_| RepositoryError::Integrity)?;
        task.stored = StoredTask::new(next.clone(), task.stored.execution().clone());
        state
            .outbox
            .push(request.cancellation_intent().event().id());
        if leased {
            Ok(CancellationOutcome::Signalled(next))
        } else {
            Ok(CancellationOutcome::Cancelled(next))
        }
    }

    async fn claim_execution(
        &self,
        claim: ExecutionClaim,
    ) -> Result<ClaimOutcome, RepositoryError> {
        let mut state = self.state.lock().await;
        if state.completed_deliveries.contains(&claim.job_id()) {
            return Ok(ClaimOutcome::Stale);
        }
        let Some(task) = state.tasks.get_mut(&claim.task_id()) else {
            return Ok(ClaimOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot();
        if snapshot.current_job_id() != claim.job_id()
            || snapshot.generation() != claim.generation()
            || !matches!(snapshot.state(), TaskState::Working)
            || snapshot.cancellation_requested()
            || claim.now() >= snapshot.expires_at()
            || task.lease_claimed_at.is_some()
        {
            return Ok(ClaimOutcome::Stale);
        }
        let version = snapshot.version();
        task.lease_claimed_at = Some(claim.now());
        Ok(ClaimOutcome::Leased(TaskLease::new(
            task.stored.clone(),
            version,
            claim.now(),
            task.input_history.clone(),
        )))
    }

    async fn abandon_execution(
        &self,
        claim: AbandonExecution,
    ) -> Result<AbandonOutcome, RepositoryError> {
        let mut state = self.state.lock().await;
        let Some(task) = state.tasks.get_mut(&claim.task_id()) else {
            return Ok(AbandonOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot().clone();
        if task.lease_claimed_at != Some(claim.lease_claimed_at())
            || snapshot.current_job_id() != claim.job_id()
            || snapshot.generation() != claim.generation()
        {
            return Ok(AbandonOutcome::Stale);
        }
        if snapshot.version() == claim.expected_version() {
            task.lease_claimed_at = None;
            return Ok(AbandonOutcome::Released);
        }
        let cancellation_advanced = snapshot.cancellation_requested()
            && matches!(snapshot.state(), TaskState::Working)
            && snapshot.version().get() == claim.expected_version().get().saturating_add(1);
        if !cancellation_advanced {
            return Err(RepositoryError::Integrity);
        }
        let next = snapshot
            .transitioned(snapshot.version(), TaskTransition::Cancel, claim.now())
            .map_err(|_| RepositoryError::Integrity)?;
        task.stored = StoredTask::new(next, task.stored.execution().clone());
        task.lease_claimed_at = None;
        state.completed_deliveries.insert(claim.job_id());
        Ok(AbandonOutcome::Cancelled)
    }

    async fn require_input(
        &self,
        request: RequireInput,
    ) -> Result<SettlementOutcome, RepositoryError> {
        let mut state = self.state.lock().await;
        let Some(task) = state.tasks.get_mut(&request.task_id()) else {
            return Ok(SettlementOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot().clone();
        if task.lease_claimed_at != Some(request.lease_claimed_at())
            || snapshot.generation() != request.generation()
            || snapshot.version() != request.expected_version()
            || snapshot.current_job_id() != request.job_id()
            || snapshot.cancellation_requested()
        {
            return Ok(SettlementOutcome::Stale);
        }
        let prior_keys: HashSet<&str> = task
            .input_history
            .iter()
            .flat_map(|round| round.exchanges().keys().map(InputKey::as_str))
            .collect();
        if request
            .round()
            .exchanges()
            .keys()
            .any(|key| prior_keys.contains(key.as_str()))
        {
            return Err(RepositoryError::Integrity);
        }
        let next = snapshot
            .transitioned(
                request.expected_version(),
                TaskTransition::RequireInput(request.round().clone()),
                request.now(),
            )
            .map_err(|_| RepositoryError::Integrity)?;
        task.stored = StoredTask::new(next.clone(), task.stored.execution().clone());
        task.lease_claimed_at = None;
        state.completed_deliveries.insert(request.job_id());
        Ok(SettlementOutcome::Applied(next))
    }

    async fn settle_execution(
        &self,
        settlement: SettleExecution,
    ) -> Result<SettlementOutcome, RepositoryError> {
        let mut state = self.state.lock().await;
        if state.completed_deliveries.contains(&settlement.job_id()) {
            return Ok(SettlementOutcome::Stale);
        }
        let Some(task) = state.tasks.get_mut(&settlement.task_id()) else {
            return Ok(SettlementOutcome::NotFound);
        };
        let snapshot = task.stored.snapshot().clone();
        let cancellation_advanced = snapshot.cancellation_requested()
            && snapshot.version().get() == settlement.expected_version().get().saturating_add(1);
        if task.lease_claimed_at != Some(settlement.lease_claimed_at())
            || snapshot.current_job_id() != settlement.job_id()
            || snapshot.generation() != settlement.generation()
            || !matches!(snapshot.state(), TaskState::Working)
            || (snapshot.version() != settlement.expected_version() && !cancellation_advanced)
        {
            return Ok(SettlementOutcome::Stale);
        }
        let transition = match settlement.settlement() {
            TerminalSettlement::Completed(result) => TaskTransition::Complete(result.clone()),
            TerminalSettlement::Failed(failure) => TaskTransition::Fail(*failure),
            TerminalSettlement::Cancelled => TaskTransition::Cancel,
        };
        let next = snapshot
            .transitioned(snapshot.version(), transition, settlement.now())
            .map_err(|_| RepositoryError::Integrity)?;
        task.stored = StoredTask::new(next.clone(), task.stored.execution().clone());
        task.lease_claimed_at = None;
        state.completed_deliveries.insert(settlement.job_id());
        Ok(SettlementOutcome::Applied(next))
    }

    async fn expire_batch(&self, batch: ExpiryBatch) -> Result<ExpiryReport, RepositoryError> {
        let mut state = self.state.lock().await;
        let mut expired = Vec::new();
        for (task_id, task) in &mut state.tasks {
            if expired.len() == batch.limit().get() {
                break;
            }
            let snapshot = task.stored.snapshot().clone();
            if snapshot.state().is_terminal() || snapshot.expires_at() > batch.now() {
                continue;
            }
            let next = snapshot
                .transitioned(
                    snapshot.version(),
                    TaskTransition::Fail(TaskFailureCode::Expired),
                    batch.now(),
                )
                .map_err(|_| RepositoryError::Integrity)?;
            task.stored = StoredTask::new(next, task.stored.execution().clone());
            task.lease_claimed_at = None;
            expired.push(*task_id);
        }
        let saturated = expired.len() == batch.limit().get();
        Ok(ExpiryReport::new(expired, saturated))
    }
}

#[derive(Default)]
struct MemoryCancellation {
    state: Mutex<HashMap<(TaskId, TaskGeneration), Option<CancellationToken>>>,
}
impl MemoryCancellation {
    async fn was_signalled(&self, task_id: TaskId, generation: TaskGeneration) -> bool {
        self.state
            .lock()
            .await
            .get(&(task_id, generation))
            .is_some_and(|token| token.as_ref().is_none_or(CancellationToken::is_cancelled))
    }
}

#[async_trait]
impl CancellationRuntime for MemoryCancellation {
    async fn register(
        &self,
        task_id: TaskId,
        generation: TaskGeneration,
        cancellation: CancellationToken,
    ) -> Result<(), CancellationRuntimeError> {
        let mut state = self.state.lock().await;
        if state
            .insert((task_id, generation), Some(cancellation.clone()))
            .is_some_and(|token| token.is_none())
        {
            cancellation.cancel();
        }
        Ok(())
    }

    async fn signal(
        &self,
        task_id: TaskId,
        generation: TaskGeneration,
    ) -> Result<(), CancellationRuntimeError> {
        let mut state = self.state.lock().await;
        match state.get(&(task_id, generation)) {
            Some(Some(cancellation)) => cancellation.cancel(),
            Some(None) => {}
            None => {
                state.insert((task_id, generation), None);
            }
        }
        Ok(())
    }

    async fn release(&self, task_id: TaskId, generation: TaskGeneration) {
        self.state.lock().await.remove(&(task_id, generation));
    }
}

struct Harness {
    repository: Arc<MemoryRepository>,
    cancellation: Arc<MemoryCancellation>,
    clock: ManualClock,
    config: TaskConfig,
    principal: Principal,
}

impl Harness {
    fn new(ttl: Duration) -> Result<Self, Box<dyn Error>> {
        let tenant_id = TenantId::new();
        let principal = Principal::new(
            SubjectId::new(),
            PrincipalKind::User,
            Some(tenant_id),
            AuthMethod::Jwt,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal2,
            Vec::new(),
        )?;
        Ok(Self {
            repository: Arc::new(MemoryRepository::default()),
            cancellation: Arc::new(MemoryCancellation::default()),
            clock: ManualClock::new(),
            config: TaskConfig::new(ttl, Duration::from_millis(500), 32)?,
            principal,
        })
    }

    fn service(&self) -> TaskService<MemoryRepository, MemoryCancellation, ManualClock> {
        TaskService::new(
            Arc::clone(&self.repository),
            Arc::clone(&self.cancellation),
            self.clock.clone(),
            self.config,
        )
    }
    fn request_context(
        &self,
        requested_revision: Option<&str>,
        supported_revision: Option<&str>,
    ) -> Result<McpRequestContext, Box<dyn Error>> {
        let requested = requested_revision
            .map(task_extension)
            .transpose()?
            .into_iter();
        let supported = supported_revision
            .map(task_extension)
            .transpose()?
            .into_iter();
        let metadata = McpRequestMetadata::new(
            MCP_PROTOCOL_REVISION,
            McpClientIdentity::new("mcp-tasks-tests", "1")?,
            Vec::new(),
            requested,
            None,
        )?;
        let catalog = McpExtensionCatalog::new(supported)?;
        let invocation = InvocationContext::new(
            RequestId::new(),
            TraceContext::new(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
                None,
            ),
            self.principal.clone(),
            self.principal.tenant_id,
            Decision::Allow,
            "policy.mcp-tasks".parse()?,
            Self::budget_bounds()?,
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
            CancellationToken::new(),
        )?;
        let canonical = McpCanonicalContext::new(invocation, TenantMode::Tenant)?;
        Ok(McpRequestContext::new(metadata, &catalog, canonical))
    }

    fn context(&self) -> Result<McpRequestContext, Box<dyn Error>> {
        self.request_context(
            Some(TASKS_EXTENSION_REVISION),
            Some(TASKS_EXTENSION_REVISION),
        )
    }
    fn context_for(
        principal: Principal,
        tenant_mode: TenantMode,
    ) -> Result<McpRequestContext, Box<dyn Error>> {
        let extension = task_extension(TASKS_EXTENSION_REVISION)?;
        let metadata = McpRequestMetadata::new(
            MCP_PROTOCOL_REVISION,
            McpClientIdentity::new("mcp-tasks-tests", "1")?,
            Vec::new(),
            [extension.clone()],
            None,
        )?;
        let catalog = McpExtensionCatalog::new([extension])?;
        let tenant_id = principal.tenant_id;
        let invocation = InvocationContext::new(
            RequestId::new(),
            TraceContext::new(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
                None,
            ),
            principal,
            tenant_id,
            Decision::Allow,
            "policy.mcp-tasks".parse()?,
            Self::budget_bounds()?,
            OffsetDateTime::now_utc() + time::Duration::minutes(5),
            CancellationToken::new(),
        )?;
        let canonical = McpCanonicalContext::new(invocation, tenant_mode)?;
        Ok(McpRequestContext::new(metadata, &catalog, canonical))
    }

    fn budget_bounds() -> Result<BudgetBounds, Box<dyn Error>> {
        Ok(BudgetBounds::new(16_384, 16_384, 10_000)?)
    }

    fn command(key: &str, input: Value) -> Result<CreateTaskCommand, Box<dyn Error>> {
        let capability = CapabilityKey::new(
            CapabilityId::new("documents.summarize".to_owned())?,
            CapabilityVersion::new("1.2.3".to_owned())?,
        );
        let budget = TaskBudget::new(
            Self::budget_bounds()?,
            BudgetReservationRef::new("budget-reservation-1".to_owned())?,
        );
        let execution = TaskExecution::new(
            capability,
            TenantMode::Tenant,
            ConfirmationEvidence::NotRequiredByPolicy,
            input,
            IdempotencyKey::new(key.to_owned())?,
            budget,
        )?;
        Ok(CreateTaskCommand::new(execution)?)
    }

    async fn create(&self, key: &str) -> Result<TaskSnapshot, Box<dyn Error>> {
        let context = self.context()?;
        Ok(self
            .service()
            .create(
                &context,
                Harness::command(key, json!({"document_id": "doc-1"}))?,
            )
            .await?)
    }

    fn owner(&self) -> TaskOwner {
        TaskOwner::from_principal(&self.principal)
    }
}
fn task_extension(revision: &str) -> Result<McpExtension, Box<dyn Error>> {
    Ok(McpExtension::new(
        McpExtensionId::new(TASKS_EXTENSION_ID)?,
        McpExtensionRevision::new(revision)?,
    ))
}
fn canonical_result(value: Value) -> Result<CanonicalTaskResult, TaskValueError> {
    CanonicalTaskResult::from_tool_result(CanonicalToolResult::success(
        ToolRepresentation::structured_only(value),
    ))
}

fn input_round(number: u64, keys: &[&str]) -> Result<InputRound, Box<dyn Error>> {
    let mut exchanges = BTreeMap::new();
    for key in keys {
        exchanges.insert(
            InputKey::new((*key).to_owned())?,
            InputExchange::pending(json!({
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": "provide value",
                    "requestedSchema": {
                        "type": "object",
                        "properties": {"value": {"type": "string"}},
                        "required": ["value"]
                    }
                }
            }))?,
        );
    }
    Ok(InputRound::new(
        number,
        TaskRequestState::new(format!("round-state-{number}"))?,
        exchanges,
    )?)
}

async fn pause(
    harness: &Harness,
    snapshot: &TaskSnapshot,
    round: InputRound,
) -> Result<TaskSnapshot, Box<dyn Error>> {
    let claim = harness
        .repository
        .claim_execution(ExecutionClaim::new(
            snapshot.task_id(),
            snapshot.generation(),
            snapshot.current_job_id(),
            harness.clock.now_utc(),
        ))
        .await?;
    let ClaimOutcome::Leased(lease) = claim else {
        return Err("task was not leased".into());
    };
    let outcome = harness
        .repository
        .require_input(RequireInput::new(
            snapshot.task_id(),
            snapshot.generation(),
            lease.version(),
            lease.claimed_at(),
            snapshot.current_job_id(),
            round,
            harness.clock.now_utc(),
        ))
        .await?;
    let SettlementOutcome::Applied(snapshot) = outcome else {
        return Err("task did not enter input-required".into());
    };
    Ok(snapshot)
}

async fn lease(harness: &Harness, snapshot: &TaskSnapshot) -> Result<TaskLease, Box<dyn Error>> {
    let outcome = harness
        .repository
        .claim_execution(ExecutionClaim::new(
            snapshot.task_id(),
            snapshot.generation(),
            snapshot.current_job_id(),
            harness.clock.now_utc(),
        ))
        .await?;
    let ClaimOutcome::Leased(lease) = outcome else {
        return Err("task was not leased".into());
    };
    Ok(lease)
}

#[test]
fn advertisement_requires_exact_tasks_revision() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let disabled = harness.request_context(None, Some(TASKS_EXTENSION_REVISION))?;
    let mismatch = harness.request_context(Some("2026-07-27"), Some(TASKS_EXTENSION_REVISION))?;
    let enabled = harness.context()?;
    assert_eq!(advertised_task_methods(&disabled), &[]);
    assert_eq!(advertised_task_methods(&mismatch), &[]);
    assert_eq!(
        advertised_task_methods(&enabled),
        &[TaskMethod::Get, TaskMethod::Update, TaskMethod::Cancel]
    );
    assert_eq!(
        advertised_tasks_extension(&enabled).map(|extension| extension.revision().as_str()),
        Some(TASKS_EXTENSION_REVISION)
    );
    Ok(())
}

#[test]
fn list_and_result_methods_are_unsupported() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    assert_eq!(
        authorize_task_method(&context, "tasks/list"),
        Err(TaskServiceError::UnsupportedMethod)
    );
    assert_eq!(
        authorize_task_method(&context, "tasks/result"),
        Err(TaskServiceError::UnsupportedMethod)
    );
    Ok(())
}
#[tokio::test]
async fn mismatched_revision_create_has_no_durable_effect() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.request_context(Some("2026-07-27"), Some(TASKS_EXTENSION_REVISION))?;
    let result = harness
        .service()
        .create(
            &context,
            Harness::command("not-negotiated", json!({"document_id": "doc-1"}))?,
        )
        .await;
    assert!(matches!(result, Err(TaskServiceError::NotNegotiated)));
    assert_eq!(harness.repository.task_count().await, 0);
    assert_eq!(harness.repository.outbox_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn create_rolls_back_state_and_outbox_on_atomic_failure() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    harness.repository.fail_next_create();
    let result = harness
        .service()
        .create(
            &context,
            Harness::command("create-rollback", json!({"document_id": "doc-1"}))?,
        )
        .await;
    assert!(matches!(
        result,
        Err(TaskServiceError::Repository(RepositoryError::Unavailable))
    ));
    assert_eq!(harness.repository.task_count().await, 0);
    assert_eq!(harness.repository.outbox_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn create_is_idempotent_and_fingerprint_conflicts() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let first = harness
        .service()
        .create(
            &context,
            Harness::command("create-idempotent", json!({"document_id": "doc-1"}))?,
        )
        .await?;
    let replay = harness
        .service()
        .create(
            &context,
            Harness::command("create-idempotent", json!({"document_id": "doc-1"}))?,
        )
        .await?;
    let conflict = harness
        .service()
        .create(
            &context,
            Harness::command("create-idempotent", json!({"document_id": "doc-2"}))?,
        )
        .await;
    assert_eq!(replay.task_id(), first.task_id());
    assert_eq!(harness.repository.outbox_count().await, 1);
    assert!(matches!(
        conflict,
        Err(TaskServiceError::IdempotencyConflict)
    ));
    Ok(())
}

#[tokio::test]
async fn create_derives_owner_and_identity_only_from_request_context() -> Result<(), Box<dyn Error>>
{
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let request_id = context.canonical().invocation().request_id();
    let snapshot = harness
        .service()
        .create(
            &context,
            Harness::command("context-identity", json!({"document_id": "doc-1"}))?,
        )
        .await?;
    assert_eq!(
        snapshot.owner(),
        TaskOwner::from_principal(&harness.principal)
    );
    assert_eq!(snapshot.identity().request_id(), request_id);
    assert_eq!(
        snapshot.identity().correlation_id().as_uuid(),
        request_id.as_uuid()
    );
    assert_eq!(snapshot.identity().causation_id(), None);
    Ok(())
}

#[tokio::test]
async fn create_wire_is_flattened_and_immediately_resolvable_after_restart()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let adapter = RmcpTasksAdapter::new(harness.service());
    let created = adapter
        .create_for_tool_call(
            &context,
            Harness::command("wire-create", json!({"document_id": "doc-1"}))?,
        )
        .await?;
    let wire = serde_json::to_value(&created)?;
    let restarted = RmcpTasksAdapter::new(harness.service());
    let resolved = restarted
        .get(&context, GetTaskParams::new(created.task.task_id.clone()))
        .await?;
    assert_eq!(wire["resultType"], "task");
    assert!(wire.get("task").is_none());
    assert_eq!(resolved.task.task.task_id, created.task.task_id);
    Ok(())
}

#[tokio::test]
async fn completed_wire_preserves_canonical_result_and_status_shape() -> Result<(), Box<dyn Error>>
{
    let harness = Harness::new(Duration::from_secs(60))?;
    let working = harness.create("wire-completed").await?;
    let lease = lease(&harness, &working).await?;
    let canonical = canonical_result(json!({"message": "ok"}))?;
    let expected = Value::Object(canonical.as_map().clone());
    let outcome = harness
        .repository
        .settle_execution(SettleExecution::new(
            working.task_id(),
            working.generation(),
            lease.version(),
            lease.claimed_at(),
            working.current_job_id(),
            TerminalSettlement::Completed(canonical),
            harness.clock.now_utc(),
        ))
        .await?;
    assert!(matches!(outcome, SettlementOutcome::Applied(_)));
    let context = harness.context()?;
    let result = RmcpTasksAdapter::new(harness.service())
        .get(&context, GetTaskParams::new(working.task_id().to_string()))
        .await?;
    let wire = serde_json::to_value(result)?;
    assert_eq!(wire["status"], "completed");
    assert_eq!(wire["result"], expected);
    assert_eq!(wire["result"]["resultType"], "complete");
    assert!(wire.get("error").is_none());
    assert!(wire["ttlMs"].is_u64());
    Ok(())
}
#[tokio::test]
async fn input_required_wire_contains_only_current_outstanding_requests()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("wire-input").await?;
    let waiting = pause(
        &harness,
        &working,
        input_round(1, &["answered", "pending"])?,
    )
    .await?;
    harness
        .service()
        .update(
            &context,
            waiting.task_id(),
            InputResponses::new(BTreeMap::from([(
                "answered".to_owned(),
                json!({"action": "accept", "content": {"value": "done"}}),
            )]))?,
        )
        .await?;
    let result = RmcpTasksAdapter::new(harness.service())
        .get(&context, GetTaskParams::new(waiting.task_id().to_string()))
        .await?;
    let wire = serde_json::to_value(result)?;
    assert_eq!(wire["status"], "input_required");
    assert!(wire["inputRequests"].get("answered").is_none());
    assert!(wire["inputRequests"].get("pending").is_some());
    assert!(wire.get("result").is_none());
    assert!(wire.get("error").is_none());
    Ok(())
}

#[tokio::test]
async fn failed_and_cancelled_wire_payloads_are_mutually_exclusive() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let failed = harness.create("wire-failed").await?;
    let failed_lease = lease(&harness, &failed).await?;
    harness
        .repository
        .settle_execution(SettleExecution::new(
            failed.task_id(),
            failed.generation(),
            failed_lease.version(),
            failed_lease.claimed_at(),
            failed.current_job_id(),
            TerminalSettlement::Failed(TaskFailureCode::Indeterminate),
            harness.clock.now_utc(),
        ))
        .await?;
    let cancelled = harness.create("wire-cancelled").await?;
    harness
        .service()
        .cancel(&context, cancelled.task_id())
        .await?;
    let adapter = RmcpTasksAdapter::new(harness.service());
    let failed_wire = serde_json::to_value(
        adapter
            .get(&context, GetTaskParams::new(failed.task_id().to_string()))
            .await?,
    )?;
    let cancelled_wire = serde_json::to_value(
        adapter
            .get(
                &context,
                GetTaskParams::new(cancelled.task_id().to_string()),
            )
            .await?,
    )?;
    assert_eq!(failed_wire["status"], "failed");
    assert_eq!(failed_wire["error"]["code"], -32_603);
    assert_eq!(
        failed_wire["error"]["message"],
        "task outcome is indeterminate"
    );
    assert!(failed_wire.get("result").is_none());
    assert_eq!(cancelled_wire["status"], "cancelled");
    assert!(cancelled_wire.get("error").is_none());
    assert!(cancelled_wire.get("result").is_none());
    Ok(())
}

#[tokio::test]
async fn owner_scope_hides_task_existence_for_get_update_and_cancel() -> Result<(), Box<dyn Error>>
{
    let harness = Harness::new(Duration::from_secs(60))?;
    let snapshot = harness.create("owner-isolation").await?;
    let other_subject = Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        harness.principal.tenant_id,
        AuthMethod::Jwt,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal2,
        Vec::new(),
    )?;
    let other_tenant = Principal::new(
        harness.owner().subject_id(),
        PrincipalKind::User,
        Some(TenantId::new()),
        AuthMethod::Jwt,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal2,
        Vec::new(),
    )?;
    let tenantless = Principal::new(
        harness.owner().subject_id(),
        PrincipalKind::User,
        None,
        AuthMethod::Jwt,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal2,
        Vec::new(),
    )?;
    let other_subject = Harness::context_for(other_subject, TenantMode::Tenant)?;
    let other_tenant = Harness::context_for(other_tenant, TenantMode::Tenant)?;
    let tenantless = Harness::context_for(tenantless, TenantMode::Global)?;
    let service = harness.service();
    assert!(matches!(
        service.get(&other_tenant, snapshot.task_id()).await,
        Err(TaskServiceError::NotFound)
    ));
    assert!(matches!(
        service.get(&tenantless, snapshot.task_id()).await,
        Err(TaskServiceError::NotFound)
    ));
    assert!(matches!(
        service.get(&other_subject, snapshot.task_id()).await,
        Err(TaskServiceError::NotFound)
    ));
    let responses = InputResponses::new(BTreeMap::from([(
        "hidden".to_owned(),
        json!({"action": "accept"}),
    )]))?;
    assert_eq!(
        service
            .update(&other_subject, snapshot.task_id(), responses)
            .await,
        Err(TaskServiceError::NotFound)
    );
    assert_eq!(
        service.cancel(&other_subject, snapshot.task_id()).await,
        Err(TaskServiceError::NotFound)
    );
    Ok(())
}

#[tokio::test]
async fn input_updates_accept_current_keys_once_and_resume_once() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("input-round").await?;
    let waiting = pause(&harness, &working, input_round(1, &["first", "second"])?).await?;
    let unknown = InputResponses::new(BTreeMap::from([(
        "unknown".to_owned(),
        json!({"action": "accept", "content": {"value": "ignored"}}),
    )]))?;
    harness
        .service()
        .update(&context, waiting.task_id(), unknown)
        .await?;
    assert_eq!(harness.repository.outbox_count().await, 1);
    let first = InputResponses::new(BTreeMap::from([(
        "first".to_owned(),
        json!({"action": "accept", "content": {"value": "one"}}),
    )]))?;
    harness
        .service()
        .update(&context, waiting.task_id(), first.clone())
        .await?;
    harness
        .service()
        .update(&context, waiting.task_id(), first)
        .await?;
    let second = InputResponses::new(BTreeMap::from([(
        "second".to_owned(),
        json!({"action": "accept", "content": {"value": "two"}}),
    )]))?;
    harness
        .service()
        .update(&context, waiting.task_id(), second)
        .await?;
    let resumed = harness
        .repository
        .snapshot(waiting.task_id())
        .await
        .ok_or("missing")?;
    assert!(matches!(resumed.state(), TaskState::Working));
    assert_eq!(resumed.generation().get(), 2);
    assert_eq!(harness.repository.outbox_count().await, 2);
    Ok(())
}

#[tokio::test]
async fn racing_final_inputs_and_stale_old_keys_do_not_duplicate_resume()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("input-race").await?;
    let waiting = pause(&harness, &working, input_round(1, &["only"])?).await?;
    let response = InputResponses::new(BTreeMap::from([(
        "only".to_owned(),
        json!({"action": "accept", "content": {"value": "one"}}),
    )]))?;
    let service = harness.service();
    let first = service.update(&context, waiting.task_id(), response.clone());
    let second = service.update(&context, waiting.task_id(), response.clone());
    let (first, second) = tokio::join!(first, second);
    first?;
    second?;
    harness
        .service()
        .update(&context, waiting.task_id(), response)
        .await?;
    assert_eq!(harness.repository.outbox_count().await, 2);
    Ok(())
}

#[tokio::test]
async fn cancel_before_lease_is_terminal_and_after_completion_is_immutable()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let before = harness.create("cancel-before").await?;
    harness.service().cancel(&context, before.task_id()).await?;
    let cancelled = harness
        .repository
        .snapshot(before.task_id())
        .await
        .ok_or("missing")?;
    assert!(matches!(cancelled.state(), TaskState::Cancelled));

    let working = harness.create("cancel-after").await?;
    let lease = lease(&harness, &working).await?;
    harness
        .repository
        .settle_execution(SettleExecution::new(
            working.task_id(),
            working.generation(),
            lease.version(),
            lease.claimed_at(),
            working.current_job_id(),
            TerminalSettlement::Completed(canonical_result(json!({"ok": true}))?),
            harness.clock.now_utc(),
        ))
        .await?;
    harness
        .service()
        .cancel(&context, working.task_id())
        .await?;
    let completed = harness
        .repository
        .snapshot(working.task_id())
        .await
        .ok_or("missing")?;
    assert!(matches!(completed.state(), TaskState::Completed { .. }));
    Ok(())
}

#[tokio::test]
async fn cancel_during_lease_signals_token_and_allows_cancelled_settlement()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("cancel-during").await?;
    let lease = lease(&harness, &working).await?;
    let token = CancellationToken::new();
    harness
        .cancellation
        .register(working.task_id(), working.generation(), token.clone())
        .await?;
    harness
        .service()
        .cancel(&context, working.task_id())
        .await?;
    assert!(token.is_cancelled());
    let outcome = harness
        .repository
        .settle_execution(SettleExecution::new(
            working.task_id(),
            working.generation(),
            lease.version(),
            lease.claimed_at(),
            working.current_job_id(),
            TerminalSettlement::Cancelled,
            harness.clock.now_utc(),
        ))
        .await?;
    let SettlementOutcome::Applied(snapshot) = outcome else {
        return Err("cancelled settlement was fenced".into());
    };
    assert!(matches!(snapshot.state(), TaskState::Cancelled));
    Ok(())
}

#[tokio::test]
async fn cancellation_retries_against_generation_that_won_input_resume()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("cancel-resume-race").await?;
    let waiting = pause(&harness, &working, input_round(1, &["only"])?).await?;
    harness.repository.resume_before_next_cancel();
    harness
        .service()
        .cancel(&context, waiting.task_id())
        .await?;
    let cancelled = harness
        .repository
        .snapshot(waiting.task_id())
        .await
        .ok_or("missing")?;
    assert_eq!(cancelled.generation().get(), 2);
    assert!(matches!(cancelled.state(), TaskState::Working));
    assert!(cancelled.cancellation_requested());
    assert!(
        harness
            .cancellation
            .was_signalled(waiting.task_id(), cancelled.generation())
            .await
    );
    Ok(())
}

#[tokio::test]
async fn old_worker_generation_cannot_settle_after_input_resume() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let generation_one = harness.create("generation-fence").await?;
    let lease_one = lease(&harness, &generation_one).await?;
    let SettlementOutcome::Applied(waiting) = harness
        .repository
        .require_input(RequireInput::new(
            generation_one.task_id(),
            generation_one.generation(),
            lease_one.version(),
            lease_one.claimed_at(),
            generation_one.current_job_id(),
            input_round(1, &["only"])?,
            harness.clock.now_utc(),
        ))
        .await?
    else {
        return Err("input pause failed".into());
    };
    harness
        .service()
        .update(
            &context,
            waiting.task_id(),
            InputResponses::new(BTreeMap::from([(
                "only".to_owned(),
                json!({"action": "accept", "content": {"value": "done"}}),
            )]))?,
        )
        .await?;
    let stale = harness
        .repository
        .settle_execution(SettleExecution::new(
            generation_one.task_id(),
            generation_one.generation(),
            lease_one.version(),
            lease_one.claimed_at(),
            generation_one.current_job_id(),
            TerminalSettlement::Completed(canonical_result(Value::Null)?),
            harness.clock.now_utc(),
        ))
        .await?;
    assert!(matches!(stale, SettlementOutcome::Stale));
    Ok(())
}
#[tokio::test]
async fn abandoned_pre_effect_claim_can_be_retried() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let working = harness.create("abandon-retry").await?;
    let first = lease(&harness, &working).await?;
    let abandoned = harness
        .repository
        .abandon_execution(AbandonExecution::new(
            working.task_id(),
            working.generation(),
            first.version(),
            first.claimed_at(),
            working.current_job_id(),
            harness.clock.now_utc(),
        ))
        .await?;
    assert_eq!(abandoned, AbandonOutcome::Released);
    let retried = lease(&harness, &working).await?;
    assert_eq!(retried.version(), first.version());
    Ok(())
}

#[tokio::test]
async fn stale_attempt_cannot_settle_after_same_generation_reclaim() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let working = harness.create("lease-attempt-fence").await?;
    let first = lease(&harness, &working).await?;
    assert!(
        harness
            .repository
            .expire_active_lease(working.task_id())
            .await
    );
    let second = lease(&harness, &working).await?;
    assert_ne!(first.claimed_at(), second.claimed_at());

    let stale = harness
        .repository
        .settle_execution(SettleExecution::new(
            working.task_id(),
            working.generation(),
            first.version(),
            first.claimed_at(),
            working.current_job_id(),
            TerminalSettlement::Failed(TaskFailureCode::Indeterminate),
            harness.clock.now_utc(),
        ))
        .await?;
    assert!(matches!(stale, SettlementOutcome::Stale));

    let applied = harness
        .repository
        .settle_execution(SettleExecution::new(
            working.task_id(),
            working.generation(),
            second.version(),
            second.claimed_at(),
            working.current_job_id(),
            TerminalSettlement::Failed(TaskFailureCode::Indeterminate),
            harness.clock.now_utc(),
        ))
        .await?;
    assert!(matches!(applied, SettlementOutcome::Applied(_)));
    Ok(())
}

#[tokio::test]
async fn abandon_terminalizes_same_generation_cancellation_successor() -> Result<(), Box<dyn Error>>
{
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("abandon-cancel-successor").await?;
    let lease = lease(&harness, &working).await?;
    harness
        .service()
        .cancel(&context, working.task_id())
        .await?;
    let outcome = harness
        .repository
        .abandon_execution(AbandonExecution::new(
            working.task_id(),
            working.generation(),
            lease.version(),
            lease.claimed_at(),
            working.current_job_id(),
            harness.clock.now_utc(),
        ))
        .await?;
    assert_eq!(outcome, AbandonOutcome::Cancelled);
    let snapshot = harness
        .repository
        .snapshot(working.task_id())
        .await
        .ok_or("missing")?;
    assert!(matches!(snapshot.state(), TaskState::Cancelled));
    Ok(())
}

#[tokio::test]
async fn expiry_survives_service_restart_and_late_update_cannot_revive()
-> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(1))?;
    let context = harness.context()?;
    let working = harness.create("expiry").await?;
    let waiting = pause(&harness, &working, input_round(1, &["only"])?).await?;
    harness.clock.advance(Duration::from_secs(2));
    let report = TaskExpiryRunner::new(
        Arc::clone(&harness.repository),
        harness.clock.clone(),
        harness.config,
    )
    .run_once()
    .await?;
    assert_eq!(report.expired(), &[waiting.task_id()]);
    let restarted = harness.service();
    restarted
        .update(
            &context,
            waiting.task_id(),
            InputResponses::new(BTreeMap::from([(
                "only".to_owned(),
                json!({"action": "accept", "content": {"value": "late"}}),
            )]))?,
        )
        .await?;
    let expired = harness
        .repository
        .snapshot(waiting.task_id())
        .await
        .ok_or("missing")?;
    assert!(matches!(
        expired.state(),
        TaskState::Failed {
            failure: TaskFailureCode::Expired
        }
    ));
    Ok(())
}

#[test]
fn input_required_rejects_nonprotocol_worker_values_with_redacted_error() {
    let result = InputExchange::pending(json!({
        "secret": "sensitive-provider-output"
    }));
    let Err(error) = result else {
        panic!("nonprotocol input request was accepted");
    };
    assert_eq!(error, TaskValueError::Invalid);
    assert!(!format!("{error:?} {error}").contains("sensitive-provider-output"));
}

#[test]
fn canonical_result_projection_preserves_tool_error_and_input_required_algebra()
-> Result<(), Box<dyn Error>> {
    let tool_error = CanonicalTaskResult::from_tool_result(CanonicalToolResult::error(
        ToolFailure::new(ToolFailureCode::Rejected),
    ))?;
    assert_eq!(tool_error.as_map()["resultType"], "complete");
    assert_eq!(tool_error.as_map()["isError"], true);
    assert_eq!(
        tool_error.as_map()["content"][0]["text"],
        "tool request was rejected"
    );
    let request = CanonicalInputRequest::new(
        InputRequestId::new("approval")?,
        InputPrompt::new("Approve execution")?,
        JsonSchemaDocument::compile(json!({
            "type": "object",
            "properties": {"approved": {"type": "boolean"}},
            "required": ["approved"]
        }))?,
    );
    let input_required =
        InputRequiredToolResult::new(vec![request], RequestState::new("signed-state")?)?;
    let round = InputRound::from_tool_input_required(1, input_required.clone())?;
    assert_eq!(
        round.pending().next().map(|(key, _)| key.as_str()),
        Some("approval")
    );
    assert_eq!(round.request_state().as_str(), "signed-state");
    assert!(matches!(
        CanonicalTaskResult::from_tool_result(CanonicalToolResult::input_required(input_required)),
        Err(TaskValueError::Invalid)
    ));
    Ok(())
}

#[test]
fn canonical_result_rejects_unbounded_output_with_redacted_errors() {
    let secret = "sensitive-provider-output"
        .repeat(MAX_TASK_RESULT_BYTES / "sensitive-provider-output".len() + 1);
    let result = canonical_result(json!({"secret": secret}));
    let Err(error) = result else {
        panic!("oversized task result was accepted");
    };
    let rendered = format!("{error:?} {error}");
    assert_eq!(error, TaskValueError::TooLong);
    assert!(!rendered.contains("sensitive-provider-output"));
}

#[test]
fn canonical_result_deserialization_rejects_noncanonical_object_without_leaking_values() {
    let result = serde_json::from_value::<CanonicalTaskResult>(json!({
        "resultType": "complete",
        "isError": false,
        "content": [{"type": "text", "secret": "sensitive-provider-output"}]
    }));
    let Err(error) = result else {
        panic!("noncanonical task result was accepted");
    };
    assert!(!error.to_string().contains("sensitive-provider-output"));
}

#[test]
fn debug_output_redacts_input_responses_results_and_idempotency() -> Result<(), Box<dyn Error>> {
    let command = Harness::command(
        "secret-idempotency-key",
        json!({"credential": "secret-access-token"}),
    )?;
    let responses = InputResponses::new(BTreeMap::from([(
        "secret-key".to_owned(),
        json!({"credential": "secret-response-token"}),
    )]))?;
    let result = canonical_result(json!({"credential": "secret-result-token"}))?;
    let output = format!("{command:?} {responses:?} {result:?}");
    assert!(!output.contains("secret-access-token"));
    assert!(!output.contains("secret-response-token"));
    assert!(!output.contains("secret-result-token"));
    assert!(!output.contains("secret-idempotency-key"));
    Ok(())
}

#[tokio::test]
async fn rmcp_update_and_cancel_ack_are_empty_complete_results() -> Result<(), Box<dyn Error>> {
    let harness = Harness::new(Duration::from_secs(60))?;
    let context = harness.context()?;
    let working = harness.create("ack-wire").await?;
    let waiting = pause(&harness, &working, input_round(1, &["only"])?).await?;
    let adapter = RmcpTasksAdapter::new(harness.service());
    let update = adapter
        .update(
            &context,
            UpdateTaskParams::new(
                waiting.task_id().to_string(),
                BTreeMap::from([(
                    "only".to_owned(),
                    json!({"action": "accept", "content": {"value": "done"}}),
                )]),
            ),
        )
        .await?;
    let cancel = adapter
        .cancel(
            &context,
            CancelTaskParams::new(waiting.task_id().to_string()),
        )
        .await?;
    assert_eq!(
        serde_json::to_value(update)?,
        json!({"resultType": "complete"})
    );
    assert_eq!(
        serde_json::to_value(cancel)?,
        json!({"resultType": "complete"})
    );
    Ok(())
}
