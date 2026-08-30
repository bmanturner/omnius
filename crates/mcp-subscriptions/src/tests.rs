use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    BudgetBounds, DataPolicyRef, InvocationContext, TenantMode, TraceContext, TraceParent,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId as CanonicalTenantId,
};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use time::OffsetDateTime;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::*;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn task(value: &str) -> TaskId {
    TaskId::new(value).unwrap_or_else(|error| panic!("test task: {error}"))
}

fn position(sequence: u64) -> EventPosition {
    EventPosition::new(sequence, sequence).unwrap_or_else(|error| panic!("test position: {error}"))
}

fn snapshot(tenant_id: &TenantId, task_id: &TaskId, sequence: u64, message: &str) -> TaskSnapshot {
    TaskSnapshot::new(TaskSnapshotData {
        task_id: task_id.clone(),
        tenant_id: tenant_id.clone(),
        position: position(sequence),
        status: TaskStatus::Working,
        status_message: Some(
            ConfidentialStatusMessage::new(message)
                .unwrap_or_else(|error| panic!("test confidential message: {error}")),
        ),
        created_at_ms: 1,
        last_updated_at_ms: sequence,
        ttl_ms: 60_000,
    })
    .unwrap_or_else(|error| panic!("test snapshot: {error}"))
}
fn snapshot_at(
    tenant_id: &TenantId,
    task_id: &TaskId,
    event_position: EventPosition,
) -> TaskSnapshot {
    TaskSnapshot::new(TaskSnapshotData {
        task_id: task_id.clone(),
        tenant_id: tenant_id.clone(),
        position: event_position,
        status: TaskStatus::Working,
        status_message: None,
        created_at_ms: 1,
        last_updated_at_ms: event_position.sequence(),
        ttl_ms: 60_000,
    })
    .unwrap_or_else(|error| panic!("test snapshot position: {error}"))
}

struct CanonicalIdentity {
    principal: Principal,
    tenant_id: CanonicalTenantId,
    principal_id: PrincipalId,
    domain_tenant_id: TenantId,
}

impl CanonicalIdentity {
    fn new() -> Self {
        let tenant_id = CanonicalTenantId::new();
        let principal = Principal::new(
            SubjectId::new(),
            PrincipalKind::User,
            Some(tenant_id),
            AuthMethod::Session,
            OffsetDateTime::now_utc(),
            AssuranceLevel::Aal1,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test principal: {error}"));
        let principal_id = PrincipalId::new(principal.subject_id.to_string())
            .unwrap_or_else(|error| panic!("domain principal: {error}"));
        let domain_tenant_id = TenantId::new(tenant_id.to_string())
            .unwrap_or_else(|error| panic!("domain tenant: {error}"));
        Self {
            principal,
            tenant_id,
            principal_id,
            domain_tenant_id,
        }
    }

    fn in_same_tenant(other: &Self) -> Self {
        let tenant_id = other.tenant_id;
        let principal = Principal::new(
            SubjectId::new(),
            PrincipalKind::User,
            Some(tenant_id),
            AuthMethod::Session,
            OffsetDateTime::now_utc(),
            AssuranceLevel::Aal1,
            Vec::new(),
        )
        .unwrap_or_else(|error| panic!("test principal: {error}"));
        let principal_id = PrincipalId::new(principal.subject_id.to_string())
            .unwrap_or_else(|error| panic!("domain principal: {error}"));
        Self {
            principal,
            tenant_id,
            principal_id,
            domain_tenant_id: other.domain_tenant_id.clone(),
        }
    }
}

struct TestRequestContext {
    context: McpRequestContext,
    subscription_id: SubscriptionId,
}

fn extension(revision: &str) -> McpExtension {
    McpExtension::new(
        McpExtensionId::new(TASKS_EXTENSION_ID)
            .unwrap_or_else(|error| panic!("extension id: {error}")),
        McpExtensionRevision::new(revision)
            .unwrap_or_else(|error| panic!("extension revision: {error}")),
    )
}

fn request_context(revision: &str, identity: &CanonicalIdentity) -> TestRequestContext {
    let request_id = RequestId::new();
    let invocation = InvocationContext::new(
        request_id,
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse::<TraceParent>()
                .unwrap_or_else(|error| panic!("trace parent: {error}")),
            None,
        ),
        identity.principal.clone(),
        Some(identity.tenant_id),
        Decision::Allow,
        DataPolicyRef::new("mcp-tasks-test".to_owned())
            .unwrap_or_else(|error| panic!("data policy: {error}")),
        BudgetBounds::new(1_024, 1_024, 1_024).unwrap_or_else(|error| panic!("budget: {error}")),
        OffsetDateTime::now_utc() + time::Duration::minutes(5),
        CancellationToken::new(),
    )
    .unwrap_or_else(|error| panic!("invocation: {error}"));
    let canonical = McpCanonicalContext::new(invocation, TenantMode::Tenant)
        .unwrap_or_else(|error| panic!("canonical context: {error}"));
    let requested = extension(revision);
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("test-client", "1.0.0")
            .unwrap_or_else(|error| panic!("client: {error}")),
        Vec::new(),
        [requested],
        None,
    )
    .unwrap_or_else(|error| panic!("metadata: {error}"));
    let catalog = McpExtensionCatalog::new([extension(TASKS_EXTENSION_REVISION)])
        .unwrap_or_else(|error| panic!("catalog: {error}"));
    let context = McpRequestContext::new(metadata, &catalog, canonical);
    let subscription_id = SubscriptionId::new(request_id.to_string())
        .unwrap_or_else(|error| panic!("subscription id: {error}"));
    TestRequestContext {
        context,
        subscription_id,
    }
}

fn request(task_id: &TaskId) -> SubscribeRequest {
    SubscribeRequest {
        task_ids: vec![task_id.clone()],
        event_classes: vec![RequestedEventClass::TaskSnapshots],
        ttl_ms: 10_000,
        start: SubscriptionStart::Initial {
            idempotency_key: None,
        },
    }
}

#[derive(Clone, Debug)]
struct HandleBinding {
    principal_id: PrincipalId,
    tenant_id: TenantId,
    task_ids: BTreeSet<TaskId>,
    cursors: BTreeMap<TaskId, EventPosition>,
    idempotency_key: Option<IdempotencyKey>,
    closed: bool,
}

#[derive(Clone, Debug)]
struct TaskHandleBinding {
    principal: PrincipalId,
    tenant: TenantId,
    task: TaskId,
}

#[derive(Debug, Default)]
struct RepositoryState {
    histories: HashMap<(TenantId, TaskId), Vec<TaskSnapshot>>,
    used: HashSet<SubscriptionId>,
    handles: HashMap<SubscriptionHandle, HandleBinding>,
    task_handles: HashMap<TaskHandle, TaskHandleBinding>,
    next_handle: u64,
    finish_count: usize,
    finish_failures_remaining: usize,
    finish_terminal_error: Option<RepositoryError>,
    replay_count: usize,
}

#[derive(Debug, Default)]
struct TestRepository {
    state: Mutex<RepositoryState>,
}

impl TestRepository {
    fn replace_history(&self, tenant_id: &TenantId, task_id: &TaskId, events: Vec<TaskSnapshot>) {
        lock(&self.state)
            .histories
            .insert((tenant_id.clone(), task_id.clone()), events);
    }

    fn append(&self, event: TaskSnapshot) {
        lock(&self.state)
            .histories
            .entry((event.tenant_id().clone(), event.task_id().clone()))
            .or_default()
            .push(event);
    }

    fn fail_finishes(&self, failures: usize) {
        lock(&self.state).finish_failures_remaining = failures;
    }

    fn fail_finish_terminally(&self, error: RepositoryError) {
        lock(&self.state).finish_terminal_error = Some(error);
    }

    fn has_checkpoint(&self, task_id: &TaskId, expected: EventPosition) -> bool {
        lock(&self.state)
            .handles
            .values()
            .any(|binding| binding.cursors.get(task_id).copied() == Some(expected))
    }

    fn replay_count(&self) -> usize {
        lock(&self.state).replay_count
    }

    fn bind_task_handle(&self, identity: &CanonicalIdentity, task_id: &TaskId) -> TaskHandle {
        let handle = TaskHandle::new(format!("task-handle-{}", task_id.as_str()))
            .unwrap_or_else(|error| panic!("task handle: {error}"));
        lock(&self.state).task_handles.insert(
            handle.clone(),
            TaskHandleBinding {
                principal: identity.principal_id.clone(),
                tenant: identity.domain_tenant_id.clone(),
                task: task_id.clone(),
            },
        );
        handle
    }

    fn finish_count(&self) -> usize {
        lock(&self.state).finish_count
    }
}

#[async_trait]
impl SubscriptionRepository for TestRepository {
    async fn begin(
        &self,
        begin: &BeginSubscription,
    ) -> Result<BeginSubscriptionResult, RepositoryError> {
        let mut state = lock(&self.state);
        if state.used.contains(&begin.subscription_id) {
            return Err(RepositoryError::IdentifierReused);
        }
        let requested_tasks = begin.task_ids.iter().cloned().collect::<BTreeSet<_>>();
        let (cursors, idempotency_key, consumed_proof) = match &begin.start {
            SubscriptionStart::Initial { idempotency_key } => {
                let conflicts_with_prior_claim = state.handles.values().any(|binding| {
                    binding.principal_id == begin.principal_id
                        && binding.tenant_id == begin.tenant_id
                        && binding.task_ids == requested_tasks
                        && (binding.closed
                            || idempotency_key
                                .as_ref()
                                .is_some_and(|key| binding.idempotency_key.as_ref() == Some(key)))
                });
                if conflicts_with_prior_claim {
                    return Err(RepositoryError::InvalidReconnect);
                }
                (BTreeMap::new(), idempotency_key.clone(), None)
            }
            SubscriptionStart::Replacement(ReconnectProof::Idempotency(key)) => {
                let (handle, binding) = state
                    .handles
                    .iter()
                    .find(|(_, binding)| {
                        binding.closed
                            && binding.principal_id == begin.principal_id
                            && binding.tenant_id == begin.tenant_id
                            && binding.task_ids == requested_tasks
                            && binding.idempotency_key.as_ref() == Some(key)
                    })
                    .map(|(handle, binding)| (handle.clone(), binding.clone()))
                    .ok_or(RepositoryError::InvalidReconnect)?;
                (binding.cursors, Some(key.clone()), Some(handle))
            }
            SubscriptionStart::Replacement(ReconnectProof::Tasks(handles)) => {
                let mut proven_tasks = BTreeSet::new();
                for handle in handles.as_slice() {
                    let binding = state
                        .task_handles
                        .get(handle)
                        .ok_or(RepositoryError::InvalidReconnect)?;
                    if binding.principal != begin.principal_id || binding.tenant != begin.tenant_id
                    {
                        return Err(RepositoryError::InvalidReconnect);
                    }
                    proven_tasks.insert(binding.task.clone());
                }
                if proven_tasks != requested_tasks {
                    return Err(RepositoryError::InvalidReconnect);
                }
                let replaces_closed_stream = state.handles.values().any(|binding| {
                    binding.closed
                        && binding.principal_id == begin.principal_id
                        && binding.tenant_id == begin.tenant_id
                        && binding.task_ids == requested_tasks
                });
                if !replaces_closed_stream {
                    return Err(RepositoryError::InvalidReconnect);
                }
                (BTreeMap::new(), None, None)
            }
        };
        state.used.insert(begin.subscription_id.clone());
        state.next_handle = state.next_handle.saturating_add(1);
        let handle = SubscriptionHandle::new(format!("handle-{}", state.next_handle))
            .map_err(|_| RepositoryError::Inconsistent)?;
        if let Some(consumed) = consumed_proof {
            state
                .handles
                .get_mut(&consumed)
                .ok_or(RepositoryError::Inconsistent)?
                .idempotency_key = None;
        }
        state.handles.insert(
            handle.clone(),
            HandleBinding {
                principal_id: begin.principal_id.clone(),
                tenant_id: begin.tenant_id.clone(),
                task_ids: requested_tasks,
                cursors: cursors.clone(),
                idempotency_key,
                closed: false,
            },
        );
        Ok(BeginSubscriptionResult {
            subscription_handle: handle,
            resume_cursors: cursors
                .into_iter()
                .map(|(task_id, position)| TaskCursor { task_id, position })
                .collect(),
        })
    }

    async fn current_snapshot(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
    ) -> Result<Option<TaskSnapshot>, RepositoryError> {
        Ok(lock(&self.state)
            .histories
            .get(&(tenant_id.clone(), task_id.clone()))
            .and_then(|events| events.last().cloned()))
    }

    async fn replay_after(
        &self,
        tenant_id: &TenantId,
        task_id: &TaskId,
        after: EventPosition,
        limit: usize,
    ) -> Result<ReplayResult, RepositoryError> {
        let mut state = lock(&self.state);
        state.replay_count = state.replay_count.saturating_add(1);
        let events = state
            .histories
            .get(&(tenant_id.clone(), task_id.clone()))
            .ok_or(RepositoryError::Inconsistent)?;
        let Some(oldest) = events.first() else {
            return Ok(ReplayResult::Events {
                snapshots: Vec::new(),
                has_more: false,
            });
        };
        let newest = events
            .last()
            .map(TaskSnapshot::position)
            .ok_or(RepositoryError::Inconsistent)?;
        if oldest.position().sequence() > after.sequence().saturating_add(1) {
            return Ok(ReplayResult::Gap(ReplayWindow {
                oldest_available: oldest.position(),
                newest_available: newest,
            }));
        }
        let available = events
            .iter()
            .filter(|event| event.position().sequence() > after.sequence())
            .count();
        Ok(ReplayResult::Events {
            snapshots: events
                .iter()
                .filter(|event| event.position().sequence() > after.sequence())
                .take(limit)
                .cloned()
                .collect(),
            has_more: available > limit,
        })
    }

    async fn checkpoint(&self, checkpoint: &SubscriptionCheckpoint) -> Result<(), RepositoryError> {
        let mut state = lock(&self.state);
        let binding = state
            .handles
            .get_mut(&checkpoint.subscription_handle)
            .ok_or(RepositoryError::Inconsistent)?;
        if !binding.task_ids.contains(&checkpoint.cursor.task_id)
            || binding
                .cursors
                .get(&checkpoint.cursor.task_id)
                .is_some_and(|position| *position >= checkpoint.cursor.position)
        {
            return Err(RepositoryError::Inconsistent);
        }
        binding.cursors.insert(
            checkpoint.cursor.task_id.clone(),
            checkpoint.cursor.position,
        );
        Ok(())
    }

    async fn finish(&self, finish: &FinishSubscription) -> Result<(), RepositoryError> {
        let mut state = lock(&self.state);
        state.finish_count = state.finish_count.saturating_add(1);
        if state.finish_failures_remaining > 0 {
            state.finish_failures_remaining -= 1;
            return Err(RepositoryError::Unavailable);
        }
        if let Some(error) = state.finish_terminal_error {
            return Err(error);
        }
        let binding = state
            .handles
            .get_mut(&finish.subscription_handle)
            .ok_or(RepositoryError::Inconsistent)?;
        for cursor in &finish.cursors {
            if !binding.task_ids.contains(&cursor.task_id) {
                return Err(RepositoryError::Inconsistent);
            }
            if binding
                .cursors
                .get(&cursor.task_id)
                .is_none_or(|position| *position <= cursor.position)
            {
                binding
                    .cursors
                    .insert(cursor.task_id.clone(), cursor.position);
            }
        }
        binding.closed = true;
        Ok(())
    }
}

#[derive(Debug, Default)]
struct TestAuthorizer {
    allowed: Mutex<HashSet<(PrincipalId, TenantId, TaskId)>>,
    gate: Mutex<Option<Arc<Semaphore>>>,
    calls: AtomicUsize,
}

impl TestAuthorizer {
    fn allow(&self, identity: &CanonicalIdentity, task_id: &TaskId) {
        lock(&self.allowed).insert((
            identity.principal_id.clone(),
            identity.domain_tenant_id.clone(),
            task_id.clone(),
        ));
    }

    fn revoke(&self, identity: &CanonicalIdentity, task_id: &TaskId) {
        lock(&self.allowed).remove(&(
            identity.principal_id.clone(),
            identity.domain_tenant_id.clone(),
            task_id.clone(),
        ));
    }

    fn block(&self) -> Arc<Semaphore> {
        let gate = Arc::new(Semaphore::new(0));
        *lock(&self.gate) = Some(Arc::clone(&gate));
        gate
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

#[async_trait]
impl SubscriptionAuthorizer for TestAuthorizer {
    async fn authorize(&self, check: &AuthorizationCheck) -> Result<bool, AuthorizationError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        let gate = lock(&self.gate).clone();
        if let Some(gate) = gate {
            let _permit = gate
                .acquire_owned()
                .await
                .map_err(|_| AuthorizationError::Unavailable)?;
        }
        Ok(lock(&self.allowed).contains(&(
            check.principal_id.clone(),
            check.tenant_id.clone(),
            check.task_id.clone(),
        )))
    }
}

#[derive(Debug)]
struct TestRuntime {
    leases: Mutex<HashMap<SubscriptionId, (u64, DeliveryDisconnectSignal)>>,
    now_ms: Mutex<u64>,
    clock_available: AtomicBool,
}

impl Default for TestRuntime {
    fn default() -> Self {
        Self {
            leases: Mutex::new(HashMap::new()),
            now_ms: Mutex::new(1_000),
            clock_available: AtomicBool::new(true),
        }
    }
}

impl TestRuntime {
    fn disconnect_signal(&self, subscription_id: &SubscriptionId) -> DeliveryDisconnectSignal {
        lock(&self.leases).get(subscription_id).map_or_else(
            || panic!("missing runtime lease"),
            |(_, signal)| signal.clone(),
        )
    }

    fn is_armed(&self, subscription_id: &SubscriptionId) -> bool {
        lock(&self.leases).contains_key(subscription_id)
    }

    fn fail_clock(&self) {
        self.clock_available.store(false, Ordering::Release);
    }
}

#[async_trait]
impl SubscriptionRuntime for TestRuntime {
    async fn arm(&self, lease: &RuntimeLease) -> Result<(), RuntimeError> {
        lock(&self.leases).insert(
            lease.subscription_id.clone(),
            (lease.expires_at_ms, lease.disconnect.clone()),
        );
        Ok(())
    }

    async fn now_ms(&self) -> Result<u64, RuntimeError> {
        if !self.clock_available.load(Ordering::Acquire) {
            return Err(RuntimeError::Unavailable);
        }
        Ok(*lock(&self.now_ms))
    }

    async fn disarm(&self, subscription_id: &SubscriptionId) -> Result<(), RuntimeError> {
        lock(&self.leases).remove(subscription_id);
        Ok(())
    }
}

#[derive(Debug)]
struct AttachedQueue {
    limits: DeliveryLimits,
    frames: Vec<DeliveryFrame>,
    retained_bytes: usize,
}

#[derive(Debug, Default)]
struct AttachedTestDelivery {
    queues: Mutex<HashMap<SubscriptionId, AttachedQueue>>,
}

impl AttachedTestDelivery {
    fn frames(&self, subscription_id: &SubscriptionId) -> Vec<DeliveryFrame> {
        lock(&self.queues)
            .get(subscription_id)
            .map_or_else(Vec::new, |queue| queue.frames.clone())
    }
}

#[async_trait]
impl SubscriptionDelivery for AttachedTestDelivery {
    async fn open(
        &self,
        subscription_id: &SubscriptionId,
        limits: DeliveryLimits,
    ) -> Result<DeliveryOpen, DeliveryError> {
        let mut queues = lock(&self.queues);
        if queues.contains_key(subscription_id) {
            return Err(DeliveryError::AlreadyOpen);
        }
        queues.insert(
            subscription_id.clone(),
            AttachedQueue {
                limits,
                frames: Vec::new(),
                retained_bytes: 0,
            },
        );
        Ok(DeliveryOpen::attached(DeliveryDisconnectSignal::new()))
    }

    async fn deliver(
        &self,
        subscription_id: &SubscriptionId,
        frame: DeliveryFrame,
    ) -> Result<DeliveryAdmission, DeliveryError> {
        let mut queues = lock(&self.queues);
        let Some(queue) = queues.get_mut(subscription_id) else {
            return Ok(DeliveryAdmission::Disconnected);
        };
        let encoded_len = frame.encoded_len();
        let retained_bytes = queue.retained_bytes.saturating_add(encoded_len);
        if queue.frames.len() >= queue.limits.max_frames || retained_bytes > queue.limits.max_bytes
        {
            return Ok(DeliveryAdmission::SlowConsumer);
        }
        queue.retained_bytes = retained_bytes;
        queue.frames.push(frame);
        Ok(DeliveryAdmission::Accepted)
    }

    async fn close(
        &self,
        subscription_id: &SubscriptionId,
        _mode: DeliveryCloseMode,
        _close: DeliveryFrame,
    ) -> Result<DrainOutcome, DeliveryError> {
        if lock(&self.queues).remove(subscription_id).is_some() {
            Ok(DrainOutcome::Drained)
        } else {
            Ok(DrainOutcome::Disconnected)
        }
    }
}

#[derive(Debug)]
struct FakeBackplane {
    ready: Arc<AtomicBool>,
}

#[async_trait]
impl TaskSubscriptionBackplane for FakeBackplane {
    fn kind(&self) -> BackplaneKind {
        BackplaneKind::Local
    }

    fn guarantee(&self) -> BackplaneGuarantee {
        BackplaneGuarantee::Ephemeral
    }

    fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    async fn publish(&self, _hint: BackplaneHint) -> Result<(), BackplaneError> {
        if self.is_ready() {
            Ok(())
        } else {
            Err(BackplaneError::NotReady)
        }
    }
}

struct FakeReceiver {
    records: mpsc::Receiver<Result<BackplaneRecord, BackplaneError>>,
}

#[async_trait]
impl BackplaneReceiver for FakeReceiver {
    async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError> {
        self.records
            .recv()
            .await
            .unwrap_or(Err(BackplaneError::Disconnected))
    }
}

struct Fixture {
    repository: Arc<TestRepository>,
    authorizer: Arc<TestAuthorizer>,
    runtime: Arc<TestRuntime>,
    delivery: Arc<BoundedDeliveryQueue>,
    service: TaskSubscriptionService,
    selected: SelectedBackplane,
    records: mpsc::Sender<Result<BackplaneRecord, BackplaneError>>,
    receiver: Option<SelectedBackplaneReceiver>,
    cancellation: CancellationToken,
}

impl Fixture {
    async fn start_receiver(&mut self) {
        let receiver = self
            .receiver
            .take()
            .unwrap_or_else(|| panic!("receiver already consumed"));
        let service = self.service.clone();
        let cancellation = self.cancellation.clone();
        tokio::spawn(async move {
            let _ = service.run_backplane(receiver, &cancellation).await;
        });
        for _ in 0..32 {
            if self.selected.is_ready() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("test receiver did not become ready");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

fn fixture(config: SubscriptionConfig) -> Fixture {
    let repository = Arc::new(TestRepository::default());
    let authorizer = Arc::new(TestAuthorizer::default());
    let runtime = Arc::new(TestRuntime::default());
    let delivery = Arc::new(BoundedDeliveryQueue::default());
    let ready = Arc::new(AtomicBool::new(true));
    let provider = Arc::new(FakeBackplane { ready });
    let (records, receiver) = mpsc::channel(8);
    let registration =
        BackplaneRegistration::new(provider, Box::new(FakeReceiver { records: receiver }));
    let parts = SelectedBackplane::exactly_one([registration])
        .unwrap_or_else(|error| panic!("selected backplane: {error}"));
    let selected = parts.backplane.clone();
    let service = TaskSubscriptionService::new(
        config,
        repository.clone(),
        authorizer.clone(),
        runtime.clone(),
        delivery.clone(),
        parts.backplane,
    )
    .unwrap_or_else(|error| panic!("test service: {error}"));
    Fixture {
        repository,
        authorizer,
        runtime,
        delivery,
        service,
        selected,
        records,
        receiver: Some(parts.receiver),
        cancellation: CancellationToken::new(),
    }
}

async fn started_fixture(config: SubscriptionConfig) -> Fixture {
    let mut fixture = fixture(config);
    fixture.start_receiver().await;
    fixture
}

async fn next_frame(stream: &mut DeliveryStream) -> DeliveryFrame {
    tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .unwrap_or_else(|error| panic!("test frame timeout: {error}"))
        .unwrap_or_else(|| panic!("test stream closed"))
}
async fn wait_until_disarmed(runtime: &TestRuntime, subscription_id: &SubscriptionId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while runtime.is_armed(subscription_id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "subscription was not disarmed"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn wait_until_checkpointed(
    repository: &TestRepository,
    task_id: &TaskId,
    expected: EventPosition,
) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while !repository.has_checkpoint(task_id, expected) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "subscription checkpoint did not advance"
        );
        tokio::task::yield_now().await;
    }
}

async fn wait_until_replayed(repository: &TestRepository, minimum_calls: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while repository.replay_count() < minimum_calls {
        assert!(
            tokio::time::Instant::now() < deadline,
            "subscription replay did not run"
        );
        tokio::task::yield_now().await;
    }
}

async fn wait_until_authorized(authorizer: &TestAuthorizer, minimum_calls: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    while authorizer.calls() < minimum_calls {
        assert!(
            tokio::time::Instant::now() < deadline,
            "authorization was not reached"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn exact_tasks_revision_is_required_per_request() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let context = request_context("2026-07-27", &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);

    let result = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await;

    assert_eq!(result, Err(SubscriptionError::NotNegotiated));
    assert_eq!(fixture.repository.finish_count(), 0);
}

#[tokio::test]
async fn admission_requires_running_sole_receiver() {
    let mut fixture = fixture(SubscriptionConfig::default());
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );

    assert_eq!(
        fixture
            .service
            .subscribe(&context.context, request(&task_id))
            .await,
        Err(SubscriptionError::BackplaneUnavailable)
    );
    fixture.start_receiver().await;
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe after readiness: {error}"));
    assert_eq!(lease.subscription_id, context.subscription_id);
}

#[test]
fn selection_and_local_receiver_are_exactly_one() {
    assert!(matches!(
        SelectedBackplane::exactly_one(Vec::<BackplaneRegistration>::new()),
        Err(BackplaneSelectionError::NoneSelected)
    ));
    let first =
        LocalTaskBackplane::registration(1).unwrap_or_else(|error| panic!("first local: {error}"));
    let second =
        LocalTaskBackplane::registration(1).unwrap_or_else(|error| panic!("second local: {error}"));
    assert!(matches!(
        SelectedBackplane::exactly_one([first, second]),
        Err(BackplaneSelectionError::MultipleSelected)
    ));
}

#[test]
fn provider_wire_records_are_strict_and_reconciliation_safe() {
    let limits = BackplaneWireLimits {
        max_record_bytes: 256,
    };
    let valid =
        br#"{"version":1,"tenantId":"tenant-a","taskId":"task-a","sequence":2,"revision":2}"#;
    assert!(matches!(
        crate::backplane::decode_nats_record(valid, limits),
        BackplaneRecord::TaskChanged(_)
    ));
    assert_eq!(
        crate::backplane::decode_nats_record(br#"{"version":1}"#, limits),
        BackplaneRecord::IngressGap
    );
    assert_eq!(
        crate::backplane::decode_nats_record(&vec![b'x'; 257], limits),
        BackplaneRecord::IngressGap
    );
    assert_eq!(
        crate::backplane::decode_redis_record("tasks", "other", valid, limits),
        Err(BackplaneError::InvalidRecord)
    );
    assert_eq!(
        crate::backplane::decode_redis_record(
            "tasks",
            "tasks",
            br#"{"version":1,"tenantId":"tenant-a","taskId":"task-a","sequence":2,"revision":2,"extra":true}"#,
            limits,
        ),
        Ok(BackplaneRecord::IngressGap)
    );
    assert_eq!(
        crate::backplane::redis_ingress_record(
            omnius_events_redis_ephemeral::RedisEphemeralIngress::IngressGap { loss_generation: 1 },
            "tasks",
            limits,
        ),
        Ok(BackplaneRecord::IngressGap)
    );
    assert_eq!(
        crate::backplane::nats_ingress_record(
            omnius_events_nats::NatsCoreFanoutIngress::IngressGap { loss_generation: 1 },
            limits,
        ),
        BackplaneRecord::IngressGap
    );
}

#[tokio::test]
async fn local_lag_becomes_reconciliation_gap() {
    let registration = LocalTaskBackplane::registration(1)
        .unwrap_or_else(|error| panic!("local backplane: {error}"));
    let parts = SelectedBackplane::exactly_one([registration])
        .unwrap_or_else(|error| panic!("selection: {error}"));
    let mut receiver = parts.receiver;
    receiver
        .start()
        .unwrap_or_else(|error| panic!("start receiver: {error}"));
    let tenant_id = TenantId::new("tenant-a").unwrap_or_else(|error| panic!("tenant: {error}"));
    let task_id = task("task-a");
    for sequence in 1..=2 {
        parts
            .backplane
            .publish(BackplaneHint {
                tenant_id: tenant_id.clone(),
                task_id: task_id.clone(),
                observed_position: position(sequence),
            })
            .await
            .unwrap_or_else(|error| panic!("publish: {error}"));
    }
    assert_eq!(
        receiver
            .receive()
            .await
            .unwrap_or_else(|error| panic!("receive: {error}")),
        BackplaneRecord::IngressGap
    );
}

#[tokio::test]
async fn acknowledgement_is_first_and_every_frame_is_correlated() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));

    let acknowledgement = next_frame(&mut stream).await;
    assert!(matches!(acknowledgement, DeliveryFrame::Acknowledged(_)));
    assert_eq!(acknowledgement.subscription_id(), &context.subscription_id);
    let snapshot_frame = next_frame(&mut stream).await;
    assert_eq!(snapshot_frame.subscription_id(), &context.subscription_id);
    assert!(matches!(
        snapshot_frame,
        DeliveryFrame::TaskSnapshot { snapshot, .. }
            if snapshot.task_id() == &task_id && snapshot.position() == position(1)
    ));
}

#[tokio::test]
async fn ingress_gap_reconciles_authoritative_current_state() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    fixture.repository.append(snapshot(
        &identity.domain_tenant_id,
        &task_id,
        2,
        "step 2 of 3",
    ));
    fixture
        .records
        .send(Ok(BackplaneRecord::IngressGap))
        .await
        .unwrap_or_else(|error| panic!("gap send: {error}"));

    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::TaskSnapshot { snapshot, .. } if snapshot.position() == position(2)
    ));
}

#[tokio::test]
async fn cross_tenant_and_revoked_delivery_authorization_fail_closed() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let other = CanonicalIdentity::new();
    let other_context = request_context(TASKS_EXTENSION_REVISION, &other);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    assert_eq!(
        fixture
            .service
            .subscribe(&other_context.context, request(&task_id))
            .await,
        Err(SubscriptionError::Unauthorized)
    );

    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    fixture.authorizer.revoke(&identity, &task_id);
    fixture
        .repository
        .append(snapshot(&identity.domain_tenant_id, &task_id, 2, "working"));
    fixture
        .records
        .send(Ok(BackplaneRecord::TaskChanged(BackplaneHint {
            tenant_id: identity.domain_tenant_id.clone(),
            task_id: task_id.clone(),
            observed_position: position(2),
        })))
        .await
        .unwrap_or_else(|error| panic!("hint send: {error}"));

    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::AuthorizationRevoked,
            cursors,
            ..
        }) if cursors == vec![TaskCursor { task_id, position: position(1) }]
    ));
}

#[tokio::test]
async fn sequence_and_revision_must_both_advance() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    fixture.repository.append(snapshot_at(
        &identity.domain_tenant_id,
        &task_id,
        EventPosition::new(2, 1).unwrap_or_else(|error| panic!("non-advancing revision: {error}")),
    ));
    fixture
        .records
        .send(Ok(BackplaneRecord::TaskChanged(BackplaneHint {
            tenant_id: identity.domain_tenant_id,
            task_id: task_id.clone(),
            observed_position: position(2),
        })))
        .await
        .unwrap_or_else(|error| panic!("hint send: {error}"));

    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::Failed,
            cursors,
            ..
        }) if cursors == vec![TaskCursor { task_id, position: position(1) }]
    ));
}

#[tokio::test]
async fn idle_stream_drop_signals_authoritative_cleanup_and_releases_capacity() {
    let fixture = started_fixture(SubscriptionConfig {
        max_active_subscriptions: 1,
        ..SubscriptionConfig::default()
    })
    .await;
    let first_identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &first_identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&first_identity, &task_id);
    fixture.repository.replace_history(
        &first_identity.domain_tenant_id,
        &task_id,
        vec![snapshot(
            &first_identity.domain_tenant_id,
            &task_id,
            1,
            "working",
        )],
    );
    let lease = fixture
        .service
        .subscribe(&first_context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let signal = fixture.runtime.disconnect_signal(&lease.subscription_id);
    let stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    drop(stream);
    assert!(signal.is_cancelled());
    let _ = fixture
        .service
        .disconnect(&lease.subscription_id, 1_001)
        .await;
    assert!(!fixture.runtime.is_armed(&lease.subscription_id));
    assert_eq!(fixture.repository.finish_count(), 1);

    let second_identity = CanonicalIdentity::new();
    let second_context = request_context(TASKS_EXTENSION_REVISION, &second_identity);
    fixture.authorizer.allow(&second_identity, &task_id);
    fixture.repository.replace_history(
        &second_identity.domain_tenant_id,
        &task_id,
        vec![snapshot(
            &second_identity.domain_tenant_id,
            &task_id,
            1,
            "working",
        )],
    );
    fixture
        .service
        .subscribe(&second_context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("capacity was not released: {error}"));
}

#[tokio::test]
async fn reconnect_uses_new_request_id_and_replays_from_authoritative_cursor() {
    assert_eq!(IdempotencyKey::new(""), Err(ValueError::Empty));
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let idempotency_key = IdempotencyKey::new("task-a-subscription")
        .unwrap_or_else(|error| panic!("idempotency key: {error}"));
    let mut first_request = request(&task_id);
    first_request.start = SubscriptionStart::Initial {
        idempotency_key: Some(idempotency_key.clone()),
    };
    let first = fixture
        .service
        .subscribe(&first_context.context, first_request)
        .await
        .unwrap_or_else(|error| panic!("first subscribe: {error}"));
    let mut first_stream = fixture
        .delivery
        .take_stream(&first.subscription_id)
        .unwrap_or_else(|error| panic!("first stream: {error}"));
    let _ = next_frame(&mut first_stream).await;
    let _ = next_frame(&mut first_stream).await;
    let _ = fixture
        .service
        .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false)
        .await;
    let _ = next_frame(&mut first_stream).await;

    fixture.repository.append(snapshot(
        &identity.domain_tenant_id,
        &task_id,
        2,
        "completed",
    ));
    let mut replacement = request(&task_id);
    replacement.start =
        SubscriptionStart::Replacement(ReconnectProof::Idempotency(idempotency_key.clone()));
    assert_eq!(
        fixture
            .service
            .subscribe(&first_context.context, replacement.clone())
            .await,
        Err(SubscriptionError::IdentifierReused)
    );

    let proofless_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    assert_eq!(
        fixture
            .service
            .subscribe(&proofless_context.context, request(&task_id))
            .await,
        Err(SubscriptionError::InvalidReconnect)
    );

    let other_identity = CanonicalIdentity::new();
    fixture.authorizer.allow(&other_identity, &task_id);
    let cross_scope_context = request_context(TASKS_EXTENSION_REVISION, &other_identity);
    assert_eq!(
        fixture
            .service
            .subscribe(&cross_scope_context.context, replacement.clone())
            .await,
        Err(SubscriptionError::InvalidReconnect)
    );

    let second_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let second = fixture
        .service
        .subscribe(&second_context.context, replacement)
        .await
        .unwrap_or_else(|error| panic!("reconnect: {error}"));
    assert_ne!(first.subscription_id, second.subscription_id);
    let mut second_stream = fixture
        .delivery
        .take_stream(&second.subscription_id)
        .unwrap_or_else(|error| panic!("second stream: {error}"));
    let acknowledgement = next_frame(&mut second_stream).await;
    assert!(matches!(acknowledgement, DeliveryFrame::Acknowledged(_)));
    assert_eq!(
        acknowledgement.subscription_id(),
        &second_context.subscription_id
    );
    let replay = next_frame(&mut second_stream).await;
    assert_eq!(replay.subscription_id(), &second_context.subscription_id);
    assert!(matches!(
        replay,
        DeliveryFrame::TaskSnapshot {
            replayed: true,
            snapshot,
            ..
        } if snapshot.position() == position(2)
    ));
}

#[tokio::test]
async fn replacement_accepts_nonempty_scope_bound_task_handles() {
    assert_eq!(
        TaskReconnectHandles::new(Vec::new()),
        Err(ValueError::Empty)
    );
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let task_handle = fixture.repository.bind_task_handle(&identity, &task_id);
    let first = fixture
        .service
        .subscribe(&first_context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("first subscribe: {error}"));
    let mut first_stream = fixture
        .delivery
        .take_stream(&first.subscription_id)
        .unwrap_or_else(|error| panic!("first stream: {error}"));
    let _ = next_frame(&mut first_stream).await;
    let _ = next_frame(&mut first_stream).await;
    let _ = fixture
        .service
        .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false)
        .await;
    let _ = next_frame(&mut first_stream).await;

    fixture.repository.append(snapshot(
        &identity.domain_tenant_id,
        &task_id,
        2,
        "completed",
    ));
    let second_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let mut replacement = request(&task_id);
    replacement.start = SubscriptionStart::Replacement(ReconnectProof::Tasks(
        TaskReconnectHandles::new(vec![task_handle])
            .unwrap_or_else(|error| panic!("task handles: {error}")),
    ));
    let second = fixture
        .service
        .subscribe(&second_context.context, replacement)
        .await
        .unwrap_or_else(|error| panic!("replacement: {error}"));
    let mut second_stream = fixture
        .delivery
        .take_stream(&second.subscription_id)
        .unwrap_or_else(|error| panic!("second stream: {error}"));
    let acknowledgement = next_frame(&mut second_stream).await;
    assert_eq!(
        acknowledgement.subscription_id(),
        &second_context.subscription_id
    );
    let snapshot_frame = next_frame(&mut second_stream).await;
    assert_eq!(
        snapshot_frame.subscription_id(),
        &second_context.subscription_id
    );
    assert!(matches!(
        snapshot_frame,
        DeliveryFrame::TaskSnapshot {
            replayed: false,
            snapshot,
            ..
        } if snapshot.position() == position(2)
    ));
}

#[tokio::test]
async fn slow_consumer_is_closed_with_correlated_cursor() {
    let fixture = started_fixture(SubscriptionConfig {
        delivery: DeliveryLimits {
            max_frames: 2,
            max_bytes: 1024 * 1024,
        },
        ..SubscriptionConfig::default()
    })
    .await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    wait_until_checkpointed(&fixture.repository, &task_id, position(1)).await;
    wait_until_replayed(&fixture.repository, 1).await;
    for sequence in 2..=4 {
        fixture.repository.append(snapshot(
            &identity.domain_tenant_id,
            &task_id,
            sequence,
            "working",
        ));
    }
    fixture
        .records
        .send(Ok(BackplaneRecord::IngressGap))
        .await
        .unwrap_or_else(|error| panic!("gap send: {error}"));
    wait_until_disarmed(&fixture.runtime, &lease.subscription_id).await;

    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::SlowConsumer,
            cursors,
            ..
        }) if cursors == vec![TaskCursor { task_id, position: position(3) }]
    ));
}

#[tokio::test]
async fn graceful_server_drain_is_finite_and_preserves_final_cursor() {
    let fixture = started_fixture(SubscriptionConfig {
        drain_timeout_ms: 50,
        ..SubscriptionConfig::default()
    })
    .await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    fixture.service.drain_all(1_001).await;

    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::ServerDrain,
            drain: DrainOutcome::Drained,
            cursors,
            ..
        }) if cursors == vec![TaskCursor { task_id, position: position(1) }]
    ));
}

#[tokio::test]
async fn replacement_with_sixty_four_replay_frames_returns_before_attachment_and_drains() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let idempotency_key = IdempotencyKey::new("sixty-four-replay")
        .unwrap_or_else(|error| panic!("idempotency key: {error}"));
    let mut initial_request = request(&task_id);
    initial_request.start = SubscriptionStart::Initial {
        idempotency_key: Some(idempotency_key.clone()),
    };
    let first = fixture
        .service
        .subscribe(&first_context.context, initial_request)
        .await
        .unwrap_or_else(|error| panic!("first subscribe: {error}"));
    let mut first_stream = fixture
        .delivery
        .take_stream(&first.subscription_id)
        .unwrap_or_else(|error| panic!("first stream: {error}"));
    let _ = next_frame(&mut first_stream).await;
    let _ = next_frame(&mut first_stream).await;
    wait_until_checkpointed(&fixture.repository, &task_id, position(1)).await;
    let _ = fixture
        .service
        .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false)
        .await;
    let _ = next_frame(&mut first_stream).await;
    for sequence in 2..=65 {
        fixture.repository.append(snapshot(
            &identity.domain_tenant_id,
            &task_id,
            sequence,
            "replayed",
        ));
    }

    let second_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let mut replacement_request = request(&task_id);
    replacement_request.start =
        SubscriptionStart::Replacement(ReconnectProof::Idempotency(idempotency_key));
    let replacement = tokio::time::timeout(
        Duration::from_secs(1),
        fixture
            .service
            .subscribe(&second_context.context, replacement_request),
    )
    .await
    .unwrap_or_else(|error| panic!("replacement admission blocked: {error}"))
    .unwrap_or_else(|error| panic!("replacement subscribe: {error}"));
    let mut replacement_stream = fixture
        .delivery
        .take_stream(&replacement.subscription_id)
        .unwrap_or_else(|error| panic!("replacement stream: {error}"));
    assert!(matches!(
        next_frame(&mut replacement_stream).await,
        DeliveryFrame::Acknowledged(_)
    ));
    for expected_sequence in 2..=65 {
        assert!(matches!(
            next_frame(&mut replacement_stream).await,
            DeliveryFrame::TaskSnapshot {
                replayed: true,
                snapshot,
                ..
            } if snapshot.position() == position(expected_sequence)
        ));
    }
}

#[tokio::test]
async fn one_frame_queue_waits_for_acknowledgement_consumption_before_initialization() {
    let fixture = started_fixture(SubscriptionConfig {
        delivery: DeliveryLimits {
            max_frames: 1,
            max_bytes: 1024 * 1024,
        },
        ..SubscriptionConfig::default()
    })
    .await;
    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );

    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Acknowledged(_)
    ));
    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::TaskSnapshot { snapshot, .. }
            if snapshot.position() == position(1)
    ));
}

#[tokio::test]
async fn finish_failure_retries_one_closing_claim_before_reconnect() {
    let fixture = started_fixture(SubscriptionConfig::default()).await;
    let identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let idempotency_key = IdempotencyKey::new("retryable-finish")
        .unwrap_or_else(|error| panic!("idempotency key: {error}"));
    let mut initial_request = request(&task_id);
    initial_request.start = SubscriptionStart::Initial {
        idempotency_key: Some(idempotency_key.clone()),
    };
    let first = fixture
        .service
        .subscribe(&first_context.context, initial_request)
        .await
        .unwrap_or_else(|error| panic!("first subscribe: {error}"));
    let mut first_stream = fixture
        .delivery
        .take_stream(&first.subscription_id)
        .unwrap_or_else(|error| panic!("first stream: {error}"));
    let _ = next_frame(&mut first_stream).await;
    let _ = next_frame(&mut first_stream).await;
    wait_until_checkpointed(&fixture.repository, &task_id, position(1)).await;
    fixture.repository.fail_finishes(1);

    let first_close =
        fixture
            .service
            .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false);
    let duplicate_close =
        fixture
            .service
            .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false);
    let _ = tokio::join!(first_close, duplicate_close);
    assert_eq!(fixture.repository.finish_count(), 2);

    let second_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let mut replacement_request = request(&task_id);
    replacement_request.start =
        SubscriptionStart::Replacement(ReconnectProof::Idempotency(idempotency_key));
    let replacement = fixture
        .service
        .subscribe(&second_context.context, replacement_request)
        .await;
    assert!(replacement.is_ok(), "replacement failed: {replacement:?}");
}

#[tokio::test]
async fn terminal_finish_error_closes_failed_and_releases_capacity() {
    let fixture = started_fixture(SubscriptionConfig {
        max_active_subscriptions: 1,
        max_subscriptions_per_tenant: 1,
        max_subscriptions_per_principal: 1,
        ..SubscriptionConfig::default()
    })
    .await;
    let first_identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &first_identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&first_identity, &task_id);
    fixture.repository.replace_history(
        &first_identity.domain_tenant_id,
        &task_id,
        vec![snapshot(
            &first_identity.domain_tenant_id,
            &task_id,
            1,
            "working",
        )],
    );
    let first = fixture
        .service
        .subscribe(&first_context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("first subscribe: {error}"));
    let mut first_stream = fixture
        .delivery
        .take_stream(&first.subscription_id)
        .unwrap_or_else(|error| panic!("first stream: {error}"));
    let _ = next_frame(&mut first_stream).await;
    let _ = next_frame(&mut first_stream).await;
    fixture
        .repository
        .fail_finish_terminally(RepositoryError::Inconsistent);

    let _ = fixture
        .service
        .cancel(&first.subscription_id, CloseReason::Cancelled, 1_001, false)
        .await;
    assert!(matches!(
        next_frame(&mut first_stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::Failed,
            ..
        })
    ));

    let second_identity = CanonicalIdentity::new();
    let second_context = request_context(TASKS_EXTENSION_REVISION, &second_identity);
    fixture.authorizer.allow(&second_identity, &task_id);
    fixture.repository.replace_history(
        &second_identity.domain_tenant_id,
        &task_id,
        vec![snapshot(
            &second_identity.domain_tenant_id,
            &task_id,
            1,
            "working",
        )],
    );
    let replacement = fixture
        .service
        .subscribe(&second_context.context, request(&task_id))
        .await;
    assert!(
        replacement.is_ok(),
        "terminal finish error leaked capacity: {replacement:?}"
    );
}

#[tokio::test]
async fn backplane_clock_failure_fences_and_closes_every_active_stream() {
    let mut fixture = fixture(SubscriptionConfig::default());
    let receiver = fixture
        .receiver
        .take()
        .unwrap_or_else(|| panic!("receiver already consumed"));
    let service = fixture.service.clone();
    let cancellation = fixture.cancellation.clone();
    let backplane_task =
        tokio::spawn(async move { service.run_backplane(receiver, &cancellation).await });
    for _ in 0..32 {
        if fixture.selected.is_ready() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(fixture.selected.is_ready(), "receiver did not start");

    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = fixture
        .service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let mut stream = fixture
        .delivery
        .take_stream(&lease.subscription_id)
        .unwrap_or_else(|error| panic!("stream: {error}"));
    let _ = next_frame(&mut stream).await;
    let _ = next_frame(&mut stream).await;
    wait_until_replayed(&fixture.repository, 1).await;
    fixture.runtime.fail_clock();
    fixture
        .records
        .send(Ok(BackplaneRecord::IngressGap))
        .await
        .unwrap_or_else(|error| panic!("clock failure trigger: {error}"));
    let result = tokio::time::timeout(Duration::from_secs(1), backplane_task)
        .await
        .unwrap_or_else(|error| panic!("backplane did not stop: {error}"))
        .unwrap_or_else(|error| panic!("backplane task failed: {error}"));
    assert_eq!(result, Err(BackplaneError::Disconnected));
    wait_until_disarmed(&fixture.runtime, &lease.subscription_id).await;
    assert!(matches!(
        next_frame(&mut stream).await,
        DeliveryFrame::Closed(SubscriptionClosed {
            reason: CloseReason::Failed,
            ..
        })
    ));
}

#[tokio::test]
async fn pending_subscription_counts_against_atomic_tenant_quota() {
    let fixture = started_fixture(SubscriptionConfig {
        max_active_subscriptions: 2,
        max_subscriptions_per_tenant: 1,
        max_subscriptions_per_principal: 2,
        ..SubscriptionConfig::default()
    })
    .await;
    let first_identity = CanonicalIdentity::new();
    let second_identity = CanonicalIdentity::in_same_tenant(&first_identity);
    let first_context = request_context(TASKS_EXTENSION_REVISION, &first_identity);
    let second_context = request_context(TASKS_EXTENSION_REVISION, &second_identity);
    let task_id = task("task-a");
    fixture.authorizer.allow(&first_identity, &task_id);
    fixture.authorizer.allow(&second_identity, &task_id);
    fixture.repository.replace_history(
        &first_identity.domain_tenant_id,
        &task_id,
        vec![snapshot(
            &first_identity.domain_tenant_id,
            &task_id,
            1,
            "working",
        )],
    );
    let gate = fixture.authorizer.block();
    let service = fixture.service.clone();
    let first_task = task_id.clone();
    let first_admission = tokio::spawn(async move {
        service
            .subscribe(&first_context.context, request(&first_task))
            .await
    });
    wait_until_authorized(&fixture.authorizer, 1).await;

    assert_eq!(
        fixture
            .service
            .subscribe(&second_context.context, request(&task_id))
            .await,
        Err(SubscriptionError::CapacityExceeded)
    );
    gate.add_permits(1);
    assert!(
        first_admission
            .await
            .unwrap_or_else(|error| panic!("first admission task: {error}"))
            .is_ok()
    );
}

#[tokio::test]
async fn tenant_quota_is_independent_across_tenants() {
    let fixture = started_fixture(SubscriptionConfig {
        max_active_subscriptions: 2,
        max_subscriptions_per_tenant: 1,
        max_subscriptions_per_principal: 1,
        ..SubscriptionConfig::default()
    })
    .await;
    let first_identity = CanonicalIdentity::new();
    let second_identity = CanonicalIdentity::new();
    let first_context = request_context(TASKS_EXTENSION_REVISION, &first_identity);
    let second_context = request_context(TASKS_EXTENSION_REVISION, &second_identity);
    let task_id = task("task-a");
    for identity in [&first_identity, &second_identity] {
        fixture.authorizer.allow(identity, &task_id);
        fixture.repository.replace_history(
            &identity.domain_tenant_id,
            &task_id,
            vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
        );
    }

    let first = fixture
        .service
        .subscribe(&first_context.context, request(&task_id))
        .await;
    let second = fixture
        .service
        .subscribe(&second_context.context, request(&task_id))
        .await;
    assert!(
        first.is_ok() && second.is_ok(),
        "cross-tenant admission failed: {first:?} {second:?}"
    );
}

#[tokio::test]
async fn principal_quota_releases_after_failed_admission() {
    let fixture = started_fixture(SubscriptionConfig {
        max_active_subscriptions: 2,
        max_subscriptions_per_tenant: 2,
        max_subscriptions_per_principal: 1,
        ..SubscriptionConfig::default()
    })
    .await;
    let identity = CanonicalIdentity::new();
    let denied_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let admitted_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let over_quota_context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    assert_eq!(
        fixture
            .service
            .subscribe(&denied_context.context, request(&task_id))
            .await,
        Err(SubscriptionError::Unauthorized)
    );
    fixture.authorizer.allow(&identity, &task_id);
    fixture.repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    assert!(
        fixture
            .service
            .subscribe(&admitted_context.context, request(&task_id))
            .await
            .is_ok()
    );
    assert_eq!(
        fixture
            .service
            .subscribe(&over_quota_context.context, request(&task_id))
            .await,
        Err(SubscriptionError::CapacityExceeded)
    );
}

#[tokio::test]
async fn explicitly_attached_test_adapter_initializes_before_subscribe_returns() {
    let repository = Arc::new(TestRepository::default());
    let authorizer = Arc::new(TestAuthorizer::default());
    let runtime = Arc::new(TestRuntime::default());
    let delivery = Arc::new(AttachedTestDelivery::default());
    let provider = Arc::new(FakeBackplane {
        ready: Arc::new(AtomicBool::new(true)),
    });
    let (_records, receiver) = mpsc::channel(1);
    let parts = SelectedBackplane::exactly_one([BackplaneRegistration::new(
        provider,
        Box::new(FakeReceiver { records: receiver }),
    )])
    .unwrap_or_else(|error| panic!("selected backplane: {error}"));
    let selected = parts.backplane.clone();
    let service = TaskSubscriptionService::new(
        SubscriptionConfig::default(),
        repository.clone(),
        authorizer.clone(),
        runtime,
        delivery.clone(),
        parts.backplane,
    )
    .unwrap_or_else(|error| panic!("service: {error}"));
    let cancellation = CancellationToken::new();
    let receiver_cancellation = cancellation.clone();
    let receiver_service = service.clone();
    let receiver_task = tokio::spawn(async move {
        receiver_service
            .run_backplane(parts.receiver, &receiver_cancellation)
            .await
    });
    for _ in 0..32 {
        if selected.is_ready() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(selected.is_ready(), "receiver did not start");

    let identity = CanonicalIdentity::new();
    let context = request_context(TASKS_EXTENSION_REVISION, &identity);
    let task_id = task("task-a");
    authorizer.allow(&identity, &task_id);
    repository.replace_history(
        &identity.domain_tenant_id,
        &task_id,
        vec![snapshot(&identity.domain_tenant_id, &task_id, 1, "working")],
    );
    let lease = service
        .subscribe(&context.context, request(&task_id))
        .await
        .unwrap_or_else(|error| panic!("subscribe: {error}"));
    let frames = delivery.frames(&lease.subscription_id);
    assert!(matches!(
        frames.as_slice(),
        [
            DeliveryFrame::Acknowledged(_),
            DeliveryFrame::TaskSnapshot { .. }
        ]
    ));

    cancellation.cancel();
    receiver_task
        .await
        .unwrap_or_else(|error| panic!("receiver task: {error}"))
        .unwrap_or_else(|error| panic!("receiver loop: {error}"));
}
