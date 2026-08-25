//! Supervision, cancellation, heartbeat reporting, and bounded shutdown for long-lived tasks.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    future::Future,
    panic::{AssertUnwindSafe, catch_unwind},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::{FutureExt as _, future::join_all};
use rsk_core::{ErrorCode, ServiceError};
use thiserror::Error;
use tokio::{task::JoinHandle, time};
use tokio_util::sync::CancellationToken;

type TaskFuture = Pin<Box<dyn Future<Output = Result<(), ServiceError>> + Send + 'static>>;
type TaskFn = dyn Fn(TaskContext) -> TaskFuture + Send + Sync + 'static;

/// Operational importance of a supervised task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Criticality {
    /// Unexpected final exit makes the process unready and requests shutdown.
    Required,
    /// Unexpected final exit degrades only the owning capability.
    Degraded,
    /// Unexpected final exit is reported without degrading readiness.
    BestEffort,
}

/// Condition under which a task may be restarted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartMode {
    /// Never restart the task.
    Never,
    /// Restart only failures and panics.
    OnFailure,
    /// Restart successful and failed exits.
    Always,
}

/// Bounded exponential restart policy with capped deterministic jitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartPolicy {
    mode: RestartMode,
    max_restarts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    jitter_percent: u8,
}

impl RestartPolicy {
    /// A policy that never restarts.
    pub const NEVER: Self = Self {
        mode: RestartMode::Never,
        max_restarts: 0,
        initial_backoff: Duration::ZERO,
        max_backoff: Duration::ZERO,
        jitter_percent: 0,
    };

    /// Creates a bounded restart-on-failure policy.
    #[must_use]
    pub fn on_failure(
        max_restarts: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
        jitter_percent: u8,
    ) -> Self {
        Self::bounded(
            RestartMode::OnFailure,
            max_restarts,
            initial_backoff,
            max_backoff,
            jitter_percent,
        )
    }

    /// Creates a bounded restart-always policy.
    #[must_use]
    pub fn always(
        max_restarts: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
        jitter_percent: u8,
    ) -> Self {
        Self::bounded(
            RestartMode::Always,
            max_restarts,
            initial_backoff,
            max_backoff,
            jitter_percent,
        )
    }

    fn bounded(
        mode: RestartMode,
        max_restarts: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
        jitter_percent: u8,
    ) -> Self {
        Self {
            mode,
            max_restarts,
            initial_backoff,
            max_backoff: max_backoff.max(initial_backoff),
            jitter_percent: jitter_percent.min(50),
        }
    }

    /// Returns the restart condition.
    #[must_use]
    pub const fn mode(self) -> RestartMode {
        self.mode
    }

    /// Returns the maximum number of restarts after the initial attempt.
    #[must_use]
    pub const fn max_restarts(self) -> u32 {
        self.max_restarts
    }

    fn delay(self, task_name: &str, restart: u32) -> Duration {
        let exponent = restart.saturating_sub(1).min(31);
        let base = self
            .initial_backoff
            .saturating_mul(1_u32 << exponent)
            .min(self.max_backoff);
        if self.jitter_percent == 0 || base.is_zero() {
            return base;
        }

        let entropy = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| {
                elapsed.as_secs().rotate_left(17) ^ u64::from(elapsed.subsec_nanos())
            });
        let hash = task_name
            .bytes()
            .fold(u64::from(restart) ^ entropy, |hash, byte| {
                hash.wrapping_mul(1_099_511_628_211)
                    .wrapping_add(u64::from(byte))
            });
        let width = u64::from(self.jitter_percent) * 2 + 1;
        let sample = u8::try_from(hash % width).unwrap_or_default();
        let percent = 100_i16 + i16::from(sample) - i16::from(self.jitter_percent);
        base.mul_f64(f64::from(percent) / 100.0)
            .min(self.max_backoff)
    }
}

/// Heartbeat expectation for a supervised task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeartbeatPolicy {
    /// This task does not emit heartbeats.
    None,
    /// A task expected to report heartbeats.
    Expected {
        /// Maximum permitted time between heartbeats.
        stale_after: Duration,
    },
}

/// Declarative registration for one long-lived task.
pub struct TaskSpec {
    name: String,
    module: String,
    criticality: Criticality,
    restart_policy: RestartPolicy,
    heartbeat_policy: HeartbeatPolicy,
    shutdown_timeout: Duration,
    run: Arc<TaskFn>,
}

impl TaskSpec {
    /// Creates a task registration from an async task factory.
    pub fn new<F, Fut>(
        name: impl Into<String>,
        module: impl Into<String>,
        criticality: Criticality,
        shutdown_timeout: Duration,
        run: F,
    ) -> Self
    where
        F: Fn(TaskContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), ServiceError>> + Send + 'static,
    {
        Self {
            name: name.into(),
            module: module.into(),
            criticality,
            restart_policy: RestartPolicy::NEVER,
            heartbeat_policy: HeartbeatPolicy::None,
            shutdown_timeout,
            run: Arc::new(move |context| Box::pin(run(context))),
        }
    }

    /// Sets the bounded restart policy for degraded and best-effort tasks.
    ///
    /// Required task exits are always fatal and never restart.
    #[must_use]
    pub const fn with_restart_policy(mut self, policy: RestartPolicy) -> Self {
        self.restart_policy = policy;
        self
    }

    /// Sets the heartbeat expectation.
    #[must_use]
    pub const fn with_heartbeat_policy(mut self, policy: HeartbeatPolicy) -> Self {
        self.heartbeat_policy = policy;
        self
    }
}

impl fmt::Debug for TaskSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TaskSpec")
            .field("name", &self.name)
            .field("module", &self.module)
            .field("criticality", &self.criticality)
            .field("restart_policy", &self.restart_policy)
            .field("heartbeat_policy", &self.heartbeat_policy)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish_non_exhaustive()
    }
}

/// Cancellation and heartbeat controls provided to a task attempt.
#[derive(Clone, Debug)]
pub struct TaskContext {
    draining: CancellationToken,
    shutdown_requested: CancellationToken,
    cancelled: CancellationToken,
    state: Arc<Mutex<TaskState>>,
}

impl TaskContext {
    /// Resolves when graceful draining begins.
    pub async fn draining(&self) {
        self.draining.cancelled().await;
    }
    /// Resolves when bounded shutdown is requested after any pre-drain phase.
    pub async fn shutdown_requested(&self) {
        self.shutdown_requested.cancelled().await;
    }

    /// Resolves when this task's drain deadline expires or shutdown is forced.
    pub async fn cancelled(&self) {
        self.cancelled.cancelled().await;
    }

    /// Returns whether graceful draining has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.is_cancelled()
    }
    /// Returns whether bounded shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested.is_cancelled()
    }

    /// Returns whether cancellation has been requested for this task.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.is_cancelled()
    }

    /// Records a heartbeat at the current wall-clock time.
    pub fn heartbeat(&self) {
        lock(&self.state).heartbeat_at = Some(SystemTime::now());
    }
}

/// Last observed terminal result for a task attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskExit {
    /// The task returned successfully.
    Success,
    /// The task returned a safe coded failure.
    Failure(ErrorCode),
    /// The task panicked; the panic payload is deliberately discarded.
    Panic,
    /// The task observed shutdown cancellation before returning.
    Cancelled,
    /// The supervisor aborted a task that exceeded its shutdown bound.
    Aborted,
}

/// Current lifecycle state of a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskStatus {
    /// Registered but not yet started.
    Registered,
    /// The task attempt is running.
    Running,
    /// The task is waiting for bounded restart backoff.
    Restarting,
    /// The task exited successfully.
    Exited,
    /// The owning capability is degraded.
    Degraded,
    /// The task failed without degrading the process.
    Failed,
    /// The task was cancelled during shutdown.
    Cancelled,
    /// The task panicked and will not restart.
    Panicked,
    /// The supervisor aborted the task after its shutdown bound.
    Aborted,
}

/// Operator-safe state for one supervised task.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSnapshot {
    /// Unique task name.
    pub name: String,
    /// Owning module.
    pub module: String,
    /// Operational criticality.
    pub criticality: Criticality,
    /// Time at which the latest attempt started.
    pub started_at: Option<SystemTime>,
    /// Time at which the latest heartbeat was recorded.
    pub heartbeat_at: Option<SystemTime>,
    /// Heartbeat expectation.
    pub heartbeat_policy: HeartbeatPolicy,
    /// Restart policy.
    pub restart_policy: RestartPolicy,
    /// Number of restarts after the initial attempt.
    pub restarts: u32,
    /// Per-task drain deadline.
    pub shutdown_timeout: Duration,
    /// Current lifecycle state.
    pub status: TaskStatus,
    /// Last terminal result, without internal error or panic details.
    pub last_exit: Option<TaskExit>,
    /// Whether cancellation has been requested for this task.
    pub cancellation_requested: bool,
}

impl TaskSnapshot {
    /// Returns whether the most recent heartbeat has exceeded its policy bound.
    #[must_use]
    pub fn heartbeat_is_stale(&self, now: SystemTime) -> bool {
        match (self.heartbeat_policy, self.heartbeat_at) {
            (HeartbeatPolicy::Expected { stale_after }, Some(last)) => now
                .duration_since(last)
                .is_ok_and(|elapsed| elapsed > stale_after),
            (HeartbeatPolicy::Expected { stale_after }, None) => self
                .started_at
                .and_then(|started| now.duration_since(started).ok())
                .is_some_and(|elapsed| elapsed > stale_after),
            (HeartbeatPolicy::None, _) => false,
        }
    }
}

#[derive(Debug)]
struct TaskState {
    name: String,
    module: String,
    criticality: Criticality,
    started_at: Option<SystemTime>,
    heartbeat_at: Option<SystemTime>,
    heartbeat_policy: HeartbeatPolicy,
    restart_policy: RestartPolicy,
    restarts: u32,
    shutdown_timeout: Duration,
    status: TaskStatus,
    last_exit: Option<TaskExit>,
    cancellation: CancellationToken,
    completed: CancellationToken,
}

impl TaskState {
    fn snapshot(&self) -> TaskSnapshot {
        TaskSnapshot {
            name: self.name.clone(),
            module: self.module.clone(),
            criticality: self.criticality,
            started_at: self.started_at,
            heartbeat_at: self.heartbeat_at,
            heartbeat_policy: self.heartbeat_policy,
            restart_policy: self.restart_policy,
            restarts: self.restarts,
            shutdown_timeout: self.shutdown_timeout,
            status: self.status,
            last_exit: self.last_exit,
            cancellation_requested: self.cancellation.is_cancelled(),
        }
    }
}

#[derive(Clone)]
struct PreDrainHook(Arc<dyn Fn() + Send + Sync + 'static>);

impl fmt::Debug for PreDrainHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreDrainHook([REDACTED])")
    }
}

#[derive(Debug)]
struct Shared {
    states: Mutex<BTreeMap<String, Arc<Mutex<TaskState>>>>,
    draining: CancellationToken,
    shutdown_requested: CancellationToken,
    force: CancellationToken,
    fatal: AtomicBool,
    pre_drain_hook: Option<PreDrainHook>,
}

/// Collects task registrations before they are started together.
#[derive(Debug, Default)]
pub struct Supervisor {
    specs: Vec<TaskSpec>,
    names: HashSet<String>,
}

impl Supervisor {
    /// Creates an empty supervisor.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a uniquely named long-lived task.
    ///
    /// # Errors
    ///
    /// Returns [`RegisterError`] for an empty identity or duplicate task name.
    pub fn register(&mut self, spec: TaskSpec) -> Result<(), RegisterError> {
        if spec.name.trim().is_empty() || spec.module.trim().is_empty() {
            return Err(RegisterError::EmptyIdentity);
        }
        if !self.names.insert(spec.name.clone()) {
            return Err(RegisterError::DuplicateName(spec.name));
        }
        self.specs.push(spec);
        Ok(())
    }

    /// Starts all registrations with a synchronous hook invoked before a required-task failure
    /// signals drain.
    ///
    /// # Errors
    ///
    /// Returns [`StartError::NoRuntime`] when no Tokio runtime is entered.
    pub fn start_with_pre_drain_hook<F>(self, hook: F) -> Result<SupervisorHandle, StartError>
    where
        F: Fn() + Send + Sync + 'static,
    {
        self.start_inner(Some(PreDrainHook(Arc::new(hook))))
    }

    /// Starts all registrations and the shutdown deadline coordinator.
    ///
    /// # Errors
    ///
    /// Returns [`StartError::NoRuntime`] when no Tokio runtime is entered.
    pub fn start(self) -> Result<SupervisorHandle, StartError> {
        self.start_inner(None)
    }

    fn start_inner(
        self,
        pre_drain_hook: Option<PreDrainHook>,
    ) -> Result<SupervisorHandle, StartError> {
        tokio::runtime::Handle::try_current().map_err(|_| StartError::NoRuntime)?;

        let draining = CancellationToken::new();
        let shutdown_requested = CancellationToken::new();
        let force = CancellationToken::new();
        let mut states = BTreeMap::new();
        let mut task_states = Vec::with_capacity(self.specs.len());

        for spec in &self.specs {
            let cancellation = CancellationToken::new();
            let completed = CancellationToken::new();
            let state = Arc::new(Mutex::new(TaskState {
                name: spec.name.clone(),
                module: spec.module.clone(),
                criticality: spec.criticality,
                started_at: None,
                heartbeat_at: None,
                heartbeat_policy: spec.heartbeat_policy,
                restart_policy: spec.restart_policy,
                restarts: 0,
                shutdown_timeout: spec.shutdown_timeout,
                status: TaskStatus::Registered,
                last_exit: None,
                cancellation,
                completed,
            }));
            states.insert(spec.name.clone(), Arc::clone(&state));
            task_states.push(state);
        }

        let shared = Arc::new(Shared {
            states: Mutex::new(states),
            draining,
            shutdown_requested,
            force,
            fatal: AtomicBool::new(false),
            pre_drain_hook,
        });
        let mut tasks = Vec::with_capacity(self.specs.len());
        let mut deadlines = Vec::with_capacity(self.specs.len());
        for (spec, state) in self.specs.into_iter().zip(task_states) {
            let deadline = spec.shutdown_timeout;
            let cancellation = lock(&state).cancellation.clone();
            let completed = lock(&state).completed.clone();
            let deadline_state = Arc::clone(&state);
            let task = tokio::spawn(run_task(spec, state, Arc::clone(&shared)));
            deadlines.push((
                deadline,
                cancellation,
                completed,
                task.abort_handle(),
                deadline_state,
            ));
            tasks.push(task);
        }

        let coordinator_shared = Arc::clone(&shared);
        let coordinator = tokio::spawn(async move {
            coordinator_shared.shutdown_requested.cancelled().await;
            coordinator_shared.draining.cancel();
            join_all(deadlines.into_iter().map(
                |(deadline, cancellation, completed, abort, state)| {
                    let force = coordinator_shared.force.clone();
                    async move {
                        tokio::select! {
                            () = completed.cancelled() => return,
                            () = time::sleep(deadline) => {}
                            () = force.cancelled() => {}
                        }
                        cancellation.cancel();
                        abort.abort();
                        let mut state = lock(&state);
                        if matches!(
                            state.status,
                            TaskStatus::Registered | TaskStatus::Running | TaskStatus::Restarting
                        ) {
                            state.status = TaskStatus::Aborted;
                            state.last_exit = Some(TaskExit::Aborted);
                        }
                    }
                },
            ))
            .await;
        });

        Ok(SupervisorHandle {
            shared,
            tasks,
            coordinator: Some(coordinator),
        })
    }
}

/// Registration failure detected before any task is spawned.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum RegisterError {
    /// Task names and module names must be non-empty.
    #[error("task name and module must be non-empty")]
    EmptyIdentity,
    /// Task names are unique within a supervisor.
    #[error("duplicate supervised task name: {0}")]
    DuplicateName(String),
}

/// Failure to start a supervisor.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StartError {
    /// Task spawning requires an entered Tokio runtime.
    #[error("runtime supervisor must start inside a Tokio runtime")]
    NoRuntime,
}

/// Cloneable lifecycle controls retained while [`SupervisorHandle::shutdown`] is awaited.
#[derive(Clone, Debug)]
pub struct SupervisorControl {
    shared: Arc<Shared>,
}

impl SupervisorControl {
    /// Marks the process unready and asks tasks to stop accepting new work.
    pub fn begin_drain(&self) {
        self.shared.draining.cancel();
    }

    /// Begins bounded shutdown, cancelling remaining tasks at their deadlines.
    pub fn request_shutdown(&self) {
        self.shared.shutdown_requested.cancel();
    }

    /// Immediately cancels and aborts remaining tasks after a second signal.
    pub fn force_cancel(&self) {
        self.shared.draining.cancel();
        self.shared.shutdown_requested.cancel();
        self.shared.force.cancel();
        for state in lock(&self.shared.states).values() {
            lock(state).cancellation.cancel();
        }
    }

    /// Resolves when shutdown is requested explicitly or by a required task exit.
    pub async fn shutdown_requested(&self) {
        self.shared.shutdown_requested.cancelled().await;
    }

    /// Returns whether graceful draining has begun.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.shared.draining.is_cancelled()
    }

    /// Returns whether shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shared.shutdown_requested.is_cancelled()
    }

    /// Returns operator-safe snapshots in stable task-name order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<TaskSnapshot> {
        lock(&self.shared.states)
            .values()
            .map(|state| lock(state).snapshot())
            .collect()
    }
}

/// Running supervisor controls and diagnostics.
#[derive(Debug)]
pub struct SupervisorHandle {
    shared: Arc<Shared>,
    tasks: Vec<JoinHandle<()>>,
    coordinator: Option<JoinHandle<()>>,
}

impl SupervisorHandle {
    /// Returns cloneable controls that remain usable while shutdown is awaited.
    #[must_use]
    pub fn control(&self) -> SupervisorControl {
        SupervisorControl {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Marks the process unready and asks tasks to stop accepting new work.
    pub fn begin_drain(&self) {
        self.control().begin_drain();
    }

    /// Begins bounded shutdown, cancelling each task after its configured deadline.
    pub fn request_shutdown(&self) {
        self.control().request_shutdown();
    }

    /// Immediately cancels all task deadlines, as for a second termination signal.
    pub fn force_cancel(&self) {
        self.control().force_cancel();
    }

    /// Resolves when shutdown is requested explicitly or by a required task exit.
    pub async fn shutdown_requested(&self) {
        self.shared.shutdown_requested.cancelled().await;
    }

    /// Returns whether shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.control().is_shutdown_requested()
    }

    /// Returns operator-safe snapshots in stable task-name order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<TaskSnapshot> {
        self.control().snapshots()
    }

    /// Runs bounded shutdown and aborts tasks that ignore cancellation.
    pub async fn shutdown(mut self) -> ShutdownReport {
        self.request_shutdown();
        if let Some(coordinator) = self.coordinator.take() {
            let _ = coordinator.await;
        }

        let _ = join_all(&mut self.tasks).await;

        let snapshots = self.snapshots();
        let forced = snapshots
            .iter()
            .filter(|snapshot| snapshot.status == TaskStatus::Aborted)
            .map(|snapshot| snapshot.name.clone())
            .collect();
        ShutdownReport {
            snapshots,
            forced,
            fatal: self.shared.fatal.load(Ordering::Acquire),
        }
    }
}
impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        self.force_cancel();
        if let Some(coordinator) = self.coordinator.take() {
            coordinator.abort();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// Final bounded-shutdown result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShutdownReport {
    /// Final task snapshots.
    pub snapshots: Vec<TaskSnapshot>,
    /// Tasks aborted after ignoring their cancellation bound.
    pub forced: Vec<String>,
    /// Whether a required task caused shutdown.
    pub fatal: bool,
}
struct CompletionGuard(CancellationToken);

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

async fn run_task(spec: TaskSpec, state: Arc<Mutex<TaskState>>, shared: Arc<Shared>) {
    let _completion = CompletionGuard(lock(&state).completed.clone());
    loop {
        {
            let mut state = lock(&state);
            state.started_at = Some(SystemTime::now());
            state.heartbeat_at = None;
            state.status = TaskStatus::Running;
            state.last_exit = None;
        }
        tracing::info!(task = %spec.name, module = %spec.module, "supervised task started");

        let context = TaskContext {
            draining: shared.draining.clone(),
            shutdown_requested: shared.shutdown_requested.clone(),
            cancelled: lock(&state).cancellation.clone(),
            state: Arc::clone(&state),
        };
        let result = match catch_unwind(AssertUnwindSafe(|| (spec.run)(context))) {
            Ok(future) => AssertUnwindSafe(future).catch_unwind().await,
            Err(panic) => Err(panic),
        };
        let cancelled = lock(&state).cancellation.is_cancelled();
        let exit = if cancelled {
            TaskExit::Cancelled
        } else {
            match result {
                Ok(Ok(())) => TaskExit::Success,
                Ok(Err(error)) => TaskExit::Failure(error.code()),
                Err(_) => TaskExit::Panic,
            }
        };

        let can_restart = spec.criticality != Criticality::Required
            && !shared.shutdown_requested.is_cancelled()
            && !cancelled
            && should_restart(spec.restart_policy, exit, lock(&state).restarts);
        if can_restart {
            let restart = {
                let mut state = lock(&state);
                state.restarts += 1;
                state.status = TaskStatus::Restarting;
                state.last_exit = Some(exit);
                state.restarts
            };
            let delay = spec.restart_policy.delay(&spec.name, restart);
            tracing::warn!(
                task = %spec.name,
                module = %spec.module,
                restart,
                delay_ms = delay.as_millis(),
                "supervised task restarting"
            );
            tokio::select! {
                () = time::sleep(delay) => continue,
                () = shared.shutdown_requested.cancelled() => {
                    finish(&state, TaskExit::Cancelled, spec.criticality, true);
                    return;
                }
            }
        }

        let shutting_down = shared.shutdown_requested.is_cancelled();
        finish(&state, exit, spec.criticality, shutting_down);
        if spec.criticality == Criticality::Required
            && exit != TaskExit::Cancelled
            && !shutting_down
        {
            shared.fatal.store(true, Ordering::Release);
            if let Some(hook) = &shared.pre_drain_hook {
                (hook.0)();
            }
            shared.draining.cancel();
            shared.shutdown_requested.cancel();
            tracing::error!(task = %spec.name, module = %spec.module, "required supervised task exited");
        } else if exit != TaskExit::Cancelled {
            tracing::warn!(task = %spec.name, module = %spec.module, "supervised task exited");
        }
        return;
    }
}

fn should_restart(policy: RestartPolicy, exit: TaskExit, completed_restarts: u32) -> bool {
    if completed_restarts >= policy.max_restarts {
        return false;
    }
    match policy.mode {
        RestartMode::Never => false,
        RestartMode::OnFailure => matches!(exit, TaskExit::Failure(_) | TaskExit::Panic),
        RestartMode::Always => matches!(
            exit,
            TaskExit::Success | TaskExit::Failure(_) | TaskExit::Panic
        ),
    }
}

fn finish(state: &Mutex<TaskState>, exit: TaskExit, criticality: Criticality, shutting_down: bool) {
    let mut state = lock(state);
    state.last_exit = Some(exit);
    state.status = match exit {
        TaskExit::Success if criticality == Criticality::Degraded && !shutting_down => {
            TaskStatus::Degraded
        }
        TaskExit::Success => TaskStatus::Exited,
        TaskExit::Cancelled => TaskStatus::Cancelled,
        TaskExit::Panic | TaskExit::Failure(_) if criticality == Criticality::Degraded => {
            TaskStatus::Degraded
        }
        TaskExit::Panic => TaskStatus::Panicked,
        TaskExit::Aborted => TaskStatus::Aborted,
        TaskExit::Failure(_) => TaskStatus::Failed,
    };
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::sync::oneshot;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn task_failed_code() -> ErrorCode {
        match ErrorCode::try_new("TASK_FAILED") {
            Ok(code) => code,
            Err(_) => unreachable!("static error code is valid"),
        }
    }

    fn failure() -> ServiceError {
        ServiceError::new(task_failed_code(), "task failed")
    }

    fn panicking_factory(_: TaskContext) -> std::future::Ready<Result<(), ServiceError>> {
        panic!("task factory panic")
    }

    #[tokio::test]
    async fn drains_or_aborts_each_task_within_its_deadline() -> TestResult {
        let (drained_tx, drained_rx) = oneshot::channel();
        let drained_tx = Arc::new(Mutex::new(Some(drained_tx)));
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "http",
            "http-api",
            Criticality::Required,
            Duration::from_millis(80),
            move |context| {
                let drained_tx = Arc::clone(&drained_tx);
                async move {
                    context.draining().await;
                    if let Some(sender) = lock(&drained_tx).take() {
                        let _ = sender.send(());
                    }
                    Ok(())
                }
            },
        ))?;
        supervisor.register(TaskSpec::new(
            "worker",
            "jobs",
            Criticality::Degraded,
            Duration::from_millis(20),
            |_| async {
                futures::future::pending::<()>().await;
                Ok(())
            },
        ))?;

        let handle = supervisor.start()?;
        tokio::task::yield_now().await;
        handle.request_shutdown();
        time::timeout(Duration::from_millis(30), drained_rx).await??;
        let report = time::timeout(Duration::from_millis(80), handle.shutdown()).await?;

        assert!(!report.fatal);
        assert_eq!(report.forced, ["worker"]);
        assert_eq!(report.snapshots[0].status, TaskStatus::Exited);
        assert_eq!(report.snapshots[1].status, TaskStatus::Aborted);
        assert!(report.snapshots[1].cancellation_requested);
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_does_not_wait_for_a_completed_tasks_deadline() -> TestResult {
        let (draining_observed_tx, draining_observed_rx) = oneshot::channel();
        let draining_observed_tx = Arc::new(Mutex::new(Some(draining_observed_tx)));
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "cooperative",
            "runtime",
            Criticality::Required,
            Duration::from_secs(60),
            move |context| {
                let draining_observed_tx = Arc::clone(&draining_observed_tx);
                async move {
                    context.draining().await;
                    if let Some(sender) = lock(&draining_observed_tx).take() {
                        let _ = sender.send(());
                    }
                    context.shutdown_requested().await;
                    Ok(())
                }
            },
        ))?;

        let handle = supervisor.start()?;
        handle.begin_drain();
        time::timeout(Duration::from_millis(80), draining_observed_rx).await??;
        handle.request_shutdown();
        let report = time::timeout(Duration::from_millis(80), handle.shutdown()).await?;

        assert!(report.forced.is_empty());
        assert_eq!(report.snapshots[0].status, TaskStatus::Exited);
        Ok(())
    }

    #[tokio::test]
    async fn required_failure_requests_shutdown_without_exposing_cause() -> TestResult {
        let attempts = Arc::new(AtomicU32::new(0));
        let mut supervisor = Supervisor::new();
        supervisor.register(
            TaskSpec::new(
                "listener",
                "http-api",
                Criticality::Required,
                Duration::from_millis(10),
                {
                    let attempts = Arc::clone(&attempts);
                    move |_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        async { Err(failure()) }
                    }
                },
            )
            .with_restart_policy(RestartPolicy::on_failure(
                3,
                Duration::ZERO,
                Duration::ZERO,
                0,
            )),
        )?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), handle.shutdown_requested()).await?;
        let report = handle.shutdown().await;

        assert!(report.fatal);
        assert_eq!(report.snapshots[0].status, TaskStatus::Failed);
        assert_eq!(
            report.snapshots[0].last_exit,
            Some(TaskExit::Failure(task_failed_code()))
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(report.snapshots[0].restarts, 0);
        Ok(())
    }

    #[tokio::test]
    async fn synchronous_required_task_factory_panic_is_caught_and_fatal() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(
            TaskSpec::new(
                "panicking",
                "core",
                Criticality::Required,
                Duration::from_millis(10),
                panicking_factory,
            )
            .with_restart_policy(RestartPolicy::on_failure(
                3,
                Duration::ZERO,
                Duration::ZERO,
                0,
            )),
        )?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), handle.shutdown_requested()).await?;
        let report = handle.shutdown().await;

        assert!(report.fatal);
        assert_eq!(report.snapshots[0].status, TaskStatus::Panicked);
        assert_eq!(report.snapshots[0].restarts, 0);
        assert_eq!(report.snapshots[0].last_exit, Some(TaskExit::Panic));
        Ok(())
    }

    #[tokio::test]
    async fn asynchronous_required_task_panic_is_caught_and_fatal() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "panicking-future",
            "core",
            Criticality::Required,
            Duration::from_millis(10),
            |_| async { panic!("task future panic") },
        ))?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), handle.shutdown_requested()).await?;
        let report = handle.shutdown().await;

        assert!(report.fatal);
        assert_eq!(report.snapshots[0].status, TaskStatus::Panicked);
        assert_eq!(report.snapshots[0].last_exit, Some(TaskExit::Panic));
        Ok(())
    }

    #[tokio::test]
    async fn degraded_task_uses_bounded_restarts_without_global_shutdown() -> TestResult {
        let attempts = Arc::new(AtomicU32::new(0));
        let mut supervisor = Supervisor::new();
        supervisor.register(
            TaskSpec::new(
                "exporter",
                "telemetry",
                Criticality::Degraded,
                Duration::from_millis(10),
                {
                    let attempts = Arc::clone(&attempts);
                    move |_| {
                        attempts.fetch_add(1, Ordering::SeqCst);
                        async { Err(failure()) }
                    }
                },
            )
            .with_restart_policy(RestartPolicy::on_failure(
                2,
                Duration::from_millis(1),
                Duration::from_millis(2),
                20,
            )),
        )?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), async {
            while attempts.load(Ordering::SeqCst) != 3 {
                tokio::task::yield_now().await;
            }
            while handle.snapshots()[0].status != TaskStatus::Degraded {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        assert!(!handle.is_shutdown_requested());
        assert_eq!(handle.snapshots()[0].restarts, 2);
        let report = handle.shutdown().await;
        assert!(!report.fatal);
        Ok(())
    }

    #[tokio::test]
    async fn successful_degraded_task_exit_marks_capability_degraded() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "optional-consumer",
            "jobs",
            Criticality::Degraded,
            Duration::from_millis(10),
            |_| async { Ok(()) },
        ))?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), async {
            while handle.snapshots()[0].status != TaskStatus::Degraded {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert!(!handle.is_shutdown_requested());

        let report = handle.shutdown().await;
        assert_eq!(report.snapshots[0].status, TaskStatus::Degraded);
        Ok(())
    }

    #[tokio::test]
    async fn degraded_task_panic_marks_capability_degraded() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "optional-panicking",
            "jobs",
            Criticality::Degraded,
            Duration::from_millis(10),
            panicking_factory,
        ))?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), async {
            while handle.snapshots()[0].status != TaskStatus::Degraded {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(handle.snapshots()[0].last_exit, Some(TaskExit::Panic));

        let report = handle.shutdown().await;
        assert_eq!(report.snapshots[0].status, TaskStatus::Degraded);
        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_snapshots_apply_the_configured_staleness_bound() -> TestResult {
        let (heartbeat_tx, heartbeat_rx) = oneshot::channel();
        let heartbeat_tx = Arc::new(Mutex::new(Some(heartbeat_tx)));
        let mut supervisor = Supervisor::new();
        supervisor.register(
            TaskSpec::new(
                "heartbeat",
                "jobs",
                Criticality::Degraded,
                Duration::from_millis(20),
                move |context| {
                    let heartbeat_tx = Arc::clone(&heartbeat_tx);
                    async move {
                        context.heartbeat();
                        if let Some(sender) = lock(&heartbeat_tx).take() {
                            let _ = sender.send(());
                        }
                        context.draining().await;
                        Ok(())
                    }
                },
            )
            .with_heartbeat_policy(HeartbeatPolicy::Expected {
                stale_after: Duration::from_secs(1),
            }),
        )?;

        let handle = supervisor.start()?;
        time::timeout(Duration::from_millis(100), heartbeat_rx).await??;
        let snapshot = &handle.snapshots()[0];
        assert!(snapshot.heartbeat_at.is_some());
        assert!(!snapshot.heartbeat_is_stale(SystemTime::now()));
        assert!(snapshot.heartbeat_is_stale(SystemTime::now() + Duration::from_secs(2)));

        let report = handle.shutdown().await;
        assert!(report.forced.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn cloneable_control_forces_shutdown_while_report_is_awaited() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "long-deadline",
            "test",
            Criticality::BestEffort,
            Duration::from_secs(60),
            |_| async {
                futures::future::pending::<()>().await;
                Ok(())
            },
        ))?;

        let handle = supervisor.start()?;
        let control = handle.control();
        let shutdown = tokio::spawn(handle.shutdown());
        control.force_cancel();
        let report = time::timeout(Duration::from_millis(100), shutdown).await??;

        assert_eq!(report.forced, ["long-deadline"]);
        assert_eq!(report.snapshots[0].status, TaskStatus::Aborted);
        Ok(())
    }

    #[tokio::test]
    async fn uncooperative_task_is_aborted_at_configured_deadline() -> TestResult {
        let mut supervisor = Supervisor::new();
        supervisor.register(TaskSpec::new(
            "stuck",
            "test",
            Criticality::BestEffort,
            Duration::from_millis(1),
            |_| async {
                futures::future::pending::<()>().await;
                Ok(())
            },
        ))?;

        let handle = supervisor.start()?;
        let report = time::timeout(Duration::from_millis(100), handle.shutdown()).await?;
        assert_eq!(report.forced, ["stuck"]);
        assert_eq!(report.snapshots[0].status, TaskStatus::Aborted);
        assert!(report.snapshots[0].cancellation_requested);
        Ok(())
    }
}
