use std::{collections::HashSet, fmt, sync::Arc, time::SystemTime};

use futures::future::{BoxFuture, join_all};
use rsk_events_nats::NatsJetStreamEvents;
use rsk_outbox::PostgresOutbox;
use rsk_runtime::{Criticality, SupervisorControl, TaskExit, TaskSnapshot, TaskStatus};
use rsk_scheduler::PostgresScheduler;
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;

const MAX_COMPONENT_ID_BYTES: usize = 128;

/// Validated logical identifier for one selected worker component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BackendId(String);

impl BackendId {
    /// Validates and owns a bounded non-secret component identifier.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerDiagnosticsBuildError::InvalidBackendId`] for invalid input.
    pub fn new(value: impl Into<String>) -> Result<Self, WorkerDiagnosticsBuildError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_COMPONENT_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.')
            })
        {
            return Err(WorkerDiagnosticsBuildError::InvalidBackendId);
        }
        Ok(Self(value))
    }

    /// Returns the safe logical identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Provider-independent pause fence returned only at the worker application boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ControlStatus {
    /// Whether new leases are paused.
    pub paused: bool,
    /// Monotonic provider-native control revision.
    pub revision: u64,
}

/// Redis/Apalis status without pretending its sets are PGMQ tables.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RedisJobStatus {
    /// Logical worker-owned backend identifier.
    pub backend_id: BackendId,
    /// Active Apalis list length.
    pub queued: u64,
    /// Future Apalis sorted-set length.
    pub scheduled: u64,
    /// Retained successful records.
    pub completed: u64,
    /// Retained killed records.
    pub dead_lettered: u64,
    /// Age of the oldest canonical envelope observed by the bounded Redis scan.
    pub oldest_outstanding_age_ms: Option<u64>,
    /// Whether the bounded Redis sample covered the entire outstanding backlog.
    pub oldest_outstanding_age_complete: bool,
    /// Durable lease pause state.
    pub paused: bool,
    /// Durable pause fence.
    pub control_revision: u64,
}

/// PGMQ status retaining its source/dead/archive and visibility semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PgmqJobStatus {
    /// Logical worker-owned backend identifier.
    pub backend_id: BackendId,
    /// All live source-table rows.
    pub source_total: u64,
    /// Source rows visible to a new read.
    pub source_visible: u64,
    /// Source rows with a prior read and an active visibility lease.
    pub source_leased: u64,
    /// Source rows initially delayed and never read.
    pub source_delayed: u64,
    /// All retained terminal dead-queue rows.
    pub dead_total: u64,
    /// Dead rows visible to inspection tooling.
    pub dead_visible: u64,
    /// Successful source archive rows.
    pub archived_completed: u64,
    /// Age of the oldest source row.
    pub oldest_source_age_ms: Option<u64>,
    /// Durable lease pause state.
    pub paused: bool,
    /// Durable pause fence.
    pub control_revision: u64,
}

/// Closed selected job-provider status union.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum JobProviderStatus {
    /// Redis/Apalis native status.
    Redis(RedisJobStatus),
    /// PostgreSQL Message Queue native status.
    Pgmq(PgmqJobStatus),
}

/// Redacted dead record with explicit provider-native identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum DeadRecord {
    /// Apalis transport record retaining the same transport identity on replay.
    Redis {
        /// Opaque Apalis record identity.
        record_id: String,
        /// Canonical core job identity.
        job_id: String,
        /// Envelope creation time.
        created_at: OffsetDateTime,
        /// Provider terminal time.
        failed_at: OffsetDateTime,
        /// Persisted delivery attempt.
        attempt: u16,
        /// Exact canonical envelope length, never its bytes.
        envelope_bytes: usize,
    },
    /// PGMQ dead-queue row; replay creates a new provider message identity.
    Pgmq {
        /// PGMQ dead-queue message identity.
        record_id: i64,
        /// Valid canonical core job identity.
        job_id: String,
        /// Provider enqueue time.
        created_at: OffsetDateTime,
        /// Provider terminal time.
        failed_at: OffsetDateTime,
        /// Explicit or safely inferred one-based terminal attempt.
        attempt: u16,
        /// Exact canonical envelope length, never its bytes.
        envelope_bytes: usize,
    },
}

/// Explicit replay result; provider identity semantics are never collapsed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum ReplayReceipt {
    /// Redis moved the same stored request and transport identity out of its dead set.
    RedisSameJobSameMessage {
        /// Canonical core job identity.
        job_id: String,
        /// Reused opaque Apalis record identity.
        record_id: String,
    },
    /// PGMQ preserved canonical job identity but allocated a new source message identity.
    PgmqSameJobNewMessage {
        /// Canonical core job identity.
        job_id: String,
        /// Removed dead-queue message identity.
        prior_dead_message_id: i64,
        /// Newly allocated source-queue message identity.
        new_source_message_id: i64,
    },
}

/// Redacted scheduler aggregate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SchedulerStatus {
    /// Unpaused schedules due by the PostgreSQL clock.
    pub due_schedules: u64,
    /// Runs waiting for or retrying handoff.
    pub pending_dispatch: u64,
    /// Runs holding a live execution fence.
    pub active_executions: u64,
    /// Permanently failed runs.
    pub failed_runs: u64,
}

/// Redacted transactional outbox backlog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OutboxStatus {
    /// Every unpublished row.
    pub unpublished_total: u64,
    /// Claimable rows.
    pub ready: u64,
    /// Future-eligible rows.
    pub delayed: u64,
    /// Rows with an active lease.
    pub actively_leased: u64,
    /// Rows at or above the configured attempt ceiling.
    pub exhausted: u64,
    /// Age of the oldest unpublished row.
    pub oldest_unpublished_age_ms: Option<u64>,
}

/// One durable `JetStream` consumer snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NatsConsumerStatus {
    /// Logical selected consumer identifier.
    pub consumer_id: BackendId,
    /// Messages pending first delivery.
    pub lag: u64,
    /// Delivered messages awaiting acknowledgement.
    pub ack_pending: u64,
    /// Current server redelivery count.
    pub redelivered: u64,
}

/// Operator-safe snapshot of one supervised task.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerTaskStatus {
    /// Stable task name.
    pub name: String,
    /// Owning module.
    pub module: String,
    /// Required, degraded, or best-effort criticality.
    pub criticality: &'static str,
    /// Current lifecycle status.
    pub status: &'static str,
    /// Latest terminal result category.
    pub last_exit: Option<&'static str>,
    /// Time since the last heartbeat.
    pub heartbeat_age_ms: Option<u64>,
    /// Whether the heartbeat is stale under its task policy.
    pub heartbeat_stale: bool,
    /// Whether task-specific cancellation has been requested.
    pub cancellation_requested: bool,
}

/// Complete provider-explicit worker operational snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkerStatus {
    /// Collection time.
    pub collected_at: OffsetDateTime,
    /// Whether pre-shutdown drain has begun.
    pub draining: bool,
    /// Whether bounded shutdown has begun.
    pub shutdown_requested: bool,
    /// Supervisor task snapshots.
    pub tasks: Vec<WorkerTaskStatus>,
    /// Selected job providers, retaining native meanings.
    pub jobs: Vec<JobProviderStatus>,
    /// Durable scheduler status when selected.
    pub scheduler: Option<SchedulerStatus>,
    /// Transactional outbox backlog when selected.
    pub outbox: Option<OutboxStatus>,
    /// Selected `JetStream` consumers.
    pub nats: Vec<NatsConsumerStatus>,
}

/// Safe operational failure classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerOperationError {
    /// A requested logical provider was not registered.
    #[error("worker backend was not found")]
    NotFound,
    /// A list bound or provider-native record identity was invalid.
    #[error("worker operation request is invalid")]
    InvalidRequest,
    /// A mutation fence did not match current state.
    #[error("worker control revision conflicted")]
    Conflict,
    /// Replay was rejected because leasing was not paused.
    #[error("worker leasing must be paused")]
    NotPaused,
    /// A selected provider could not complete a bounded operation.
    #[error("worker operation is unavailable")]
    Unavailable,
}

/// Worker diagnostics construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerDiagnosticsBuildError {
    /// A logical component identifier was empty, oversized, or non-portable.
    #[error("worker backend identifier is invalid")]
    InvalidBackendId,
    /// Two selected components used the same logical identifier.
    #[error("worker backend identifier is duplicated")]
    DuplicateBackendId,
}

pub(crate) trait JobOperations: Send + Sync {
    fn backend_id(&self) -> &BackendId;
    fn status(&self) -> BoxFuture<'_, Result<JobProviderStatus, WorkerOperationError>>;
    fn set_paused(
        &self,
        paused: bool,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ControlStatus, WorkerOperationError>>;
    fn dead_records(
        &self,
        limit: u16,
    ) -> BoxFuture<'_, Result<Vec<DeadRecord>, WorkerOperationError>>;
    fn replay_dead(
        &self,
        record_id: &str,
        expected_revision: u64,
    ) -> BoxFuture<'_, Result<ReplayReceipt, WorkerOperationError>>;
}

pub(crate) struct DiagnosticComponents {
    pub jobs: Vec<Arc<dyn JobOperations>>,
    pub scheduler: Option<PostgresScheduler>,
    pub outbox: Option<PostgresOutbox>,
    pub nats: Vec<(BackendId, Arc<NatsJetStreamEvents>)>,
    ids: HashSet<BackendId>,
}

impl DiagnosticComponents {
    pub(crate) fn new() -> Self {
        Self {
            jobs: Vec::new(),
            scheduler: None,
            outbox: None,
            nats: Vec::new(),
            ids: HashSet::new(),
        }
    }

    pub(crate) fn insert_job(
        &mut self,
        source: Arc<dyn JobOperations>,
    ) -> Result<(), WorkerDiagnosticsBuildError> {
        if !self.ids.insert(source.backend_id().clone()) {
            return Err(WorkerDiagnosticsBuildError::DuplicateBackendId);
        }
        self.jobs.push(source);
        Ok(())
    }

    pub(crate) fn insert_nats(
        &mut self,
        id: BackendId,
        source: Arc<NatsJetStreamEvents>,
    ) -> Result<(), WorkerDiagnosticsBuildError> {
        if !self.ids.insert(id.clone()) {
            return Err(WorkerDiagnosticsBuildError::DuplicateBackendId);
        }
        self.nats.push((id, source));
        Ok(())
    }
}

/// Cloneable operational source shared by protected administration and worker lifecycle code.
#[derive(Clone)]
pub struct WorkerDiagnostics {
    control: SupervisorControl,
    jobs: Arc<[Arc<dyn JobOperations>]>,
    scheduler: Option<PostgresScheduler>,
    outbox: Option<PostgresOutbox>,
    nats: Arc<[(BackendId, Arc<NatsJetStreamEvents>)]>,
}

impl fmt::Debug for WorkerDiagnostics {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerDiagnostics")
            .field("job_sources", &self.jobs.len())
            .field("has_scheduler", &self.scheduler.is_some())
            .field("has_outbox", &self.outbox.is_some())
            .field("nats_consumers", &self.nats.len())
            .finish_non_exhaustive()
    }
}

impl WorkerDiagnostics {
    pub(crate) fn from_components(
        control: SupervisorControl,
        components: DiagnosticComponents,
    ) -> Self {
        Self {
            control,
            jobs: components.jobs.into(),
            scheduler: components.scheduler,
            outbox: components.outbox,
            nats: components.nats.into(),
        }
    }

    /// Collects one complete safe snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerOperationError::Unavailable`] when any selected provider cannot answer.
    pub(crate) async fn status(&self) -> Result<WorkerStatus, WorkerOperationError> {
        let job_results = join_all(self.jobs.iter().map(|source| source.status())).await;
        let jobs = job_results.into_iter().collect::<Result<Vec<_>, _>>()?;
        let scheduler = match &self.scheduler {
            Some(scheduler) => {
                let status = scheduler
                    .status()
                    .await
                    .map_err(|_| WorkerOperationError::Unavailable)?;
                Some(SchedulerStatus {
                    due_schedules: status.due_schedules,
                    pending_dispatch: status.pending_dispatch,
                    active_executions: status.active_executions,
                    failed_runs: status.failed_runs,
                })
            }
            None => None,
        };
        let outbox = match &self.outbox {
            Some(outbox) => {
                let status = outbox
                    .backlog_status()
                    .await
                    .map_err(|_| WorkerOperationError::Unavailable)?;
                Some(OutboxStatus {
                    unpublished_total: status.unpublished_total(),
                    ready: status.ready(),
                    delayed: status.delayed(),
                    actively_leased: status.actively_leased(),
                    exhausted: status.exhausted(),
                    oldest_unpublished_age_ms: status.oldest_unpublished_age().map(duration_millis),
                })
            }
            None => None,
        };
        let nats_results = join_all(self.nats.iter().map(|(consumer_id, source)| async move {
            let status = source
                .status()
                .await
                .map_err(|_| WorkerOperationError::Unavailable)?;
            Ok::<_, WorkerOperationError>(NatsConsumerStatus {
                consumer_id: consumer_id.clone(),
                lag: status.lag(),
                ack_pending: u64::try_from(status.ack_pending()).unwrap_or(u64::MAX),
                redelivered: u64::try_from(status.redelivered()).unwrap_or(u64::MAX),
            })
        }))
        .await;
        let nats = nats_results.into_iter().collect::<Result<Vec<_>, _>>()?;
        let now = SystemTime::now();
        let tasks = self
            .control
            .snapshots()
            .into_iter()
            .map(|snapshot| task_status(snapshot, now))
            .collect();
        Ok(WorkerStatus {
            collected_at: OffsetDateTime::now_utc(),
            draining: self.control.is_draining(),
            shutdown_requested: self.control.is_shutdown_requested(),
            tasks,
            jobs,
            scheduler,
            outbox,
            nats,
        })
    }

    /// Applies a provider-native revision-fenced pause or resume.
    pub(crate) async fn set_paused(
        &self,
        backend_id: &BackendId,
        paused: bool,
        expected_revision: u64,
    ) -> Result<ControlStatus, WorkerOperationError> {
        self.job(backend_id)?
            .set_paused(paused, expected_revision)
            .await
    }

    /// Reads at most `limit` redacted terminal records from one explicit provider.
    pub(crate) async fn dead_records(
        &self,
        backend_id: &BackendId,
        limit: u16,
    ) -> Result<Vec<DeadRecord>, WorkerOperationError> {
        self.job(backend_id)?.dead_records(limit).await
    }

    /// Replays one provider-native terminal identity under an explicit control fence.
    pub(crate) async fn replay_dead(
        &self,
        backend_id: &BackendId,
        record_id: &str,
        expected_revision: u64,
    ) -> Result<ReplayReceipt, WorkerOperationError> {
        self.job(backend_id)?
            .replay_dead(record_id, expected_revision)
            .await
    }

    fn job(&self, backend_id: &BackendId) -> Result<&Arc<dyn JobOperations>, WorkerOperationError> {
        self.jobs
            .iter()
            .find(|source| source.backend_id() == backend_id)
            .ok_or(WorkerOperationError::NotFound)
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn task_status(snapshot: TaskSnapshot, now: SystemTime) -> WorkerTaskStatus {
    let heartbeat_stale = snapshot.heartbeat_is_stale(now);
    WorkerTaskStatus {
        name: snapshot.name,
        module: snapshot.module,
        criticality: match snapshot.criticality {
            Criticality::Required => "required",
            Criticality::Degraded => "degraded",
            Criticality::BestEffort => "best_effort",
        },
        status: match snapshot.status {
            TaskStatus::Registered => "registered",
            TaskStatus::Running => "running",
            TaskStatus::Restarting => "restarting",
            TaskStatus::Exited => "exited",
            TaskStatus::Degraded => "degraded",
            TaskStatus::Failed => "failed",
            TaskStatus::Cancelled => "cancelled",
            TaskStatus::Panicked => "panicked",
            TaskStatus::Aborted => "aborted",
        },
        last_exit: snapshot.last_exit.map(|exit| match exit {
            TaskExit::Success => "success",
            TaskExit::Failure(_) => "failure",
            TaskExit::Panic => "panic",
            TaskExit::Cancelled => "cancelled",
            TaskExit::Aborted => "aborted",
        }),
        heartbeat_age_ms: snapshot
            .heartbeat_at
            .and_then(|heartbeat| now.duration_since(heartbeat).ok())
            .map(duration_millis),
        heartbeat_stale,
        cancellation_requested: snapshot.cancellation_requested,
    }
}
