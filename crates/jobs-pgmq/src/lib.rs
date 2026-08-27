//! Typed PGMQ 0.33.7 jobs over the workspace PostgreSQL pool.
//!
//! A [`PgmqJobProvider`] binds one exact Rust [`Job`] definition to deterministic source and
//! dead-letter queues. Runtime connection only verifies that deployment tooling has provisioned
//! both queues. Workers use one-message reads, PGMQ's durable one-based `read_ct`, and local
//! per-worker concurrency and starts-per-minute limits. Horizontal replicas therefore multiply
//! aggregate concurrency and rate.
//!
//! Delivery and acknowledgements are at least once. Every storage transition is fenced to the
//! exact PGMQ `read_ct` leased to the handler, while handlers must still make effects idempotent
//! with [`DeliveryContext::effect_identity`]. The visibility lease exceeds the hard handler
//! timeout and configured grace, and both client and PostgreSQL statement deadlines bound
//! provider-owned storage mutations.

#![forbid(unsafe_code)]

use std::{
    cell::Cell,
    fmt,
    future::{Future, poll_fn},
    marker::PhantomData,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Once},
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use pgmq::{Message, PGMQueueExt, pg_ext::VisibilityTimeoutOffset};
use rand_core::{OsRng, RngCore as _};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EncodedJobEnvelope, EnqueueError,
    EnqueueReceipt, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuer, JobHandler,
    JobId, JobName, QueueName, TypedJobHandler, TypedJobHandlerAdapter, Version,
    limits as job_limits,
};
use omnius_postgres::PostgresPool;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, PgPool};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::task::{JoinError, JoinSet};
use tokio_util::sync::CancellationToken;

thread_local! {
    static REDACT_HANDLER_PANIC: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_PANIC_HOOK: Once = Once::new();

const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MIN_SERVER_TIMEOUT: Duration = Duration::from_millis(1);
const MAX_LEASE_GRACE: Duration = Duration::from_mins(5);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_CLEANUP_INTERVAL: Duration = Duration::from_mins(5);
const MAX_CLEANUP_BATCH_SIZE: u16 = 1_000;
const PHYSICAL_QUEUE_MAX_BYTES: usize = 46;
const FINGERPRINT_BYTES: usize = 19;
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MAX_DEAD_RECORDS: usize = 1_000;
const CONTROL_TABLE: &str = "pgmq.omnius_job_control";
const DEAD_ATTEMPT_HEADER: &str = "omnius-attempt";
const MAX_STORED_JSON_BYTES: usize = job_limits::ENVELOPE_BYTES * 2;

/// Bounded worker and database-operation timing with no connection topology.
#[derive(Clone, Eq, PartialEq)]
pub struct PgmqJobConfig {
    operation_timeout: Duration,
    poll_interval: Duration,
    lease_grace: Duration,
    shutdown_timeout: Duration,
    cleanup_interval: Duration,
    cleanup_batch_size: u16,
}

impl PgmqJobConfig {
    /// Builds fully bounded provider configuration.
    ///
    /// `lease_grace` must exceed `operation_timeout`, and `shutdown_timeout` must not exceed
    /// `lease_grace`, so a cancelled attempt has time to change visibility before bounded drain
    /// ends.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqJobConfigError`] when a duration is zero or excessive, timings are
    /// inconsistent, or the cleanup batch is outside 1 through 1000.
    pub fn new(
        operation_timeout: Duration,
        poll_interval: Duration,
        lease_grace: Duration,
        shutdown_timeout: Duration,
        cleanup_interval: Duration,
        cleanup_batch_size: u16,
    ) -> Result<Self, PgmqJobConfigError> {
        let config = Self {
            operation_timeout,
            poll_interval,
            lease_grace,
            shutdown_timeout,
            cleanup_interval,
            cleanup_batch_size,
        };
        config.validate()?;
        Ok(config)
    }

    /// Per-operation database deadline.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Delay between empty one-message reads.
    #[must_use]
    pub const fn poll_interval(&self) -> Duration {
        self.poll_interval
    }

    /// Time reserved after the hard handler timeout for bounded storage work.
    #[must_use]
    pub const fn lease_grace(&self) -> Duration {
        self.lease_grace
    }

    /// Maximum cancellation drain time.
    #[must_use]
    pub const fn shutdown_timeout(&self) -> Duration {
        self.shutdown_timeout
    }

    /// Interval between automatic retention passes.
    #[must_use]
    pub const fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }

    /// Maximum rows deleted by one retention statement.
    #[must_use]
    pub const fn cleanup_batch_size(&self) -> u16 {
        self.cleanup_batch_size
    }

    fn validate(&self) -> Result<(), PgmqJobConfigError> {
        bounded_duration(
            self.operation_timeout,
            MAX_OPERATION_TIMEOUT,
            PgmqJobConfigError::OperationTimeout,
        )?;
        bounded_duration(
            self.poll_interval,
            MAX_POLL_INTERVAL,
            PgmqJobConfigError::PollInterval,
        )?;
        bounded_duration(
            self.lease_grace,
            MAX_LEASE_GRACE,
            PgmqJobConfigError::LeaseGrace,
        )?;
        bounded_duration(
            self.shutdown_timeout,
            MAX_SHUTDOWN_TIMEOUT,
            PgmqJobConfigError::ShutdownTimeout,
        )?;
        bounded_duration(
            self.cleanup_interval,
            MAX_CLEANUP_INTERVAL,
            PgmqJobConfigError::CleanupInterval,
        )?;
        if self.lease_grace <= self.operation_timeout || self.shutdown_timeout > self.lease_grace {
            return Err(PgmqJobConfigError::LeaseTiming);
        }
        if self.cleanup_batch_size == 0 || self.cleanup_batch_size > MAX_CLEANUP_BATCH_SIZE {
            return Err(PgmqJobConfigError::CleanupBatchSize);
        }
        Ok(())
    }
}

impl Default for PgmqJobConfig {
    fn default() -> Self {
        Self {
            operation_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(250),
            lease_grace: Duration::from_secs(10),
            shutdown_timeout: Duration::from_secs(10),
            cleanup_interval: Duration::from_secs(30),
            cleanup_batch_size: 128,
        }
    }
}

impl fmt::Debug for PgmqJobConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgmqJobConfig")
            .field("operation_timeout", &self.operation_timeout)
            .field("poll_interval", &self.poll_interval)
            .field("lease_grace", &self.lease_grace)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("cleanup_interval", &self.cleanup_interval)
            .field("cleanup_batch_size", &self.cleanup_batch_size)
            .finish()
    }
}

/// Secret-safe configuration validation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqJobConfigError {
    /// A database operation deadline was zero or excessive.
    #[error("PGMQ operation timeout is invalid")]
    OperationTimeout,
    /// The empty-queue polling interval was zero or excessive.
    #[error("PGMQ poll interval is invalid")]
    PollInterval,
    /// The post-handler lease grace was zero or excessive.
    #[error("PGMQ lease grace is invalid")]
    LeaseGrace,
    /// The bounded drain deadline was zero or excessive.
    #[error("PGMQ shutdown timeout is invalid")]
    ShutdownTimeout,
    /// The retention interval was zero or excessive.
    #[error("PGMQ cleanup interval is invalid")]
    CleanupInterval,
    /// Lease, storage, and shutdown timings were inconsistent.
    #[error("PGMQ lease timing is invalid")]
    LeaseTiming,
    /// The cleanup batch was outside 1 through 1000.
    #[error("PGMQ cleanup batch size is invalid")]
    CleanupBatchSize,
}

/// Validated exact typed routing derived from a [`Job`] declaration.
pub struct PgmqJobDefinition<J> {
    name: JobName,
    version: Version,
    queue: QueueName,
    source: String,
    dead: String,
    marker: PhantomData<fn() -> J>,
}

impl<J: Job> PgmqJobDefinition<J> {
    /// Validates the complete declaration and derives deterministic PGMQ-safe queue names.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqJobDefinitionError`] for an unsupported destination policy, invalid core
    /// declaration, or identifier that cannot meet PGMQ's lowercase 46-byte physical-name bound.
    pub fn new() -> Result<Self, PgmqJobDefinitionError> {
        let name =
            JobName::try_from(J::NAME).map_err(|_| PgmqJobDefinitionError::InvalidDeclaration)?;
        let version =
            Version::new(J::VERSION).map_err(|_| PgmqJobDefinitionError::InvalidDeclaration)?;
        if matches!(J::POLICY.dead_letter(), DeadLetterPolicy::Destination(_)) {
            return Err(PgmqJobDefinitionError::UnsupportedDeadLetterDestination);
        }
        J::POLICY
            .validate_for(J::VERSION)
            .map_err(|_| PgmqJobDefinitionError::InvalidDeclaration)?;
        if !valid_metrics_prefix(J::METRICS_PREFIX) || !valid_runbook(J::RUNBOOK) {
            return Err(PgmqJobDefinitionError::InvalidDeclaration);
        }
        let queue = QueueName::try_from(J::POLICY.queue())
            .map_err(|_| PgmqJobDefinitionError::InvalidDeclaration)?;
        let fingerprint = dispatch_policy_fingerprint::<J>();
        let source = physical_queue_name('j', J::VERSION, &fingerprint)?;
        let dead = physical_queue_name('d', J::VERSION, &fingerprint)?;
        Ok(Self {
            name,
            version,
            queue,
            source,
            dead,
            marker: PhantomData,
        })
    }

    /// Stable job name.
    #[must_use]
    pub const fn name(&self) -> &JobName {
        &self.name
    }

    /// Exact accepted wire version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Logical core queue returned in enqueue receipts.
    #[must_use]
    pub const fn queue(&self) -> &QueueName {
        &self.queue
    }

    fn header_matches(&self, envelope: &EncodedJobEnvelope) -> bool {
        envelope.job_name() == &self.name
            && envelope.version() == self.version
            && envelope.queue() == &self.queue
            && envelope.attempt_policy().max_attempts() == J::POLICY.max_attempts()
            && envelope.attempt_policy().timeout() == J::POLICY.timeout()
    }

    fn accepts(&self, envelope: &EncodedJobEnvelope) -> bool {
        if !self.header_matches(envelope) {
            return false;
        }
        let Ok(typed) = envelope.decode::<J>() else {
            return false;
        };
        let Ok(canonical) = typed.encode() else {
            return false;
        };
        canonical.bytes() == envelope.bytes()
    }
}

impl<J> Clone for PgmqJobDefinition<J> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            version: self.version,
            queue: self.queue.clone(),
            source: self.source.clone(),
            dead: self.dead.clone(),
            marker: PhantomData,
        }
    }
}

impl<J> fmt::Debug for PgmqJobDefinition<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgmqJobDefinition")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("queue", &self.queue)
            .field("source", &"[REDACTED]")
            .field("dead", &"[REDACTED]")
            .field("physical_queues", &"[REDACTED]")
            .finish()
    }
}

/// Safe typed-definition failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqJobDefinitionError {
    /// Core name, version, policy, metrics prefix, or runbook is invalid.
    #[error("PGMQ job declaration is invalid")]
    InvalidDeclaration,
    /// PGMQ cannot preserve a caller-selected dead-letter destination.
    #[error("PGMQ dead-letter destinations are unsupported")]
    UnsupportedDeadLetterDestination,
    /// A derived physical queue identifier could not meet the fixed PGMQ bound.
    #[error("PGMQ physical queue identifier is invalid")]
    InvalidPhysicalQueue,
}

/// Safe provisioning failure for explicit deployment tooling.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqProvisionError {
    /// Provider configuration was invalid.
    #[error(transparent)]
    Config(#[from] PgmqJobConfigError),
    /// Typed declaration was invalid.
    #[error(transparent)]
    Definition(#[from] PgmqJobDefinitionError),
    /// Embedded installation or queue creation exceeded its deadline.
    #[error("PGMQ provisioning timed out")]
    Timeout,
    /// Embedded installation or queue creation failed.
    #[error("PGMQ provisioning is unavailable")]
    Unavailable,
}

/// Safe verification-only runtime connection failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqConnectError {
    /// Provider configuration was invalid.
    #[error(transparent)]
    Config(#[from] PgmqJobConfigError),
    /// Typed declaration was invalid.
    #[error(transparent)]
    Definition(#[from] PgmqJobDefinitionError),
    /// Queue metadata could not be read before the configured deadline.
    #[error("PGMQ runtime verification is unavailable")]
    Unavailable,
    /// Deployment tooling has not provisioned both exact typed queues.
    #[error("PGMQ queues are not provisioned")]
    NotProvisioned,
    /// A payload table still grants `pg_monitor` read access.
    #[error("PGMQ payload table permissions are insecure")]
    InsecurePermissions,
}

/// Redacted point-in-time status for one typed source and dead-letter pair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PgmqJobDiagnostics {
    source_total: u64,
    source_visible: u64,
    source_leased: u64,
    source_delayed: u64,
    dead_total: u64,
    dead_visible: u64,
    completed: u64,
    oldest_age: Option<Duration>,
    paused: bool,
    control_revision: i64,
}

impl PgmqJobDiagnostics {
    /// All source records.
    #[must_use]
    pub const fn source_total(self) -> u64 {
        self.source_total
    }

    /// Source records currently eligible for a read.
    #[must_use]
    pub const fn source_visible(self) -> u64 {
        self.source_visible
    }

    /// Previously read source records whose visibility deadline is in the future.
    #[must_use]
    pub const fn source_leased(self) -> u64 {
        self.source_leased
    }

    /// Never-read source records whose initial visibility deadline is in the future.
    #[must_use]
    pub const fn source_delayed(self) -> u64 {
        self.source_delayed
    }

    /// All terminal records retained in the separate dead-letter queue.
    #[must_use]
    pub const fn dead_total(self) -> u64 {
        self.dead_total
    }

    /// Dead-letter records currently visible and not leased by provider tooling.
    #[must_use]
    pub const fn dead_visible(self) -> u64 {
        self.dead_visible
    }

    /// Successfully processed records retained in the source archive.
    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Age of the oldest outstanding source record.
    #[must_use]
    pub const fn oldest_age(self) -> Option<Duration> {
        self.oldest_age
    }

    /// Whether new source leases are administratively paused.
    #[must_use]
    pub const fn paused(self) -> bool {
        self.paused
    }

    /// Durable administrative-control revision.
    #[must_use]
    pub const fn control_revision(self) -> i64 {
        self.control_revision
    }
}

/// Safe bounded diagnostics failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqDiagnosticsError {
    /// Provider tables could not answer the bounded status query.
    #[error("PGMQ diagnostics are unavailable")]
    Unavailable,
}

/// Durable pause state for one typed provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgmqControlState {
    paused: bool,
    revision: i64,
}

impl PgmqControlState {
    /// Whether workers may acquire new source leases.
    #[must_use]
    pub const fn paused(self) -> bool {
        self.paused
    }

    /// Revision required by the next control mutation or replay.
    #[must_use]
    pub const fn revision(self) -> i64 {
        self.revision
    }
}

/// Redacted metadata for one retained PGMQ dead-letter record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgmqDeadRecord {
    record_id: i64,
    job_id: JobId,
    created_at: OffsetDateTime,
    failed_at: OffsetDateTime,
    attempt: u16,
    envelope_bytes: usize,
}

impl PgmqDeadRecord {
    /// Provider-native dead-letter message identifier.
    #[must_use]
    pub const fn record_id(self) -> i64 {
        self.record_id
    }

    /// Stable core job identifier.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Original core-envelope creation time.
    #[must_use]
    pub const fn created_at(self) -> OffsetDateTime {
        self.created_at
    }

    /// Time at which PGMQ retained the terminal envelope.
    #[must_use]
    pub const fn failed_at(self) -> OffsetDateTime {
        self.failed_at
    }

    /// Explicit terminal attempt, or the safe historical terminal attempt for a legacy row.
    #[must_use]
    pub const fn attempt(self) -> u16 {
        self.attempt
    }

    /// Stored JSON envelope size without envelope content.
    #[must_use]
    pub const fn envelope_bytes(self) -> usize {
        self.envelope_bytes
    }
}

/// Identity behavior of a successful PGMQ dead-letter replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgmqReplayIdentity {
    /// The core job UUID is preserved while PGMQ allocates a new source message identifier.
    SameJobNewMessage,
}

/// Receipt for one exact transactional PGMQ replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PgmqReplayReceipt {
    job_id: JobId,
    prior_dead_message_id: i64,
    new_source_message_id: i64,
    identity: PgmqReplayIdentity,
    revision: i64,
}

impl PgmqReplayReceipt {
    /// Preserved core job identifier.
    #[must_use]
    pub const fn job_id(self) -> JobId {
        self.job_id
    }

    /// Removed dead-letter message identifier.
    #[must_use]
    pub const fn prior_dead_message_id(self) -> i64 {
        self.prior_dead_message_id
    }

    /// Newly allocated source-queue message identifier.
    #[must_use]
    pub const fn new_source_message_id(self) -> i64 {
        self.new_source_message_id
    }

    /// Provider-native identity behavior.
    #[must_use]
    pub const fn identity(self) -> PgmqReplayIdentity {
        self.identity
    }

    /// Control revision under which replay was fenced.
    #[must_use]
    pub const fn revision(self) -> i64 {
        self.revision
    }
}

/// Secret-safe administrative operation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqAdminError {
    /// Requested dead-letter list size is zero or exceeds the provider bound.
    #[error("PGMQ dead-letter limit is invalid")]
    InvalidLimit,
    /// The expected durable control revision is stale or invalid.
    #[error("PGMQ control revision conflict")]
    RevisionConflict,
    /// Replay is forbidden until leasing is durably paused.
    #[error("PGMQ replay requires a paused worker")]
    NotPaused,
    /// The requested provider-native dead-letter record does not exist.
    #[error("PGMQ dead-letter record was not found")]
    RecordNotFound,
    /// Stored redacted metadata or the exact stored envelope is invalid.
    #[error("PGMQ dead-letter record is invalid")]
    CorruptRecord,
    /// A bounded provider-owned administrative operation failed.
    #[error("PGMQ administration is unavailable")]
    Unavailable,
}

/// Rows removed by one bounded retention pass.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PgmqCleanupResult {
    completed_removed: u64,
    dead_removed: u64,
}

impl PgmqCleanupResult {
    /// Expired successful archive records removed.
    #[must_use]
    pub const fn completed_removed(self) -> u64 {
        self.completed_removed
    }

    /// Expired visible dead-letter records removed.
    #[must_use]
    pub const fn dead_removed(self) -> u64 {
        self.dead_removed
    }
}

/// Safe bounded retention failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqCleanupError {
    /// A provider-owned retention query failed.
    #[error("PGMQ retention cleanup is unavailable")]
    Unavailable,
}

/// Safe worker lifecycle failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqWorkerError {
    /// A bounded lease, acknowledgement, visibility, terminal transfer, or retention operation
    /// failed. Payloads and database details are never retained.
    #[error("PGMQ worker failed")]
    Runtime,
}

/// Typed PGMQ provider and object-safe core enqueuer.
pub struct PgmqJobProvider<J> {
    pool: PgPool,
    queue: PGMQueueExt,
    definition: PgmqJobDefinition<J>,
    config: PgmqJobConfig,
    diagnostics_sql: String,
    archive_cleanup_sql: String,
    dead_cleanup_sql: String,
    dead_records_sql: String,
    replay_size_sql: String,
    replay_message_sql: String,
    dead_delete_sql: String,
    fence_sql: String,
    visibility_sql: String,
    delete_sql: String,
}

type DeadRow = (
    i64,
    Option<String>,
    Option<String>,
    OffsetDateTime,
    Option<i32>,
    i32,
    i64,
);

async fn verify_runtime_queues<J>(
    queue: &PGMQueueExt,
    definition: &PgmqJobDefinition<J>,
    operation_timeout: Duration,
) -> Result<(), PgmqConnectError> {
    let queues = tokio::time::timeout(operation_timeout, queue.list_queues())
        .await
        .map_err(|_| PgmqConnectError::Unavailable)?
        .map_err(|_| PgmqConnectError::Unavailable)?;
    let source_found = queues.as_ref().is_some_and(|queues| {
        queues.iter().any(|candidate| {
            candidate.queue_name == definition.source
                && !candidate.is_unlogged
                && !candidate.is_partitioned
        })
    });
    let dead_found = queues.as_ref().is_some_and(|queues| {
        queues.iter().any(|candidate| {
            candidate.queue_name == definition.dead
                && !candidate.is_unlogged
                && !candidate.is_partitioned
        })
    });
    if !source_found || !dead_found {
        return Err(PgmqConnectError::NotProvisioned);
    }
    Ok(())
}

async fn verify_runtime_control<J>(
    pool: &PgPool,
    definition: &PgmqJobDefinition<J>,
    operation_timeout: Duration,
) -> Result<(), PgmqConnectError> {
    let control_table_found = tokio::time::timeout(
        operation_timeout,
        sqlx::query_scalar::<_, bool>("SELECT to_regclass($1::text) IS NOT NULL")
            .bind(CONTROL_TABLE)
            .fetch_one(pool),
    )
    .await
    .map_err(|_| PgmqConnectError::Unavailable)?
    .map_err(|_| PgmqConnectError::Unavailable)?;
    if !control_table_found {
        return Err(PgmqConnectError::NotProvisioned);
    }
    let control_row_found = tokio::time::timeout(
        operation_timeout,
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (\
                 SELECT 1 FROM pgmq.omnius_job_control \
                 WHERE queue_name = $1 AND revision >= 0\
             )",
        )
        .bind(&definition.source)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| PgmqConnectError::Unavailable)?
    .map_err(|_| PgmqConnectError::Unavailable)?;
    if !control_row_found {
        return Err(PgmqConnectError::NotProvisioned);
    }
    Ok(())
}

async fn verify_runtime_permissions<J>(
    pool: &PgPool,
    definition: &PgmqJobDefinition<J>,
    operation_timeout: Duration,
) -> Result<(), PgmqConnectError> {
    let payload_tables = payload_table_names(definition);
    let pg_monitor_can_select = tokio::time::timeout(
        operation_timeout,
        sqlx::query_scalar::<_, bool>(
            "SELECT has_table_privilege('pg_monitor', $1::text, 'SELECT') \
                 OR has_table_privilege('pg_monitor', $2::text, 'SELECT') \
                 OR has_table_privilege('pg_monitor', $3::text, 'SELECT') \
                 OR has_table_privilege('pg_monitor', $4::text, 'SELECT') \
                 OR has_table_privilege('pg_monitor', $5::text, 'SELECT')",
        )
        .bind(&payload_tables[0])
        .bind(&payload_tables[1])
        .bind(&payload_tables[2])
        .bind(&payload_tables[3])
        .bind(CONTROL_TABLE)
        .fetch_one(pool),
    )
    .await
    .map_err(|_| PgmqConnectError::Unavailable)?
    .map_err(|_| PgmqConnectError::Unavailable)?;
    if pg_monitor_can_select {
        return Err(PgmqConnectError::InsecurePermissions);
    }
    Ok(())
}

impl<J: Job> PgmqJobProvider<J> {
    /// Installs the pinned embedded PGMQ SQL, creates both exact typed queues and their durable
    /// control row, and removes `pg_monitor` access to provider-owned tables.
    ///
    /// This is the only schema-mutating API in the crate. It is intended for deployment tooling
    /// and disposable test setup, never application runtime construction.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqProvisionError`] for invalid configuration or declaration, timeout, embedded
    /// installation, queue creation, or payload-permission hardening failure.
    pub async fn provision(
        pool: &PostgresPool,
        config: &PgmqJobConfig,
    ) -> Result<(), PgmqProvisionError> {
        config.validate()?;
        let definition = PgmqJobDefinition::<J>::new()?;
        let sqlx_pool = pool.sqlx_pool();
        let queue = PGMQueueExt::new_with_pool(sqlx_pool.clone()).await;
        run_with_timeout(config.operation_timeout, queue.install_sql_from_embedded())
            .await
            .map_err(|error| map_provision_result(&error))?;
        run_with_timeout(config.operation_timeout, queue.create(&definition.source))
            .await
            .map_err(|error| map_provision_result(&error))?;
        run_with_timeout(config.operation_timeout, queue.create(&definition.dead))
            .await
            .map_err(|error| map_provision_result(&error))?;
        provision_control_and_harden_acls(&sqlx_pool, &definition, config.operation_timeout)
            .await?;
        Ok(())
    }

    /// Verifies both queues and binds the shared `SQLx` pool without mutating database schema.
    ///
    /// Runtime construction never installs SQL, initializes an extension, creates a queue, purges,
    /// drops, or performs retention cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqConnectError`] for invalid configuration or declaration, bounded metadata
    /// failure, missing provisioning, or insecure payload-table permissions.
    pub async fn connect(
        pool: PostgresPool,
        config: PgmqJobConfig,
    ) -> Result<Self, PgmqConnectError> {
        config.validate()?;
        let definition = PgmqJobDefinition::<J>::new()?;
        let sqlx_pool = pool.sqlx_pool();
        let queue = PGMQueueExt::new_with_pool(sqlx_pool.clone()).await;
        verify_runtime_queues(&queue, &definition, config.operation_timeout).await?;
        verify_runtime_control(&sqlx_pool, &definition, config.operation_timeout).await?;
        verify_runtime_permissions(&sqlx_pool, &definition, config.operation_timeout).await?;
        let diagnostics_sql = format!(
            "WITH source AS (\
                 SELECT count(*)::bigint AS total,\
                        count(*) FILTER (WHERE vt <= statement_timestamp())::bigint AS visible,\
                        count(*) FILTER (\
                            WHERE vt > statement_timestamp() AND read_ct > 0\
                        )::bigint AS leased,\
                        count(*) FILTER (\
                            WHERE vt > statement_timestamp() AND read_ct = 0\
                        )::bigint AS delayed,\
                        CASE WHEN min(enqueued_at) IS NULL THEN NULL \
                             ELSE GREATEST(\
                                 0::numeric,\
                                 floor(extract(epoch FROM (\
                                     statement_timestamp() - min(enqueued_at)\
                                 )) * 1000)\
                             )::bigint \
                        END AS oldest_age_ms \
                 FROM pgmq.q_{}\
             ), dead AS (\
                 SELECT count(*)::bigint AS total,\
                        count(*) FILTER (WHERE vt <= statement_timestamp())::bigint AS visible \
                 FROM pgmq.q_{}\
             ), archive AS (\
                 SELECT count(*)::bigint AS completed FROM pgmq.a_{}\
             ), control AS (\
                 SELECT paused, revision FROM pgmq.omnius_job_control WHERE queue_name = $1\
             ) \
             SELECT source.total, source.visible, source.leased, source.delayed,\
                    source.oldest_age_ms, dead.total, dead.visible, archive.completed,\
                    control.paused, control.revision \
             FROM source CROSS JOIN dead CROSS JOIN archive CROSS JOIN control",
            definition.source, definition.dead, definition.source
        );
        let archive_cleanup_sql = cleanup_sql("a", &definition.source, "archived_at", false);
        let dead_cleanup_sql = cleanup_sql("q", &definition.dead, "enqueued_at", true);
        let dead_records_sql = format!(
            "SELECT msg_id, message->>'id', message->>'created_at', enqueued_at,\
                    NULLIF(headers->>'{DEAD_ATTEMPT_HEADER}', '')::integer, read_ct,\
                    octet_length(message::text)::bigint \
             FROM pgmq.q_{} \
             ORDER BY enqueued_at, msg_id LIMIT $1",
            definition.dead
        );
        let replay_size_sql = format!(
            "SELECT octet_length(message::text)::bigint \
             FROM pgmq.q_{} WHERE msg_id = $1 FOR UPDATE",
            definition.dead
        );
        let replay_message_sql = format!(
            "SELECT message FROM pgmq.q_{} WHERE msg_id = $1",
            definition.dead
        );
        let dead_delete_sql = format!("DELETE FROM pgmq.q_{} WHERE msg_id = $1", definition.dead);
        let fence_sql = format!(
            "SELECT read_ct FROM pgmq.q_{} \
             WHERE msg_id = $1 AND read_ct = $2 FOR UPDATE",
            definition.source
        );
        let visibility_sql = format!(
            "UPDATE pgmq.q_{} \
             SET vt = clock_timestamp() + ($3::integer * interval '1 second') \
             WHERE msg_id = $1 AND read_ct = $2",
            definition.source
        );
        let delete_sql = format!(
            "DELETE FROM pgmq.q_{} WHERE msg_id = $1 AND read_ct = $2",
            definition.source
        );
        Ok(Self {
            pool: sqlx_pool,
            queue,
            definition,
            config,
            diagnostics_sql,
            archive_cleanup_sql,
            dead_cleanup_sql,
            dead_records_sql,
            replay_size_sql,
            replay_message_sql,
            dead_delete_sql,
            fence_sql,
            visibility_sql,
            delete_sql,
        })
    }

    /// Validated logical typed definition. Physical queue identifiers remain redacted.
    #[must_use]
    pub const fn definition(&self) -> &PgmqJobDefinition<J> {
        &self.definition
    }

    /// Enqueues through a caller-owned `SQLx` connection or transaction.
    ///
    /// This method never begins, commits, rolls back, or retries a transaction. Its returned job
    /// identifier means the statement succeeded in the caller's transaction; durability still
    /// depends on the caller committing that transaction.
    ///
    /// # Errors
    ///
    /// Returns [`EnqueueError::InvalidEnvelope`] for any declaration, policy, typed payload, or
    /// canonical-object mismatch; [`EnqueueError::Rejected`] for an unrepresentable delay; and
    /// [`EnqueueError::Unavailable`] for bounded PGMQ/SQLx failure.
    pub async fn enqueue_with(
        &self,
        connection: &mut PgConnection,
        envelope: EncodedJobEnvelope,
    ) -> Result<JobId, EnqueueError> {
        let prepared = self.prepare_enqueue(&envelope)?;
        tokio::time::timeout(
            self.config.operation_timeout,
            self.queue.send_delay_with_cxn(
                &self.definition.source,
                &prepared.message,
                VisibilityTimeoutOffset::seconds(prepared.delay_seconds),
                connection,
            ),
        )
        .await
        .map_err(|_| EnqueueError::Unavailable)?
        .map_err(|_| EnqueueError::Unavailable)?;
        Ok(prepared.job_id)
    }

    /// Reads one statement-consistent redacted provider status directly from PGMQ tables.
    ///
    /// Initial delay (`read_ct = 0`) and an active or retry lease (`read_ct > 0`) are reported
    /// separately. No envelope column is selected.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqDiagnosticsError::Unavailable`] when provider state is missing, inconsistent,
    /// fails, or exceeds the configured operation deadline.
    pub async fn diagnostics(&self) -> Result<PgmqJobDiagnostics, PgmqDiagnosticsError> {
        type DiagnosticsRow = (i64, i64, i64, i64, Option<i64>, i64, i64, i64, bool, i64);
        let row = tokio::time::timeout(
            self.config.operation_timeout,
            sqlx::query_as::<_, DiagnosticsRow>(&self.diagnostics_sql)
                .bind(&self.definition.source)
                .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| PgmqDiagnosticsError::Unavailable)?
        .map_err(|_| PgmqDiagnosticsError::Unavailable)?
        .ok_or(PgmqDiagnosticsError::Unavailable)?;
        let source_total = nonnegative(row.0)?;
        let source_visible = nonnegative(row.1)?;
        let source_leased = nonnegative(row.2)?;
        let source_delayed = nonnegative(row.3)?;
        let classified = source_visible
            .checked_add(source_leased)
            .and_then(|count| count.checked_add(source_delayed))
            .ok_or(PgmqDiagnosticsError::Unavailable)?;
        if classified != source_total || row.9 < 0 {
            return Err(PgmqDiagnosticsError::Unavailable);
        }
        let oldest_age = row
            .4
            .map(nonnegative)
            .transpose()?
            .map(Duration::from_millis);
        Ok(PgmqJobDiagnostics {
            source_total,
            source_visible,
            source_leased,
            source_delayed,
            dead_total: nonnegative(row.5)?,
            dead_visible: nonnegative(row.6)?,
            completed: nonnegative(row.7)?,
            oldest_age,
            paused: row.8,
            control_revision: row.9,
        })
    }

    /// Reads the durable provider control row without exposing physical routing.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqAdminError::Unavailable`] when the provisioned row cannot be read within the
    /// configured operation deadline.
    pub async fn control_state(&self) -> Result<PgmqControlState, PgmqAdminError> {
        let state = tokio::time::timeout(
            self.config.operation_timeout,
            sqlx::query_as::<_, (bool, i64)>(
                "SELECT paused, revision FROM pgmq.omnius_job_control WHERE queue_name = $1",
            )
            .bind(&self.definition.source)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| PgmqAdminError::Unavailable)?
        .map_err(|_| PgmqAdminError::Unavailable)?
        .ok_or(PgmqAdminError::Unavailable)?;
        if state.1 < 0 {
            return Err(PgmqAdminError::Unavailable);
        }
        Ok(PgmqControlState {
            paused: state.0,
            revision: state.1,
        })
    }

    /// Durably pauses or resumes new source leases under an optimistic revision fence.
    ///
    /// A successful pause waits for any source-read transaction already holding the control row,
    /// so no lease can commit after the pause commits.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqAdminError::RevisionConflict`] for a stale revision and
    /// [`PgmqAdminError::Unavailable`] for a missing row, bounded timeout, or database failure.
    pub async fn set_paused(
        &self,
        paused: bool,
        expected_revision: i64,
    ) -> Result<PgmqControlState, PgmqAdminError> {
        if expected_revision < 0 {
            return Err(PgmqAdminError::RevisionConflict);
        }
        let database_deadline = Instant::now()
            .checked_add(self.config.operation_timeout)
            .ok_or(PgmqAdminError::Unavailable)?;
        let operation = async {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            set_local_database_timeouts(&mut transaction, database_deadline)
                .await
                .map_err(|()| PgmqAdminError::Unavailable)?;
            let current = sqlx::query_scalar::<_, i64>(
                "SELECT revision FROM pgmq.omnius_job_control \
                 WHERE queue_name = $1 FOR UPDATE",
            )
            .bind(&self.definition.source)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| PgmqAdminError::Unavailable)?
            .ok_or(PgmqAdminError::Unavailable)?;
            if current != expected_revision {
                return Err(PgmqAdminError::RevisionConflict);
            }
            let state = sqlx::query_as::<_, (bool, i64)>(
                "UPDATE pgmq.omnius_job_control \
                 SET paused = $2, revision = revision + 1 \
                 WHERE queue_name = $1 AND revision = $3 \
                 RETURNING paused, revision",
            )
            .bind(&self.definition.source)
            .bind(paused)
            .bind(expected_revision)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| PgmqAdminError::Unavailable)?
            .ok_or(PgmqAdminError::RevisionConflict)?;
            transaction
                .commit()
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            Ok(PgmqControlState {
                paused: state.0,
                revision: state.1,
            })
        };
        tokio::time::timeout(self.config.operation_timeout, operation)
            .await
            .map_err(|_| PgmqAdminError::Unavailable)?
    }

    /// Lists a bounded oldest-first page of redacted dead-letter metadata.
    ///
    /// The provider query selects only identifiers, timestamps, terminal-attempt metadata, and the
    /// JSON byte count. Legacy rows without the provider attempt header use their durable dead-row
    /// read count when available, otherwise the job's terminal attempt, after envelope metadata
    /// validation. It never selects an envelope or payload.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqAdminError::InvalidLimit`] outside `1..=1000`,
    /// [`PgmqAdminError::CorruptRecord`] for invalid stored metadata, or
    /// [`PgmqAdminError::Unavailable`] for a bounded query failure.
    pub async fn dead_records(&self, limit: usize) -> Result<Vec<PgmqDeadRecord>, PgmqAdminError> {
        if !(1..=MAX_DEAD_RECORDS).contains(&limit) {
            return Err(PgmqAdminError::InvalidLimit);
        }
        let limit = i64::try_from(limit).map_err(|_| PgmqAdminError::InvalidLimit)?;
        let rows = tokio::time::timeout(
            self.config.operation_timeout,
            sqlx::query_as::<_, DeadRow>(&self.dead_records_sql)
                .bind(limit)
                .fetch_all(&self.pool),
        )
        .await
        .map_err(|_| PgmqAdminError::Unavailable)?
        .map_err(|_| PgmqAdminError::Unavailable)?;
        rows.into_iter()
            .map(|row| {
                let record_id = row.0;
                let job_id = row
                    .1
                    .ok_or(PgmqAdminError::CorruptRecord)?
                    .parse()
                    .map_err(|_| PgmqAdminError::CorruptRecord)?;
                let created_at =
                    OffsetDateTime::parse(&row.2.ok_or(PgmqAdminError::CorruptRecord)?, &Rfc3339)
                        .map_err(|_| PgmqAdminError::CorruptRecord)?;
                let terminal_attempt = J::POLICY.max_attempts();
                let historical_attempt = u16::try_from(row.5)
                    .ok()
                    .filter(|attempt| (1..=terminal_attempt).contains(attempt))
                    .unwrap_or(terminal_attempt);
                let attempt = match row.4 {
                    Some(attempt) => {
                        u16::try_from(attempt).map_err(|_| PgmqAdminError::CorruptRecord)?
                    }
                    None => historical_attempt,
                };
                let envelope_bytes =
                    usize::try_from(row.6).map_err(|_| PgmqAdminError::CorruptRecord)?;
                if record_id <= 0
                    || attempt == 0
                    || envelope_bytes == 0
                    || envelope_bytes > MAX_STORED_JSON_BYTES
                {
                    return Err(PgmqAdminError::CorruptRecord);
                }
                Ok(PgmqDeadRecord {
                    record_id,
                    job_id,
                    created_at,
                    failed_at: row.3,
                    attempt,
                    envelope_bytes,
                })
            })
            .collect()
    }

    /// Replays one exact stored dead-letter JSON value while the provider is durably paused.
    ///
    /// The control row and exact dead record are locked in one transaction. PGMQ allocates a new
    /// source message identifier while the core job UUID and complete stored envelope are retained.
    ///
    /// # Errors
    ///
    /// Returns an administrative fence, pause, record, validation, timeout, or availability error.
    pub async fn replay_dead(
        &self,
        dead_msg_id: i64,
        expected_revision: i64,
    ) -> Result<PgmqReplayReceipt, PgmqAdminError> {
        if expected_revision < 0 {
            return Err(PgmqAdminError::RevisionConflict);
        }
        if dead_msg_id <= 0 {
            return Err(PgmqAdminError::RecordNotFound);
        }
        let database_deadline = Instant::now()
            .checked_add(self.config.operation_timeout)
            .ok_or(PgmqAdminError::Unavailable)?;
        let operation = async {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            set_local_database_timeouts(&mut transaction, database_deadline)
                .await
                .map_err(|()| PgmqAdminError::Unavailable)?;
            let control = sqlx::query_as::<_, (bool, i64)>(
                "SELECT paused, revision FROM pgmq.omnius_job_control \
                 WHERE queue_name = $1 FOR UPDATE",
            )
            .bind(&self.definition.source)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| PgmqAdminError::Unavailable)?
            .ok_or(PgmqAdminError::Unavailable)?;
            if control.1 != expected_revision {
                return Err(PgmqAdminError::RevisionConflict);
            }
            if !control.0 {
                return Err(PgmqAdminError::NotPaused);
            }
            let envelope_bytes = sqlx::query_scalar::<_, i64>(&self.replay_size_sql)
                .bind(dead_msg_id)
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?
                .ok_or(PgmqAdminError::RecordNotFound)?;
            let envelope_bytes =
                usize::try_from(envelope_bytes).map_err(|_| PgmqAdminError::CorruptRecord)?;
            if envelope_bytes > MAX_STORED_JSON_BYTES {
                return Err(PgmqAdminError::CorruptRecord);
            }
            let message = sqlx::query_scalar::<_, Value>(&self.replay_message_sql)
                .bind(dead_msg_id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            let job_id = self.validate_replay_message(&message)?;
            let new_source_message_id = self
                .queue
                .send_with_cxn(&self.definition.source, &message, &mut *transaction)
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            let removed = sqlx::query(&self.dead_delete_sql)
                .bind(dead_msg_id)
                .execute(&mut *transaction)
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?
                .rows_affected();
            if removed != 1 || new_source_message_id <= 0 {
                return Err(PgmqAdminError::Unavailable);
            }
            transaction
                .commit()
                .await
                .map_err(|_| PgmqAdminError::Unavailable)?;
            Ok(PgmqReplayReceipt {
                job_id,
                prior_dead_message_id: dead_msg_id,
                new_source_message_id,
                identity: PgmqReplayIdentity::SameJobNewMessage,
                revision: control.1,
            })
        };
        tokio::time::timeout(self.config.operation_timeout, operation)
            .await
            .map_err(|_| PgmqAdminError::Unavailable)?
    }

    /// Deletes expired successful archives and visible dead-letter records in small batches.
    ///
    /// A pass alternates both provider-owned tables until each is drained or the single configured
    /// operation budget expires. It never reads from or deletes the live source table and never
    /// removes a leased dead-letter record.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqCleanupError::Unavailable`] for a bounded `SQLx` failure.
    pub async fn cleanup_retention(&self) -> Result<PgmqCleanupResult, PgmqCleanupError> {
        self.cleanup_retention_until(Instant::now() + self.config.operation_timeout)
            .await
    }

    /// Runs one local worker until cancelled, then stops leasing and drains bounded in-flight work.
    ///
    /// Concurrency and optional starts-per-minute are instantiated independently for each call and
    /// come from `J::POLICY`; replicas multiply both. Reads are cancellable, one message at a time,
    /// and never use PGMQ's database-side polling. Success archives the source record. Permanent,
    /// panicked, and exhausted attempts atomically send the canonical object to the separate dead
    /// queue and delete the source in one `SQLx` transaction. Any acknowledgement or storage failure
    /// stops this worker so lease expiry can redeliver unacknowledged work.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqWorkerError::Runtime`] when a bounded queue, acknowledgement, terminal
    /// transaction, retention, or task operation fails.
    pub async fn run_worker<H>(
        &self,
        handler: H,
        cancellation: CancellationToken,
    ) -> Result<(), PgmqWorkerError>
    where
        H: TypedJobHandler<J>,
    {
        install_redacting_panic_hook();
        let worker_cancellation = cancellation.child_token();
        let handler: Arc<dyn JobHandler> = Arc::new(TypedJobHandlerAdapter::<J, H>::new(handler));
        let worker = worker_loop(self.clone(), handler, worker_cancellation.clone());
        let cleanup = retention_loop(self.clone(), worker_cancellation.clone());
        tokio::pin!(worker);
        tokio::pin!(cleanup);
        let failed = tokio::select! {
            result = &mut worker => {
                worker_cancellation.cancel();
                result.is_err() || cleanup.await.is_err()
            }
            result = &mut cleanup => {
                worker_cancellation.cancel();
                result.is_err() || worker.await.is_err()
            }
        };
        if failed {
            Err(PgmqWorkerError::Runtime)
        } else {
            Ok(())
        }
    }

    fn prepare_enqueue(
        &self,
        envelope: &EncodedJobEnvelope,
    ) -> Result<PreparedEnvelope, EnqueueError> {
        if !self.definition.accepts(envelope) {
            return Err(EnqueueError::InvalidEnvelope);
        }
        let message: Value =
            serde_json::from_slice(envelope.bytes()).map_err(|_| EnqueueError::InvalidEnvelope)?;
        if !message.is_object() {
            return Err(EnqueueError::InvalidEnvelope);
        }
        let delay_seconds = eligibility_delay_seconds(envelope.not_before())?;
        Ok(PreparedEnvelope {
            job_id: envelope.id(),
            message,
            delay_seconds,
        })
    }

    fn validate_replay_message(&self, message: &Value) -> Result<JobId, PgmqAdminError> {
        if !message.is_object() {
            return Err(PgmqAdminError::CorruptRecord);
        }
        let bytes = serde_json::to_vec(message).map_err(|_| PgmqAdminError::CorruptRecord)?;
        if bytes.len() > job_limits::ENVELOPE_BYTES {
            return Err(PgmqAdminError::CorruptRecord);
        }
        let envelope = EncodedJobEnvelope::restore(&bytes, self.definition.queue.clone())
            .map_err(|_| PgmqAdminError::CorruptRecord)?;
        if !self.definition.header_matches(&envelope) {
            return Err(PgmqAdminError::CorruptRecord);
        }
        let typed = envelope
            .decode::<J>()
            .map_err(|_| PgmqAdminError::CorruptRecord)?;
        let canonical = typed.encode().map_err(|_| PgmqAdminError::CorruptRecord)?;
        let canonical_message = serde_json::from_slice::<Value>(canonical.bytes())
            .map_err(|_| PgmqAdminError::CorruptRecord)?;
        if &canonical_message != message {
            return Err(PgmqAdminError::CorruptRecord);
        }
        Ok(envelope.id())
    }

    async fn cleanup_retention_until(
        &self,
        deadline: Instant,
    ) -> Result<PgmqCleanupResult, PgmqCleanupError> {
        let mut result = PgmqCleanupResult::default();
        let mut archive_drained = false;
        let mut dead_drained = false;
        let batch = u64::from(self.config.cleanup_batch_size);
        while !archive_drained || !dead_drained {
            if Instant::now() >= deadline {
                break;
            }
            if !archive_drained {
                let removed = self
                    .cleanup_batch(&self.archive_cleanup_sql, deadline)
                    .await?;
                result.completed_removed = result.completed_removed.saturating_add(removed);
                archive_drained = removed < batch;
            }
            if Instant::now() >= deadline {
                break;
            }
            if !dead_drained {
                let removed = self.cleanup_batch(&self.dead_cleanup_sql, deadline).await?;
                result.dead_removed = result.dead_removed.saturating_add(removed);
                dead_drained = removed < batch;
            }
        }
        Ok(result)
    }

    async fn cleanup_batch(
        &self,
        statement: &str,
        deadline: Instant,
    ) -> Result<u64, PgmqCleanupError> {
        let retention = i64::try_from(J::POLICY.retention().as_secs())
            .map_err(|_| PgmqCleanupError::Unavailable)?;
        let batch = i64::from(self.config.cleanup_batch_size);
        let operation = sqlx::query(statement)
            .bind(retention)
            .bind(batch)
            .execute(&self.pool);
        within_deadline(deadline, self.config.operation_timeout, operation)
            .await
            .ok_or(PgmqCleanupError::Unavailable)?
            .map(|result| result.rows_affected())
            .map_err(|_| PgmqCleanupError::Unavailable)
    }
}

impl<J> Clone for PgmqJobProvider<J> {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            queue: self.queue.clone(),
            definition: self.definition.clone(),
            config: self.config.clone(),
            diagnostics_sql: self.diagnostics_sql.clone(),
            archive_cleanup_sql: self.archive_cleanup_sql.clone(),
            dead_cleanup_sql: self.dead_cleanup_sql.clone(),
            dead_records_sql: self.dead_records_sql.clone(),
            replay_size_sql: self.replay_size_sql.clone(),
            replay_message_sql: self.replay_message_sql.clone(),
            dead_delete_sql: self.dead_delete_sql.clone(),
            fence_sql: self.fence_sql.clone(),
            visibility_sql: self.visibility_sql.clone(),
            delete_sql: self.delete_sql.clone(),
        }
    }
}

impl<J> fmt::Debug for PgmqJobProvider<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PgmqJobProvider")
            .field("pool", &"[REDACTED]")
            .field("queue", &"[REDACTED]")
            .field("definition", &self.definition)
            .field("config", &self.config)
            .field("diagnostics_sql", &"[REDACTED]")
            .field("archive_cleanup_sql", &"[REDACTED]")
            .field("dead_cleanup_sql", &"[REDACTED]")
            .field("dead_records_sql", &"[REDACTED]")
            .field("replay_size_sql", &"[REDACTED]")
            .field("replay_message_sql", &"[REDACTED]")
            .field("dead_delete_sql", &"[REDACTED]")
            .field("fence_sql", &"[REDACTED]")
            .field("visibility_sql", &"[REDACTED]")
            .field("delete_sql", &"[REDACTED]")
            .finish()
    }
}

impl<J: Job> JobEnqueuer for PgmqJobProvider<J> {
    fn enqueue(
        &self,
        envelope: EncodedJobEnvelope,
    ) -> futures::future::BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>> {
        Box::pin(async move {
            let prepared = self.prepare_enqueue(&envelope)?;
            tokio::time::timeout(
                self.config.operation_timeout,
                self.queue.send_delay(
                    &self.definition.source,
                    &prepared.message,
                    VisibilityTimeoutOffset::seconds(prepared.delay_seconds),
                ),
            )
            .await
            .map_err(|_| EnqueueError::Unavailable)?
            .map_err(|_| EnqueueError::Unavailable)?;
            Ok(EnqueueReceipt::new(
                prepared.job_id,
                self.definition.queue.clone(),
                OffsetDateTime::now_utc(),
            ))
        })
    }
}

struct PreparedEnvelope {
    job_id: JobId,
    message: Value,
    delay_seconds: i32,
}

enum SourceLease {
    Message(Message<Value>),
    Empty,
    Paused,
}

#[expect(
    clippy::too_many_lines,
    reason = "one loop keeps PGMQ leasing, local limits, cancellation, and bounded drain ordered"
)]
async fn worker_loop<J: Job>(
    provider: PgmqJobProvider<J>,
    handler: Arc<dyn JobHandler>,
    cancellation: CancellationToken,
) -> Result<(), ()> {
    let mut tasks = JoinSet::new();
    let concurrency = usize::from(J::POLICY.max_concurrency());
    let rate_interval = J::POLICY.rate_per_minute().map(rate_interval);
    let mut next_start: Option<Instant> = None;
    let lease_seconds = lease_seconds::<J>(&provider.config)?;
    let mut failed = false;

    while !cancellation.is_cancelled() && !failed {
        while let Some(result) = tasks.try_join_next() {
            failed |= join_failed(result);
        }
        if failed {
            break;
        }
        if tasks.len() >= concurrency {
            tokio::select! {
                () = cancellation.cancelled() => break,
                result = tasks.join_next() => {
                    failed |= result.is_none_or(join_failed);
                }
            }
            continue;
        }
        if let Some(start) = next_start
            && start > Instant::now()
        {
            if tasks.is_empty() {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep_until(start.into()) => {}
                }
            } else {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep_until(start.into()) => {}
                    result = tasks.join_next() => {
                        failed |= result.is_none_or(join_failed);
                    }
                }
            }
            continue;
        }

        let lease_started = Instant::now();
        let read = lease_source(&provider, lease_seconds);
        let leased = tokio::select! {
            () = cancellation.cancelled() => break,
            result = read => {
                match result {
                    Ok(SourceLease::Message(message)) => Some(message),
                    Ok(SourceLease::Empty | SourceLease::Paused) => None,
                    Err(()) => {
                        failed = true;
                        None
                    }
                }
            }
        };
        let Some(message) = leased else {
            if failed {
                break;
            }
            if tasks.is_empty() {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep(provider.config.poll_interval) => {}
                }
            } else {
                tokio::select! {
                    () = cancellation.cancelled() => break,
                    () = tokio::time::sleep(provider.config.poll_interval) => {}
                    result = tasks.join_next() => {
                        failed |= result.is_none_or(join_failed);
                    }
                }
            }
            continue;
        };
        if let Some(interval) = rate_interval {
            next_start = Some(Instant::now() + interval);
        }
        let attempt_provider = provider.clone();
        let attempt_handler = Arc::clone(&handler);
        let attempt_cancellation = cancellation.clone();
        tasks.spawn(async move {
            process_message(
                attempt_provider,
                attempt_handler,
                attempt_cancellation,
                lease_started,
                message,
            )
            .await
        });
    }

    cancellation.cancel();
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            failed |= join_failed(result);
        }
    };
    if tokio::time::timeout(provider.config.shutdown_timeout, drain)
        .await
        .is_err()
    {
        tasks.abort_all();
    }
    if failed { Err(()) } else { Ok(()) }
}

async fn lease_source<J: Job>(
    provider: &PgmqJobProvider<J>,
    lease_seconds: i32,
) -> Result<SourceLease, ()> {
    let database_deadline = Instant::now()
        .checked_add(provider.config.operation_timeout)
        .ok_or(())?;
    let operation = async {
        let mut transaction = provider.pool.begin().await.map_err(|_| ())?;
        set_local_database_timeouts(&mut transaction, database_deadline).await?;
        let paused = sqlx::query_scalar::<_, bool>(
            "SELECT paused FROM pgmq.omnius_job_control \
             WHERE queue_name = $1 FOR SHARE",
        )
        .bind(&provider.definition.source)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|_| ())?
        .ok_or(())?;
        if paused {
            transaction.commit().await.map_err(|_| ())?;
            return Ok(SourceLease::Paused);
        }
        let message = provider
            .queue
            .read_with_cxn::<_, Value>(
                &provider.definition.source,
                VisibilityTimeoutOffset::seconds(lease_seconds),
                &mut *transaction,
            )
            .await
            .map_err(|_| ())?;
        transaction.commit().await.map_err(|_| ())?;
        Ok(message.map_or(SourceLease::Empty, SourceLease::Message))
    };
    run_until_database_deadline(database_deadline, operation).await
}

async fn retention_loop<J: Job>(
    provider: PgmqJobProvider<J>,
    cancellation: CancellationToken,
) -> Result<(), ()> {
    let mut interval = tokio::time::interval(provider.config.cleanup_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Tokio intervals tick immediately; consume that tick so cleanup begins after
    // the configured interval instead of racing worker startup.
    interval.tick().await;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            _ = interval.tick() => {
                provider.cleanup_retention().await.map_err(|_| ())?;
            }
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one attempt keeps fencing, handler lifecycle, and storage transition visibly ordered"
)]
async fn process_message<J: Job>(
    provider: PgmqJobProvider<J>,
    handler: Arc<dyn JobHandler>,
    cancellation: CancellationToken,
    lease_started: Instant,
    message: Message<Value>,
) -> Result<(), ()> {
    let storage_deadline = lease_started
        .checked_add(J::POLICY.timeout())
        .and_then(|deadline| deadline.checked_add(provider.config.lease_grace))
        .ok_or(())?;
    let attempt = u16::try_from(message.read_ct).map_err(|_| ())?;
    if attempt == 0 || attempt > J::POLICY.max_attempts() {
        return terminal_transfer(
            &provider,
            message.msg_id,
            message.read_ct,
            &message.message,
            storage_deadline,
        )
        .await;
    }
    let bytes = serde_json::to_vec(&message.message).map_err(|_| ())?;
    let envelope = match EncodedJobEnvelope::restore(&bytes, provider.definition.queue.clone()) {
        Ok(envelope)
            if provider.definition.header_matches(&envelope) && envelope.decode::<J>().is_ok() =>
        {
            envelope
        }
        Ok(_) | Err(_) => {
            return terminal_transfer(
                &provider,
                message.msg_id,
                message.read_ct,
                &message.message,
                storage_deadline,
            )
            .await;
        }
    };
    let timeout = J::POLICY.timeout();
    let deadline = deadline_after(timeout).ok_or(())?;
    let attempt_cancellation = cancellation.child_token();
    let context =
        DeliveryContext::from_envelope(&envelope, attempt, attempt_cancellation.clone(), deadline)
            .map_err(|_| ())?;
    let future = with_redacted_handler_panic(|| {
        panic::catch_unwind(AssertUnwindSafe(|| handler.handle(envelope, context)))
    });
    let outcome = match future {
        Ok(mut future) => {
            let mut outcome = {
                let guarded = poll_fn(|context| {
                    with_redacted_handler_panic(|| {
                        match panic::catch_unwind(AssertUnwindSafe(|| {
                            future.as_mut().poll(context)
                        })) {
                            Ok(Poll::Ready(outcome)) => {
                                Poll::Ready(AttemptOutcome::Handler(outcome))
                            }
                            Ok(Poll::Pending) => Poll::Pending,
                            Err(_) => Poll::Ready(AttemptOutcome::Panicked),
                        }
                    })
                });
                tokio::pin!(guarded);
                tokio::select! {
                    biased;
                    () = cancellation.cancelled() => AttemptOutcome::Cancelled,
                    result = tokio::time::timeout(timeout, guarded.as_mut()) => {
                        match result {
                            Ok(outcome) => outcome,
                            Err(_) => AttemptOutcome::TimedOut,
                        }
                    }
                }
            };
            if matches!(
                outcome,
                AttemptOutcome::TimedOut | AttemptOutcome::Cancelled
            ) {
                attempt_cancellation.cancel();
            }
            let dropped = with_redacted_handler_panic(|| {
                panic::catch_unwind(AssertUnwindSafe(|| drop(future)))
            });
            if dropped.is_err() {
                outcome = AttemptOutcome::Panicked;
            }
            outcome
        }
        Err(_) => AttemptOutcome::Panicked,
    };
    match outcome {
        AttemptOutcome::Handler(HandlerOutcome::Succeeded) => {
            archive_success(&provider, message.msg_id, message.read_ct, storage_deadline).await
        }
        AttemptOutcome::Handler(HandlerOutcome::Permanent(_)) | AttemptOutcome::Panicked => {
            terminal_transfer(
                &provider,
                message.msg_id,
                message.read_ct,
                &message.message,
                storage_deadline,
            )
            .await
        }
        AttemptOutcome::Handler(HandlerOutcome::Retryable(_)) | AttemptOutcome::TimedOut => {
            attempt_cancellation.cancel();
            if attempt >= J::POLICY.max_attempts() {
                terminal_transfer(
                    &provider,
                    message.msg_id,
                    message.read_ct,
                    &message.message,
                    storage_deadline,
                )
                .await
            } else {
                let delay = retry_delay_seconds::<J>(attempt)?;
                change_visibility(
                    &provider,
                    message.msg_id,
                    message.read_ct,
                    delay,
                    storage_deadline,
                )
                .await
            }
        }
        AttemptOutcome::Handler(HandlerOutcome::Cancelled) | AttemptOutcome::Cancelled => {
            attempt_cancellation.cancel();
            change_visibility(
                &provider,
                message.msg_id,
                message.read_ct,
                0,
                storage_deadline,
            )
            .await
        }
    }
}

enum AttemptOutcome {
    Handler(HandlerOutcome),
    Panicked,
    TimedOut,
    Cancelled,
}

async fn archive_success<J: Job>(
    provider: &PgmqJobProvider<J>,
    message_id: i64,
    expected_read_count: i32,
    deadline: Instant,
) -> Result<(), ()> {
    let budget = remaining_operation_budget(deadline, provider.config.operation_timeout)?;
    let database_deadline = Instant::now().checked_add(budget).ok_or(())?;
    let operation = async {
        let mut transaction = provider.pool.begin().await.map_err(|_| ())?;
        set_local_database_timeouts(&mut transaction, database_deadline).await?;
        let owned = sqlx::query_scalar::<_, i32>(&provider.fence_sql)
            .bind(message_id)
            .bind(expected_read_count)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ())?;
        if owned.is_none() {
            return Ok(());
        }
        let archived = provider
            .queue
            .archive_with_cxn(&provider.definition.source, message_id, &mut *transaction)
            .await
            .map_err(|_| ())?;
        if !archived {
            return Err(());
        }
        transaction.commit().await.map_err(|_| ())
    };
    run_until_database_deadline(database_deadline, operation).await
}

async fn change_visibility<J: Job>(
    provider: &PgmqJobProvider<J>,
    message_id: i64,
    expected_read_count: i32,
    delay_seconds: i32,
    deadline: Instant,
) -> Result<(), ()> {
    let budget = remaining_operation_budget(deadline, provider.config.operation_timeout)?;
    let database_deadline = Instant::now().checked_add(budget).ok_or(())?;
    let operation = async {
        let mut transaction = provider.pool.begin().await.map_err(|_| ())?;
        set_local_database_timeouts(&mut transaction, database_deadline).await?;
        let updated = sqlx::query(&provider.visibility_sql)
            .bind(message_id)
            .bind(expected_read_count)
            .bind(delay_seconds)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ())?
            .rows_affected();
        if updated == 0 {
            return Ok(());
        }
        if updated != 1 {
            return Err(());
        }
        transaction.commit().await.map_err(|_| ())
    };
    run_until_database_deadline(database_deadline, operation).await
}

async fn terminal_transfer<J: Job>(
    provider: &PgmqJobProvider<J>,
    message_id: i64,
    expected_read_count: i32,
    message: &Value,
    deadline: Instant,
) -> Result<(), ()> {
    let budget = remaining_operation_budget(deadline, provider.config.operation_timeout)?;
    let database_deadline = Instant::now().checked_add(budget).ok_or(())?;
    let operation = async {
        let mut transaction = provider.pool.begin().await.map_err(|_| ())?;
        set_local_database_timeouts(&mut transaction, database_deadline).await?;
        let owned = sqlx::query_scalar::<_, i32>(&provider.fence_sql)
            .bind(message_id)
            .bind(expected_read_count)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|_| ())?;
        if owned.is_none() {
            return Ok(());
        }
        let headers = serde_json::json!({ "omnius-attempt": expected_read_count });
        provider
            .queue
            .send_delay_with_headers_with_cxn(
                &provider.definition.dead,
                message,
                Some(&headers),
                VisibilityTimeoutOffset::seconds(0),
                &mut *transaction,
            )
            .await
            .map_err(|_| ())?;
        let deleted = sqlx::query(&provider.delete_sql)
            .bind(message_id)
            .bind(expected_read_count)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ())?
            .rows_affected();
        if deleted != 1 {
            return Ok(());
        }
        transaction.commit().await.map_err(|_| ())
    };
    run_until_database_deadline(database_deadline, operation).await
}

fn remaining_operation_budget(
    deadline: Instant,
    operation_timeout: Duration,
) -> Result<Duration, ()> {
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    let budget = remaining.min(operation_timeout);
    if budget < MIN_SERVER_TIMEOUT {
        return Err(());
    }
    Ok(budget)
}

async fn set_local_database_timeouts(
    connection: &mut PgConnection,
    deadline: Instant,
) -> Result<(), ()> {
    let budget = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    if budget < MIN_SERVER_TIMEOUT {
        return Err(());
    }
    let milliseconds = budget.as_millis();
    let setting = format!("{milliseconds}ms");
    sqlx::query(
        "SELECT set_config('statement_timeout', $1, true), \
                set_config('lock_timeout', $1, true)",
    )
    .bind(setting)
    .execute(connection)
    .await
    .map_err(|_| ())?;
    Ok(())
}
async fn run_until_database_deadline<T, F>(deadline: Instant, operation: F) -> Result<T, ()>
where
    F: Future<Output = Result<T, ()>>,
{
    let remaining = deadline.checked_duration_since(Instant::now()).ok_or(())?;
    tokio::time::timeout(remaining, operation)
        .await
        .map_err(|_| ())?
}

async fn within_deadline<T, F>(
    deadline: Instant,
    operation_timeout: Duration,
    operation: F,
) -> Option<T>
where
    F: Future<Output = T>,
{
    let remaining = deadline.checked_duration_since(Instant::now())?;
    if remaining.is_zero() {
        return None;
    }
    tokio::time::timeout(remaining.min(operation_timeout), operation)
        .await
        .ok()
}

async fn run_with_timeout<T, E, F>(timeout: Duration, operation: F) -> Result<T, TimedError<E>>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::time::timeout(timeout, operation)
        .await
        .map_err(|_| TimedError::Timeout)?
        .map_err(TimedError::Operation)
}

enum TimedError<E> {
    Timeout,
    Operation(E),
}

fn map_provision_result<E>(error: &TimedError<E>) -> PgmqProvisionError {
    match error {
        TimedError::Timeout => PgmqProvisionError::Timeout,
        TimedError::Operation(_) => PgmqProvisionError::Unavailable,
    }
}

fn eligibility_delay_seconds(not_before: Option<OffsetDateTime>) -> Result<i32, EnqueueError> {
    let Some(not_before) = not_before else {
        return Ok(0);
    };
    let now = OffsetDateTime::now_utc();
    if not_before <= now {
        return Ok(0);
    }
    let nanos = not_before.unix_timestamp_nanos() - now.unix_timestamp_nanos();
    let nanos = u128::try_from(nanos).map_err(|_| EnqueueError::Rejected)?;
    ceil_nanos_seconds(nanos).ok_or(EnqueueError::Rejected)
}

fn retry_delay_seconds<J: Job>(attempt: u16) -> Result<i32, ()> {
    let initial_ms = u64::try_from(J::POLICY.initial_backoff().as_millis()).map_err(|_| ())?;
    let maximum_ms = u64::try_from(J::POLICY.max_backoff().as_millis()).map_err(|_| ())?;
    let mut ceiling_ms = initial_ms;
    for _ in 1..attempt {
        ceiling_ms = ceiling_ms
            .saturating_mul(u64::from(J::POLICY.multiplier()))
            .min(maximum_ms);
    }
    let sample = entropy(attempt);
    let delay_ms = match J::POLICY.jitter() {
        Jitter::Full => uniform_inclusive(sample, ceiling_ms).max(1),
        Jitter::Equal => {
            let half = ceiling_ms / 2;
            (half + uniform_inclusive(sample, ceiling_ms - half)).max(1)
        }
    };
    ceil_nanos_seconds(u128::from(delay_ms) * 1_000_000).ok_or(())
}

fn lease_seconds<J: Job>(config: &PgmqJobConfig) -> Result<i32, ()> {
    let total = J::POLICY
        .timeout()
        .checked_add(config.lease_grace)
        .ok_or(())?;
    let nanos = total.as_nanos();
    ceil_nanos_seconds(nanos)
        .and_then(|seconds| seconds.checked_add(1))
        .ok_or(())
}

fn ceil_nanos_seconds(nanos: u128) -> Option<i32> {
    let seconds = nanos
        .checked_add(NANOS_PER_SECOND - 1)?
        .checked_div(NANOS_PER_SECOND)?;
    i32::try_from(seconds).ok()
}

fn rate_interval(rate_per_minute: u32) -> Duration {
    let nanos = 60_u64
        .saturating_mul(1_000_000_000)
        .checked_div(u64::from(rate_per_minute))
        .unwrap_or(1)
        .max(1);
    Duration::from_nanos(nanos)
}

fn deadline_after(timeout: Duration) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(timeout.as_secs()).ok()?;
    OffsetDateTime::now_utc().checked_add(time::Duration::seconds(seconds))
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "JoinSet yields ownership and this classifier immediately consumes the result"
)]
fn join_failed(result: Result<Result<(), ()>, JoinError>) -> bool {
    !matches!(result, Ok(Ok(())))
}

fn nonnegative(value: i64) -> Result<u64, PgmqDiagnosticsError> {
    u64::try_from(value).map_err(|_| PgmqDiagnosticsError::Unavailable)
}

async fn provision_control_and_harden_acls<J: Job>(
    pool: &PgPool,
    definition: &PgmqJobDefinition<J>,
    timeout: Duration,
) -> Result<(), PgmqProvisionError> {
    let tables = payload_table_names(definition);
    let revoke_sql = format!(
        "REVOKE SELECT ON TABLE {}, {}, {}, {}, {CONTROL_TABLE} FROM pg_monitor",
        tables[0], tables[1], tables[2], tables[3]
    );
    let database_deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(PgmqProvisionError::Unavailable)?;
    let operation = async {
        let mut transaction = pool.begin().await.map_err(|_| ())?;
        set_local_database_timeouts(&mut transaction, database_deadline).await?;
        sqlx::query(
            "ALTER DEFAULT PRIVILEGES IN SCHEMA pgmq \
             REVOKE SELECT ON TABLES FROM pg_monitor",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS pgmq.omnius_job_control (\
                 queue_name text PRIMARY KEY,\
                 paused boolean NOT NULL DEFAULT false,\
                 revision bigint NOT NULL DEFAULT 0,\
                 CONSTRAINT omnius_job_control_revision_nonnegative CHECK (revision >= 0)\
             )",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?;
        sqlx::query(
            "INSERT INTO pgmq.omnius_job_control (queue_name, paused, revision) \
             VALUES ($1, false, 0) ON CONFLICT (queue_name) DO NOTHING",
        )
        .bind(&definition.source)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ())?;
        sqlx::query(&revoke_sql)
            .execute(&mut *transaction)
            .await
            .map_err(|_| ())?;
        transaction.commit().await.map_err(|_| ())
    };
    run_with_timeout(timeout, operation)
        .await
        .map_err(|error| map_provision_result(&error))
}

fn payload_table_names<J>(definition: &PgmqJobDefinition<J>) -> [String; 4] {
    [
        format!("pgmq.q_{}", definition.source),
        format!("pgmq.a_{}", definition.source),
        format!("pgmq.q_{}", definition.dead),
        format!("pgmq.a_{}", definition.dead),
    ]
}

fn cleanup_sql(prefix: &str, queue: &str, timestamp: &str, require_visible: bool) -> String {
    let visibility = if require_visible {
        " AND vt <= clock_timestamp()"
    } else {
        ""
    };
    let delete_visibility = if require_visible {
        " AND records.vt <= clock_timestamp()"
    } else {
        ""
    };
    format!(
        "WITH expired AS (\
             SELECT ctid FROM pgmq.{prefix}_{queue} \
             WHERE {timestamp} < clock_timestamp() - ($1::bigint * interval '1 second')\
             {visibility} \
             ORDER BY {timestamp}, msg_id LIMIT $2\
         ) \
         DELETE FROM pgmq.{prefix}_{queue} AS records \
         USING expired WHERE records.ctid = expired.ctid{delete_visibility}"
    )
}

fn physical_queue_name(
    kind: char,
    version: u16,
    fingerprint: &str,
) -> Result<String, PgmqJobDefinitionError> {
    let value = format!("{kind}{version}_{fingerprint}");
    if valid_physical_queue(&value) {
        Ok(value)
    } else {
        Err(PgmqJobDefinitionError::InvalidPhysicalQueue)
    }
}

fn valid_physical_queue(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= PHYSICAL_QUEUE_MAX_BYTES
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn dispatch_policy_fingerprint<J: Job>() -> String {
    let policy = J::POLICY;
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, J::NAME.as_bytes());
    hasher.update(J::VERSION.to_be_bytes());
    hasher.update([match policy.idempotency() {
        IdempotencyRequirement::Required => 0,
        IdempotencyRequirement::Optional => 1,
    }]);
    hasher.update(policy.max_attempts().to_be_bytes());
    hasher.update(policy.initial_backoff().as_millis().to_be_bytes());
    hasher.update(policy.max_backoff().as_millis().to_be_bytes());
    hasher.update([policy.multiplier()]);
    hasher.update([match policy.jitter() {
        Jitter::Full => 0,
        Jitter::Equal => 1,
    }]);
    hasher.update(policy.timeout().as_secs().to_be_bytes());
    hasher.update(policy.max_concurrency().to_be_bytes());
    match policy.rate_per_minute() {
        Some(rate) => {
            hasher.update([1]);
            hasher.update(rate.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hash_bytes(&mut hasher, policy.queue().as_bytes());
    hasher.update([policy.priority()]);
    hasher.update(policy.retention().as_secs().to_be_bytes());
    match policy.dead_letter() {
        DeadLetterPolicy::Retain => hasher.update([0]),
        DeadLetterPolicy::Destination(destination) => {
            hasher.update([1]);
            hash_bytes(&mut hasher, destination.as_bytes());
        }
    }
    match policy.compatibility() {
        CompatibilityPolicy::Exact => hasher.update([0]),
        CompatibilityPolicy::BackwardCompatible { minimum_version } => {
            hasher.update([1]);
            hasher.update(minimum_version.to_be_bytes());
        }
    }
    hasher.update(
        u64::try_from(policy.max_payload_bytes())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    let digest = hasher.finalize();
    hex_string(&digest[..FINGERPRINT_BYTES])
}

fn hash_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn entropy(attempt: u16) -> u64 {
    let mut bytes = [0_u8; 8];
    if OsRng.try_fill_bytes(&mut bytes).is_ok() {
        return u64::from_le_bytes(bytes);
    }
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    mix(time.as_secs() ^ u64::from(time.subsec_nanos()) ^ u64::from(attempt))
}

fn uniform_inclusive(mut sample: u64, maximum: u64) -> u64 {
    if maximum == u64::MAX {
        return sample;
    }
    let range = maximum + 1;
    let rejection_floor = u64::MAX - (u64::MAX % range);
    while sample >= rejection_floor {
        sample = mix(sample);
    }
    sample % range
}

fn mix(mut value: u64) -> u64 {
    value ^= value >> 12;
    value ^= value << 25;
    value ^= value >> 27;
    value.wrapping_mul(2_685_821_657_736_338_717)
}

fn install_redacting_panic_hook() {
    INSTALL_PANIC_HOOK.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |information| {
            let redacted = REDACT_HANDLER_PANIC.try_with(Cell::get).unwrap_or(false);
            if !redacted {
                previous(information);
            }
        }));
    });
}

fn with_redacted_handler_panic<T>(run: impl FnOnce() -> T) -> T {
    let previous = REDACT_HANDLER_PANIC.with(|redacted| redacted.replace(true));
    let _reset = PanicRedactionReset(previous);
    run()
}

struct PanicRedactionReset(bool);

impl Drop for PanicRedactionReset {
    fn drop(&mut self) {
        REDACT_HANDLER_PANIC.with(|redacted| redacted.set(self.0));
    }
}

fn valid_metrics_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= omnius_jobs_core::limits::METRICS_PREFIX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_runbook(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= omnius_jobs_core::limits::RUNBOOK
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':' | b'#')
        })
}

fn bounded_duration(
    value: Duration,
    maximum: Duration,
    error: PgmqJobConfigError,
) -> Result<(), PgmqJobConfigError> {
    if value.is_zero() || value > maximum {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use omnius_jobs_core::{
        CompatibilityPolicy, DeadLetterPolicy, IdempotencyRequirement, Jitter, Job, JobPolicy,
    };
    use serde::{Deserialize, Serialize};

    use super::{
        PgmqJobConfig, PgmqJobConfigError, PgmqJobDefinition, PgmqJobDefinitionError,
        dispatch_policy_fingerprint, valid_physical_queue,
    };
    use std::time::Duration;

    const fn policy(queue: &'static str, attempts: u16) -> JobPolicy {
        policy_with_dead_letter(queue, attempts, DeadLetterPolicy::Retain)
    }

    const fn policy_with_dead_letter(
        queue: &'static str,
        attempts: u16,
        dead_letter: DeadLetterPolicy,
    ) -> JobPolicy {
        match JobPolicy::new(
            IdempotencyRequirement::Optional,
            attempts,
            10,
            100,
            2,
            Jitter::Full,
            2,
            3,
            Some(30),
            queue,
            2,
            60,
            dead_letter,
            CompatibilityPolicy::Exact,
            4_096,
        ) {
            Ok(policy) => policy,
            Err(_) => panic!("test policy must be valid"),
        }
    }

    #[derive(Deserialize, Serialize)]
    struct FirstJob {
        value: u32,
    }

    impl Job for FirstJob {
        const NAME: &'static str = "test.first";
        const VERSION: u16 = 65_535;
        const POLICY: JobPolicy = policy("first", 3);
        const METRICS_PREFIX: &'static str = "first";
        const RUNBOOK: &'static str = "runbooks/first";
    }

    #[derive(Deserialize, Serialize)]
    struct SecondJob {
        value: u32,
    }

    impl Job for SecondJob {
        const NAME: &'static str = "test.first";
        const VERSION: u16 = 65_535;
        const POLICY: JobPolicy = policy("first", 3);
        const METRICS_PREFIX: &'static str = "renamed";
        const RUNBOOK: &'static str = "runbooks/renamed";
    }

    #[derive(Deserialize, Serialize)]
    struct DestinationJob {
        value: u32,
    }

    impl Job for DestinationJob {
        const NAME: &'static str = "test.destination";
        const VERSION: u16 = 1;
        const POLICY: JobPolicy =
            policy_with_dead_letter("destination", 3, DeadLetterPolicy::Destination("external"));
        const METRICS_PREFIX: &'static str = "destination";
        const RUNBOOK: &'static str = "runbooks/destination";
    }

    #[test]
    fn physical_names_are_valid_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let definition = PgmqJobDefinition::<FirstJob>::new()?;
        assert!(valid_physical_queue(&definition.source));
        assert!(valid_physical_queue(&definition.dead));
        assert!(definition.source.len() <= 46);
        assert!(definition.dead.len() <= 46);
        Ok(())
    }

    #[test]
    fn rust_path_refactors_preserve_wire_queue_identity() {
        assert_eq!(
            dispatch_policy_fingerprint::<FirstJob>(),
            dispatch_policy_fingerprint::<SecondJob>()
        );
    }

    #[test]
    fn destination_dead_letter_policy_is_rejected() {
        assert!(matches!(
            PgmqJobDefinition::<DestinationJob>::new(),
            Err(PgmqJobDefinitionError::UnsupportedDeadLetterDestination)
        ));
    }

    #[test]
    fn config_debug_contains_no_topology_or_secret() {
        let rendered = format!("{:?}", PgmqJobConfig::default());
        assert!(!rendered.contains("postgres://"));
        assert!(!rendered.contains("queue"));
    }

    #[test]
    fn operation_timeout_is_bounded() {
        let result = PgmqJobConfig::new(
            Duration::ZERO,
            Duration::from_millis(10),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        );
        assert_eq!(result, Err(PgmqJobConfigError::OperationTimeout));
    }

    #[test]
    fn lease_grace_must_cover_storage_and_shutdown() {
        let result = PgmqJobConfig::new(
            Duration::from_secs(2),
            Duration::from_millis(10),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        );
        assert_eq!(result, Err(PgmqJobConfigError::LeaseTiming));
    }

    #[test]
    fn poll_interval_has_a_hard_upper_bound() {
        let result = PgmqJobConfig::new(
            Duration::from_secs(1),
            Duration::from_secs(31),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1,
        );
        assert_eq!(result, Err(PgmqJobConfigError::PollInterval));
    }

    #[test]
    fn cleanup_interval_has_a_hard_upper_bound() {
        let result = PgmqJobConfig::new(
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(301),
            1,
        );
        assert_eq!(result, Err(PgmqJobConfigError::CleanupInterval));
    }

    #[test]
    fn cleanup_batch_has_a_hard_upper_bound() {
        let result = PgmqJobConfig::new(
            Duration::from_secs(1),
            Duration::from_millis(10),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            1_001,
        );
        assert_eq!(result, Err(PgmqJobConfigError::CleanupBatchSize));
    }
}
