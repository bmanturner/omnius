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
use rsk_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EncodedJobEnvelope, EnqueueError,
    EnqueueReceipt, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuer, JobHandler,
    JobId, JobName, QueueName, TypedJobHandler, TypedJobHandlerAdapter, Version,
};
use rsk_postgres::PostgresPool;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use sqlx::{PgConnection, PgPool};
use thiserror::Error;
use time::OffsetDateTime;
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

/// Redacted point-in-time counts for one typed source and dead-letter pair.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PgmqJobDiagnostics {
    source_total: u64,
    source_visible: u64,
    dead_total: u64,
    dead_visible: u64,
    completed: u64,
}

impl PgmqJobDiagnostics {
    /// All source records, including delayed or currently leased records.
    #[must_use]
    pub const fn source_total(self) -> u64 {
        self.source_total
    }

    /// Source records currently eligible for a one-message read.
    #[must_use]
    pub const fn source_visible(self) -> u64 {
        self.source_visible
    }

    /// All terminal records retained in the separate dead-letter queue.
    #[must_use]
    pub const fn dead_total(self) -> u64 {
        self.dead_total
    }

    /// Dead-letter records currently visible and not leased by inspection tooling.
    #[must_use]
    pub const fn dead_visible(self) -> u64 {
        self.dead_visible
    }

    /// Successfully processed records retained in the source archive.
    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }
}

/// Safe bounded diagnostics failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PgmqDiagnosticsError {
    /// PGMQ or PostgreSQL could not answer all bounded count operations.
    #[error("PGMQ diagnostics are unavailable")]
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
    archive_count_sql: String,
    archive_cleanup_sql: String,
    dead_cleanup_sql: String,
    fence_sql: String,
    visibility_sql: String,
    delete_sql: String,
}

impl<J: Job> PgmqJobProvider<J> {
    /// Installs the pinned embedded PGMQ SQL, creates both exact typed queues, and removes
    /// `pg_monitor` access to their payload tables.
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
        harden_payload_acls(&sqlx_pool, &definition, config.operation_timeout).await?;
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
        let queues = tokio::time::timeout(config.operation_timeout, queue.list_queues())
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
        let payload_tables = payload_table_names(&definition);
        let pg_monitor_can_select = tokio::time::timeout(
            config.operation_timeout,
            sqlx::query_scalar::<_, bool>(
                "SELECT has_table_privilege('pg_monitor', $1::text, 'SELECT') \
                     OR has_table_privilege('pg_monitor', $2::text, 'SELECT') \
                     OR has_table_privilege('pg_monitor', $3::text, 'SELECT') \
                     OR has_table_privilege('pg_monitor', $4::text, 'SELECT')",
            )
            .bind(&payload_tables[0])
            .bind(&payload_tables[1])
            .bind(&payload_tables[2])
            .bind(&payload_tables[3])
            .fetch_one(&sqlx_pool),
        )
        .await
        .map_err(|_| PgmqConnectError::Unavailable)?
        .map_err(|_| PgmqConnectError::Unavailable)?;
        if pg_monitor_can_select {
            return Err(PgmqConnectError::InsecurePermissions);
        }
        let archive_count_sql =
            format!("SELECT count(*)::bigint FROM pgmq.a_{}", definition.source);
        let archive_cleanup_sql = cleanup_sql("a", &definition.source, "archived_at", false);
        let dead_cleanup_sql = cleanup_sql("q", &definition.dead, "enqueued_at", true);
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
            archive_count_sql,
            archive_cleanup_sql,
            dead_cleanup_sql,
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

    /// Reads bounded aggregate queue and successful-archive counts without payloads or topology.
    ///
    /// PGMQ metrics cannot distinguish delayed records from active leases, so this API reports
    /// only total and currently visible source/dead counts.
    ///
    /// # Errors
    ///
    /// Returns [`PgmqDiagnosticsError::Unavailable`] when any count fails or exceeds the configured
    /// operation deadline.
    pub async fn diagnostics(&self) -> Result<PgmqJobDiagnostics, PgmqDiagnosticsError> {
        let operation = async {
            let source = self
                .queue
                .metrics(&self.definition.source)
                .await
                .map_err(|_| ())?;
            let dead = self
                .queue
                .metrics(&self.definition.dead)
                .await
                .map_err(|_| ())?;
            let completed = sqlx::query_scalar::<_, i64>(&self.archive_count_sql)
                .fetch_one(&self.pool)
                .await
                .map_err(|_| ())?;
            Ok::<_, ()>((source, dead, completed))
        };
        let (source, dead, completed) =
            tokio::time::timeout(self.config.operation_timeout, operation)
                .await
                .map_err(|_| PgmqDiagnosticsError::Unavailable)?
                .map_err(|()| PgmqDiagnosticsError::Unavailable)?;
        Ok(PgmqJobDiagnostics {
            source_total: nonnegative(source.queue_length)?,
            source_visible: nonnegative(source.queue_visible_length)?,
            dead_total: nonnegative(dead.queue_length)?,
            dead_visible: nonnegative(dead.queue_visible_length)?,
            completed: nonnegative(completed)?,
        })
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
            archive_count_sql: self.archive_count_sql.clone(),
            archive_cleanup_sql: self.archive_cleanup_sql.clone(),
            dead_cleanup_sql: self.dead_cleanup_sql.clone(),
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
            .field("archive_count_sql", &"[REDACTED]")
            .field("archive_cleanup_sql", &"[REDACTED]")
            .field("dead_cleanup_sql", &"[REDACTED]")
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
        let read = tokio::time::timeout(
            provider.config.operation_timeout,
            provider.queue.read::<Value>(
                &provider.definition.source,
                VisibilityTimeoutOffset::seconds(lease_seconds),
            ),
        );
        let leased = tokio::select! {
            () = cancellation.cancelled() => break,
            result = read => {
                if let Ok(Ok(message)) = result {
                    message
                } else {
                    failed = true;
                    None
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

async fn retention_loop<J: Job>(
    provider: PgmqJobProvider<J>,
    cancellation: CancellationToken,
) -> Result<(), ()> {
    let mut interval = tokio::time::interval(provider.config.cleanup_interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
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
        provider
            .queue
            .send_with_cxn(&provider.definition.dead, message, &mut *transaction)
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

async fn harden_payload_acls<J: Job>(
    pool: &PgPool,
    definition: &PgmqJobDefinition<J>,
    timeout: Duration,
) -> Result<(), PgmqProvisionError> {
    let tables = payload_table_names(definition);
    let revoke_sql = format!(
        "REVOKE SELECT ON TABLE {}, {}, {}, {} FROM pg_monitor",
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
    format!(
        "WITH expired AS (\
             SELECT ctid FROM pgmq.{prefix}_{queue} \
             WHERE {timestamp} < clock_timestamp() - ($1::bigint * interval '1 second')\
             {visibility} \
             ORDER BY {timestamp}, msg_id LIMIT $2\
         ) \
         DELETE FROM pgmq.{prefix}_{queue} AS records \
         USING expired WHERE records.ctid = expired.ctid"
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
        && value.len() <= rsk_jobs_core::limits::METRICS_PREFIX
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_runbook(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= rsk_jobs_core::limits::RUNBOOK
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
    use rsk_jobs_core::{
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
