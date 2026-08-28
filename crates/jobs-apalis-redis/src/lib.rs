//! Typed Apalis 0.7.4 Redis jobs without exposing its isolated Redis client line.
//!
//! One [`RedisJobProvider`] is bound to one [`Job`] declaration. Its Redis namespace includes the
//! job name, queue, priority, exact version, and dispatch-policy fingerprint, so incompatible
//! workers cannot consume one another's records. Running workers expire terminal records according
//! to `J::POLICY.retention()`, and canonical core envelope bytes remain intact; the Apalis `ULID`
//! remains transport metadata rather than replacing the core `UUIDv7` job ID.

#![forbid(unsafe_code)]

use std::{
    cell::Cell,
    fmt,
    marker::PhantomData,
    panic::{self, AssertUnwindSafe},
    sync::{
        Arc, Once,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apalis::{
    layers::{WorkerBuilderExt as _, limit::RateLimitLayer},
    prelude::{
        Attempt, BoxDynError, Data, Error as ApalisError, Event, Monitor, Storage as _, TaskId,
        WorkerBuilder, WorkerFactoryFn as _,
    },
};
use apalis_redis::{Config as BackendConfig, RedisPollError, RedisStorage};
use futures::future::{BoxFuture, poll_fn};
use omnius_config::{ExposeSecret as _, SecretString};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, EncodedJobEnvelope, EnqueueError,
    EnqueueReceipt, HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnqueuer, JobHandler,
    JobId, JobName, QueueName, TypedJobHandler, TypedJobHandlerAdapter, Version,
};
use rand_core::{OsRng, RngCore as _};
use redis_apalis::aio::{ConnectionManager, ConnectionManagerConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
thread_local! {
    static REDACT_HANDLER_PANIC: Cell<bool> = const { Cell::new(false) };
}
static INSTALL_PANIC_HOOK: Once = Once::new();

const MAX_URL_BYTES: usize = 4_096;
const MAX_NAMESPACE_BYTES: usize = 128;
const REQUIRED_BUFFER_SIZE: usize = 1;
const MAX_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const MAX_KEEP_ALIVE: Duration = Duration::from_mins(5);
const MAX_ORPHAN_AFTER: Duration = Duration::from_hours(24);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_mins(5);
const MAX_PHYSICAL_WORKER_NAME_BYTES: usize = 64;
const WORKER_RANDOM_BYTES: usize = 16;
const WORKER_RANDOM_HEX_BYTES: usize = WORKER_RANDOM_BYTES * 2;
const WORKER_SUFFIX_BYTES: usize = 1 + WORKER_RANDOM_HEX_BYTES;
const CLEANUP_BATCH_SIZE: usize = 128;
const CLEANUP_FAILURE_LIMIT: u8 = 3;
const MAX_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const CLEANUP_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const APALIS_MAX_ATTEMPTS: u16 = 5;
const MAX_DEAD_RECORDS: usize = 100;
const MAX_DIAGNOSTIC_RECORDS: usize = 100;
const MAX_RECORD_ID_BYTES: usize = 128;
const MAX_CONTROL_REVISION: i64 = 9_007_199_254_740_990;
const MAX_CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(100);
const NANOS_PER_SECOND: i128 = 1_000_000_000;
const TERMINAL_CLEANUP_SCRIPT: &str = r#"
local cutoff = tonumber(ARGV[1])
local batch_size = tonumber(ARGV[2])

local function has_type(key, expected)
    local actual = redis.call("TYPE", key).ok
    return actual == "none" or actual == expected
end

if not has_type(KEYS[1], "zset")
    or not has_type(KEYS[2], "zset")
    or not has_type(KEYS[3], "hash")
    or not has_type(KEYS[4], "hash")
then
    return redis.error_reply("invalid terminal storage")
end

local function cleanup(terminal_set)
    local ids = redis.call(
        "ZRANGEBYSCORE",
        terminal_set,
        "-inf",
        cutoff,
        "LIMIT",
        0,
        batch_size
    )
    for _, id in ipairs(ids) do
        redis.call("HDEL", KEYS[3], id)
        redis.call("HDEL", KEYS[4], id)
        redis.call("ZREM", terminal_set, id)
    end
    return #ids
end

return cleanup(KEYS[1]) + cleanup(KEYS[2])
"#;
const RECOVER_INFLIGHT_SCRIPT: &str = r#"
local function has_type(key, expected)
    local actual = redis.call("TYPE", key).ok
    return actual == "none" or actual == expected
end

local consumers_type = redis.call("TYPE", KEYS[3]).ok
if not has_type(KEYS[1], "set")
    or not has_type(KEYS[2], "list")
    or (consumers_type ~= "none"
        and consumers_type ~= "zset"
        and consumers_type ~= "string")
    or not has_type(KEYS[4], "list")
    or not has_type(KEYS[5], "zset")
then
    return redis.error_reply("invalid recovery storage")
end
if consumers_type == "string" and redis.call("GET", KEYS[3]) ~= "omnius-paused-v1" then
    return redis.error_reply("invalid consumer fence")
end

local ids = redis.call("SMEMBERS", KEYS[1])
for _, id in ipairs(ids) do
    if redis.call("SREM", KEYS[1], id) == 1 then
        redis.call("RPUSH", KEYS[2], id)
    end
end
if consumers_type == "zset" then
    redis.call("ZREM", KEYS[3], KEYS[1])
else
    redis.call("ZREM", KEYS[5], KEYS[1])
end
if #ids > 0 then
    redis.call("DEL", KEYS[4])
    redis.call("LPUSH", KEYS[4], 1)
end
return #ids
"#;
const CONTROL_STATE_SCRIPT: &str = r#"
local actual = redis.call("TYPE", KEYS[1]).ok
if actual ~= "none" and actual ~= "hash" then
    return redis.error_reply("invalid control storage")
end

redis.call("HSETNX", KEYS[1], "paused", "0")
redis.call("HSETNX", KEYS[1], "revision", "0")

local paused = redis.call("HGET", KEYS[1], "paused")
local revision = redis.call("HGET", KEYS[1], "revision")
local revision_number = tonumber(revision)
if (paused ~= "0" and paused ~= "1")
    or not revision_number
    or revision_number < 0
    or revision_number ~= math.floor(revision_number)
    or revision_number > 9007199254740990
then
    return redis.error_reply("invalid control state")
end

return { paused, revision }
"#;
const SET_PAUSED_SCRIPT: &str = r#"
local control_type = redis.call("TYPE", KEYS[1]).ok
local consumers_type = redis.call("TYPE", KEYS[2]).ok
local held_type = redis.call("TYPE", KEYS[3]).ok
if (control_type ~= "none" and control_type ~= "hash")
    or (held_type ~= "none" and held_type ~= "zset")
then
    return redis.error_reply("invalid control storage")
end

redis.call("HSETNX", KEYS[1], "paused", "0")
redis.call("HSETNX", KEYS[1], "revision", "0")
local paused = redis.call("HGET", KEYS[1], "paused")
local revision = redis.call("HGET", KEYS[1], "revision")
local revision_number = tonumber(revision)
if (paused ~= "0" and paused ~= "1")
    or not revision_number
    or revision_number < 0
    or revision_number ~= math.floor(revision_number)
    or revision_number >= 9007199254740990
then
    return redis.error_reply("invalid control state")
end
if paused == "0" then
    if held_type ~= "none"
        or (consumers_type ~= "none" and consumers_type ~= "zset")
    then
        return redis.error_reply("invalid unpaused consumer storage")
    end
elseif consumers_type ~= "string"
    or redis.call("GET", KEYS[2]) ~= "omnius-paused-v1"
then
    return redis.error_reply("invalid paused consumer storage")
end

if revision ~= ARGV[2] then
    return { 0, paused, revision }
end

if ARGV[1] == "1" and paused == "0" then
    if consumers_type == "zset" then
        redis.call("RENAME", KEYS[2], KEYS[3])
    end
    redis.call("SET", KEYS[2], "omnius-paused-v1")
elseif ARGV[1] == "0" and paused == "1" then
    redis.call("DEL", KEYS[2])
    if held_type == "zset" then
        redis.call("RENAME", KEYS[3], KEYS[2])
    end
end

redis.call("HSET", KEYS[1], "paused", ARGV[1])
local next_revision = redis.call("HINCRBY", KEYS[1], "revision", 1)
return { 1, ARGV[1], next_revision }
"#;
const REPLAY_DEAD_SCRIPT: &str = r#"
local function has_type(key, expected)
    local actual = redis.call("TYPE", key).ok
    return actual == "none" or actual == expected
end

if not has_type(KEYS[1], "hash")
    or not has_type(KEYS[2], "string")
    or not has_type(KEYS[3], "zset")
    or not has_type(KEYS[4], "hash")
    or not has_type(KEYS[5], "hash")
    or not has_type(KEYS[6], "list")
    or not has_type(KEYS[7], "list")
then
    return redis.error_reply("invalid replay storage")
end

redis.call("HSETNX", KEYS[1], "paused", "0")
redis.call("HSETNX", KEYS[1], "revision", "0")

local paused = redis.call("HGET", KEYS[1], "paused")
local revision = redis.call("HGET", KEYS[1], "revision")
local revision_number = tonumber(revision)
if (paused ~= "0" and paused ~= "1")
    or not revision_number
    or revision_number < 0
    or revision_number ~= math.floor(revision_number)
    or revision_number >= 9007199254740990
then
    return redis.error_reply("invalid control state")
end

if revision ~= ARGV[1] then
    return { 0, revision }
end
if paused ~= "1" or redis.call("GET", KEYS[2]) ~= "omnius-paused-v1" then
    return { 1, revision }
end
if not redis.call("ZSCORE", KEYS[3], ARGV[2]) then
    return { 2, revision }
end
if not redis.call("HGET", KEYS[4], ARGV[2]) then
    return { 3, revision }
end

redis.call("ZREM", KEYS[3], ARGV[2])
redis.call("HDEL", KEYS[5], ARGV[2])
redis.call("RPUSH", KEYS[6], ARGV[2])
redis.call("DEL", KEYS[7])
redis.call("LPUSH", KEYS[7], 1)
local next_revision = redis.call("HINCRBY", KEYS[1], "revision", 1)
return { 4, next_revision }
"#;

/// Secret-safe connectivity and bounded Apalis worker timing.
pub struct RedisJobConfig {
    url: SecretString,
    namespace_prefix: String,
    connection_timeout: Duration,
    operation_timeout: Duration,
    poll_interval: Duration,
    scheduled_poll_interval: Duration,
    keep_alive: Duration,
    orphan_after: Duration,
    buffer_size: usize,
    shutdown_timeout: Duration,
}

impl RedisJobConfig {
    /// Creates a configuration with conservative production worker timings.
    #[must_use]
    pub fn new(url: SecretString) -> Self {
        Self {
            url,
            namespace_prefix: "omnius:v1".to_owned(),
            connection_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(100),
            scheduled_poll_interval: Duration::from_secs(1),
            keep_alive: Duration::from_secs(30),
            orphan_after: Duration::from_mins(5),
            buffer_size: REQUIRED_BUFFER_SIZE,
            shutdown_timeout: Duration::from_secs(25),
        }
    }

    /// Sets the bounded application namespace placed before job policy components.
    #[must_use]
    pub fn with_namespace_prefix(mut self, value: impl Into<String>) -> Self {
        self.namespace_prefix = value.into();
        self
    }

    /// Sets the eager Redis connection deadline.
    #[must_use]
    pub const fn with_connection_timeout(mut self, value: Duration) -> Self {
        self.connection_timeout = value;
        self
    }

    /// Sets the deadline for every Redis operation, including worker heartbeat and acknowledgement.
    #[must_use]
    pub const fn with_operation_timeout(mut self, value: Duration) -> Self {
        self.operation_timeout = value;
        self
    }

    /// Sets how often workers fetch available jobs.
    #[must_use]
    pub const fn with_poll_interval(mut self, value: Duration) -> Self {
        self.poll_interval = value;
        self
    }

    /// Sets how often eligible scheduled and retried jobs become active.
    #[must_use]
    pub const fn with_scheduled_poll_interval(mut self, value: Duration) -> Self {
        self.scheduled_poll_interval = value;
        self
    }

    /// Sets the consumer heartbeat and abandoned-job recovery threshold.
    #[must_use]
    pub const fn with_orphan_recovery(
        mut self,
        keep_alive: Duration,
        orphan_after: Duration,
    ) -> Self {
        self.keep_alive = keep_alive;
        self.orphan_after = orphan_after;
        self
    }

    /// Sets the backend fetch buffer, which must be exactly one to isolate corrupt records and
    /// bound decoded batch allocation.
    #[must_use]
    pub const fn with_buffer_size(mut self, value: usize) -> Self {
        self.buffer_size = value;
        self
    }

    /// Sets the bounded drain window after cancellation.
    #[must_use]
    pub const fn with_shutdown_timeout(mut self, value: Duration) -> Self {
        self.shutdown_timeout = value;
        self
    }

    /// Validates secrets, namespaces, and every bounded timing dimension.
    ///
    /// # Errors
    ///
    /// Returns [`RedisJobConfigError`] for malformed or unsafe values. Diagnostics never include
    /// the configured URL.
    pub fn validate(&self) -> Result<(), RedisJobConfigError> {
        let exposed = self.url.expose_secret();
        if exposed.trim().is_empty()
            || exposed.len() > MAX_URL_BYTES
            || redis_apalis::Client::open(exposed).is_err()
        {
            return Err(RedisJobConfigError::InvalidUrl);
        }
        if !valid_namespace_prefix(&self.namespace_prefix) {
            return Err(RedisJobConfigError::InvalidNamespace);
        }
        bounded_duration(
            self.connection_timeout,
            MAX_CONNECTION_TIMEOUT,
            RedisJobConfigError::InvalidConnectionTimeout,
        )?;
        bounded_duration(
            self.operation_timeout,
            MAX_OPERATION_TIMEOUT,
            RedisJobConfigError::InvalidOperationTimeout,
        )?;
        bounded_duration(
            self.poll_interval,
            MAX_POLL_INTERVAL,
            RedisJobConfigError::InvalidPollInterval,
        )?;
        bounded_duration(
            self.scheduled_poll_interval,
            MAX_POLL_INTERVAL,
            RedisJobConfigError::InvalidScheduledPollInterval,
        )?;
        bounded_duration(
            self.keep_alive,
            MAX_KEEP_ALIVE,
            RedisJobConfigError::InvalidOrphanRecovery,
        )?;
        bounded_duration(
            self.orphan_after,
            MAX_ORPHAN_AFTER,
            RedisJobConfigError::InvalidOrphanRecovery,
        )?;
        if self.orphan_after < self.keep_alive.saturating_mul(2) {
            return Err(RedisJobConfigError::InvalidOrphanRecovery);
        }
        if self.buffer_size != REQUIRED_BUFFER_SIZE {
            return Err(RedisJobConfigError::InvalidBufferSize);
        }
        bounded_duration(
            self.shutdown_timeout,
            MAX_SHUTDOWN_TIMEOUT,
            RedisJobConfigError::InvalidShutdownTimeout,
        )
    }
}

impl fmt::Debug for RedisJobConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisJobConfig")
            .field("url", &"[REDACTED]")
            .field("namespace_prefix", &"[REDACTED]")
            .field("connection_timeout", &self.connection_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("poll_interval", &self.poll_interval)
            .field("scheduled_poll_interval", &self.scheduled_poll_interval)
            .field("keep_alive", &self.keep_alive)
            .field("orphan_after", &self.orphan_after)
            .field("buffer_size", &self.buffer_size)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .finish()
    }
}

/// Invalid adapter configuration with no secret-bearing data.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisJobConfigError {
    /// The secret was empty, oversized, or not a Redis URL.
    #[error("Apalis Redis URL is invalid")]
    InvalidUrl,
    /// The namespace was empty, oversized, or contained unsafe bytes.
    #[error("Apalis Redis namespace is invalid")]
    InvalidNamespace,
    /// The eager connection deadline was zero or excessive.
    #[error("Apalis Redis connection timeout is invalid")]
    InvalidConnectionTimeout,
    /// A Redis operation deadline was zero or excessive.
    #[error("Apalis Redis operation timeout is invalid")]
    InvalidOperationTimeout,
    /// The active-job polling interval was zero or excessive.
    #[error("Apalis Redis poll interval is invalid")]
    InvalidPollInterval,
    /// The scheduled-job polling interval was zero or excessive.
    #[error("Apalis Redis scheduled poll interval is invalid")]
    InvalidScheduledPollInterval,
    /// Heartbeat and orphan recovery timings were unsafe or inconsistent.
    #[error("Apalis Redis orphan recovery timing is invalid")]
    InvalidOrphanRecovery,
    /// The backend fetch buffer was not exactly one.
    #[error("Apalis Redis buffer size must be one")]
    InvalidBufferSize,
    /// The worker drain deadline was zero or excessive.
    #[error("Apalis Redis shutdown timeout is invalid")]
    InvalidShutdownTimeout,
}

/// Validated typed job routing derived from `J::POLICY`.
pub struct JobDefinition<J> {
    name: JobName,
    version: Version,
    queue: QueueName,
    priority: u8,
    namespace: String,
    marker: PhantomData<fn() -> J>,
}

impl<J: Job> JobDefinition<J> {
    /// Validates a typed declaration against capabilities of Apalis Redis 0.7.4.
    ///
    /// Apalis hardcodes five maximum attempts and only retains dead records in the source
    /// namespace. Definitions asking for more attempts or a destination dead-letter queue are
    /// rejected rather than silently weakened.
    ///
    /// # Errors
    ///
    /// Returns [`JobDefinitionError`] for an invalid core declaration or unsupported policy.
    pub fn new(config: &RedisJobConfig) -> Result<Self, JobDefinitionError> {
        config
            .validate()
            .map_err(|_| JobDefinitionError::InvalidConfiguration)?;
        let name =
            JobName::try_from(J::NAME).map_err(|_| JobDefinitionError::InvalidDeclaration)?;
        let version =
            Version::new(J::VERSION).map_err(|_| JobDefinitionError::InvalidDeclaration)?;
        J::POLICY
            .validate_for(J::VERSION)
            .map_err(|_| JobDefinitionError::InvalidDeclaration)?;
        if !valid_metrics_prefix(J::METRICS_PREFIX) || !valid_runbook(J::RUNBOOK) {
            return Err(JobDefinitionError::InvalidDeclaration);
        }
        if J::POLICY.max_attempts() > APALIS_MAX_ATTEMPTS {
            return Err(JobDefinitionError::TooManyAttempts);
        }
        if !matches!(J::POLICY.dead_letter(), DeadLetterPolicy::Retain) {
            return Err(JobDefinitionError::UnsupportedDeadLetterDestination);
        }
        let queue = QueueName::try_from(J::POLICY.queue())
            .map_err(|_| JobDefinitionError::InvalidDeclaration)?;
        let priority = J::POLICY.priority();
        let namespace = format!(
            "{}:jobs:{}:p{}:{}:v{}:d{}",
            config.namespace_prefix,
            queue.as_str(),
            priority,
            name.as_str(),
            version.get(),
            dispatch_policy_fingerprint::<J>()
        );
        if namespace.len() > 512 {
            return Err(JobDefinitionError::NamespaceTooLong);
        }
        Ok(Self {
            name,
            version,
            queue,
            priority,
            namespace,
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

    /// Queue selected by the typed policy.
    #[must_use]
    pub const fn queue(&self) -> &QueueName {
        &self.queue
    }

    /// Priority selected by the typed policy.
    #[must_use]
    pub const fn priority(&self) -> u8 {
        self.priority
    }

    /// Explicit Redis namespace for this exact job version and dispatch policy.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn header_matches(&self, envelope: &EncodedJobEnvelope) -> bool {
        envelope.job_name() == &self.name
            && envelope.version() == self.version
            && envelope.queue() == &self.queue
            && envelope.attempt_policy().max_attempts() == J::POLICY.max_attempts()
            && envelope.attempt_policy().timeout() == J::POLICY.timeout()
    }

    fn accepts(&self, envelope: &EncodedJobEnvelope) -> bool {
        self.header_matches(envelope) && envelope.decode::<J>().is_ok()
    }
}

impl<J> Clone for JobDefinition<J> {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            version: self.version,
            queue: self.queue.clone(),
            priority: self.priority,
            namespace: self.namespace.clone(),
            marker: PhantomData,
        }
    }
}

impl<J> fmt::Debug for JobDefinition<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JobDefinition")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("queue", &self.queue)
            .field("priority", &self.priority)
            .field("namespace", &"[REDACTED]")
            .finish()
    }
}

/// A core job policy unsupported by Apalis Redis 0.7.4.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum JobDefinitionError {
    /// Adapter configuration was invalid.
    #[error("Apalis Redis job configuration is invalid")]
    InvalidConfiguration,
    /// Core name, version, policy, metrics prefix, or runbook is invalid.
    #[error("job declaration is invalid")]
    InvalidDeclaration,
    /// Apalis Redis hardcodes a maximum of five attempts.
    #[error("Apalis Redis supports at most five attempts")]
    TooManyAttempts,
    /// Apalis Redis can retain dead records but cannot publish a destination dead-letter queue.
    #[error("Apalis Redis does not support destination dead-letter queues")]
    UnsupportedDeadLetterDestination,
    /// The fully qualified Redis key namespace exceeded its fixed bound.
    #[error("Apalis Redis job namespace is too long")]
    NamespaceTooLong,
}

/// Safe constructor failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisJobConnectError {
    /// Configuration validation failed.
    #[error(transparent)]
    Config(#[from] RedisJobConfigError),
    /// Typed job definition validation failed.
    #[error(transparent)]
    Definition(#[from] JobDefinitionError),
    /// Redis did not accept a connection before the configured deadline.
    #[error("Apalis Redis is unavailable")]
    Unavailable,
}

/// Redacted observable queue state for one typed job namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JobDiagnostics {
    queued: u64,
    scheduled: u64,
    completed: u64,
    dead_lettered: u64,
    oldest_outstanding_age: Option<Duration>,
    oldest_outstanding_age_complete: bool,
    paused: bool,
    revision: i64,
}

impl JobDiagnostics {
    /// Active records waiting for a worker.
    #[must_use]
    pub const fn queued(self) -> u64 {
        self.queued
    }

    /// Records not yet eligible for delivery.
    #[must_use]
    pub const fn scheduled(self) -> u64 {
        self.scheduled
    }

    /// Successfully completed retained records.
    #[must_use]
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Terminal retained Apalis dead-letter records.
    #[must_use]
    pub const fn dead_lettered(self) -> u64 {
        self.dead_lettered
    }

    /// Age of the oldest canonical envelope observed by the bounded outstanding-record scan.
    #[must_use]
    pub const fn oldest_outstanding_age(self) -> Option<Duration> {
        self.oldest_outstanding_age
    }

    /// Whether the bounded sample covered every active and scheduled record.
    #[must_use]
    pub const fn oldest_outstanding_age_complete(self) -> bool {
        self.oldest_outstanding_age_complete
    }

    /// Whether leasing is durably paused.
    #[must_use]
    pub const fn paused(self) -> bool {
        self.paused
    }

    /// Current namespace control revision.
    #[must_use]
    pub const fn revision(self) -> i64 {
        self.revision
    }
}

/// Durable pause state for one exact Redis job namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedisControlState {
    paused: bool,
    revision: i64,
}

impl RedisControlState {
    /// Whether workers must refrain from leasing.
    #[must_use]
    pub const fn paused(self) -> bool {
        self.paused
    }

    /// Revision used to fence the next administrative mutation.
    #[must_use]
    pub const fn revision(self) -> i64 {
        self.revision
    }
}

/// Bounded dead-letter metadata without the envelope, failure, or result.
#[derive(Clone, Eq, PartialEq)]
pub struct RedisDeadRecord {
    record_id: String,
    job_id: JobId,
    created_at: OffsetDateTime,
    failed_at: OffsetDateTime,
    attempt: u16,
    envelope_bytes: usize,
}

impl RedisDeadRecord {
    /// Opaque Apalis Redis record identifier accepted by [`RedisJobProvider::replay_dead`].
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Stable core job identifier stored inside the canonical envelope.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Canonical envelope creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Time Apalis moved the record to dead storage.
    #[must_use]
    pub const fn failed_at(&self) -> OffsetDateTime {
        self.failed_at
    }

    /// Last one-based delivery attempt.
    #[must_use]
    pub const fn attempt(&self) -> u16 {
        self.attempt
    }

    /// Exact byte count of the stored canonical envelope.
    #[must_use]
    pub const fn envelope_bytes(&self) -> usize {
        self.envelope_bytes
    }
}

impl fmt::Debug for RedisDeadRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisDeadRecord")
            .field("record_id", &self.record_id)
            .field("job_id", &self.job_id)
            .field("created_at", &self.created_at)
            .field("failed_at", &self.failed_at)
            .field("attempt", &self.attempt)
            .field("envelope_bytes", &self.envelope_bytes)
            .finish()
    }
}

/// Provider identity guarantee for a successful Redis dead replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisReplayIdentity {
    /// Both the core job ID and opaque Apalis message ID are preserved.
    SameJobSameMessage,
}

/// Redacted receipt for one atomically replayed Redis dead record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisReplayReceipt {
    record_id: String,
    job_id: JobId,
    identity: RedisReplayIdentity,
    revision: i64,
}

impl RedisReplayReceipt {
    /// Replayed opaque Apalis Redis record identifier.
    #[must_use]
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    /// Preserved core job identifier.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    /// Explicit Redis replay identity guarantee.
    #[must_use]
    pub const fn identity(&self) -> RedisReplayIdentity {
        self.identity
    }

    /// Control revision after replay.
    #[must_use]
    pub const fn revision(&self) -> i64 {
        self.revision
    }
}

/// Safe Redis administrative operation failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisAdminError {
    /// Dead-record list bounds require a value from one through one hundred.
    #[error("Redis dead-record limit is invalid")]
    InvalidLimit,
    /// The expected control revision no longer owns the namespace.
    #[error("Redis job control revision conflicts")]
    RevisionConflict,
    /// Dead replay is permitted only while the namespace is paused.
    #[error("Redis job namespace is not paused")]
    NotPaused,
    /// The opaque dead record does not exist.
    #[error("Redis dead record was not found")]
    RecordNotFound,
    /// Stored provider metadata or its canonical envelope is invalid.
    #[error("Redis dead record is corrupt")]
    CorruptRecord,
    /// Redis did not complete the bounded administrative operation.
    #[error("Redis job administration is unavailable")]
    Unavailable,
}

/// Safe diagnostics failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum JobDiagnosticsError {
    /// Redis did not answer the bounded diagnostic commands.
    #[error("Apalis Redis diagnostics are unavailable")]
    Unavailable,
}

/// Safe worker lifecycle failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisJobWorkerError {
    /// Worker identity was empty, oversized, or not portable.
    #[error("Apalis Redis worker name is invalid")]
    InvalidWorkerName,
    /// Apalis could not complete its bounded worker lifecycle.
    #[error("Apalis Redis worker failed")]
    Runtime,
}

#[derive(Clone, Deserialize, Serialize)]
struct PersistedEnvelope {
    bytes: Vec<u8>,
}

struct WorkerState<J> {
    handler: Arc<dyn JobHandler>,
    definition: JobDefinition<J>,
    storage: RedisStorage<PersistedEnvelope, ConnectionManager>,
    operation_timeout: Duration,
    cancellation: CancellationToken,
}

enum AttemptOutcome {
    Handler(HandlerOutcome),
    TimedOut,
    Panicked,
}

/// Typed Redis provider and object-safe core enqueuer.
///
/// No Apalis or Redis implementation type appears in this public API.
pub struct RedisJobProvider<J> {
    storage: RedisStorage<PersistedEnvelope, ConnectionManager>,
    definition: JobDefinition<J>,
    cleanup_script: redis_apalis::Script,
    control_script: redis_apalis::Script,
    set_paused_script: redis_apalis::Script,
    replay_dead_script: redis_apalis::Script,
    operation_timeout: Duration,
    shutdown_timeout: Duration,
    control_poll_interval: Duration,
}

impl<J: Job> RedisJobProvider<J> {
    /// Connects eagerly and binds one validated typed job namespace.
    ///
    /// # Errors
    ///
    /// Returns [`RedisJobConnectError`] when configuration, declaration, or connectivity fails.
    pub async fn connect(config: &RedisJobConfig) -> Result<Self, RedisJobConnectError> {
        config.validate()?;
        let definition = JobDefinition::new(config)?;
        let client = redis_apalis::Client::open(config.url.expose_secret())
            .map_err(|_| RedisJobConnectError::Unavailable)?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(config.connection_timeout)
            .set_response_timeout(config.operation_timeout);
        let connection = tokio::time::timeout(
            config.connection_timeout,
            client.get_connection_manager_with_config(manager_config),
        )
        .await
        .map_err(|_| RedisJobConnectError::Unavailable)?
        .map_err(|_| RedisJobConnectError::Unavailable)?;
        let backend_config = BackendConfig::default()
            .set_namespace(definition.namespace())
            .set_poll_interval(config.poll_interval)
            .set_enqueue_scheduled(config.scheduled_poll_interval)
            .set_keep_alive(config.keep_alive)
            .set_reenqueue_orphaned_after(config.orphan_after)
            .set_buffer_size(config.buffer_size);
        let storage = RedisStorage::new_with_config(connection, backend_config);
        let control_script = redis_apalis::Script::new(CONTROL_STATE_SCRIPT);
        read_control_state(&storage, &control_script, config.operation_timeout)
            .await
            .map_err(|_| RedisJobConnectError::Unavailable)?;
        Ok(Self {
            storage,
            definition,
            cleanup_script: redis_apalis::Script::new(TERMINAL_CLEANUP_SCRIPT),
            control_script,
            set_paused_script: redis_apalis::Script::new(SET_PAUSED_SCRIPT),
            replay_dead_script: redis_apalis::Script::new(REPLAY_DEAD_SCRIPT),
            operation_timeout: config.operation_timeout,
            shutdown_timeout: config.shutdown_timeout,
            control_poll_interval: config.poll_interval.min(MAX_CONTROL_POLL_INTERVAL),
        })
    }

    /// Validated static job routing.
    #[must_use]
    pub const fn definition(&self) -> &JobDefinition<J> {
        &self.definition
    }

    /// Reads bounded aggregate state without exposing Redis keys, errors, or payloads.
    ///
    /// # Errors
    ///
    /// Returns [`JobDiagnosticsError::Unavailable`] when Redis cannot answer.
    pub async fn diagnostics(&self) -> Result<JobDiagnostics, JobDiagnosticsError> {
        let mut connection = self.storage.get_connection().clone();
        let config = self.storage.get_config();
        let queued = redis_count(
            &mut connection,
            "LLEN",
            &config.active_jobs_list(),
            self.operation_timeout,
        )
        .await?;
        let scheduled = redis_count(
            &mut connection,
            "ZCARD",
            &config.scheduled_jobs_set(),
            self.operation_timeout,
        )
        .await?;
        let completed = redis_count(
            &mut connection,
            "ZCARD",
            &config.done_jobs_set(),
            self.operation_timeout,
        )
        .await?;
        let dead_lettered = redis_count(
            &mut connection,
            "ZCARD",
            &config.dead_jobs_set(),
            self.operation_timeout,
        )
        .await?;
        let oldest = oldest_outstanding_age(
            &self.storage,
            &self.definition,
            queued,
            scheduled,
            self.operation_timeout,
        )
        .await?;
        let control = self
            .control_state()
            .await
            .map_err(|_| JobDiagnosticsError::Unavailable)?;
        Ok(JobDiagnostics {
            queued,
            scheduled,
            completed,
            dead_lettered,
            oldest_outstanding_age: oldest.age,
            oldest_outstanding_age_complete: oldest.complete,
            paused: control.paused(),
            revision: control.revision(),
        })
    }

    /// Reads the durable namespace pause state.
    ///
    /// # Errors
    ///
    /// Returns [`RedisAdminError::Unavailable`] when Redis does not return a valid state before the
    /// fixed operation deadline.
    pub async fn control_state(&self) -> Result<RedisControlState, RedisAdminError> {
        read_control_state(&self.storage, &self.control_script, self.operation_timeout).await
    }

    /// Atomically changes pause state when `expected_revision` still owns the namespace.
    ///
    /// Pausing atomically replaces Apalis's consumer registry with a typed fence before returning.
    /// Its dequeue script must validate that registry before moving any job to an in-flight set, so
    /// no live, crashed, or suspended generation can acquire a lease while the fence is installed.
    ///
    /// # Errors
    ///
    /// Returns [`RedisAdminError::RevisionConflict`] for a stale or invalid revision and
    /// [`RedisAdminError::Unavailable`] when Redis rejects or times out the bounded script.
    pub async fn set_paused(
        &self,
        paused: bool,
        expected_revision: i64,
    ) -> Result<RedisControlState, RedisAdminError> {
        if !(0..=MAX_CONTROL_REVISION).contains(&expected_revision) {
            return Err(RedisAdminError::RevisionConflict);
        }
        let config = self.storage.get_config();
        let mut invocation = self.set_paused_script.prepare_invoke();
        invocation
            .key(control_key(&self.storage))
            .key(config.consumers_set())
            .key(held_consumers_key(&self.storage))
            .arg(i32::from(paused))
            .arg(expected_revision);
        let mut connection = self.storage.get_connection().clone();
        let (status, paused_value, revision) = tokio::time::timeout(
            self.operation_timeout,
            invocation.invoke_async::<(i64, i64, i64)>(&mut connection),
        )
        .await
        .map_err(|_| RedisAdminError::Unavailable)?
        .map_err(|_| RedisAdminError::Unavailable)?;
        if status == 0 {
            return Err(RedisAdminError::RevisionConflict);
        }
        decode_control_state(paused_value, revision)
    }

    /// Lists oldest retained dead records with a strict `1..=100` bound and no failure or payload.
    ///
    /// # Errors
    ///
    /// Returns [`RedisAdminError::InvalidLimit`] outside the bound,
    /// [`RedisAdminError::CorruptRecord`] for invalid retained metadata, or
    /// [`RedisAdminError::Unavailable`] when Redis cannot complete the fixed-deadline operation.
    pub async fn dead_records(
        &self,
        limit: usize,
    ) -> Result<Vec<RedisDeadRecord>, RedisAdminError> {
        let limit = dead_record_limit(limit)?;
        tokio::time::timeout(
            self.operation_timeout,
            dead_records_unbounded(&self.storage, &self.definition, limit),
        )
        .await
        .map_err(|_| RedisAdminError::Unavailable)?
    }

    /// Atomically returns one exact retained request to the active queue while paused.
    ///
    /// # Errors
    ///
    /// Returns [`RedisAdminError::RevisionConflict`] for a stale revision,
    /// [`RedisAdminError::NotPaused`] while leasing is enabled,
    /// [`RedisAdminError::RecordNotFound`] when the opaque record was already moved, and safe
    /// corruption or availability errors for invalid storage.
    pub async fn replay_dead(
        &self,
        record_id: &str,
        expected_revision: i64,
    ) -> Result<RedisReplayReceipt, RedisAdminError> {
        if !(0..=MAX_CONTROL_REVISION).contains(&expected_revision) {
            return Err(RedisAdminError::RevisionConflict);
        }
        if record_id.is_empty() || record_id.len() > MAX_RECORD_ID_BYTES {
            return Err(RedisAdminError::RecordNotFound);
        }
        tokio::time::timeout(
            self.operation_timeout,
            replay_dead_unbounded(self, record_id, expected_revision),
        )
        .await
        .map_err(|_| RedisAdminError::Unavailable)?
    }

    /// Runs a real Apalis worker until `cancellation` fires, then stops leasing and drains bounded
    /// in-flight work. Cooperative handlers observe the same cancellation through
    /// [`DeliveryContext::cancellation`].
    ///
    /// Tower concurrency and optional starts-per-minute limits come directly from `J::POLICY` and
    /// are instantiated per physical worker invocation; horizontal replicas multiply aggregate
    /// capacity. Handler timeout, retry classification, bounded exponential jitter, and terminal
    /// dead-letter mapping are applied per one-based delivery attempt.
    ///
    /// # Errors
    ///
    /// Returns [`RedisJobWorkerError`] for an invalid worker identity or lifecycle failure.
    pub async fn run_worker<H>(
        &self,
        worker_name: &str,
        handler: H,
        cancellation: CancellationToken,
    ) -> Result<(), RedisJobWorkerError>
    where
        H: TypedJobHandler<J>,
    {
        if !valid_logical_worker_name(worker_name) {
            return Err(RedisJobWorkerError::InvalidWorkerName);
        }
        install_redacting_panic_hook();
        let physical_worker_name =
            physical_worker_name(worker_name).map_err(|()| RedisJobWorkerError::Runtime)?;
        let runtime_cancellation = cancellation.child_token();
        let handler: Arc<dyn JobHandler> = Arc::new(TypedJobHandlerAdapter::<J, H>::new(handler));
        let workers = worker_supervisor(
            self,
            &physical_worker_name,
            handler,
            runtime_cancellation.clone(),
        );
        let cleanup = retention_loop(
            self.storage.clone(),
            self.cleanup_script.clone(),
            J::POLICY.retention(),
            self.operation_timeout,
            runtime_cancellation.clone(),
        );
        tokio::pin!(workers);
        tokio::pin!(cleanup);
        let lifecycle_failed = tokio::select! {
            worker_result = &mut workers => {
                runtime_cancellation.cancel();
                worker_result.is_err() || cleanup.await.is_err()
            }
            cleanup_result = &mut cleanup => {
                runtime_cancellation.cancel();
                cleanup_result.is_err() || workers.await.is_err()
            }
        };
        if lifecycle_failed {
            Err(RedisJobWorkerError::Runtime)
        } else {
            Ok(())
        }
    }
}

impl<J> Clone for RedisJobProvider<J> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            definition: self.definition.clone(),
            shutdown_timeout: self.shutdown_timeout,
            cleanup_script: self.cleanup_script.clone(),
            control_script: self.control_script.clone(),
            set_paused_script: self.set_paused_script.clone(),
            replay_dead_script: self.replay_dead_script.clone(),
            operation_timeout: self.operation_timeout,
            control_poll_interval: self.control_poll_interval,
        }
    }
}

impl<J> fmt::Debug for RedisJobProvider<J> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisJobProvider")
            .field("storage", &"[REDACTED]")
            .field("scripts", &"[REDACTED]")
            .field("definition", &self.definition)
            .field("operation_timeout", &self.operation_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("control_poll_interval", &self.control_poll_interval)
            .finish_non_exhaustive()
    }
}

impl<J: Job> JobEnqueuer for RedisJobProvider<J> {
    fn enqueue(
        &self,
        envelope: EncodedJobEnvelope,
    ) -> BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>> {
        Box::pin(async move {
            if !self.definition.accepts(&envelope) {
                return Err(EnqueueError::InvalidEnvelope);
            }
            let job_id = envelope.id();
            let queue = self.definition.queue.clone();
            let not_before = envelope.not_before();
            let request = apalis::prelude::Request::new(PersistedEnvelope {
                bytes: envelope.bytes().to_vec(),
            });
            let mut storage = self.storage.clone();
            let now = OffsetDateTime::now_utc();
            let operation = async {
                if let Some(eligible_at) = not_before
                    && eligible_at > now
                {
                    let timestamp = ceil_unix_seconds(eligible_at).ok_or(EnqueueError::Rejected)?;
                    storage
                        .schedule_request(request, timestamp)
                        .await
                        .map_err(|_| EnqueueError::Unavailable)
                } else {
                    storage
                        .push_request(request)
                        .await
                        .map_err(|_| EnqueueError::Unavailable)
                }
            };
            tokio::time::timeout(self.operation_timeout, operation)
                .await
                .map_err(|_| EnqueueError::Unavailable)??;
            Ok(EnqueueReceipt::new(
                job_id,
                queue,
                OffsetDateTime::now_utc(),
            ))
        })
    }
}

enum ControlWatch {
    StopLeasing,
    Shutdown,
}

async fn worker_supervisor<J: Job>(
    provider: &RedisJobProvider<J>,
    physical_worker_name: &str,
    handler: Arc<dyn JobHandler>,
    cancellation: CancellationToken,
) -> Result<(), RedisJobWorkerError> {
    loop {
        match wait_until_leasing_enabled(provider, &cancellation).await {
            ControlWatch::Shutdown => return Ok(()),
            ControlWatch::StopLeasing => {}
        }
        match run_worker_generation(
            provider,
            physical_worker_name,
            Arc::clone(&handler),
            &cancellation,
        )
        .await?
        {
            ControlWatch::Shutdown => return Ok(()),
            ControlWatch::StopLeasing => {}
        }
    }
}

async fn wait_until_leasing_enabled<J: Job>(
    provider: &RedisJobProvider<J>,
    cancellation: &CancellationToken,
) -> ControlWatch {
    loop {
        let state = tokio::select! {
            () = cancellation.cancelled() => return ControlWatch::Shutdown,
            state = provider.control_state() => state,
        };
        if matches!(state, Ok(state) if !state.paused()) {
            return ControlWatch::StopLeasing;
        }
        tokio::select! {
            () = cancellation.cancelled() => return ControlWatch::Shutdown,
            () = tokio::time::sleep(provider.control_poll_interval) => {}
        }
    }
}

async fn watch_worker_control<J: Job>(
    provider: &RedisJobProvider<J>,
    cancellation: &CancellationToken,
) -> ControlWatch {
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return ControlWatch::Shutdown,
            () = tokio::time::sleep(provider.control_poll_interval) => {}
        }
        let state = tokio::select! {
            () = cancellation.cancelled() => return ControlWatch::Shutdown,
            state = provider.control_state() => state,
        };
        if !matches!(state, Ok(state) if !state.paused()) {
            return ControlWatch::StopLeasing;
        }
    }
}

async fn run_worker_generation<J: Job>(
    provider: &RedisJobProvider<J>,
    physical_worker_name: &str,
    handler: Arc<dyn JobHandler>,
    cancellation: &CancellationToken,
) -> Result<ControlWatch, RedisJobWorkerError> {
    let generation_cancellation = cancellation.child_token();
    let state = Arc::new(WorkerState {
        handler,
        definition: provider.definition.clone(),
        cancellation: generation_cancellation.clone(),
        storage: provider.storage.clone(),
        operation_timeout: provider.operation_timeout,
    });
    let rate_limit = J::POLICY
        .rate_per_minute()
        .map(|rate| RateLimitLayer::new(u64::from(rate), Duration::from_secs(60)));
    let fatal_ack = Arc::new(AtomicBool::new(false));
    let event_fatal_ack = Arc::clone(&fatal_ack);
    let event_cancellation = generation_cancellation.clone();
    let worker = WorkerBuilder::new(physical_worker_name)
        .concurrency(usize::from(J::POLICY.max_concurrency()))
        .option_layer(rate_limit)
        .data(state)
        .backend(provider.storage.clone())
        .build_fn(execute::<J>);
    let signal_cancellation = generation_cancellation.clone();
    let signal = async move {
        signal_cancellation.cancelled().await;
        Ok(())
    };
    let shutdown_timeout = provider.shutdown_timeout;
    let monitor = Monitor::new()
        .on_event(move |event| {
            if let Event::Error(error) = event.inner()
                && matches!(
                    error.downcast_ref::<RedisPollError>(),
                    Some(RedisPollError::AckError(_))
                )
            {
                event_fatal_ack.store(true, Ordering::Release);
                event_cancellation.cancel();
            }
        })
        .register(worker)
        .with_terminator(async move {
            tokio::time::sleep(shutdown_timeout).await;
        })
        .run_with_signal(signal);
    let control = watch_worker_control(provider, cancellation);
    tokio::pin!(monitor);
    tokio::pin!(control);
    let (decision, lifecycle_failed) = tokio::select! {
        result = &mut monitor => {
            generation_cancellation.cancel();
            (
                if cancellation.is_cancelled() {
                    ControlWatch::Shutdown
                } else {
                    ControlWatch::StopLeasing
                },
                result.is_err() || fatal_ack.load(Ordering::Acquire),
            )
        }
        decision = &mut control => {
            generation_cancellation.cancel();
            (decision, monitor.await.is_err())
        }
    };
    let recovery_failed = recover_inflight(
        &provider.storage,
        physical_worker_name,
        provider.operation_timeout,
    )
    .await
    .is_err();
    if lifecycle_failed || recovery_failed || fatal_ack.load(Ordering::Acquire) {
        Err(RedisJobWorkerError::Runtime)
    } else {
        Ok(decision)
    }
}

fn control_key(storage: &RedisStorage<PersistedEnvelope, ConnectionManager>) -> String {
    format!("{}:admin:control", storage.get_config().get_namespace())
}

fn held_consumers_key(storage: &RedisStorage<PersistedEnvelope, ConnectionManager>) -> String {
    format!(
        "{}:admin:paused-consumers",
        storage.get_config().get_namespace()
    )
}

fn result_hash(storage: &RedisStorage<PersistedEnvelope, ConnectionManager>) -> String {
    format!("{}::result", storage.get_config().job_data_hash())
}

async fn read_control_state(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    script: &redis_apalis::Script,
    operation_timeout: Duration,
) -> Result<RedisControlState, RedisAdminError> {
    let mut invocation = script.prepare_invoke();
    invocation.key(control_key(storage));
    let mut connection = storage.get_connection().clone();
    let (paused, revision) = tokio::time::timeout(
        operation_timeout,
        invocation.invoke_async::<(i64, i64)>(&mut connection),
    )
    .await
    .map_err(|_| RedisAdminError::Unavailable)?
    .map_err(|_| RedisAdminError::Unavailable)?;
    decode_control_state(paused, revision)
}

fn decode_control_state(paused: i64, revision: i64) -> Result<RedisControlState, RedisAdminError> {
    if !(0..=MAX_CONTROL_REVISION).contains(&revision) {
        return Err(RedisAdminError::Unavailable);
    }
    let paused = match paused {
        0 => false,
        1 => true,
        _ => return Err(RedisAdminError::Unavailable),
    };
    Ok(RedisControlState { paused, revision })
}

fn dead_record_limit(limit: usize) -> Result<usize, RedisAdminError> {
    if (1..=MAX_DEAD_RECORDS).contains(&limit) {
        Ok(limit)
    } else {
        Err(RedisAdminError::InvalidLimit)
    }
}

struct OldestOutstanding {
    age: Option<Duration>,
    complete: bool,
}

async fn oldest_outstanding_age<J: Job>(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    definition: &JobDefinition<J>,
    queued: u64,
    scheduled: u64,
    operation_timeout: Duration,
) -> Result<OldestOutstanding, JobDiagnosticsError> {
    let operation = async {
        let config = storage.get_config();
        let mut connection = storage.get_connection().clone();
        let active_limit = usize::try_from(queued.min(MAX_DIAGNOSTIC_RECORDS as u64))
            .map_err(|_| JobDiagnosticsError::Unavailable)?;
        let scheduled_limit =
            usize::try_from(scheduled.min((MAX_DIAGNOSTIC_RECORDS - active_limit) as u64))
                .map_err(|_| JobDiagnosticsError::Unavailable)?;
        let active = if active_limit == 0 {
            Vec::new()
        } else {
            redis_apalis::cmd("LRANGE")
                .arg(config.active_jobs_list())
                .arg(0)
                .arg(
                    i64::try_from(active_limit - 1)
                        .map_err(|_| JobDiagnosticsError::Unavailable)?,
                )
                .query_async::<Vec<String>>(&mut connection)
                .await
                .map_err(|_| JobDiagnosticsError::Unavailable)?
        };
        let scheduled_records = if scheduled_limit == 0 {
            Vec::new()
        } else {
            redis_apalis::cmd("ZRANGE")
                .arg(config.scheduled_jobs_set())
                .arg(0)
                .arg(
                    i64::try_from(scheduled_limit - 1)
                        .map_err(|_| JobDiagnosticsError::Unavailable)?,
                )
                .query_async::<Vec<String>>(&mut connection)
                .await
                .map_err(|_| JobDiagnosticsError::Unavailable)?
        };
        let mut fetched_storage = storage.clone();
        let mut oldest = None;
        for record_id in active.iter().chain(&scheduled_records) {
            let task_id = record_id
                .parse::<TaskId>()
                .map_err(|_| JobDiagnosticsError::Unavailable)?;
            let request = fetched_storage
                .fetch_by_id(&task_id)
                .await
                .map_err(|_| JobDiagnosticsError::Unavailable)?
                .ok_or(JobDiagnosticsError::Unavailable)?;
            let envelope =
                EncodedJobEnvelope::restore(&request.args.bytes, definition.queue.clone())
                    .map_err(|_| JobDiagnosticsError::Unavailable)?;
            if !definition.header_matches(&envelope) {
                return Err(JobDiagnosticsError::Unavailable);
            }
            oldest = Some(
                oldest.map_or(envelope.created_at(), |current: OffsetDateTime| {
                    current.min(envelope.created_at())
                }),
            );
        }
        let age = oldest.map(|created_at| {
            let now = OffsetDateTime::now_utc();
            if created_at >= now {
                Duration::ZERO
            } else {
                Duration::try_from(now - created_at).unwrap_or(Duration::MAX)
            }
        });
        Ok(OldestOutstanding {
            age,
            complete: queued.saturating_add(scheduled) <= MAX_DIAGNOSTIC_RECORDS as u64,
        })
    };
    tokio::time::timeout(operation_timeout, operation)
        .await
        .map_err(|_| JobDiagnosticsError::Unavailable)?
}

async fn dead_records_unbounded<J: Job>(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    definition: &JobDefinition<J>,
    limit: usize,
) -> Result<Vec<RedisDeadRecord>, RedisAdminError> {
    let mut connection = storage.get_connection().clone();
    let maximum = i64::try_from(limit - 1).map_err(|_| RedisAdminError::InvalidLimit)?;
    let values: Vec<(String, i64)> = redis_apalis::cmd("ZRANGE")
        .arg(storage.get_config().dead_jobs_set())
        .arg(0)
        .arg(maximum)
        .arg("WITHSCORES")
        .query_async(&mut connection)
        .await
        .map_err(|_| RedisAdminError::Unavailable)?;
    let mut fetched_storage = storage.clone();
    let mut records = Vec::with_capacity(values.len());
    for (record_id, failed_at) in values {
        records
            .push(fetch_dead_record(&mut fetched_storage, definition, record_id, failed_at).await?);
    }
    Ok(records)
}

async fn fetch_dead_record<J: Job>(
    storage: &mut RedisStorage<PersistedEnvelope, ConnectionManager>,
    definition: &JobDefinition<J>,
    record_id: String,
    failed_at: i64,
) -> Result<RedisDeadRecord, RedisAdminError> {
    if record_id.is_empty() || record_id.len() > MAX_RECORD_ID_BYTES {
        return Err(RedisAdminError::CorruptRecord);
    }
    let task_id = record_id
        .parse::<TaskId>()
        .map_err(|_| RedisAdminError::CorruptRecord)?;
    let request = storage
        .fetch_by_id(&task_id)
        .await
        .map_err(|_| RedisAdminError::Unavailable)?
        .ok_or(RedisAdminError::CorruptRecord)?;
    if request.parts.task_id.to_string() != record_id {
        return Err(RedisAdminError::CorruptRecord);
    }
    let attempt = u16::try_from(request.parts.attempt.current())
        .map_err(|_| RedisAdminError::CorruptRecord)?;
    if attempt == 0 {
        return Err(RedisAdminError::CorruptRecord);
    }
    let envelope = EncodedJobEnvelope::restore(&request.args.bytes, definition.queue.clone())
        .map_err(|_| RedisAdminError::CorruptRecord)?;
    if !definition.header_matches(&envelope) {
        return Err(RedisAdminError::CorruptRecord);
    }
    let created_at = envelope.created_at();
    let failed_at = OffsetDateTime::from_unix_timestamp(failed_at)
        .map_err(|_| RedisAdminError::CorruptRecord)?
        .max(created_at);
    Ok(RedisDeadRecord {
        record_id,
        job_id: envelope.id(),
        created_at,
        failed_at,
        attempt,
        envelope_bytes: request.args.bytes.len(),
    })
}

async fn replay_dead_unbounded<J: Job>(
    provider: &RedisJobProvider<J>,
    record_id: &str,
    expected_revision: i64,
) -> Result<RedisReplayReceipt, RedisAdminError> {
    record_id
        .parse::<TaskId>()
        .map_err(|_| RedisAdminError::RecordNotFound)?;
    let config = provider.storage.get_config();
    let mut connection = provider.storage.get_connection().clone();
    let failed_at: Option<i64> = redis_apalis::cmd("ZSCORE")
        .arg(config.dead_jobs_set())
        .arg(record_id)
        .query_async(&mut connection)
        .await
        .map_err(|_| RedisAdminError::Unavailable)?;
    let failed_at = failed_at.ok_or(RedisAdminError::RecordNotFound)?;
    let mut storage = provider.storage.clone();
    let record = fetch_dead_record(
        &mut storage,
        &provider.definition,
        record_id.to_owned(),
        failed_at,
    )
    .await?;
    let mut invocation = provider.replay_dead_script.prepare_invoke();
    invocation
        .key(control_key(&provider.storage))
        .key(config.consumers_set())
        .key(config.dead_jobs_set())
        .key(config.job_data_hash())
        .key(result_hash(&provider.storage))
        .key(config.active_jobs_list())
        .key(config.signal_list())
        .arg(expected_revision)
        .arg(record_id);
    let (status, revision) = invocation
        .invoke_async::<(i64, i64)>(&mut connection)
        .await
        .map_err(|_| RedisAdminError::Unavailable)?;
    match status {
        0 => Err(RedisAdminError::RevisionConflict),
        1 => Err(RedisAdminError::NotPaused),
        2 => Err(RedisAdminError::RecordNotFound),
        3 => Err(RedisAdminError::CorruptRecord),
        4 => Ok(RedisReplayReceipt {
            record_id: record.record_id,
            job_id: record.job_id,
            identity: RedisReplayIdentity::SameJobSameMessage,
            revision,
        }),
        _ => Err(RedisAdminError::Unavailable),
    }
}

async fn execute<J: Job>(
    persisted: PersistedEnvelope,
    task_id: TaskId,
    attempt: Attempt,
    state: Data<Arc<WorkerState<J>>>,
) -> Result<(), ApalisError> {
    persist_delivery_attempt(&state.storage, &task_id, &attempt, state.operation_timeout).await?;
    let envelope = EncodedJobEnvelope::restore(&persisted.bytes, state.definition.queue.clone())
        .map_err(|_| delivery_error(true))?;
    if !state.definition.header_matches(&envelope) {
        return Err(delivery_error(true));
    }
    let attempt_number = u16::try_from(attempt.current()).map_err(|_| delivery_error(true))?;
    let timeout = J::POLICY.timeout();
    let deadline = deadline_after(timeout).ok_or_else(|| delivery_error(true))?;
    let attempt_cancellation = state.cancellation.child_token();
    let context = DeliveryContext::from_envelope(
        &envelope,
        attempt_number,
        attempt_cancellation.clone(),
        deadline,
    )
    .map_err(|_| delivery_error(true))?;
    let handler = with_redacted_handler_panic(|| {
        panic::catch_unwind(AssertUnwindSafe(|| state.handler.handle(envelope, context)))
    })
    .map_err(|_| delivery_error(true))?;
    let mut handler = handler;
    let handler = poll_fn(move |context| {
        with_redacted_handler_panic(|| {
            match panic::catch_unwind(AssertUnwindSafe(|| handler.as_mut().poll(context))) {
                Ok(Poll::Ready(outcome)) => Poll::Ready(Ok(outcome)),
                Ok(Poll::Pending) => Poll::Pending,
                Err(_) => Poll::Ready(Err(())),
            }
        })
    });
    tokio::pin!(handler);
    let outcome = tokio::select! {
        outcome = &mut handler => match outcome {
            Ok(outcome) => AttemptOutcome::Handler(outcome),
            Err(()) => AttemptOutcome::Panicked,
        },
        () = tokio::time::sleep(timeout) => {
            attempt_cancellation.cancel();
            AttemptOutcome::TimedOut
        }
    };
    match outcome {
        AttemptOutcome::Handler(HandlerOutcome::Succeeded) => Ok(()),
        AttemptOutcome::Handler(HandlerOutcome::Permanent(_)) | AttemptOutcome::Panicked => {
            Err(delivery_error(true))
        }
        AttemptOutcome::Handler(HandlerOutcome::Retryable(_)) | AttemptOutcome::TimedOut => {
            retry_or_dead_letter::<J>(attempt_number, &state.cancellation, true).await
        }
        AttemptOutcome::Handler(HandlerOutcome::Cancelled) => {
            retry_or_dead_letter::<J>(attempt_number, &state.cancellation, false).await
        }
    }
}

async fn persist_delivery_attempt(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    task_id: &TaskId,
    attempt: &Attempt,
    operation_timeout: Duration,
) -> Result<(), ApalisError> {
    let mut storage = storage.clone();
    let fetched = tokio::time::timeout(operation_timeout, storage.fetch_by_id(task_id))
        .await
        .map_err(|_| delivery_error(false))?
        .map_err(|_| delivery_error(false))?;
    let Some(mut request) = fetched else {
        return Err(delivery_error(true));
    };
    request.parts.attempt = attempt.clone();
    tokio::time::timeout(operation_timeout, storage.update(request))
        .await
        .map_err(|_| delivery_error(false))?
        .map_err(|_| delivery_error(false))
}

async fn retry_or_dead_letter<J: Job>(
    attempt: u16,
    cancellation: &CancellationToken,
    apply_backoff: bool,
) -> Result<(), ApalisError> {
    if attempt >= J::POLICY.max_attempts() {
        return Err(delivery_error(true));
    }
    if apply_backoff {
        let delay = jittered_backoff::<J>(attempt);
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            () = cancellation.cancelled() => {}
        }
    }
    Err(delivery_error(false))
}

#[derive(Debug, Error)]
#[error("job delivery failed")]
struct SafeDeliveryError;

fn delivery_error(terminal: bool) -> ApalisError {
    let boxed: BoxDynError = Box::new(SafeDeliveryError);
    if terminal {
        ApalisError::Abort(Arc::new(boxed))
    } else {
        ApalisError::Failed(Arc::new(boxed))
    }
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

fn jittered_backoff<J: Job>(attempt: u16) -> Duration {
    let initial_ms = u64::try_from(J::POLICY.initial_backoff().as_millis()).unwrap_or(u64::MAX);
    let maximum_ms = u64::try_from(J::POLICY.max_backoff().as_millis()).unwrap_or(u64::MAX);
    let mut ceiling_ms = initial_ms;
    for _ in 1..attempt {
        ceiling_ms = ceiling_ms
            .saturating_mul(u64::from(J::POLICY.multiplier()))
            .min(maximum_ms);
    }
    let sample = entropy(attempt);
    let delay_ms = match J::POLICY.jitter() {
        omnius_jobs_core::Jitter::Full => uniform_inclusive(sample, ceiling_ms),
        omnius_jobs_core::Jitter::Equal => {
            let half = ceiling_ms / 2;
            half + uniform_inclusive(sample, ceiling_ms - half)
        }
    };
    Duration::from_millis(delay_ms)
}

fn entropy(attempt: u16) -> u64 {
    let mut bytes = [0_u8; 8];
    if OsRng.try_fill_bytes(&mut bytes).is_ok() {
        return u64::from_le_bytes(bytes);
    }
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seed = time.as_secs() ^ u64::from(time.subsec_nanos()) ^ u64::from(attempt);
    mix(seed)
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

fn deadline_after(timeout: Duration) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(timeout.as_secs()).ok()?;
    OffsetDateTime::now_utc().checked_add(time::Duration::seconds(seconds))
}

fn ceil_unix_seconds(value: OffsetDateTime) -> Option<i64> {
    let nanos = value.unix_timestamp_nanos();
    let mut seconds = nanos.div_euclid(NANOS_PER_SECOND);
    if nanos.rem_euclid(NANOS_PER_SECOND) != 0 {
        seconds += 1;
    }
    i64::try_from(seconds).ok()
}

async fn recover_inflight(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    physical_worker_name: &str,
    operation_timeout: Duration,
) -> Result<usize, WorkerRecoveryFailure> {
    let config = storage.get_config();
    let inflight = format!("{}:{physical_worker_name}", config.inflight_jobs_set());
    let script = redis_apalis::Script::new(RECOVER_INFLIGHT_SCRIPT);
    let mut invocation = script.prepare_invoke();
    invocation
        .key(inflight)
        .key(config.active_jobs_list())
        .key(config.consumers_set())
        .key(config.signal_list())
        .key(held_consumers_key(storage));
    let mut connection = storage.get_connection().clone();
    let recovered = tokio::time::timeout(
        operation_timeout,
        invocation.invoke_async::<i64>(&mut connection),
    )
    .await
    .map_err(|_| WorkerRecoveryFailure)?
    .map_err(|_| WorkerRecoveryFailure)?;
    usize::try_from(recovered).map_err(|_| WorkerRecoveryFailure)
}

#[derive(Clone, Copy, Debug)]
struct WorkerRecoveryFailure;

async fn retention_loop(
    storage: RedisStorage<PersistedEnvelope, ConnectionManager>,
    script: redis_apalis::Script,
    retention: Duration,
    operation_timeout: Duration,
    cancellation: CancellationToken,
) -> Result<(), CleanupFailure> {
    let interval = cleanup_interval(retention);
    let mut next_delay = Duration::ZERO;
    let mut consecutive_failures = 0_u8;
    loop {
        tokio::select! {
            () = cancellation.cancelled() => return Ok(()),
            () = tokio::time::sleep(next_delay) => {}
        }
        match cleanup_terminal_batch(&storage, &script, retention, operation_timeout).await {
            Ok(removed) => {
                consecutive_failures = 0;
                next_delay = if removed >= CLEANUP_BATCH_SIZE {
                    Duration::ZERO
                } else {
                    interval
                };
            }
            Err(error) => {
                consecutive_failures = consecutive_failures.saturating_add(1);
                if consecutive_failures >= CLEANUP_FAILURE_LIMIT {
                    return Err(error);
                }
                next_delay = interval.min(CLEANUP_RETRY_INTERVAL);
            }
        }
    }
}

async fn cleanup_terminal_batch(
    storage: &RedisStorage<PersistedEnvelope, ConnectionManager>,
    script: &redis_apalis::Script,
    retention: Duration,
    operation_timeout: Duration,
) -> Result<usize, CleanupFailure> {
    let retention_seconds = i64::try_from(retention.as_secs()).map_err(|_| CleanupFailure)?;
    // Apalis floors terminal timestamps to seconds, so one extra second prevents early expiry.
    let cutoff = OffsetDateTime::now_utc()
        .unix_timestamp()
        .checked_sub(retention_seconds)
        .and_then(|seconds| seconds.checked_sub(1))
        .ok_or(CleanupFailure)?;
    let config = storage.get_config();
    let mut connection = storage.get_connection().clone();
    let mut invocation = script.prepare_invoke();
    let data_hash = config.job_data_hash();
    let result_hash = format!("{data_hash}::result");
    invocation
        .key(config.done_jobs_set())
        .key(config.dead_jobs_set())
        .key(data_hash)
        .key(result_hash)
        .arg(cutoff)
        .arg(CLEANUP_BATCH_SIZE);
    let removed = tokio::time::timeout(
        operation_timeout,
        invocation.invoke_async::<i64>(&mut connection),
    )
    .await
    .map_err(|_| CleanupFailure)?
    .map_err(|_| CleanupFailure)?;
    usize::try_from(removed).map_err(|_| CleanupFailure)
}

fn cleanup_interval(retention: Duration) -> Duration {
    retention
        .checked_div(2)
        .unwrap_or(retention)
        .min(MAX_CLEANUP_INTERVAL)
        .max(Duration::from_millis(100))
}

#[derive(Clone, Copy, Debug)]
struct CleanupFailure;

fn dispatch_policy_fingerprint<J: Job>() -> String {
    let policy = J::POLICY;
    let mut hasher = Sha256::new();
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
    let queue = policy.queue().as_bytes();
    hasher.update(u64::try_from(queue.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(queue);
    hasher.update([policy.priority()]);
    hasher.update(policy.retention().as_secs().to_be_bytes());
    match policy.dead_letter() {
        DeadLetterPolicy::Retain => hasher.update([0]),
        DeadLetterPolicy::Destination(destination) => {
            hasher.update([1]);
            hasher.update(
                u64::try_from(destination.len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            hasher.update(destination.as_bytes());
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
    hex_string(&digest[..16])
}

fn physical_worker_name(logical_name: &str) -> Result<String, ()> {
    let mut random = [0_u8; WORKER_RANDOM_BYTES];
    OsRng.try_fill_bytes(&mut random).map_err(|_| ())?;
    let mut physical = String::with_capacity(logical_name.len() + WORKER_SUFFIX_BYTES);
    physical.push_str(logical_name);
    physical.push('-');
    push_hex(&mut physical, &random);
    Ok(physical)
}

fn hex_string(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    push_hex(&mut encoded, bytes);
    encoded
}

fn push_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

async fn redis_count(
    connection: &mut ConnectionManager,
    command: &'static str,
    key: &str,
    operation_timeout: Duration,
) -> Result<u64, JobDiagnosticsError> {
    tokio::time::timeout(
        operation_timeout,
        redis_apalis::cmd(command).arg(key).query_async(connection),
    )
    .await
    .map_err(|_| JobDiagnosticsError::Unavailable)?
    .map_err(|_| JobDiagnosticsError::Unavailable)
}

fn valid_namespace_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_NAMESPACE_BYTES
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.as_bytes()[value.len() - 1].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn valid_logical_worker_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .len()
            .checked_add(WORKER_SUFFIX_BYTES)
            .is_some_and(|length| length <= MAX_PHYSICAL_WORKER_NAME_BYTES)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
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
    error: RedisJobConfigError,
) -> Result<(), RedisJobConfigError> {
    if value.is_zero() || value > maximum {
        Err(error)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use omnius_config::SecretString;
    use omnius_jobs_core::{
        CompatibilityPolicy, DeadLetterPolicy, IdempotencyRequirement, Jitter, JobPolicy,
    };
    use serde::{Deserialize, Serialize};

    use super::*;

    const fn policy(max_attempts: u16, dead_letter: DeadLetterPolicy) -> JobPolicy {
        match JobPolicy::new(
            IdempotencyRequirement::Optional,
            max_attempts,
            10,
            100,
            2,
            Jitter::Equal,
            1,
            2,
            None,
            "unit",
            4,
            60,
            dead_letter,
            CompatibilityPolicy::Exact,
            1_024,
        ) {
            Ok(policy) => policy,
            Err(_) => panic!("test policy must be valid"),
        }
    }

    #[derive(Deserialize, Serialize)]
    struct ValidJob {
        value: u8,
    }

    impl Job for ValidJob {
        const NAME: &'static str = "unit.valid";
        const VERSION: u16 = 1;
        const POLICY: JobPolicy = policy(3, DeadLetterPolicy::Retain);
        const METRICS_PREFIX: &'static str = "unit_valid";
        const RUNBOOK: &'static str = "runbooks/unit-valid";
    }

    #[derive(Deserialize, Serialize)]
    struct ChangedPolicyJob;

    impl Job for ChangedPolicyJob {
        const NAME: &'static str = "unit.valid";
        const VERSION: u16 = 1;
        const POLICY: JobPolicy = policy(4, DeadLetterPolicy::Retain);
        const METRICS_PREFIX: &'static str = "unit_valid";
        const RUNBOOK: &'static str = "runbooks/unit-valid";
    }

    #[derive(Deserialize, Serialize)]
    struct TooManyAttemptsJob;

    impl Job for TooManyAttemptsJob {
        const NAME: &'static str = "unit.too_many";
        const VERSION: u16 = 1;
        const POLICY: JobPolicy = policy(6, DeadLetterPolicy::Retain);
        const METRICS_PREFIX: &'static str = "unit_too_many";
        const RUNBOOK: &'static str = "runbooks/unit-too-many";
    }

    #[derive(Deserialize, Serialize)]
    struct DestinationJob;

    impl Job for DestinationJob {
        const NAME: &'static str = "unit.destination";
        const VERSION: u16 = 1;
        const POLICY: JobPolicy = policy(3, DeadLetterPolicy::Destination("jobs.failed"));
        const METRICS_PREFIX: &'static str = "unit_destination";
        const RUNBOOK: &'static str = "runbooks/unit-destination";
    }

    fn config() -> RedisJobConfig {
        RedisJobConfig::new(SecretString::from(
            "redis://default:top-secret@127.0.0.1:6379".to_owned(),
        ))
    }

    #[test]
    fn config_debug_redacts_connection_secret_and_key_namespace() {
        let rendered = format!("{:?}", config());
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("top-secret"));
        assert!(!rendered.contains("omnius:v1"));
    }

    #[test]
    fn config_rejects_malformed_url_and_unbounded_timing() {
        let malformed = RedisJobConfig::new(SecretString::from("not a URL".to_owned()));
        assert_eq!(malformed.validate(), Err(RedisJobConfigError::InvalidUrl));
        let zero_poll = config().with_poll_interval(Duration::ZERO);
        assert_eq!(
            zero_poll.validate(),
            Err(RedisJobConfigError::InvalidPollInterval)
        );
        let invalid_namespace = config().with_namespace_prefix("unsafe namespace");
        assert_eq!(
            invalid_namespace.validate(),
            Err(RedisJobConfigError::InvalidNamespace)
        );
        let unsafe_recovery =
            config().with_orphan_recovery(Duration::from_secs(10), Duration::from_secs(15));
        assert_eq!(
            unsafe_recovery.validate(),
            Err(RedisJobConfigError::InvalidOrphanRecovery)
        );
    }

    #[test]
    fn config_rejects_zero_operation_timeout() {
        let invalid = config().with_operation_timeout(Duration::ZERO);
        assert_eq!(
            invalid.validate(),
            Err(RedisJobConfigError::InvalidOperationTimeout)
        );
    }

    #[test]
    fn config_rejects_excessive_operation_timeout() {
        let invalid =
            config().with_operation_timeout(MAX_OPERATION_TIMEOUT + Duration::from_nanos(1));
        assert_eq!(
            invalid.validate(),
            Err(RedisJobConfigError::InvalidOperationTimeout)
        );
    }

    #[test]
    fn config_rejects_multi_record_backend_buffer() {
        let invalid = config().with_buffer_size(2);
        assert_eq!(
            invalid.validate(),
            Err(RedisJobConfigError::InvalidBufferSize)
        );
    }

    #[test]
    fn definition_namespaces_exact_version_and_dispatch_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let definition = JobDefinition::<ValidJob>::new(&config())?;
        let changed = JobDefinition::<ChangedPolicyJob>::new(&config())?;
        assert!(definition.namespace().contains(":unit.valid:v1:d"));
        assert_ne!(definition.namespace(), changed.namespace());
        Ok(())
    }

    #[test]
    fn definition_rejects_backend_semantics_apalis_cannot_enforce() {
        assert!(matches!(
            JobDefinition::<TooManyAttemptsJob>::new(&config()),
            Err(JobDefinitionError::TooManyAttempts)
        ));
        assert!(matches!(
            JobDefinition::<DestinationJob>::new(&config()),
            Err(JobDefinitionError::UnsupportedDeadLetterDestination)
        ));
    }

    #[test]
    fn physical_worker_identity_is_unique_and_portably_bounded() {
        let logical = "a".repeat(MAX_PHYSICAL_WORKER_NAME_BYTES - WORKER_SUFFIX_BYTES);
        let first = physical_worker_name(&logical);
        let second = physical_worker_name(&logical);
        assert!(first.is_ok());
        assert!(second.is_ok());
        assert!(valid_logical_worker_name(&logical));
        assert_eq!(
            first.as_ref().map(String::len),
            Ok(MAX_PHYSICAL_WORKER_NAME_BYTES)
        );
        assert_ne!(first, second);
    }
    #[test]
    fn logical_worker_identity_reserves_random_suffix_capacity() {
        let oversized = "a".repeat(MAX_PHYSICAL_WORKER_NAME_BYTES - WORKER_SUFFIX_BYTES + 1);
        assert!(!valid_logical_worker_name(&oversized));
    }

    #[test]
    fn uniform_jitter_is_bounded_for_full_and_equal_ranges() {
        assert_eq!(uniform_inclusive(0, 100), 0);
        assert!(uniform_inclusive(u64::MAX, 100) <= 100);
        let equal = 50 + uniform_inclusive(42, 50);
        assert!((50..=100).contains(&equal));
    }
    #[test]
    fn dead_record_limit_enforces_public_boundaries() {
        assert_eq!(dead_record_limit(0), Err(RedisAdminError::InvalidLimit));
        assert_eq!(dead_record_limit(1), Ok(1));
        assert_eq!(dead_record_limit(100), Ok(100));
        assert_eq!(dead_record_limit(101), Err(RedisAdminError::InvalidLimit));
    }
}
