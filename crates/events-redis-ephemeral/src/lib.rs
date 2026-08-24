//! Loss-tolerant Redis Pub/Sub fan-out with bounded local retention.
//!
//! Publishing uses the shared multiplexed Redis connection. Receiving uses one synchronous
//! dedicated connection on Tokio's blocking pool because redis 1.6.0's async Pub/Sub path owns an
//! internal unbounded MPSC queue. The provider retains at most a validated fixed byte budget in
//! its bounded Tokio channel.
//!
//! Redis is a trust boundary: redis-rs materializes one complete RESP message before this provider
//! can reject an oversized payload. Deployments must grant exact-channel `PUBLISH` only to trusted
//! producers and configure Redis `proto-max-bulk-len` to an acceptable transient process-memory
//! bound. `max_message_bytes` bounds publishing and retained delivery, not the Redis parser's
//! transient allocation.
//!
//! This provider is deliberately ephemeral: messages can be lost before subscription readiness,
//! during disconnect and supervised restart, when the local receiver is full, when a message is
//! oversized, and during shutdown. There is no replay, acknowledgement, or delivery guarantee.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
    time::{Duration, Instant},
};

use metrics::{counter, histogram};
use redis::cmd;
use rsk_core::{ErrorCode, ServiceError};
use rsk_redis_core::{RedisCommandFamily, RedisCore};
use rsk_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::mpsc::{self, error::TryRecvError, error::TrySendError};

const LISTENER_TASK_NAME: &str = "redis-pubsub-listener";
const MODULE_NAME: &str = "events-redis-ephemeral";
const LISTENER_ERROR_CODE: &str = "REDIS_PUBSUB_UNAVAILABLE";
const MAX_CHANNELS: usize = 256;
const MAX_CHANNEL_NAME_BYTES: usize = 64;
const MAX_DELIVERY_CAPACITY: usize = 65_536;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETAINED_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_READ_POLL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESTARTS: u32 = 32;
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_JITTER_PERCENT: u8 = 50;

/// Bounded supervisor restart policy for the degraded listener.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RedisEphemeralRestartConfig {
    /// Maximum restarts after the initial listener attempt.
    pub max_restarts: u32,
    /// Delay before the first restart.
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum exponential restart delay.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
    /// Symmetric deterministic jitter bound applied by the supervisor.
    pub jitter_percent: u8,
}

impl Default for RedisEphemeralRestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 8,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            jitter_percent: 20,
        }
    }
}

/// Configuration for one static, bounded Redis Pub/Sub fan-out listener.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RedisEphemeralConfig {
    /// Enables this optional degraded capability.
    pub enabled: bool,
    /// Static logical channels resolved through the Redis key namespace at construction.
    pub channels: Vec<String>,
    /// Maximum messages retained for the local consumer.
    pub delivery_capacity: usize,
    /// Maximum accepted publish and receive payload size.
    pub max_message_bytes: usize,
    /// Read and write deadline used while connecting, naming, and subscribing.
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,
    /// Read deadline that makes the synchronous receive loop observe cancellation.
    #[serde(with = "humantime_serde")]
    pub read_poll_timeout: Duration,
    /// Supervisor deadline for graceful listener shutdown.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Bounded restart-on-failure policy.
    pub restart: RedisEphemeralRestartConfig,
}

impl Default for RedisEphemeralConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            channels: Vec::new(),
            delivery_capacity: 64,
            max_message_bytes: 256 * 1024,
            operation_timeout: Duration::from_secs(2),
            read_poll_timeout: Duration::from_millis(100),
            shutdown_timeout: Duration::from_secs(3),
            restart: RedisEphemeralRestartConfig::default(),
        }
    }
}

impl fmt::Debug for RedisEphemeralConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEphemeralConfig")
            .field("enabled", &self.enabled)
            .field("channel_count", &self.channels.len())
            .field("delivery_capacity", &self.delivery_capacity)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("operation_timeout", &self.operation_timeout)
            .field("read_poll_timeout", &self.read_poll_timeout)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("restart", &self.restart)
            .finish()
    }
}

impl RedisEphemeralConfig {
    /// Validates static names, queue and message bounds, deadlines, and restart limits.
    ///
    /// A disabled configuration may omit channels, but all supplied policy remains validated.
    ///
    /// # Errors
    ///
    /// Returns [`RedisEphemeralConfigError`] for any unsafe or inconsistent bound.
    pub fn validate(&self) -> Result<(), RedisEphemeralConfigError> {
        if self.channels.len() > MAX_CHANNELS {
            return Err(RedisEphemeralConfigError::TooManyChannels);
        }
        if self.enabled && self.channels.is_empty() {
            return Err(RedisEphemeralConfigError::ChannelsRequired);
        }
        let mut unique = BTreeSet::new();
        for channel in &self.channels {
            if !portable_channel(channel) {
                return Err(RedisEphemeralConfigError::InvalidChannel);
            }
            if !unique.insert(channel) {
                return Err(RedisEphemeralConfigError::DuplicateChannel);
            }
        }
        if !(1..=MAX_DELIVERY_CAPACITY).contains(&self.delivery_capacity) {
            return Err(RedisEphemeralConfigError::InvalidDeliveryCapacity);
        }
        if !(1..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes) {
            return Err(RedisEphemeralConfigError::InvalidMessageLimit);
        }
        let retained_bytes = self
            .delivery_capacity
            .checked_mul(self.max_message_bytes)
            .ok_or(RedisEphemeralConfigError::InvalidDeliveryBudget)?;
        if retained_bytes > MAX_RETAINED_MESSAGE_BYTES {
            return Err(RedisEphemeralConfigError::InvalidDeliveryBudget);
        }
        if self.operation_timeout.is_zero()
            || self.operation_timeout > MAX_OPERATION_TIMEOUT
            || self.read_poll_timeout.is_zero()
            || self.read_poll_timeout > MAX_READ_POLL_TIMEOUT
            || self.shutdown_timeout.is_zero()
            || self.shutdown_timeout > MAX_SHUTDOWN_TIMEOUT
        {
            return Err(RedisEphemeralConfigError::InvalidTimeout);
        }
        let minimum_shutdown = self
            .operation_timeout
            .checked_add(self.read_poll_timeout.saturating_mul(2))
            .ok_or(RedisEphemeralConfigError::InvalidTimeout)?;
        if self.shutdown_timeout < minimum_shutdown {
            return Err(RedisEphemeralConfigError::InvalidTimeout);
        }
        if !(1..=MAX_RESTARTS).contains(&self.restart.max_restarts)
            || self.restart.initial_backoff.is_zero()
            || self.restart.initial_backoff > self.restart.max_backoff
            || self.restart.max_backoff > MAX_BACKOFF
            || self.restart.jitter_percent > MAX_JITTER_PERCENT
        {
            return Err(RedisEphemeralConfigError::InvalidRestartPolicy);
        }
        Ok(())
    }
}

/// Invalid ephemeral Redis event configuration or composition.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RedisEphemeralConfigError {
    /// Enabled listeners require at least one static channel.
    #[error("enabled Redis ephemeral events require at least one channel")]
    ChannelsRequired,
    /// The static channel count exceeded the fixed bound.
    #[error("Redis ephemeral event channel count exceeds its safety bound")]
    TooManyChannels,
    /// A channel was empty, oversized, or not portable ASCII.
    #[error("Redis ephemeral event channel configuration is invalid")]
    InvalidChannel,
    /// Static logical channels must be unique.
    #[error("Redis ephemeral event channels must be unique")]
    DuplicateChannel,
    /// The bounded handoff capacity was zero or too large.
    #[error("Redis ephemeral event delivery capacity is invalid")]
    InvalidDeliveryCapacity,
    /// The message-size limit was zero or too large.
    #[error("Redis ephemeral event message-size limit is invalid")]
    InvalidMessageLimit,
    /// Count and message limits combined exceeded the hard retained-byte budget.
    #[error("Redis ephemeral event retained delivery budget is invalid")]
    InvalidDeliveryBudget,
    /// A deadline was zero, too large, or could not bound shutdown.
    #[error("Redis ephemeral event timeout policy is invalid")]
    InvalidTimeout,
    /// Restart count, delay, or jitter was outside its fixed bound.
    #[error("Redis ephemeral event restart policy is invalid")]
    InvalidRestartPolicy,
    /// The capability was enabled without enabled Redis core composition.
    #[error("enabled Redis ephemeral events require Redis core")]
    RedisCoreRequired,
    /// A physical channel could not be resolved through the Redis namespace.
    #[error("Redis ephemeral event channel namespace is invalid")]
    InvalidNamespace,
}

/// One configured Redis ephemeral fan-out capability.
pub struct RedisEphemeralEvents {
    publisher: RedisEphemeralPublisher,
    receiver: RedisEphemeralReceiver,
    listener: ListenerRegistration,
}

impl fmt::Debug for RedisEphemeralEvents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEphemeralEvents")
            .field("publisher", &self.publisher)
            .field("receiver", &self.receiver)
            .finish_non_exhaustive()
    }
}

impl RedisEphemeralEvents {
    /// Builds the optional provider without opening its degraded listener connection.
    ///
    /// Physical channel names are resolved exactly once through [`RedisCore::key`]. The returned
    /// listener task owns connection and resubscription attempts, so provider construction remains
    /// successful while the dedicated Pub/Sub path is unavailable.
    ///
    /// # Errors
    ///
    /// Returns [`RedisEphemeralConfigError`] for invalid policy, missing Redis core, or namespace
    /// resolution failure.
    pub fn new(
        config: &RedisEphemeralConfig,
        redis: Option<RedisCore>,
    ) -> Result<Option<Self>, RedisEphemeralConfigError> {
        config.validate()?;
        if !config.enabled {
            return Ok(None);
        }
        let redis = redis.ok_or(RedisEphemeralConfigError::RedisCoreRequired)?;
        if config.max_message_bytes > redis.max_value_bytes() {
            return Err(RedisEphemeralConfigError::InvalidMessageLimit);
        }
        let channels = Arc::new(ResolvedChannels::new(&redis, &config.channels)?);
        let (sender, receiver) = mpsc::channel(config.delivery_capacity);
        let publisher = RedisEphemeralPublisher {
            redis: redis.clone(),
            channels: Arc::clone(&channels),
            max_message_bytes: config.max_message_bytes,
        };
        let listener = ListenerRegistration {
            state: Arc::new(ListenerState {
                redis,
                channels,
                sender,
                max_message_bytes: config.max_message_bytes,
                operation_timeout: config.operation_timeout,
                read_poll_timeout: config.read_poll_timeout,
            }),
            shutdown_timeout: config.shutdown_timeout,
            restart: config.restart,
        };
        Ok(Some(Self {
            publisher,
            receiver: RedisEphemeralReceiver { receiver },
            listener,
        }))
    }

    /// Returns a cheap publisher clone for application fan-out calls.
    #[must_use]
    pub fn publisher(&self) -> RedisEphemeralPublisher {
        self.publisher.clone()
    }

    /// Consumes the provider into its publisher, sole bounded receiver, and listener task.
    ///
    /// Register the task with [`rsk_runtime::Supervisor`] before treating subscriptions as ready.
    #[must_use]
    pub fn into_parts(self) -> (RedisEphemeralPublisher, RedisEphemeralReceiver, TaskSpec) {
        let Self {
            publisher,
            receiver,
            listener,
        } = self;
        (publisher, receiver, listener.into_task_spec())
    }
}

/// Cheap publisher over Redis core's multiplexed `PUBLISH` path.
#[derive(Clone)]
pub struct RedisEphemeralPublisher {
    redis: RedisCore,
    channels: Arc<ResolvedChannels>,
    max_message_bytes: usize,
}

impl fmt::Debug for RedisEphemeralPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEphemeralPublisher")
            .field("channel_count", &self.channels.logical_to_physical.len())
            .field("max_message_bytes", &self.max_message_bytes)
            .finish_non_exhaustive()
    }
}

impl RedisEphemeralPublisher {
    /// Publishes one loss-tolerant message on a configured logical channel.
    ///
    /// The returned receiver count is Redis's point-in-time informational count only. It does not
    /// establish acknowledgement, processing, replay, or any other delivery guarantee.
    ///
    /// # Errors
    ///
    /// Returns [`PublishError`] for an unknown logical channel, oversized payload, or unavailable
    /// Redis command path. Errors never retain channel, payload, URL, or Redis diagnostics.
    pub async fn publish(
        &self,
        channel: &str,
        payload: &[u8],
    ) -> Result<PublishOutcome, PublishError> {
        counter!("rsk_events_redis_ephemeral_publish_attempts_total").increment(1);
        let started = Instant::now();
        let Some(physical) = self.channels.logical_to_physical.get(channel) else {
            record_publish(PublishStatus::Rejected, started.elapsed());
            return Err(PublishError::UnknownChannel);
        };
        if payload.len() > self.max_message_bytes {
            record_publish(PublishStatus::Rejected, started.elapsed());
            return Err(PublishError::MessageTooLarge);
        }
        let mut command = cmd("PUBLISH");
        command.arg(physical).arg(payload);
        let result = self
            .redis
            .query::<u64>(RedisCommandFamily::PubSub, command)
            .await;
        if let Ok(receiver_count) = result {
            record_publish(PublishStatus::Published, started.elapsed());
            Ok(PublishOutcome { receiver_count })
        } else {
            record_publish(PublishStatus::Unavailable, started.elapsed());
            Err(PublishError::Unavailable)
        }
    }
}

/// Safe publish failure categories without channel, payload, URL, or Redis error details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PublishError {
    /// The logical channel was not statically configured.
    #[error("Redis ephemeral event channel is not configured")]
    UnknownChannel,
    /// The payload exceeded the configured local publish bound.
    #[error("Redis ephemeral event payload exceeds its size limit")]
    MessageTooLarge,
    /// Redis rejected or could not complete `PUBLISH`.
    #[error("Redis ephemeral event publishing is unavailable")]
    Unavailable,
}

/// Point-in-time information returned by Redis after `PUBLISH`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishOutcome {
    receiver_count: u64,
}

impl PublishOutcome {
    /// Returns Redis's informational receiver count, not a delivery acknowledgement.
    #[must_use]
    pub const fn receiver_count(self) -> u64 {
        self.receiver_count
    }
}

/// One bounded, loss-tolerant message delivered by the local listener.
pub struct EphemeralMessage {
    channel: Arc<str>,
    message: redis::Msg,
}

impl fmt::Debug for EphemeralMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralMessage")
            .field("channel", &"[redacted]")
            .field("payload", &"[redacted]")
            .field("payload_len", &self.message.get_payload_bytes().len())
            .finish()
    }
}

impl PartialEq for EphemeralMessage {
    fn eq(&self, other: &Self) -> bool {
        self.channel == other.channel && self.payload() == other.payload()
    }
}

impl Eq for EphemeralMessage {}

impl EphemeralMessage {
    /// Returns the configured logical channel.
    #[must_use]
    pub fn channel(&self) -> &str {
        &self.channel
    }

    /// Returns the opaque payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.message.get_payload_bytes()
    }
}

/// Sole consumer for the provider-owned bounded delivery queue.
pub struct RedisEphemeralReceiver {
    receiver: mpsc::Receiver<EphemeralMessage>,
}

impl fmt::Debug for RedisEphemeralReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisEphemeralReceiver")
            .field("queued", &self.receiver.len())
            .field("capacity", &self.receiver.max_capacity())
            .finish_non_exhaustive()
    }
}

impl RedisEphemeralReceiver {
    /// Waits for the next locally retained message, or `None` after listener closure.
    pub async fn recv(&mut self) -> Option<EphemeralMessage> {
        self.receiver.recv().await
    }

    /// Attempts to receive a retained message without waiting.
    ///
    /// # Errors
    ///
    /// Returns Tokio's empty or disconnected bounded-channel state.
    pub fn try_recv(&mut self) -> Result<EphemeralMessage, TryRecvError> {
        self.receiver.try_recv()
    }

    /// Returns the current bounded queue length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Returns whether no message is currently retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }
}

struct ListenerRegistration {
    state: Arc<ListenerState>,
    shutdown_timeout: Duration,
    restart: RedisEphemeralRestartConfig,
}

impl ListenerRegistration {
    fn into_task_spec(self) -> TaskSpec {
        let state = self.state;
        TaskSpec::new(
            LISTENER_TASK_NAME,
            MODULE_NAME,
            Criticality::Degraded,
            self.shutdown_timeout,
            move |context| {
                let state = Arc::clone(&state);
                async move { run_listener_attempt(state, context).await }
            },
        )
        .with_restart_policy(RestartPolicy::on_failure(
            self.restart.max_restarts,
            self.restart.initial_backoff,
            self.restart.max_backoff,
            self.restart.jitter_percent,
        ))
    }
}

struct ListenerState {
    redis: RedisCore,
    channels: Arc<ResolvedChannels>,
    sender: mpsc::Sender<EphemeralMessage>,
    max_message_bytes: usize,
    operation_timeout: Duration,
    read_poll_timeout: Duration,
}

struct ResolvedChannels {
    logical_to_physical: BTreeMap<String, String>,
    physical_to_logical: BTreeMap<String, Arc<str>>,
    physical: Arc<[String]>,
}

impl ResolvedChannels {
    fn new(
        redis: &RedisCore,
        logical_channels: &[String],
    ) -> Result<Self, RedisEphemeralConfigError> {
        let mut logical_to_physical = BTreeMap::new();
        let mut physical_to_logical = BTreeMap::new();
        let mut physical = Vec::with_capacity(logical_channels.len());
        for logical in logical_channels {
            let resolved = redis
                .key(&["events", logical])
                .map_err(|_| RedisEphemeralConfigError::InvalidNamespace)?;
            logical_to_physical.insert(logical.clone(), resolved.clone());
            physical_to_logical.insert(resolved.clone(), Arc::<str>::from(logical.as_str()));
            physical.push(resolved);
        }
        Ok(Self {
            logical_to_physical,
            physical_to_logical,
            physical: physical.into(),
        })
    }
}

async fn run_listener_attempt(
    state: Arc<ListenerState>,
    context: TaskContext,
) -> Result<(), ServiceError> {
    record_listener_status(ListenerStatus::Connecting);
    let connection = state
        .redis
        .dedicated_sync_pubsub_connection(
            state.operation_timeout,
            state.operation_timeout,
            state.operation_timeout,
        )
        .await;
    let Ok(connection) = connection else {
        record_connection(MetricStatus::Error);
        record_listener_status(ListenerStatus::Disconnected);
        return Err(listener_error());
    };
    if is_stopping(&context) || state.sender.is_closed() {
        record_listener_status(ListenerStatus::Stopped);
        return Ok(());
    }
    record_connection(MetricStatus::Ok);
    let blocking_state = Arc::clone(&state);
    let blocking_context = context.clone();
    let result =
        tokio::task::spawn_blocking(move || listen(connection, &blocking_state, &blocking_context))
            .await;
    if let Ok(result) = result {
        result
    } else {
        record_connection(MetricStatus::Error);
        record_listener_status(ListenerStatus::Disconnected);
        Err(listener_error())
    }
}

fn listen(
    mut connection: redis::Connection,
    state: &ListenerState,
    context: &TaskContext,
) -> Result<(), ServiceError> {
    let mut pubsub = connection.as_pubsub();
    // One multi-channel SUBSCRIBE avoids redis-rs retaining messages between sequential
    // subscription calls; after setup, get_message consumes directly from the bounded socket path.
    let subscription = pubsub.subscribe(Arc::clone(&state.channels.physical));
    let poll_deadline = pubsub.set_read_timeout(Some(state.read_poll_timeout));
    if subscription.is_err() || poll_deadline.is_err() {
        record_subscription(MetricStatus::Error);
        record_listener_status(ListenerStatus::Disconnected);
        return Err(listener_error());
    }
    record_subscription(MetricStatus::Ok);
    record_listener_status(ListenerStatus::Subscribed);

    loop {
        if is_stopping(context) || state.sender.is_closed() {
            record_listener_status(ListenerStatus::Stopped);
            return Ok(());
        }
        match pubsub.get_message() {
            Ok(message) => {
                counter!("rsk_events_redis_ephemeral_received_total").increment(1);
                let payload = message.get_payload_bytes();
                if payload.len() > state.max_message_bytes {
                    record_drop(DropReason::Oversize);
                    continue;
                }
                let Some(channel) = state
                    .channels
                    .physical_to_logical
                    .get(message.get_channel_name())
                    .cloned()
                else {
                    record_drop(DropReason::Unknown);
                    continue;
                };
                let delivery = EphemeralMessage { channel, message };
                match state.sender.try_send(delivery) {
                    Ok(()) => {
                        counter!("rsk_events_redis_ephemeral_delivered_total").increment(1);
                    }
                    Err(TrySendError::Full(_)) => record_drop(DropReason::Full),
                    Err(TrySendError::Closed(_)) => {
                        record_drop(DropReason::Closed);
                        record_listener_status(ListenerStatus::Stopped);
                        return Ok(());
                    }
                }
            }
            Err(error) if error.is_timeout() => {
                if is_stopping(context) || state.sender.is_closed() {
                    record_listener_status(ListenerStatus::Stopped);
                    return Ok(());
                }
            }
            Err(_) => {
                record_connection(MetricStatus::Error);
                record_listener_status(ListenerStatus::Disconnected);
                return Err(listener_error());
            }
        }
    }
}

fn is_stopping(context: &TaskContext) -> bool {
    context.is_draining() || context.is_shutdown_requested() || context.is_cancelled()
}

fn portable_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel.len() <= MAX_CHANNEL_NAME_BYTES
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn listener_error() -> ServiceError {
    ServiceError::new(listener_error_code(), "Redis Pub/Sub listener unavailable")
}

fn listener_error_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(LISTENER_ERROR_CODE) else {
        unreachable!("static Redis Pub/Sub listener error code must be valid")
    };
    code
}

#[derive(Clone, Copy)]
enum MetricStatus {
    Ok,
    Error,
}

impl MetricStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy)]
enum PublishStatus {
    Published,
    Rejected,
    Unavailable,
}

impl PublishStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy)]
enum ListenerStatus {
    Connecting,
    Subscribed,
    Disconnected,
    Stopped,
}

impl ListenerStatus {
    const fn label(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Subscribed => "subscribed",
            Self::Disconnected => "disconnected",
            Self::Stopped => "stopped",
        }
    }
}

#[derive(Clone, Copy)]
enum DropReason {
    Full,
    Oversize,
    Unknown,
    Closed,
}

impl DropReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Oversize => "oversize",
            Self::Unknown => "unknown",
            Self::Closed => "closed",
        }
    }
}

fn record_publish(status: PublishStatus, elapsed: Duration) {
    counter!(
        "rsk_events_redis_ephemeral_publish_status_total",
        "status" => status.label()
    )
    .increment(1);
    histogram!(
        "rsk_events_redis_ephemeral_publish_duration_seconds",
        "status" => status.label()
    )
    .record(elapsed.as_secs_f64());
}

fn record_connection(status: MetricStatus) {
    counter!(
        "rsk_events_redis_ephemeral_listener_connections_total",
        "status" => status.label()
    )
    .increment(1);
}

fn record_subscription(status: MetricStatus) {
    counter!(
        "rsk_events_redis_ephemeral_listener_subscriptions_total",
        "status" => status.label()
    )
    .increment(1);
}

fn record_listener_status(status: ListenerStatus) {
    counter!(
        "rsk_events_redis_ephemeral_listener_status_total",
        "status" => status.label()
    )
    .increment(1);
}

fn record_drop(reason: DropReason) {
    counter!(
        "rsk_events_redis_ephemeral_dropped_total",
        "reason" => reason.label()
    )
    .increment(1);
}
