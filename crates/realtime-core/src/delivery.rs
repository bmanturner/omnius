use std::{
    collections::{HashMap, VecDeque},
    fmt,
    future::ready,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures::{future::poll_fn, task::AtomicWaker};
use rsk_runtime::{Criticality, TaskSpec};
use thiserror::Error;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::{
    ConnectionId, ConnectionRegistry, ConnectionState, ControlOutput, FanoutDeliveryIntent,
    FanoutIntentPriority, FanoutIntentReservation, FanoutIntentSink, FanoutReservationContext,
    MAX_ENVELOPE_BYTES, MessageType, OutboundMessage, SubscriptionId,
};

/// Default number of retained messages for one connection.
pub const DEFAULT_DELIVERY_MESSAGES_PER_CONNECTION: usize = 64;
/// Default queued and reserved bytes for one connection.
pub const DEFAULT_DELIVERY_BYTES_PER_CONNECTION: usize = 1024 * 1024;
/// Default queued and reserved bytes across a hub.
pub const DEFAULT_DELIVERY_TOTAL_BYTES: usize = 1024 * 1024 * 1024;
/// Default time allowed for already-admitted messages to drain.
pub const DEFAULT_DELIVERY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard ceiling for one connection's retained message count.
pub const MAX_DELIVERY_MESSAGES_PER_CONNECTION: usize = 4_096;
/// Hard ceiling for one connection's queued and reserved bytes.
pub const MAX_DELIVERY_BYTES_PER_CONNECTION: usize = 64 * 1024 * 1024;
/// Hard ceiling for queued and reserved bytes across a hub.
pub const MAX_DELIVERY_TOTAL_BYTES: usize = 64 * 1024 * 1024 * 1024;
/// Longest accepted realtime drain deadline.
pub const MAX_DELIVERY_DRAIN_TIMEOUT: Duration = Duration::from_mins(5);

const MIN_DELIVERY_DRAIN_TIMEOUT: Duration = Duration::from_millis(10);
const DRAIN_TASK_CLEANUP_GRACE: Duration = Duration::from_secs(1);

/// Invalid connection-delivery capacity or deadline configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeliveryQueueConfigError {
    /// Every count and byte capacity must be nonzero.
    #[error("realtime delivery capacities must be non-zero")]
    ZeroCapacity,
    /// A configured capacity exceeded its compile-time ceiling.
    #[error("realtime delivery capacity exceeds its hard limit")]
    ExceedsHardLimit,
    /// One connection can retain more bytes than the whole hub.
    #[error("realtime per-connection delivery bytes exceed the total")]
    PerConnectionExceedsTotal,
    /// The registry capacity cannot be isolated within the total byte budget.
    #[error("realtime delivery total cannot isolate every registry connection")]
    RegistryCapacityExceedsTotal,
    /// The drain deadline falls outside its fixed bounds.
    #[error("invalid realtime delivery drain timeout")]
    InvalidDrainTimeout,
}

/// Validated count, byte, and drain bounds for connection delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryQueueConfig {
    max_messages_per_connection: usize,
    max_bytes_per_connection: usize,
    max_total_bytes: usize,
    drain_timeout: Duration,
}

impl DeliveryQueueConfig {
    /// Creates validated fixed delivery bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryQueueConfigError`] for zero, excessive, inconsistent, or invalid limits.
    pub fn new(
        max_messages_per_connection: usize,
        max_bytes_per_connection: usize,
        max_total_bytes: usize,
        drain_timeout: Duration,
    ) -> Result<Self, DeliveryQueueConfigError> {
        if max_messages_per_connection == 0 || max_bytes_per_connection == 0 || max_total_bytes == 0
        {
            return Err(DeliveryQueueConfigError::ZeroCapacity);
        }
        if max_messages_per_connection > MAX_DELIVERY_MESSAGES_PER_CONNECTION
            || max_bytes_per_connection > MAX_DELIVERY_BYTES_PER_CONNECTION
            || max_total_bytes > MAX_DELIVERY_TOTAL_BYTES
        {
            return Err(DeliveryQueueConfigError::ExceedsHardLimit);
        }
        if max_bytes_per_connection > max_total_bytes {
            return Err(DeliveryQueueConfigError::PerConnectionExceedsTotal);
        }
        if drain_timeout < MIN_DELIVERY_DRAIN_TIMEOUT || drain_timeout > MAX_DELIVERY_DRAIN_TIMEOUT
        {
            return Err(DeliveryQueueConfigError::InvalidDrainTimeout);
        }
        Ok(Self {
            max_messages_per_connection,
            max_bytes_per_connection,
            max_total_bytes,
            drain_timeout,
        })
    }

    /// Returns the retained message limit for one connection, including reservations.
    #[must_use]
    pub const fn max_messages_per_connection(self) -> usize {
        self.max_messages_per_connection
    }

    /// Returns the queued and reserved byte limit for one connection.
    #[must_use]
    pub const fn max_bytes_per_connection(self) -> usize {
        self.max_bytes_per_connection
    }

    /// Returns the queued and reserved byte limit across the hub.
    #[must_use]
    pub const fn max_total_bytes(self) -> usize {
        self.max_total_bytes
    }

    /// Returns the complete graceful-drain budget.
    #[must_use]
    pub const fn drain_timeout(self) -> Duration {
        self.drain_timeout
    }
}

impl Default for DeliveryQueueConfig {
    fn default() -> Self {
        Self {
            max_messages_per_connection: DEFAULT_DELIVERY_MESSAGES_PER_CONNECTION,
            max_bytes_per_connection: DEFAULT_DELIVERY_BYTES_PER_CONNECTION,
            max_total_bytes: DEFAULT_DELIVERY_TOTAL_BYTES,
            drain_timeout: DEFAULT_DELIVERY_DRAIN_TIMEOUT,
        }
    }
}

/// Generic policy applied when ordinary connection data cannot be reserved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SlowConsumerPolicy {
    /// Purge and terminate only the full connection.
    #[default]
    Disconnect,
}

/// Queue priority for transport-neutral delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryPriority {
    /// Ordinary application data.
    Normal,
    /// Command, revocation, and lifecycle control.
    High,
}

impl From<FanoutIntentPriority> for DeliveryPriority {
    fn from(priority: FanoutIntentPriority) -> Self {
        match priority {
            FanoutIntentPriority::Normal => Self::Normal,
            FanoutIntentPriority::High => Self::High,
        }
    }
}

/// Terminal transport action produced by the hub.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryTerminal {
    /// The connection exceeded its fixed outbound capacity.
    SlowConsumer,
    /// The process stopped intake and completed or exhausted its drain budget.
    Draining,
}

/// One already-encoded bounded transport message.
#[derive(Debug, Eq, PartialEq)]
pub struct DeliveryMessage {
    encoded: Vec<u8>,
    message_type: MessageType,
    priority: DeliveryPriority,
}

impl DeliveryMessage {
    /// Returns the exact bounded v1 envelope bytes.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Consumes the delivery and returns its exact bounded v1 envelope bytes.
    #[must_use]
    pub fn into_encoded(self) -> Vec<u8> {
        self.encoded
    }

    /// Returns the queue priority used for this delivery.
    #[must_use]
    pub const fn priority(&self) -> DeliveryPriority {
        self.priority
    }

    /// Returns the protocol message type used by named transport events.
    #[must_use]
    pub const fn message_type(&self) -> &MessageType {
        &self.message_type
    }
}

/// One receiver result, either an encoded envelope or a terminal transport action.
#[derive(Debug, Eq, PartialEq)]
pub enum QueuedDelivery {
    /// One already-encoded protocol envelope.
    Message(DeliveryMessage),
    /// A terminal action that must not be starved by ordinary data.
    Terminal(DeliveryTerminal),
}

/// Stable value-free delivery failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeliveryError {
    /// Connection and fan-out intake has stopped.
    #[error("realtime delivery intake is closed")]
    IntakeClosed,
    /// The selected connection is absent or inactive.
    #[error("realtime delivery connection is not active")]
    ConnectionNotActive,
    /// A receiver already owns the connection queue.
    #[error("realtime delivery connection already has a receiver")]
    ReceiverAlreadyOpen,
    /// The fixed connection-queue map capacity is exhausted.
    #[error("realtime delivery connection capacity is exhausted")]
    ConnectionCapacity,
    /// The requested reservation exceeds a fixed queue bound.
    #[error("realtime delivery reservation exceeds its bound")]
    ReservationTooLarge,
    /// The target was disconnected by the slow-consumer policy.
    #[error("realtime delivery connection is a slow consumer")]
    SlowConsumer,
    /// The connection queue is terminal or closed.
    #[error("realtime delivery connection is closed")]
    Closed,
    /// An outbound protocol value could not be encoded within its fixed bound.
    #[error("realtime delivery message cannot be encoded")]
    Encoding,
    /// The registry or delivery state could not be trusted.
    #[error("realtime delivery is unavailable")]
    Unavailable,
    /// An unaddressed reservation cannot select a connection-owned queue.
    #[error("realtime delivery reservation requires a connection")]
    ConnectionRequired,
}

/// Current value-free connection-delivery gauges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    /// Whether new connection and fan-out intake is accepted.
    pub intake_open: bool,
    /// Whether graceful drain has begun.
    pub draining: bool,
    /// Number of receiver-owned active queues.
    pub active_queues: usize,
    /// Number of queued encoded envelopes.
    pub queued_messages: usize,
    /// Bytes retained by queued encoded envelopes.
    pub queued_bytes: usize,
    /// Number of reservations held before encoding.
    pub reserved_messages: usize,
    /// Bytes held by reservations before encoding.
    pub reserved_bytes: usize,
    /// Number of queued high-priority envelopes.
    pub high_priority_messages: usize,
}

/// Monotonic value-free delivery counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryMetricsSnapshot {
    /// Successfully admitted envelopes.
    pub admitted: u64,
    /// Envelopes reported sent by an exclusive receiver.
    pub sent: u64,
    /// Generation-stale envelopes discarded before admission or receiver yield.
    pub stale_generation_dropped: u64,
    /// Queued envelopes purged by generation-qualified revocation.
    pub revocation_purged: u64,
    /// Ordinary envelopes evicted so high-priority control could not be starved.
    pub priority_purged: u64,
    /// Connections terminated by the fixed slow-consumer policy.
    pub slow_consumer_disconnects: u64,
    /// Messages rejected before allocation by a full ordinary queue.
    pub normal_rejected: u64,
    /// Messages discarded when the drain deadline expired.
    pub drain_deadline_dropped: u64,
    /// Attempts rejected after intake closed.
    pub intake_rejected: u64,
    /// Number of drain transitions.
    pub drains_started: u64,
}

#[derive(Default)]
struct DeliveryMetrics {
    admitted: AtomicU64,
    sent: AtomicU64,
    stale_generation_dropped: AtomicU64,
    revocation_purged: AtomicU64,
    priority_purged: AtomicU64,
    slow_consumer_disconnects: AtomicU64,
    normal_rejected: AtomicU64,
    drain_deadline_dropped: AtomicU64,
    intake_rejected: AtomicU64,
    drains_started: AtomicU64,
}

impl DeliveryMetrics {
    fn snapshot(&self) -> DeliveryMetricsSnapshot {
        DeliveryMetricsSnapshot {
            admitted: self.admitted.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            stale_generation_dropped: self.stale_generation_dropped.load(Ordering::Relaxed),
            revocation_purged: self.revocation_purged.load(Ordering::Relaxed),
            priority_purged: self.priority_purged.load(Ordering::Relaxed),
            slow_consumer_disconnects: self.slow_consumer_disconnects.load(Ordering::Relaxed),
            normal_rejected: self.normal_rejected.load(Ordering::Relaxed),
            drain_deadline_dropped: self.drain_deadline_dropped.load(Ordering::Relaxed),
            intake_rejected: self.intake_rejected.load(Ordering::Relaxed),
            drains_started: self.drains_started.load(Ordering::Relaxed),
        }
    }
}

struct StoredMessage {
    encoded: Vec<u8>,
    message_type: MessageType,
    priority: DeliveryPriority,
    generation: Option<(SubscriptionId, u64)>,
}

struct QueueRecord {
    high: VecDeque<StoredMessage>,
    normal: VecDeque<StoredMessage>,
    queued_bytes: usize,
    reserved_messages: usize,
    reserved_bytes: usize,
    reservation_epoch: u64,
    terminal: Option<DeliveryTerminal>,
    receiver_open: bool,
    closed: bool,
    waker: Arc<AtomicWaker>,
}

impl QueueRecord {
    fn new(waker: Arc<AtomicWaker>) -> Self {
        Self {
            high: VecDeque::new(),
            normal: VecDeque::new(),
            queued_bytes: 0,
            reserved_messages: 0,
            reserved_bytes: 0,
            reservation_epoch: 0,
            terminal: None,
            receiver_open: true,
            closed: false,
            waker,
        }
    }

    fn queued_messages(&self) -> usize {
        self.high.len() + self.normal.len()
    }

    const fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

struct HubState {
    intake_open: bool,
    draining: bool,
    queues: HashMap<ConnectionId, QueueRecord>,
    queued_messages: usize,
    queued_bytes: usize,
    reserved_messages: usize,
    reserved_bytes: usize,
    high_priority_messages: usize,
}

impl Default for HubState {
    fn default() -> Self {
        Self {
            intake_open: true,
            draining: false,
            queues: HashMap::new(),
            queued_messages: 0,
            queued_bytes: 0,
            reserved_messages: 0,
            reserved_bytes: 0,
            high_priority_messages: 0,
        }
    }
}

struct DeliveryInner {
    registry: Arc<ConnectionRegistry>,
    config: DeliveryQueueConfig,
    policy: SlowConsumerPolicy,
    state: Mutex<HubState>,
    changed: Notify,
    metrics: DeliveryMetrics,
}

/// Shared owner of bounded connection queues, intake, drain, and value-free diagnostics.
#[derive(Clone)]
pub struct ConnectionDeliveryHub {
    inner: Arc<DeliveryInner>,
}

impl ConnectionDeliveryHub {
    /// Creates an empty delivery hub whose total budget isolates every registry connection.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryQueueConfigError::RegistryCapacityExceedsTotal`] when the registry could
    /// admit more per-connection byte budgets than the hub-wide bound can isolate.
    pub fn new(
        registry: Arc<ConnectionRegistry>,
        config: DeliveryQueueConfig,
    ) -> Result<Self, DeliveryQueueConfigError> {
        let required_total = registry
            .config()
            .max_connections()
            .checked_mul(config.max_bytes_per_connection)
            .ok_or(DeliveryQueueConfigError::RegistryCapacityExceedsTotal)?;
        if required_total > config.max_total_bytes {
            return Err(DeliveryQueueConfigError::RegistryCapacityExceedsTotal);
        }
        Ok(Self {
            inner: Arc::new(DeliveryInner {
                registry,
                config,
                policy: SlowConsumerPolicy::Disconnect,
                state: Mutex::new(HubState::default()),
                changed: Notify::new(),
                metrics: DeliveryMetrics::default(),
            }),
        })
    }

    /// Returns the authoritative registry used for admission and dequeue generation checks.
    #[must_use]
    pub fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.inner.registry
    }

    /// Returns the fixed queue and drain bounds.
    #[must_use]
    pub fn config(&self) -> DeliveryQueueConfig {
        self.inner.config
    }

    /// Returns the fixed generic slow-consumer policy.
    #[must_use]
    pub fn slow_consumer_policy(&self) -> SlowConsumerPolicy {
        self.inner.policy
    }

    /// Returns whether new transport connections and fan-out reservations are accepted.
    #[must_use]
    pub fn is_accepting(&self) -> bool {
        lock(&self.inner.state).intake_open
    }

    /// Creates a cloneable sink for fan-out and command-reply admission.
    #[must_use]
    pub fn sink(&self) -> ConnectionDeliverySink {
        ConnectionDeliverySink { hub: self.clone() }
    }

    /// Opens the exclusive receiver for one active registry connection.
    ///
    /// # Errors
    ///
    /// Returns a stable [`DeliveryError`] when intake is closed, the registry connection is not
    /// active, or a receiver already owns the queue.
    pub fn open_connection(
        &self,
        connection_id: ConnectionId,
    ) -> Result<ConnectionDeliveryReceiver, DeliveryError> {
        if !self.connection_is_active(connection_id)? {
            return Err(DeliveryError::ConnectionNotActive);
        }
        let waker = Arc::new(AtomicWaker::new());
        let mut state = lock(&self.inner.state);
        if !state.intake_open {
            self.inner
                .metrics
                .intake_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(DeliveryError::IntakeClosed);
        }
        if state.queues.contains_key(&connection_id) {
            return Err(DeliveryError::ReceiverAlreadyOpen);
        }
        if state.queues.len() >= self.inner.registry.config().max_connections() {
            return Err(DeliveryError::ConnectionCapacity);
        }
        state
            .queues
            .insert(connection_id, QueueRecord::new(Arc::clone(&waker)));
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(ConnectionDeliveryReceiver {
            hub: self.clone(),
            connection_id,
            waker,
            open: true,
        })
    }

    /// Reserves, encodes, and admits one command or lifecycle message at the selected priority.
    ///
    /// Capacity is acquired before protocol encoding allocates the envelope bytes.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for closed intake, capacity, lifecycle, or encoding failures.
    pub fn enqueue(
        &self,
        connection_id: ConnectionId,
        priority: DeliveryPriority,
        message: OutboundMessage,
    ) -> Result<(), DeliveryError> {
        self.sink()
            .reserve_message(connection_id, priority, MAX_ENVELOPE_BYTES)?
            .admit_message(message)
    }

    /// Synchronously stops connection and fan-out intake without discarding admitted data.
    pub fn begin_drain(&self) {
        let mut state = lock(&self.inner.state);
        if state.draining {
            return;
        }
        state.intake_open = false;
        state.draining = true;
        self.inner
            .metrics
            .drains_started
            .fetch_add(1, Ordering::Relaxed);
        drop(state);
        self.inner.changed.notify_waiters();
    }

    /// Stops intake, drains already-admitted data until the configured deadline, then signals all
    /// transports and closes their registry connections.
    pub async fn drain(&self) -> DeliveryDrainOutcome {
        self.begin_drain();
        let deadline = Instant::now() + self.inner.config.drain_timeout;
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            let _ = notified.as_mut().enable();
            let drained = {
                let state = lock(&self.inner.state);
                state.queued_messages == 0 && state.reserved_messages == 0
            };
            if drained {
                return self.finish_drain(false);
            }
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => {
                    return self.finish_drain(true);
                }
                () = &mut notified => {}
            }
        }
    }

    /// Immediately discards retained work and wakes every receiver with a drain terminal.
    #[must_use]
    pub fn force_close(&self) -> DeliveryDrainOutcome {
        self.begin_drain();
        self.finish_drain(true)
    }

    /// Closes one queue idempotently, releases retained data, and closes registry indexes.
    pub fn close_connection(&self, connection_id: ConnectionId) {
        let waker = {
            let mut state = lock(&self.inner.state);
            let Some(queue) = state.queues.get(&connection_id) else {
                drop(state);
                let _ = self.inner.registry.close(connection_id);
                return;
            };
            let waker = Arc::clone(&queue.waker);
            clear_queue_locked(&mut state, connection_id);
            invalidate_reservations_locked(&mut state, connection_id);
            state.queues.remove(&connection_id);
            waker
        };
        waker.wake();
        self.inner.changed.notify_waiters();
        let _ = self.inner.registry.begin_close(connection_id);
        let _ = self.inner.registry.close(connection_id);
    }

    /// Returns exact value-free gauges without connection, topic, or payload labels.
    #[must_use]
    pub fn status(&self) -> DeliveryStatus {
        let state = lock(&self.inner.state);
        DeliveryStatus {
            intake_open: state.intake_open,
            draining: state.draining,
            active_queues: state
                .queues
                .values()
                .filter(|queue| queue.receiver_open && !queue.closed)
                .count(),
            queued_messages: state.queued_messages,
            queued_bytes: state.queued_bytes,
            reserved_messages: state.reserved_messages,
            reserved_bytes: state.reserved_bytes,
            high_priority_messages: state.high_priority_messages,
        }
    }

    /// Returns monotonic value-free delivery counters.
    #[must_use]
    pub fn metrics(&self) -> DeliveryMetricsSnapshot {
        self.inner.metrics.snapshot()
    }

    /// Builds the required runtime task that owns the complete configured drain budget.
    #[must_use]
    pub fn drain_task_spec(&self) -> TaskSpec {
        let hub = self.clone();
        let shutdown_timeout = self
            .inner
            .config
            .drain_timeout
            .saturating_add(DRAIN_TASK_CLEANUP_GRACE);
        TaskSpec::new(
            "realtime-delivery-drain",
            "realtime-delivery",
            Criticality::Required,
            shutdown_timeout,
            move |context| {
                let hub = hub.clone();
                async move {
                    tokio::select! {
                        () = context.draining() => {}
                        () = context.shutdown_requested() => {}
                        () = context.cancelled() => return Ok(()),
                    }
                    tokio::select! {
                        _ = hub.drain() => {}
                        () = context.cancelled() => {
                            let _ = hub.force_close();
                            return Ok(());
                        }
                    }
                    if !context.is_shutdown_requested() && !context.is_cancelled() {
                        tokio::select! {
                            () = context.shutdown_requested() => {}
                            () = context.cancelled() => { let _ = hub.force_close(); }
                        }
                    }
                    Ok(())
                }
            },
        )
    }

    fn connection_is_active(&self, connection_id: ConnectionId) -> Result<bool, DeliveryError> {
        self.inner
            .registry
            .connection(connection_id)
            .map(|connection| {
                connection.is_some_and(|connection| connection.state() == ConnectionState::Active)
            })
            .map_err(|_| DeliveryError::Unavailable)
    }

    #[allow(clippy::too_many_lines)]
    fn reserve_addressed(
        &self,
        connection_id: ConnectionId,
        priority: DeliveryPriority,
        maximum_encoded_bytes: usize,
        purge_generation: Option<(SubscriptionId, u64)>,
    ) -> Result<DeliveryReservation, DeliveryError> {
        if maximum_encoded_bytes == 0
            || maximum_encoded_bytes > MAX_ENVELOPE_BYTES
            || maximum_encoded_bytes > self.inner.config.max_bytes_per_connection
        {
            return Err(DeliveryError::ReservationTooLarge);
        }
        if !self.connection_is_active(connection_id)? {
            return Err(DeliveryError::ConnectionNotActive);
        }

        let mut wake = None;
        let mut state = lock(&self.inner.state);
        if !state.intake_open {
            self.inner
                .metrics
                .intake_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(DeliveryError::IntakeClosed);
        }
        let Some(queue) = state.queues.get(&connection_id) else {
            return Err(DeliveryError::ConnectionNotActive);
        };
        if queue.closed || queue.terminal.is_some() {
            return Err(DeliveryError::Closed);
        }

        if let Some(generation) = purge_generation {
            let purged = purge_generation_locked(&mut state, connection_id, generation);
            self.inner
                .metrics
                .revocation_purged
                .fetch_add(purged as u64, Ordering::Relaxed);
        }

        if priority == DeliveryPriority::High {
            let locally_purged = make_room_for_high_locked(
                &mut state,
                connection_id,
                maximum_encoded_bytes,
                self.inner.config,
            );
            let globally_purged = make_global_room_for_high_locked(
                &mut state,
                maximum_encoded_bytes,
                self.inner.config,
            );
            self.inner
                .metrics
                .priority_purged
                .fetch_add((locally_purged + globally_purged) as u64, Ordering::Relaxed);
        }
        let exceeds_connection = state.queues.get(&connection_id).is_none_or(|queue| {
            queue.queued_messages() + queue.reserved_messages
                >= self.inner.config.max_messages_per_connection
                || queue.queued_bytes() + queue.reserved_bytes + maximum_encoded_bytes
                    > self.inner.config.max_bytes_per_connection
        });
        let exceeds_total = state.queued_bytes + state.reserved_bytes + maximum_encoded_bytes
            > self.inner.config.max_total_bytes;
        if exceeds_connection || exceeds_total {
            if priority == DeliveryPriority::Normal {
                self.inner
                    .metrics
                    .normal_rejected
                    .fetch_add(1, Ordering::Relaxed);
            }
            if mark_slow_locked(&mut state, connection_id) {
                self.inner
                    .metrics
                    .slow_consumer_disconnects
                    .fetch_add(1, Ordering::Relaxed);
                wake = state
                    .queues
                    .get(&connection_id)
                    .map(|queue| Arc::clone(&queue.waker));
            }
            let became_slow = wake.is_some();
            drop(state);
            if became_slow {
                let _ = self.inner.registry.begin_close(connection_id);
                let _ = self.inner.registry.close(connection_id);
            }
            if let Some(waker) = wake {
                waker.wake();
            }
            self.inner.changed.notify_waiters();
            return Err(DeliveryError::SlowConsumer);
        }

        let reservation_epoch = if let Some(queue) = state.queues.get_mut(&connection_id) {
            queue.reserved_messages += 1;
            queue.reserved_bytes += maximum_encoded_bytes;
            queue.reservation_epoch
        } else {
            return Err(DeliveryError::Closed);
        };
        state.reserved_messages += 1;
        state.reserved_bytes += maximum_encoded_bytes;
        drop(state);
        self.inner.changed.notify_waiters();
        Ok(DeliveryReservation {
            hub: self.clone(),
            connection_id,
            priority,
            reserved_bytes: maximum_encoded_bytes,
            reservation_epoch,
            active: true,
        })
    }

    fn finish_drain(&self, deadline_expired: bool) -> DeliveryDrainOutcome {
        let mut wake = Vec::new();
        let mut connections = Vec::new();
        let dropped_messages;
        {
            let mut state = lock(&self.inner.state);
            dropped_messages = if deadline_expired {
                let dropped = state.queued_messages;
                let ids: Vec<_> = state.queues.keys().copied().collect();
                for connection_id in ids {
                    clear_queue_locked(&mut state, connection_id);
                    invalidate_reservations_locked(&mut state, connection_id);
                }
                self.inner
                    .metrics
                    .drain_deadline_dropped
                    .fetch_add(dropped as u64, Ordering::Relaxed);
                dropped
            } else {
                0
            };
            for (connection_id, queue) in &mut state.queues {
                if queue.receiver_open && !queue.closed {
                    queue.terminal = Some(DeliveryTerminal::Draining);
                    wake.push(Arc::clone(&queue.waker));
                    connections.push(*connection_id);
                }
            }
        }
        for waker in wake {
            waker.wake();
        }
        for connection_id in connections {
            let _ = self.inner.registry.begin_close(connection_id);
            let _ = self.inner.registry.close(connection_id);
        }
        self.inner.changed.notify_waiters();
        DeliveryDrainOutcome {
            deadline_expired,
            dropped_messages,
        }
    }
}

impl fmt::Debug for ConnectionDeliveryHub {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionDeliveryHub")
            .field("config", &self.inner.config)
            .field("policy", &self.inner.policy)
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

/// Result of one bounded drain attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryDrainOutcome {
    /// Whether queued work remained at the deadline.
    pub deadline_expired: bool,
    /// Number of queued envelopes discarded at the deadline.
    pub dropped_messages: usize,
}

/// Cloneable admission boundary used by fan-out and command handlers.
#[derive(Clone, Debug)]
pub struct ConnectionDeliverySink {
    hub: ConnectionDeliveryHub,
}

impl ConnectionDeliverySink {
    /// Reserves one addressed queue slot and byte budget before encoding.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] without allocating an envelope when the target cannot admit it.
    pub fn reserve_message(
        &self,
        connection_id: ConnectionId,
        priority: DeliveryPriority,
        maximum_encoded_bytes: usize,
    ) -> Result<DeliveryReservation, DeliveryError> {
        self.hub
            .reserve_addressed(connection_id, priority, maximum_encoded_bytes, None)
    }
}

impl FanoutIntentSink for ConnectionDeliverySink {
    type Error = DeliveryError;
    type Reservation = DeliveryReservation;

    fn reserve(
        &self,
        _maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        ready(Err(DeliveryError::ConnectionRequired))
    }

    fn reserve_for(
        &self,
        connection_id: ConnectionId,
        priority: FanoutIntentPriority,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        ready(self.reserve_message(connection_id, priority.into(), maximum_encoded_bytes))
    }

    fn reserve_intent(
        &self,
        context: FanoutReservationContext,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        let purge_generation = match context {
            FanoutReservationContext::Control {
                subscription_id,
                subscription_generation,
                ..
            } => Some((subscription_id, subscription_generation)),
            FanoutReservationContext::Target { .. } => None,
        };
        ready(self.hub.reserve_addressed(
            context.connection_id(),
            context.priority().into(),
            maximum_encoded_bytes,
            purge_generation,
        ))
    }

    fn is_target_rejection(&self, error: &Self::Error) -> bool {
        matches!(
            error,
            DeliveryError::SlowConsumer
                | DeliveryError::Closed
                | DeliveryError::ConnectionNotActive
        )
    }
}

impl FanoutIntentSink for ConnectionDeliveryHub {
    type Error = DeliveryError;
    type Reservation = DeliveryReservation;

    fn reserve(
        &self,
        _maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        ready(Err(DeliveryError::ConnectionRequired))
    }

    fn reserve_for(
        &self,
        connection_id: ConnectionId,
        priority: FanoutIntentPriority,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        ready(self.reserve_addressed(connection_id, priority.into(), maximum_encoded_bytes, None))
    }

    fn reserve_intent(
        &self,
        context: FanoutReservationContext,
        maximum_encoded_bytes: usize,
    ) -> impl Future<Output = Result<Self::Reservation, Self::Error>> + Send {
        let purge_generation = match context {
            FanoutReservationContext::Control {
                subscription_id,
                subscription_generation,
                ..
            } => Some((subscription_id, subscription_generation)),
            FanoutReservationContext::Target { .. } => None,
        };
        ready(self.reserve_addressed(
            context.connection_id(),
            context.priority().into(),
            maximum_encoded_bytes,
            purge_generation,
        ))
    }

    fn is_target_rejection(&self, error: &Self::Error) -> bool {
        matches!(
            error,
            DeliveryError::SlowConsumer
                | DeliveryError::Closed
                | DeliveryError::ConnectionNotActive
        )
    }
}

/// One exact count-and-byte reservation released on drop or transferred at admission.
#[must_use = "dropping a delivery reservation releases its count and byte capacity"]
pub struct DeliveryReservation {
    hub: ConnectionDeliveryHub,
    connection_id: ConnectionId,
    priority: DeliveryPriority,
    reserved_bytes: usize,
    reservation_epoch: u64,
    active: bool,
}

impl DeliveryReservation {
    /// Encodes and atomically transfers this reservation to one outbound protocol message.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError`] for encoding, lifecycle, stale, or admission failures.
    pub fn admit_message(mut self, message: OutboundMessage) -> Result<(), DeliveryError> {
        let envelope = message
            .into_envelope()
            .map_err(|_| DeliveryError::Encoding)?;
        let message_type = envelope.message_type().clone();
        let encoded = envelope.encode().map_err(|_| DeliveryError::Encoding)?;
        self.admit_stored(StoredMessage {
            encoded,
            message_type,
            priority: self.priority,
            generation: None,
        })
    }

    fn admit_intent(mut self, intent: FanoutDeliveryIntent) -> Result<(), DeliveryError> {
        let stored = match intent {
            FanoutDeliveryIntent::Target(target) => {
                if target.connection_id() != self.connection_id
                    || self.priority != DeliveryPriority::Normal
                {
                    return Err(DeliveryError::Unavailable);
                }
                let generation = (target.subscription_id(), target.subscription_generation());
                let (message_type, encoded) = target.into_delivery_parts();
                StoredMessage {
                    encoded,
                    message_type,
                    priority: DeliveryPriority::Normal,
                    generation: Some(generation),
                }
            }
            FanoutDeliveryIntent::Control(intent) => {
                if intent.connection_id() != self.connection_id
                    || self.priority != DeliveryPriority::High
                {
                    return Err(DeliveryError::Unavailable);
                }
                let generation = intent.subscription_generation();
                let output = intent.into_output();
                let subscription_id = match &output {
                    ControlOutput::SubscriptionRevoked {
                        subscription_id, ..
                    } => *subscription_id,
                    ControlOutput::Pong { .. } => return Err(DeliveryError::Unavailable),
                };
                let envelope = OutboundMessage::Control(output)
                    .into_envelope()
                    .map_err(|_| DeliveryError::Encoding)?;
                let message_type = envelope.message_type().clone();
                StoredMessage {
                    encoded: envelope.encode().map_err(|_| DeliveryError::Encoding)?,
                    message_type,
                    priority: DeliveryPriority::High,
                    generation: Some((subscription_id, generation)),
                }
            }
        };
        self.admit_stored(stored)
    }

    fn admit_stored(&mut self, stored: StoredMessage) -> Result<(), DeliveryError> {
        if stored.encoded.len() > self.reserved_bytes {
            return Err(DeliveryError::ReservationTooLarge);
        }
        if let Some((subscription_id, generation)) = stored.generation {
            let current = match stored.priority {
                DeliveryPriority::Normal => self
                    .hub
                    .inner
                    .registry
                    .is_subscription_current_active(subscription_id, generation),
                DeliveryPriority::High => self
                    .hub
                    .inner
                    .registry
                    .is_subscription_current_generation(subscription_id, generation),
            }
            .map_err(|_| DeliveryError::Unavailable)?;
            if !current {
                self.hub
                    .inner
                    .metrics
                    .stale_generation_dropped
                    .fetch_add(1, Ordering::Relaxed);
                self.release();
                return Ok(());
            }
        }

        let waker = {
            let mut state = lock(&self.hub.inner.state);
            let Some(queue) = state.queues.get(&self.connection_id) else {
                return Err(DeliveryError::Closed);
            };
            if queue.closed || queue.terminal.is_some() {
                return Err(DeliveryError::Closed);
            }

            if stored.priority == DeliveryPriority::High
                && let Some(generation) = stored.generation
            {
                let purged = purge_generation_locked(&mut state, self.connection_id, generation);
                self.hub
                    .inner
                    .metrics
                    .revocation_purged
                    .fetch_add(purged as u64, Ordering::Relaxed);
            }

            release_reservation_locked(
                &mut state,
                self.connection_id,
                self.reserved_bytes,
                self.reservation_epoch,
            );
            self.active = false;
            let actual_bytes = stored.encoded.len();
            let priority = stored.priority;
            let Some(queue) = state.queues.get_mut(&self.connection_id) else {
                return Err(DeliveryError::Closed);
            };
            let waker = Arc::clone(&queue.waker);
            match priority {
                DeliveryPriority::Normal => queue.normal.push_back(stored),
                DeliveryPriority::High => queue.high.push_back(stored),
            }
            queue.queued_bytes += actual_bytes;
            state.queued_messages += 1;
            state.queued_bytes += actual_bytes;
            if priority == DeliveryPriority::High {
                state.high_priority_messages += 1;
            }
            waker
        };
        self.hub
            .inner
            .metrics
            .admitted
            .fetch_add(1, Ordering::Relaxed);
        waker.wake();
        self.hub.inner.changed.notify_waiters();
        Ok(())
    }

    fn release(&mut self) {
        if !self.active {
            return;
        }
        let mut state = lock(&self.hub.inner.state);
        release_reservation_locked(
            &mut state,
            self.connection_id,
            self.reserved_bytes,
            self.reservation_epoch,
        );
        self.active = false;
        drop(state);
        self.hub.inner.changed.notify_waiters();
    }
}

impl FanoutIntentReservation for DeliveryReservation {
    type Error = DeliveryError;

    fn admit(
        self,
        intent: FanoutDeliveryIntent,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        ready(self.admit_intent(intent))
    }
}

impl fmt::Debug for DeliveryReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryReservation")
            .field("priority", &self.priority)
            .field("reserved_bytes", &self.reserved_bytes)
            .field("reservation_epoch", &self.reservation_epoch)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl Drop for DeliveryReservation {
    fn drop(&mut self) {
        self.release();
    }
}

/// Exclusive receiver for one connection-owned queue.
#[must_use = "dropping the receiver closes its queue and registry connection"]
pub struct ConnectionDeliveryReceiver {
    hub: ConnectionDeliveryHub,
    connection_id: ConnectionId,
    waker: Arc<AtomicWaker>,
    open: bool,
}

impl ConnectionDeliveryReceiver {
    /// Returns the exact connection owned by this receiver.
    #[must_use]
    pub const fn connection_id(&self) -> ConnectionId {
        self.connection_id
    }

    /// Waits for the next high-priority, normal, or terminal delivery.
    pub async fn recv(&mut self) -> Option<QueuedDelivery> {
        poll_fn(|context| self.poll_recv(context)).await
    }

    /// Polls the connection queue without introducing another channel.
    pub fn poll_recv(&mut self, context: &mut Context<'_>) -> Poll<Option<QueuedDelivery>> {
        loop {
            let stored = {
                let mut state = lock(&self.hub.inner.state);
                let Some(queue) = state.queues.get_mut(&self.connection_id) else {
                    self.open = false;
                    return Poll::Ready(None);
                };
                if let Some(terminal) = queue.terminal.take() {
                    queue.closed = true;
                    return Poll::Ready(Some(QueuedDelivery::Terminal(terminal)));
                }
                let message = queue.high.pop_front().or_else(|| queue.normal.pop_front());
                if let Some(message) = message {
                    let bytes = message.encoded.len();
                    queue.queued_bytes -= bytes;
                    state.queued_messages -= 1;
                    state.queued_bytes -= bytes;
                    if message.priority == DeliveryPriority::High {
                        state.high_priority_messages -= 1;
                    }
                    Some(message)
                } else if queue.closed {
                    self.open = false;
                    return Poll::Ready(None);
                } else {
                    self.waker.register(context.waker());
                    None
                }
            };

            let Some(message) = stored else {
                return Poll::Pending;
            };
            self.hub.inner.changed.notify_waiters();
            if let Some((subscription_id, generation)) = message.generation {
                let current = match message.priority {
                    DeliveryPriority::Normal => self
                        .hub
                        .inner
                        .registry
                        .is_subscription_current_active(subscription_id, generation),
                    DeliveryPriority::High => self
                        .hub
                        .inner
                        .registry
                        .is_subscription_current_generation(subscription_id, generation),
                };
                match current {
                    Ok(true) => {}
                    Ok(false) => {
                        self.hub
                            .inner
                            .metrics
                            .stale_generation_dropped
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    Err(_) => {
                        self.hub.close_connection(self.connection_id);
                        self.open = false;
                        return Poll::Ready(None);
                    }
                }
            }
            return Poll::Ready(Some(QueuedDelivery::Message(DeliveryMessage {
                encoded: message.encoded,
                message_type: message.message_type,
                priority: message.priority,
            })));
        }
    }

    /// Records one successful transport write without adding identifier labels.
    pub fn record_sent(&self) {
        self.hub.inner.metrics.sent.fetch_add(1, Ordering::Relaxed);
    }

    fn close(&mut self) {
        if self.open {
            self.open = false;
            self.hub.close_connection(self.connection_id);
        }
        let mut state = lock(&self.hub.inner.state);
        if let Some(queue) = state.queues.get_mut(&self.connection_id) {
            queue.receiver_open = false;
            if queue.closed && queue.reserved_messages == 0 {
                state.queues.remove(&self.connection_id);
            }
        }
    }
}

impl fmt::Debug for ConnectionDeliveryReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionDeliveryReceiver")
            .field("open", &self.open)
            .finish_non_exhaustive()
    }
}

impl Drop for ConnectionDeliveryReceiver {
    fn drop(&mut self) {
        self.close();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn release_reservation_locked(
    state: &mut HubState,
    connection_id: ConnectionId,
    reserved_bytes: usize,
    reservation_epoch: u64,
) {
    let mut remove = false;
    let mut released = false;
    if let Some(queue) = state.queues.get_mut(&connection_id)
        && queue.reservation_epoch == reservation_epoch
    {
        queue.reserved_messages -= 1;
        queue.reserved_bytes -= reserved_bytes;
        remove = queue.closed && !queue.receiver_open && queue.reserved_messages == 0;
        released = true;
    }
    if released {
        state.reserved_messages -= 1;
        state.reserved_bytes -= reserved_bytes;
    }
    if remove {
        state.queues.remove(&connection_id);
    }
}

fn invalidate_reservations_locked(state: &mut HubState, connection_id: ConnectionId) {
    let Some((reserved_messages, reserved_bytes)) =
        state.queues.get_mut(&connection_id).map(|queue| {
            let reserved = (queue.reserved_messages, queue.reserved_bytes);
            queue.reserved_messages = 0;
            queue.reserved_bytes = 0;
            queue.reservation_epoch = queue.reservation_epoch.wrapping_add(1);
            reserved
        })
    else {
        return;
    };
    state.reserved_messages -= reserved_messages;
    state.reserved_bytes -= reserved_bytes;
}

fn clear_queue_locked(state: &mut HubState, connection_id: ConnectionId) -> usize {
    let Some(queue) = state.queues.get_mut(&connection_id) else {
        return 0;
    };
    let messages = queue.queued_messages();
    let bytes = queue.queued_bytes();
    let high = queue.high.len();
    queue.high.clear();
    queue.normal.clear();
    queue.queued_bytes = 0;
    state.queued_messages -= messages;
    state.queued_bytes -= bytes;
    state.high_priority_messages -= high;
    messages
}

fn purge_generation_locked(
    state: &mut HubState,
    connection_id: ConnectionId,
    generation: (SubscriptionId, u64),
) -> usize {
    let Some(queue) = state.queues.get_mut(&connection_id) else {
        return 0;
    };
    let mut removed_messages = 0;
    let mut removed_bytes = 0;
    queue.normal.retain(|message| {
        if message.generation == Some(generation) {
            removed_messages += 1;
            removed_bytes += message.encoded.len();
            false
        } else {
            true
        }
    });
    queue.queued_bytes -= removed_bytes;
    state.queued_messages -= removed_messages;
    state.queued_bytes -= removed_bytes;
    removed_messages
}

fn make_room_for_high_locked(
    state: &mut HubState,
    connection_id: ConnectionId,
    reservation_bytes: usize,
    config: DeliveryQueueConfig,
) -> usize {
    let Some(queue) = state.queues.get_mut(&connection_id) else {
        return 0;
    };
    let mut removed_messages = 0;
    let mut removed_bytes = 0;
    while queue.queued_messages() + queue.reserved_messages >= config.max_messages_per_connection
        || queue.queued_bytes() + queue.reserved_bytes + reservation_bytes
            > config.max_bytes_per_connection
    {
        let Some(message) = queue.normal.pop_front() else {
            break;
        };
        removed_messages += 1;
        removed_bytes += message.encoded.len();
    }
    queue.queued_bytes -= removed_bytes;
    state.queued_messages -= removed_messages;
    state.queued_bytes -= removed_bytes;
    removed_messages
}

fn make_global_room_for_high_locked(
    state: &mut HubState,
    reservation_bytes: usize,
    config: DeliveryQueueConfig,
) -> usize {
    let mut removed_messages = 0;
    while state.queued_bytes + state.reserved_bytes + reservation_bytes > config.max_total_bytes {
        let candidate = state.queues.iter().find_map(|(connection_id, queue)| {
            (!queue.normal.is_empty()).then_some(*connection_id)
        });
        let Some(connection_id) = candidate else {
            break;
        };
        let Some(queue) = state.queues.get_mut(&connection_id) else {
            break;
        };
        let Some(message) = queue.normal.pop_front() else {
            break;
        };
        let bytes = message.encoded.len();
        queue.queued_bytes -= bytes;
        state.queued_messages -= 1;
        state.queued_bytes -= bytes;
        removed_messages += 1;
    }
    removed_messages
}

fn mark_slow_locked(state: &mut HubState, connection_id: ConnectionId) -> bool {
    let already_terminal = state
        .queues
        .get(&connection_id)
        .is_none_or(|queue| queue.closed || queue.terminal.is_some());
    if already_terminal {
        return false;
    }
    clear_queue_locked(state, connection_id);
    invalidate_reservations_locked(state, connection_id);
    if let Some(queue) = state.queues.get_mut(&connection_id) {
        queue.terminal = Some(DeliveryTerminal::SlowConsumer);
    }
    true
}
