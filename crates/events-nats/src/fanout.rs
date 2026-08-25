//! Ephemeral Core NATS fan-out over one exact subject and a bounded local ingress.
//!
//! Core NATS is deliberately loss-tolerant: publications before readiness, during disconnect,
//! after local overflow, or during shutdown can be lost. There is no stream, acknowledgement,
//! cursor, replay, or durable consumer. Each registered listener task owns one subscription for
//! its application instance.
//!
//! The SDK materializes a complete protocol message before this provider can reject a payload over
//! its local limit. Deployments must therefore grant exact-subject publication only to trusted
//! producers and keep the server's maximum payload within an acceptable transient memory bound.

use std::{
    fmt,
    future::ready,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_nats::{Client, Event as NatsEvent, Subject, connection::State as ConnectionState};
use bytes::Bytes;
use futures::StreamExt as _;
use metrics::{counter, histogram};
use rsk_config::DeploymentEnvironment;
use rsk_core::{ErrorCode, ServiceError};
use rsk_runtime::{Criticality, RestartPolicy, TaskContext, TaskSpec};
use thiserror::Error;
use tokio::{
    sync::{Notify, mpsc, watch},
    time,
};

use crate::{
    config::{
        NatsConnectionConfig, NatsCoreFanoutConfig, NatsCoreFanoutConfigError, NatsRestartConfig,
    },
    connection,
};

const TASK_NAME: &str = "nats-core-fanout-listener";
const MODULE_NAME: &str = "events-nats";
const ASYNC_ERROR_SETTLE_INTERVAL: Duration = Duration::from_millis(100);
const LISTENER_ERROR_CODE: &str = "NATS_CORE_FANOUT_UNAVAILABLE";
const CONNECTION_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// One Core NATS fan-out capability with a publisher, bounded receiver, and supervised listener.
pub struct NatsCoreFanout {
    publisher: NatsCoreFanoutPublisher,
    receiver: NatsCoreFanoutReceiver,
    listener: ListenerRegistration,
    status: NatsCoreFanoutStatus,
}

impl fmt::Debug for NatsCoreFanout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanout")
            .field("publisher", &self.publisher)
            .field("receiver", &self.receiver)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl NatsCoreFanout {
    /// Connects the publication path and prepares a separately supervised subscription path.
    ///
    /// This constructor performs no `JetStream` request and creates no server-side resource. The
    /// listener does not subscribe until its returned task is registered and started.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for rejected bounds, unsafe connection policy, authentication,
    /// or publication-connection failure.
    pub async fn connect(
        connection_config: &NatsConnectionConfig,
        config: NatsCoreFanoutConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, NatsCoreFanoutError> {
        connection_config
            .validate_for(environment)
            .map_err(|_| NatsCoreFanoutError::Config)?;
        config.validate()?;
        let connected = connection::connect(connection_config, environment)
            .await
            .map_err(|_| NatsCoreFanoutError::Connect)?;
        let subject = Subject::from(config.subject.clone());
        let (sender, receiver) = mpsc::channel(config.ingress_capacity);
        let (status_sender, status_receiver) = watch::channel(NatsCoreFanoutLifecycle::Pending);
        let publisher = NatsCoreFanoutPublisher {
            client: connected.client,
            subject: subject.clone(),
            max_message_bytes: config.max_message_bytes,
            operation_timeout: connection_config.operation_timeout,
        };
        let listener = ListenerRegistration {
            state: Arc::new(ListenerState {
                connection_config: connection_config.clone(),
                environment,
                subject,
                sender,
                max_message_bytes: config.max_message_bytes,
                operation_timeout: connection_config.operation_timeout,
                status: status_sender,
            }),
            shutdown_timeout: config.shutdown_timeout,
            restart: config.restart,
        };
        let status = NatsCoreFanoutStatus {
            receiver: status_receiver,
        };
        Ok(Self {
            publisher,
            receiver: NatsCoreFanoutReceiver { receiver },
            listener,
            status,
        })
    }

    /// Returns a cheap publisher clone for ephemeral fan-out calls.
    #[must_use]
    pub fn publisher(&self) -> NatsCoreFanoutPublisher {
        self.publisher.clone()
    }

    /// Returns a cloneable, value-free lifecycle observer.
    #[must_use]
    pub fn status(&self) -> NatsCoreFanoutStatus {
        self.status.clone()
    }

    /// Consumes the capability into its publisher, sole receiver, status, and listener task.
    ///
    /// Register the task with [`rsk_runtime::Supervisor`] before treating the subscription as
    /// ready. Readiness means the server processed the exact `SUBSCRIBE`, not that any message is
    /// retained or replayable.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        NatsCoreFanoutPublisher,
        NatsCoreFanoutReceiver,
        NatsCoreFanoutStatus,
        TaskSpec,
    ) {
        let Self {
            publisher,
            receiver,
            listener,
            status,
        } = self;
        (publisher, receiver, status, listener.into_task_spec())
    }
}

/// Cheap Core NATS publisher for one statically configured exact subject.
#[derive(Clone)]
pub struct NatsCoreFanoutPublisher {
    client: Client,
    subject: Subject,
    max_message_bytes: usize,
    operation_timeout: Duration,
}

impl fmt::Debug for NatsCoreFanoutPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutPublisher")
            .field("subject", &"[REDACTED]")
            .field("max_message_bytes", &self.max_message_bytes)
            .finish_non_exhaustive()
    }
}

impl NatsCoreFanoutPublisher {
    /// Publishes opaque bounded bytes and flushes the Core NATS connection within one deadline.
    ///
    /// A successful flush only establishes server handoff. It is not a delivery acknowledgement
    /// and does not imply that any application instance retained the message.
    ///
    /// # Errors
    ///
    /// Returns a value-free size or availability error without retaining SDK diagnostics.
    pub async fn publish(&self, payload: Bytes) -> Result<(), NatsCoreFanoutPublishError> {
        let started = std::time::Instant::now();
        if payload.len() > self.max_message_bytes {
            record_publish(PublishStatus::Rejected, started.elapsed());
            return Err(NatsCoreFanoutPublishError::MessageTooLarge);
        }
        let result = match time::timeout(self.operation_timeout, async {
            self.client
                .publish(self.subject.clone(), payload)
                .await
                .map_err(|_| NatsCoreFanoutPublishError::Unavailable)?;
            self.client
                .flush()
                .await
                .map_err(|_| NatsCoreFanoutPublishError::Unavailable)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(NatsCoreFanoutPublishError::Unavailable),
        };
        record_publish(
            if result.is_ok() {
                PublishStatus::Published
            } else {
                PublishStatus::Unavailable
            },
            started.elapsed(),
        );
        result
    }
}

/// Safe Core NATS publication failure without subject, payload, tenant, URL, or SDK details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsCoreFanoutPublishError {
    /// The opaque record exceeded the configured local publication bound.
    #[error("Core NATS fan-out payload exceeds its size limit")]
    MessageTooLarge,
    /// Core NATS could not accept and flush the publication within its deadline.
    #[error("Core NATS fan-out publishing is unavailable")]
    Unavailable,
}

/// One bounded opaque Core NATS record retained by this application instance.
#[derive(Clone, Eq, PartialEq)]
pub struct NatsCoreFanoutMessage {
    payload: Bytes,
}

impl fmt::Debug for NatsCoreFanoutMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutMessage")
            .field("payload", &"[REDACTED]")
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl NatsCoreFanoutMessage {
    /// Returns the opaque provider record.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the record without copying its byte storage.
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

/// Sole consumer for the provider-owned bounded ingress.
pub struct NatsCoreFanoutReceiver {
    receiver: mpsc::Receiver<NatsCoreFanoutMessage>,
}

impl fmt::Debug for NatsCoreFanoutReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutReceiver")
            .field("queued", &self.receiver.len())
            .field("capacity", &self.receiver.max_capacity())
            .finish_non_exhaustive()
    }
}

impl NatsCoreFanoutReceiver {
    /// Waits for the next locally retained message, or `None` after sender closure.
    pub async fn recv(&mut self) -> Option<NatsCoreFanoutMessage> {
        self.receiver.recv().await
    }

    /// Attempts to receive one retained message without waiting.
    ///
    /// # Errors
    ///
    /// Returns Tokio's empty or disconnected bounded-channel state.
    pub fn try_recv(&mut self) -> Result<NatsCoreFanoutMessage, mpsc::error::TryRecvError> {
        self.receiver.try_recv()
    }

    /// Returns the current bounded queue length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.receiver.len()
    }

    /// Returns whether the bounded ingress is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.receiver.is_empty()
    }
}

/// Value-free lifecycle of the application instance's one Core NATS subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NatsCoreFanoutLifecycle {
    /// The listener task has not started.
    Pending,
    /// A supervised attempt is connecting or installing its exact subscription.
    Connecting,
    /// The server processed the subscription and the connection is currently ready.
    Ready,
    /// The subscription is temporarily unavailable while reconnect or restart proceeds.
    Degraded,
    /// Cancellation or receiver closure stopped intake.
    Stopped,
}

/// Cloneable, value-free lifecycle and readiness observer.
#[derive(Clone)]
pub struct NatsCoreFanoutStatus {
    receiver: watch::Receiver<NatsCoreFanoutLifecycle>,
}

impl fmt::Debug for NatsCoreFanoutStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutStatus")
            .field("lifecycle", &self.lifecycle())
            .finish()
    }
}

impl NatsCoreFanoutStatus {
    /// Returns the latest value-free lifecycle state.
    #[must_use]
    pub fn lifecycle(&self) -> NatsCoreFanoutLifecycle {
        if self.receiver.has_changed().is_err() {
            NatsCoreFanoutLifecycle::Stopped
        } else {
            *self.receiver.borrow()
        }
    }

    /// Returns whether the exact subscription is ready at this instant.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.lifecycle() == NatsCoreFanoutLifecycle::Ready
    }

    /// Waits for and returns the next lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns a value-free error if the internal lifecycle source is no longer available.
    pub async fn changed(&mut self) -> Result<NatsCoreFanoutLifecycle, NatsCoreFanoutStatusError> {
        match self.receiver.changed().await {
            Ok(()) => Ok(*self.receiver.borrow_and_update()),
            Err(_) if self.lifecycle() == NatsCoreFanoutLifecycle::Stopped => {
                Ok(NatsCoreFanoutLifecycle::Stopped)
            }
            Err(_) => Err(NatsCoreFanoutStatusError::Unavailable),
        }
    }

    /// Waits until the subscription becomes ready.
    ///
    /// # Errors
    ///
    /// Returns a value-free error if intake stops first or lifecycle observation closes.
    pub async fn wait_until_ready(&mut self) -> Result<(), NatsCoreFanoutStatusError> {
        loop {
            match self.lifecycle() {
                NatsCoreFanoutLifecycle::Ready => return Ok(()),
                NatsCoreFanoutLifecycle::Stopped => {
                    return Err(NatsCoreFanoutStatusError::Stopped);
                }
                NatsCoreFanoutLifecycle::Pending
                | NatsCoreFanoutLifecycle::Connecting
                | NatsCoreFanoutLifecycle::Degraded => {
                    self.changed().await?;
                }
            }
        }
    }
}

/// Safe lifecycle-observation failure without provider or application values.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsCoreFanoutStatusError {
    /// Intake stopped before readiness was reached.
    #[error("Core NATS fan-out listener stopped before readiness")]
    Stopped,
    /// The internal lifecycle source closed.
    #[error("Core NATS fan-out lifecycle status is unavailable")]
    Unavailable,
}

/// Safe Core NATS capability construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsCoreFanoutError {
    /// Declarative connection or fan-out configuration was rejected.
    #[error("Core NATS fan-out configuration is invalid")]
    Config,
    /// Publication-path connection or authentication failed.
    #[error("Core NATS fan-out connection failed")]
    Connect,
}

impl From<NatsCoreFanoutConfigError> for NatsCoreFanoutError {
    fn from(_: NatsCoreFanoutConfigError) -> Self {
        Self::Config
    }
}

struct ListenerRegistration {
    state: Arc<ListenerState>,
    shutdown_timeout: Duration,
    restart: NatsRestartConfig,
}

impl ListenerRegistration {
    fn into_task_spec(self) -> TaskSpec {
        let state = self.state;
        TaskSpec::new(
            TASK_NAME,
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

#[derive(Default)]
struct AttemptErrorLatch {
    generation: AtomicU64,
    notification: Notify,
    transition: Mutex<()>,
}

impl AttemptErrorLatch {
    fn latch(&self, status: &watch::Sender<NatsCoreFanoutLifecycle>) {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.generation.fetch_add(1, Ordering::AcqRel);
        transition(status, NatsCoreFanoutLifecycle::Degraded);
        self.notification.notify_one();
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn transition_ready(
        &self,
        status: &watch::Sender<NatsCoreFanoutLifecycle>,
        expected_generation: u64,
    ) -> bool {
        let _transition = self
            .transition
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.generation() != expected_generation {
            return false;
        }
        transition(status, NatsCoreFanoutLifecycle::Ready);
        true
    }

    async fn latched(&self) {
        while self.generation() == 0 {
            self.notification.notified().await;
        }
    }
}

struct ListenerState {
    connection_config: NatsConnectionConfig,
    environment: DeploymentEnvironment,
    subject: Subject,
    sender: mpsc::Sender<NatsCoreFanoutMessage>,
    max_message_bytes: usize,
    operation_timeout: Duration,
    status: watch::Sender<NatsCoreFanoutLifecycle>,
}

impl Drop for ListenerState {
    fn drop(&mut self) {
        transition(&self.status, NatsCoreFanoutLifecycle::Stopped);
    }
}

#[allow(clippy::too_many_lines)]
async fn run_listener_attempt(
    state: Arc<ListenerState>,
    context: TaskContext,
) -> Result<(), ServiceError> {
    transition(&state.status, NatsCoreFanoutLifecycle::Connecting);
    let async_errors = Arc::new(AttemptErrorLatch::default());
    let callback_errors = Arc::clone(&async_errors);
    let listener_status = state.status.clone();
    let connected = tokio::select! {
        biased;
        () = context.draining() => return stopped(&state.status),
        () = context.shutdown_requested() => return stopped(&state.status),
        () = context.cancelled() => return stopped(&state.status),
        result = connection::connect_with_event_callback(
            &state.connection_config,
            state.environment,
            move |event| {
                match event {
                    NatsEvent::ServerError(_) | NatsEvent::ClientError(_) => {
                        callback_errors.latch(&listener_status);
                    }
                    NatsEvent::Disconnected
                    | NatsEvent::LameDuckMode
                    | NatsEvent::Draining
                    | NatsEvent::Closed => {
                        transition(&listener_status, NatsCoreFanoutLifecycle::Degraded);
                    }
                    _ => {}
                }
                ready(())
            },
        ) => result,
    };
    let Ok(connected) = connected else {
        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
        counter!("rsk_events_nats_core_connection_total", "status" => "error").increment(1);
        return Err(listener_error());
    };
    counter!("rsk_events_nats_core_connection_total", "status" => "ok").increment(1);
    if is_stopping(&context) || state.sender.is_closed() {
        return stopped(&state.status);
    }
    let subscribe = time::timeout(
        state.operation_timeout,
        connected.client.subscribe(state.subject.clone()),
    );
    let subscription = tokio::select! {
        biased;
        () = context.draining() => return stopped(&state.status),
        () = context.shutdown_requested() => return stopped(&state.status),
        () = context.cancelled() => return stopped(&state.status),
        result = subscribe => result,
    };
    let Ok(Ok(mut subscription)) = subscription else {
        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
        counter!("rsk_events_nats_core_subscription_total", "status" => "error").increment(1);
        return Err(listener_error());
    };
    let statistics = connected.client.statistics();
    let mut observed_connection_generation = statistics.connects.load(Ordering::Relaxed);
    if !flush_readiness(&connected.client, &state, &context, &async_errors).await? {
        return stopped(&state.status);
    }
    counter!("rsk_events_nats_core_subscription_total", "status" => "ok").increment(1);

    let mut connection_poll = time::interval(CONNECTION_POLL_INTERVAL);
    connection_poll.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = context.draining() => return stopped(&state.status),
            () = context.shutdown_requested() => return stopped(&state.status),
            () = context.cancelled() => return stopped(&state.status),
            () = state.sender.closed() => return stopped(&state.status),
            () = async_errors.latched() => {
                transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
                return Err(listener_error());
            }
            message = subscription.next() => {
                let Some(message) = message else {
                    transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
                    return Err(listener_error());
                };
                counter!("rsk_events_nats_core_received_total").increment(1);
                if message.payload.len() > state.max_message_bytes {
                    record_drop(DropReason::Oversize);
                    continue;
                }
                let delivery = NatsCoreFanoutMessage {
                    payload: message.payload,
                };
                match state.sender.try_send(delivery) {
                    Ok(()) => counter!("rsk_events_nats_core_delivered_total").increment(1),
                    Err(mpsc::error::TrySendError::Full(_)) => record_drop(DropReason::Full),
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        record_drop(DropReason::Closed);
                        return stopped(&state.status);
                    }
                }
            }
            _ = connection_poll.tick() => {
                if async_errors.generation() != 0 {
                    transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
                    return Err(listener_error());
                }
                let connection_generation = statistics.connects.load(Ordering::Relaxed);
                match connected.client.connection_state() {
                    ConnectionState::Connected
                        if connection_generation != observed_connection_generation
                            || !is_ready(&state.status) =>
                    {
                        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
                        if !flush_readiness(
                            &connected.client,
                            &state,
                            &context,
                            &async_errors,
                        )
                        .await?
                        {
                            return stopped(&state.status);
                        }
                        observed_connection_generation = connection_generation;
                    }
                    ConnectionState::Pending | ConnectionState::Disconnected => {
                        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
                    }
                    ConnectionState::Connected => {}
                }
            }
        }
    }
}

async fn flush_readiness(
    client: &Client,
    state: &ListenerState,
    context: &TaskContext,
    async_errors: &AttemptErrorLatch,
) -> Result<bool, ServiceError> {
    let error_generation = async_errors.generation();
    if error_generation != 0 {
        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
        return Err(listener_error());
    }
    let flush = time::timeout(state.operation_timeout, client.flush());
    let result = tokio::select! {
        biased;
        () = context.draining() => return Ok(false),
        () = context.shutdown_requested() => return Ok(false),
        () = context.cancelled() => return Ok(false),
        result = flush => result,
    };
    if !matches!(result, Ok(Ok(()))) {
        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
        return Err(listener_error());
    }

    tokio::select! {
        biased;
        () = context.draining() => return Ok(false),
        () = context.shutdown_requested() => return Ok(false),
        () = context.cancelled() => return Ok(false),
        () = async_errors.latched() => {
            transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
            return Err(listener_error());
        }
        () = time::sleep(ASYNC_ERROR_SETTLE_INTERVAL) => {}
    }
    if !async_errors.transition_ready(&state.status, error_generation) {
        transition(&state.status, NatsCoreFanoutLifecycle::Degraded);
        return Err(listener_error());
    }
    Ok(true)
}

fn transition(status: &watch::Sender<NatsCoreFanoutLifecycle>, lifecycle: NatsCoreFanoutLifecycle) {
    let changed = status.send_if_modified(|current| {
        if *current == NatsCoreFanoutLifecycle::Stopped || *current == lifecycle {
            return false;
        }
        *current = lifecycle;
        true
    });
    if changed {
        counter!("rsk_events_nats_core_lifecycle_total", "status" => lifecycle.label())
            .increment(1);
    }
}

fn is_ready(status: &watch::Sender<NatsCoreFanoutLifecycle>) -> bool {
    *status.borrow() == NatsCoreFanoutLifecycle::Ready
}

#[allow(clippy::unnecessary_wraps)]
fn stopped(status: &watch::Sender<NatsCoreFanoutLifecycle>) -> Result<(), ServiceError> {
    transition(status, NatsCoreFanoutLifecycle::Stopped);
    Ok(())
}

fn is_stopping(context: &TaskContext) -> bool {
    context.is_draining() || context.is_shutdown_requested() || context.is_cancelled()
}

impl NatsCoreFanoutLifecycle {
    const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Connecting => "connecting",
            Self::Ready => "ready",
            Self::Degraded => "degraded",
            Self::Stopped => "stopped",
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
enum DropReason {
    Oversize,
    Full,
    Closed,
}

impl DropReason {
    const fn label(self) -> &'static str {
        match self {
            Self::Oversize => "oversize",
            Self::Full => "full",
            Self::Closed => "closed",
        }
    }
}

fn record_publish(status: PublishStatus, elapsed: Duration) {
    counter!("rsk_events_nats_core_publish_total", "status" => status.label()).increment(1);
    histogram!("rsk_events_nats_core_publish_duration_seconds", "status" => status.label())
        .record(elapsed.as_secs_f64());
}

fn record_drop(reason: DropReason) {
    counter!("rsk_events_nats_core_dropped_total", "reason" => reason.label()).increment(1);
}

fn listener_error() -> ServiceError {
    ServiceError::new(
        listener_error_code(),
        "Core NATS fan-out listener unavailable",
    )
}

fn listener_error_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(LISTENER_ERROR_CODE) else {
        unreachable!("static Core NATS listener error code must be valid")
    };
    code
}
