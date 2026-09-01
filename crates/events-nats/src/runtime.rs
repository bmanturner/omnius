use std::{
    cell::Cell,
    fmt,
    future::poll_fn,
    panic::{self, AssertUnwindSafe},
    sync::{Arc, Once},
    task::Poll,
    time::{Duration, Instant},
};

use async_nats::{
    Client,
    jetstream::{
        self, AckKind,
        consumer::PullConsumer,
        message::{Message, PublishMessage},
    },
};
use futures::{FutureExt as _, StreamExt as _, future::BoxFuture, stream::FuturesUnordered};
use metrics::{counter, gauge, histogram};
use omnius_config::DeploymentEnvironment;
use omnius_core::{ErrorCode, ServiceError};
use omnius_health::{CheckFailure, HealthCheckSpec};
use omnius_jobs_core::{FailureCode, Version};
use omnius_runtime::{Criticality, HeartbeatPolicy, RestartPolicy, TaskContext, TaskSpec};
use serde::Serialize;
use tokio::time;
use tokio_util::sync::CancellationToken;

use crate::{
    config::{NatsConnectionConfig, NatsEventsConfig},
    connection,
    error::NatsEventsError,
    event::{RawEvent, encode_bounded},
    publisher::NatsOutboxPublisher,
    resource::expected_resources,
    verification::{verify_consumer, verify_stream},
};

const TASK_NAME: &str = "nats-consumers";
const HEALTH_NAME: &str = "nats-jetstream";
const MODULE_NAME: &str = "events-nats";
const PUBLISHER_DRAIN_TASK_NAME: &str = "nats-publisher-drain";
const SERVICE_ERROR_CODE: &str = "NATS_EVENTS_UNAVAILABLE";
const HEALTH_ERROR_CODE: &str = "NATS_EVENTS_UNHEALTHY";

thread_local! {
    static REDACT_HANDLER_PANIC: Cell<bool> = const { Cell::new(false) };
}

static INSTALL_PANIC_HOOK: Once = Once::new();

const MAX_INVALID_DLQ_CAPTURE_BYTES: usize = 64 * 1024;
const INVALID_DLQ_METADATA_BYTES: usize = 512;

/// Object-safe application delivery boundary.
pub trait EventHandler: Send + Sync + 'static {
    /// Handles one validated immutable event.
    fn handle(&self, event: RawEvent, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome>;
}

/// Durable handler disposition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerOutcome {
    /// The durable effect completed and the source may be acknowledged.
    Success,
    /// The event should be `NAKed` for delayed redelivery.
    Retryable(FailureCode),
    /// The event should be durably dead-lettered before acknowledging the source.
    Permanent(FailureCode),
}

/// Safe metadata and cancellation delivered to one handler invocation.
#[derive(Clone, Debug)]
pub struct DeliveryContext {
    delivery_count: u32,
    redelivered: bool,
    cancellation: CancellationToken,
}

impl DeliveryContext {
    /// One-based `JetStream` delivery count.
    #[must_use]
    pub const fn delivery_count(&self) -> u32 {
        self.delivery_count
    }

    /// Whether this delivery follows an earlier unacknowledged attempt.
    #[must_use]
    pub const fn is_redelivered(&self) -> bool {
        self.redelivered
    }

    /// Resolves when handler time or task shutdown is exhausted.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Returns whether cancellation has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Fresh point-in-time durable consumer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerStatus {
    lag: u64,
    ack_pending: usize,
    redelivered: usize,
}

impl ConsumerStatus {
    /// Messages pending initial delivery to this durable.
    #[must_use]
    pub const fn lag(self) -> u64 {
        self.lag
    }

    /// Delivered messages awaiting acknowledgement.
    #[must_use]
    pub const fn ack_pending(self) -> usize {
        self.ack_pending
    }

    /// Current server count of redelivered messages.
    #[must_use]
    pub const fn redelivered(self) -> usize {
        self.redelivered
    }
}

/// Verified durable `JetStream` consumer runtime.
pub struct NatsJetStreamEvents {
    client: Client,
    jetstream: jetstream::Context,
    consumer: PullConsumer,
    config: Arc<NatsEventsConfig>,
}

impl fmt::Debug for NatsJetStreamEvents {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsJetStreamEvents")
            .field("connection", &"[REDACTED]")
            .field("resources", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl NatsJetStreamEvents {
    /// Connects a runtime identity, fetches all declared resources, and exactly verifies them.
    ///
    /// This constructor never creates or updates a stream or consumer.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid policy, denied runtime access, or any resource drift.
    pub async fn connect(
        connection_config: &NatsConnectionConfig,
        config: NatsEventsConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, NatsEventsError> {
        config.validate_for(environment)?;
        let connected = connection::connect(connection_config, environment).await?;
        let (main, dlq, expected_consumer) = expected_resources(&config)?;
        let main_stream = verify_stream(&connected.jetstream, &main).await?;
        verify_stream(&connected.jetstream, &dlq).await?;
        let consumer = verify_consumer(
            &main_stream,
            &config.consumer.durable_name,
            &expected_consumer,
        )
        .await?;
        counter!("omnius_events_nats_verification_total", "status" => "ok").increment(1);
        Ok(Self {
            client: connected.client,
            jetstream: connected.jetstream,
            consumer,
            config: Arc::new(config),
        })
    }

    /// Builds the required supervised durable-consumer task.
    #[must_use]
    pub fn task_spec(self: Arc<Self>, handler: Arc<dyn EventHandler>) -> TaskSpec {
        let config = Arc::clone(&self.config);
        TaskSpec::new(
            TASK_NAME,
            MODULE_NAME,
            Criticality::Required,
            config.delivery.shutdown_timeout,
            move |context| {
                let runtime = Arc::clone(&self);
                let handler = Arc::clone(&handler);
                async move {
                    runtime
                        .run(handler, context)
                        .await
                        .map_err(|_| service_error())
                }
            },
        )
        .with_restart_policy(RestartPolicy::on_failure(
            config.restart.max_restarts,
            config.restart.initial_backoff,
            config.restart.max_backoff,
            config.restart.jitter_percent,
        ))
        .with_heartbeat_policy(HeartbeatPolicy::Expected {
            stale_after: config.heartbeat_stale_after,
        })
    }

    /// Builds a bounded, value-free health probe from a fresh consumer-info request.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        let consumer = self.consumer.clone();
        HealthCheckSpec::new(
            HEALTH_NAME,
            MODULE_NAME,
            Criticality::Required,
            self.config.health_timeout,
            move || {
                let consumer = consumer.clone();
                async move {
                    consumer
                        .get_info()
                        .await
                        .map(|_| ())
                        .map_err(|_| CheckFailure::new(health_error_code()))
                }
            },
        )
    }

    /// Fetches fresh lag, acknowledgement-pending, and redelivery information.
    ///
    /// # Errors
    ///
    /// Returns a safe access error if the point-in-time server request fails.
    pub async fn status(&self) -> Result<ConsumerStatus, NatsEventsError> {
        let info = self
            .consumer
            .get_info()
            .await
            .map_err(|_| NatsEventsError::Access)?;
        gauge!("omnius_events_nats_consumer_lag").set(metric_count(info.num_pending));
        gauge!("omnius_events_nats_consumer_ack_pending")
            .set(metric_count_usize(info.num_ack_pending));
        gauge!("omnius_events_nats_consumer_redelivered")
            .set(metric_count_usize(info.num_redelivered));
        Ok(ConsumerStatus {
            lag: info.num_pending,
            ack_pending: info.num_ack_pending,
            redelivered: info.num_redelivered,
        })
    }

    /// Flushes and terminally drains the underlying SDK connection.
    ///
    /// # Errors
    ///
    /// Returns a safe shutdown error if either bounded SDK operation fails.
    pub async fn drain(&self) -> Result<(), NatsEventsError> {
        time::timeout(self.config.delivery.shutdown_timeout, async {
            self.client
                .flush()
                .await
                .map_err(|_| NatsEventsError::Shutdown)?;
            self.client
                .drain()
                .await
                .map_err(|_| NatsEventsError::Shutdown)
        })
        .await
        .map_err(|_| NatsEventsError::Shutdown)?
    }

    async fn run(
        &self,
        handler: Arc<dyn EventHandler>,
        context: TaskContext,
    ) -> Result<(), NatsEventsError> {
        install_redacting_panic_hook();
        while !context.is_draining() && !context.is_shutdown_requested() && !context.is_cancelled()
        {
            let fetch = self
                .consumer
                .fetch()
                .max_messages(self.config.delivery.pull_batch)
                .max_bytes(self.config.delivery.pull_max_bytes)
                .heartbeat(self.config.delivery.pull_expiry / 2)
                .expires(self.config.delivery.pull_expiry)
                .messages();
            let mut batch = tokio::select! {
                biased;
                () = context.draining() => break,
                () = context.shutdown_requested() => break,
                () = context.cancelled() => break,
                result = fetch => result.map_err(|_| NatsEventsError::Fetch)?,
            };
            context.heartbeat();
            let mut active = FuturesUnordered::new();
            let mut stop = false;
            loop {
                while active.len() >= self.config.delivery.concurrency {
                    tokio::select! {
                        biased;
                        () = context.draining() => { stop = true; break; }
                        () = context.shutdown_requested() => { stop = true; break; }
                        () = context.cancelled() => { stop = true; break; }
                        Some(result) = active.next() => {
                            record_delivery(result);
                            context.heartbeat();
                        }
                    }
                }
                if stop {
                    break;
                }
                let next = tokio::select! {
                    biased;
                    () = context.draining() => { stop = true; None }
                    () = context.shutdown_requested() => { stop = true; None }
                    () = context.cancelled() => { stop = true; None }
                    item = batch.next() => item,
                };
                let Some(message) = next else {
                    break;
                };
                let message = message.map_err(|_| NatsEventsError::Fetch)?;
                active.push(self.process_message(message, Arc::clone(&handler), context.clone()));
            }
            drop(batch);
            while !active.is_empty() {
                if let Some(result) = active.next().await {
                    record_delivery(result);
                    context.heartbeat();
                }
            }
            if stop {
                break;
            }
        }
        self.drain().await
    }

    fn process_message(
        &self,
        message: Message,
        handler: Arc<dyn EventHandler>,
        task_context: TaskContext,
    ) -> BoxFuture<'static, DeliveryResult> {
        let jetstream = self.jetstream.clone();
        let config = Arc::clone(&self.config);
        async move {
            let started = Instant::now();
            let (event, stream_sequence, delivered) =
                match decode_delivery(&jetstream, &config, &message).await {
                    Ok(delivery) => delivery,
                    Err(result) => return result,
                };
            let disposition = if delivered >= config.consumer.max_deliveries {
                Invocation::MaxDeliveries
            } else {
                invoke_handler(
                    handler,
                    event.clone(),
                    delivered,
                    config.delivery.handler_timeout,
                    task_context,
                )
                .await
            };
            let result = match disposition {
                Invocation::Outcome(HandlerOutcome::Success) => message
                    .double_ack_with(AckKind::Ack)
                    .await
                    .map_or(DeliveryResult::AckFailed, |()| DeliveryResult::Success),
                Invocation::Outcome(HandlerOutcome::Retryable(_)) => message
                    .ack_with(AckKind::Nak(Some(config.delivery.retry_nak_delay)))
                    .await
                    .map_or(DeliveryResult::AckFailed, |()| DeliveryResult::Retry),
                Invocation::Outcome(HandlerOutcome::Permanent(code)) => {
                    dead_letter(
                        &jetstream,
                        &config,
                        &message,
                        &event,
                        stream_sequence,
                        delivered,
                        DeadLetterReason::Permanent,
                        Some(&code),
                    )
                    .await
                }
                Invocation::MaxDeliveries => {
                    dead_letter(
                        &jetstream,
                        &config,
                        &message,
                        &event,
                        stream_sequence,
                        delivered,
                        DeadLetterReason::MaxDeliveries,
                        None,
                    )
                    .await
                }
                Invocation::TimedOut => DeliveryResult::TimedOut,
                Invocation::Cancelled => DeliveryResult::Cancelled,
                Invocation::Panicked => {
                    let code = static_failure_code("handler_panic");
                    dead_letter(
                        &jetstream,
                        &config,
                        &message,
                        &event,
                        stream_sequence,
                        delivered,
                        DeadLetterReason::Permanent,
                        Some(&code),
                    )
                    .await
                }
            };
            histogram!("omnius_events_nats_delivery_duration_seconds", "status" => result.label())
                .record(started.elapsed().as_secs_f64());
            result
        }
        .boxed()
    }
}

/// Verified durable `JetStream` publication and consumer composition.
///
/// Construction verifies the pre-provisioned stream, DLQ, and durable consumer. It never creates
/// or updates broker resources and is intentionally distinct from ephemeral Core NATS fan-out.
pub struct NatsJetStreamRuntime {
    publisher: NatsOutboxPublisher,
    events: Arc<NatsJetStreamEvents>,
}

impl fmt::Debug for NatsJetStreamRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsJetStreamRuntime")
            .field("resources", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl NatsJetStreamRuntime {
    /// Connects separate publication and consumption identities and verifies every declared
    /// `JetStream` resource.
    ///
    /// # Errors
    ///
    /// Returns a safe error for invalid policy, denied access, or resource drift.
    pub async fn connect(
        connection_config: &NatsConnectionConfig,
        config: NatsEventsConfig,
        environment: DeploymentEnvironment,
    ) -> Result<Self, NatsEventsError> {
        let publisher =
            NatsOutboxPublisher::connect(connection_config, &config, environment).await?;
        let events =
            Arc::new(NatsJetStreamEvents::connect(connection_config, config, environment).await?);
        Ok(Self { publisher, events })
    }

    /// Returns the verified durable outbox publisher.
    #[must_use]
    pub const fn publisher(&self) -> &NatsOutboxPublisher {
        &self.publisher
    }

    /// Returns the verified durable consumer runtime.
    #[must_use]
    pub const fn events(&self) -> &Arc<NatsJetStreamEvents> {
        &self.events
    }

    /// Builds the required consumer task for an application-owned event handler.
    #[must_use]
    pub fn consumer_task(&self, handler: Arc<dyn EventHandler>) -> TaskSpec {
        Arc::clone(&self.events).task_spec(handler)
    }

    /// Builds the required resource task that drains the durable publication connection after
    /// transport delivery has stopped.
    #[must_use]
    pub fn publisher_drain_task(&self) -> TaskSpec {
        let publisher = self.publisher.clone();
        TaskSpec::new(
            PUBLISHER_DRAIN_TASK_NAME,
            MODULE_NAME,
            Criticality::Required,
            self.events.config.delivery.shutdown_timeout,
            move |context| {
                let publisher = publisher.clone();
                async move {
                    tokio::select! {
                        () = context.draining() => {}
                        () = context.shutdown_requested() => {}
                        () = context.cancelled() => return Ok(()),
                    }
                    publisher.drain().await.map_err(|_| service_error())
                }
            },
        )
    }
    /// Builds the required fresh-resource health check.
    #[must_use]
    pub fn health_check(&self) -> HealthCheckSpec {
        self.events.health_check()
    }

    /// Fetches fresh durable consumer state.
    ///
    /// # Errors
    ///
    /// Returns a safe access error when the broker cannot provide current state.
    pub async fn status(&self) -> Result<ConsumerStatus, NatsEventsError> {
        self.events.status().await
    }

    /// Flushes and drains both durable consumer and publication resource connections.
    ///
    /// # Errors
    ///
    /// Returns a safe bounded-shutdown failure.
    pub async fn drain(&self) -> Result<(), NatsEventsError> {
        self.events.drain().await?;
        self.publisher.drain().await
    }
}

async fn decode_delivery(
    context: &jetstream::Context,
    config: &NatsEventsConfig,
    message: &Message,
) -> Result<(RawEvent, u64, u32), DeliveryResult> {
    let Ok(info) = message.info() else {
        return Err(dead_letter_invalid(context, config, message, 0, 0).await);
    };
    let stream_sequence = info.stream_sequence;
    let delivered = u32::try_from(info.delivered).unwrap_or(u32::MAX);
    if delivered == 0 {
        return Err(
            dead_letter_invalid(context, config, message, stream_sequence, delivered).await,
        );
    }
    let Ok(event) = RawEvent::decode(message.payload.clone(), config.stream.max_message_size)
    else {
        return Err(
            dead_letter_invalid(context, config, message, stream_sequence, delivered).await,
        );
    };
    Ok((event, stream_sequence, delivered))
}

#[derive(Clone, Copy)]
enum DeliveryResult {
    Success,
    Retry,
    DeadLettered,
    DeadLetterFailed,
    AckFailed,
    TimedOut,
    Cancelled,
}

impl DeliveryResult {
    const fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retry => "retry",
            Self::DeadLettered => "dead_lettered",
            Self::DeadLetterFailed => "dead_letter_failed",
            Self::AckFailed => "ack_failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }
}

fn record_delivery(result: DeliveryResult) {
    counter!("omnius_events_nats_delivery_total", "status" => result.label()).increment(1);
}

enum Invocation {
    Outcome(HandlerOutcome),
    MaxDeliveries,
    TimedOut,
    Cancelled,
    Panicked,
}

async fn invoke_handler(
    handler: Arc<dyn EventHandler>,
    event: RawEvent,
    delivery_count: u32,
    timeout: Duration,
    task_context: TaskContext,
) -> Invocation {
    let cancellation = CancellationToken::new();
    let handler_context = DeliveryContext {
        delivery_count,
        redelivered: delivery_count > 1,
        cancellation: cancellation.clone(),
    };
    let future = with_redacted_handler_panic(|| {
        panic::catch_unwind(AssertUnwindSafe(|| handler.handle(event, handler_context)))
    });
    let Ok(mut future) = future else {
        return Invocation::Panicked;
    };
    let mut outcome = {
        let guarded = poll_fn(|context| {
            with_redacted_handler_panic(|| {
                match panic::catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(context))) {
                    Ok(Poll::Ready(outcome)) => Poll::Ready(Invocation::Outcome(outcome)),
                    Ok(Poll::Pending) => Poll::Pending,
                    Err(_) => Poll::Ready(Invocation::Panicked),
                }
            })
        });
        tokio::pin!(guarded);
        tokio::select! {
            biased;
            () = task_context.shutdown_requested() => {
                cancellation.cancel();
                Invocation::Cancelled
            }
            () = task_context.cancelled() => {
                cancellation.cancel();
                Invocation::Cancelled
            }
            () = time::sleep(timeout) => {
                cancellation.cancel();
                Invocation::TimedOut
            }
            outcome = &mut guarded => outcome,
        }
    };
    let dropped =
        with_redacted_handler_panic(|| panic::catch_unwind(AssertUnwindSafe(|| drop(future))));
    if dropped.is_err() {
        outcome = Invocation::Panicked;
    }
    outcome
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum DeadLetterReason {
    Permanent,
    MaxDeliveries,
    InvalidEvent,
}

#[derive(Serialize)]
struct DeadLetterRecord<'event> {
    event: &'event serde_json::value::RawValue,
    delivery: DeadLetterMetadata<'event>,
}

#[derive(Serialize)]
struct DeadLetterMetadata<'event> {
    event_id: omnius_jobs_core::EventId,
    event_version: Version,
    stream_sequence: u64,
    delivery_count: u32,
    reason: DeadLetterReason,
    failure_code: Option<&'event str>,
}

#[derive(Serialize)]
struct InvalidDeadLetterRecord {
    invalid_event: QuarantinedPayload,
    delivery: InvalidDeadLetterMetadata,
}

#[derive(Serialize)]
struct QuarantinedPayload {
    encoding: &'static str,
    bytes: String,
    original_bytes: usize,
    captured_bytes: usize,
    truncated: bool,
}

#[derive(Serialize)]
struct InvalidDeadLetterMetadata {
    stream_sequence: u64,
    delivery_count: u32,
    reason: DeadLetterReason,
}

#[expect(
    clippy::too_many_arguments,
    reason = "dead-letter durability requires every source fence and declared resource explicitly"
)]
async fn dead_letter(
    context: &jetstream::Context,
    config: &NatsEventsConfig,
    message: &Message,
    event: &RawEvent,
    stream_sequence: u64,
    delivery_count: u32,
    reason: DeadLetterReason,
    failure_code: Option<&FailureCode>,
) -> DeliveryResult {
    let Ok(raw) = event.raw_json() else {
        return dlq_failed();
    };
    let record = DeadLetterRecord {
        event: raw,
        delivery: DeadLetterMetadata {
            event_id: event.id(),
            event_version: event.version(),
            stream_sequence,
            delivery_count,
            reason,
            failure_code: failure_code.map(FailureCode::as_str),
        },
    };
    let Ok(bytes) = encode_bounded(&record, config.dlq.stream.max_message_size) else {
        return dlq_failed();
    };
    publish_dead_letter(
        context,
        config,
        message,
        bytes,
        Some(format!("dlq:{}", event.id())),
    )
    .await
}

async fn dead_letter_invalid(
    context: &jetstream::Context,
    config: &NatsEventsConfig,
    message: &Message,
    stream_sequence: u64,
    delivery_count: u32,
) -> DeliveryResult {
    let captured_bytes =
        invalid_capture_len(message.payload.len(), config.dlq.stream.max_message_size);
    let record = InvalidDeadLetterRecord {
        invalid_event: QuarantinedPayload {
            encoding: "hex",
            bytes: encode_hex(&message.payload[..captured_bytes]),
            original_bytes: message.payload.len(),
            captured_bytes,
            truncated: captured_bytes < message.payload.len(),
        },
        delivery: InvalidDeadLetterMetadata {
            stream_sequence,
            delivery_count,
            reason: DeadLetterReason::InvalidEvent,
        },
    };
    let Ok(bytes) = encode_bounded(&record, config.dlq.stream.max_message_size) else {
        return dlq_failed();
    };
    publish_dead_letter(
        context,
        config,
        message,
        bytes,
        (stream_sequence != 0).then(|| format!("dlq-invalid:{stream_sequence}")),
    )
    .await
}

async fn publish_dead_letter(
    context: &jetstream::Context,
    config: &NatsEventsConfig,
    message: &Message,
    bytes: Vec<u8>,
    dedupe_id: Option<String>,
) -> DeliveryResult {
    let mut publish = PublishMessage::build().payload(bytes.into());
    if let Some(dedupe_id) = dedupe_id {
        publish = publish.message_id(dedupe_id);
    }
    let ack = match context
        .send_publish(config.dlq.subject.clone(), publish)
        .await
    {
        Ok(ack) => match ack.await {
            Ok(ack) => ack,
            Err(_) => return dlq_failed(),
        },
        Err(_) => return dlq_failed(),
    };
    if ack.stream != config.dlq.stream.name {
        return dlq_failed();
    }
    counter!("omnius_events_nats_dlq_total", "status" => "published").increment(1);
    match message.double_ack_with(AckKind::Ack).await {
        Ok(()) => DeliveryResult::DeadLettered,
        Err(_) => DeliveryResult::AckFailed,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn invalid_capture_len(original_bytes: usize, dlq_max_message_size: usize) -> usize {
    original_bytes
        .min(MAX_INVALID_DLQ_CAPTURE_BYTES)
        .min(dlq_max_message_size.saturating_sub(INVALID_DLQ_METADATA_BYTES) / 2)
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

fn metric_count(value: u64) -> f64 {
    u32::try_from(value).unwrap_or(u32::MAX).into()
}

fn metric_count_usize(value: usize) -> f64 {
    u32::try_from(value).unwrap_or(u32::MAX).into()
}

fn dlq_failed() -> DeliveryResult {
    counter!("omnius_events_nats_dlq_total", "status" => "failed").increment(1);
    DeliveryResult::DeadLetterFailed
}

fn static_failure_code(value: &'static str) -> FailureCode {
    let Ok(code) = FailureCode::try_from(value) else {
        unreachable!("static NATS handler failure code must be valid")
    };
    code
}

fn service_error() -> ServiceError {
    ServiceError::new(service_error_code(), "durable event delivery unavailable")
}

fn service_error_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(SERVICE_ERROR_CODE) else {
        unreachable!("static NATS service error code must be valid")
    };
    code
}

fn health_error_code() -> ErrorCode {
    let Ok(code) = ErrorCode::try_new(HEALTH_ERROR_CODE) else {
        unreachable!("static NATS health error code must be valid")
    };
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_payload_hex_encoding_accepts_arbitrary_bytes() {
        assert_eq!(encode_hex(&[0x00, 0x7f, 0xff]), "007fff");
    }

    #[test]
    fn invalid_payload_capture_has_a_strict_absolute_bound() {
        assert_eq!(
            invalid_capture_len(usize::MAX, usize::MAX),
            MAX_INVALID_DLQ_CAPTURE_BYTES
        );
    }

    #[test]
    fn invalid_payload_capture_reserves_dlq_metadata_space() {
        let captured = invalid_capture_len(usize::MAX, 1_024);

        assert!(captured * 2 + INVALID_DLQ_METADATA_BYTES <= 1_024);
    }
}
