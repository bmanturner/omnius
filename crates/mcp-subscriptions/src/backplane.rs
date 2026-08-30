use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use omnius_events_nats::{
    NatsCoreFanoutIngress, NatsCoreFanoutLifecycle, NatsCoreFanoutPublishError,
    NatsCoreFanoutPublisher, NatsCoreFanoutReceiver, NatsCoreFanoutStatus,
};
use omnius_events_redis_ephemeral::{
    PublishError as RedisPublishError, RedisEphemeralIngress, RedisEphemeralListenerState,
    RedisEphemeralListenerStatus, RedisEphemeralPublisher, RedisEphemeralReceiver,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;

use crate::{
    BackplaneError, BackplaneGuarantee, BackplaneHint, BackplaneKind, BackplaneReceiver,
    BackplaneRecord, BackplaneRegistration, EventPosition, TaskId, TaskSubscriptionBackplane,
    TenantId,
};

const WIRE_VERSION: u8 = 1;
const MAX_WIRE_RECORD_BYTES: usize = 16 * 1024;
const MAX_LOCAL_CAPACITY: usize = 65_536;
const MAX_REDIS_CHANNEL_BYTES: usize = 64;

/// Finite task-hint wire policy shared by ephemeral provider adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackplaneWireLimits {
    /// Maximum encoded task-hint record accepted or published by this adapter.
    pub max_record_bytes: usize,
}

impl Default for BackplaneWireLimits {
    fn default() -> Self {
        Self {
            max_record_bytes: 4 * 1024,
        }
    }
}

impl BackplaneWireLimits {
    fn validate(self) -> Result<Self, BackplaneAdapterError> {
        if !(1..=MAX_WIRE_RECORD_BYTES).contains(&self.max_record_bytes) {
            return Err(BackplaneAdapterError::InvalidConfiguration);
        }
        Ok(self)
    }
}

/// Safe provider-adapter construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BackplaneAdapterError {
    /// Wire size or logical-channel policy was invalid.
    #[error("task subscription backplane adapter configuration is invalid")]
    InvalidConfiguration,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireHintRef<'a> {
    version: u8,
    tenant_id: &'a str,
    task_id: &'a str,
    sequence: u64,
    revision: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct WireHint {
    version: u8,
    tenant_id: String,
    task_id: String,
    sequence: u64,
    revision: u64,
}

fn encode_hint(
    hint: &BackplaneHint,
    limits: BackplaneWireLimits,
) -> Result<Vec<u8>, BackplaneError> {
    let encoded = serde_json::to_vec(&WireHintRef {
        version: WIRE_VERSION,
        tenant_id: hint.tenant_id.as_str(),
        task_id: hint.task_id.as_str(),
        sequence: hint.observed_position.sequence(),
        revision: hint.observed_position.revision(),
    })
    .map_err(|_| BackplaneError::InvalidRecord)?;
    if encoded.len() > limits.max_record_bytes {
        return Err(BackplaneError::Overflow);
    }
    Ok(encoded)
}

fn decode_hint(
    payload: &[u8],
    limits: BackplaneWireLimits,
) -> Result<BackplaneHint, BackplaneError> {
    if payload.len() > limits.max_record_bytes {
        return Err(BackplaneError::Overflow);
    }
    let wire: WireHint =
        serde_json::from_slice(payload).map_err(|_| BackplaneError::InvalidRecord)?;
    if wire.version != WIRE_VERSION {
        return Err(BackplaneError::InvalidRecord);
    }
    Ok(BackplaneHint {
        tenant_id: TenantId::new(wire.tenant_id).map_err(|_| BackplaneError::InvalidRecord)?,
        task_id: TaskId::new(wire.task_id).map_err(|_| BackplaneError::InvalidRecord)?,
        observed_position: EventPosition::new(wire.sequence, wire.revision)
            .map_err(|_| BackplaneError::InvalidRecord)?,
    })
}

fn reconciliation_record(payload: &[u8], limits: BackplaneWireLimits) -> BackplaneRecord {
    decode_hint(payload, limits).map_or(BackplaneRecord::IngressGap, BackplaneRecord::TaskChanged)
}

fn portable_redis_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel.len() <= MAX_REDIS_CHANNEL_BYTES
        && channel
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

pub(crate) fn decode_redis_record(
    expected_channel: &str,
    actual_channel: &str,
    payload: &[u8],
    limits: BackplaneWireLimits,
) -> Result<BackplaneRecord, BackplaneError> {
    if actual_channel != expected_channel {
        return Err(BackplaneError::InvalidRecord);
    }
    Ok(reconciliation_record(payload, limits))
}

pub(crate) fn decode_nats_record(payload: &[u8], limits: BackplaneWireLimits) -> BackplaneRecord {
    reconciliation_record(payload, limits)
}

/// Bounded, ephemeral, single-process development backplane.
///
/// Construction creates exactly one local receiver. Publication before the supervised receiver is
/// running, receiver lag, process restart, and disconnect are observable loss conditions that
/// reconcile through the authoritative repository.
#[derive(Debug)]
pub struct LocalTaskBackplane {
    sender: broadcast::Sender<BackplaneHint>,
}

impl LocalTaskBackplane {
    /// Creates the application publisher/readiness view and its sole receiver registration.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneAdapterError::InvalidConfiguration`] when `capacity` is zero or exceeds
    /// the bounded local-channel capacity.
    pub fn registration(capacity: usize) -> Result<BackplaneRegistration, BackplaneAdapterError> {
        if !(1..=MAX_LOCAL_CAPACITY).contains(&capacity) {
            return Err(BackplaneAdapterError::InvalidConfiguration);
        }
        let (sender, receiver) = broadcast::channel(capacity);
        Ok(BackplaneRegistration::new(
            Arc::new(Self { sender }),
            Box::new(LocalReceiver { receiver }),
        ))
    }
}

#[derive(Debug)]
struct LocalReceiver {
    receiver: broadcast::Receiver<BackplaneHint>,
}

#[async_trait]
impl BackplaneReceiver for LocalReceiver {
    async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError> {
        match self.receiver.recv().await {
            Ok(hint) => Ok(BackplaneRecord::TaskChanged(hint)),
            Err(broadcast::error::RecvError::Lagged(_)) => Ok(BackplaneRecord::IngressGap),
            Err(broadcast::error::RecvError::Closed) => Err(BackplaneError::Disconnected),
        }
    }
}

#[async_trait]
impl TaskSubscriptionBackplane for LocalTaskBackplane {
    fn kind(&self) -> BackplaneKind {
        BackplaneKind::Local
    }

    fn guarantee(&self) -> BackplaneGuarantee {
        BackplaneGuarantee::Ephemeral
    }

    fn is_ready(&self) -> bool {
        self.sender.receiver_count() == 1
    }

    async fn publish(&self, hint: BackplaneHint) -> Result<(), BackplaneError> {
        self.sender
            .send(hint)
            .map(|_| ())
            .map_err(|_| BackplaneError::NotReady)
    }
}

/// Ephemeral Redis Pub/Sub task-hint adapter.
///
/// The provider listener `TaskSpec` is deliberately not accepted or returned here. Composition
/// keeps it when splitting [`omnius_events_redis_ephemeral::RedisEphemeralEvents::into_parts`].
pub struct RedisTaskBackplane {
    publisher: RedisEphemeralPublisher,
    readiness: RedisEphemeralListenerStatus,
    logical_channel: Arc<str>,
    limits: BackplaneWireLimits,
}

impl std::fmt::Debug for RedisTaskBackplane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RedisTaskBackplane")
            .field("ready", &self.readiness.is_ready())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl RedisTaskBackplane {
    /// Builds an adapter from the public publisher, sole receiver, and readiness parts.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneAdapterError::InvalidConfiguration`] when the wire-record limit is
    /// outside its supported range or the logical Redis channel is empty, too long, or contains
    /// non-portable characters.
    pub fn registration_from_parts(
        publisher: RedisEphemeralPublisher,
        receiver: RedisEphemeralReceiver,
        readiness: RedisEphemeralListenerStatus,
        logical_channel: impl Into<String>,
        limits: BackplaneWireLimits,
    ) -> Result<BackplaneRegistration, BackplaneAdapterError> {
        let limits = limits.validate()?;
        let logical_channel = logical_channel.into();
        if !portable_redis_channel(&logical_channel) {
            return Err(BackplaneAdapterError::InvalidConfiguration);
        }
        let logical_channel: Arc<str> = logical_channel.into();
        Ok(BackplaneRegistration::new(
            Arc::new(Self {
                publisher,
                readiness: readiness.clone(),
                logical_channel: Arc::clone(&logical_channel),
                limits,
            }),
            Box::new(RedisReceiver {
                receiver,
                readiness,
                logical_channel,
                limits,
            }),
        ))
    }
}

#[async_trait]
impl TaskSubscriptionBackplane for RedisTaskBackplane {
    fn kind(&self) -> BackplaneKind {
        BackplaneKind::Redis
    }

    fn guarantee(&self) -> BackplaneGuarantee {
        BackplaneGuarantee::Ephemeral
    }

    fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }

    async fn publish(&self, hint: BackplaneHint) -> Result<(), BackplaneError> {
        if !self.is_ready() {
            return Err(BackplaneError::NotReady);
        }
        let encoded = encode_hint(&hint, self.limits)?;
        self.publisher
            .publish(&self.logical_channel, &encoded)
            .await
            .map(|_| ())
            .map_err(|error| match error {
                RedisPublishError::UnknownChannel => BackplaneError::InvalidRecord,
                RedisPublishError::MessageTooLarge => BackplaneError::Overflow,
                RedisPublishError::Unavailable => BackplaneError::Disconnected,
            })
    }
}

struct RedisReceiver {
    receiver: RedisEphemeralReceiver,
    readiness: RedisEphemeralListenerStatus,
    logical_channel: Arc<str>,
    limits: BackplaneWireLimits,
}

pub(crate) fn redis_ingress_record(
    ingress: RedisEphemeralIngress,
    logical_channel: &str,
    limits: BackplaneWireLimits,
) -> Result<BackplaneRecord, BackplaneError> {
    match ingress {
        RedisEphemeralIngress::Message(message) => decode_redis_record(
            logical_channel,
            message.channel(),
            message.payload(),
            limits,
        ),
        RedisEphemeralIngress::IngressGap { .. } => Ok(BackplaneRecord::IngressGap),
    }
}

#[async_trait]
impl BackplaneReceiver for RedisReceiver {
    async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError> {
        loop {
            tokio::select! {
                ingress = self.receiver.recv_ingress() => {
                    return redis_ingress_record(
                        ingress.ok_or(BackplaneError::Disconnected)?,
                        &self.logical_channel,
                        self.limits,
                    );
                }
                state = self.readiness.changed() => {
                    match state {
                        Some(RedisEphemeralListenerState::Subscribed) => {
                            return Ok(BackplaneRecord::IngressGap);
                        }
                        Some(
                            RedisEphemeralListenerState::Connecting
                            | RedisEphemeralListenerState::Disconnected,
                        ) => {}
                        Some(RedisEphemeralListenerState::Stopped) | None => {
                            return Err(BackplaneError::Disconnected);
                        }
                    }
                }
            }
        }
    }
}

/// Ephemeral NATS Core task-hint adapter.
///
/// This adapter accepts no `JetStream` type and cannot advertise durable delivery. Composition
/// keeps the listener `TaskSpec` returned by [`omnius_events_nats::NatsCoreFanout::into_parts`].
pub struct NatsCoreTaskBackplane {
    publisher: NatsCoreFanoutPublisher,
    readiness: NatsCoreFanoutStatus,
    limits: BackplaneWireLimits,
}

impl std::fmt::Debug for NatsCoreTaskBackplane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NatsCoreTaskBackplane")
            .field("ready", &self.readiness.is_ready())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl NatsCoreTaskBackplane {
    /// Builds an adapter from the public Core NATS publisher, sole receiver, and readiness parts.
    ///
    /// # Errors
    ///
    /// Returns [`BackplaneAdapterError::InvalidConfiguration`] when the wire-record limit is
    /// outside its supported range.
    pub fn registration_from_parts(
        publisher: NatsCoreFanoutPublisher,
        receiver: NatsCoreFanoutReceiver,
        readiness: NatsCoreFanoutStatus,
        limits: BackplaneWireLimits,
    ) -> Result<BackplaneRegistration, BackplaneAdapterError> {
        let limits = limits.validate()?;
        Ok(BackplaneRegistration::new(
            Arc::new(Self {
                publisher,
                readiness: readiness.clone(),
                limits,
            }),
            Box::new(NatsReceiver {
                receiver,
                readiness,
                limits,
            }),
        ))
    }
}

#[async_trait]
impl TaskSubscriptionBackplane for NatsCoreTaskBackplane {
    fn kind(&self) -> BackplaneKind {
        BackplaneKind::NatsCore
    }

    fn guarantee(&self) -> BackplaneGuarantee {
        BackplaneGuarantee::Ephemeral
    }

    fn is_ready(&self) -> bool {
        self.readiness.is_ready()
    }

    async fn publish(&self, hint: BackplaneHint) -> Result<(), BackplaneError> {
        if !self.is_ready() {
            return Err(BackplaneError::NotReady);
        }
        let encoded = encode_hint(&hint, self.limits)?;
        self.publisher
            .publish(Bytes::from(encoded))
            .await
            .map_err(|error| match error {
                NatsCoreFanoutPublishError::MessageTooLarge => BackplaneError::Overflow,
                NatsCoreFanoutPublishError::Unavailable => BackplaneError::Disconnected,
            })
    }
}

struct NatsReceiver {
    receiver: NatsCoreFanoutReceiver,
    readiness: NatsCoreFanoutStatus,
    limits: BackplaneWireLimits,
}

pub(crate) fn nats_ingress_record(
    ingress: NatsCoreFanoutIngress,
    limits: BackplaneWireLimits,
) -> BackplaneRecord {
    match ingress {
        NatsCoreFanoutIngress::Message(message) => decode_nats_record(message.payload(), limits),
        NatsCoreFanoutIngress::IngressGap { .. } => BackplaneRecord::IngressGap,
    }
}

#[async_trait]
impl BackplaneReceiver for NatsReceiver {
    async fn receive(&mut self) -> Result<BackplaneRecord, BackplaneError> {
        loop {
            tokio::select! {
                ingress = self.receiver.recv_ingress() => {
                    return Ok(nats_ingress_record(
                        ingress.ok_or(BackplaneError::Disconnected)?,
                        self.limits,
                    ));
                }
                state = self.readiness.changed() => {
                    match state {
                        Ok(NatsCoreFanoutLifecycle::Ready) => {
                            return Ok(BackplaneRecord::IngressGap);
                        }
                        Ok(
                            NatsCoreFanoutLifecycle::Pending
                            | NatsCoreFanoutLifecycle::Connecting
                            | NatsCoreFanoutLifecycle::Degraded,
                        ) => {}
                        Ok(NatsCoreFanoutLifecycle::Stopped) | Err(_) => {
                            return Err(BackplaneError::Disconnected);
                        }
                    }
                }
            }
        }
    }
}
