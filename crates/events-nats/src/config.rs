use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
    time::Duration,
};

use omnius_config::{DeploymentEnvironment, ExposeSecret as _, SecretString};
use omnius_jobs_core::Destination;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

const MAX_URL_BYTES: usize = 2_048;
const MAX_AUTH_BYTES: usize = 1_024;
const MAX_PATHS: usize = 16;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_STREAM_NAME_BYTES: usize = 128;
const MAX_SUBJECTS: usize = 64;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_ROUTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
const MAX_MESSAGES: u64 = 1_000_000_000;
const MAX_AGE: Duration = Duration::from_hours(8_784);
const MAX_DUPLICATE_WINDOW: Duration = Duration::from_hours(24);
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_ACK_WAIT: Duration = Duration::from_hours(1);
const MAX_DELIVERIES: u32 = 1_000;
const MAX_ACK_PENDING: usize = 65_536;
const MAX_RESTARTS: u32 = 32;
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const MAX_JITTER_PERCENT: u8 = 50;
const DLQ_METADATA_ALLOWANCE: usize = 1_024;
const MAX_FANOUT_INGRESS_CAPACITY: usize = 65_536;
const MAX_FANOUT_RETAINED_BYTES: usize = 64 * 1024 * 1024;

/// Authentication material used for a NATS connection.
#[derive(Clone, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case", deny_unknown_fields)]
pub enum NatsAuthConfig {
    /// A NATS JWT/NKey `.creds` file loaded by the SDK.
    CredentialsFile {
        /// Path to the credentials file.
        path: PathBuf,
    },
    /// Development and test-only username/password authentication.
    UserPassword {
        /// NATS username, retained in redacted memory.
        username: SecretString,
        /// NATS password, retained in redacted memory.
        password: SecretString,
    },
}

impl fmt::Debug for NatsAuthConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CredentialsFile { .. } => formatter
                .debug_struct("CredentialsFile")
                .field("path", &"[REDACTED]")
                .finish(),
            Self::UserPassword { .. } => formatter
                .debug_struct("UserPassword")
                .field("username", &"[REDACTED]")
                .field("password", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Secret-safe NATS connection configuration with bounded SDK queues.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsConnectionConfig {
    /// One NATS server URL without embedded credentials.
    pub url: SecretString,
    /// Explicit authentication approach.
    pub auth: NatsAuthConfig,
    /// Whether the SDK must negotiate TLS.
    pub tls_required: bool,
    /// Additional PEM root-certificate paths.
    pub root_certificates: Vec<PathBuf>,
    /// Full connection and handshake deadline.
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    /// Provider request, flush, and acknowledgement deadline.
    #[serde(with = "humantime_serde")]
    pub operation_timeout: Duration,
    /// Bounded SDK command queue.
    pub client_capacity: usize,
    /// Bounded SDK subscription queue used by Core NATS, pull batches, and request inboxes.
    pub subscription_capacity: usize,
    /// Consecutive reconnect attempts before the connection closes.
    pub max_reconnects: usize,
}

impl fmt::Debug for NatsConnectionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsConnectionConfig")
            .field("url", &"[REDACTED]")
            .field("auth", &self.auth)
            .field("tls_required", &self.tls_required)
            .field("root_certificate_count", &self.root_certificates.len())
            .field("connection_timeout", &self.connection_timeout)
            .field("operation_timeout", &self.operation_timeout)
            .field("client_capacity", &self.client_capacity)
            .field("subscription_capacity", &self.subscription_capacity)
            .field("max_reconnects", &self.max_reconnects)
            .finish()
    }
}

impl NatsConnectionConfig {
    /// Creates a test/development connection using explicit credentials.
    #[must_use]
    pub fn new(url: SecretString, auth: NatsAuthConfig) -> Self {
        Self {
            url,
            auth,
            tls_required: true,
            root_certificates: Vec::new(),
            connection_timeout: Duration::from_secs(5),
            operation_timeout: Duration::from_secs(5),
            client_capacity: 1_024,
            subscription_capacity: 1_024,
            max_reconnects: 16,
        }
    }

    /// Validates all secret-independent bounds and the deployment transport policy.
    ///
    /// # Errors
    ///
    /// Returns a value-free error for malformed, embedded-secret, unbounded, or production-unsafe
    /// configuration.
    pub fn validate_for(&self, environment: DeploymentEnvironment) -> Result<(), NatsConfigError> {
        let raw_url = self.url.expose_secret();
        if raw_url.is_empty() || raw_url.len() > MAX_URL_BYTES {
            return Err(NatsConfigError::InvalidConnection);
        }
        let parsed = Url::parse(raw_url).map_err(|_| NatsConfigError::InvalidConnection)?;
        if !matches!(parsed.scheme(), "nats" | "tls")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(NatsConfigError::InvalidConnection);
        }
        match &self.auth {
            NatsAuthConfig::CredentialsFile { path } => {
                if !valid_path(path) {
                    return Err(NatsConfigError::InvalidAuthentication);
                }
            }
            NatsAuthConfig::UserPassword { username, password } => {
                if environment == DeploymentEnvironment::Production {
                    return Err(NatsConfigError::ProductionCredentialsRequired);
                }
                if !valid_auth_value(username) || !valid_auth_value(password) {
                    return Err(NatsConfigError::InvalidAuthentication);
                }
            }
        }
        if environment == DeploymentEnvironment::Production && !self.tls_required {
            return Err(NatsConfigError::ProductionTlsRequired);
        }
        if self.root_certificates.len() > MAX_PATHS
            || self.root_certificates.iter().any(|path| !valid_path(path))
        {
            return Err(NatsConfigError::InvalidCertificatePath);
        }
        if !bounded_duration(self.connection_timeout, MAX_TIMEOUT)
            || !bounded_duration(self.operation_timeout, MAX_TIMEOUT)
            || !(1..=65_536).contains(&self.client_capacity)
            || !(1..=65_536).contains(&self.subscription_capacity)
            || !(1..=1_000).contains(&self.max_reconnects)
        {
            return Err(NatsConfigError::InvalidConnectionBounds);
        }
        Ok(())
    }
}

/// `JetStream` message retention policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NatsRetentionPolicy {
    /// Retain until a declared stream limit is reached.
    Limits,
    /// Retain while at least one consumer has interest.
    Interest,
}

/// `JetStream` storage backend.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NatsStorage {
    /// Durable file storage.
    File,
    /// Volatile memory storage, allowed outside production only.
    Memory,
}

/// Behavior when a declared stream limit is reached.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum NatsDiscardPolicy {
    /// Remove the oldest retained message.
    Old,
    /// Reject the new message.
    New,
}

/// Complete bounded configuration for one `JetStream` stream.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsStreamConfig {
    /// Stable `JetStream` stream name.
    pub name: String,
    /// Bounded NATS subject set captured by this stream.
    pub subjects: Vec<String>,
    /// Retention semantics.
    pub retention: NatsRetentionPolicy,
    /// Storage backend.
    pub storage: NatsStorage,
    /// Limit overflow behavior.
    pub discard: NatsDiscardPolicy,
    /// Replication factor.
    pub replicas: usize,
    /// Maximum retained age.
    #[serde(with = "humantime_serde")]
    pub max_age: Duration,
    /// Maximum retained bytes.
    pub max_bytes: u64,
    /// Maximum retained messages.
    pub max_messages: u64,
    /// Maximum accepted message bytes.
    pub max_message_size: usize,
    /// Maximum consumers on the stream.
    pub max_consumers: u32,
    /// Server message-ID duplicate tracking window.
    #[serde(with = "humantime_serde")]
    pub duplicate_window: Duration,
}

impl fmt::Debug for NatsStreamConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsStreamConfig")
            .field("name", &"[REDACTED]")
            .field("subject_count", &self.subjects.len())
            .field("retention", &self.retention)
            .field("storage", &self.storage)
            .field("discard", &self.discard)
            .field("replicas", &self.replicas)
            .field("max_age", &self.max_age)
            .field("max_bytes", &self.max_bytes)
            .field("max_messages", &self.max_messages)
            .field("max_message_size", &self.max_message_size)
            .field("max_consumers", &self.max_consumers)
            .field("duplicate_window", &self.duplicate_window)
            .finish()
    }
}

/// Durable pull-consumer configuration.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsConsumerConfig {
    /// Stable durable consumer name.
    pub durable_name: String,
    /// Subject filters within the main stream.
    pub filter_subjects: Vec<String>,
    /// Unacknowledged delivery window.
    #[serde(with = "humantime_serde")]
    pub ack_wait: Duration,
    /// Maximum source deliveries before the provider routes to the DLQ.
    pub max_deliveries: u32,
    /// Maximum server-side unacknowledged deliveries.
    pub max_ack_pending: usize,
}

impl fmt::Debug for NatsConsumerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsConsumerConfig")
            .field("durable_name", &"[REDACTED]")
            .field("filter_count", &self.filter_subjects.len())
            .field("ack_wait", &self.ack_wait)
            .field("max_deliveries", &self.max_deliveries)
            .field("max_ack_pending", &self.max_ack_pending)
            .finish()
    }
}

/// Bounded pull and handler lifecycle policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsDeliveryConfig {
    /// Maximum messages in one server pull request.
    pub pull_batch: usize,
    /// Maximum bytes in one server pull request.
    pub pull_max_bytes: usize,
    /// Maximum concurrent handlers.
    pub concurrency: usize,
    /// Server pull expiry.
    #[serde(with = "humantime_serde")]
    pub pull_expiry: Duration,
    /// Per-handler deadline.
    #[serde(with = "humantime_serde")]
    pub handler_timeout: Duration,
    /// Delay attached to retryable NAKs.
    #[serde(with = "humantime_serde")]
    pub retry_nak_delay: Duration,
    /// Supervisor shutdown deadline.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
}

/// DLQ stream and one exact publish subject.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsDlqConfig {
    /// Dedicated DLQ stream declaration.
    pub stream: NatsStreamConfig,
    /// Exact subject used for DLQ records.
    pub subject: String,
}

impl fmt::Debug for NatsDlqConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsDlqConfig")
            .field("stream", &self.stream)
            .field("subject", &"[REDACTED]")
            .finish()
    }
}

/// Bounded supervisor restart policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsRestartConfig {
    /// Maximum restarts after the initial attempt.
    pub max_restarts: u32,
    /// Initial exponential backoff.
    #[serde(with = "humantime_serde")]
    pub initial_backoff: Duration,
    /// Maximum exponential backoff.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
    /// Symmetric jitter percentage.
    pub jitter_percent: u8,
}

/// Static bounded policy for ephemeral Core NATS fan-out.
///
/// The exact subject is shared by publication and the one subscription owned by each application
/// instance. This policy never creates a stream, durable consumer, cursor, or replay resource.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NatsCoreFanoutConfig {
    /// Exact subject permitted for both `PUBLISH` and `SUBSCRIBE`.
    pub subject: String,
    /// Maximum messages retained in the provider-owned local ingress.
    pub ingress_capacity: usize,
    /// Maximum opaque message size accepted for publication and local delivery.
    pub max_message_bytes: usize,
    /// Supervisor deadline for stopping the listener task.
    #[serde(with = "humantime_serde")]
    pub shutdown_timeout: Duration,
    /// Bounded restart-on-failure policy for the degraded listener.
    pub restart: NatsRestartConfig,
}

impl fmt::Debug for NatsCoreFanoutConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsCoreFanoutConfig")
            .field("subject", &"[REDACTED]")
            .field("ingress_capacity", &self.ingress_capacity)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("shutdown_timeout", &self.shutdown_timeout)
            .field("restart", &self.restart)
            .finish()
    }
}

impl NatsCoreFanoutConfig {
    /// Creates a bounded ephemeral policy for one exact subject.
    #[must_use]
    pub fn new(subject: String) -> Self {
        Self {
            subject,
            ingress_capacity: 64,
            max_message_bytes: 256 * 1024,
            shutdown_timeout: Duration::from_secs(3),
            restart: NatsRestartConfig {
                max_restarts: 8,
                initial_backoff: Duration::from_millis(100),
                max_backoff: Duration::from_secs(5),
                jitter_percent: 20,
            },
        }
    }

    /// Validates the exact subject and every local memory, shutdown, and restart bound.
    ///
    /// # Errors
    ///
    /// Returns a value-free error before allocating the configured ingress queue or using NATS.
    pub fn validate(&self) -> Result<(), NatsCoreFanoutConfigError> {
        if !exact_subject(&self.subject) {
            return Err(NatsCoreFanoutConfigError::InvalidSubject);
        }
        if !(1..=MAX_FANOUT_INGRESS_CAPACITY).contains(&self.ingress_capacity)
            || !(1..=MAX_MESSAGE_BYTES).contains(&self.max_message_bytes)
        {
            return Err(NatsCoreFanoutConfigError::InvalidIngressBounds);
        }
        let retained_bytes = self
            .ingress_capacity
            .checked_mul(self.max_message_bytes)
            .ok_or(NatsCoreFanoutConfigError::InvalidIngressBounds)?;
        if retained_bytes > MAX_FANOUT_RETAINED_BYTES
            || !bounded_duration(self.shutdown_timeout, MAX_TIMEOUT)
        {
            return Err(NatsCoreFanoutConfigError::InvalidIngressBounds);
        }
        if self.restart.max_restarts == 0
            || self.restart.max_restarts > MAX_RESTARTS
            || !bounded_duration(self.restart.initial_backoff, MAX_BACKOFF)
            || self.restart.initial_backoff > self.restart.max_backoff
            || self.restart.max_backoff > MAX_BACKOFF
            || self.restart.jitter_percent > MAX_JITTER_PERCENT
        {
            return Err(NatsCoreFanoutConfigError::InvalidRestart);
        }
        Ok(())
    }
}

/// Safe, value-free Core NATS fan-out configuration rejection.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsCoreFanoutConfigError {
    /// The publish/subscribe subject was not one exact portable NATS subject.
    #[error("Core NATS fan-out subject configuration is invalid")]
    InvalidSubject,
    /// A message, local ingress, retained-byte, or shutdown bound was invalid.
    #[error("Core NATS fan-out ingress configuration is invalid")]
    InvalidIngressBounds,
    /// Restart count, delay, or jitter was outside the fixed provider bound.
    #[error("Core NATS fan-out restart configuration is invalid")]
    InvalidRestart,
}

/// Full declarative durable-events policy.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NatsEventsConfig {
    /// Main durable event stream.
    pub stream: NatsStreamConfig,
    /// Static outbox destination to exact NATS publish-subject mapping.
    pub routes: BTreeMap<String, String>,
    /// Durable pull consumer.
    pub consumer: NatsConsumerConfig,
    /// Bounded delivery lifecycle.
    pub delivery: NatsDeliveryConfig,
    /// Dedicated DLQ policy.
    pub dlq: NatsDlqConfig,
    /// Bounded supervisor restart policy.
    pub restart: NatsRestartConfig,
    /// Maximum permitted gap between successful pull/processing heartbeats.
    #[serde(with = "humantime_serde")]
    pub heartbeat_stale_after: Duration,
    /// Point health-check deadline.
    #[serde(with = "humantime_serde")]
    pub health_timeout: Duration,
}

impl fmt::Debug for NatsEventsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NatsEventsConfig")
            .field("stream", &self.stream)
            .field("route_count", &self.routes.len())
            .field("consumer", &self.consumer)
            .field("delivery", &self.delivery)
            .field("dlq", &self.dlq)
            .field("restart", &self.restart)
            .field("heartbeat_stale_after", &self.heartbeat_stale_after)
            .field("health_timeout", &self.health_timeout)
            .finish()
    }
}

impl NatsEventsConfig {
    /// Validates every count, byte, name, subject, duration, and combined allocation budget.
    ///
    /// # Errors
    ///
    /// Returns [`NatsConfigError`] before any allocation proportional to configured values or any
    /// network operation occurs.
    pub fn validate_for(&self, environment: DeploymentEnvironment) -> Result<(), NatsConfigError> {
        validate_stream(&self.stream, environment)?;
        validate_stream(&self.dlq.stream, environment)?;
        if self.stream.name == self.dlq.stream.name
            || !exact_subject(&self.dlq.subject)
            || self.dlq.stream.subjects.as_slice() != [self.dlq.subject.as_str()]
        {
            return Err(NatsConfigError::InvalidDlq);
        }
        let required_dlq_size = self
            .stream
            .max_message_size
            .checked_add(DLQ_METADATA_ALLOWANCE)
            .ok_or(NatsConfigError::InvalidDlq)?;
        if self.dlq.stream.max_message_size < required_dlq_size {
            return Err(NatsConfigError::InvalidDlq);
        }
        if self.routes.is_empty() || self.routes.len() > MAX_ROUTES {
            return Err(NatsConfigError::InvalidRoutes);
        }
        for (destination, subject) in &self.routes {
            Destination::try_from(destination.as_str())
                .map_err(|_| NatsConfigError::InvalidRoutes)?;
            if !exact_subject(subject) || !captured_by_any(subject, &self.stream.subjects) {
                return Err(NatsConfigError::InvalidRoutes);
            }
        }
        validate_consumer(&self.consumer, &self.stream)?;
        validate_delivery(&self.delivery, &self.consumer, &self.stream)?;
        if self.restart.max_restarts == 0
            || self.restart.max_restarts > MAX_RESTARTS
            || !bounded_duration(self.restart.initial_backoff, MAX_BACKOFF)
            || self.restart.initial_backoff > self.restart.max_backoff
            || self.restart.max_backoff > MAX_BACKOFF
            || self.restart.jitter_percent > MAX_JITTER_PERCENT
        {
            return Err(NatsConfigError::InvalidRestart);
        }
        if !bounded_duration(self.heartbeat_stale_after, MAX_ACK_WAIT)
            || self.heartbeat_stale_after < self.delivery.pull_expiry
            || !bounded_duration(self.health_timeout, MAX_TIMEOUT)
        {
            return Err(NatsConfigError::InvalidOperationalBounds);
        }
        Ok(())
    }
}

/// Safe, value-free configuration rejection.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum NatsConfigError {
    /// URL syntax or embedded URL credentials are invalid.
    #[error("NATS connection configuration is invalid")]
    InvalidConnection,
    /// Authentication material is empty, oversized, or malformed.
    #[error("NATS authentication configuration is invalid")]
    InvalidAuthentication,
    /// Production requires a credentials-file authentication approach.
    #[error("production NATS credentials-file authentication is required")]
    ProductionCredentialsRequired,
    /// Production requires TLS negotiation.
    #[error("production NATS TLS is required")]
    ProductionTlsRequired,
    /// A certificate path is invalid.
    #[error("NATS certificate configuration is invalid")]
    InvalidCertificatePath,
    /// A timeout, SDK queue, or reconnect count is unbounded.
    #[error("NATS connection bounds are invalid")]
    InvalidConnectionBounds,
    /// A stream name, subject set, storage policy, or retention limit is invalid.
    #[error("NATS stream configuration is invalid")]
    InvalidStream,
    /// A static outbox route is invalid.
    #[error("NATS route configuration is invalid")]
    InvalidRoutes,
    /// Durable pull-consumer policy is invalid.
    #[error("NATS consumer configuration is invalid")]
    InvalidConsumer,
    /// Pull, handler, retry, or shutdown bounds are invalid.
    #[error("NATS delivery configuration is invalid")]
    InvalidDelivery,
    /// DLQ stream/subject/size policy is invalid.
    #[error("NATS DLQ configuration is invalid")]
    InvalidDlq,
    /// Restart policy is invalid.
    #[error("NATS restart policy is invalid")]
    InvalidRestart,
    /// Heartbeat or health bounds are invalid.
    #[error("NATS operational bounds are invalid")]
    InvalidOperationalBounds,
}

fn validate_stream(
    stream: &NatsStreamConfig,
    environment: DeploymentEnvironment,
) -> Result<(), NatsConfigError> {
    if !valid_name(&stream.name)
        || stream.subjects.is_empty()
        || stream.subjects.len() > MAX_SUBJECTS
        || stream
            .subjects
            .iter()
            .any(|subject| !filter_subject(subject))
        || stream.subjects.iter().collect::<BTreeSet<_>>().len() != stream.subjects.len()
        || stream.retention != NatsRetentionPolicy::Limits
        || (environment == DeploymentEnvironment::Production && stream.storage != NatsStorage::File)
        || !(1..=5).contains(&stream.replicas)
        || !bounded_duration(stream.max_age, MAX_AGE)
        || !(1..=MAX_TOTAL_BYTES).contains(&stream.max_bytes)
        || !(1..=MAX_MESSAGES).contains(&stream.max_messages)
        || !(1..=MAX_MESSAGE_BYTES).contains(&stream.max_message_size)
        || stream.max_consumers == 0
        || stream.max_consumers > 100_000
        || !bounded_duration(stream.duplicate_window, MAX_DUPLICATE_WINDOW)
        || stream.duplicate_window > stream.max_age
    {
        return Err(NatsConfigError::InvalidStream);
    }
    Ok(())
}

fn validate_consumer(
    consumer: &NatsConsumerConfig,
    stream: &NatsStreamConfig,
) -> Result<(), NatsConfigError> {
    if !valid_name(&consumer.durable_name)
        || consumer.filter_subjects.is_empty()
        || consumer.filter_subjects.len() > MAX_SUBJECTS
        || consumer
            .filter_subjects
            .iter()
            .any(|subject| !filter_subject(subject) || !captured_by_any(subject, &stream.subjects))
        || consumer
            .filter_subjects
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != consumer.filter_subjects.len()
        || !bounded_duration(consumer.ack_wait, MAX_ACK_WAIT)
        || !(2..=MAX_DELIVERIES).contains(&consumer.max_deliveries)
        || !(1..=MAX_ACK_PENDING).contains(&consumer.max_ack_pending)
    {
        return Err(NatsConfigError::InvalidConsumer);
    }
    Ok(())
}

fn validate_delivery(
    delivery: &NatsDeliveryConfig,
    consumer: &NatsConsumerConfig,
    stream: &NatsStreamConfig,
) -> Result<(), NatsConfigError> {
    let retained = delivery
        .pull_batch
        .checked_mul(stream.max_message_size)
        .ok_or(NatsConfigError::InvalidDelivery)?;
    if delivery.pull_batch == 0
        || delivery.pull_batch > consumer.max_ack_pending
        || delivery.pull_max_bytes == 0
        || delivery.pull_max_bytes > retained
        || delivery.pull_max_bytes > MAX_MESSAGE_BYTES.saturating_mul(64)
        || delivery.concurrency == 0
        || delivery.concurrency > delivery.pull_batch
        || !bounded_duration(delivery.pull_expiry, MAX_TIMEOUT)
        || !bounded_duration(delivery.handler_timeout, MAX_ACK_WAIT)
        || delivery.handler_timeout >= consumer.ack_wait
        || !bounded_duration(delivery.retry_nak_delay, MAX_ACK_WAIT)
        || delivery.retry_nak_delay >= consumer.ack_wait
        || !bounded_duration(delivery.shutdown_timeout, MAX_ACK_WAIT)
        || delivery.shutdown_timeout < delivery.handler_timeout
    {
        return Err(NatsConfigError::InvalidDelivery);
    }
    Ok(())
}

fn valid_auth_value(value: &SecretString) -> bool {
    let value = value.expose_secret();
    !value.is_empty()
        && value.len() <= MAX_AUTH_BYTES
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_path(path: &std::path::Path) -> bool {
    let Some(value) = path.to_str() else {
        return false;
    };
    !value.is_empty() && value.len() <= MAX_PATH_BYTES && !value.contains('\0')
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_STREAM_NAME_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(crate) fn exact_subject(value: &str) -> bool {
    subject_tokens(value, false)
}

pub(crate) fn filter_subject(value: &str) -> bool {
    subject_tokens(value, true)
}

fn subject_tokens(value: &str, wildcards: bool) -> bool {
    if value.is_empty() || value.len() > MAX_SUBJECT_BYTES || !value.is_ascii() {
        return false;
    }
    let mut tokens = value.split('.').peekable();
    while let Some(token) = tokens.next() {
        if token.is_empty() {
            return false;
        }
        if token == ">" {
            if !wildcards || tokens.peek().is_some() {
                return false;
            }
        } else if token == "*" {
            if !wildcards {
                return false;
            }
        } else if token.bytes().any(|byte| {
            byte.is_ascii_whitespace() || byte.is_ascii_control() || matches!(byte, b'*' | b'>')
        }) {
            return false;
        }
    }
    true
}

pub(crate) fn subject_matches(filter: &str, subject: &str) -> bool {
    let mut filters = filter.split('.');
    let mut subjects = subject.split('.');
    loop {
        match (filters.next(), subjects.next()) {
            (Some(">"), Some(_)) | (None, None) => return true,
            (Some("*"), Some(_)) => {}
            (Some(left), Some(right)) if left == right => {}
            _ => return false,
        }
    }
}

fn captured_by_any(subject: &str, filters: &[String]) -> bool {
    filters.iter().any(|filter| {
        if subject.contains('*') || subject.contains('>') {
            filter_subset_of(subject, filter)
        } else {
            subject_matches(filter, subject)
        }
    })
}

fn filter_subset_of(candidate: &str, capture: &str) -> bool {
    let mut candidates = candidate.split('.');
    let mut captures = capture.split('.');
    loop {
        match (candidates.next(), captures.next()) {
            (Some(_), Some(">")) | (None, None) => return true,
            (Some(">"), Some(_)) => return false,
            (Some(_), Some("*")) => {}
            (Some(left), Some(right)) if left == right => {}
            _ => return false,
        }
    }
}

fn bounded_duration(value: Duration, maximum: Duration) -> bool {
    !value.is_zero() && value <= maximum
}

#[cfg(test)]
mod tests {
    use super::{filter_subset_of, subject_matches};

    #[test]
    fn terminal_wildcard_requires_a_trailing_subject_token() {
        assert!(!subject_matches("orders.>", "orders"));
    }

    #[test]
    fn terminal_wildcard_matches_one_trailing_subject_token() {
        assert!(subject_matches("orders.>", "orders.created"));
    }

    #[test]
    fn wildcard_capture_does_not_include_its_bare_prefix() {
        assert!(!filter_subset_of("orders", "orders.>"));
    }
}
