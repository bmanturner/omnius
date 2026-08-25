//! Provider-neutral typed jobs and domain events.
//!
//! Delivery is at least once: a provider may redeliver the same [`EncodedJobEnvelope`]. Handlers
//! must use [`DeliveryContext::effect_identity`] for idempotent effects or record the effect in the
//! same transaction as domain state. This crate deliberately contains no queue, retry executor,
//! persistence, scheduler, outbox, inbox, or transport implementation.

#![forbid(unsafe_code)]

use std::{
    borrow::Borrow,
    collections::{BTreeMap, VecDeque},
    fmt, io,
    marker::PhantomData,
    num::NonZeroU16,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use futures::future::BoxFuture;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};
use serde_json::{Value, value::RawValue};
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Stable string and wire byte ceilings.
pub mod limits {
    /// Job name bytes.
    pub const JOB_NAME: usize = 128;
    /// Event name bytes.
    pub const EVENT_NAME: usize = 128;
    /// Source bytes.
    pub const SOURCE: usize = 128;
    /// Subject bytes.
    pub const SUBJECT: usize = 256;
    /// Tenant identifier bytes.
    pub const TENANT: usize = 128;
    /// Queue name bytes.
    pub const QUEUE: usize = 64;
    /// Destination bytes.
    pub const DESTINATION: usize = 256;
    /// Idempotency-key bytes.
    pub const IDEMPOTENCY_KEY: usize = 255;
    /// Metadata-key bytes.
    pub const METADATA_KEY: usize = 64;
    /// Per-job metrics prefix bytes.
    pub const METRICS_PREFIX: usize = 128;
    /// Per-job runbook reference bytes.
    pub const RUNBOOK: usize = 256;
    /// Metadata entries.
    pub const METADATA_ENTRIES: usize = 32;
    /// Serialized metadata bytes.
    pub const METADATA_BYTES: usize = 16 * 1024;
    /// Maximum nested containers in one metadata value.
    pub const METADATA_DEPTH: usize = 16;
    /// Maximum scalar and container nodes across one metadata value.
    pub const METADATA_NODES: usize = 1_024;
    /// Absolute payload ceiling.
    pub const PAYLOAD_BYTES: usize = 1024 * 1024;
    /// Absolute envelope ceiling.
    pub const ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
    /// Capturing fixture records (at most 64 MiB of encoded envelopes).
    pub const CAPTURED_JOBS: usize = 32;
}

/// Kind of rejected bounded string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextKind {
    /// Job name.
    JobName,
    /// Event name.
    EventName,
    /// Source.
    Source,
    /// Subject.
    Subject,
    /// Tenant.
    Tenant,
    /// Queue.
    Queue,
    /// Destination.
    Destination,
    /// Traceparent.
    Traceparent,
    /// Idempotency key.
    IdempotencyKey,
    /// Metadata key.
    MetadataKey,
    /// Handler failure code.
    FailureCode,
}

/// Safe bounded-string error. The rejected string is never retained.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum TextError {
    /// Value was empty or structurally too short.
    #[error("{0:?} is too short")]
    TooShort(TextKind),
    /// Value exceeded its byte ceiling.
    #[error("{0:?} exceeds its byte limit")]
    TooLong(TextKind),
    /// Value was outside the portable `ASCII` grammar.
    #[error("{0:?} has an invalid portable format")]
    Invalid(TextKind),
}

fn portable(
    value: &str,
    kind: TextKind,
    min: usize,
    max: usize,
    allowed: impl Fn(u8) -> bool,
) -> Result<(), TextError> {
    if value.len() < min {
        return Err(TextError::TooShort(kind));
    }
    if value.len() > max {
        return Err(TextError::TooLong(kind));
    }
    if !value.is_ascii() || !value.bytes().all(allowed) {
        return Err(TextError::Invalid(kind));
    }
    Ok(())
}

const fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn job_name(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::JobName, 2, limits::JOB_NAME, name_byte)?;
    if !value.as_bytes()[0].is_ascii_lowercase() {
        return Err(TextError::Invalid(TextKind::JobName));
    }
    Ok(())
}

fn event_suffix(value: &str) -> Option<u16> {
    let (base, version) = value.rsplit_once(".v")?;
    if base.is_empty()
        || version.is_empty()
        || (version.len() > 1 && version.starts_with('0'))
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    version.parse().ok().filter(|version| *version > 0)
}

fn event_name(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::EventName, 5, limits::EVENT_NAME, name_byte)?;
    if !value.as_bytes()[0].is_ascii_lowercase() || event_suffix(value).is_none() {
        return Err(TextError::Invalid(TextKind::EventName));
    }
    Ok(())
}

fn source(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::Source, 1, limits::SOURCE, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
    })
}
fn subject(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::Subject, 1, limits::SUBJECT, |byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')
    })
}
fn tenant(value: &str) -> Result<(), TextError> {
    if value.is_empty() {
        return Err(TextError::TooShort(TextKind::Tenant));
    }
    if value.len() > limits::TENANT {
        return Err(TextError::TooLong(TextKind::Tenant));
    }
    if value.len() != 36 {
        return Err(TextError::Invalid(TextKind::Tenant));
    }
    let parsed = Uuid::parse_str(value).map_err(|_| TextError::Invalid(TextKind::Tenant))?;
    let mut buffer = Uuid::encode_buffer();
    if parsed.get_version_num() != 7 || parsed.hyphenated().encode_lower(&mut buffer) != value {
        return Err(TextError::Invalid(TextKind::Tenant));
    }
    Ok(())
}
fn queue(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::Queue, 1, limits::QUEUE, name_byte)?;
    if !value.as_bytes()[0].is_ascii_lowercase() {
        return Err(TextError::Invalid(TextKind::Queue));
    }
    Ok(())
}
fn destination(value: &str) -> Result<(), TextError> {
    portable(
        value,
        TextKind::Destination,
        1,
        limits::DESTINATION,
        |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':'),
    )
}
fn idempotency_key(value: &str) -> Result<(), TextError> {
    portable(
        value,
        TextKind::IdempotencyKey,
        1,
        limits::IDEMPOTENCY_KEY,
        |byte| byte.is_ascii_graphic(),
    )
}
fn metadata_key(value: &str) -> Result<(), TextError> {
    portable(
        value,
        TextKind::MetadataKey,
        1,
        limits::METADATA_KEY,
        |byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'),
    )
}
fn failure_code(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::FailureCode, 1, 64, name_byte)
}
fn traceparent(value: &str) -> Result<(), TextError> {
    if value.len() < 55 {
        return Err(TextError::TooShort(TextKind::Traceparent));
    }
    if value.len() > 55 {
        return Err(TextError::TooLong(TextKind::Traceparent));
    }
    let bytes = value.as_bytes();
    let valid_hex = bytes
        .iter()
        .enumerate()
        .filter(|(index, _)| !matches!(index, 2 | 35 | 52))
        .all(|(_, byte)| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if &bytes[..2] != b"00"
        || bytes[2] != b'-'
        || bytes[35] != b'-'
        || bytes[52] != b'-'
        || !valid_hex
        || bytes[3..35].iter().all(|byte| *byte == b'0')
        || bytes[36..52].iter().all(|byte| *byte == b'0')
    {
        return Err(TextError::Invalid(TextKind::Traceparent));
    }
    Ok(())
}

macro_rules! bounded_string {
    ($name:ident, $validator:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);
        impl $name {
            /// Borrows the validated string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
            /// Consumes the wrapper.
            #[must_use]
            pub fn into_inner(self) -> String {
                self.0
            }
        }
        impl TryFrom<&str> for $name {
            type Error = TextError;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                $validator(value)?;
                Ok(Self(value.to_owned()))
            }
        }
        impl TryFrom<String> for $name {
            type Error = TextError;
            fn try_from(value: String) -> Result<Self, Self::Error> {
                $validator(&value)?;
                Ok(Self(value))
            }
        }
        impl FromStr for $name {
            type Err = TextError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value)
            }
        }
        impl Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_struct(stringify!($name))
                    .field("value", &"[REDACTED]")
                    .field("byte_len", &self.0.len())
                    .finish_non_exhaustive()
            }
        }
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::try_from(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_string!(JobName, job_name, "A stable portable job name.");
bounded_string!(
    EventName,
    event_name,
    "A stable portable event name ending in `.vN`."
);
bounded_string!(Source, source, "A bounded event producer.");
bounded_string!(Subject, subject, "A bounded event subject.");
bounded_string!(TenantId, tenant, "A canonical `UUIDv7` tenant identifier.");
bounded_string!(QueueName, queue, "A bounded portable queue name.");
bounded_string!(Destination, destination, "A bounded portable destination.");
bounded_string!(
    Traceparent,
    traceparent,
    "A validated W3C version 00 traceparent."
);
bounded_string!(
    IdempotencyKey,
    idempotency_key,
    "A bounded idempotency key."
);
bounded_string!(MetadataKey, metadata_key, "A bounded event metadata key.");
bounded_string!(
    FailureCode,
    failure_code,
    "A bounded safe handler failure code."
);

/// Safe `UUIDv7` parse error that never retains input.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum IdError {
    /// Not a `UUID`.
    #[error("identifier is not a valid UUID")]
    Invalid,
    /// Not `UUIDv7`.
    #[error("identifier must be UUID version 7")]
    NotVersion7,
}

macro_rules! id_type {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);
        impl $name {
            /// Generates a `UUIDv7`.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            /// Validates an existing `UUIDv7`.
            ///
            /// # Errors
            ///
            /// Returns [`IdError::NotVersion7`] when `value` is not a `UUIDv7`.
            pub fn from_uuid(value: Uuid) -> Result<Self, IdError> {
                if value.get_version_num() == 7 {
                    Ok(Self(value))
                } else {
                    Err(IdError::NotVersion7)
                }
            }
            /// Returns the `UUID`.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
        impl FromStr for $name {
            type Err = IdError;
            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::from_uuid(Uuid::parse_str(value).map_err(|_| IdError::Invalid)?)
            }
        }
        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::from_str(&String::deserialize(deserializer)?)
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}
id_type!(JobId, "A time-ordered `UUIDv7` job identifier.");
id_type!(EventId, "A time-ordered `UUIDv7` event identifier.");

/// Non-zero message version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version(NonZeroU16);
impl Version {
    /// Validates a version.
    ///
    /// # Errors
    ///
    /// Returns [`VersionError`] when `value` is zero.
    pub const fn new(value: u16) -> Result<Self, VersionError> {
        match NonZeroU16::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(VersionError),
        }
    }
    /// Integer version.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}
impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.get())
    }
}
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
/// Zero is not a wire version.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("message version must be at least 1")]
pub struct VersionError;

/// Whether an application key is mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdempotencyRequirement {
    /// Key required.
    Required,
    /// Job `ID` is the fallback identity.
    Optional,
}
/// Exponential jitter strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Jitter {
    /// Jitter the full current ceiling.
    Full,
    /// Preserve half and jitter half.
    Equal,
}
/// Terminal retry behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeadLetterPolicy {
    /// Retain a terminal provider record.
    Retain,
    /// Publish to a bounded destination.
    Destination(&'static str),
}
/// Rolling-deployment compatibility declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompatibilityPolicy {
    /// Exact version only.
    Exact,
    /// A separate migration adapter may accept older versions.
    BackwardCompatible {
        /// Inclusive oldest adapter input.
        minimum_version: u16,
    },
}

/// Validated static job execution policy; it does not execute retries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JobPolicy {
    idempotency: IdempotencyRequirement,
    max_attempts: u16,
    initial_backoff_ms: u64,
    max_backoff_ms: u64,
    multiplier: u8,
    jitter: Jitter,
    timeout_seconds: u32,
    max_concurrency: u16,
    rate_per_minute: Option<u32>,
    queue: &'static str,
    priority: u8,
    retention_seconds: u64,
    dead_letter: DeadLetterPolicy,
    compatibility: CompatibilityPolicy,
    max_payload_bytes: usize,
}

impl JobPolicy {
    /// Constructs a bounded static declaration.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when an execution dimension is outside its supported bounds.
    #[expect(
        clippy::too_many_arguments,
        reason = "the policy deliberately makes every execution dimension explicit"
    )]
    pub const fn new(
        idempotency: IdempotencyRequirement,
        max_attempts: u16,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        multiplier: u8,
        jitter: Jitter,
        timeout_seconds: u32,
        max_concurrency: u16,
        rate_per_minute: Option<u32>,
        queue: &'static str,
        priority: u8,
        retention_seconds: u64,
        dead_letter: DeadLetterPolicy,
        compatibility: CompatibilityPolicy,
        max_payload_bytes: usize,
    ) -> Result<Self, PolicyError> {
        if max_attempts == 0 || max_attempts > 100 {
            return Err(PolicyError::Attempts);
        }
        if initial_backoff_ms == 0 || initial_backoff_ms > 86_400_000 {
            return Err(PolicyError::Backoff);
        }
        if max_backoff_ms < initial_backoff_ms || max_backoff_ms > 86_400_000 {
            return Err(PolicyError::Backoff);
        }
        if multiplier < 2 || multiplier > 10 {
            return Err(PolicyError::Multiplier);
        }
        if timeout_seconds == 0 || timeout_seconds > 86_400 {
            return Err(PolicyError::Timeout);
        }
        if max_concurrency == 0 || max_concurrency > 10_000 {
            return Err(PolicyError::Concurrency);
        }
        if let Some(rate) = rate_per_minute
            && (rate == 0 || rate > 1_000_000)
        {
            return Err(PolicyError::Rate);
        }
        if !static_queue(queue) {
            return Err(PolicyError::Queue);
        }
        if priority > 9 {
            return Err(PolicyError::Priority);
        }
        if retention_seconds == 0 || retention_seconds > 31_536_000 {
            return Err(PolicyError::Retention);
        }
        if let DeadLetterPolicy::Destination(value) = dead_letter
            && !static_destination(value)
        {
            return Err(PolicyError::DeadLetter);
        }
        if max_payload_bytes == 0 || max_payload_bytes > limits::PAYLOAD_BYTES {
            return Err(PolicyError::Payload);
        }
        Ok(Self {
            idempotency,
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
            multiplier,
            jitter,
            timeout_seconds,
            max_concurrency,
            rate_per_minute,
            queue,
            priority,
            retention_seconds,
            dead_letter,
            compatibility,
            max_payload_bytes,
        })
    }
    /// Checks version-dependent compatibility.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::Compatibility`] when `version` is zero or is outside the declared
    /// compatibility range.
    pub const fn validate_for(self, version: u16) -> Result<(), PolicyError> {
        if version == 0 {
            return Err(PolicyError::Compatibility);
        }
        if let CompatibilityPolicy::BackwardCompatible { minimum_version } = self.compatibility
            && (minimum_version == 0 || minimum_version > version)
        {
            return Err(PolicyError::Compatibility);
        }
        Ok(())
    }
    /// Idempotency requirement.
    #[must_use]
    pub const fn idempotency(self) -> IdempotencyRequirement {
        self.idempotency
    }
    /// Attempt ceiling.
    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }
    /// Initial backoff.
    #[must_use]
    pub const fn initial_backoff(self) -> Duration {
        Duration::from_millis(self.initial_backoff_ms)
    }
    /// Maximum backoff.
    #[must_use]
    pub const fn max_backoff(self) -> Duration {
        Duration::from_millis(self.max_backoff_ms)
    }
    /// Multiplier.
    #[must_use]
    pub const fn multiplier(self) -> u8 {
        self.multiplier
    }
    /// Jitter strategy.
    #[must_use]
    pub const fn jitter(self) -> Jitter {
        self.jitter
    }
    /// Attempt timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_seconds as u64)
    }
    /// Concurrency ceiling.
    #[must_use]
    pub const fn max_concurrency(self) -> u16 {
        self.max_concurrency
    }
    /// Starts per minute.
    #[must_use]
    pub const fn rate_per_minute(self) -> Option<u32> {
        self.rate_per_minute
    }
    /// Queue.
    #[must_use]
    pub const fn queue(self) -> &'static str {
        self.queue
    }
    /// Priority 0 through 9.
    #[must_use]
    pub const fn priority(self) -> u8 {
        self.priority
    }
    /// Terminal retention.
    #[must_use]
    pub const fn retention(self) -> Duration {
        Duration::from_secs(self.retention_seconds)
    }
    /// Dead-letter behavior.
    #[must_use]
    pub const fn dead_letter(self) -> DeadLetterPolicy {
        self.dead_letter
    }
    /// Compatibility declaration.
    #[must_use]
    pub const fn compatibility(self) -> CompatibilityPolicy {
        self.compatibility
    }
    /// Payload ceiling.
    #[must_use]
    pub const fn max_payload_bytes(self) -> usize {
        self.max_payload_bytes
    }
}

const fn static_queue(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limits::QUEUE || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if !name_byte(bytes[index]) {
            return false;
        }
        index += 1;
    }
    true
}
const fn static_destination(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limits::DESTINATION {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b'/' | b':')) {
            return false;
        }
        index += 1;
    }
    true
}

const fn static_metrics_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limits::METRICS_PREFIX {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_') {
            return false;
        }
        index += 1;
    }
    true
}

const fn static_runbook(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > limits::RUNBOOK {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if !(byte.is_ascii_alphanumeric()
            || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':' | b'#'))
        {
            return false;
        }
        index += 1;
    }
    true
}
/// Safe policy validation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicyError {
    /// Attempts outside 1 through 100.
    #[error("maximum attempts must be within 1 through 100")]
    Attempts,
    /// Backoff outside 1ms through 24h or maximum below initial.
    #[error("backoff bounds are invalid")]
    Backoff,
    /// Multiplier outside 2 through 10.
    #[error("backoff multiplier must be within 2 through 10")]
    Multiplier,
    /// Timeout outside 1s through 24h.
    #[error("timeout must be within 1s through 24h")]
    Timeout,
    /// Concurrency outside 1 through 10000.
    #[error("concurrency must be within 1 through 10000")]
    Concurrency,
    /// Rate outside 1 through 1000000.
    #[error("rate must be within 1 through 1000000 per minute")]
    Rate,
    /// Invalid queue.
    #[error("queue is invalid")]
    Queue,
    /// Priority outside 0 through 9.
    #[error("priority must be within 0 through 9")]
    Priority,
    /// Retention outside 1s through 365d.
    #[error("retention must be within 1s through 365d")]
    Retention,
    /// Invalid dead-letter destination.
    #[error("dead-letter destination is invalid")]
    DeadLetter,
    /// Invalid compatibility range.
    #[error("compatibility range is invalid")]
    Compatibility,
    /// Payload ceiling outside 1 byte through 1MiB.
    #[error("payload limit is invalid")]
    Payload,
}

/// Owned typed job payload and static declaration.
pub trait Job: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Stable job name.
    const NAME: &'static str;
    /// Stable wire version.
    const VERSION: u16;
    /// Static execution policy.
    const POLICY: JobPolicy;
    /// Low-cardinality metrics prefix dedicated to this job.
    const METRICS_PREFIX: &'static str;
    /// Stable operator runbook reference.
    const RUNBOOK: &'static str;
}
/// Owned typed domain-event payload.
pub trait DomainEvent: Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Stable event type ending in `.vN`.
    const NAME: &'static str;
    /// Stable wire version matching the suffix.
    const VERSION: u16;
}

/// Canonical job attempt fields.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttemptPolicy {
    max_attempts: u16,
    timeout_seconds: u32,
}
impl AttemptPolicy {
    /// Attempt ceiling.
    #[must_use]
    pub const fn max_attempts(self) -> u16 {
        self.max_attempts
    }
    /// Per-attempt timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        Duration::from_secs(self.timeout_seconds as u64)
    }
    fn validate(self) -> Result<(), EnvelopeError> {
        if self.max_attempts == 0
            || self.max_attempts > 100
            || self.timeout_seconds == 0
            || self.timeout_seconds > 86_400
        {
            return Err(EnvelopeError::AttemptPolicyMismatch);
        }
        Ok(())
    }
}

/// Safe envelope error with no payload-bearing detail.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EnvelopeError {
    /// Static name invalid.
    #[error("static message name is invalid")]
    DeclaredName,
    /// Static version invalid.
    #[error("static message version is invalid")]
    DeclaredVersion,
    /// Static policy invalid.
    #[error("static job policy is invalid")]
    DeclaredPolicy,
    /// Event suffix mismatch.
    #[error("event name suffix differs from version")]
    EventSuffix,
    /// Wire name mismatch.
    #[error("wire message name differs from typed declaration")]
    NameMismatch,
    /// Wire version mismatch.
    #[error("wire version differs from typed declaration")]
    VersionMismatch,
    /// Attempt policy mismatch.
    #[error("wire attempt policy differs from static policy")]
    AttemptPolicyMismatch,
    /// Required key absent.
    #[error("idempotency key is required")]
    IdempotencyRequired,
    /// Correlation `ID` not `UUIDv7`.
    #[error("correlation identifier must be UUID version 7")]
    CorrelationId,
    /// Causation `ID` not `UUIDv7`.
    #[error("causation identifier must be UUID version 7")]
    CausationId,
    /// Payload is not a `JSON` object.
    #[error("payload must serialize as a JSON object")]
    PayloadShape,
    /// Payload too large.
    #[error("payload exceeds its byte limit")]
    PayloadTooLarge,
    /// Envelope too large.
    #[error("envelope exceeds its byte limit")]
    EnvelopeTooLarge,
    /// Safe encoding failure.
    #[error("envelope serialization failed")]
    Encode,
    /// Safe decoding failure.
    #[error("envelope deserialization failed")]
    Decode,
}

fn uuid7(value: Uuid, cause: bool) -> Result<(), EnvelopeError> {
    if value.get_version_num() == 7 {
        Ok(())
    } else if cause {
        Err(EnvelopeError::CausationId)
    } else {
        Err(EnvelopeError::CorrelationId)
    }
}
struct CappedWriter {
    written: usize,
    max: usize,
    first: Option<u8>,
    exceeded: bool,
}

impl io::Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.first.is_none() {
            self.first = bytes
                .iter()
                .copied()
                .find(|byte| !byte.is_ascii_whitespace());
        }
        let Some(total) = self.written.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("serialized value exceeds its limit"));
        };
        if total > self.max {
            self.exceeded = true;
            return Err(io::Error::other("serialized value exceeds its limit"));
        }
        self.written = total;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn payload_ok<T: Serialize>(value: &T, max: usize) -> Result<(), EnvelopeError> {
    let mut writer = CappedWriter {
        written: 0,
        max,
        first: None,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return if writer.exceeded {
            Err(EnvelopeError::PayloadTooLarge)
        } else {
            Err(EnvelopeError::Encode)
        };
    }
    if writer.first != Some(b'{') {
        return Err(EnvelopeError::PayloadShape);
    }
    Ok(())
}

fn raw_object_ok(value: &RawValue, max: usize) -> Result<(), EnvelopeError> {
    let bytes = value.get().as_bytes();
    if bytes.len() > max {
        return Err(EnvelopeError::PayloadTooLarge);
    }
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        != Some(b'{')
    {
        return Err(EnvelopeError::PayloadShape);
    }
    Ok(())
}

#[derive(Deserialize)]
struct RawJobPayload<'a> {
    #[serde(borrow)]
    payload: &'a RawValue,
}

#[derive(Deserialize)]
struct RawEventFields<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
    #[serde(default, borrow)]
    metadata: Option<&'a RawValue>,
}
fn job_declaration<J: Job>() -> Result<(JobName, Version), EnvelopeError> {
    let name = JobName::try_from(J::NAME).map_err(|_| EnvelopeError::DeclaredName)?;
    let version = Version::new(J::VERSION).map_err(|_| EnvelopeError::DeclaredVersion)?;
    J::POLICY
        .validate_for(J::VERSION)
        .map_err(|_| EnvelopeError::DeclaredPolicy)?;
    if !static_metrics_prefix(J::METRICS_PREFIX) || !static_runbook(J::RUNBOOK) {
        return Err(EnvelopeError::DeclaredPolicy);
    }
    Ok((name, version))
}
fn event_declaration<E: DomainEvent>() -> Result<(EventName, Version), EnvelopeError> {
    let name = EventName::try_from(E::NAME).map_err(|_| EnvelopeError::DeclaredName)?;
    let version = Version::new(E::VERSION).map_err(|_| EnvelopeError::DeclaredVersion)?;
    if event_suffix(name.as_str()) != Some(E::VERSION) {
        return Err(EnvelopeError::EventSuffix);
    }
    Ok((name, version))
}

/// Job construction metadata.
#[derive(Clone)]
pub struct JobEnvelopeOptions {
    tenant_id: Option<TenantId>,
    not_before: Option<OffsetDateTime>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    idempotency_key: Option<IdempotencyKey>,
}
impl JobEnvelopeOptions {
    /// Starts with a required `UUIDv7` correlation `ID`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CorrelationId`] when `correlation_id` is not a `UUIDv7`.
    pub fn new(correlation_id: Uuid) -> Result<Self, EnvelopeError> {
        uuid7(correlation_id, false)?;
        Ok(Self {
            tenant_id: None,
            not_before: None,
            correlation_id,
            causation_id: None,
            idempotency_key: None,
        })
    }
    /// Adds tenant metadata.
    #[must_use]
    pub fn with_tenant(mut self, value: TenantId) -> Self {
        self.tenant_id = Some(value);
        self
    }
    /// Adds eligibility time.
    #[must_use]
    pub fn with_not_before(mut self, value: OffsetDateTime) -> Self {
        self.not_before = Some(value);
        self
    }
    /// Adds `UUIDv7` causation metadata.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CausationId`] when `value` is not a `UUIDv7`.
    pub fn with_causation(mut self, value: Uuid) -> Result<Self, EnvelopeError> {
        uuid7(value, true)?;
        self.causation_id = Some(value);
        Ok(self)
    }
    /// Adds application idempotency metadata.
    #[must_use]
    pub fn with_idempotency_key(mut self, value: IdempotencyKey) -> Self {
        self.idempotency_key = Some(value);
        self
    }
}
impl fmt::Debug for JobEnvelopeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobEnvelopeOptions")
            .field("has_tenant", &self.tenant_id.is_some())
            .field("correlation_id", &self.correlation_id)
            .field("causation_id", &self.causation_id)
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .finish_non_exhaustive()
    }
}

/// Canonical typed job envelope.
#[derive(Clone, Deserialize, Serialize)]
#[serde(bound(serialize = "J: Serialize", deserialize = "J: DeserializeOwned"))]
pub struct JobEnvelope<J: Job> {
    id: JobId,
    #[serde(rename = "type")]
    job_type: JobName,
    version: Version,
    tenant_id: Option<TenantId>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    not_before: Option<OffsetDateTime>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    idempotency_key: Option<IdempotencyKey>,
    attempt_policy: AttemptPolicy,
    payload: J,
}
impl<J: Job> JobEnvelope<J> {
    /// Creates a `UUIDv7` envelope at the current `UTC` time.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the job declaration or payload is invalid, or a required
    /// idempotency key is absent.
    pub fn new(payload: J, options: JobEnvelopeOptions) -> Result<Self, EnvelopeError> {
        let (job_type, version) = job_declaration::<J>()?;
        if J::POLICY.idempotency() == IdempotencyRequirement::Required
            && options.idempotency_key.is_none()
        {
            return Err(EnvelopeError::IdempotencyRequired);
        }
        payload_ok(&payload, J::POLICY.max_payload_bytes())?;
        Ok(Self {
            id: JobId::new(),
            job_type,
            version,
            tenant_id: options.tenant_id,
            created_at: OffsetDateTime::now_utc(),
            not_before: options.not_before,
            correlation_id: options.correlation_id,
            causation_id: options.causation_id,
            idempotency_key: options.idempotency_key,
            attempt_policy: AttemptPolicy {
                max_attempts: J::POLICY.max_attempts(),
                timeout_seconds: J::POLICY.timeout_seconds,
            },
            payload,
        })
    }
    /// Job `ID`.
    #[must_use]
    pub const fn id(&self) -> JobId {
        self.id
    }
    /// Payload.
    #[must_use]
    pub const fn payload(&self) -> &J {
        &self.payload
    }
    /// Consumes into payload.
    #[must_use]
    pub fn into_payload(self) -> J {
        self.payload
    }
    /// Encodes a provider-boundary value.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the envelope is invalid, cannot serialize, or exceeds its
    /// byte ceiling.
    pub fn encode(&self) -> Result<EncodedJobEnvelope, EnvelopeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| EnvelopeError::Encode)?;
        if bytes.len() > limits::ENVELOPE_BYTES {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        Ok(EncodedJobEnvelope {
            bytes: bytes.into_boxed_slice(),
            id: self.id,
            job_name: self.job_type.clone(),
            version: self.version,
            queue: QueueName::try_from(J::POLICY.queue())
                .map_err(|_| EnvelopeError::DeclaredPolicy)?,
            tenant_id: self.tenant_id.clone(),
            created_at: self.created_at,
            not_before: self.not_before,
            correlation_id: self.correlation_id,
            causation_id: self.causation_id,
            idempotency_key: self.idempotency_key.clone(),
            attempt_policy: self.attempt_policy,
        })
    }
    /// Decodes bounded `JSON` and checks declaration, policy, and payload limits.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when `bytes` is oversized, malformed, or inconsistent with the
    /// typed declaration and policy.
    pub fn decode(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > limits::ENVELOPE_BYTES {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        let raw: RawJobPayload<'_> =
            serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Decode)?;
        raw_object_ok(raw.payload, J::POLICY.max_payload_bytes())?;
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Decode)?;
        envelope.validate()?;
        Ok(envelope)
    }
    fn validate(&self) -> Result<(), EnvelopeError> {
        let (name, version) = job_declaration::<J>()?;
        if self.job_type != name {
            return Err(EnvelopeError::NameMismatch);
        }
        if self.version != version {
            return Err(EnvelopeError::VersionMismatch);
        }
        let policy = AttemptPolicy {
            max_attempts: J::POLICY.max_attempts(),
            timeout_seconds: J::POLICY.timeout_seconds,
        };
        if self.attempt_policy != policy {
            return Err(EnvelopeError::AttemptPolicyMismatch);
        }
        if J::POLICY.idempotency() == IdempotencyRequirement::Required
            && self.idempotency_key.is_none()
        {
            return Err(EnvelopeError::IdempotencyRequired);
        }
        uuid7(self.correlation_id, false)?;
        if let Some(value) = self.causation_id {
            uuid7(value, true)?;
        }
        payload_ok(&self.payload, J::POLICY.max_payload_bytes())
    }
}
impl<J: Job> fmt::Debug for JobEnvelope<J> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JobEnvelope")
            .field("id", &self.id)
            .field("type", &self.job_type.as_str())
            .field("version", &self.version)
            .field("has_tenant", &self.tenant_id.is_some())
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .field("payload", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct EncodedJobHeader {
    id: JobId,
    #[serde(rename = "type")]
    job_name: JobName,
    version: Version,
    tenant_id: Option<TenantId>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    not_before: Option<OffsetDateTime>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    idempotency_key: Option<IdempotencyKey>,
    attempt_policy: AttemptPolicy,
    #[serde(rename = "payload")]
    _payload: serde::de::IgnoredAny,
}
impl EncodedJobHeader {
    fn validate(&self) -> Result<(), EnvelopeError> {
        uuid7(self.correlation_id, false)?;
        if let Some(value) = self.causation_id {
            uuid7(value, true)?;
        }
        self.attempt_policy.validate()
    }
}

/// Validated encoded job for object-safe provider boundaries.
#[derive(Clone)]
pub struct EncodedJobEnvelope {
    bytes: Box<[u8]>,
    id: JobId,
    job_name: JobName,
    version: Version,
    queue: QueueName,
    tenant_id: Option<TenantId>,
    created_at: OffsetDateTime,
    not_before: Option<OffsetDateTime>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    idempotency_key: Option<IdempotencyKey>,
    attempt_policy: AttemptPolicy,
}
impl EncodedJobEnvelope {
    /// Restores a provider-boundary value from bounded canonical bytes and separately persisted
    /// queue policy.
    ///
    /// The payload is syntactically checked but not materialized. Typed payload validation remains
    /// the responsibility of [`Self::decode`] at dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the envelope is oversized, malformed, or contains invalid
    /// erased identity or attempt metadata.
    pub fn restore(bytes: &[u8], queue: QueueName) -> Result<Self, EnvelopeError> {
        if bytes.len() > limits::ENVELOPE_BYTES {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        let header: EncodedJobHeader =
            serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Decode)?;
        header.validate()?;
        Ok(Self {
            bytes: bytes.into(),
            id: header.id,
            job_name: header.job_name,
            version: header.version,
            queue,
            tenant_id: header.tenant_id,
            created_at: header.created_at,
            not_before: header.not_before,
            correlation_id: header.correlation_id,
            causation_id: header.causation_id,
            idempotency_key: header.idempotency_key,
            attempt_policy: header.attempt_policy,
        })
    }
    /// Canonical bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Job `ID`.
    #[must_use]
    pub const fn id(&self) -> JobId {
        self.id
    }
    /// Stable job name.
    #[must_use]
    pub const fn job_name(&self) -> &JobName {
        &self.job_name
    }
    /// Version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Queue.
    #[must_use]
    pub const fn queue(&self) -> &QueueName {
        &self.queue
    }
    /// Optional tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }
    /// Envelope creation time.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
    /// Earliest eligible delivery time.
    #[must_use]
    pub const fn not_before(&self) -> Option<OffsetDateTime> {
        self.not_before
    }
    /// Correlation `UUIDv7`.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
    /// Optional causation `UUIDv7`.
    #[must_use]
    pub const fn causation_id(&self) -> Option<Uuid> {
        self.causation_id
    }
    /// Optional application idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
    /// Validated attempt limits.
    #[must_use]
    pub const fn attempt_policy(&self) -> AttemptPolicy {
        self.attempt_policy
    }
    /// Typed decode.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the encoded envelope is malformed or incompatible with
    /// `J`.
    pub fn decode<J: Job>(&self) -> Result<JobEnvelope<J>, EnvelopeError> {
        JobEnvelope::decode(&self.bytes)
    }
}
impl fmt::Debug for EncodedJobEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedJobEnvelope")
            .field("id", &self.id)
            .field("type", &self.job_name.as_str())
            .field("version", &self.version)
            .field("queue", &self.queue.as_str())
            .field("encoded_bytes", &self.bytes.len())
            .field("payload", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Bounded additive event metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct EventMetadata {
    entries: BTreeMap<MetadataKey, Value>,
    encoded_bytes: usize,
}
impl EventMetadata {
    /// Empty metadata.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            encoded_bytes: 2,
        }
    }
    /// Validates and owns a map.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] when the map has too many entries or bytes, contains an invalid
    /// key, or cannot serialize.
    pub fn try_from_map(entries: BTreeMap<String, Value>) -> Result<Self, MetadataError> {
        if entries.len() > limits::METADATA_ENTRIES {
            return Err(MetadataError::Entries);
        }
        let mut checked = BTreeMap::new();
        for (key, value) in entries {
            metadata_value_ok(&value)?;
            checked.insert(
                MetadataKey::try_from(key).map_err(|_| MetadataError::Key)?,
                value,
            );
        }
        let encoded_bytes = metadata_size(&checked)?;
        Ok(Self {
            entries: checked,
            encoded_bytes,
        })
    }
    /// Inserts or replaces one entry atomically.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] without changing the map when the resulting metadata exceeds an
    /// entry or byte limit, or cannot serialize.
    pub fn insert(
        &mut self,
        key: MetadataKey,
        value: Value,
    ) -> Result<Option<Value>, MetadataError> {
        if !self.entries.contains_key(&key) && self.entries.len() == limits::METADATA_ENTRIES {
            return Err(MetadataError::Entries);
        }
        metadata_value_ok(&value)?;
        let previous = self.entries.insert(key.clone(), value);
        match metadata_size(&self.entries) {
            Ok(size) => {
                self.encoded_bytes = size;
                Ok(previous)
            }
            Err(error) => {
                if let Some(value) = previous {
                    self.entries.insert(key, value);
                } else {
                    self.entries.remove(&key);
                }
                Err(error)
            }
        }
    }
    /// Looks up an entry.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }
    /// Entry count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Empty state.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Serialized byte count.
    #[must_use]
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}
impl Default for EventMetadata {
    fn default() -> Self {
        Self::new()
    }
}
fn metadata_value_ok(root: &Value) -> Result<(), MetadataError> {
    let mut stack = vec![(root, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((value, depth)) = stack.pop() {
        nodes = nodes.checked_add(1).ok_or(MetadataError::Complexity)?;
        if nodes > limits::METADATA_NODES || depth > limits::METADATA_DEPTH {
            return Err(MetadataError::Complexity);
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                stack.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn metadata_size(value: &BTreeMap<MetadataKey, Value>) -> Result<usize, MetadataError> {
    let mut writer = CappedWriter {
        written: 0,
        max: limits::METADATA_BYTES,
        first: None,
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return if writer.exceeded {
            Err(MetadataError::Bytes)
        } else {
            Err(MetadataError::Encode)
        };
    }
    Ok(writer.written)
}
impl Serialize for EventMetadata {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.entries.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for EventMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::try_from_map(BTreeMap::<String, Value>::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}
impl fmt::Debug for EventMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventMetadata")
            .field("entries", &self.entries.len())
            .field("encoded_bytes", &self.encoded_bytes)
            .field("values", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
/// Safe metadata error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum MetadataError {
    /// Too many entries.
    #[error("metadata exceeds entry limit")]
    Entries,
    /// Invalid key.
    #[error("metadata key is invalid")]
    Key,
    /// Too many bytes.
    #[error("metadata exceeds byte limit")]
    Bytes,
    /// Excessive value nesting or node count.
    #[error("metadata exceeds complexity limit")]
    Complexity,
    /// Safe encoding failure.
    #[error("metadata serialization failed")]
    Encode,
}

/// Event payload/envelope byte limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventLimits {
    max_payload: usize,
    max_envelope: usize,
}
impl EventLimits {
    /// Validates limits.
    ///
    /// # Errors
    ///
    /// Returns [`EventLimitsError`] when either limit is outside its supported range or the
    /// envelope limit is smaller than the payload limit.
    pub const fn new(max_payload: usize, max_envelope: usize) -> Result<Self, EventLimitsError> {
        if max_payload == 0 || max_payload > limits::PAYLOAD_BYTES {
            return Err(EventLimitsError::Payload);
        }
        if max_envelope < max_payload || max_envelope > limits::ENVELOPE_BYTES {
            return Err(EventLimitsError::Envelope);
        }
        Ok(Self {
            max_payload,
            max_envelope,
        })
    }
}
impl Default for EventLimits {
    fn default() -> Self {
        Self {
            max_payload: 256 * 1024,
            max_envelope: 512 * 1024,
        }
    }
}
/// Safe event limit error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EventLimitsError {
    /// Invalid payload limit.
    #[error("event payload limit is invalid")]
    Payload,
    /// Invalid envelope limit.
    #[error("event envelope limit is invalid")]
    Envelope,
}

/// Event construction metadata.
#[derive(Clone)]
pub struct EventEnvelopeOptions {
    source: Source,
    subject: Subject,
    tenant_id: Option<TenantId>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    traceparent: Option<Traceparent>,
    metadata: EventMetadata,
}
impl EventEnvelopeOptions {
    /// Starts with source, subject, and `UUIDv7` correlation `ID`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CorrelationId`] when `correlation_id` is not a `UUIDv7`.
    pub fn new(
        source: Source,
        subject: Subject,
        correlation_id: Uuid,
    ) -> Result<Self, EnvelopeError> {
        uuid7(correlation_id, false)?;
        Ok(Self {
            source,
            subject,
            tenant_id: None,
            correlation_id,
            causation_id: None,
            traceparent: None,
            metadata: EventMetadata::new(),
        })
    }
    /// Adds tenant.
    #[must_use]
    pub fn with_tenant(mut self, value: TenantId) -> Self {
        self.tenant_id = Some(value);
        self
    }
    /// Adds `UUIDv7` cause.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError::CausationId`] when `value` is not a `UUIDv7`.
    pub fn with_causation(mut self, value: Uuid) -> Result<Self, EnvelopeError> {
        uuid7(value, true)?;
        self.causation_id = Some(value);
        Ok(self)
    }
    /// Adds `W3C` trace context.
    #[must_use]
    pub fn with_traceparent(mut self, value: Traceparent) -> Self {
        self.traceparent = Some(value);
        self
    }
    /// Adds bounded metadata.
    #[must_use]
    pub fn with_metadata(mut self, value: EventMetadata) -> Self {
        self.metadata = value;
        self
    }
}
impl fmt::Debug for EventEnvelopeOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventEnvelopeOptions")
            .field("source", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("has_tenant", &self.tenant_id.is_some())
            .field("has_traceparent", &self.traceparent.is_some())
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Canonical typed event envelope.
#[derive(Clone, Deserialize, Serialize)]
#[serde(bound(serialize = "E: Serialize", deserialize = "E: DeserializeOwned"))]
pub struct EventEnvelope<E: DomainEvent> {
    id: EventId,
    #[serde(rename = "type")]
    event_type: EventName,
    version: Version,
    source: Source,
    subject: Subject,
    tenant_id: Option<TenantId>,
    #[serde(with = "time::serde::rfc3339")]
    occurred_at: OffsetDateTime,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    traceparent: Option<Traceparent>,
    data: E,
    #[serde(default)]
    metadata: EventMetadata,
}
impl<E: DomainEvent> EventEnvelope<E> {
    /// Creates a `UUIDv7` envelope at the current `UTC` time.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the event declaration or payload is invalid.
    pub fn new(
        data: E,
        options: EventEnvelopeOptions,
        limits: EventLimits,
    ) -> Result<Self, EnvelopeError> {
        let (event_type, version) = event_declaration::<E>()?;
        payload_ok(&data, limits.max_payload)?;
        Ok(Self {
            id: EventId::new(),
            event_type,
            version,
            source: options.source,
            subject: options.subject,
            tenant_id: options.tenant_id,
            occurred_at: OffsetDateTime::now_utc(),
            correlation_id: options.correlation_id,
            causation_id: options.causation_id,
            traceparent: options.traceparent,
            data,
            metadata: options.metadata,
        })
    }
    /// Event `ID`.
    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }
    /// Event type.
    #[must_use]
    pub const fn event_name(&self) -> &EventName {
        &self.event_type
    }
    /// Event schema version.
    #[must_use]
    pub const fn version(&self) -> Version {
        self.version
    }
    /// Producer identity.
    #[must_use]
    pub const fn source(&self) -> &Source {
        &self.source
    }
    /// Aggregate or resource subject.
    #[must_use]
    pub const fn subject(&self) -> &Subject {
        &self.subject
    }
    /// Optional tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }
    /// Domain occurrence time.
    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }
    /// Correlation `UUIDv7`.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
    /// Optional causation `UUIDv7`.
    #[must_use]
    pub const fn causation_id(&self) -> Option<Uuid> {
        self.causation_id
    }
    /// Optional W3C trace context.
    #[must_use]
    pub const fn traceparent(&self) -> Option<&Traceparent> {
        self.traceparent.as_ref()
    }
    /// Typed data.
    #[must_use]
    pub const fn data(&self) -> &E {
        &self.data
    }
    /// Additive metadata.
    #[must_use]
    pub const fn metadata(&self) -> &EventMetadata {
        &self.metadata
    }
    /// Encodes bounded canonical `JSON`.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when the envelope is invalid, cannot serialize, or exceeds its
    /// byte ceiling.
    pub fn encode(&self, limits: EventLimits) -> Result<Vec<u8>, EnvelopeError> {
        self.validate(limits)?;
        let bytes = serde_json::to_vec(self).map_err(|_| EnvelopeError::Encode)?;
        if bytes.len() > limits.max_envelope {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        Ok(bytes)
    }
    /// Decodes `JSON`; unknown top-level additions are ignored and metadata entries are preserved.
    ///
    /// # Errors
    ///
    /// Returns [`EnvelopeError`] when `bytes` is oversized, malformed, or inconsistent with the
    /// typed declaration and limits.
    pub fn decode(bytes: &[u8], limits: EventLimits) -> Result<Self, EnvelopeError> {
        if bytes.len() > limits.max_envelope {
            return Err(EnvelopeError::EnvelopeTooLarge);
        }
        let raw: RawEventFields<'_> =
            serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Decode)?;
        raw_object_ok(raw.data, limits.max_payload)?;
        if raw
            .metadata
            .is_some_and(|metadata| metadata.get().len() > limits::METADATA_BYTES)
        {
            return Err(EnvelopeError::PayloadTooLarge);
        }
        let envelope: Self = serde_json::from_slice(bytes).map_err(|_| EnvelopeError::Decode)?;
        envelope.validate(limits)?;
        Ok(envelope)
    }
    fn validate(&self, limits: EventLimits) -> Result<(), EnvelopeError> {
        let (name, version) = event_declaration::<E>()?;
        if self.event_type != name {
            return Err(EnvelopeError::NameMismatch);
        }
        if self.version != version {
            return Err(EnvelopeError::VersionMismatch);
        }
        uuid7(self.correlation_id, false)?;
        if let Some(value) = self.causation_id {
            uuid7(value, true)?;
        }
        payload_ok(&self.data, limits.max_payload)
    }
}
impl<E: DomainEvent> fmt::Debug for EventEnvelope<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventEnvelope")
            .field("id", &self.id)
            .field("type", &self.event_type.as_str())
            .field("version", &self.version)
            .field("source", &"[REDACTED]")
            .field("subject", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

/// Provider acceptance receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnqueueReceipt {
    job_id: JobId,
    queue: QueueName,
    accepted_at: OffsetDateTime,
}
impl EnqueueReceipt {
    /// Creates a provider acceptance receipt.
    #[must_use]
    pub const fn new(job_id: JobId, queue: QueueName, accepted_at: OffsetDateTime) -> Self {
        Self {
            job_id,
            queue,
            accepted_at,
        }
    }
    /// Job `ID`.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
    /// Queue.
    #[must_use]
    pub const fn queue(&self) -> &QueueName {
        &self.queue
    }
    /// Acceptance time.
    #[must_use]
    pub const fn accepted_at(&self) -> OffsetDateTime {
        self.accepted_at
    }
}
/// Safe provider enqueue failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum EnqueueError {
    /// Typed validation failed.
    #[error("job envelope is invalid")]
    InvalidEnvelope,
    /// Bounded capacity exhausted.
    #[error("job enqueuer is at capacity")]
    Capacity,
    /// Temporary provider failure.
    #[error("job enqueuer is unavailable")]
    Unavailable,
    /// Permanent provider rejection.
    #[error("job enqueuer rejected request")]
    Rejected,
}
/// Object-safe provider port.
pub trait JobEnqueuer: Send + Sync {
    /// Enqueues one validated encoded envelope.
    ///
    /// # Errors
    ///
    /// The returned future resolves to [`EnqueueError`] when the provider cannot accept the
    /// envelope.
    fn enqueue(
        &self,
        envelope: EncodedJobEnvelope,
    ) -> BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>>;
}
/// Typed helper for every object-safe enqueuer.
pub trait JobEnqueuerExt: JobEnqueuer {
    /// Encodes and enqueues a typed envelope.
    ///
    /// # Errors
    ///
    /// The returned future resolves to [`EnqueueError::InvalidEnvelope`] when encoding fails, or
    /// to an [`EnqueueError`] reported by the provider.
    fn enqueue_typed<'a, J: Job>(
        &'a self,
        envelope: &'a JobEnvelope<J>,
    ) -> BoxFuture<'a, Result<EnqueueReceipt, EnqueueError>> {
        Box::pin(async move {
            self.enqueue(
                envelope
                    .encode()
                    .map_err(|_| EnqueueError::InvalidEnvelope)?,
            )
            .await
        })
    }
}
impl<T: JobEnqueuer + ?Sized> JobEnqueuerExt for T {}

/// Stable identity for duplicate-safe effects.
///
/// An application idempotency key is canonical within its job-name and tenant namespace. The
/// generated job identifier is used only when no application key is present.
#[derive(Clone)]
pub struct EffectIdentity {
    job_id: JobId,
    job_name: JobName,
    tenant_id: Option<TenantId>,
    idempotency_key: Option<IdempotencyKey>,
}
impl EffectIdentity {
    fn from_envelope(envelope: &EncodedJobEnvelope) -> Self {
        Self {
            job_id: envelope.id,
            job_name: envelope.job_name.clone(),
            tenant_id: envelope.tenant_id.clone(),
            idempotency_key: envelope.idempotency_key.clone(),
        }
    }
    /// Delivery job identifier, which is the fallback effect identity when no key is present.
    #[must_use]
    pub const fn job_id(&self) -> JobId {
        self.job_id
    }
    /// Stable job-name namespace.
    #[must_use]
    pub const fn job_name(&self) -> &JobName {
        &self.job_name
    }
    /// Optional tenant namespace.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }
    /// Optional canonical application key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}
impl PartialEq for EffectIdentity {
    fn eq(&self, other: &Self) -> bool {
        match (&self.idempotency_key, &other.idempotency_key) {
            (Some(key), Some(other_key)) => {
                self.job_name == other.job_name
                    && self.tenant_id == other.tenant_id
                    && key == other_key
            }
            (None, None) => self.job_id == other.job_id,
            _ => false,
        }
    }
}
impl Eq for EffectIdentity {}
impl fmt::Debug for EffectIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EffectIdentity")
            .field("job_id", &self.job_id)
            .field("job_name", &self.job_name)
            .field("has_tenant", &self.tenant_id.is_some())
            .field("has_idempotency_key", &self.idempotency_key.is_some())
            .finish_non_exhaustive()
    }
}
/// Safe delivery context error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DeliveryContextError {
    /// Attempt zero is invalid.
    #[error("attempt must be at least 1")]
    ZeroAttempt,
    /// Attempt exceeds static policy.
    #[error("attempt exceeds static maximum")]
    AttemptExceeded,
}
/// One at-least-once delivery invocation.
#[derive(Clone)]
pub struct DeliveryContext {
    attempt: NonZeroU16,
    cancellation: CancellationToken,
    deadline: OffsetDateTime,
    tenant_id: Option<TenantId>,
    correlation_id: Uuid,
    causation_id: Option<Uuid>,
    effect_identity: EffectIdentity,
}
impl DeliveryContext {
    /// Builds context from encoded immutable identity metadata.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryContextError`] when `attempt` is zero or exceeds the envelope policy.
    pub fn from_envelope(
        envelope: &EncodedJobEnvelope,
        attempt: u16,
        cancellation: CancellationToken,
        deadline: OffsetDateTime,
    ) -> Result<Self, DeliveryContextError> {
        let attempt = NonZeroU16::new(attempt).ok_or(DeliveryContextError::ZeroAttempt)?;
        if attempt.get() > envelope.attempt_policy.max_attempts {
            return Err(DeliveryContextError::AttemptExceeded);
        }
        Ok(Self {
            attempt,
            cancellation,
            deadline,
            tenant_id: envelope.tenant_id.clone(),
            correlation_id: envelope.correlation_id,
            causation_id: envelope.causation_id,
            effect_identity: EffectIdentity::from_envelope(envelope),
        })
    }
    /// One-based attempt.
    #[must_use]
    pub const fn attempt(&self) -> NonZeroU16 {
        self.attempt
    }
    /// Cooperative cancellation token.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
    /// Cancellation state.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
    /// Attempt deadline.
    #[must_use]
    pub const fn deadline(&self) -> OffsetDateTime {
        self.deadline
    }
    /// Optional tenant identity.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<&TenantId> {
        self.tenant_id.as_ref()
    }
    /// Correlation `UUIDv7`.
    #[must_use]
    pub const fn correlation_id(&self) -> Uuid {
        self.correlation_id
    }
    /// Optional causation `UUIDv7`.
    #[must_use]
    pub const fn causation_id(&self) -> Option<Uuid> {
        self.causation_id
    }
    /// Stable duplicate-safe identity.
    #[must_use]
    pub const fn effect_identity(&self) -> &EffectIdentity {
        &self.effect_identity
    }
    fn matches(&self, envelope: &EncodedJobEnvelope) -> bool {
        self.tenant_id == envelope.tenant_id
            && self.correlation_id == envelope.correlation_id
            && self.causation_id == envelope.causation_id
            && self.effect_identity == EffectIdentity::from_envelope(envelope)
    }
}
impl fmt::Debug for DeliveryContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeliveryContext")
            .field("attempt", &self.attempt)
            .field("cancelled", &self.is_cancelled())
            .field("deadline", &self.deadline)
            .field("effect_identity", &self.effect_identity)
            .finish_non_exhaustive()
    }
}
/// Safe handler failure classification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlerFailure(FailureCode);
impl HandlerFailure {
    /// Creates a classified failure.
    #[must_use]
    pub const fn new(code: FailureCode) -> Self {
        Self(code)
    }
    /// Safe code.
    #[must_use]
    pub const fn code(&self) -> &FailureCode {
        &self.0
    }
    fn known(code: &'static str) -> Self {
        Self(FailureCode(code.to_owned()))
    }
}
/// Explicit handler outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HandlerOutcome {
    /// Effect completed.
    Succeeded,
    /// Retry within policy.
    Retryable(HandlerFailure),
    /// Never automatically retry.
    Permanent(HandlerFailure),
    /// Cancellation interrupted work before completion.
    Cancelled,
}
/// Object-safe handler port.
pub trait JobHandler: Send + Sync {
    /// Stable accepted name.
    fn job_name(&self) -> &'static str;
    /// Exact accepted version.
    fn job_version(&self) -> u16;
    /// Low-cardinality metrics prefix.
    fn metrics_prefix(&self) -> &'static str;
    /// Stable operator runbook reference.
    fn runbook(&self) -> &'static str;
    /// Handles one delivery.
    fn handle(
        &self,
        envelope: EncodedJobEnvelope,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome>;
}
/// Typed handler contract.
pub trait TypedJobHandler<J: Job>: Send + Sync + 'static {
    /// Handles an owned payload.
    fn handle(&self, job: J, context: DeliveryContext) -> BoxFuture<'_, HandlerOutcome>;
}
/// Adapter from a typed handler to object-safe dispatch.
pub struct TypedJobHandlerAdapter<J, H> {
    handler: H,
    marker: PhantomData<fn() -> J>,
}
impl<J, H> TypedJobHandlerAdapter<J, H> {
    /// Wraps a handler.
    #[must_use]
    pub const fn new(handler: H) -> Self {
        Self {
            handler,
            marker: PhantomData,
        }
    }
}
impl<J: Job, H: TypedJobHandler<J>> JobHandler for TypedJobHandlerAdapter<J, H> {
    fn job_name(&self) -> &'static str {
        J::NAME
    }
    fn job_version(&self) -> u16 {
        J::VERSION
    }
    fn metrics_prefix(&self) -> &'static str {
        J::METRICS_PREFIX
    }
    fn runbook(&self) -> &'static str {
        J::RUNBOOK
    }
    fn handle(
        &self,
        envelope: EncodedJobEnvelope,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        Box::pin(async move {
            if context.is_cancelled() {
                return HandlerOutcome::Cancelled;
            }
            if !context.matches(&envelope) {
                return HandlerOutcome::Permanent(HandlerFailure::known("context_mismatch"));
            }
            let Ok(envelope) = envelope.decode::<J>() else {
                return HandlerOutcome::Permanent(HandlerFailure::known("invalid_envelope"));
            };
            self.handler.handle(envelope.into_payload(), context).await
        })
    }
}

/// Bounded fixture named by the module catalog.
pub mod capturing_job_enqueuer {
    use super::{
        Arc, BoxFuture, EncodedJobEnvelope, EnqueueError, EnqueueReceipt, Error, JobEnqueuer,
        Mutex, OffsetDateTime, VecDeque, fmt, limits,
    };
    /// Safe fixture error.
    #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
    pub enum CaptureError {
        /// Capacity outside 1 through 10000.
        #[error("capture capacity is invalid")]
        InvalidCapacity,
        /// Poisoned fixture state.
        #[error("capture state is unavailable")]
        Unavailable,
    }
    struct Inner {
        capacity: usize,
        records: Mutex<VecDeque<EncodedJobEnvelope>>,
    }
    /// Bounded concurrency-safe capturing enqueuer.
    #[derive(Clone)]
    pub struct CapturingJobEnqueuer {
        inner: Arc<Inner>,
    }
    impl CapturingJobEnqueuer {
        /// Creates fixed capacity.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError::InvalidCapacity`] when `capacity` is zero or exceeds the
        /// fixture limit.
        pub fn new(capacity: usize) -> Result<Self, CaptureError> {
            if capacity == 0 || capacity > limits::CAPTURED_JOBS {
                return Err(CaptureError::InvalidCapacity);
            }
            Ok(Self {
                inner: Arc::new(Inner {
                    capacity,
                    records: Mutex::new(VecDeque::with_capacity(capacity)),
                }),
            })
        }
        /// Retained count.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError::Unavailable`] when the fixture state is poisoned.
        pub fn len(&self) -> Result<usize, CaptureError> {
            self.inner
                .records
                .lock()
                .map(|records| records.len())
                .map_err(|_| CaptureError::Unavailable)
        }
        /// Empty state.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError::Unavailable`] when the fixture state is poisoned.
        pub fn is_empty(&self) -> Result<bool, CaptureError> {
            Ok(self.len()? == 0)
        }
        /// Non-destructive acceptance-order snapshot.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError::Unavailable`] when the fixture state is poisoned.
        pub fn snapshot(&self) -> Result<Vec<EncodedJobEnvelope>, CaptureError> {
            self.inner
                .records
                .lock()
                .map(|records| records.iter().cloned().collect())
                .map_err(|_| CaptureError::Unavailable)
        }
        /// Acceptance-order drain without payload copies.
        ///
        /// # Errors
        ///
        /// Returns [`CaptureError::Unavailable`] when the fixture state is poisoned.
        pub fn drain(&self) -> Result<Vec<EncodedJobEnvelope>, CaptureError> {
            self.inner
                .records
                .lock()
                .map(|mut records| records.drain(..).collect())
                .map_err(|_| CaptureError::Unavailable)
        }
    }
    impl JobEnqueuer for CapturingJobEnqueuer {
        fn enqueue(
            &self,
            envelope: EncodedJobEnvelope,
        ) -> BoxFuture<'_, Result<EnqueueReceipt, EnqueueError>> {
            Box::pin(async move {
                let job_id = envelope.id;
                let queue = envelope.queue.clone();
                let mut records = self
                    .inner
                    .records
                    .lock()
                    .map_err(|_| EnqueueError::Unavailable)?;
                if records.len() == self.inner.capacity {
                    return Err(EnqueueError::Capacity);
                }
                records.push_back(envelope);
                drop(records);
                Ok(EnqueueReceipt::new(
                    job_id,
                    queue,
                    OffsetDateTime::now_utc(),
                ))
            })
        }
    }
    impl fmt::Debug for CapturingJobEnqueuer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("CapturingJobEnqueuer")
                .field("capacity", &self.inner.capacity)
                .field("retained", &self.len().ok())
                .field("payloads", &"[REDACTED]")
                .finish_non_exhaustive()
        }
    }
}
pub use capturing_job_enqueuer::{CaptureError, CapturingJobEnqueuer};
