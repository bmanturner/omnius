use std::{borrow::Borrow, fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

use crate::limits;

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

pub(crate) const fn name_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn job_name(value: &str) -> Result<(), TextError> {
    portable(value, TextKind::JobName, 2, limits::JOB_NAME, name_byte)?;
    if !value.as_bytes()[0].is_ascii_lowercase() {
        return Err(TextError::Invalid(TextKind::JobName));
    }
    Ok(())
}

pub(crate) fn event_suffix(value: &str) -> Option<u16> {
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

impl FailureCode {
    /// Builds a code from a crate-owned literal that already satisfies the failure-code grammar.
    pub(crate) fn known(code: &'static str) -> Self {
        Self(code.to_owned())
    }
}
