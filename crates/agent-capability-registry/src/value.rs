use std::{borrow::Cow, fmt, str::FromStr};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;

/// Maximum UTF-8 byte length of a capability identifier.
pub const MAX_CAPABILITY_ID_BYTES: usize = 128;
/// Maximum byte length of a capability semantic version.
pub const MAX_CAPABILITY_VERSION_BYTES: usize = 32;
/// Maximum UTF-8 byte length of a capability title.
pub const MAX_TITLE_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a capability description.
pub const MAX_DESCRIPTION_BYTES: usize = 2_048;
/// Maximum byte length of a permission name.
pub const MAX_PERMISSION_BYTES: usize = 128;
/// Maximum byte length of a data-policy reference.
pub const MAX_DATA_POLICY_REF_BYTES: usize = 256;
/// Maximum byte length of an idempotency key.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
/// W3C Trace Context's maximum `tracestate` length.
pub const MAX_TRACE_STATE_BYTES: usize = 512;
/// W3C Trace Context's maximum number of `tracestate` list members.
pub const MAX_TRACE_STATE_MEMBERS: usize = 32;

/// A bounded owned value was empty, excessive, or malformed.
///
/// The rejected value is deliberately absent from this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueError {
    /// The value must not be empty.
    #[error("value must not be empty")]
    Empty,
    /// The value exceeded its fixed byte limit.
    #[error("value exceeds its fixed byte limit")]
    TooLong,
    /// The value contained a character outside its grammar.
    #[error("value contains a forbidden character")]
    InvalidCharacter,
    /// The value did not conform to its required structure.
    #[error("value has an invalid format")]
    InvalidFormat,
}

macro_rules! owned_string_type {
    ($name:ident, $doc:literal, $validator:ident, $schema:expr) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a string value.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError`] when the value violates this type's grammar or bound.
            pub fn new(value: String) -> Result<Self, ValueError> {
                $validator(&value)?;
                Ok(Self(value))
            }

            /// Borrows the validated string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value.to_owned())
            }
        }

        impl TryFrom<String> for $name {
            type Error = ValueError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Value::deserialize(deserializer)
                    .map_err(|_| D::Error::custom(ValueError::InvalidFormat))?;
                let Value::String(value) = value else {
                    return Err(D::Error::custom(ValueError::InvalidFormat));
                };
                Self::new(value).map_err(D::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn schema_id() -> Cow<'static, str> {
                concat!(module_path!(), "::", stringify!($name)).into()
            }

            fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
                $schema
            }
        }
    };
}

owned_string_type!(
    CapabilityId,
    "A stable, lower-case capability identifier.",
    validate_capability_id,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[a-z][a-z0-9.-]*$"
    })
);

owned_string_type!(
    CapabilityVersion,
    "A bounded `major.minor.patch` capability version.",
    validate_capability_version,
    schemars::json_schema!({
        "type": "string",
        "minLength": 5,
        "maxLength": 32,
        "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
    })
);

owned_string_type!(
    CapabilityTitle,
    "A short human-readable capability title.",
    validate_title,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128
    })
);

owned_string_type!(
    CapabilityDescription,
    "A bounded human-readable capability description.",
    validate_description,
    schemars::json_schema!({
        "type": "string",
        "maxLength": 2048
    })
);

owned_string_type!(
    Permission,
    "A stable permission required by a capability.",
    validate_permission,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 128,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]*$"
    })
);

owned_string_type!(
    DataPolicyRef,
    "A bounded reference to the authoritative data-handling policy.",
    validate_data_policy_ref,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/#-]*$"
    })
);

owned_string_type!(
    IdempotencyKey,
    "A bounded opaque idempotency key.",
    validate_idempotency_key,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "pattern": "^[!-~]+$"
    })
);

owned_string_type!(
    TraceParent,
    "A validated W3C `traceparent` value using the version `00` wire format.",
    validate_traceparent,
    schemars::json_schema!({
        "type": "string",
        "minLength": 55,
        "maxLength": 55,
        "pattern": "^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"
    })
);

owned_string_type!(
    TraceState,
    "A bounded W3C `tracestate` list.",
    validate_tracestate,
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 512
    })
);

/// Validated, owned W3C trace propagation fields.
#[derive(Clone, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceContext {
    traceparent: TraceParent,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tracestate: Option<TraceState>,
}

impl TraceContext {
    /// Creates a trace context from individually validated fields.
    #[must_use]
    pub fn new(traceparent: TraceParent, tracestate: Option<TraceState>) -> Self {
        Self {
            traceparent,
            tracestate,
        }
    }

    /// Returns the W3C parent trace identifier and flags.
    #[must_use]
    pub const fn traceparent(&self) -> &TraceParent {
        &self.traceparent
    }

    /// Returns the optional W3C vendor state list.
    #[must_use]
    pub const fn tracestate(&self) -> Option<&TraceState> {
        self.tracestate.as_ref()
    }
}

impl<'de> Deserialize<'de> for TraceContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)
            .map_err(|_| D::Error::custom(ValueError::InvalidFormat))?;
        let Value::Object(object) = &value else {
            return Err(D::Error::custom(ValueError::InvalidFormat));
        };
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "traceparent" | "tracestate"))
        {
            return Err(D::Error::custom(ValueError::InvalidFormat));
        }
        let wire: TraceContextWire = serde_json::from_value(value)
            .map_err(|_| D::Error::custom(ValueError::InvalidFormat))?;
        Ok(Self::new(wire.traceparent, wire.tracestate))
    }
}

#[derive(Deserialize)]
struct TraceContextWire {
    traceparent: TraceParent,
    #[serde(default)]
    tracestate: Option<TraceState>,
}

impl fmt::Debug for TraceContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TraceContext([redacted])")
    }
}

fn validate_capability_id(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_CAPABILITY_ID_BYTES)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ValueError::Empty);
    };
    if !first.is_ascii_lowercase()
        || !bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte))
    {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_capability_version(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_CAPABILITY_VERSION_BYTES)?;
    let mut parts = value.split('.');
    for _ in 0..3 {
        let Some(part) = parts.next() else {
            return Err(ValueError::InvalidFormat);
        };
        if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ValueError::InvalidFormat);
        }
    }
    if parts.next().is_some() {
        return Err(ValueError::InvalidFormat);
    }
    Ok(())
}

fn validate_title(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_TITLE_BYTES)?;
    if value.chars().any(char::is_control) {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_description(value: &str) -> Result<(), ValueError> {
    validate_bound(value, MAX_DESCRIPTION_BYTES)?;
    if value
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_permission(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_PERMISSION_BYTES)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ValueError::Empty);
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_data_policy_ref(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_DATA_POLICY_REF_BYTES)?;
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ValueError::Empty);
    };
    if !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._:/#-".contains(&byte))
    {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_idempotency_key(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_IDEMPOTENCY_KEY_BYTES)?;
    if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(ValueError::InvalidCharacter);
    }
    Ok(())
}

fn validate_traceparent(value: &str) -> Result<(), ValueError> {
    if value.len() != 55 {
        return Err(ValueError::InvalidFormat);
    }
    let bytes = value.as_bytes();
    if &bytes[0..3] != b"00-" || bytes[35] != b'-' || bytes[52] != b'-' {
        return Err(ValueError::InvalidFormat);
    }
    let trace_id = &bytes[3..35];
    let parent_id = &bytes[36..52];
    let flags = &bytes[53..55];
    if !trace_id
        .iter()
        .chain(parent_id)
        .chain(flags)
        .all(u8::is_ascii_hexdigit)
        || trace_id
            .iter()
            .chain(parent_id)
            .chain(flags)
            .any(u8::is_ascii_uppercase)
        || trace_id.iter().all(|byte| *byte == b'0')
        || parent_id.iter().all(|byte| *byte == b'0')
    {
        return Err(ValueError::InvalidFormat);
    }
    Ok(())
}

fn validate_tracestate(value: &str) -> Result<(), ValueError> {
    validate_nonempty_bound(value, MAX_TRACE_STATE_BYTES)?;
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'\t' | 0x20..=0x7e))
    {
        return Err(ValueError::InvalidCharacter);
    }

    let member_count = value.split(',').count();
    if member_count > MAX_TRACE_STATE_MEMBERS {
        return Err(ValueError::TooLong);
    }

    for (index, raw_member) in value.split(',').enumerate() {
        let member = raw_member.trim_matches(|character| matches!(character, ' ' | '\t'));
        let Some((key, member_value)) = member.split_once('=') else {
            return Err(ValueError::InvalidFormat);
        };
        if !valid_tracestate_key(key)
            || member_value.is_empty()
            || member_value.ends_with(' ')
            || !member_value
                .bytes()
                .all(|byte| matches!(byte, 0x20..=0x2b | 0x2d..=0x3c | 0x3e..=0x7e))
        {
            return Err(ValueError::InvalidFormat);
        }
        if value
            .split(',')
            .skip(index + 1)
            .filter_map(|candidate| {
                candidate
                    .trim_matches(|character| matches!(character, ' ' | '\t'))
                    .split_once('=')
            })
            .any(|(candidate_key, _)| candidate_key == key)
        {
            return Err(ValueError::InvalidFormat);
        }
    }
    Ok(())
}

fn valid_tracestate_key(key: &str) -> bool {
    if key.is_empty() || key.len() > 256 {
        return false;
    }
    let mut at_parts = key.split('@');
    let Some(first) = at_parts.next() else {
        return false;
    };
    let second = at_parts.next();
    if at_parts.next().is_some() {
        return false;
    }
    let valid_part = |part: &str, max_len: usize, digit_may_start: bool| {
        !part.is_empty()
            && part.len() <= max_len
            && (part.as_bytes()[0].is_ascii_lowercase()
                || (digit_may_start && part.as_bytes()[0].is_ascii_digit()))
            && part.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'*' | b'/')
            })
    };
    match second {
        Some(system) => valid_part(first, 241, true) && valid_part(system, 14, false),
        None => valid_part(first, 256, false),
    }
}

fn validate_nonempty_bound(value: &str, maximum: usize) -> Result<(), ValueError> {
    if value.is_empty() {
        return Err(ValueError::Empty);
    }
    validate_bound(value, maximum)
}

fn validate_bound(value: &str, maximum: usize) -> Result<(), ValueError> {
    if value.len() > maximum {
        return Err(ValueError::TooLong);
    }
    Ok(())
}
