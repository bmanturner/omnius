use std::{fmt, str::FromStr, sync::Arc};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use thiserror::Error;
use uuid::{Uuid, Variant, Version};

/// The only protocol version accepted or emitted by this crate.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum encoded size of one JSON envelope.
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 byte length of a message type.
pub const MAX_MESSAGE_TYPE_BYTES: usize = 128;
/// Maximum UTF-8 byte length of a topic.
pub const MAX_TOPIC_BYTES: usize = 128;
/// Maximum byte length of an opaque cursor.
pub const MAX_CURSOR_BYTES: usize = 256;
/// Maximum conservatively measured size of an object payload.
pub const MAX_PAYLOAD_BYTES: usize = 12 * 1024;
/// Maximum number of JSON values in one object payload.
pub const MAX_PAYLOAD_NODES: usize = 1_024;
/// Maximum nesting depth of an object payload.
pub const MAX_PAYLOAD_DEPTH: usize = 32;

/// The inbound command type for creating a subscription.
pub const SUBSCRIBE_MESSAGE_TYPE: &str = "subscription.create";
/// The inbound command type for deleting a subscription.
pub const UNSUBSCRIBE_MESSAGE_TYPE: &str = "subscription.delete";
/// The inbound heartbeat command type.
pub const PING_MESSAGE_TYPE: &str = "ping";
/// The accepted reply type for a created subscription.
pub const SUBSCRIPTION_CREATED_MESSAGE_TYPE: &str = "subscription.created";
/// The accepted reply type for a deleted subscription.
pub const SUBSCRIPTION_DELETED_MESSAGE_TYPE: &str = "subscription.deleted";
/// The rejected command reply type.
pub const COMMAND_REJECTED_MESSAGE_TYPE: &str = "command.rejected";
/// The heartbeat control reply type.
pub const PONG_MESSAGE_TYPE: &str = "pong";
/// The subscription-revoked control type.
pub const SUBSCRIPTION_REVOKED_MESSAGE_TYPE: &str = "subscription.revoked";

/// A wire identifier was malformed, non-canonical, or not a `UUIDv7` value.
///
/// Rejected input is deliberately never retained by this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WireIdError {
    /// The input was not a UUID.
    #[error("realtime identifier is not a valid UUID")]
    InvalidUuid,
    /// The input was not the lower-case hyphenated canonical UUID representation.
    #[error("realtime identifier is not canonical")]
    NonCanonical,
    /// The UUID was not an RFC-compatible version 7 UUID.
    #[error("realtime identifier must be a UUIDv7 value")]
    NotVersion7,
}

fn parse_uuid_v7(value: &str) -> Result<Uuid, WireIdError> {
    let uuid = Uuid::parse_str(value).map_err(|_| WireIdError::InvalidUuid)?;
    let mut buffer = Uuid::encode_buffer();
    if uuid.hyphenated().encode_lower(&mut buffer) != value {
        return Err(WireIdError::NonCanonical);
    }
    if uuid.get_version() != Some(Version::SortRand) || uuid.get_variant() != Variant::RFC4122 {
        return Err(WireIdError::NotVersion7);
    }
    Ok(uuid)
}

macro_rules! wire_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Validates an existing UUID.
            ///
            /// # Errors
            ///
            /// Returns [`WireIdError::NotVersion7`] unless `value` is an RFC-compatible `UUIDv7`.
            pub fn from_uuid(value: Uuid) -> Result<Self, WireIdError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(WireIdError::NotVersion7)
                }
            }

            /// Returns the underlying UUID.
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
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut buffer = Uuid::encode_buffer();
                formatter.write_str(self.0.hyphenated().encode_lower(&mut buffer))
            }
        }

        impl FromStr for $name {
            type Err = WireIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                parse_uuid_v7(value).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut buffer = Uuid::encode_buffer();
                serializer.serialize_str(self.0.hyphenated().encode_lower(&mut buffer))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                value.parse().map_err(D::Error::custom)
            }
        }
    };
}

wire_id!(
    MessageId,
    "A canonical `UUIDv7` protocol-message identifier."
);
wire_id!(ConnectionId, "A canonical `UUIDv7` connection identifier.");
wire_id!(
    SubscriptionId,
    "A canonical `UUIDv7` subscription identifier."
);

/// A portable bounded string was invalid.
///
/// Rejected input is deliberately never retained by this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PortableStringError {
    /// The value was empty.
    #[error("portable realtime value cannot be empty")]
    Empty,
    /// The value exceeded its fixed byte limit.
    #[error("portable realtime value exceeds its byte limit")]
    TooLong,
    /// The value contained a non-portable character.
    #[error("portable realtime value contains an invalid character")]
    InvalidCharacter,
}

fn validate_portable_identifier(
    value: &str,
    max_bytes: usize,
    allow_slash: bool,
) -> Result<(), PortableStringError> {
    if value.is_empty() {
        return Err(PortableStringError::Empty);
    }
    if value.len() > max_bytes {
        return Err(PortableStringError::TooLong);
    }
    if !value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(byte, b'.' | b'_' | b':' | b'-')
            || (allow_slash && byte == b'/')
    }) {
        return Err(PortableStringError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! portable_identifier {
    ($name:ident, $description:literal, $max:expr, $slash:expr) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates and owns a portable identifier.
            ///
            /// # Errors
            ///
            /// Returns [`PortableStringError`] for an empty, oversized, or non-portable value.
            pub fn new(value: impl AsRef<str>) -> Result<Self, PortableStringError> {
                let value = value.as_ref();
                validate_portable_identifier(value, $max, $slash)?;
                Ok(Self(Arc::from(value)))
            }

            /// Returns the validated identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = PortableStringError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
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
                let value = String::deserialize(deserializer)?;
                validate_portable_identifier(&value, $max, $slash).map_err(D::Error::custom)?;
                Ok(Self(Arc::from(value)))
            }
        }
    };
}

portable_identifier!(
    MessageType,
    "A bounded portable protocol message type.",
    MAX_MESSAGE_TYPE_BYTES,
    false
);
portable_identifier!(
    Topic,
    "A bounded portable routing topic. A topic carries no authorization meaning.",
    MAX_TOPIC_BYTES,
    true
);

/// An opaque, bounded resume cursor.
///
/// The core validates and preserves this value but never interprets it or promises replay.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OpaqueCursor(Arc<str>);

impl OpaqueCursor {
    /// Validates and owns an opaque cursor.
    ///
    /// # Errors
    ///
    /// Returns [`PortableStringError`] for an empty cursor, a cursor longer than
    /// [`MAX_CURSOR_BYTES`], or a cursor containing bytes outside visible ASCII.
    pub fn new(value: impl AsRef<str>) -> Result<Self, PortableStringError> {
        let value = value.as_ref();
        if value.is_empty() {
            return Err(PortableStringError::Empty);
        }
        if value.len() > MAX_CURSOR_BYTES {
            return Err(PortableStringError::TooLong);
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(PortableStringError::InvalidCharacter);
        }
        Ok(Self(Arc::from(value)))
    }

    /// Returns the cursor without interpreting it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for OpaqueCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for OpaqueCursor {
    type Err = PortableStringError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for OpaqueCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OpaqueCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A JSON object violated the fixed payload bounds.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PayloadError {
    /// The payload exceeded the conservative encoded-size bound.
    #[error("realtime payload exceeds its size limit")]
    TooLarge,
    /// The payload contained too many JSON values.
    #[error("realtime payload exceeds its node limit")]
    TooManyNodes,
    /// The payload nested too deeply.
    #[error("realtime payload exceeds its depth limit")]
    TooDeep,
}

fn checked_payload_add(total: &mut usize, amount: usize) -> Result<(), PayloadError> {
    *total = total.checked_add(amount).ok_or(PayloadError::TooLarge)?;
    if *total > MAX_PAYLOAD_BYTES {
        return Err(PayloadError::TooLarge);
    }
    Ok(())
}

fn measure_value(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
    bytes: &mut usize,
) -> Result<(), PayloadError> {
    if depth > MAX_PAYLOAD_DEPTH {
        return Err(PayloadError::TooDeep);
    }
    *nodes = nodes.checked_add(1).ok_or(PayloadError::TooManyNodes)?;
    if *nodes > MAX_PAYLOAD_NODES {
        return Err(PayloadError::TooManyNodes);
    }

    match value {
        Value::Null => checked_payload_add(bytes, 4),
        Value::Bool(_) => checked_payload_add(bytes, 5),
        Value::Number(_) => checked_payload_add(bytes, 32),
        Value::String(value) => {
            checked_payload_add(bytes, value.len().saturating_mul(6).saturating_add(2))
        }
        Value::Array(values) => {
            checked_payload_add(bytes, values.len().saturating_add(2))?;
            for value in values {
                measure_value(value, depth + 1, nodes, bytes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            checked_payload_add(bytes, values.len().saturating_add(2))?;
            for (key, value) in values {
                checked_payload_add(bytes, key.len().saturating_mul(6).saturating_add(3))?;
                measure_value(value, depth + 1, nodes, bytes)?;
            }
            Ok(())
        }
    }
}
fn measure_object(values: &Map<String, Value>) -> Result<(), PayloadError> {
    let mut nodes = 1;
    let mut bytes = 0;
    checked_payload_add(&mut bytes, values.len().saturating_add(2))?;
    for (key, value) in values {
        checked_payload_add(&mut bytes, key.len().saturating_mul(6).saturating_add(3))?;
        measure_value(value, 2, &mut nodes, &mut bytes)?;
    }
    Ok(())
}

fn canonicalize_value(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                canonicalize_value(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                canonicalize_value(value);
            }
            values.sort_keys();
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// A bounded JSON object suitable for a protocol payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ObjectPayload(Map<String, Value>);

impl ObjectPayload {
    /// Validates and owns a JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`PayloadError`] when the object exceeds its size, node, or depth limit.
    pub fn new(mut values: Map<String, Value>) -> Result<Self, PayloadError> {
        measure_object(&values)?;
        for value in values.values_mut() {
            canonicalize_value(value);
        }
        values.sort_keys();
        Ok(Self(values))
    }

    /// Creates an empty object payload.
    #[must_use]
    pub fn empty() -> Self {
        Self(Map::new())
    }

    /// Borrows the bounded object.
    #[must_use]
    pub const fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    /// Consumes the wrapper and returns the object.
    #[must_use]
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }
}

/// A stable, redacted protocol decoding failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProtocolError {
    /// Input exceeded [`MAX_ENVELOPE_BYTES`] before JSON decoding began.
    #[error("realtime envelope exceeds its byte limit")]
    EnvelopeTooLarge,
    /// The envelope was malformed, omitted a required field, or contained an unknown field.
    #[error("realtime envelope is invalid")]
    InvalidEnvelope,
    /// The protocol version was not [`PROTOCOL_VERSION`].
    #[error("realtime protocol version is unsupported")]
    UnsupportedVersion,
    /// A message or correlation identifier was invalid.
    #[error("realtime envelope contains an invalid identifier")]
    InvalidIdentifier,
    /// The message type was not a bounded portable identifier.
    #[error("realtime envelope contains an invalid message type")]
    InvalidMessageType,
    /// The command type is valid but unsupported by this protocol version.
    #[error("realtime command type is unknown")]
    UnknownCommand,
    /// The payload was not an object or did not match the selected message schema.
    #[error("realtime payload is invalid")]
    InvalidPayload,
    /// The object payload exceeded a fixed structural bound.
    #[error("realtime payload exceeds a structural limit")]
    PayloadOutOfBounds,
}

/// Crate-internal JSON value decoded with duplicate-key rejection.
pub(crate) struct StrictValue(
    /// The strictly decoded JSON value.
    pub(crate) Value,
);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = StrictValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_i128<E>(self, value: i128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        i64::try_from(value)
            .map_err(|_| E::custom("JSON integer is out of range"))
            .and_then(|value| self.visit_i64(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Number(value.into())))
    }

    fn visit_u128<E>(self, value: u128) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        u64::try_from(value)
            .map_err(|_| E::custom("JSON integer is out of range"))
            .and_then(|value| self.visit_u64(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictValue)
            .ok_or_else(|| E::custom("JSON number is not finite"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0));
        while let Some(StrictValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(StrictValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
            let StrictValue(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(StrictValue(Value::Object(values)))
    }
}

/// Crate-internal wrapper requiring a nullable field to be present.
#[derive(Deserialize)]
pub(crate) struct RequiredNullable<T>(
    /// The present field value, which may explicitly be null.
    pub(crate) Option<T>,
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecodedEnvelope {
    v: u16,
    id: String,
    #[serde(rename = "type")]
    message_type: String,
    correlation_id: RequiredNullable<String>,
    payload: StrictValue,
}

/// The exact v1 JSON envelope used in both directions.
///
/// All five fields are always serialized. A missing correlation identifier is encoded as `null`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProtocolEnvelope {
    v: u16,
    id: MessageId,
    #[serde(rename = "type")]
    message_type: MessageType,
    correlation_id: Option<MessageId>,
    payload: ObjectPayload,
}

impl ProtocolEnvelope {
    /// Creates a bounded version-1 envelope with a fresh message identifier.
    #[must_use]
    pub fn new(
        message_type: MessageType,
        correlation_id: Option<MessageId>,
        payload: ObjectPayload,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id: MessageId::new(),
            message_type,
            correlation_id,
            payload,
        }
    }

    /// Creates a bounded version-1 envelope with an explicit identifier.
    #[must_use]
    pub const fn with_id(
        id: MessageId,
        message_type: MessageType,
        correlation_id: Option<MessageId>,
        payload: ObjectPayload,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            message_type,
            correlation_id,
            payload,
        }
    }

    /// Parses an exact, bounded version-1 envelope.
    ///
    /// The input byte limit is checked before JSON decoding or string allocation.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`ProtocolError`] for malformed, unsupported, or excessive input.
    pub fn parse(input: &[u8]) -> Result<Self, ProtocolError> {
        if input.len() > MAX_ENVELOPE_BYTES {
            return Err(ProtocolError::EnvelopeTooLarge);
        }
        let decoded: DecodedEnvelope =
            serde_json::from_slice(input).map_err(|_| ProtocolError::InvalidEnvelope)?;
        if decoded.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        let id = decoded
            .id
            .parse()
            .map_err(|_| ProtocolError::InvalidIdentifier)?;
        let correlation_id = decoded
            .correlation_id
            .0
            .map(|value| value.parse())
            .transpose()
            .map_err(|_| ProtocolError::InvalidIdentifier)?;
        let message_type = MessageType::new(decoded.message_type)
            .map_err(|_| ProtocolError::InvalidMessageType)?;
        let Value::Object(payload) = decoded.payload.0 else {
            return Err(ProtocolError::InvalidPayload);
        };
        let payload = ObjectPayload::new(payload).map_err(|_| ProtocolError::PayloadOutOfBounds)?;
        Ok(Self::with_id(id, message_type, correlation_id, payload))
    }

    /// Encodes the exact five-field JSON envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::EnvelopeTooLarge`] if the encoded form exceeds the wire limit.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let encoded = serde_json::to_vec(self).map_err(|_| ProtocolError::InvalidEnvelope)?;
        if encoded.len() > MAX_ENVELOPE_BYTES {
            return Err(ProtocolError::EnvelopeTooLarge);
        }
        Ok(encoded)
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.v
    }

    /// Returns the message identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.id
    }

    /// Returns the validated message type.
    #[must_use]
    pub const fn message_type(&self) -> &MessageType {
        &self.message_type
    }

    /// Returns the optional request correlation identifier.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<MessageId> {
        self.correlation_id
    }

    /// Returns the bounded object payload.
    #[must_use]
    pub const fn payload(&self) -> &ObjectPayload {
        &self.payload
    }
}

/// The validated payload of `subscription.create`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubscribeCommand {
    subscription_id: SubscriptionId,
    topic: Topic,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cursor: Option<OpaqueCursor>,
}

impl SubscribeCommand {
    /// Creates a validated subscribe command.
    #[must_use]
    pub const fn new(
        subscription_id: SubscriptionId,
        topic: Topic,
        cursor: Option<OpaqueCursor>,
    ) -> Self {
        Self {
            subscription_id,
            topic,
            cursor,
        }
    }

    /// Returns the client-selected subscription identifier.
    #[must_use]
    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    /// Returns the routing topic, which carries no authorization meaning.
    #[must_use]
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Returns the uninterpreted resume cursor.
    #[must_use]
    pub const fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }
}

/// The validated payload of `subscription.delete`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UnsubscribeCommand {
    subscription_id: SubscriptionId,
}

impl UnsubscribeCommand {
    /// Creates a validated unsubscribe command.
    #[must_use]
    pub const fn new(subscription_id: SubscriptionId) -> Self {
        Self { subscription_id }
    }

    /// Returns the target subscription identifier.
    #[must_use]
    pub const fn subscription_id(self) -> SubscriptionId {
        self.subscription_id
    }
}

/// The empty validated payload of `ping`.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PingCommand {}

impl PingCommand {
    /// Creates an empty ping command.
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

fn payload_from_serializable<T>(value: &T) -> Result<ObjectPayload, ProtocolError>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).map_err(|_| ProtocolError::InvalidPayload)?;
    let Value::Object(values) = value else {
        return Err(ProtocolError::InvalidPayload);
    };
    ObjectPayload::new(values).map_err(|_| ProtocolError::PayloadOutOfBounds)
}

/// A fully validated inbound command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InboundCommand {
    /// Create a tenant-scoped subscription.
    Subscribe {
        /// The command message identifier.
        id: MessageId,
        /// An optional upstream correlation identifier.
        correlation_id: Option<MessageId>,
        /// The validated command payload.
        command: SubscribeCommand,
    },
    /// Delete an existing subscription.
    Unsubscribe {
        /// The command message identifier.
        id: MessageId,
        /// An optional upstream correlation identifier.
        correlation_id: Option<MessageId>,
        /// The validated command payload.
        command: UnsubscribeCommand,
    },
    /// Validate and authorize a heartbeat command.
    Ping {
        /// The command message identifier.
        id: MessageId,
        /// An optional upstream correlation identifier.
        correlation_id: Option<MessageId>,
        /// The validated empty command payload.
        command: PingCommand,
    },
}

impl InboundCommand {
    /// Parses, validates, and selects one supported v1 command.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`ProtocolError`] for invalid envelopes, unknown commands, and payloads
    /// that do not match the selected command schema.
    pub fn parse(input: &[u8]) -> Result<Self, ProtocolError> {
        Self::from_envelope(ProtocolEnvelope::parse(input)?)
    }

    /// Selects and validates a command from an already validated envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnknownCommand`] for non-command message types and
    /// [`ProtocolError::InvalidPayload`] when the payload schema does not match.
    pub fn from_envelope(envelope: ProtocolEnvelope) -> Result<Self, ProtocolError> {
        let id = envelope.id;
        let correlation_id = envelope.correlation_id;
        let message_type = envelope.message_type;
        let payload = Value::Object(envelope.payload.into_map());
        match message_type.as_str() {
            SUBSCRIBE_MESSAGE_TYPE => {
                let command =
                    serde_json::from_value(payload).map_err(|_| ProtocolError::InvalidPayload)?;
                Ok(Self::Subscribe {
                    id,
                    correlation_id,
                    command,
                })
            }
            UNSUBSCRIBE_MESSAGE_TYPE => {
                let command =
                    serde_json::from_value(payload).map_err(|_| ProtocolError::InvalidPayload)?;
                Ok(Self::Unsubscribe {
                    id,
                    correlation_id,
                    command,
                })
            }
            PING_MESSAGE_TYPE => {
                let command =
                    serde_json::from_value(payload).map_err(|_| ProtocolError::InvalidPayload)?;
                Ok(Self::Ping {
                    id,
                    correlation_id,
                    command,
                })
            }
            _ => Err(ProtocolError::UnknownCommand),
        }
    }

    /// Builds the exact v1 envelope for this validated command.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] only if the bounded typed payload cannot be represented as an
    /// object.
    pub fn to_envelope(&self) -> Result<ProtocolEnvelope, ProtocolError> {
        match self {
            Self::Subscribe {
                id,
                correlation_id,
                command,
            } => Ok(ProtocolEnvelope::with_id(
                *id,
                MessageType::new(SUBSCRIBE_MESSAGE_TYPE)
                    .map_err(|_| ProtocolError::InvalidMessageType)?,
                *correlation_id,
                payload_from_serializable(command)?,
            )),
            Self::Unsubscribe {
                id,
                correlation_id,
                command,
            } => Ok(ProtocolEnvelope::with_id(
                *id,
                MessageType::new(UNSUBSCRIBE_MESSAGE_TYPE)
                    .map_err(|_| ProtocolError::InvalidMessageType)?,
                *correlation_id,
                payload_from_serializable(command)?,
            )),
            Self::Ping {
                id,
                correlation_id,
                command,
            } => Ok(ProtocolEnvelope::with_id(
                *id,
                MessageType::new(PING_MESSAGE_TYPE)
                    .map_err(|_| ProtocolError::InvalidMessageType)?,
                *correlation_id,
                payload_from_serializable(command)?,
            )),
        }
    }

    /// Returns the command message identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        match self {
            Self::Subscribe { id, .. } | Self::Unsubscribe { id, .. } | Self::Ping { id, .. } => {
                *id
            }
        }
    }

    /// Returns the declared application action name for this command.
    #[must_use]
    pub const fn declared_action(&self) -> &'static str {
        match self {
            Self::Subscribe { .. } => crate::service::SUBSCRIBE_ACTION,
            Self::Unsubscribe { .. } => crate::service::UNSUBSCRIBE_ACTION,
            Self::Ping { .. } => crate::service::PING_ACTION,
        }
    }
}

/// A stable public rejection category.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionCode {
    /// The command was not authorized or authoritative facts could not be resolved safely.
    Unauthorized,
    /// The connection is not active.
    ConnectionNotActive,
    /// The target does not exist for this connection.
    NotFound,
    /// The command conflicts with existing registry state.
    Conflict,
    /// A configured registry capacity was reached.
    CapacityExceeded,
    /// The registry could not safely complete the command.
    Unavailable,
}

impl RejectionCode {
    /// Returns a fixed public message containing no submitted identifiers, topics, or policy data.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "command is not authorized",
            Self::ConnectionNotActive => "connection is not active",
            Self::NotFound => "command target was not found",
            Self::Conflict => "command conflicts with current state",
            Self::CapacityExceeded => "realtime capacity is exhausted",
            Self::Unavailable => "realtime command is unavailable",
        }
    }
}

/// The successful effect represented by an accepted command reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptedKind {
    /// A subscription was created exactly once.
    SubscriptionCreated {
        /// The created subscription.
        subscription_id: SubscriptionId,
        /// The validated routing topic.
        topic: Topic,
    },
    /// A subscription was removed.
    SubscriptionDeleted {
        /// The removed subscription.
        subscription_id: SubscriptionId,
    },
}

/// A structured accepted command output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedOutput {
    id: MessageId,
    correlation_id: MessageId,
    kind: AcceptedKind,
}

impl AcceptedOutput {
    /// Creates a subscription-created reply correlated to `command_id`.
    #[must_use]
    pub fn subscription_created(
        command_id: MessageId,
        subscription_id: SubscriptionId,
        topic: Topic,
    ) -> Self {
        Self {
            id: MessageId::new(),
            correlation_id: command_id,
            kind: AcceptedKind::SubscriptionCreated {
                subscription_id,
                topic,
            },
        }
    }

    /// Creates a subscription-deleted reply correlated to `command_id`.
    #[must_use]
    pub fn subscription_deleted(command_id: MessageId, subscription_id: SubscriptionId) -> Self {
        Self {
            id: MessageId::new(),
            correlation_id: command_id,
            kind: AcceptedKind::SubscriptionDeleted { subscription_id },
        }
    }

    /// Returns the accepted effect.
    #[must_use]
    pub const fn kind(&self) -> &AcceptedKind {
        &self.kind
    }

    fn into_envelope(self) -> Result<ProtocolEnvelope, ProtocolError> {
        let (message_type, payload) = match self.kind {
            AcceptedKind::SubscriptionCreated {
                subscription_id,
                topic,
            } => {
                let mut payload = Map::new();
                payload.insert(
                    "subscription_id".into(),
                    Value::String(subscription_id.to_string()),
                );
                payload.insert("topic".into(), Value::String(topic.as_str().into()));
                (
                    SUBSCRIPTION_CREATED_MESSAGE_TYPE,
                    ObjectPayload::new(payload),
                )
            }
            AcceptedKind::SubscriptionDeleted { subscription_id } => {
                let mut payload = Map::new();
                payload.insert(
                    "subscription_id".into(),
                    Value::String(subscription_id.to_string()),
                );
                (
                    SUBSCRIPTION_DELETED_MESSAGE_TYPE,
                    ObjectPayload::new(payload),
                )
            }
        };
        Ok(ProtocolEnvelope::with_id(
            self.id,
            MessageType::new(message_type).map_err(|_| ProtocolError::InvalidMessageType)?,
            Some(self.correlation_id),
            payload.map_err(|_| ProtocolError::PayloadOutOfBounds)?,
        ))
    }
}

/// A structured rejected command output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectedOutput {
    id: MessageId,
    correlation_id: MessageId,
    code: RejectionCode,
}

impl RejectedOutput {
    /// Creates a redacted rejection correlated to `command_id`.
    #[must_use]
    pub fn new(command_id: MessageId, code: RejectionCode) -> Self {
        Self {
            id: MessageId::new(),
            correlation_id: command_id,
            code,
        }
    }

    /// Returns the stable rejection category.
    #[must_use]
    pub const fn code(self) -> RejectionCode {
        self.code
    }

    fn into_envelope(self) -> Result<ProtocolEnvelope, ProtocolError> {
        let mut payload = Map::new();
        payload.insert(
            "code".into(),
            serde_json::to_value(self.code).map_err(|_| ProtocolError::InvalidPayload)?,
        );
        payload.insert("message".into(), Value::String(self.code.message().into()));
        Ok(ProtocolEnvelope::with_id(
            self.id,
            MessageType::new(COMMAND_REJECTED_MESSAGE_TYPE)
                .map_err(|_| ProtocolError::InvalidMessageType)?,
            Some(self.correlation_id),
            ObjectPayload::new(payload).map_err(|_| ProtocolError::PayloadOutOfBounds)?,
        ))
    }
}

/// A stable reason for server-side subscription revocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Authoritative authorization facts changed.
    AuthorizationChanged,
    /// Authoritative tenant membership changed.
    MembershipChanged,
    /// The authenticated identity was revoked.
    IdentityRevoked,
    /// The subscribed resource ceased to exist.
    ResourceRemoved,
}

/// A structured adapter-neutral control output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlOutput {
    /// A successful authorized response to a ping command.
    Pong {
        /// The generated control-message identifier.
        id: MessageId,
        /// The ping command identifier.
        correlation_id: MessageId,
    },
    /// An active subscription was revoked server-side.
    SubscriptionRevoked {
        /// The generated control-message identifier.
        id: MessageId,
        /// The revoked subscription.
        subscription_id: SubscriptionId,
        /// The stable reason for revocation.
        reason: RevocationReason,
    },
}

impl ControlOutput {
    /// Creates a pong control output correlated to an authorized ping.
    #[must_use]
    pub fn pong(command_id: MessageId) -> Self {
        Self::Pong {
            id: MessageId::new(),
            correlation_id: command_id,
        }
    }

    /// Creates a server-initiated subscription-revoked control output.
    #[must_use]
    pub fn subscription_revoked(subscription_id: SubscriptionId, reason: RevocationReason) -> Self {
        Self::SubscriptionRevoked {
            id: MessageId::new(),
            subscription_id,
            reason,
        }
    }

    fn into_envelope(self) -> Result<ProtocolEnvelope, ProtocolError> {
        match self {
            Self::Pong { id, correlation_id } => Ok(ProtocolEnvelope::with_id(
                id,
                MessageType::new(PONG_MESSAGE_TYPE)
                    .map_err(|_| ProtocolError::InvalidMessageType)?,
                Some(correlation_id),
                ObjectPayload::empty(),
            )),
            Self::SubscriptionRevoked {
                id,
                subscription_id,
                reason,
            } => {
                let mut payload = Map::new();
                payload.insert(
                    "subscription_id".into(),
                    Value::String(subscription_id.to_string()),
                );
                payload.insert(
                    "reason".into(),
                    serde_json::to_value(reason).map_err(|_| ProtocolError::InvalidPayload)?,
                );
                Ok(ProtocolEnvelope::with_id(
                    id,
                    MessageType::new(SUBSCRIPTION_REVOKED_MESSAGE_TYPE)
                        .map_err(|_| ProtocolError::InvalidMessageType)?,
                    None,
                    ObjectPayload::new(payload).map_err(|_| ProtocolError::PayloadOutOfBounds)?,
                ))
            }
        }
    }
}

/// A bounded provider-neutral event output for one authorized subscription.
#[derive(Clone, Eq, PartialEq)]
pub struct EventOutput {
    id: MessageId,
    event_type: MessageType,
    correlation_id: Option<MessageId>,
    subscription_id: SubscriptionId,
    topic: Topic,
    cursor: Option<OpaqueCursor>,
    data: ObjectPayload,
}

impl EventOutput {
    /// Creates a bounded event projection with a fresh message identifier.
    #[must_use]
    pub fn new(
        event_type: MessageType,
        correlation_id: Option<MessageId>,
        subscription_id: SubscriptionId,
        topic: Topic,
        cursor: Option<OpaqueCursor>,
        data: ObjectPayload,
    ) -> Self {
        Self::with_id(
            MessageId::new(),
            event_type,
            correlation_id,
            subscription_id,
            topic,
            cursor,
            data,
        )
    }

    /// Creates a bounded event projection preserving a stable source identifier.
    #[must_use]
    pub const fn with_id(
        id: MessageId,
        event_type: MessageType,
        correlation_id: Option<MessageId>,
        subscription_id: SubscriptionId,
        topic: Topic,
        cursor: Option<OpaqueCursor>,
        data: ObjectPayload,
    ) -> Self {
        Self {
            id,
            event_type,
            correlation_id,
            subscription_id,
            topic,
            cursor,
            data,
        }
    }

    /// Returns the stable event identifier.
    #[must_use]
    pub const fn id(&self) -> MessageId {
        self.id
    }

    /// Returns the portable event type.
    #[must_use]
    pub const fn event_type(&self) -> &MessageType {
        &self.event_type
    }

    /// Returns the optional correlation identifier.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<MessageId> {
        self.correlation_id
    }

    /// Returns the target subscription.
    #[must_use]
    pub const fn subscription_id(&self) -> SubscriptionId {
        self.subscription_id
    }

    /// Returns the authoritative routing topic.
    #[must_use]
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Returns the genuine-replay cursor when one was supplied.
    #[must_use]
    pub const fn cursor(&self) -> Option<&OpaqueCursor> {
        self.cursor.as_ref()
    }

    /// Returns the bounded event data.
    #[must_use]
    pub const fn data(&self) -> &ObjectPayload {
        &self.data
    }

    fn into_envelope(self) -> Result<ProtocolEnvelope, ProtocolError> {
        let mut payload = Map::new();
        payload.insert(
            "subscription_id".into(),
            Value::String(self.subscription_id.to_string()),
        );
        payload.insert("topic".into(), Value::String(self.topic.as_str().into()));
        payload.insert(
            "cursor".into(),
            self.cursor
                .map_or(Value::Null, |cursor| Value::String(cursor.as_str().into())),
        );
        payload.insert("data".into(), Value::Object(self.data.into_map()));

        Ok(ProtocolEnvelope::with_id(
            self.id,
            self.event_type,
            self.correlation_id,
            ObjectPayload::new(payload).map_err(|_| ProtocolError::PayloadOutOfBounds)?,
        ))
    }
}

impl fmt::Debug for EventOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EventOutput { .. }")
    }
}

/// A structured outbound protocol message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OutboundMessage {
    /// A successful state-changing command reply.
    Accepted(AcceptedOutput),
    /// A stable redacted command rejection.
    Rejected(RejectedOutput),
    /// A bounded application event projection.
    Event(EventOutput),
    /// An adapter-neutral control message.
    Control(ControlOutput),
}

impl OutboundMessage {
    /// Converts the structured output into the exact v1 envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if the fully encoded event payload exceeds its fixed bound.
    pub fn into_envelope(self) -> Result<ProtocolEnvelope, ProtocolError> {
        match self {
            Self::Accepted(output) => output.into_envelope(),
            Self::Rejected(output) => output.into_envelope(),
            Self::Event(output) => output.into_envelope(),
            Self::Control(output) => output.into_envelope(),
        }
    }

    /// Encodes this output as an exact bounded v1 JSON envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if payload construction or final envelope encoding exceeds a
    /// fixed protocol bound.
    pub fn encode(self) -> Result<Vec<u8>, ProtocolError> {
        self.into_envelope()?.encode()
    }
}
