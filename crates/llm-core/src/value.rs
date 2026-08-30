use std::{borrow::Cow, collections::BTreeMap, fmt};

use omnius_core::RequestId;
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::Value;
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};

/// A deterministically ordered, owned JSON object.
pub type JsonObject = BTreeMap<String, Value>;

/// A canonical contract value violated a fixed invariant.
///
/// Rejected values are deliberately absent from this error's `Debug` and `Display`
/// representations.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ContractError {
    /// The only supported schema version was not supplied.
    #[error("unsupported LLM contract schema version")]
    UnsupportedSchemaVersion,
    /// A stable identifier was empty.
    #[error("stable identifier must not be empty")]
    EmptyIdentifier,
    /// A stable name was empty.
    #[error("stable name must not be empty")]
    EmptyName,
    /// A MIME type was empty.
    #[error("MIME type must not be empty")]
    EmptyMimeType,
    /// A URI or binary reference was empty or malformed.
    #[error("URI or binary reference is invalid")]
    InvalidReference,
    /// A route revision was zero.
    #[error("route revision must be positive")]
    InvalidRevision,
    /// A required capability occurred more than once.
    #[error("required capabilities must be unique")]
    DuplicateRequiredCapability,
    /// A preferred capability occurred more than once.
    #[error("preferred capabilities must be unique")]
    DuplicatePreferredCapability,
    /// A declared tool name occurred more than once.
    #[error("tool names must be unique")]
    DuplicateToolName,
    /// A generation probability was outside its canonical range.
    #[error("top-p must be finite and between zero and one")]
    InvalidTopP,
    /// A floating-point generation control was not finite.
    #[error("generation controls must be finite")]
    NonFiniteGenerationControl,
    /// A limit that must be positive was zero.
    #[error("required limit must be positive")]
    InvalidPositiveLimit,
    /// A response candidate index occurred more than once.
    #[error("candidate indices must be unique")]
    DuplicateCandidateIndex,
    /// A selected candidate index did not identify a retained candidate.
    #[error("selected candidate is not retained")]
    SelectedCandidateMissing,
    /// The selected/default output differed from the selected candidate output.
    #[error("selected output does not match the selected candidate")]
    SelectedOutputMismatch,
    /// A nested content part violated a canonical invariant.
    #[error("content part is invalid")]
    InvalidContent,
}

/// The fixed version of the canonical LLM request and response wire contracts.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SchemaVersion {
    /// Version `1.0.0`.
    #[default]
    V1_0_0,
}

impl SchemaVersion {
    /// The current fixed schema version.
    pub const CURRENT: Self = Self::V1_0_0;

    /// Returns the version's exact wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        "1.0.0"
    }
}

impl Serialize for SchemaVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)
            .map_err(|_| D::Error::custom(ContractError::UnsupportedSchemaVersion))?;
        if value == Self::CURRENT.as_str() {
            Ok(Self::CURRENT)
        } else {
            Err(D::Error::custom(ContractError::UnsupportedSchemaVersion))
        }
    }
}

impl JsonSchema for SchemaVersion {
    fn schema_name() -> Cow<'static, str> {
        "SchemaVersion".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::SchemaVersion").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"type": "string", "const": "1.0.0"})
    }
}

/// An owned request correlation identifier from the canonical LLM wire contract.
///
/// The fixed examples intentionally use opaque identifiers rather than UUIDs. Runtime
/// correlation IDs convert losslessly through [`From<RequestId>`].
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct LlmRequestId(String);

impl LlmRequestId {
    /// Validates and owns an opaque request identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::EmptyIdentifier`] when the identifier is empty.
    pub fn new(value: String) -> Result<Self, ContractError> {
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// Borrows the exact opaque wire identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<RequestId> for LlmRequestId {
    fn from(value: RequestId) -> Self {
        Self(value.to_string())
    }
}

impl TryFrom<String> for LlmRequestId {
    type Error = ContractError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl AsRef<str> for LlmRequestId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for LlmRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LlmRequestId([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for LlmRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)
            .map_err(|_| D::Error::custom(ContractError::EmptyIdentifier))?;
        Self::new(value).map_err(D::Error::custom)
    }
}

impl JsonSchema for LlmRequestId {
    fn schema_name() -> Cow<'static, str> {
        "LlmRequestId".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::LlmRequestId").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1
        })
    }
}

/// An RFC 3339 instant normalized to the UTC offset.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UtcTimestamp(OffsetDateTime);

impl UtcTimestamp {
    /// Normalizes an instant to UTC.
    #[must_use]
    pub const fn new(value: OffsetDateTime) -> Self {
        Self(value.to_offset(UtcOffset::UTC))
    }

    /// Returns the normalized UTC instant.
    #[must_use]
    pub const fn get(self) -> OffsetDateTime {
        self.0
    }
}

impl fmt::Debug for UtcTimestamp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("UtcTimestamp")
            .field(&self.0)
            .finish()
    }
}

impl Serialize for UtcTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        time::serde::rfc3339::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for UtcTimestamp {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        time::serde::rfc3339::deserialize(deserializer).map(Self::new)
    }
}

impl JsonSchema for UtcTimestamp {
    fn schema_name() -> Cow<'static, str> {
        "UtcTimestamp".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::UtcTimestamp").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({"type": "string", "format": "date-time"})
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RequiredNullable<T>(Option<T>);

impl<T> RequiredNullable<T> {
    pub(crate) const fn new(value: Option<T>) -> Self {
        Self(value)
    }

    pub(crate) const fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

pub(crate) fn deserialize_optional_non_null<'de, D, T>(
    deserializer: D,
) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

pub(crate) fn validate_identifier(value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::EmptyIdentifier)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_name(value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::EmptyName)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_mime_type(value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::EmptyMimeType)
    } else {
        Ok(())
    }
}

pub(crate) fn validate_reference(value: &str) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        Err(ContractError::InvalidReference)
    } else {
        Ok(())
    }
}
