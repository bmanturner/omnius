use std::{fmt, num::NonZeroU64};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

const MAX_PROMPT_ID_BYTES: usize = 128;
const MAX_OPAQUE_ID_BYTES: usize = 256;
const MAX_UNTRUSTED_TEXT_BYTES: usize = 1_048_576;

/// A value-free failure to construct a bounded catalog value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ValueError {
    /// An identifier was empty, oversized, or contained unsupported bytes.
    #[error("identifier is invalid")]
    Identifier,
    /// A revision number was zero.
    #[error("revision is invalid")]
    Revision,
    /// A digest did not use the canonical 64-character lowercase hexadecimal encoding.
    #[error("digest is invalid")]
    Digest,
    /// Untrusted text exceeded the fixed catalog boundary.
    #[error("untrusted text exceeds its limit")]
    TextLimit,
}

fn validate_prompt_id(value: &str) -> Result<(), ValueError> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return Err(ValueError::Identifier);
    };
    if value.len() > MAX_PROMPT_ID_BYTES
        || !first.is_ascii_lowercase()
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(ValueError::Identifier);
    }
    Ok(())
}

fn validate_opaque_id(value: &str) -> Result<(), ValueError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-' | b'@')
        })
    {
        return Err(ValueError::Identifier);
    }
    Ok(())
}

macro_rules! bounded_id {
    ($name:ident, $doc:literal, $validator:ident) => {
        #[doc = $doc]
        #[derive(Clone, Eq, Ord, PartialEq, PartialOrd, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns an identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ValueError::Identifier`] when the value is empty, oversized, or malformed.
            pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
                let value = value.into();
                $validator(&value)?;
                Ok(Self(value))
            }

            /// Borrows the identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
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
                Self::new(value).map_err(|_| de::Error::custom("invalid bounded identifier"))
            }
        }
    };
}

bounded_id!(
    PromptId,
    "A stable catalog prompt identifier.",
    validate_prompt_id
);
bounded_id!(
    OwnerId,
    "The bounded owner identifier for a prompt.",
    validate_opaque_id
);
bounded_id!(
    RouteId,
    "A bounded logical LLM route identifier.",
    validate_opaque_id
);
bounded_id!(ToolId, "A bounded tool identifier.", validate_opaque_id);
bounded_id!(
    EvaluationSetId,
    "A bounded evaluation-set identifier.",
    validate_opaque_id
);
bounded_id!(
    TenantId,
    "A bounded tenant isolation identifier.",
    validate_opaque_id
);
bounded_id!(
    PrincipalId,
    "A bounded principal isolation identifier.",
    validate_opaque_id
);
bounded_id!(
    AuthorizationId,
    "A bounded authorization-decision identifier.",
    validate_opaque_id
);
bounded_id!(
    SourceId,
    "A bounded context-source identifier.",
    validate_opaque_id
);
bounded_id!(
    SourceRevisionId,
    "A bounded context-source revision identifier.",
    validate_opaque_id
);
bounded_id!(
    ModelRevisionId,
    "A bounded model revision identifier.",
    validate_opaque_id
);
bounded_id!(
    PolicyRevisionId,
    "A bounded policy revision identifier.",
    validate_opaque_id
);
bounded_id!(
    SchemaRevisionId,
    "A bounded schema revision identifier.",
    validate_opaque_id
);
bounded_id!(
    ToolRevisionId,
    "A bounded tool revision identifier.",
    validate_opaque_id
);
bounded_id!(
    CapabilityRevisionId,
    "A bounded capability-evidence revision identifier.",
    validate_opaque_id
);

/// A positive immutable prompt revision number.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PromptRevisionNumber(NonZeroU64);

impl PromptRevisionNumber {
    /// Creates a positive prompt revision number.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Revision`] for zero.
    pub fn new(value: u64) -> Result<Self, ValueError> {
        NonZeroU64::new(value).map(Self).ok_or(ValueError::Revision)
    }

    /// Returns the numeric revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Returns the following revision, if representable.
    #[must_use]
    pub fn checked_next(self) -> Option<Self> {
        self.get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .map(Self)
    }
}

/// A canonical SHA-256 digest used to bind immutable content and cache semantics.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentDigest([u8; 32]);

impl ContentDigest {
    /// Hashes bytes into a canonical digest.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parses the canonical lowercase hexadecimal representation.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::Digest`] for any non-canonical representation.
    pub fn from_hex(value: &str) -> Result<Self, ValueError> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ValueError::Digest);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_hex(pair[0]).ok_or(ValueError::Digest)?;
            let low = decode_hex(pair[1]).ok_or(ValueError::Digest)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }

    /// Returns the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns canonical lowercase hexadecimal without exposing source content.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in self.0 {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ContentDigest([REDACTED])")
    }
}

impl Serialize for ContentDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(|_| de::Error::custom("invalid digest"))
    }
}

fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// A bounded string that is always treated as untrusted data.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UntrustedText(String);

impl UntrustedText {
    /// Validates and owns untrusted text.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError::TextLimit`] when the UTF-8 byte length exceeds one MiB.
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.len() > MAX_UNTRUSTED_TEXT_BYTES {
            return Err(ValueError::TextLimit);
        }
        Ok(Self(value))
    }

    /// Borrows the untrusted text without changing its data classification.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the UTF-8 byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the text is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<String> for UntrustedText {
    type Error = ValueError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<UntrustedText> for String {
    fn from(value: UntrustedText) -> Self {
        value.0
    }
}

impl fmt::Debug for UntrustedText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UntrustedText([REDACTED])")
    }
}

/// Ordered data-classification ceiling used by catalog, retrieval, and cache policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum DataClassification {
    /// Public data.
    Public = 0,
    /// Non-public operational data.
    Internal = 1,
    /// Confidential tenant or user data.
    Confidential = 2,
    /// Restricted data requiring explicit handling approval.
    Restricted = 3,
}
