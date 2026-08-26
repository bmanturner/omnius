use std::{fmt, str::FromStr};

use rsk_audit::AuditActor;
use rsk_auth_core::{Principal, PrincipalKind, SubjectId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;

const MAX_CODE_BYTES: usize = 64;
const MAX_OBJECT_REFERENCE_BYTES: usize = 128;

/// A bounded privacy value was invalid.
///
/// The error intentionally contains none of the rejected value.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrivacyValueError {
    /// The value was empty.
    #[error("privacy value must not be empty")]
    Empty,
    /// The value exceeded its public bound.
    #[error("privacy value exceeds its maximum length")]
    TooLong,
    /// The value used characters outside its portable grammar.

    #[error("privacy value contains an invalid character")]
    InvalidCharacter,
    /// A UUID was not an RFC-compatible version 7 UUID.
    #[error("privacy identifier must be a UUIDv7 value")]
    NotVersion7,
}
macro_rules! privacy_uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Generates a new time-ordered `UUIDv7` identity.
            #[must_use]
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            /// Restores an existing `UUIDv7` identity.
            ///
            /// # Errors
            ///
            /// Returns [`crate::PrivacyValueError::NotVersion7`] for any other UUID version or
            /// variant.
            pub fn from_uuid(value: uuid::Uuid) -> Result<Self, crate::PrivacyValueError> {
                if value.get_version() == Some(uuid::Version::SortRand)
                    && value.get_variant() == uuid::Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(crate::PrivacyValueError::NotVersion7)
                }
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> uuid::Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, formatter)
            }
        }

        impl std::str::FromStr for $name {
            type Err = crate::PrivacyValueError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = uuid::Uuid::parse_str(value)
                    .map_err(|_| crate::PrivacyValueError::NotVersion7)?;
                Self::from_uuid(uuid)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let uuid = <uuid::Uuid as serde::Deserialize>::deserialize(deserializer)?;
                Self::from_uuid(uuid).map_err(serde::de::Error::custom)
            }
        }
    };
}

pub(crate) use privacy_uuid_id;

fn validate_code(value: &str) -> Result<(), PrivacyValueError> {
    if value.is_empty() {
        return Err(PrivacyValueError::Empty);
    }
    if value.len() > MAX_CODE_BYTES {
        return Err(PrivacyValueError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(PrivacyValueError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! code_value {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns a portable value of at most 64 bytes.
            ///
            /// # Errors
            ///
            /// Returns [`PrivacyValueError`] for an empty, oversized, or non-portable value.
            pub fn new(value: impl Into<String>) -> Result<Self, PrivacyValueError> {
                let value = value.into();
                validate_code(&value)?;
                Ok(Self(value))
            }

            /// Returns the validated value.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = PrivacyValueError;

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
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

code_value!(
    PolicyVersion,
    "A bounded immutable legal or moderation policy revision."
);
code_value!(
    ReasonCode,
    "A bounded machine-readable privacy or moderation reason."
);

/// A normalized jurisdiction code such as `EU`, `US`, or `US-CA`.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Jurisdiction(String);

impl Jurisdiction {
    /// Validates and owns a 2 through 16 byte upper-case jurisdiction code.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyValueError`] for an invalid code.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivacyValueError> {
        let value = value.into();
        if value.len() < 2 {
            return Err(PrivacyValueError::Empty);
        }
        if value.len() > 16 {
            return Err(PrivacyValueError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PrivacyValueError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the normalized code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Jurisdiction {
    type Err = PrivacyValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Serialize for Jurisdiction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Jurisdiction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A bounded opaque reference to retained moderation evidence.
///
/// The referenced content is never carried by this value and its `Debug` output is redacted.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ObjectReference(String);

impl ObjectReference {
    /// Validates an opaque reference of at most 128 bytes.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyValueError`] for an empty, oversized, or non-portable reference.
    pub fn new(value: impl Into<String>) -> Result<Self, PrivacyValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(PrivacyValueError::Empty);
        }
        if value.len() > MAX_OBJECT_REFERENCE_BYTES {
            return Err(PrivacyValueError::TooLong);
        }
        if !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        }) {
            return Err(PrivacyValueError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the opaque reference for an evidence-store adapter.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ObjectReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectReference([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for ObjectReference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}

/// A closed, coherent actor identity used by durable privacy records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorIdentity {
    /// Trusted internal work without a subject credential.
    System,
    /// An authenticated human user.
    User(SubjectId),
    /// An authenticated service account.
    ServiceAccount(SubjectId),
}

impl ActorIdentity {
    /// Derives an actor from the canonical authenticated principal.
    #[must_use]
    pub const fn from_principal(principal: &Principal) -> Self {
        match principal.kind {
            PrincipalKind::User => Self::User(principal.subject_id),
            PrincipalKind::ServiceAccount => Self::ServiceAccount(principal.subject_id),
        }
    }

    /// Returns the stable database actor class.
    #[must_use]
    pub const fn kind_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User(_) => "user",
            Self::ServiceAccount(_) => "service_account",
        }
    }

    /// Returns the authenticated subject when present.
    #[must_use]
    pub const fn subject_id(self) -> Option<SubjectId> {
        match self {
            Self::System => None,
            Self::User(subject_id) | Self::ServiceAccount(subject_id) => Some(subject_id),
        }
    }

    pub(crate) const fn audit_actor(self) -> AuditActor {
        match self {
            Self::System => AuditActor::System,
            Self::User(subject_id) => AuditActor::User(subject_id),
            Self::ServiceAccount(subject_id) => AuditActor::ServiceAccount(subject_id),
        }
    }
}
