use std::{fmt, str::FromStr};

use omnius_auth_core::{SubjectId, TenantId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::{Uuid, Variant, Version};

/// A stable conversation-domain value violated a fixed invariant.
///
/// Variants deliberately carry no rejected value or conversation content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ConversationContractError {
    /// An identifier was not an RFC-compatible `UUIDv7` value.
    #[error("conversation identifier is invalid")]
    InvalidIdentifier,
    /// A persisted revision was zero, exhausted, or outside PostgreSQL `bigint`.
    #[error("conversation revision is invalid")]
    InvalidRevision,
    /// A timestamp was non-UTC or a timeline was not monotonic.
    #[error("conversation timeline is invalid")]
    InvalidTimeline,
    /// A pagination request or page violated its fixed bound or ordering.
    #[error("conversation pagination is invalid")]
    InvalidPagination,
    /// Provider continuation state was not an approved, bounded representation.
    #[error("provider continuation state is invalid")]
    InvalidProviderState,
    /// A durable job reference snapshot was incomplete, duplicated, or excessive.
    #[error("durable job reference snapshot is invalid")]
    InvalidJobSnapshot,
    /// A deletion or retention event was incomplete or internally inconsistent.
    #[error("conversation retention event is invalid")]
    InvalidRetentionEvent,
}

macro_rules! uuid_v7_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered RFC-compatible `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Restores an existing RFC-compatible `UUIDv7` identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ConversationContractError::InvalidIdentifier`] for another UUID
            /// version or variant.
            pub fn from_uuid(value: Uuid) -> Result<Self, ConversationContractError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(ConversationContractError::InvalidIdentifier)
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
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ConversationContractError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                let uuid = Uuid::parse_str(value)
                    .map_err(|_| ConversationContractError::InvalidIdentifier)?;
                Self::from_uuid(uuid)
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
                Self::from_str(&String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(ConversationId, "The stable identity of one conversation.");
uuid_v7_id!(
    ConversationMessageId,
    "The client-generated stable identity of one canonical conversation message."
);
uuid_v7_id!(
    ProviderStateId,
    "The stable identity of one sanctioned provider-state record."
);
uuid_v7_id!(
    DeletionRequestId,
    "The stable idempotency identity of one conversation deletion request."
);
uuid_v7_id!(
    DeletionFenceEventId,
    "The stable identity of one durable conversation deletion-fence event."
);
uuid_v7_id!(
    RetentionInventoryEventId,
    "The stable identity of one durable retention-inventory event."
);

macro_rules! revision_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);

        impl $name {
            /// Initial persisted revision.
            pub const INITIAL: Self = Self(1);

            /// Restores a positive revision representable by PostgreSQL `bigint`.
            ///
            /// # Errors
            ///
            /// Returns [`ConversationContractError::InvalidRevision`] for zero or signed
            /// overflow.
            pub const fn from_u64(value: u64) -> Result<Self, ConversationContractError> {
                if value == 0 || value > i64::MAX as u64 {
                    Err(ConversationContractError::InvalidRevision)
                } else {
                    Ok(Self(value))
                }
            }

            /// Returns the persisted integer revision.
            #[must_use]
            pub const fn get(self) -> u64 {
                self.0
            }

            /// Returns the next immutable revision snapshot.
            ///
            /// # Errors
            ///
            /// Returns [`ConversationContractError::InvalidRevision`] when the signed
            /// persistence range is exhausted.
            pub const fn next(self) -> Result<Self, ConversationContractError> {
                if self.0 == i64::MAX as u64 {
                    Err(ConversationContractError::InvalidRevision)
                } else {
                    Ok(Self(self.0 + 1))
                }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::from_u64(u64::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

revision_type!(
    ConversationRevision,
    "The immutable optimistic-concurrency revision of a conversation."
);
revision_type!(
    ConversationMessageRevision,
    "The immutable optimistic-concurrency revision of a message."
);
revision_type!(
    ProviderStateRevision,
    "The immutable optimistic-concurrency revision of sanctioned provider state."
);
revision_type!(
    DefinitionRevision,
    "A positive immutable prompt, route, schema, or tool definition revision."
);

/// A positive, monotonically increasing message position within one conversation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct MessageSequence(u64);

impl MessageSequence {
    /// Restores a positive sequence representable by PostgreSQL `bigint`.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidRevision`] for zero or signed overflow.
    pub const fn from_u64(value: u64) -> Result<Self, ConversationContractError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(ConversationContractError::InvalidRevision)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the persisted sequence.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next monotonic message position.
    ///
    /// # Errors
    ///
    /// Returns [`ConversationContractError::InvalidRevision`] when the signed persistence
    /// range is exhausted.
    pub const fn next(self) -> Result<Self, ConversationContractError> {
        if self.0 == i64::MAX as u64 {
            Err(ConversationContractError::InvalidRevision)
        } else {
            Ok(Self(self.0 + 1))
        }
    }
}

impl<'de> Deserialize<'de> for MessageSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::from_u64(u64::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Tenant and authenticated principal authorization facts required by every repository operation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub struct ConversationAuthorization {
    tenant_id: TenantId,
    principal_id: SubjectId,
}

impl ConversationAuthorization {
    /// Creates an authorization scope from canonical authenticated identities.
    #[must_use]
    pub const fn new(tenant_id: TenantId, principal_id: SubjectId) -> Self {
        Self {
            tenant_id,
            principal_id,
        }
    }

    /// Returns the required tenant identity.
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    /// Returns the required authenticated principal identity.
    #[must_use]
    pub const fn principal_id(self) -> SubjectId {
        self.principal_id
    }
}

pub(crate) fn validate_utc(value: OffsetDateTime) -> Result<(), ConversationContractError> {
    if value.offset() == UtcOffset::UTC {
        Ok(())
    } else {
        Err(ConversationContractError::InvalidTimeline)
    }
}

pub(crate) fn validate_timeline(
    earlier: OffsetDateTime,
    later: OffsetDateTime,
) -> Result<(), ConversationContractError> {
    validate_utc(earlier)?;
    validate_utc(later)?;
    if later < earlier {
        Err(ConversationContractError::InvalidTimeline)
    } else {
        Ok(())
    }
}
