use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::{Uuid, Version};

/// An identifier could not be parsed as a UUID.
#[derive(Debug, Error)]
#[error("invalid UUID identifier")]
pub struct ParseIdError {
    #[source]
    source: uuid::Error,
}

macro_rules! uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a time-ordered `UUIDv7` identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Wraps an already validated UUID.
            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID value.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }

            /// Reports whether this identifier was generated as `UUIDv7`.
            #[must_use]
            pub fn is_v7(self) -> bool {
                self.0.get_version() == Some(Version::SortRand)
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl FromStr for $name {
            type Err = ParseIdError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(value)
                    .map(Self)
                    .map_err(|source| ParseIdError { source })
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

uuid_id!(RequestId, "A request-scoped correlation identifier.");
uuid_id!(
    CorrelationId,
    "An identifier linking work across transports."
);
uuid_id!(
    CausationId,
    "An identifier naming the work item that caused another."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identifiers_are_uuid_v7() {
        assert!(RequestId::new().is_v7());
        assert!(CorrelationId::new().is_v7());
        assert!(CausationId::new().is_v7());
    }

    #[test]
    fn identifier_json_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let request_id = RequestId::new();
        let encoded = serde_json::to_string(&request_id)?;
        let decoded: RequestId = serde_json::from_str(&encoded)?;
        assert_eq!(decoded, request_id);
        Ok(())
    }

    #[test]
    fn malformed_identifier_has_safe_error() {
        let result = "not-an-identifier".parse::<RequestId>();
        let Err(error) = result else {
            panic!("malformed identifier was accepted");
        };
        assert_eq!(error.to_string(), "invalid UUID identifier");
    }
}
