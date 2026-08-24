//! Provider-independent reference aggregate and persistence port.

use std::{error::Error, fmt, future::Future, str::FromStr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset};
use uuid::{Uuid, Version};

const MAX_NAME_CHARS: usize = 100;

/// `UUIDv7` identity for one reference record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReferenceRecordId(Uuid);

impl ReferenceRecordId {
    /// Generates a time-ordered `UUIDv7` identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID after verifying the `UUIDv7` invariant.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceDomainError::InvalidId`] for another UUID version.
    pub fn from_uuid(value: Uuid) -> Result<Self, ReferenceDomainError> {
        if value.get_version() == Some(Version::SortRand) {
            Ok(Self(value))
        } else {
            Err(ReferenceDomainError::InvalidId)
        }
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for ReferenceRecordId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ReferenceRecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for ReferenceRecordId {
    type Err = ReferenceDomainError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid = Uuid::parse_str(value).map_err(|_| ReferenceDomainError::InvalidId)?;
        Self::from_uuid(uuid)
    }
}

/// Minimal mutable aggregate used by the API reference profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReferenceRecord {
    id: ReferenceRecordId,
    name: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl ReferenceRecord {
    /// Creates a record after enforcing domain invariants.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceDomainError`] for an invalid name or non-UTC time.
    pub fn create(
        id: ReferenceRecordId,
        name: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<Self, ReferenceDomainError> {
        Self::restore(id, name.into(), now, now)
    }

    /// Restores a persisted record while defending the domain boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceDomainError`] when persisted data violates an invariant.
    pub fn restore(
        id: ReferenceRecordId,
        name: String,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, ReferenceDomainError> {
        validate_name(&name)?;
        validate_timeline(created_at, updated_at)?;
        Ok(Self {
            id,
            name,
            created_at,
            updated_at,
        })
    }

    /// Changes the name at a monotonic UTC instant.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceDomainError`] for an invalid name or timestamp.
    pub fn rename(
        &mut self,
        name: impl Into<String>,
        now: OffsetDateTime,
    ) -> Result<(), ReferenceDomainError> {
        let name = name.into();
        validate_name(&name)?;
        validate_timeline(self.updated_at, now)?;
        self.name = name;
        self.updated_at = now;
        Ok(())
    }

    /// Returns the stable identity.
    #[must_use]
    pub const fn id(&self) -> ReferenceRecordId {
        self.id
    }

    /// Returns the validated display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the UTC creation instant.
    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the UTC last-update instant.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// Persistence port implemented by provider adapters.
pub trait ReferenceRecordRepository: Send + Sync {
    /// Provider-specific safe failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists a new aggregate.
    fn create(
        &self,
        record: &ReferenceRecord,
    ) -> impl Future<Output = Result<ReferenceRecord, Self::Error>> + Send;

    /// Fetches one aggregate by identity.
    fn get(
        &self,
        id: ReferenceRecordId,
    ) -> impl Future<Output = Result<Option<ReferenceRecord>, Self::Error>> + Send;

    /// Persists the current aggregate state.
    fn update(
        &self,
        record: &ReferenceRecord,
    ) -> impl Future<Output = Result<Option<ReferenceRecord>, Self::Error>> + Send;

    /// Deletes one aggregate and reports whether it existed.
    fn delete(
        &self,
        id: ReferenceRecordId,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send;
}

/// Stable domain invariant failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReferenceDomainError {
    /// Identifiers must be `UUIDv7`.
    #[error("reference record identifier is invalid")]
    InvalidId,
    /// Names must contain non-whitespace text and at most 100 characters.
    #[error("reference record name is invalid")]
    InvalidName,
    /// Timestamps must be UTC and monotonic.
    #[error("reference record timeline is invalid")]
    InvalidTimeline,
}

fn validate_name(name: &str) -> Result<(), ReferenceDomainError> {
    let length = name.chars().count();
    if name.trim().is_empty() || length > MAX_NAME_CHARS {
        Err(ReferenceDomainError::InvalidName)
    } else {
        Ok(())
    }
}

fn validate_timeline(
    earlier: OffsetDateTime,
    later: OffsetDateTime,
) -> Result<(), ReferenceDomainError> {
    if earlier.offset() != UtcOffset::UTC || later.offset() != UtcOffset::UTC || later < earlier {
        Err(ReferenceDomainError::InvalidTimeline)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_enforces_name_and_monotonic_utc_time() -> Result<(), ReferenceDomainError> {
        let id = ReferenceRecordId::new();
        let created = OffsetDateTime::UNIX_EPOCH + time::Duration::days(20_000);
        let mut record = ReferenceRecord::create(id, "First", created)?;
        record.rename("Second", created + time::Duration::seconds(1))?;
        assert_eq!(record.name(), "Second");
        assert_eq!(record.id(), id);
        assert_eq!(
            record.rename("   ", created + time::Duration::seconds(2)),
            Err(ReferenceDomainError::InvalidName)
        );
        assert_eq!(
            record.rename("Third", created - time::Duration::seconds(1)),
            Err(ReferenceDomainError::InvalidTimeline)
        );
        Ok(())
    }

    #[test]
    fn identifiers_reject_non_v7_uuids() {
        assert_eq!(
            ReferenceRecordId::from_uuid(Uuid::nil()),
            Err(ReferenceDomainError::InvalidId)
        );
    }
}
