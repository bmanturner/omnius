use std::{error::Error, future::Future};

use omnius_pagination::{
    CursorCodec, CursorEncodeError, CursorPage, OpaqueCursor, PageLimit, PageRequest,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{ReferenceRecord, ReferenceRecordId};

const CURSOR_NAMESPACE: &[u8] = b"reference-records:created-at-asc:v1";
const TIMESTAMP_BYTES: usize = 16;
const ID_BYTES: usize = 16;
const TIMESTAMP_START: usize = CURSOR_NAMESPACE.len();
const ID_START: usize = TIMESTAMP_START + TIMESTAMP_BYTES;
const CURSOR_PAYLOAD_BYTES: usize = CURSOR_NAMESPACE.len() + TIMESTAMP_BYTES + ID_BYTES;

/// Decoded immutable keyset for the canonical reference-record ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReferenceRecordCursor {
    created_at: OffsetDateTime,
    id: ReferenceRecordId,
}

impl ReferenceRecordCursor {
    /// Creates a keyset from one persisted record.
    #[must_use]
    pub const fn from_record(record: &ReferenceRecord) -> Self {
        Self {
            created_at: record.created_at(),
            id: record.id(),
        }
    }

    /// Returns the immutable primary sort value.
    #[must_use]
    pub const fn created_at(self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns the unique sort tiebreaker.
    #[must_use]
    pub const fn id(self) -> ReferenceRecordId {
        self.id
    }

    /// Authenticates this keyset as an opaque transport cursor.
    ///
    /// # Errors
    ///
    /// Returns [`ReferencePaginationError::CursorEncoding`] if the shared
    /// cursor codec cannot encode the fixed-size payload.
    pub fn encode(self, codec: &CursorCodec) -> Result<OpaqueCursor, ReferencePaginationError> {
        let mut payload = [0_u8; CURSOR_PAYLOAD_BYTES];
        payload[..TIMESTAMP_START].copy_from_slice(CURSOR_NAMESPACE);
        payload[TIMESTAMP_START..ID_START]
            .copy_from_slice(&self.created_at.unix_timestamp_nanos().to_be_bytes());
        payload[ID_START..].copy_from_slice(self.id.as_uuid().as_bytes());
        codec
            .encode(&payload)
            .map_err(ReferencePaginationError::from_encode_error)
    }

    fn decode(
        cursor: &OpaqueCursor,
        codec: &CursorCodec,
    ) -> Result<Self, ReferencePaginationError> {
        let payload = codec
            .decode(cursor)
            .map_err(|_| ReferencePaginationError::InvalidCursor)?;
        let payload: [u8; CURSOR_PAYLOAD_BYTES] = payload
            .try_into()
            .map_err(|_| ReferencePaginationError::InvalidCursor)?;
        if &payload[..TIMESTAMP_START] != CURSOR_NAMESPACE {
            return Err(ReferencePaginationError::InvalidCursor);
        }
        let timestamp = i128::from_be_bytes(
            payload[TIMESTAMP_START..ID_START]
                .try_into()
                .map_err(|_| ReferencePaginationError::InvalidCursor)?,
        );
        let created_at = OffsetDateTime::from_unix_timestamp_nanos(timestamp)
            .map_err(|_| ReferencePaginationError::InvalidCursor)?;
        let id = uuid::Uuid::from_bytes(
            payload[ID_START..]
                .try_into()
                .map_err(|_| ReferencePaginationError::InvalidCursor)?,
        );
        let id = ReferenceRecordId::from_uuid(id)
            .map_err(|_| ReferencePaginationError::InvalidCursor)?;
        Ok(Self { created_at, id })
    }
}

/// Validated, normalized case-insensitive name filter for reference-record lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceRecordNameFilter(String);

impl ReferenceRecordNameFilter {
    /// Trims and validates one non-empty filter value.
    ///
    /// # Errors
    ///
    /// Returns [`ReferencePaginationError::InvalidFilter`] when the value is blank or exceeds the
    /// aggregate name bound.
    pub fn try_new(value: impl Into<String>) -> Result<Self, ReferencePaginationError> {
        let value = value.into();
        let value = value.trim();
        if value.is_empty() || value.chars().count() > crate::MAX_NAME_CHARS {
            return Err(ReferencePaginationError::InvalidFilter);
        }
        Ok(Self(value.to_owned()))
    }

    /// Returns the normalized filter text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated reference-record keyset page request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReferenceRecordPageRequest {
    limit: PageLimit,
    cursor: Option<ReferenceRecordCursor>,
    name_filter: Option<ReferenceRecordNameFilter>,
}

impl ReferenceRecordPageRequest {
    /// Verifies and decodes strict transport pagination parameters.
    ///
    /// # Errors
    ///
    /// Returns [`ReferencePaginationError::InvalidCursor`] for every malformed,
    /// unauthenticated, unsupported, or resource-invalid cursor.
    pub fn decode(
        request: &PageRequest,
        codec: &CursorCodec,
    ) -> Result<Self, ReferencePaginationError> {
        let cursor = request
            .cursor
            .as_ref()
            .map(|cursor| ReferenceRecordCursor::decode(cursor, codec))
            .transpose()?;
        Ok(Self {
            limit: request.limit,
            cursor,
            name_filter: None,
        })
    }

    /// Creates a first-page request with a validated bound.
    #[must_use]
    pub const fn first(limit: PageLimit) -> Self {
        Self {
            limit,
            cursor: None,
            name_filter: None,
        }
    }

    /// Applies a normalized filter without changing the decoded keyset.
    #[must_use]
    pub fn with_name_filter(mut self, filter: Option<ReferenceRecordNameFilter>) -> Self {
        self.name_filter = filter;
        self
    }

    /// Returns the maximum number of records to expose.
    #[must_use]
    pub const fn limit(&self) -> PageLimit {
        self.limit
    }

    /// Returns the decoded continuation keyset.
    #[must_use]
    pub const fn cursor(&self) -> Option<ReferenceRecordCursor> {
        self.cursor
    }

    /// Returns the normalized case-insensitive name filter.
    #[must_use]
    pub fn name_filter(&self) -> Option<&ReferenceRecordNameFilter> {
        self.name_filter.as_ref()
    }
}

/// Provider-independent stable pagination failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReferencePaginationError {
    /// The supplied cursor failed uniform decoding or resource validation.
    #[error("reference record cursor is invalid")]
    InvalidCursor,
    /// A filter violated the resource's public bounds.
    #[error("reference record filter is invalid")]
    InvalidFilter,
    /// The fixed-size internal cursor payload could not be encoded.
    #[error("reference record cursor encoding failed")]
    CursorEncoding,
}

impl ReferencePaginationError {
    const fn from_encode_error(_error: CursorEncodeError) -> Self {
        Self::CursorEncoding
    }
}

/// Paginated persistence port implemented by provider adapters.
pub trait ReferenceRecordPaginator: Send + Sync {
    /// Provider-specific safe failure type.
    type Error: Error + Send + Sync + 'static;

    /// Lists one bounded page in canonical `(created_at, id)` order.
    fn list(
        &self,
        request: ReferenceRecordPageRequest,
    ) -> impl Future<Output = Result<CursorPage<ReferenceRecord>, Self::Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use omnius_pagination::CursorSigningKey;

    #[test]
    fn reference_cursor_round_trips_and_rejects_other_key() -> Result<(), Box<dyn Error>> {
        let codec = CursorCodec::new(CursorSigningKey::new([7; 32]));
        let other_codec = CursorCodec::new(CursorSigningKey::new([8; 32]));
        let created_at = OffsetDateTime::from_unix_timestamp(1_787_443_200)?;
        let record = ReferenceRecord::create(ReferenceRecordId::new(), "Cursor", created_at)?;
        let expected = ReferenceRecordCursor::from_record(&record);
        let cursor = expected.encode(&codec)?;
        let request = ReferenceRecordPageRequest::decode(
            &PageRequest::new(PageLimit::new(25)?, Some(cursor.clone())),
            &codec,
        )?;
        assert_eq!(request.cursor(), Some(expected));
        assert_eq!(
            ReferenceRecordPageRequest::decode(
                &PageRequest::new(PageLimit::new(25)?, Some(cursor)),
                &other_codec,
            ),
            Err(ReferencePaginationError::InvalidCursor)
        );
        Ok(())
    }

    #[test]
    fn name_filter_trims_and_rejects_blank_values() -> Result<(), Box<dyn Error>> {
        let filter = ReferenceRecordNameFilter::try_new("  Primary  ")?;
        assert_eq!(filter.as_str(), "Primary");
        assert_eq!(
            ReferenceRecordNameFilter::try_new("   "),
            Err(ReferencePaginationError::InvalidFilter)
        );
        Ok(())
    }
}
