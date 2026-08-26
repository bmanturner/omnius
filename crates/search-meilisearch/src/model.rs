use std::{collections::BTreeMap, fmt};

use rsk_auth_core::TenantId;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::config::{
    HARD_MAX_DOCUMENT_BYTES, HARD_MAX_FILTER_BYTES, HARD_MAX_HITS, HARD_MAX_OFFSET,
    HARD_MAX_QUERY_BYTES, SearchLimits,
};

const MAX_ALIAS_BYTES: usize = 64;
const MAX_FIELD_BYTES: usize = 64;
const MAX_SOURCE_ID_BYTES: usize = 256;
const MAX_FILTERS: usize = 32;
const MAX_DOCUMENT_FIELDS: usize = 64;
const MAX_JSON_DEPTH: usize = 4;
const MAX_JSON_ARRAY_ITEMS: usize = 64;
const MAX_JSON_STRING_BYTES: usize = 16_384;
const MAX_CURSOR_BYTES: usize = 1_024;
const MAX_INDEX_UID_BYTES: usize = 256;
const RESERVED_FIELDS: [&str; 5] = [
    "id",
    "_tenant_id",
    "_source_id",
    "_source_revision",
    "_schema_version",
];

/// Bounded logical search index alias.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IndexAlias(String);

impl IndexAlias {
    /// Validates and owns a portable alias.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidIndexAlias`] for an empty, oversized, or non-portable value.
    pub fn new(value: impl Into<String>) -> Result<Self, SearchModelError> {
        let value = value.into();
        if !portable_identifier(&value, MAX_ALIAS_BYTES) {
            return Err(SearchModelError::InvalidIndexAlias);
        }
        Ok(Self(value))
    }

    /// Borrows the logical alias.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for IndexAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("IndexAlias").field(&self.0).finish()
    }
}

impl fmt::Display for IndexAlias {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Validated searchable or filterable document field name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct FieldName(String);

impl FieldName {
    /// Validates a dotted portable field path that cannot collide with adapter metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidField`] for a reserved or malformed value.
    pub fn new(value: impl Into<String>) -> Result<Self, SearchModelError> {
        let value = value.into();
        if value.len() > MAX_FIELD_BYTES
            || RESERVED_FIELDS.contains(&value.as_str())
            || !value
                .split('.')
                .all(|segment| portable_identifier(segment, MAX_FIELD_BYTES))
        {
            return Err(SearchModelError::InvalidField);
        }
        Ok(Self(value))
    }

    /// Borrows the field path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for FieldName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("FieldName").field(&self.0).finish()
    }
}

/// Bounded application-owned source identifier.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceId(String);

impl SourceId {
    /// Validates and owns a source identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidSourceId`] when the value is not portable and bounded.
    pub fn new(value: impl Into<String>) -> Result<Self, SearchModelError> {
        let value = value.into();
        let mut bytes = value.bytes();
        if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'))
            || value.len() > MAX_SOURCE_ID_BYTES
            || !bytes.all(|byte| {
                matches!(
                    byte,
                    b'A'..=b'Z'
                        | b'a'..=b'z'
                        | b'0'..=b'9'
                        | b'_'
                        | b'-'
                        | b'.'
                        | b':'
                        | b'/'
                )
            })
        {
            return Err(SearchModelError::InvalidSourceId);
        }
        Ok(Self(value))
    }

    /// Borrows the source identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SourceId([REDACTED])")
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Monotonic application-owned source revision representable by PostgreSQL `bigint`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceRevision(u64);

impl SourceRevision {
    /// Creates a positive bounded revision.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidSourceRevision`] for zero or values above `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, SearchModelError> {
        if value == 0 || value > i64::MAX as u64 {
            return Err(SearchModelError::InvalidSourceRevision);
        }
        Ok(Self(value))
    }

    /// Returns the revision value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    pub(crate) fn as_i64(self) -> i64 {
        i64::try_from(self.0).unwrap_or(i64::MAX)
    }
}

/// One versioned, explicit index schema.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSchema {
    alias: IndexAlias,
    version: u32,
    searchable_fields: Vec<FieldName>,
    filterable_fields: Vec<FieldName>,
}

impl IndexSchema {
    /// Creates a versioned schema with sorted, duplicate-free field lists.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidSchema`] for version zero or unbounded field lists.
    pub fn new(
        alias: IndexAlias,
        version: u32,
        mut searchable_fields: Vec<FieldName>,
        mut filterable_fields: Vec<FieldName>,
    ) -> Result<Self, SearchModelError> {
        searchable_fields.sort_unstable();
        searchable_fields.dedup();
        filterable_fields.sort_unstable();
        filterable_fields.dedup();
        if version == 0
            || searchable_fields.is_empty()
            || searchable_fields.len() > MAX_DOCUMENT_FIELDS
            || filterable_fields.len() > MAX_DOCUMENT_FIELDS
        {
            return Err(SearchModelError::InvalidSchema);
        }
        Ok(Self {
            alias,
            version,
            searchable_fields,
            filterable_fields,
        })
    }

    /// Returns the stable logical alias.
    #[must_use]
    pub const fn alias(&self) -> &IndexAlias {
        &self.alias
    }

    /// Returns the positive schema version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns sorted searchable fields.
    #[must_use]
    pub fn searchable_fields(&self) -> &[FieldName] {
        &self.searchable_fields
    }

    /// Returns sorted application filterable fields.
    #[must_use]
    pub fn filterable_fields(&self) -> &[FieldName] {
        &self.filterable_fields
    }

    /// Returns whether a caller filter is declared by this schema.
    #[must_use]
    pub fn is_filterable(&self, field: &FieldName) -> bool {
        self.filterable_fields.binary_search(field).is_ok()
    }

    /// Returns a deterministic canonical schema digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.alias.as_str().as_bytes());
        hasher.update([0]);
        hasher.update(self.version.to_be_bytes());
        for field in &self.searchable_fields {
            hasher.update([1]);
            hasher.update(field.as_str().as_bytes());
        }
        for field in &self.filterable_fields {
            hasher.update([2]);
            hasher.update(field.as_str().as_bytes());
        }
        hasher.finalize().into()
    }

    pub(crate) fn stable_uid(&self, prefix: &str) -> String {
        format!("{prefix}__{}", self.alias)
    }

    pub(crate) fn version_uid(&self, prefix: &str) -> String {
        format!("{prefix}__{}__v{}", self.alias, self.version)
    }
}

/// A bounded structured filter value.
#[derive(Clone, Eq, PartialEq)]
pub struct FilterValue(FilterValueKind);

#[derive(Clone, Eq, PartialEq)]
enum FilterValueKind {
    Text(String),
    Integer(i64),
    Boolean(bool),
}

impl FilterValue {
    /// Validates a bounded text filter value.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidFilterValue`] for empty or oversized text.
    pub fn text(value: impl Into<String>) -> Result<Self, SearchModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > 1_024 {
            return Err(SearchModelError::InvalidFilterValue);
        }
        Ok(Self(FilterValueKind::Text(value)))
    }

    /// Creates a signed-integer filter value.
    #[must_use]
    pub const fn integer(value: i64) -> Self {
        Self(FilterValueKind::Integer(value))
    }

    /// Creates a boolean filter value.
    #[must_use]
    pub const fn boolean(value: bool) -> Self {
        Self(FilterValueKind::Boolean(value))
    }

    fn render(&self) -> Result<String, SearchModelError> {
        match &self.0 {
            FilterValueKind::Text(value) => {
                serde_json::to_string(value).map_err(|_| SearchModelError::InvalidFilterValue)
            }
            FilterValueKind::Integer(value) => Ok(value.to_string()),
            FilterValueKind::Boolean(value) => Ok(value.to_string()),
        }
    }
}

impl fmt::Debug for FilterValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FilterValue([REDACTED])")
    }
}

/// One typed equality filter. Raw provider filter strings are never accepted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchFilter {
    field: FieldName,
    value: FilterValue,
}

impl SearchFilter {
    /// Creates an equality filter over a validated field and value.
    #[must_use]
    pub const fn equal(field: FieldName, value: FilterValue) -> Self {
        Self { field, value }
    }

    /// Returns the filter field.
    #[must_use]
    pub const fn field(&self) -> &FieldName {
        &self.field
    }
}

/// Bounded caller search input. Tenant scope is intentionally absent and cannot be supplied here.
pub struct SearchInput {
    query: String,
    filters: Vec<SearchFilter>,
    limit: usize,
    offset: usize,
}

impl SearchInput {
    /// Creates hard-bounded search input; configured limits are enforced again by [`crate::SearchService`].
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError`] when any hard query, filter-count, hit, or offset bound is exceeded.
    pub fn new(
        query: impl Into<String>,
        filters: Vec<SearchFilter>,
        limit: usize,
        offset: usize,
    ) -> Result<Self, SearchModelError> {
        let query = query.into();
        if query.len() > HARD_MAX_QUERY_BYTES {
            return Err(SearchModelError::QueryTooLarge);
        }
        if filters.len() > MAX_FILTERS {
            return Err(SearchModelError::TooManyFilters);
        }
        if !(1..=HARD_MAX_HITS).contains(&limit) {
            return Err(SearchModelError::InvalidHitLimit);
        }
        if offset > HARD_MAX_OFFSET {
            return Err(SearchModelError::InvalidOffset);
        }
        Ok(Self {
            query,
            filters,
            limit,
            offset,
        })
    }
    pub(crate) const fn limit_for_service(&self) -> usize {
        self.limit
    }
}

impl fmt::Debug for SearchInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SearchInput")
            .field("query", &"[REDACTED]")
            .field(
                "filters",
                &format_args!("[REDACTED; {}]", self.filters.len()),
            )
            .field("limit", &self.limit)
            .field("offset", &self.offset)
            .finish()
    }
}

/// Tenant-scoped provider request. Only the service can construct this value.
pub struct TenantScopedQuery {
    tenant_id: TenantId,
    query: String,
    rendered_filter: String,
    limit: usize,
    offset: usize,
}

impl TenantScopedQuery {
    pub(crate) fn build(
        tenant_id: TenantId,
        schema: &IndexSchema,
        input: SearchInput,
        limits: SearchLimits,
    ) -> Result<Self, SearchModelError> {
        if input.query.len() > limits.max_query_bytes {
            return Err(SearchModelError::QueryTooLarge);
        }
        if input.limit > limits.max_hits {
            return Err(SearchModelError::InvalidHitLimit);
        }
        if input.offset > limits.max_offset {
            return Err(SearchModelError::InvalidOffset);
        }
        if input
            .filters
            .iter()
            .any(|filter| !schema.is_filterable(filter.field()))
        {
            return Err(SearchModelError::FieldNotFilterable);
        }

        let mut rendered_filter = format!("_tenant_id = \"{tenant_id}\"");
        for filter in &input.filters {
            let value = filter.value.render()?;
            rendered_filter.push_str(" AND ");
            rendered_filter.push_str(filter.field.as_str());
            rendered_filter.push_str(" = ");
            rendered_filter.push_str(&value);
        }
        if rendered_filter.len() > limits.max_filter_bytes
            || rendered_filter.len() > HARD_MAX_FILTER_BYTES
        {
            return Err(SearchModelError::FilterTooLarge);
        }
        Ok(Self {
            tenant_id,
            query: input.query,
            rendered_filter,
            limit: input.limit,
            offset: input.offset,
        })
    }

    /// Returns the mandatory canonical tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Borrows redaction-sensitive query text for provider execution.
    #[must_use]
    pub fn query(&self) -> &str {
        &self.query
    }

    /// Borrows the adapter-rendered filter, always beginning with the tenant predicate.
    #[must_use]
    pub fn rendered_filter(&self) -> &str {
        &self.rendered_filter
    }

    /// Returns the bounded hit count.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Returns the bounded offset.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Debug for TenantScopedQuery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TenantScopedQuery")
            .field("tenant_id", &"[REDACTED]")
            .field("query", &"[REDACTED]")
            .field("rendered_filter", &"[REDACTED]")
            .field("limit", &self.limit)
            .field("offset", &self.offset)
            .finish()
    }
}

/// One provider-returned projection identity awaiting authoritative reauthorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchCandidate {
    source_id: SourceId,
    revision: SourceRevision,
}

impl SearchCandidate {
    pub(crate) const fn new(source_id: SourceId, revision: SourceRevision) -> Self {
        Self {
            source_id,
            revision,
        }
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Returns the indexed source revision.
    #[must_use]
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }
}

/// One authoritative, currently visible source identity returned by a batch reauthorizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedSource {
    source_id: SourceId,
    revision: SourceRevision,
}

impl AuthorizedSource {
    /// Creates an authoritative authorization result.
    #[must_use]
    pub const fn new(source_id: SourceId, revision: SourceRevision) -> Self {
        Self {
            source_id,
            revision,
        }
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Returns the current authoritative source revision.
    #[must_use]
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }
}

/// One reauthorized search result identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchHit {
    source_id: SourceId,
    revision: SourceRevision,
}

impl SearchHit {
    pub(crate) const fn new(source_id: SourceId, revision: SourceRevision) -> Self {
        Self {
            source_id,
            revision,
        }
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Returns the authoritative revision.
    #[must_use]
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }
}

/// A response containing only identities confirmed by the authoritative batch reauthorizer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResponse {
    hits: Vec<SearchHit>,
    provider_page_full: bool,
}

impl SearchResponse {
    pub(crate) const fn new(hits: Vec<SearchHit>, provider_page_full: bool) -> Self {
        Self {
            hits,
            provider_page_full,
        }
    }

    /// Returns ordered reauthorized hits.
    #[must_use]
    pub fn hits(&self) -> &[SearchHit] {
        &self.hits
    }

    /// Indicates only that the bounded provider page was full; it is not an authorization-leaking total.
    #[must_use]
    pub const fn provider_page_full(&self) -> bool {
        self.provider_page_full
    }
}

/// Bounded projection document loaded from an authoritative source adapter.
#[derive(Clone, Eq, PartialEq)]
pub struct ProjectionDocument {
    source_id: SourceId,
    revision: SourceRevision,
    fields: BTreeMap<String, Value>,
}

impl ProjectionDocument {
    /// Validates a document and prevents collisions with adapter metadata fields.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError`] for excessive fields, JSON shape/depth, reserved keys, or bytes.
    pub fn new(
        source_id: SourceId,
        revision: SourceRevision,
        fields: BTreeMap<String, Value>,
    ) -> Result<Self, SearchModelError> {
        if fields.is_empty() || fields.len() > MAX_DOCUMENT_FIELDS {
            return Err(SearchModelError::InvalidDocument);
        }
        for (name, value) in &fields {
            FieldName::new(name.clone())?;
            validate_json(value, 0)?;
        }
        let encoded = serde_json::to_vec(&fields).map_err(|_| SearchModelError::InvalidDocument)?;
        let indexed_len = encoded
            .len()
            .checked_add(source_id.as_str().len())
            .and_then(|length| length.checked_add(512))
            .ok_or(SearchModelError::DocumentTooLarge)?;
        if indexed_len > HARD_MAX_DOCUMENT_BYTES {
            return Err(SearchModelError::DocumentTooLarge);
        }
        Ok(Self {
            source_id,
            revision,
            fields,
        })
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn source_id(&self) -> &SourceId {
        &self.source_id
    }

    /// Returns the source revision.
    #[must_use]
    pub const fn revision(&self) -> SourceRevision {
        self.revision
    }

    /// Borrows validated application fields.
    #[must_use]
    pub fn fields(&self) -> &BTreeMap<String, Value> {
        &self.fields
    }

    pub(crate) fn indexed_len_upper_bound(&self) -> Result<usize, SearchModelError> {
        serde_json::to_vec(&self.fields)
            .map_err(|_| SearchModelError::InvalidDocument)?
            .len()
            .checked_add(self.source_id.as_str().len())
            .and_then(|length| length.checked_add(512))
            .ok_or(SearchModelError::DocumentTooLarge)
    }
}

impl fmt::Debug for ProjectionDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionDocument")
            .field("source_id", &self.source_id)
            .field("revision", &self.revision)
            .field("fields", &"[REDACTED]")
            .finish()
    }
}

/// Authoritative projection action produced for one outbox event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionMutation {
    /// Replace the complete derived document at this revision.
    Upsert(ProjectionDocument),
    /// Delete the derived document at this tombstone revision.
    Delete {
        /// Source identifier to remove.
        source_id: SourceId,
        /// Authoritative tombstone revision.
        revision: SourceRevision,
    },
    /// The event does not affect this projection.
    Ignore,
}

impl ProjectionMutation {
    /// Creates a deletion mutation.
    #[must_use]
    pub const fn delete(source_id: SourceId, revision: SourceRevision) -> Self {
        Self::Delete {
            source_id,
            revision,
        }
    }

    /// Returns the source identity when the mutation changes the index.
    #[must_use]
    pub const fn source_id(&self) -> Option<&SourceId> {
        match self {
            Self::Upsert(document) => Some(document.source_id()),
            Self::Delete { source_id, .. } => Some(source_id),
            Self::Ignore => None,
        }
    }

    /// Returns the authoritative revision when the mutation changes the index.
    #[must_use]
    pub const fn revision(&self) -> Option<SourceRevision> {
        match self {
            Self::Upsert(document) => Some(document.revision()),
            Self::Delete { revision, .. } => Some(*revision),
            Self::Ignore => None,
        }
    }

    pub(crate) const fn operation(&self) -> Option<&'static str> {
        match self {
            Self::Upsert(_) => Some("upsert"),
            Self::Delete { .. } => Some("delete"),
            Self::Ignore => None,
        }
    }
}

/// Opaque, bounded application backfill cursor.
#[derive(Clone, Eq, PartialEq)]
pub struct ReindexCursor(String);

impl ReindexCursor {
    /// Creates a non-empty bounded cursor.
    ///
    /// # Errors
    ///
    /// Returns [`SearchModelError::InvalidCursor`] for empty, oversized, or control-bearing data.
    pub fn new(value: impl Into<String>) -> Result<Self, SearchModelError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_CURSOR_BYTES || value.chars().any(char::is_control)
        {
            return Err(SearchModelError::InvalidCursor);
        }
        Ok(Self(value))
    }

    /// Borrows the opaque cursor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReindexCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReindexCursor([REDACTED])")
    }
}

pub(crate) fn document_id(tenant_id: TenantId, source_id: &SourceId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_uuid().as_bytes());
    hasher.update([0]);
    hasher.update(source_id.as_str().as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(crate) fn validate_index_uid(value: &str) -> Result<(), SearchModelError> {
    if !portable_identifier(value, MAX_INDEX_UID_BYTES) {
        return Err(SearchModelError::InvalidIndexUid);
    }
    Ok(())
}

/// Rejected bounded search model input.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SearchModelError {
    /// A logical alias was malformed.
    #[error("search index alias is invalid")]
    InvalidIndexAlias,
    /// A provider index UID was malformed.
    #[error("search index UID is invalid")]
    InvalidIndexUid,
    /// A document field was malformed or reserved.
    #[error("search field is invalid")]
    InvalidField,
    /// A source identifier was malformed.
    #[error("search source identifier is invalid")]
    InvalidSourceId,
    /// A source revision was zero or out of range.
    #[error("search source revision is invalid")]
    InvalidSourceRevision,
    /// A schema version or field collection was invalid.
    #[error("search index schema is invalid")]
    InvalidSchema,
    /// A filter text value was empty or oversized.
    #[error("search filter value is invalid")]
    InvalidFilterValue,
    /// Query text exceeded a hard or configured bound.
    #[error("search query exceeds its byte bound")]
    QueryTooLarge,
    /// Too many structured filters were supplied.
    #[error("search has too many filters")]
    TooManyFilters,
    /// A filter field was not declared filterable by the active schema.
    #[error("search field is not filterable")]
    FieldNotFilterable,
    /// The rendered filter exceeded its byte bound.
    #[error("search filter exceeds its byte bound")]
    FilterTooLarge,
    /// The requested hit count was zero or too large.
    #[error("search hit limit is invalid")]
    InvalidHitLimit,
    /// The requested offset exceeded its bound.
    #[error("search offset is invalid")]
    InvalidOffset,
    /// A projection document had an invalid top-level shape.
    #[error("search projection document is invalid")]
    InvalidDocument,
    /// A projection document exceeded the byte bound.
    #[error("search projection document exceeds its byte bound")]
    DocumentTooLarge,
    /// A projection document exceeded JSON depth, item, or string bounds.
    #[error("search projection document JSON is unbounded")]
    UnboundedJson,
    /// A backfill cursor was empty or unsafe.
    #[error("search reindex cursor is invalid")]
    InvalidCursor,
}

fn portable_identifier(value: &str, max_bytes: usize) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'0'..=b'9'))
        && value.len() <= max_bytes
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn validate_json(value: &Value, depth: usize) -> Result<(), SearchModelError> {
    if depth > MAX_JSON_DEPTH {
        return Err(SearchModelError::UnboundedJson);
    }
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
        Value::String(value) if value.len() <= MAX_JSON_STRING_BYTES => Ok(()),
        Value::Array(values) if values.len() <= MAX_JSON_ARRAY_ITEMS => {
            for value in values {
                validate_json(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) if values.len() <= MAX_DOCUMENT_FIELDS => {
            for (name, value) in values {
                FieldName::new(name.clone())?;
                validate_json(value, depth + 1)?;
            }
            Ok(())
        }
        Value::String(_) | Value::Array(_) | Value::Object(_) => {
            Err(SearchModelError::UnboundedJson)
        }
    }
}
