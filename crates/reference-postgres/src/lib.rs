//! Checked-query PostgreSQL adapter for the reference aggregate.

use std::time::{Duration, Instant};

use omnius_pagination::{CursorCodec, CursorPage};
use omnius_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use omnius_reference_domain::{
    ReferenceDomainError, ReferencePaginationError, ReferenceRecord, ReferenceRecordCursor,
    ReferenceRecordId, ReferenceRecordPageRequest, ReferenceRecordPaginator,
    ReferenceRecordRepository, ReferenceRecordUpdate, ReferenceRecordVersion,
};
use sqlx::PgConnection;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

/// PostgreSQL implementation of the reference record persistence port.
#[derive(Clone, Debug)]
pub struct PostgresReferenceRecordRepository {
    pool: PostgresPool,
}
/// PostgreSQL keyset paginator for reference records.
#[derive(Clone, Debug)]
pub struct PostgresReferenceRecordPaginator {
    pool: PostgresPool,
    cursor_codec: CursorCodec,
}

impl PostgresReferenceRecordPaginator {
    /// Creates a paginator over the service pool and cursor signing policy.
    #[must_use]
    pub const fn new(pool: PostgresPool, cursor_codec: CursorCodec) -> Self {
        Self { pool, cursor_codec }
    }

    /// Lists a bounded page using a caller-owned connection or transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceStoreError`] for transient, availability, cursor
    /// encoding, or persisted-data failures.
    pub async fn list_with(
        &self,
        connection: &mut PgConnection,
        request: ReferenceRecordPageRequest,
    ) -> Result<CursorPage<ReferenceRecord>, ReferenceStoreError> {
        let started = Instant::now();
        let cursor = request.cursor();
        let cursor_created_at = cursor.map(ReferenceRecordCursor::created_at);
        let cursor_id = cursor.map(|cursor| cursor.id().as_uuid());
        let name_filter = request.name_filter().map(|filter| filter.as_str());
        let visible_limit = usize::from(request.limit().get());
        let fetch_limit = i64::from(request.limit().get()) + 1;
        let result = async {
            let mut rows = sqlx::query_as!(
                ReferenceRecordRow,
                r#"
                SELECT id, name, created_at, updated_at, version
                FROM reference_records
                WHERE ($1::timestamptz IS NULL
                   OR (created_at, id) > ($1, $2))
                  AND ($3::text IS NULL OR strpos(lower(name), lower($3)) > 0)
                ORDER BY created_at ASC, id ASC
                LIMIT $4
                "#,
                cursor_created_at,
                cursor_id,
                name_filter,
                fetch_limit,
            )
            .fetch_all(&mut *connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
            let has_more = rows.len() > visible_limit;
            if has_more {
                rows.truncate(visible_limit);
            }
            let records = rows
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<ReferenceRecord>, ReferenceStoreError>>()?;
            let next_cursor = if has_more {
                records
                    .last()
                    .map(ReferenceRecordCursor::from_record)
                    .map(|cursor| cursor.encode(&self.cursor_codec))
                    .transpose()
                    .map_err(map_pagination_error)?
            } else {
                None
            };
            Ok(CursorPage::new(records, next_cursor))
        }
        .await;
        record_operation("list", result_label(&result), started.elapsed());
        result
    }
}

impl ReferenceRecordPaginator for PostgresReferenceRecordPaginator {
    type Error = ReferenceStoreError;

    async fn list(
        &self,
        request: ReferenceRecordPageRequest,
    ) -> Result<CursorPage<ReferenceRecord>, Self::Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReferenceStoreError::Unavailable)?;
        self.list_with(&mut connection, request).await
    }
}

impl PostgresReferenceRecordRepository {
    /// Creates an adapter over the owned service pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Inserts a record using a caller-owned connection or transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceStoreError`] for constraint, transient, availability,
    /// or persisted-data failures.
    pub async fn create_with(
        &self,
        connection: &mut PgConnection,
        record: &ReferenceRecord,
    ) -> Result<ReferenceRecord, ReferenceStoreError> {
        let started = Instant::now();
        let result = async {
            let row = sqlx::query_as!(
                ReferenceRecordRow,
                r#"
                INSERT INTO reference_records (id, name, created_at, updated_at, version)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, name, created_at, updated_at, version
                "#,
                record.id().as_uuid(),
                record.name(),
                record.created_at(),
                record.updated_at(),
                i64::try_from(record.version().get())
                    .map_err(|_| ReferenceStoreError::CorruptData)?,
            )
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| map_sqlx_error(&error))?;
            row.try_into()
        }
        .await;
        record_operation("create", result_label(&result), started.elapsed());
        result
    }

    /// Fetches a record using a caller-owned connection or transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceStoreError`] for transient, availability, or
    /// persisted-data failures.
    pub async fn get_with(
        &self,
        connection: &mut PgConnection,
        id: ReferenceRecordId,
    ) -> Result<Option<ReferenceRecord>, ReferenceStoreError> {
        let started = Instant::now();
        let result = sqlx::query_as!(
            ReferenceRecordRow,
            r#"
                SELECT id, name, created_at, updated_at, version
                FROM reference_records
                WHERE id = $1
                "#,
            id.as_uuid(),
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))
        .and_then(|row| row.map(TryInto::try_into).transpose());
        record_operation("get", result_label(&result), started.elapsed());
        result
    }

    /// Updates a record using a caller-owned connection or transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceStoreError`] for constraint, transient, availability,
    /// or persisted-data failures.
    pub async fn update_with(
        &self,
        connection: &mut PgConnection,
        record: &ReferenceRecord,
    ) -> Result<ReferenceRecordUpdate, ReferenceStoreError> {
        let started = Instant::now();
        let expected_version =
            i64::try_from(record.version().get()).map_err(|_| ReferenceStoreError::CorruptData)?;
        let result = sqlx::query_as!(
            ReferenceUpdateRow,
            r#"
            WITH updated AS (
                UPDATE reference_records
                SET name = $2, updated_at = $3
                WHERE id = $1 AND version = $4
                RETURNING id, name, created_at, updated_at, version
            )
            SELECT id, name, created_at, updated_at, version AS "version!", true AS "updated!"
            FROM updated
            UNION ALL
            SELECT
                NULL::uuid,
                NULL::text,
                NULL::timestamptz,
                NULL::timestamptz,
                version,
                false AS "updated!"
            FROM reference_records
            WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM updated)
            LIMIT 1
            "#,
            record.id().as_uuid(),
            record.name(),
            record.updated_at(),
            expected_version,
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))
        .and_then(|row| match row {
            Some(row) => row.try_into(),
            None => Ok(ReferenceRecordUpdate::NotFound),
        });
        record_operation("update", update_result_label(&result), started.elapsed());
        result
    }

    /// Deletes a record using a caller-owned connection or transaction.
    ///
    /// # Errors
    ///
    /// Returns [`ReferenceStoreError`] for transient or availability failures.
    pub async fn delete_with(
        &self,
        connection: &mut PgConnection,
        id: ReferenceRecordId,
    ) -> Result<bool, ReferenceStoreError> {
        let started = Instant::now();
        let result = sqlx::query!(
            r#"
                DELETE FROM reference_records
                WHERE id = $1
                "#,
            id.as_uuid(),
        )
        .execute(&mut *connection)
        .await
        .map(|deleted| deleted.rows_affected() == 1)
        .map_err(|error| map_sqlx_error(&error));
        record_operation("delete", result_label(&result), started.elapsed());
        result
    }
}

impl ReferenceRecordRepository for PostgresReferenceRecordRepository {
    type Error = ReferenceStoreError;

    async fn create(&self, record: &ReferenceRecord) -> Result<ReferenceRecord, Self::Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReferenceStoreError::Unavailable)?;
        self.create_with(&mut connection, record).await
    }

    async fn get(&self, id: ReferenceRecordId) -> Result<Option<ReferenceRecord>, Self::Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReferenceStoreError::Unavailable)?;
        self.get_with(&mut connection, id).await
    }

    async fn update(&self, record: &ReferenceRecord) -> Result<ReferenceRecordUpdate, Self::Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReferenceStoreError::Unavailable)?;
        self.update_with(&mut connection, record).await
    }

    async fn delete(&self, id: ReferenceRecordId) -> Result<bool, Self::Error> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReferenceStoreError::Unavailable)?;
        self.delete_with(&mut connection, id).await
    }
}

#[derive(Debug)]
struct ReferenceRecordRow {
    id: Uuid,
    name: String,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
    version: i64,
}

impl TryFrom<ReferenceRecordRow> for ReferenceRecord {
    type Error = ReferenceStoreError;

    fn try_from(row: ReferenceRecordRow) -> Result<Self, Self::Error> {
        let id = ReferenceRecordId::from_uuid(row.id).map_err(map_domain_error)?;
        let version = persisted_version(row.version)?;
        ReferenceRecord::restore(id, row.name, row.created_at, row.updated_at, version)
            .map_err(map_domain_error)
    }
}

#[derive(Debug)]
struct ReferenceUpdateRow {
    id: Option<Uuid>,
    name: Option<String>,
    created_at: Option<OffsetDateTime>,
    updated_at: Option<OffsetDateTime>,
    version: i64,
    updated: bool,
}

impl TryFrom<ReferenceUpdateRow> for ReferenceRecordUpdate {
    type Error = ReferenceStoreError;

    fn try_from(row: ReferenceUpdateRow) -> Result<Self, Self::Error> {
        if !row.updated {
            return Ok(Self::VersionConflict);
        }
        let id = row.id.ok_or(ReferenceStoreError::CorruptData)?;
        let name = row.name.ok_or(ReferenceStoreError::CorruptData)?;
        let created_at = row.created_at.ok_or(ReferenceStoreError::CorruptData)?;
        let updated_at = row.updated_at.ok_or(ReferenceStoreError::CorruptData)?;
        let record = ReferenceRecord::restore(
            ReferenceRecordId::from_uuid(id).map_err(map_domain_error)?,
            name,
            created_at,
            updated_at,
            persisted_version(row.version)?,
        )
        .map_err(map_domain_error)?;
        Ok(Self::Updated(record))
    }
}

fn persisted_version(version: i64) -> Result<ReferenceRecordVersion, ReferenceStoreError> {
    let version = u64::try_from(version).map_err(|_| ReferenceStoreError::CorruptData)?;
    ReferenceRecordVersion::from_u64(version).map_err(map_domain_error)
}

/// Stable, value-free persistence failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReferenceStoreError {
    /// PostgreSQL or its pool is unavailable.
    #[error("reference record persistence is unavailable")]
    Unavailable,
    /// The whole transaction may be replayed for this safe transient SQLSTATE.
    #[error("reference record transaction encountered a transient conflict")]
    Transient(RetryableSqlState),
    /// A PostgreSQL constraint rejected the requested state.
    #[error("reference record conflicts with persisted state")]
    Conflict,
    /// Persisted state violated an aggregate invariant.
    #[error("reference record persistence contains invalid state")]
    CorruptData,
}

impl RetryableTransactionError for ReferenceStoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Transient(state) => Some(*state),
            _ => None,
        }
    }
}

fn map_sqlx_error(error: &sqlx::Error) -> ReferenceStoreError {
    if let Some(state) = RetryableSqlState::from_sqlx(error) {
        return ReferenceStoreError::Transient(state);
    }
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
    {
        Some(code) if matches!(code.as_ref(), "23505" | "23514" | "23502") => {
            ReferenceStoreError::Conflict
        }
        _ => ReferenceStoreError::Unavailable,
    }
}
const fn map_domain_error(_error: ReferenceDomainError) -> ReferenceStoreError {
    ReferenceStoreError::CorruptData
}

const fn map_pagination_error(_error: ReferencePaginationError) -> ReferenceStoreError {
    ReferenceStoreError::CorruptData
}

fn result_label<T>(result: &Result<T, ReferenceStoreError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(ReferenceStoreError::Conflict) => "conflict",
        Err(ReferenceStoreError::Unavailable) => "unavailable",
        Err(ReferenceStoreError::Transient(_)) => "transient",
        Err(ReferenceStoreError::CorruptData) => "corrupt",
    }
}

fn update_result_label(
    result: &Result<ReferenceRecordUpdate, ReferenceStoreError>,
) -> &'static str {
    match result {
        Ok(ReferenceRecordUpdate::Updated(_)) => "ok",
        Ok(ReferenceRecordUpdate::NotFound) => "not_found",
        Ok(ReferenceRecordUpdate::VersionConflict) => "version_conflict",
        Err(error) => result_label::<ReferenceRecordUpdate>(&Err(*error)),
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!("omnius_postgres_queries_total", "repository" => "reference_records", "operation" => operation, "result" => result)
        .increment(1);
    metrics::histogram!("omnius_postgres_query_duration_seconds", "repository" => "reference_records", "operation" => operation)
        .record(elapsed.as_secs_f64());
}
