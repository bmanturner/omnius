//! Checked-query PostgreSQL adapter for the reference aggregate.

use std::time::{Duration, Instant};

use rsk_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use rsk_reference_domain::{
    ReferenceDomainError, ReferenceRecord, ReferenceRecordId, ReferenceRecordRepository,
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
                INSERT INTO reference_records (id, name, created_at, updated_at)
                VALUES ($1, $2, $3, $4)
                RETURNING id, name, created_at, updated_at
                "#,
                record.id().as_uuid(),
                record.name(),
                record.created_at(),
                record.updated_at(),
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
                SELECT id, name, created_at, updated_at
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
    ) -> Result<Option<ReferenceRecord>, ReferenceStoreError> {
        let started = Instant::now();
        let result = sqlx::query_as!(
            ReferenceRecordRow,
            r#"
                UPDATE reference_records
                SET name = $2, updated_at = $3
                WHERE id = $1
                RETURNING id, name, created_at, updated_at
                "#,
            record.id().as_uuid(),
            record.name(),
            record.updated_at(),
        )
        .fetch_optional(&mut *connection)
        .await
        .map_err(|error| map_sqlx_error(&error))
        .and_then(|row| row.map(TryInto::try_into).transpose());
        record_operation("update", result_label(&result), started.elapsed());
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

    async fn update(
        &self,
        record: &ReferenceRecord,
    ) -> Result<Option<ReferenceRecord>, Self::Error> {
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
}

impl TryFrom<ReferenceRecordRow> for ReferenceRecord {
    type Error = ReferenceStoreError;

    fn try_from(row: ReferenceRecordRow) -> Result<Self, Self::Error> {
        let id = ReferenceRecordId::from_uuid(row.id).map_err(map_domain_error)?;
        ReferenceRecord::restore(id, row.name, row.created_at, row.updated_at)
            .map_err(map_domain_error)
    }
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

fn result_label<T>(result: &Result<T, ReferenceStoreError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(ReferenceStoreError::Conflict) => "conflict",
        Err(ReferenceStoreError::Unavailable) => "unavailable",
        Err(ReferenceStoreError::Transient(_)) => "transient",
        Err(ReferenceStoreError::CorruptData) => "corrupt",
    }
}

fn record_operation(operation: &'static str, result: &'static str, elapsed: Duration) {
    metrics::counter!("rsk_postgres_queries_total", "repository" => "reference_records", "operation" => operation, "result" => result)
        .increment(1);
    metrics::histogram!("rsk_postgres_query_duration_seconds", "repository" => "reference_records", "operation" => operation)
        .record(elapsed.as_secs_f64());
}
