use std::{fmt, time::Duration};

use futures::future::BoxFuture;
use omnius_postgres::PostgresPool;
use sha2::{Digest as _, Sha256};
use sqlx::{Connection as _, Postgres, Row as _, Transaction};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    IndexAlias, IndexSchema, ProjectionClaim, ProjectionClaimRequest, ProjectionFreshness,
    ProjectionLedger, ProjectionStoreError, ReindexCursor, ReindexState, ReindexStatus,
    ReindexStore, ReindexStoreError,
};

/// PostgreSQL durability for projection idempotency, replay cursors, versions, and alias state.
#[derive(Clone)]
pub struct PostgresSearchStore {
    pool: PostgresPool,
}

impl fmt::Debug for PostgresSearchStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresSearchStore")
            .finish_non_exhaustive()
    }
}

impl PostgresSearchStore {
    /// Creates a store over the lifecycle-managed PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    async fn claim_inner(
        &self,
        request: ProjectionClaimRequest<'_>,
    ) -> Result<ProjectionClaim, ProjectionStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        initialize_projection_claim(&mut transaction, &request).await?;
        let stored = load_projection_claim(&mut transaction, &request).await?;
        let existing = match (stored.status.as_str(), stored.lease_active) {
            ("completed", _) => Some(ProjectionClaim::AlreadyApplied),
            ("superseded", _) => Some(ProjectionClaim::Superseded),
            ("processing", true) => Some(ProjectionClaim::Busy),
            ("pending" | "processing", false) => None,
            _ => return Err(ProjectionStoreError::Unavailable),
        };
        if let Some(claim) = existing {
            commit_projection_claim(transaction).await?;
            return Ok(claim);
        }
        if projection_source_is_active(&mut transaction, &request).await? {
            commit_projection_claim(transaction).await?;
            return Ok(ProjectionClaim::Busy);
        }
        if projection_source_is_superseded(&mut transaction, &request).await? {
            mark_projection_superseded(&mut transaction, &request).await?;
            commit_projection_claim(transaction).await?;
            return Ok(ProjectionClaim::Superseded);
        }
        let lease_token = acquire_projection_lease(&mut transaction, &request).await?;
        commit_projection_claim(transaction).await?;
        Ok(ProjectionClaim::Acquired { lease_token })
    }

    async fn complete_inner(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
    ) -> Result<(), ProjectionStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        let result = sqlx::query(
            "UPDATE public.search_projection_events \
             SET status = 'completed', lease_token = NULL, lease_expires_at = NULL, \
                 completed_at = clock_timestamp(), last_error_class = NULL, updated_at = clock_timestamp() \
             WHERE event_id = $1 AND status = 'processing' AND lease_token = $2 \
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(event_id)
        .bind(lease_token)
        .execute(&mut *connection)
        .await
        .map_err(|_| ProjectionStoreError::Unavailable)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(ProjectionStoreError::FenceLost)
        }
    }

    async fn fail_inner(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
        failure_class: &'static str,
    ) -> Result<(), ProjectionStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ProjectionStoreError::Unavailable)?;
        let result = sqlx::query(
            "UPDATE public.search_projection_events \
             SET status = 'pending', lease_token = NULL, lease_expires_at = NULL, \
                 completed_at = NULL, last_error_class = $3, updated_at = clock_timestamp() \
             WHERE event_id = $1 AND status = 'processing' AND lease_token = $2 \
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(event_id)
        .bind(lease_token)
        .bind(failure_class)
        .execute(&mut *connection)
        .await
        .map_err(|_| ProjectionStoreError::Unavailable)?;
        if result.rows_affected() == 1 {
            Ok(())
        } else {
            Err(ProjectionStoreError::FenceLost)
        }
    }

    async fn register_inner(
        &self,
        schema: &IndexSchema,
    ) -> Result<ReindexState, ReindexStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let version = schema_version_i32(schema)?;
        sqlx::query(
            "INSERT INTO public.search_index_versions \
             (index_alias, schema_version, schema_digest, status, projected_count, generation, \
              created_at, updated_at) \
             VALUES ($1, $2, $3, 'preparing', 0, 1, clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (index_alias, schema_version) DO NOTHING",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .bind(schema.digest().to_vec())
        .execute(&mut *connection)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT schema_digest, status, backfill_cursor, projected_count, generation, activated_at \
             FROM public.search_index_versions WHERE index_alias = $1 AND schema_version = $2",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        let stored_digest: Vec<u8> = row
            .try_get("schema_digest")
            .map_err(|_| ReindexStoreError::Unavailable)?;
        if stored_digest.as_slice() != schema.digest().as_slice() {
            return Err(ReindexStoreError::SchemaConflict);
        }
        decode_reindex_state(schema.alias().clone(), schema.version(), &row)
    }

    async fn transition_inner(
        &self,
        schema: &IndexSchema,
        expected_generation: u64,
        expected_status: ReindexStatus,
        next_status: ReindexStatus,
        cursor: Option<&ReindexCursor>,
        projected_delta: u32,
    ) -> Result<ReindexState, ReindexStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let generation =
            i64::try_from(expected_generation).map_err(|_| ReindexStoreError::Conflict)?;
        let version = schema_version_i32(schema)?;
        let cursor_value = cursor.map(ReindexCursor::as_str);
        let result = sqlx::query(
            "UPDATE public.search_index_versions \
             SET status = $5, backfill_cursor = $6, projected_count = projected_count + $7, \
                 generation = generation + 1, updated_at = clock_timestamp() \
             WHERE index_alias = $1 AND schema_version = $2 AND schema_digest = $3 \
               AND generation = $4 AND status = $8",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .bind(schema.digest().to_vec())
        .bind(generation)
        .bind(next_status.as_str())
        .bind(cursor_value)
        .bind(i64::from(projected_delta))
        .bind(expected_status.as_str())
        .execute(&mut *connection)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        if result.rows_affected() != 1 {
            return Err(ReindexStoreError::Conflict);
        }
        let row = sqlx::query(
            "SELECT schema_digest, status, backfill_cursor, projected_count, generation, activated_at \
             FROM public.search_index_versions WHERE index_alias = $1 AND schema_version = $2",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        decode_reindex_state(schema.alias().clone(), schema.version(), &row)
    }

    async fn activate_inner(
        &self,
        schema: &IndexSchema,
        expected_generation: u64,
    ) -> Result<ReindexState, ReindexStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let generation =
            i64::try_from(expected_generation).map_err(|_| ReindexStoreError::Conflict)?;
        let version = schema_version_i32(schema)?;
        let target = sqlx::query(
            "SELECT status, generation, schema_digest FROM public.search_index_versions \
             WHERE index_alias = $1 AND schema_version = $2 FOR UPDATE",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        let target_status: String = target
            .try_get("status")
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let target_generation: i64 = target
            .try_get("generation")
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let target_digest: Vec<u8> = target
            .try_get("schema_digest")
            .map_err(|_| ReindexStoreError::Unavailable)?;
        if target_status != "ready"
            || target_generation != generation
            || target_digest.as_slice() != schema.digest().as_slice()
        {
            return Err(ReindexStoreError::Conflict);
        }
        sqlx::query(
            "UPDATE public.search_index_versions SET status = 'retired', updated_at = clock_timestamp() \
             WHERE index_alias = $1 AND status = 'active' AND schema_version <> $2",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        let row = sqlx::query(
            "UPDATE public.search_index_versions \
             SET status = 'active', generation = generation + 1, activated_at = clock_timestamp(), \
                 updated_at = clock_timestamp() \
             WHERE index_alias = $1 AND schema_version = $2 \
             RETURNING schema_digest, status, backfill_cursor, projected_count, generation, activated_at",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        sqlx::query(
            "INSERT INTO public.search_index_aliases \
             (index_alias, active_schema_version, activated_at, updated_at) \
             VALUES ($1, $2, clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (index_alias) DO UPDATE SET active_schema_version = EXCLUDED.active_schema_version, \
                 activated_at = EXCLUDED.activated_at, updated_at = EXCLUDED.updated_at",
        )
        .bind(schema.alias().as_str())
        .bind(version)
        .execute(&mut *transaction)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?;
        let state = decode_reindex_state(schema.alias().clone(), schema.version(), &row)?;
        transaction
            .commit()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        Ok(state)
    }

    async fn freshness_inner(
        &self,
        alias: &IndexAlias,
    ) -> Result<ProjectionFreshness, ReindexStoreError> {
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| ReindexStoreError::Unavailable)?;
        let row = sqlx::query(
            "SELECT alias.activated_at, \
                    (SELECT MAX(event.completed_at) FROM public.search_projection_events AS event \
                     WHERE event.index_alias = alias.index_alias \
                       AND event.schema_version = alias.active_schema_version \
                       AND event.status = 'completed') AS last_projected_at \
             FROM public.search_index_aliases AS alias WHERE alias.index_alias = $1",
        )
        .bind(alias.as_str())
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| ReindexStoreError::Unavailable)?
        .ok_or(ReindexStoreError::NotActive)?;
        Ok(ProjectionFreshness {
            activated_at: row
                .try_get("activated_at")
                .map_err(|_| ReindexStoreError::Unavailable)?,
            last_projected_at: row
                .try_get("last_projected_at")
                .map_err(|_| ReindexStoreError::Unavailable)?,
        })
    }
}

impl ProjectionLedger for PostgresSearchStore {
    fn claim<'a>(
        &'a self,
        request: ProjectionClaimRequest<'a>,
    ) -> BoxFuture<'a, Result<ProjectionClaim, ProjectionStoreError>> {
        Box::pin(async move { self.claim_inner(request).await })
    }

    fn complete(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
    ) -> BoxFuture<'_, Result<(), ProjectionStoreError>> {
        Box::pin(async move { self.complete_inner(event_id, lease_token).await })
    }

    fn fail(
        &self,
        event_id: Uuid,
        lease_token: Uuid,
        failure_class: &'static str,
    ) -> BoxFuture<'_, Result<(), ProjectionStoreError>> {
        Box::pin(async move { self.fail_inner(event_id, lease_token, failure_class).await })
    }
}

impl ReindexStore for PostgresSearchStore {
    fn register<'a>(
        &'a self,
        schema: &'a IndexSchema,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>> {
        Box::pin(async move { self.register_inner(schema).await })
    }

    fn begin_backfill<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>> {
        Box::pin(async move {
            self.transition_inner(
                schema,
                expected_generation,
                ReindexStatus::Preparing,
                ReindexStatus::Backfilling,
                None,
                0,
            )
            .await
        })
    }

    fn advance<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
        cursor: &'a ReindexCursor,
        projected_delta: u32,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>> {
        Box::pin(async move {
            self.transition_inner(
                schema,
                expected_generation,
                ReindexStatus::Backfilling,
                ReindexStatus::Backfilling,
                Some(cursor),
                projected_delta,
            )
            .await
        })
    }

    fn mark_ready<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>> {
        Box::pin(async move {
            self.transition_inner(
                schema,
                expected_generation,
                ReindexStatus::Backfilling,
                ReindexStatus::Ready,
                None,
                0,
            )
            .await
        })
    }

    fn activate<'a>(
        &'a self,
        schema: &'a IndexSchema,
        expected_generation: u64,
    ) -> BoxFuture<'a, Result<ReindexState, ReindexStoreError>> {
        Box::pin(async move { self.activate_inner(schema, expected_generation).await })
    }

    fn freshness<'a>(
        &'a self,
        alias: &'a IndexAlias,
    ) -> BoxFuture<'a, Result<ProjectionFreshness, ReindexStoreError>> {
        Box::pin(async move { self.freshness_inner(alias).await })
    }
}

struct StoredProjectionClaim {
    status: String,
    lease_active: bool,
}

async fn initialize_projection_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<(), ProjectionStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(source_lock_key(request))
        .execute(&mut **transaction)
        .await
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    sqlx::query(
        "INSERT INTO public.search_projection_events \
         (event_id, tenant_id, index_alias, schema_version, source_id, source_revision, operation, \
          occurred_at, status, attempt_count, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', 0, clock_timestamp(), clock_timestamp()) \
         ON CONFLICT (event_id, index_alias, schema_version) DO NOTHING",
    )
    .bind(request.event_id())
    .bind(request.tenant_id().as_uuid())
    .bind(request.alias().as_str())
    .bind(claim_schema_version(request)?)
    .bind(request.source_id().as_str())
    .bind(request.revision().as_i64())
    .bind(request.operation())
    .bind(request.occurred_at())
    .execute(&mut **transaction)
    .await
    .map_err(|_| ProjectionStoreError::Unavailable)?;
    Ok(())
}

async fn load_projection_claim(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<StoredProjectionClaim, ProjectionStoreError> {
    let row = sqlx::query(
        "SELECT tenant_id, index_alias, schema_version, source_id, source_revision, operation, occurred_at, \
                status, COALESCE(lease_expires_at > clock_timestamp(), FALSE) AS lease_active \
         FROM public.search_projection_events \
         WHERE event_id = $1 AND index_alias = $2 AND schema_version = $3 FOR UPDATE",
    )
    .bind(request.event_id())
    .bind(request.alias().as_str())
    .bind(claim_schema_version(request)?)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_tenant: Uuid = row
        .try_get("tenant_id")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_alias: String = row
        .try_get("index_alias")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_schema_version: i32 = row
        .try_get("schema_version")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_source: String = row
        .try_get("source_id")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_revision: i64 = row
        .try_get("source_revision")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_operation: String = row
        .try_get("operation")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    let stored_occurred_at: OffsetDateTime = row
        .try_get("occurred_at")
        .map_err(|_| ProjectionStoreError::Unavailable)?;
    if stored_tenant != request.tenant_id().as_uuid()
        || stored_alias != request.alias().as_str()
        || stored_schema_version != claim_schema_version(request)?
        || stored_source != request.source_id().as_str()
        || stored_revision != request.revision().as_i64()
        || stored_operation != request.operation()
        || !same_postgres_timestamp(stored_occurred_at, request.occurred_at())
    {
        return Err(ProjectionStoreError::IdentityConflict);
    }
    Ok(StoredProjectionClaim {
        status: row
            .try_get("status")
            .map_err(|_| ProjectionStoreError::Unavailable)?,
        lease_active: row
            .try_get("lease_active")
            .map_err(|_| ProjectionStoreError::Unavailable)?,
    })
}

async fn projection_source_is_active(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<bool, ProjectionStoreError> {
    sqlx::query(
        "SELECT 1 FROM public.search_projection_events \
         WHERE tenant_id = $1 AND index_alias = $2 AND source_id = $3 \
           AND schema_version = $4 AND event_id <> $5 AND status = 'processing' \
           AND lease_expires_at > clock_timestamp() LIMIT 1",
    )
    .bind(request.tenant_id().as_uuid())
    .bind(request.alias().as_str())
    .bind(request.source_id().as_str())
    .bind(claim_schema_version(request)?)
    .bind(request.event_id())
    .fetch_optional(&mut **transaction)
    .await
    .map(|row| row.is_some())
    .map_err(|_| ProjectionStoreError::Unavailable)
}

async fn projection_source_is_superseded(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<bool, ProjectionStoreError> {
    sqlx::query(
        "SELECT 1 FROM public.search_projection_events \
         WHERE tenant_id = $1 AND index_alias = $2 AND source_id = $3 \
           AND schema_version = $4 AND event_id <> $5 AND status = 'completed' \
           AND source_revision >= $6 LIMIT 1",
    )
    .bind(request.tenant_id().as_uuid())
    .bind(request.alias().as_str())
    .bind(request.source_id().as_str())
    .bind(claim_schema_version(request)?)
    .bind(request.event_id())
    .bind(request.revision().as_i64())
    .fetch_optional(&mut **transaction)
    .await
    .map(|row| row.is_some())
    .map_err(|_| ProjectionStoreError::Unavailable)
}

async fn mark_projection_superseded(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<(), ProjectionStoreError> {
    sqlx::query(
        "UPDATE public.search_projection_events \
         SET status = 'superseded', lease_token = NULL, lease_expires_at = NULL, \
             completed_at = clock_timestamp(), last_error_class = NULL, updated_at = clock_timestamp() \
         WHERE event_id = $1 AND index_alias = $2 AND schema_version = $3",
    )
    .bind(request.event_id())
    .bind(request.alias().as_str())
    .bind(claim_schema_version(request)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ProjectionStoreError::Unavailable)?;
    Ok(())
}

async fn acquire_projection_lease(
    transaction: &mut Transaction<'_, Postgres>,
    request: &ProjectionClaimRequest<'_>,
) -> Result<Uuid, ProjectionStoreError> {
    let lease_token = Uuid::now_v7();
    let result = sqlx::query(
        "UPDATE public.search_projection_events \
         SET status = 'processing', \
             attempt_count = CASE WHEN attempt_count = 2147483647 THEN 1 ELSE attempt_count + 1 END, \
             lease_token = $2, \
             lease_expires_at = clock_timestamp() + $3::bigint * INTERVAL '1 microsecond', \
             last_error_class = NULL, completed_at = NULL, updated_at = clock_timestamp() \
         WHERE event_id = $1 AND index_alias = $4 AND schema_version = $5",
    )
    .bind(request.event_id())
    .bind(lease_token)
    .bind(duration_micros(request.lease_duration())?)
    .bind(request.alias().as_str())
    .bind(claim_schema_version(request)?)
    .execute(&mut **transaction)
    .await
    .map_err(|_| ProjectionStoreError::Unavailable)?;
    if result.rows_affected() != 1 {
        return Err(ProjectionStoreError::Unavailable);
    }
    Ok(lease_token)
}

async fn commit_projection_claim(
    transaction: Transaction<'_, Postgres>,
) -> Result<(), ProjectionStoreError> {
    transaction
        .commit()
        .await
        .map_err(|_| ProjectionStoreError::Unavailable)
}

fn claim_schema_version(request: &ProjectionClaimRequest<'_>) -> Result<i32, ProjectionStoreError> {
    i32::try_from(request.schema_version()).map_err(|_| ProjectionStoreError::Unavailable)
}

fn duration_micros(duration: Duration) -> Result<i64, ProjectionStoreError> {
    i64::try_from(duration.as_micros()).map_err(|_| ProjectionStoreError::Unavailable)
}

fn schema_version_i32(schema: &IndexSchema) -> Result<i32, ReindexStoreError> {
    i32::try_from(schema.version()).map_err(|_| ReindexStoreError::SchemaConflict)
}

fn decode_reindex_state(
    alias: IndexAlias,
    version: u32,
    row: &sqlx::postgres::PgRow,
) -> Result<ReindexState, ReindexStoreError> {
    let status: String = row
        .try_get("status")
        .map_err(|_| ReindexStoreError::Unavailable)?;
    let cursor: Option<String> = row
        .try_get("backfill_cursor")
        .map_err(|_| ReindexStoreError::Unavailable)?;
    let projected_count: i64 = row
        .try_get("projected_count")
        .map_err(|_| ReindexStoreError::Unavailable)?;
    let generation: i64 = row
        .try_get("generation")
        .map_err(|_| ReindexStoreError::Unavailable)?;
    Ok(ReindexState {
        alias,
        version,
        status: ReindexStatus::from_database(&status)?,
        cursor: cursor
            .map(ReindexCursor::new)
            .transpose()
            .map_err(|_| ReindexStoreError::Unavailable)?,
        projected_count: u64::try_from(projected_count)
            .map_err(|_| ReindexStoreError::Unavailable)?,
        generation: u64::try_from(generation).map_err(|_| ReindexStoreError::Unavailable)?,
        activated_at: row
            .try_get("activated_at")
            .map_err(|_| ReindexStoreError::Unavailable)?,
    })
}

fn same_postgres_timestamp(left: OffsetDateTime, right: OffsetDateTime) -> bool {
    left.unix_timestamp_nanos().div_euclid(1_000) == right.unix_timestamp_nanos().div_euclid(1_000)
}

fn source_lock_key(request: &ProjectionClaimRequest<'_>) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(request.tenant_id().as_uuid().as_bytes());
    hasher.update([0]);
    hasher.update(request.alias().as_str().as_bytes());
    hasher.update([0]);
    hasher.update(request.schema_version().to_be_bytes());
    hasher.update([0]);
    hasher.update(request.source_id().as_str().as_bytes());
    let digest = hasher.finalize();
    i64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}
