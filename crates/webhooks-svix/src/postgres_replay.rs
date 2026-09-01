use std::{fmt, num::NonZeroU32, time::Duration};

use futures::future::BoxFuture;
use omnius_postgres::{PostgresError, PostgresPool};
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ApplicationId, EndpointId, FailureClass, ProviderError, ReplayAdmission,
    ReplayAdmissionRequest, ReplayCompletion, ReplayFingerprint, ReplayLease, ReplayLeaseId,
    ReplayMode, ReplayTaskBinding, ReplayTaskId, ReplayTenantId, ReplayWindow,
};

/// Invalid durable replay-admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("PostgreSQL replay-admission policy is invalid")]
pub struct PostgresReplayAdmissionError;

/// Durable, tenant-scoped replay admission over the application PostgreSQL pool.
#[derive(Clone)]
pub struct PostgresReplayAdmission {
    pool: PostgresPool,
    tenant_id: ReplayTenantId,
    maximum_active: NonZeroU32,
    cooldown_micros: i64,
}

impl PostgresReplayAdmission {
    /// Creates a durable replay admission boundary.
    ///
    /// # Errors
    /// Returns [`PostgresReplayAdmissionError`] for a zero or unrepresentable cooldown.
    pub fn new(
        pool: PostgresPool,
        tenant_id: ReplayTenantId,
        maximum_active: NonZeroU32,
        cooldown: Duration,
    ) -> Result<Self, PostgresReplayAdmissionError> {
        let cooldown_micros = i64::try_from(cooldown.as_micros())
            .ok()
            .filter(|value| *value > 0)
            .ok_or(PostgresReplayAdmissionError)?;
        Ok(Self {
            pool,
            tenant_id,
            maximum_active,
            cooldown_micros,
        })
    }

    async fn reserve_store(
        &self,
        request: &ReplayAdmissionRequest,
    ) -> Result<ReplayLease, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut tx = connection.begin().await.map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO public.svix_replay_tenants (tenant_id) VALUES ($1) ON CONFLICT DO NOTHING",
        )
        .bind(self.tenant_id.as_str())
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "SELECT tenant_id FROM public.svix_replay_tenants WHERE tenant_id = $1 FOR UPDATE",
        )
        .bind(self.tenant_id.as_str())
        .fetch_one(&mut *tx)
        .await
        .map_err(map_sqlx)?;

        if let Some(row) = sqlx::query("SELECT lease_id, application_id, endpoint_id, fingerprint, replay_mode, window_since, window_until, state FROM public.svix_replay_leases WHERE tenant_id = $1 AND application_id = $2 AND endpoint_id = $3 AND fingerprint = $4 FOR UPDATE")
            .bind(self.tenant_id.as_str()).bind(request.application_id().as_str())
            .bind(request.endpoint_id().as_str()).bind(request.fingerprint().as_str())
            .fetch_optional(&mut *tx).await.map_err(map_sqlx)? {
            ensure_matches(&row, request)?;
            let id = lease_id(row.try_get("lease_id").map_err(map_sqlx)?)?;
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(ReplayLease::new(id, request.clone()));
        }

        sqlx::query("INSERT INTO public.svix_replay_cooldowns (tenant_id, application_id, endpoint_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
            .bind(self.tenant_id.as_str()).bind(request.application_id().as_str())
            .bind(request.endpoint_id().as_str()).execute(&mut *tx).await.map_err(map_sqlx)?;
        let cooling: bool = sqlx::query_scalar("SELECT cooldown_until IS NOT NULL AND cooldown_until > clock_timestamp() FROM public.svix_replay_cooldowns WHERE tenant_id = $1 AND application_id = $2 AND endpoint_id = $3 FOR UPDATE")
            .bind(self.tenant_id.as_str()).bind(request.application_id().as_str())
            .bind(request.endpoint_id().as_str()).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
        if cooling {
            return Err(StoreError::RateLimited);
        }
        let overlaps: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM public.svix_replay_leases WHERE tenant_id = $1 AND application_id = $2 AND endpoint_id = $3 AND state IN ('reserved', 'bound') AND window_since <= $5 AND window_until >= $4)")
            .bind(self.tenant_id.as_str()).bind(request.application_id().as_str())
            .bind(request.endpoint_id().as_str()).bind(request.window().since())
            .bind(request.window().until()).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
        if overlaps {
            return Err(StoreError::Conflict);
        }
        let active: i64 = sqlx::query_scalar("SELECT count(*) FROM public.svix_replay_leases WHERE tenant_id = $1 AND state IN ('reserved', 'bound')")
            .bind(self.tenant_id.as_str()).fetch_one(&mut *tx).await.map_err(map_sqlx)?;
        if active >= i64::from(self.maximum_active.get()) {
            return Err(StoreError::RateLimited);
        }

        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO public.svix_replay_leases (lease_id, tenant_id, application_id, endpoint_id, fingerprint, replay_mode, window_since, window_until, state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'reserved')")
            .bind(id).bind(self.tenant_id.as_str()).bind(request.application_id().as_str())
            .bind(request.endpoint_id().as_str()).bind(request.fingerprint().as_str())
            .bind(request.mode().as_str()).bind(request.window().since()).bind(request.window().until())
            .execute(&mut *tx).await.map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(ReplayLease::new(lease_id(id)?, request.clone()))
    }

    async fn bind_store(
        &self,
        lease: &ReplayLease,
        task: &ReplayTaskId,
    ) -> Result<ReplayTaskBinding, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut tx = connection.begin().await.map_err(map_sqlx)?;
        let id = parse_id(lease.id())?;
        let row = lock_lease(&mut tx, self.tenant_id.as_str(), id)
            .await?
            .ok_or(StoreError::NotFound)?;
        ensure_matches(&row, lease.request())?;
        if let Some(existing) = sqlx::query_scalar::<_, String>(
            "SELECT task_id FROM public.svix_replay_task_bindings WHERE lease_id = $1 FOR UPDATE",
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_sqlx)?
        {
            if existing != task.as_str() {
                return Err(StoreError::Conflict);
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(ReplayTaskBinding::new(lease.clone(), task.clone()));
        }
        if row.try_get::<String, _>("state").map_err(map_sqlx)? != "reserved" {
            return Err(StoreError::Conflict);
        }
        sqlx::query("INSERT INTO public.svix_replay_task_bindings (lease_id, tenant_id, application_id, task_id) VALUES ($1, $2, $3, $4)")
            .bind(id).bind(self.tenant_id.as_str()).bind(lease.request().application_id().as_str())
            .bind(task.as_str()).execute(&mut *tx).await.map_err(map_sqlx)?;
        let result = sqlx::query("UPDATE public.svix_replay_leases SET state = 'bound', updated_at = clock_timestamp() WHERE lease_id = $1 AND state = 'reserved'")
            .bind(id).execute(&mut *tx).await.map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Integrity);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(ReplayTaskBinding::new(lease.clone(), task.clone()))
    }

    async fn authorize_store(
        &self,
        application: &ApplicationId,
        task: &ReplayTaskId,
    ) -> Result<ReplayTaskBinding, StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut tx = connection.begin().await.map_err(map_sqlx)?;
        let row = sqlx::query("SELECT l.lease_id, l.application_id, l.endpoint_id, l.fingerprint, l.replay_mode, l.window_since, l.window_until, l.state FROM public.svix_replay_task_bindings b JOIN public.svix_replay_leases l ON l.lease_id = b.lease_id WHERE b.tenant_id = $1 AND b.application_id = $2 AND b.task_id = $3 AND l.state IN ('bound', 'completed') FOR UPDATE OF b, l")
            .bind(self.tenant_id.as_str()).bind(application.as_str()).bind(task.as_str())
            .fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StoreError::NotFound)?;
        let lease = row_lease(&row)?;
        tx.commit().await.map_err(map_sqlx)?;
        Ok(ReplayTaskBinding::new(lease, task.clone()))
    }

    async fn release_store(&self, lease: &ReplayLease) -> Result<(), StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut tx = connection.begin().await.map_err(map_sqlx)?;
        let id = parse_id(lease.id())?;
        let Some(row) = lock_lease(&mut tx, self.tenant_id.as_str(), id).await? else {
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(());
        };
        ensure_matches(&row, lease.request())?;
        if row.try_get::<String, _>("state").map_err(map_sqlx)? != "reserved" {
            return Err(StoreError::Conflict);
        }
        let result = sqlx::query(
            "DELETE FROM public.svix_replay_leases WHERE lease_id = $1 AND state = 'reserved'",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Integrity);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }

    async fn complete_store(
        &self,
        binding: &ReplayTaskBinding,
        completion: ReplayCompletion,
    ) -> Result<(), StoreError> {
        let mut connection = self.pool.acquire().await.map_err(map_pool)?;
        let mut tx = connection.begin().await.map_err(map_sqlx)?;
        let id = parse_id(binding.lease().id())?;
        let row = sqlx::query("SELECT l.lease_id, l.application_id, l.endpoint_id, l.fingerprint, l.replay_mode, l.window_since, l.window_until, l.state, l.terminal_completion FROM public.svix_replay_leases l JOIN public.svix_replay_task_bindings b ON b.lease_id = l.lease_id WHERE l.tenant_id = $1 AND l.lease_id = $2 AND b.task_id = $3 FOR UPDATE OF l, b")
            .bind(self.tenant_id.as_str()).bind(id).bind(binding.task_id().as_str())
            .fetch_optional(&mut *tx).await.map_err(map_sqlx)?.ok_or(StoreError::NotFound)?;
        ensure_matches(&row, binding.lease().request())?;
        let state: String = row.try_get("state").map_err(map_sqlx)?;
        let label = completion_label(completion);
        if state == "completed" {
            let recorded: Option<String> = row.try_get("terminal_completion").map_err(map_sqlx)?;
            if recorded.as_deref() != Some(label) {
                return Err(StoreError::Conflict);
            }
            tx.commit().await.map_err(map_sqlx)?;
            return Ok(());
        }
        if state != "bound" {
            return Err(StoreError::Conflict);
        }
        let result = sqlx::query("UPDATE public.svix_replay_leases SET state = 'completed', terminal_completion = $2, completed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE lease_id = $1 AND state = 'bound'")
            .bind(id).bind(label).execute(&mut *tx).await.map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Integrity);
        }
        let result = sqlx::query("UPDATE public.svix_replay_cooldowns SET cooldown_until = clock_timestamp() + $4::bigint * interval '1 microsecond', last_lease_id = $5, last_completion = $6, updated_at = clock_timestamp() WHERE tenant_id = $1 AND application_id = $2 AND endpoint_id = $3")
            .bind(self.tenant_id.as_str()).bind(binding.lease().request().application_id().as_str())
            .bind(binding.lease().request().endpoint_id().as_str()).bind(self.cooldown_micros)
            .bind(id).bind(label).execute(&mut *tx).await.map_err(map_sqlx)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::Integrity);
        }
        tx.commit().await.map_err(map_sqlx)?;
        Ok(())
    }
}

impl fmt::Debug for PostgresReplayAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresReplayAdmission")
            .field("pool", &self.pool)
            .field("maximum_active", &self.maximum_active)
            .field("cooldown_micros", &self.cooldown_micros)
            .finish_non_exhaustive()
    }
}

impl ReplayAdmission for PostgresReplayAdmission {
    fn reserve<'a>(
        &'a self,
        request: &'a ReplayAdmissionRequest,
    ) -> BoxFuture<'a, Result<ReplayLease, ProviderError>> {
        Box::pin(async move { self.reserve_store(request).await.map_err(Into::into) })
    }
    fn bind_task<'a>(
        &'a self,
        lease: &'a ReplayLease,
        task: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>> {
        Box::pin(async move { self.bind_store(lease, task).await.map_err(Into::into) })
    }
    fn authorize_task<'a>(
        &'a self,
        application: &'a ApplicationId,
        task: &'a ReplayTaskId,
    ) -> BoxFuture<'a, Result<ReplayTaskBinding, ProviderError>> {
        Box::pin(async move {
            self.authorize_store(application, task)
                .await
                .map_err(Into::into)
        })
    }
    fn release_rejected<'a>(
        &'a self,
        lease: &'a ReplayLease,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        Box::pin(async move { self.release_store(lease).await.map_err(Into::into) })
    }
    fn complete<'a>(
        &'a self,
        binding: &'a ReplayTaskBinding,
        completion: ReplayCompletion,
    ) -> BoxFuture<'a, Result<(), ProviderError>> {
        Box::pin(async move {
            self.complete_store(binding, completion)
                .await
                .map_err(Into::into)
        })
    }
}

async fn lock_lease(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant: &str,
    id: Uuid,
) -> Result<Option<sqlx::postgres::PgRow>, StoreError> {
    sqlx::query("SELECT lease_id, application_id, endpoint_id, fingerprint, replay_mode, window_since, window_until, state FROM public.svix_replay_leases WHERE tenant_id = $1 AND lease_id = $2 FOR UPDATE")
        .bind(tenant).bind(id).fetch_optional(&mut **tx).await.map_err(map_sqlx)
}
fn ensure_matches(
    row: &sqlx::postgres::PgRow,
    request: &ReplayAdmissionRequest,
) -> Result<(), StoreError> {
    let application: String = row.try_get("application_id").map_err(map_sqlx)?;
    let endpoint: String = row.try_get("endpoint_id").map_err(map_sqlx)?;
    let fingerprint: String = row.try_get("fingerprint").map_err(map_sqlx)?;
    let mode: String = row.try_get("replay_mode").map_err(map_sqlx)?;
    let since: OffsetDateTime = row.try_get("window_since").map_err(map_sqlx)?;
    let until: OffsetDateTime = row.try_get("window_until").map_err(map_sqlx)?;
    if application != request.application_id().as_str()
        || endpoint != request.endpoint_id().as_str()
        || fingerprint != request.fingerprint().as_str()
        || mode != request.mode().as_str()
        || since != request.window().since()
        || until != request.window().until()
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
fn row_lease(row: &sqlx::postgres::PgRow) -> Result<ReplayLease, StoreError> {
    let id = lease_id(row.try_get("lease_id").map_err(map_sqlx)?)?;
    let application = ApplicationId::new(
        row.try_get::<String, _>("application_id")
            .map_err(map_sqlx)?,
    )
    .map_err(|_| StoreError::Integrity)?;
    let endpoint = EndpointId::new(row.try_get::<String, _>("endpoint_id").map_err(map_sqlx)?)
        .map_err(|_| StoreError::Integrity)?;
    let fingerprint =
        ReplayFingerprint::new(row.try_get::<String, _>("fingerprint").map_err(map_sqlx)?)
            .map_err(|_| StoreError::Integrity)?;
    let mode = match row
        .try_get::<String, _>("replay_mode")
        .map_err(map_sqlx)?
        .as_str()
    {
        "missing" => ReplayMode::Missing,
        "all" => ReplayMode::All,
        "failed" => ReplayMode::Failed,
        _ => return Err(StoreError::Integrity),
    };
    let window = ReplayWindow::new(
        row.try_get("window_since").map_err(map_sqlx)?,
        row.try_get("window_until").map_err(map_sqlx)?,
    )
    .map_err(|_| StoreError::Integrity)?;
    Ok(ReplayLease::new(
        id,
        ReplayAdmissionRequest::new(application, endpoint, mode, window, fingerprint),
    ))
}
const fn completion_label(value: ReplayCompletion) -> &'static str {
    match value {
        ReplayCompletion::Finished => "finished",
        ReplayCompletion::Failed => "failed",
        ReplayCompletion::Missing => "missing",
    }
}
fn parse_id(value: &ReplayLeaseId) -> Result<Uuid, StoreError> {
    Uuid::parse_str(value.as_str()).map_err(|_| StoreError::NotFound)
}
fn lease_id(value: Uuid) -> Result<ReplayLeaseId, StoreError> {
    ReplayLeaseId::new(value.to_string()).map_err(|_| StoreError::Integrity)
}
#[derive(Clone, Copy)]
enum StoreError {
    Unavailable,
    Integrity,
    Conflict,
    NotFound,
    RateLimited,
}
impl From<StoreError> for ProviderError {
    fn from(value: StoreError) -> Self {
        Self::new(match value {
            StoreError::Unavailable => FailureClass::Unavailable,
            StoreError::Integrity => FailureClass::Server,
            StoreError::Conflict => FailureClass::Conflict,
            StoreError::NotFound => FailureClass::NotFound,
            StoreError::RateLimited => FailureClass::RateLimited,
        })
    }
}
fn map_pool(_: PostgresError) -> StoreError {
    StoreError::Unavailable
}
fn map_sqlx(error: sqlx::Error) -> StoreError {
    match error {
        sqlx::Error::Database(database) => match database.code().as_deref() {
            Some("23505") => StoreError::Conflict,
            Some(code) if code.starts_with("22") || code.starts_with("23") => StoreError::Integrity,
            _ => StoreError::Unavailable,
        },
        sqlx::Error::RowNotFound
        | sqlx::Error::ColumnNotFound(_)
        | sqlx::Error::ColumnDecode { .. } => StoreError::Integrity,
        _ => StoreError::Unavailable,
    }
}
