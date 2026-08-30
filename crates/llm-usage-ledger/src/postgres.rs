use std::fmt;

use async_trait::async_trait;
use omnius_postgres::{
    PostgresPool, PostgresTransactionRunner, RetryableSqlState, RetryableTransactionError,
    TransactionIsolation, TransactionRetryConfig, TransactionRetryConfigError, TransactionRunError,
};
use sqlx::{FromRow, PgConnection, types::Json};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    BudgetDimension, BudgetPolicy, BudgetScope, CompareAndSetDecision, CostMicrounits,
    IdempotencyKey, LedgerEvent, LedgerEventKind, LedgerVersion, RepositoryError, Reservation,
    ReservationId, ReservationRequest, ReservationState, ReserveStoreDecision, TenantId,
    UsageAmount, UsageBreakdown, UsageDelta, UsageLedgerRepository, UsageStatus, UsageVector,
};

const DIMENSIONS: [BudgetDimension; 9] = [
    BudgetDimension::Tenant,
    BudgetDimension::Principal,
    BudgetDimension::ApiKey,
    BudgetDimension::Provider,
    BudgetDimension::Model,
    BudgetDimension::Route,
    BudgetDimension::Tool,
    BudgetDimension::Operation,
    BudgetDimension::Job,
];

const LOAD_HEADER: &str = r"
    SELECT tenant_id, reservation_id, idempotency_key, request_fingerprint,
           principal_id, api_key_id, provider_id, model_id, route_id, tool_id, operation_id,
           job_id, scope_snapshot, estimate_snapshot, policy_snapshot, state_snapshot, state,
           usage_status, version,
           effective_requests::text AS effective_requests,
           effective_concurrent_streams::text AS effective_concurrent_streams,
           effective_tokens::text AS effective_tokens,
           effective_units::text AS effective_units,
           effective_tool_calls::text AS effective_tool_calls,
           effective_media_bytes::text AS effective_media_bytes,
           effective_cost_microunits::text AS effective_cost_microunits
    FROM llm_budget_reservations
    WHERE tenant_id = $1 AND reservation_id = $2
";

const INSERT_HEADER: &str = r"
    INSERT INTO llm_budget_reservations (
        tenant_id, reservation_id, idempotency_key, request_fingerprint,
        principal_id, api_key_id, provider_id, model_id, route_id, tool_id, operation_id, job_id,
        scope_snapshot, estimate_snapshot, policy_snapshot, state_snapshot,
        state, usage_status, version,
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits
    ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
        $13, $14, $15, $16, $17, $18, $19,
        $20::numeric, $21::numeric, $22::numeric, $23::numeric,
        $24::numeric, $25::numeric, $26::numeric
    )
";

const UPDATE_HEADER: &str = r"
    UPDATE llm_budget_reservations
    SET state_snapshot = $4, state = $5, usage_status = $6, version = $7,
        effective_requests = $8::numeric,
        effective_concurrent_streams = $9::numeric,
        effective_tokens = $10::numeric,
        effective_units = $11::numeric,
        effective_tool_calls = $12::numeric,
        effective_media_bytes = $13::numeric,
        effective_cost_microunits = $14::numeric,
        updated_at = clock_timestamp()
    WHERE tenant_id = $1 AND reservation_id = $2 AND version = $3
";

const INSERT_LEDGER_FACT: &str = r"
    INSERT INTO llm_usage_ledger (
        tenant_id, reservation_id, version, attribution, event_kind, state, usage_status,
        event_snapshot,
        effective_requests, effective_concurrent_streams, effective_tokens, effective_units,
        effective_tool_calls, effective_media_bytes, effective_cost_microunits,
        delta_requests, delta_concurrent_streams, delta_tokens, delta_units,
        delta_tool_calls, delta_media_bytes, delta_cost_microunits
    ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8,
        $9::numeric, $10::numeric, $11::numeric, $12::numeric,
        $13::numeric, $14::numeric, $15::numeric,
        $16::numeric, $17::numeric, $18::numeric, $19::numeric,
        $20::numeric, $21::numeric, $22::numeric
    )
";

const INSERT_COST_ADJUSTMENT: &str = r"
    INSERT INTO llm_cost_adjustments (
        tenant_id, reservation_id, version, attribution, basis,
        previous_cost_microunits, new_cost_microunits, delta_cost_microunits
    ) VALUES ($1, $2, $3, $4, $5, $6::numeric, $7::numeric, $8::numeric)
";

const EVENT_AT: &str = r"
    SELECT event_snapshot FROM llm_usage_ledger
    WHERE tenant_id = $1 AND reservation_id = $2 AND version = $3 AND attribution = 'primary'
";

const LOCK_IDEMPOTENCY: &str = r"
    SELECT pg_advisory_xact_lock(hashtextextended(
        'llm-usage:idempotency:' || $1::text || ':' || $2::text, 0))
";
const LOCK_RESERVATION: &str = r"
    SELECT pg_advisory_xact_lock(hashtextextended(
        'llm-usage:reservation:' || $1::text || ':' || $2::text, 0))
";
const LOCK_DIMENSION: &str = r"
    SELECT pg_advisory_xact_lock(hashtextextended(
        'llm-usage:dimension:' || $1::text || ':' || $2::text || ':' || COALESCE($3::text, ''), 0))
";

type AggregateRow = (String, String, String, String, String, String, String);

/// Production PostgreSQL adapter for authoritative, tenant-scoped LLM accounting.
#[derive(Clone)]
pub struct PostgresUsageLedgerRepository {
    pool: PostgresPool,
    transactions: PostgresTransactionRunner,
}

impl PostgresUsageLedgerRepository {
    /// Creates an adapter whose writes run as bounded serializable transactions.
    ///
    /// # Errors
    ///
    /// Returns [`TransactionRetryConfigError`] when the shared retry policy is invalid.
    pub fn new(
        pool: PostgresPool,
        mut retry: TransactionRetryConfig,
    ) -> Result<Self, TransactionRetryConfigError> {
        retry.isolation = TransactionIsolation::Serializable;
        let transactions = PostgresTransactionRunner::new(pool.clone(), retry)?;
        Ok(Self { pool, transactions })
    }

    /// Borrows the managed pool used for read-only diagnostics and composition.
    #[must_use]
    pub const fn pool(&self) -> &PostgresPool {
        &self.pool
    }
}

impl fmt::Debug for PostgresUsageLedgerRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresUsageLedgerRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl UsageLedgerRepository for PostgresUsageLedgerRepository {
    async fn reserve(
        &self,
        request: &ReservationRequest,
    ) -> Result<ReserveStoreDecision, RepositoryError> {
        let tenant = canonical_tenant(request.scope().tenant()).map_err(map_store_error)?;
        let request = request.clone();
        self.transactions
            .run_repeatable("llm_usage_reserve", async move |connection| {
                reserve_transaction(connection, tenant, &request).await
            })
            .await
            .map_err(map_run_error)
    }

    async fn load(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
    ) -> Result<Option<Reservation>, RepositoryError> {
        let tenant = canonical_tenant(tenant).map_err(map_store_error)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        load_reservation(&mut connection, tenant, reservation_id.as_str())
            .await
            .map_err(map_store_error)
    }

    async fn compare_and_set(
        &self,
        tenant: &TenantId,
        expected_version: LedgerVersion,
        replacement: &Reservation,
        event: &LedgerEvent,
    ) -> Result<CompareAndSetDecision, RepositoryError> {
        let tenant_uuid = canonical_tenant(tenant).map_err(map_store_error)?;
        if replacement.scope().tenant() != tenant {
            return Err(RepositoryError::CorruptState);
        }
        let replacement = replacement.clone();
        let event = event.clone();
        self.transactions
            .run_repeatable("llm_usage_compare_and_set", async move |connection| {
                compare_and_set_transaction(
                    connection,
                    tenant_uuid,
                    expected_version,
                    &replacement,
                    &event,
                )
                .await
            })
            .await
            .map_err(map_run_error)
    }

    async fn event_at(
        &self,
        tenant: &TenantId,
        reservation_id: &ReservationId,
        version: LedgerVersion,
    ) -> Result<Option<LedgerEvent>, RepositoryError> {
        let tenant = canonical_tenant(tenant).map_err(map_store_error)?;
        let version = version_to_i64(version).map_err(map_store_error)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| RepositoryError::Unavailable)?;
        load_event(&mut connection, tenant, reservation_id.as_str(), version)
            .await
            .map_err(map_store_error)
    }
}

async fn reserve_transaction(
    connection: &mut PgConnection,
    tenant: Uuid,
    request: &ReservationRequest,
) -> Result<ReserveStoreDecision, StoreError> {
    advisory_lock(
        connection,
        LOCK_IDEMPOTENCY,
        tenant,
        request.idempotency_key().as_str(),
    )
    .await?;
    let existing_id: Option<String> = sqlx::query_scalar(
        "SELECT reservation_id FROM llm_budget_reservations \
         WHERE tenant_id = $1 AND idempotency_key = $2",
    )
    .bind(tenant)
    .bind(request.idempotency_key().as_str())
    .fetch_optional(&mut *connection)
    .await
    .map_err(StoreError::database)?;
    if let Some(existing_id) = existing_id {
        let reservation = load_reservation(connection, tenant, &existing_id)
            .await?
            .ok_or(StoreError::Corrupt)?;
        let event = load_event(
            connection,
            tenant,
            reservation.id().as_str(),
            version_to_i64(reservation.version())?,
        )
        .await?
        .ok_or(StoreError::Corrupt)?;
        return if reservation.is_replay_of(request) {
            Ok(ReserveStoreDecision::Replay { reservation, event })
        } else {
            Ok(ReserveStoreDecision::Conflict)
        };
    }

    advisory_lock(connection, LOCK_RESERVATION, tenant, request.id().as_str()).await?;
    let duplicate_id: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM llm_budget_reservations \
         WHERE tenant_id = $1 AND reservation_id = $2)",
    )
    .bind(tenant)
    .bind(request.id().as_str())
    .fetch_one(&mut *connection)
    .await
    .map_err(StoreError::database)?;
    if duplicate_id {
        return Ok(ReserveStoreDecision::Conflict);
    }

    lock_scope_dimensions(connection, tenant, request.scope()).await?;
    let requested = request
        .estimate()
        .checked_total()
        .map_err(|_| StoreError::Arithmetic)?;
    for policy in request.policies() {
        let current =
            aggregate_for_dimension(connection, tenant, request.scope(), policy.dimension())
                .await?;
        if let Some(exhaustion) =
            policy
                .ceilings()
                .first_exhaustion(policy.dimension(), &current, &requested)
        {
            return Ok(ReserveStoreDecision::Exhausted(exhaustion));
        }
    }

    let (reservation, event) = Reservation::initial(request).map_err(|_| StoreError::Arithmetic)?;
    insert_header(connection, tenant, &reservation).await?;
    append_facts(
        connection,
        tenant,
        &UsageBreakdown::default(),
        &reservation,
        &event,
    )
    .await?;
    Ok(ReserveStoreDecision::Applied { reservation, event })
}

async fn compare_and_set_transaction(
    connection: &mut PgConnection,
    tenant: Uuid,
    expected_version: LedgerVersion,
    replacement: &Reservation,
    event: &LedgerEvent,
) -> Result<CompareAndSetDecision, StoreError> {
    advisory_lock(
        connection,
        LOCK_RESERVATION,
        tenant,
        replacement.id().as_str(),
    )
    .await?;
    let Some(current) = load_reservation(connection, tenant, replacement.id().as_str()).await?
    else {
        return Ok(CompareAndSetDecision::NotFound);
    };
    if current.version() != expected_version {
        return Ok(CompareAndSetDecision::VersionConflict);
    }
    validate_replacement(&current, expected_version, replacement, event)?;
    lock_scope_dimensions(connection, tenant, current.scope()).await?;

    let effective = replacement.effective_usage();
    let total = effective
        .checked_total()
        .map_err(|_| StoreError::Arithmetic)?;
    let result = sqlx::query(UPDATE_HEADER)
        .bind(tenant)
        .bind(replacement.id().as_str())
        .bind(version_to_i64(expected_version)?)
        .bind(Json(replacement.state()))
        .bind(state_sql(replacement.state()))
        .bind(usage_status_sql(replacement.state().usage_status()))
        .bind(version_to_i64(replacement.version())?)
        .bind(total.requests().get().to_string())
        .bind(total.concurrent_streams().get().to_string())
        .bind(total.tokens().get().to_string())
        .bind(total.units().get().to_string())
        .bind(total.tool_calls().get().to_string())
        .bind(total.media_bytes().get().to_string())
        .bind(total.cost().get().to_string())
        .execute(&mut *connection)
        .await
        .map_err(StoreError::database)?;
    if result.rows_affected() != 1 {
        return Ok(CompareAndSetDecision::VersionConflict);
    }

    let previous = current.effective_usage();
    append_facts(connection, tenant, &previous, replacement, event).await?;
    Ok(CompareAndSetDecision::Applied)
}

fn validate_replacement(
    current: &Reservation,
    expected_version: LedgerVersion,
    replacement: &Reservation,
    event: &LedgerEvent,
) -> Result<(), StoreError> {
    let next_version = expected_version
        .checked_next()
        .map_err(|_| StoreError::Arithmetic)?;
    if replacement.version() != next_version
        || current.id() != replacement.id()
        || current.idempotency_key() != replacement.idempotency_key()
        || current.fingerprint() != replacement.fingerprint()
        || current.scope() != replacement.scope()
        || current.estimate() != replacement.estimate()
        || current.policies() != replacement.policies()
    {
        return Err(StoreError::Corrupt);
    }
    let expected_kind = match (current.state(), replacement.state()) {
        (
            ReservationState::Reserved,
            ReservationState::Committed(_) | ReservationState::Reconciled(_),
        ) => LedgerEventKind::Committed,
        (ReservationState::Reserved, ReservationState::Released) => LedgerEventKind::Released,
        (ReservationState::Committed(_), ReservationState::Reconciled(_)) => {
            LedgerEventKind::Reconciled
        }
        _ => return Err(StoreError::Corrupt),
    };
    if let ReservationState::Reconciled(actual) = replacement.state() {
        let preserved = actual
            .includes_dispatched_request()
            .map_err(|_| StoreError::Arithmetic)?;
        if !preserved {
            return Err(StoreError::Corrupt);
        }
    }
    let previous = current.effective_usage();
    let effective = replacement.effective_usage();
    let adjustment =
        UsageDelta::between(&effective, &previous).map_err(|_| StoreError::Arithmetic)?;
    if event.version() != replacement.version()
        || event.kind() != expected_kind
        || event.state() != replacement.state().kind()
        || event.usage_status() != replacement.state().usage_status()
        || event.dimensions() != replacement.scope().dimensions()
        || event.effective_usage() != &effective
        || event.adjustment() != &adjustment
    {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn insert_header(
    connection: &mut PgConnection,
    tenant: Uuid,
    reservation: &Reservation,
) -> Result<(), StoreError> {
    let scope = reservation.scope();
    let total = reservation
        .effective_usage()
        .checked_total()
        .map_err(|_| StoreError::Arithmetic)?;
    let result = sqlx::query(INSERT_HEADER)
        .bind(tenant)
        .bind(reservation.id().as_str())
        .bind(reservation.idempotency_key().as_str())
        .bind(reservation.fingerprint().as_bytes().as_slice())
        .bind(scope.principal().map(crate::PrincipalId::as_str))
        .bind(scope.api_key().map(crate::ApiKeyId::as_str))
        .bind(scope.provider().map(crate::ProviderId::as_str))
        .bind(scope.model().map(crate::ModelId::as_str))
        .bind(scope.route().map(crate::RouteId::as_str))
        .bind(scope.tool().map(crate::ToolId::as_str))
        .bind(scope.operation().map(crate::OperationId::as_str))
        .bind(scope.job().map(crate::JobId::as_str))
        .bind(Json(scope))
        .bind(Json(reservation.estimate()))
        .bind(Json(reservation.policies()))
        .bind(Json(reservation.state()))
        .bind(state_sql(reservation.state()))
        .bind(usage_status_sql(reservation.state().usage_status()))
        .bind(version_to_i64(reservation.version())?)
        .bind(total.requests().get().to_string())
        .bind(total.concurrent_streams().get().to_string())
        .bind(total.tokens().get().to_string())
        .bind(total.units().get().to_string())
        .bind(total.tool_calls().get().to_string())
        .bind(total.media_bytes().get().to_string())
        .bind(total.cost().get().to_string())
        .execute(&mut *connection)
        .await
        .map_err(StoreError::database)?;
    if result.rows_affected() != 1 {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

async fn append_facts(
    connection: &mut PgConnection,
    tenant: Uuid,
    previous: &UsageBreakdown,
    replacement: &Reservation,
    event: &LedgerEvent,
) -> Result<(), StoreError> {
    let effective = replacement.effective_usage();
    let current_vectors = attributed_vectors(&effective);
    let previous_vectors = attributed_vectors(previous);
    let version = version_to_i64(replacement.version())?;
    let basis = cost_basis(event.kind());

    for ((attribution, current), (_, prior)) in current_vectors.into_iter().zip(previous_vectors) {
        let delta = VectorDelta::between(current, prior);
        sqlx::query(INSERT_LEDGER_FACT)
            .bind(tenant)
            .bind(replacement.id().as_str())
            .bind(version)
            .bind(attribution)
            .bind(event_kind_sql(event.kind()))
            .bind(state_sql(replacement.state()))
            .bind(usage_status_sql(replacement.state().usage_status()))
            .bind(Json(event))
            .bind(current.requests().get().to_string())
            .bind(current.concurrent_streams().get().to_string())
            .bind(current.tokens().get().to_string())
            .bind(current.units().get().to_string())
            .bind(current.tool_calls().get().to_string())
            .bind(current.media_bytes().get().to_string())
            .bind(current.cost().get().to_string())
            .bind(delta.requests.to_string())
            .bind(delta.concurrent_streams.to_string())
            .bind(delta.tokens.to_string())
            .bind(delta.units.to_string())
            .bind(delta.tool_calls.to_string())
            .bind(delta.media_bytes.to_string())
            .bind(delta.cost_microunits.to_string())
            .execute(&mut *connection)
            .await
            .map_err(StoreError::database)?;
        sqlx::query(INSERT_COST_ADJUSTMENT)
            .bind(tenant)
            .bind(replacement.id().as_str())
            .bind(version)
            .bind(attribution)
            .bind(basis)
            .bind(prior.cost().get().to_string())
            .bind(current.cost().get().to_string())
            .bind(delta.cost_microunits.to_string())
            .execute(&mut *connection)
            .await
            .map_err(StoreError::database)?;
    }
    Ok(())
}

async fn lock_scope_dimensions(
    connection: &mut PgConnection,
    tenant: Uuid,
    scope: &BudgetScope,
) -> Result<(), StoreError> {
    for dimension in DIMENSIONS {
        let value = dimension_value(scope, dimension);
        if dimension != BudgetDimension::Tenant && value.is_none() {
            continue;
        }
        sqlx::query(LOCK_DIMENSION)
            .bind(tenant)
            .bind(dimension_sql(dimension))
            .bind(value)
            .execute(&mut *connection)
            .await
            .map_err(StoreError::database)?;
    }
    Ok(())
}

async fn advisory_lock(
    connection: &mut PgConnection,
    statement: &'static str,
    tenant: Uuid,
    value: &str,
) -> Result<(), StoreError> {
    sqlx::query(statement)
        .bind(tenant)
        .bind(value)
        .execute(&mut *connection)
        .await
        .map(|_| ())
        .map_err(StoreError::database)
}

async fn aggregate_for_dimension(
    connection: &mut PgConnection,
    tenant: Uuid,
    scope: &BudgetScope,
    dimension: BudgetDimension,
) -> Result<UsageVector, StoreError> {
    let query = sqlx::query_as::<_, AggregateRow>(aggregate_statement(dimension)).bind(tenant);
    let row = match dimension_value(scope, dimension) {
        Some(value) if dimension != BudgetDimension::Tenant => query
            .bind(value)
            .fetch_one(&mut *connection)
            .await
            .map_err(StoreError::database)?,
        _ if dimension == BudgetDimension::Tenant => query
            .fetch_one(&mut *connection)
            .await
            .map_err(StoreError::database)?,
        _ => return Err(StoreError::Corrupt),
    };
    vector_from_aggregate(&row)
}

fn aggregate_statement(dimension: BudgetDimension) -> &'static str {
    macro_rules! aggregate_query {
        ($predicate:literal) => {
            concat!(
                "SELECT COALESCE(SUM(effective_requests), 0)::text, ",
                "COALESCE(SUM(effective_concurrent_streams), 0)::text, ",
                "COALESCE(SUM(effective_tokens), 0)::text, ",
                "COALESCE(SUM(effective_units), 0)::text, ",
                "COALESCE(SUM(effective_tool_calls), 0)::text, ",
                "COALESCE(SUM(effective_media_bytes), 0)::text, ",
                "COALESCE(SUM(effective_cost_microunits), 0)::text ",
                "FROM llm_budget_reservations ",
                "WHERE tenant_id = $1 AND state <> 'released'",
                $predicate
            )
        };
    }

    match dimension {
        BudgetDimension::Tenant => aggregate_query!(""),
        BudgetDimension::Principal => aggregate_query!(" AND principal_id = $2"),
        BudgetDimension::ApiKey => aggregate_query!(" AND api_key_id = $2"),
        BudgetDimension::Provider => aggregate_query!(" AND provider_id = $2"),
        BudgetDimension::Model => aggregate_query!(" AND model_id = $2"),
        BudgetDimension::Route => aggregate_query!(" AND route_id = $2"),
        BudgetDimension::Tool => aggregate_query!(" AND tool_id = $2"),
        BudgetDimension::Operation => aggregate_query!(" AND operation_id = $2"),
        BudgetDimension::Job => aggregate_query!(" AND job_id = $2"),
    }
}

async fn load_reservation(
    connection: &mut PgConnection,
    tenant: Uuid,
    reservation_id: &str,
) -> Result<Option<Reservation>, StoreError> {
    sqlx::query_as::<_, StoredHeader>(LOAD_HEADER)
        .bind(tenant)
        .bind(reservation_id)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::database)?
        .map(StoredHeader::into_reservation)
        .transpose()
}

async fn load_event(
    connection: &mut PgConnection,
    tenant: Uuid,
    reservation_id: &str,
    version: i64,
) -> Result<Option<LedgerEvent>, StoreError> {
    let event: Option<Json<LedgerEvent>> = sqlx::query_scalar(EVENT_AT)
        .bind(tenant)
        .bind(reservation_id)
        .bind(version)
        .fetch_optional(&mut *connection)
        .await
        .map_err(StoreError::database)?;
    let event = event.map(|value| value.0);
    if event
        .as_ref()
        .is_some_and(|value| version_to_i64(value.version()).ok() != Some(version))
    {
        return Err(StoreError::Corrupt);
    }
    Ok(event)
}

#[derive(FromRow)]
struct StoredHeader {
    tenant_id: Uuid,
    reservation_id: String,
    idempotency_key: String,
    request_fingerprint: Vec<u8>,
    principal_id: Option<String>,
    api_key_id: Option<String>,
    provider_id: Option<String>,
    model_id: Option<String>,
    route_id: Option<String>,
    tool_id: Option<String>,
    operation_id: Option<String>,
    job_id: Option<String>,
    scope_snapshot: Json<BudgetScope>,
    estimate_snapshot: Json<UsageBreakdown>,
    policy_snapshot: Json<Vec<BudgetPolicy>>,
    state_snapshot: Json<ReservationState>,
    state: String,
    usage_status: String,
    version: i64,
    effective_requests: String,
    effective_concurrent_streams: String,
    effective_tokens: String,
    effective_units: String,
    effective_tool_calls: String,
    effective_media_bytes: String,
    effective_cost_microunits: String,
}

impl StoredHeader {
    fn into_reservation(self) -> Result<Reservation, StoreError> {
        let scope = self.scope_snapshot.0;
        if scope.tenant().as_str() != self.tenant_id.to_string()
            || scope.principal().map(crate::PrincipalId::as_str) != self.principal_id.as_deref()
            || scope.api_key().map(crate::ApiKeyId::as_str) != self.api_key_id.as_deref()
            || scope.provider().map(crate::ProviderId::as_str) != self.provider_id.as_deref()
            || scope.model().map(crate::ModelId::as_str) != self.model_id.as_deref()
            || scope.route().map(crate::RouteId::as_str) != self.route_id.as_deref()
            || scope.tool().map(crate::ToolId::as_str) != self.tool_id.as_deref()
            || scope.operation().map(crate::OperationId::as_str) != self.operation_id.as_deref()
            || scope.job().map(crate::JobId::as_str) != self.job_id.as_deref()
        {
            return Err(StoreError::Corrupt);
        }
        let fingerprint: [u8; 32] = self
            .request_fingerprint
            .try_into()
            .map_err(|_| StoreError::Corrupt)?;
        let request = ReservationRequest::new(
            ReservationId::new(&self.reservation_id).map_err(|_| StoreError::Corrupt)?,
            IdempotencyKey::new(&self.idempotency_key).map_err(|_| StoreError::Corrupt)?,
            crate::RequestFingerprint::new(fingerprint),
            scope,
            self.estimate_snapshot.0,
            self.policy_snapshot.0,
        )
        .map_err(|_| StoreError::Corrupt)?;
        let state = self.state_snapshot.0;
        if state_sql(&state) != self.state
            || usage_status_sql(state.usage_status()) != self.usage_status
        {
            return Err(StoreError::Corrupt);
        }
        let reservation = Reservation::restore(request, state, i64_to_version(self.version)?)
            .map_err(|_| StoreError::Corrupt)?;
        let stored_total = vector_from_aggregate(&(
            self.effective_requests,
            self.effective_concurrent_streams,
            self.effective_tokens,
            self.effective_units,
            self.effective_tool_calls,
            self.effective_media_bytes,
            self.effective_cost_microunits,
        ))?;
        let effective_total = reservation
            .effective_usage()
            .checked_total()
            .map_err(|_| StoreError::Arithmetic)?;
        if stored_total != effective_total {
            return Err(StoreError::Corrupt);
        }
        Ok(reservation)
    }
}

#[derive(Clone, Copy)]
struct VectorDelta {
    requests: i128,
    concurrent_streams: i128,
    tokens: i128,
    units: i128,
    tool_calls: i128,
    media_bytes: i128,
    cost_microunits: i128,
}

impl VectorDelta {
    fn between(current: &UsageVector, previous: &UsageVector) -> Self {
        Self {
            requests: i128::from(current.requests().get()) - i128::from(previous.requests().get()),
            concurrent_streams: i128::from(current.concurrent_streams().get())
                - i128::from(previous.concurrent_streams().get()),
            tokens: i128::from(current.tokens().get()) - i128::from(previous.tokens().get()),
            units: i128::from(current.units().get()) - i128::from(previous.units().get()),
            tool_calls: i128::from(current.tool_calls().get())
                - i128::from(previous.tool_calls().get()),
            media_bytes: i128::from(current.media_bytes().get())
                - i128::from(previous.media_bytes().get()),
            cost_microunits: i128::from(current.cost().get()) - i128::from(previous.cost().get()),
        }
    }
}

fn attributed_vectors(breakdown: &UsageBreakdown) -> [(&'static str, &UsageVector); 4] {
    [
        ("primary", breakdown.primary_usage()),
        ("retry", breakdown.retry_usage()),
        ("repair", breakdown.repair_usage()),
        ("tool", breakdown.tool_usage()),
    ]
}

fn vector_from_aggregate(row: &AggregateRow) -> Result<UsageVector, StoreError> {
    Ok(UsageVector::zero()
        .with_requests(UsageAmount::new(parse_u64(&row.0)?))
        .with_concurrent_streams(UsageAmount::new(parse_u64(&row.1)?))
        .with_tokens(UsageAmount::new(parse_u64(&row.2)?))
        .with_units(UsageAmount::new(parse_u64(&row.3)?))
        .with_tool_calls(UsageAmount::new(parse_u64(&row.4)?))
        .with_media_bytes(UsageAmount::new(parse_u64(&row.5)?))
        .with_cost(CostMicrounits::new(parse_u64(&row.6)?)))
}

fn parse_u64(value: &str) -> Result<u64, StoreError> {
    value.parse().map_err(|_| StoreError::Arithmetic)
}

fn canonical_tenant(tenant: &TenantId) -> Result<Uuid, StoreError> {
    let parsed = Uuid::parse_str(tenant.as_str()).map_err(|_| StoreError::Corrupt)?;
    if parsed.to_string() != tenant.as_str() {
        return Err(StoreError::Corrupt);
    }
    Ok(parsed)
}

fn version_to_i64(version: LedgerVersion) -> Result<i64, StoreError> {
    i64::try_from(version.get()).map_err(|_| StoreError::Arithmetic)
}

fn i64_to_version(version: i64) -> Result<LedgerVersion, StoreError> {
    Ok(LedgerVersion::new(
        u64::try_from(version).map_err(|_| StoreError::Corrupt)?,
    ))
}

fn dimension_value(scope: &BudgetScope, dimension: BudgetDimension) -> Option<&str> {
    match dimension {
        BudgetDimension::Tenant => Some(scope.tenant().as_str()),
        BudgetDimension::Principal => scope.principal().map(crate::PrincipalId::as_str),
        BudgetDimension::ApiKey => scope.api_key().map(crate::ApiKeyId::as_str),
        BudgetDimension::Provider => scope.provider().map(crate::ProviderId::as_str),
        BudgetDimension::Model => scope.model().map(crate::ModelId::as_str),
        BudgetDimension::Route => scope.route().map(crate::RouteId::as_str),
        BudgetDimension::Tool => scope.tool().map(crate::ToolId::as_str),
        BudgetDimension::Operation => scope.operation().map(crate::OperationId::as_str),
        BudgetDimension::Job => scope.job().map(crate::JobId::as_str),
    }
}

const fn dimension_sql(dimension: BudgetDimension) -> &'static str {
    match dimension {
        BudgetDimension::Tenant => "tenant",
        BudgetDimension::Principal => "principal",
        BudgetDimension::ApiKey => "api_key",
        BudgetDimension::Provider => "provider",
        BudgetDimension::Model => "model",
        BudgetDimension::Route => "route",
        BudgetDimension::Tool => "tool",
        BudgetDimension::Operation => "operation",
        BudgetDimension::Job => "job",
    }
}

const fn state_sql(state: &ReservationState) -> &'static str {
    match state {
        ReservationState::Reserved => "reserved",
        ReservationState::Committed(_) => "committed",
        ReservationState::Reconciled(_) => "reconciled",
        ReservationState::Released => "released",
    }
}

const fn usage_status_sql(status: UsageStatus) -> &'static str {
    match status {
        UsageStatus::Estimated => "estimated",
        UsageStatus::Actual => "actual",
        UsageStatus::Missing => "missing",
        UsageStatus::Ambiguous => "ambiguous",
    }
}

const fn event_kind_sql(kind: LedgerEventKind) -> &'static str {
    match kind {
        LedgerEventKind::Reserved => "reserved",
        LedgerEventKind::Committed => "committed",
        LedgerEventKind::Reconciled => "reconciled",
        LedgerEventKind::Released => "released",
    }
}

const fn cost_basis(kind: LedgerEventKind) -> &'static str {
    match kind {
        LedgerEventKind::Reserved => "reservation",
        LedgerEventKind::Committed => "provider_commit",
        LedgerEventKind::Reconciled => "provider_reconcile",
        LedgerEventKind::Released => "release",
    }
}

#[derive(Clone, Copy, Debug, Error)]
enum StoreError {
    #[error("LLM usage database operation failed")]
    Database(Option<RetryableSqlState>),
    #[error("LLM usage database contains invalid state")]
    Corrupt,
    #[error("LLM usage database arithmetic overflow")]
    Arithmetic,
}

impl StoreError {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Result::map_err supplies the owned SQL error"
    )]
    fn database(error: sqlx::Error) -> Self {
        Self::Database(RetryableSqlState::from_sqlx(&error))
    }
}

impl RetryableTransactionError for StoreError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Database(state) => *state,
            Self::Corrupt | Self::Arithmetic => None,
        }
    }
}

const fn map_store_error(error: StoreError) -> RepositoryError {
    match error {
        StoreError::Database(_) => RepositoryError::Unavailable,
        StoreError::Corrupt => RepositoryError::CorruptState,
        StoreError::Arithmetic => RepositoryError::Arithmetic,
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err supplies the owned transaction error"
)]
fn map_run_error(error: TransactionRunError<StoreError>) -> RepositoryError {
    match error {
        TransactionRunError::Operation(error) => map_store_error(error),
        TransactionRunError::Acquire
        | TransactionRunError::Begin
        | TransactionRunError::Rollback
        | TransactionRunError::Commit
        | TransactionRunError::RetryExhausted { .. } => RepositoryError::Unavailable,
    }
}
