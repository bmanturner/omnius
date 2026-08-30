use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction, types::Json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    BindingDigest, ClaimResult, DeclineBehavior, ElicitationPlan, FieldPlan, FormElicitationPlan,
    FormProtection, InputRequestKey, InvocationBinding, InvocationContinuation, MAX_FORM_FIELDS,
    MAX_INPUT_REQUESTS, MAX_MRTR_ROUNDS, MrtrAuditEvent, MrtrAuditKind, MrtrMethod,
    PendingMrtrState, PlannedElicitation, ReplacementReason, Sensitivity, StateBinding, StateClaim,
    TerminalStatus, UrlElicitationPlan,
};
use crate::ports::{MrtrStateRepository, RepositoryError};

const MAX_PERSISTED_PLAN_BYTES: usize = 256 * 1024;
const MAX_CAPABILITY_KEY_BYTES: usize = 256;
const MAX_CAPABILITY_REVISION_BYTES: usize = 128;

/// PostgreSQL-backed authoritative replay ledger for multi-round elicitation.
#[derive(Clone)]
pub struct PostgresMrtrStateRepository {
    pool: PgPool,
}

impl PostgresMrtrStateRepository {
    /// Creates a replay ledger over the supplied PostgreSQL pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl fmt::Debug for PostgresMrtrStateRepository {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresMrtrStateRepository")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MrtrStateRepository for PostgresMrtrStateRepository {
    async fn create_pending(
        &self,
        state: &PendingMrtrState,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError> {
        validate_pending(state)?;
        validate_event(&event)?;
        validate_bound_event(
            &event,
            state.state_id,
            &state.binding,
            MrtrAuditKind::Issued,
            Some(state.round),
        )?;
        let plan = encode_plan(&state.plan)?;
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let authoritative = insert_pending(&mut transaction, state, plan).await?;
        insert_audit(&mut transaction, &event).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(authoritative)
    }

    async fn claim_pending(
        &self,
        claim: StateClaim,
        claimed_event: MrtrAuditEvent,
        rejected_event: MrtrAuditEvent,
    ) -> Result<ClaimResult, RepositoryError> {
        validate_binding(&claim.expected_binding)?;
        validate_event(&claimed_event)?;
        validate_event(&rejected_event)?;
        validate_bound_event(
            &claimed_event,
            claim.state_id,
            &claim.expected_binding,
            MrtrAuditKind::Claimed,
            None,
        )?;
        validate_bound_event(
            &rejected_event,
            claim.state_id,
            &claim.expected_binding,
            MrtrAuditKind::StateRejected,
            None,
        )?;
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let binding = &claim.expected_binding;
        let row = sqlx::query_as::<_, PendingRow>(
            "UPDATE public.mcp_mrtr_states \
             SET status = 'claimed', updated_at = GREATEST(updated_at, clock_timestamp()) \
             WHERE state_id = $1 AND status = 'pending' \
               AND principal_digest = $2 AND tenant_digest = $3 AND method = $4 \
               AND capability_key = $5 AND capability_revision = $6 \
               AND arguments_digest = $7 AND idempotency_digest = $8 \
               AND associated_digest = $9 \
               AND expires_at > GREATEST($10, clock_timestamp()) \
             RETURNING state_id, principal_digest, tenant_digest, method, capability_key, \
                       capability_revision, arguments_digest, idempotency_digest, \
                       associated_digest, plan_version, plan, continuation_id, round, max_rounds, \
                       issued_at, expires_at",
        )
        .bind(claim.state_id)
        .bind(binding.principal_digest.as_bytes().as_slice())
        .bind(binding.tenant_digest.as_bytes().as_slice())
        .bind(method_name(binding.method))
        .bind(&binding.capability_key)
        .bind(&binding.capability_revision)
        .bind(binding.arguments_digest.as_bytes().as_slice())
        .bind(binding.idempotency_digest.as_bytes().as_slice())
        .bind(binding.associated_digest.as_bytes().as_slice())
        .bind(claim.now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?;

        let (result, event) = match row {
            Some(row) => (
                ClaimResult::Claimed(Box::new(decode_pending(row)?)),
                &claimed_event,
            ),
            None => (ClaimResult::Rejected, &rejected_event),
        };
        insert_audit(&mut transaction, event).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(result)
    }

    async fn replace_claimed(
        &self,
        claimed_state_id: Uuid,
        fresh: &PendingMrtrState,
        reason: ReplacementReason,
        event: MrtrAuditEvent,
    ) -> Result<PendingMrtrState, RepositoryError> {
        validate_pending(fresh)?;
        validate_event(&event)?;
        if fresh.state_id == claimed_state_id {
            return Err(RepositoryError);
        }
        let expected_kind = match reason {
            ReplacementReason::InvalidResponse => MrtrAuditKind::ResponseRejected,
            ReplacementReason::MoreInput => MrtrAuditKind::Advanced,
        };
        validate_bound_event(
            &event,
            claimed_state_id,
            &fresh.binding,
            expected_kind,
            fresh.round.checked_sub(1),
        )?;
        let plan = encode_plan(&fresh.plan)?;
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let result = sqlx::query(
            "UPDATE public.mcp_mrtr_states \
             SET status = $2, updated_at = GREATEST(updated_at, clock_timestamp()) \
             WHERE state_id = $1 AND status = 'claimed' \
               AND principal_digest = $3 AND tenant_digest = $4 AND method = $5 \
               AND capability_key = $6 AND capability_revision = $7 \
               AND arguments_digest = $8 AND idempotency_digest = $9 \
               AND associated_digest = $10 \
               AND round + 1 = $11 AND max_rounds >= $12",
        )
        .bind(claimed_state_id)
        .bind(replacement_status(reason))
        .bind(fresh.binding.principal_digest.as_bytes().as_slice())
        .bind(fresh.binding.tenant_digest.as_bytes().as_slice())
        .bind(method_name(fresh.binding.method))
        .bind(&fresh.binding.capability_key)
        .bind(&fresh.binding.capability_revision)
        .bind(fresh.binding.arguments_digest.as_bytes().as_slice())
        .bind(fresh.binding.idempotency_digest.as_bytes().as_slice())
        .bind(fresh.binding.associated_digest.as_bytes().as_slice())
        .bind(i16::try_from(fresh.round).map_err(|_| RepositoryError)?)
        .bind(i16::try_from(fresh.max_rounds).map_err(|_| RepositoryError)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        require_one_row(result.rows_affected())?;
        let authoritative = insert_pending(&mut transaction, fresh, plan).await?;
        insert_audit(&mut transaction, &event).await?;
        transaction.commit().await.map_err(map_sqlx)?;
        Ok(authoritative)
    }

    async fn finish_claimed(
        &self,
        claimed_state_id: Uuid,
        status: TerminalStatus,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        validate_event(&event)?;
        let expected_kind = match status {
            TerminalStatus::Completed => MrtrAuditKind::Completed,
            TerminalStatus::Declined => MrtrAuditKind::Declined,
            TerminalStatus::Cancelled => MrtrAuditKind::Cancelled,
            TerminalStatus::Exhausted => MrtrAuditKind::Exhausted,
            TerminalStatus::InvocationFailed => MrtrAuditKind::InvocationFailed,
            TerminalStatus::Rejected => MrtrAuditKind::StateRejected,
        };
        validate_event_target(&event, claimed_state_id, expected_kind)?;
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let result = sqlx::query(
            "UPDATE public.mcp_mrtr_states \
             SET status = $2, updated_at = GREATEST(updated_at, clock_timestamp()) \
             WHERE state_id = $1 AND status = 'claimed' \
               AND method = $3 AND capability_key = $4 AND capability_revision = $5 \
               AND arguments_digest = $6 AND round = $7",
        )
        .bind(claimed_state_id)
        .bind(terminal_status(status))
        .bind(method_name(event.method.ok_or(RepositoryError)?))
        .bind(event.capability_key.as_deref().ok_or(RepositoryError)?)
        .bind(
            event
                .capability_revision
                .as_deref()
                .ok_or(RepositoryError)?,
        )
        .bind(
            event
                .arguments_digest
                .ok_or(RepositoryError)?
                .as_bytes()
                .as_slice(),
        )
        .bind(i16::try_from(event.round.ok_or(RepositoryError)?).map_err(|_| RepositoryError)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_sqlx)?;
        require_one_row(result.rows_affected())?;
        insert_audit(&mut transaction, &event).await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    async fn record_claimed(
        &self,
        claimed_state_id: Uuid,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        validate_event(&event)?;
        if !matches!(
            event.kind,
            MrtrAuditKind::Accepted | MrtrAuditKind::PartiallyAccepted | MrtrAuditKind::Declined
        ) {
            return Err(RepositoryError);
        }
        validate_event_target(&event, claimed_state_id, event.kind)?;
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        let exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT state_id FROM public.mcp_mrtr_states \
             WHERE state_id = $1 AND status = 'claimed' \
               AND method = $2 AND capability_key = $3 AND capability_revision = $4 \
               AND arguments_digest = $5 AND round = $6 \
             FOR UPDATE",
        )
        .bind(claimed_state_id)
        .bind(method_name(event.method.ok_or(RepositoryError)?))
        .bind(event.capability_key.as_deref().ok_or(RepositoryError)?)
        .bind(
            event
                .capability_revision
                .as_deref()
                .ok_or(RepositoryError)?,
        )
        .bind(
            event
                .arguments_digest
                .ok_or(RepositoryError)?
                .as_bytes()
                .as_slice(),
        )
        .bind(i16::try_from(event.round.ok_or(RepositoryError)?).map_err(|_| RepositoryError)?)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_sqlx)?
        .is_some();
        if !exists {
            return Err(RepositoryError);
        }
        insert_audit(&mut transaction, &event).await?;
        transaction.commit().await.map_err(map_sqlx)
    }

    async fn record_untrusted_rejection(
        &self,
        event: MrtrAuditEvent,
    ) -> Result<(), RepositoryError> {
        validate_event(&event)?;
        if event.state_id.is_some() || event.kind != MrtrAuditKind::StateRejected {
            return Err(RepositoryError);
        }
        let mut transaction = self.pool.begin().await.map_err(map_sqlx)?;
        insert_audit(&mut transaction, &event).await?;
        transaction.commit().await.map_err(map_sqlx)
    }
}

async fn insert_pending(
    transaction: &mut Transaction<'_, Postgres>,
    state: &PendingMrtrState,
    plan: Json<Value>,
) -> Result<PendingMrtrState, RepositoryError> {
    let ttl_micros = i64::try_from((state.expires_at - state.issued_at).whole_microseconds())
        .map_err(|_| RepositoryError)?;
    if ttl_micros <= 0 {
        return Err(RepositoryError);
    }
    let row = sqlx::query_as::<_, PendingRow>(
        "WITH authoritative AS (SELECT transaction_timestamp() AS issued_at) \
         INSERT INTO public.mcp_mrtr_states (\
            state_id, status, principal_digest, tenant_digest, method, capability_key, \
            capability_revision, arguments_digest, idempotency_digest, associated_digest, \
            plan_version, plan, continuation_id, round, max_rounds, issued_at, expires_at, \
            updated_at\
         ) SELECT \
            $1, 'pending', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
            authoritative.issued_at, \
            authoritative.issued_at + ($15::bigint * INTERVAL '1 microsecond'), \
            authoritative.issued_at \
         FROM authoritative \
         RETURNING state_id, principal_digest, tenant_digest, method, capability_key, \
                   capability_revision, arguments_digest, idempotency_digest, \
                   associated_digest, plan_version, plan, continuation_id, round, max_rounds, \
                   issued_at, expires_at",
    )
    .bind(state.state_id)
    .bind(state.binding.principal_digest.as_bytes().as_slice())
    .bind(state.binding.tenant_digest.as_bytes().as_slice())
    .bind(method_name(state.binding.method))
    .bind(&state.binding.capability_key)
    .bind(&state.binding.capability_revision)
    .bind(state.binding.arguments_digest.as_bytes().as_slice())
    .bind(state.binding.idempotency_digest.as_bytes().as_slice())
    .bind(state.binding.associated_digest.as_bytes().as_slice())
    .bind(i16::try_from(state.plan.version()).map_err(|_| RepositoryError)?)
    .bind(plan)
    .bind(state.continuation.map(InvocationContinuation::id))
    .bind(i16::try_from(state.round).map_err(|_| RepositoryError)?)
    .bind(i16::try_from(state.max_rounds).map_err(|_| RepositoryError)?)
    .bind(ttl_micros)
    .fetch_one(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    decode_pending(row)
}

async fn insert_audit(
    transaction: &mut Transaction<'_, Postgres>,
    event: &MrtrAuditEvent,
) -> Result<(), RepositoryError> {
    let round = event
        .round
        .map(i16::try_from)
        .transpose()
        .map_err(|_| RepositoryError)?;
    let arguments_digest = event
        .arguments_digest
        .map(|digest| digest.as_bytes().to_vec());
    sqlx::query(
        "INSERT INTO public.mcp_mrtr_audit_events (\
            state_id, kind, method, capability_key, capability_revision, arguments_digest, \
            round, sensitivity\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(event.state_id)
    .bind(audit_kind(event.kind))
    .bind(event.method.map(method_name))
    .bind(event.capability_key.as_deref())
    .bind(event.capability_revision.as_deref())
    .bind(arguments_digest)
    .bind(round)
    .bind(event.sensitivity.map(sensitivity_name))
    .execute(&mut **transaction)
    .await
    .map_err(map_sqlx)?;
    Ok(())
}

#[derive(FromRow)]
struct PendingRow {
    state_id: Uuid,
    principal_digest: Vec<u8>,
    tenant_digest: Vec<u8>,
    method: String,
    capability_key: String,
    capability_revision: String,
    arguments_digest: Vec<u8>,
    idempotency_digest: Vec<u8>,
    associated_digest: Vec<u8>,
    plan_version: i16,
    plan: Json<Value>,
    continuation_id: Option<Uuid>,
    round: i16,
    max_rounds: i16,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

fn decode_pending(row: PendingRow) -> Result<PendingMrtrState, RepositoryError> {
    let method = parse_method(&row.method)?;
    let binding = StateBinding {
        principal_digest: decode_digest(row.principal_digest)?,
        tenant_digest: decode_digest(row.tenant_digest)?,
        method,
        capability_key: row.capability_key,
        capability_revision: row.capability_revision,
        arguments_digest: decode_digest(row.arguments_digest)?,
        idempotency_digest: decode_digest(row.idempotency_digest)?,
        associated_digest: decode_digest(row.associated_digest)?,
    };
    validate_binding(&binding)?;
    let round = u16::try_from(row.round).map_err(|_| RepositoryError)?;
    let max_rounds = u16::try_from(row.max_rounds).map_err(|_| RepositoryError)?;
    let plan_version = u16::try_from(row.plan_version).map_err(|_| RepositoryError)?;
    let plan = decode_plan(row.plan.0, plan_version)?;
    let state = PendingMrtrState {
        state_id: row.state_id,
        binding,
        plan,
        continuation: row.continuation_id.map(InvocationContinuation::new),
        round,
        max_rounds,
        issued_at: row.issued_at,
        expires_at: row.expires_at,
    };
    validate_pending(&state)?;
    Ok(state)
}

fn decode_digest(value: Vec<u8>) -> Result<BindingDigest, RepositoryError> {
    let bytes: [u8; 32] = value.try_into().map_err(|_| RepositoryError)?;
    Ok(BindingDigest::from_bytes(bytes))
}

fn validate_pending(state: &PendingMrtrState) -> Result<(), RepositoryError> {
    validate_binding(&state.binding)?;
    if state.round == 0
        || state.max_rounds == 0
        || state.round > state.max_rounds
        || state.max_rounds > MAX_MRTR_ROUNDS
        || state.max_rounds > state.plan.max_rounds()
        || state.plan.version() != ElicitationPlan::VERSION
        || state.expires_at <= state.issued_at
        || state.expires_at - state.issued_at > time::Duration::minutes(15)
    {
        return Err(RepositoryError);
    }
    Ok(())
}

fn validate_binding(binding: &StateBinding) -> Result<(), RepositoryError> {
    let invocation = InvocationBinding::new(
        binding.method,
        &binding.capability_key,
        &binding.capability_revision,
    );
    if !invocation.validate() {
        return Err(RepositoryError);
    }
    Ok(())
}

fn validate_event(event: &MrtrAuditEvent) -> Result<(), RepositoryError> {
    if event
        .capability_key
        .as_ref()
        .is_some_and(|value| value.is_empty() || value.len() > MAX_CAPABILITY_KEY_BYTES)
        || event
            .capability_revision
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_CAPABILITY_REVISION_BYTES)
        || event
            .round
            .is_some_and(|round| round == 0 || round > MAX_MRTR_ROUNDS)
    {
        return Err(RepositoryError);
    }
    Ok(())
}
fn validate_event_target(
    event: &MrtrAuditEvent,
    state_id: Uuid,
    kind: MrtrAuditKind,
) -> Result<(), RepositoryError> {
    if event.state_id != Some(state_id) || event.kind != kind {
        return Err(RepositoryError);
    }
    Ok(())
}

fn validate_bound_event(
    event: &MrtrAuditEvent,
    state_id: Uuid,
    binding: &StateBinding,
    kind: MrtrAuditKind,
    round: Option<u16>,
) -> Result<(), RepositoryError> {
    validate_event_target(event, state_id, kind)?;
    if event.method != Some(binding.method)
        || event.capability_key.as_deref() != Some(binding.capability_key.as_str())
        || event.capability_revision.as_deref() != Some(binding.capability_revision.as_str())
        || event.arguments_digest != Some(binding.arguments_digest)
        || event.round != round
    {
        return Err(RepositoryError);
    }
    Ok(())
}

fn require_one_row(rows: u64) -> Result<(), RepositoryError> {
    if rows == 1 {
        Ok(())
    } else {
        Err(RepositoryError)
    }
}

fn map_sqlx(_: sqlx::Error) -> RepositoryError {
    RepositoryError
}

fn method_name(method: MrtrMethod) -> &'static str {
    method.as_str()
}

fn parse_method(value: &str) -> Result<MrtrMethod, RepositoryError> {
    match value {
        "tools/call" => Ok(MrtrMethod::ToolCall),
        "prompts/get" => Ok(MrtrMethod::PromptGet),
        "resources/read" => Ok(MrtrMethod::ResourceRead),
        _ => Err(RepositoryError),
    }
}

fn replacement_status(reason: ReplacementReason) -> &'static str {
    match reason {
        ReplacementReason::InvalidResponse => "replaced_invalid_response",
        ReplacementReason::MoreInput => "replaced_more_input",
    }
}

fn terminal_status(status: TerminalStatus) -> &'static str {
    match status {
        TerminalStatus::Completed => "completed",
        TerminalStatus::Declined => "declined",
        TerminalStatus::Cancelled => "cancelled",
        TerminalStatus::Exhausted => "exhausted",
        TerminalStatus::InvocationFailed => "invocation_failed",
        TerminalStatus::Rejected => "rejected",
    }
}

fn audit_kind(kind: MrtrAuditKind) -> &'static str {
    match kind {
        MrtrAuditKind::Issued => "issued",
        MrtrAuditKind::Claimed => "claimed",
        MrtrAuditKind::StateRejected => "state_rejected",
        MrtrAuditKind::ResponseRejected => "response_rejected",
        MrtrAuditKind::Accepted => "accepted",
        MrtrAuditKind::PartiallyAccepted => "partially_accepted",
        MrtrAuditKind::Declined => "declined",
        MrtrAuditKind::Cancelled => "cancelled",
        MrtrAuditKind::Advanced => "advanced",
        MrtrAuditKind::Completed => "completed",
        MrtrAuditKind::InvocationFailed => "invocation_failed",
        MrtrAuditKind::Exhausted => "exhausted",
    }
}

fn sensitivity_name(sensitivity: Sensitivity) -> &'static str {
    match sensitivity {
        Sensitivity::Public => "public",
        Sensitivity::Personal => "personal",
        Sensitivity::Confidential => "confidential",
        Sensitivity::Credential => "credential",
        Sensitivity::Password => "password",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanDto {
    version: u16,
    max_rounds: u16,
    decline_behavior: DeclineDto,
    requests: Vec<RequestDto>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestDto {
    key: String,
    elicitation: ElicitationDto,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum ElicitationDto {
    Form {
        message: String,
        schema: Value,
        fields: Vec<FieldDto>,
        protection: ProtectionDto,
    },
    Url {
        message: String,
        url: String,
        elicitation_id: String,
        sensitivity: SensitivityDto,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldDto {
    name: String,
    argument_pointer: String,
    sensitivity: SensitivityDto,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SensitivityDto {
    Public,
    Personal,
    Confidential,
    Credential,
    Password,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProtectionDto {
    Ordinary,
    StrongConfirmation,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeclineDto {
    CompleteDeclined,
    InvokeWithoutInput,
}

impl PlanDto {
    fn from_plan(plan: &ElicitationPlan) -> Self {
        let requests = plan
            .requests()
            .iter()
            .map(|(key, request)| RequestDto {
                key: key.as_str().to_owned(),
                elicitation: ElicitationDto::from_plan(request),
            })
            .collect();
        Self {
            version: plan.version(),
            max_rounds: plan.max_rounds(),
            decline_behavior: DeclineDto::from_model(plan.decline_behavior()),
            requests,
        }
    }

    fn into_plan(self) -> Result<ElicitationPlan, RepositoryError> {
        if self.version != ElicitationPlan::VERSION
            || self.requests.is_empty()
            || self.requests.len() > MAX_INPUT_REQUESTS
            || self.max_rounds == 0
            || self.max_rounds > MAX_MRTR_ROUNDS
        {
            return Err(RepositoryError);
        }
        let requests = self
            .requests
            .into_iter()
            .map(RequestDto::into_plan)
            .collect::<Result<Vec<_>, _>>()?;
        ElicitationPlan::try_new(
            requests,
            self.max_rounds,
            self.decline_behavior.into_model(),
        )
        .map_err(|_| RepositoryError)
    }
}

impl RequestDto {
    fn into_plan(self) -> Result<(InputRequestKey, PlannedElicitation), RepositoryError> {
        Ok((
            InputRequestKey::try_new(self.key).map_err(|_| RepositoryError)?,
            self.elicitation.into_plan()?,
        ))
    }
}

impl ElicitationDto {
    fn from_plan(plan: &PlannedElicitation) -> Self {
        match plan {
            PlannedElicitation::Form(form) => Self::Form {
                message: form.message().to_owned(),
                schema: form.schema().clone(),
                fields: form
                    .fields()
                    .values()
                    .map(|field| FieldDto {
                        name: field.name().to_owned(),
                        argument_pointer: field.argument_pointer().to_owned(),
                        sensitivity: SensitivityDto::from_model(field.sensitivity()),
                    })
                    .collect(),
                protection: ProtectionDto::from_model(form.protection()),
            },
            PlannedElicitation::Url(url) => Self::Url {
                message: url.message().to_owned(),
                url: url.url().as_str().to_owned(),
                elicitation_id: url.elicitation_id().to_owned(),
                sensitivity: SensitivityDto::from_model(url.sensitivity()),
            },
        }
    }

    fn into_plan(self) -> Result<PlannedElicitation, RepositoryError> {
        match self {
            Self::Form {
                message,
                schema,
                fields,
                protection,
            } => {
                if fields.is_empty() || fields.len() > MAX_FORM_FIELDS {
                    return Err(RepositoryError);
                }
                let fields = fields
                    .into_iter()
                    .map(FieldDto::into_model)
                    .collect::<Result<Vec<_>, _>>()?;
                FormElicitationPlan::try_new(message, schema, fields, protection.into_model())
                    .map(PlannedElicitation::Form)
                    .map_err(|_| RepositoryError)
            }
            Self::Url {
                message,
                url,
                elicitation_id,
                sensitivity,
            } => {
                UrlElicitationPlan::try_new(message, url, elicitation_id, sensitivity.into_model())
                    .map(PlannedElicitation::Url)
                    .map_err(|_| RepositoryError)
            }
        }
    }
}

impl FieldDto {
    fn into_model(self) -> Result<FieldPlan, RepositoryError> {
        FieldPlan::try_new(
            self.name,
            self.argument_pointer,
            self.sensitivity.into_model(),
        )
        .map_err(|_| RepositoryError)
    }
}

impl SensitivityDto {
    fn from_model(value: Sensitivity) -> Self {
        match value {
            Sensitivity::Public => Self::Public,
            Sensitivity::Personal => Self::Personal,
            Sensitivity::Confidential => Self::Confidential,
            Sensitivity::Credential => Self::Credential,
            Sensitivity::Password => Self::Password,
        }
    }

    fn into_model(self) -> Sensitivity {
        match self {
            Self::Public => Sensitivity::Public,
            Self::Personal => Sensitivity::Personal,
            Self::Confidential => Sensitivity::Confidential,
            Self::Credential => Sensitivity::Credential,
            Self::Password => Sensitivity::Password,
        }
    }
}

impl ProtectionDto {
    fn from_model(value: FormProtection) -> Self {
        match value {
            FormProtection::Ordinary => Self::Ordinary,
            FormProtection::StrongConfirmation => Self::StrongConfirmation,
        }
    }

    fn into_model(self) -> FormProtection {
        match self {
            Self::Ordinary => FormProtection::Ordinary,
            Self::StrongConfirmation => FormProtection::StrongConfirmation,
        }
    }
}

impl DeclineDto {
    fn from_model(value: DeclineBehavior) -> Self {
        match value {
            DeclineBehavior::CompleteDeclined => Self::CompleteDeclined,
            DeclineBehavior::InvokeWithoutInput => Self::InvokeWithoutInput,
        }
    }

    fn into_model(self) -> DeclineBehavior {
        match self {
            Self::CompleteDeclined => DeclineBehavior::CompleteDeclined,
            Self::InvokeWithoutInput => DeclineBehavior::InvokeWithoutInput,
        }
    }
}

fn encode_plan(plan: &ElicitationPlan) -> Result<Json<Value>, RepositoryError> {
    if plan.version() != ElicitationPlan::VERSION {
        return Err(RepositoryError);
    }
    let dto = PlanDto::from_plan(plan);
    let bytes = serde_json::to_vec(&dto).map_err(|_| RepositoryError)?;
    if bytes.len() > MAX_PERSISTED_PLAN_BYTES {
        return Err(RepositoryError);
    }
    let value = serde_json::to_value(dto).map_err(|_| RepositoryError)?;
    Ok(Json(value))
}

fn decode_plan(value: Value, stored_version: u16) -> Result<ElicitationPlan, RepositoryError> {
    let bytes = serde_json::to_vec(&value).map_err(|_| RepositoryError)?;
    if bytes.len() > MAX_PERSISTED_PLAN_BYTES {
        return Err(RepositoryError);
    }
    let dto: PlanDto = serde_json::from_value(value).map_err(|_| RepositoryError)?;
    if dto.version != stored_version || stored_version != ElicitationPlan::VERSION {
        return Err(RepositoryError);
    }
    dto.into_plan()
}
