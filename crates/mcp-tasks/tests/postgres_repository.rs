//! Opt-in isolated PostgreSQL contract for durable MCP Tasks state, CAS, inbox, and outbox.

use std::{
    collections::BTreeMap,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityId, CapabilityKey, CapabilityVersion, ConfirmationEvidence,
    IdempotencyKey, TenantMode,
};
use omnius_auth_core::{SubjectId, TenantId};
use omnius_config::DeploymentEnvironment;
use omnius_core::{CorrelationId, RequestId};
use omnius_jobs_core::{
    Destination, EventEnvelope, EventEnvelopeOptions, EventLimits, IdempotencyKey as JobKey,
    JobEnvelope, JobEnvelopeOptions, Source, Subject, TenantId as JobTenantId,
};
use omnius_mcp_tasks::{
    AbandonExecution, AbandonOutcome, AtomicCancellation, AtomicCreate, AtomicInputUpdate,
    BudgetReservationRef, CancellationOutcome, ClaimOutcome, CreateOutcome, ExecutionClaim,
    InputExchange, InputKey, InputResponses, InputRound, InputUpdateOutcome,
    PostgresTaskRepository, ProtectedTaskPayload, RequestFingerprint, RequireInput,
    SettleExecution, SettlementOutcome, StoredTask, TaskBudget, TaskCancellationJob,
    TaskCancellationRequested, TaskConfig, TaskExecution, TaskExecutionJob, TaskExecutionRequested,
    TaskGeneration, TaskId, TaskIdempotency, TaskIdentity, TaskOutboxIntent, TaskOwner,
    TaskPayloadProtectionError, TaskPayloadProtector, TaskRepository, TaskRequestState,
    TaskSnapshot, TaskState, TaskVersion, TerminalSettlement,
};
use omnius_outbox::{OutboxConfig, PostgresOutbox};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_test_support::PostgresFixture;
use serde_json::{Value, json};
use time::OffsetDateTime;
use zeroize::Zeroizing;

const RUN_POSTGRES_CONTRACT: &str = "OMNIUS_RUN_MCP_TASKS_POSTGRES_CONTRACT";
const TEST_KEY_ID: &str = "mcp-tasks-contract-key";
const TEST_ALGORITHM: &str = "aes-256-gcm";
const TEST_KEY: [u8; 32] = [0x5A; 32];

#[derive(Default)]
struct TestPayloadProtector {
    nonce_sequence: AtomicU64,
}

impl TestPayloadProtector {
    fn key() -> Result<LessSafeKey, TaskPayloadProtectionError> {
        let key = UnboundKey::new(&AES_256_GCM, &TEST_KEY)
            .map_err(|_| TaskPayloadProtectionError::Unavailable)?;
        Ok(LessSafeKey::new(key))
    }
}

#[async_trait]
impl TaskPayloadProtector for TestPayloadProtector {
    async fn seal(
        &self,
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<ProtectedTaskPayload, TaskPayloadProtectionError> {
        let sequence = self.nonce_sequence.fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0_u8; 12];
        nonce[..4].copy_from_slice(b"test");
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        let mut ciphertext = plaintext.to_vec();
        Self::key()?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut ciphertext,
            )
            .map_err(|_| TaskPayloadProtectionError::Unavailable)?;
        ProtectedTaskPayload::new(
            TEST_KEY_ID.to_owned(),
            1,
            TEST_ALGORITHM.to_owned(),
            nonce,
            ciphertext,
        )
    }

    async fn open(
        &self,
        aad: &[u8],
        payload: &ProtectedTaskPayload,
    ) -> Result<Zeroizing<Vec<u8>>, TaskPayloadProtectionError> {
        if payload.key_id() != TEST_KEY_ID
            || payload.key_revision().get() != 1
            || payload.algorithm() != TEST_ALGORITHM
        {
            return Err(TaskPayloadProtectionError::InvalidPayload);
        }
        let mut plaintext = Zeroizing::new(payload.ciphertext().to_vec());
        let plaintext_len = Self::key()?
            .open_in_place(
                Nonce::assume_unique_for_key(*payload.nonce()),
                Aad::from(aad),
                &mut plaintext,
            )
            .map_err(|_| TaskPayloadProtectionError::InvalidPayload)?
            .len();
        plaintext.truncate(plaintext_len);
        Ok(plaintext)
    }
}

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

fn postgres_config(url: omnius_config::SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 8,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "omnius-mcp-tasks-contract".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(2),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    sqlx::migrate!("../../migrations")
        .run(&pool.sqlx_pool())
        .await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

fn repository(
    pool: &PostgresPool,
    protector: Arc<dyn TaskPayloadProtector>,
) -> Result<PostgresTaskRepository, Box<dyn Error>> {
    let outbox = PostgresOutbox::new(pool.clone(), OutboxConfig::default())?;
    Ok(PostgresTaskRepository::new(
        pool.sqlx_pool(),
        outbox,
        protector,
    ))
}

fn capability() -> Result<CapabilityKey, Box<dyn Error>> {
    Ok(CapabilityKey::new(
        CapabilityId::new("documents.summarize".to_owned())?,
        CapabilityVersion::new("1.2.3".to_owned())?,
    ))
}

fn budget() -> Result<TaskBudget, Box<dyn Error>> {
    Ok(TaskBudget::new(
        BudgetBounds::new(16_384, 16_384, 10_000)?,
        BudgetReservationRef::new("budget-contract-1".to_owned())?,
    ))
}

fn event_options(
    task_id: TaskId,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<EventEnvelopeOptions, Box<dyn Error>> {
    let mut options = EventEnvelopeOptions::new(
        Source::try_from("omnius.mcp.tasks".to_owned())?,
        Subject::try_from(format!("task/{task_id}"))?,
        identity.correlation_id().as_uuid(),
    )?;
    if let Some(tenant_id) = owner.tenant_id() {
        options = options.with_tenant(JobTenantId::try_from(tenant_id.to_string())?);
    }
    Ok(options)
}

fn job_options(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<JobEnvelopeOptions, Box<dyn Error>> {
    let mut options = JobEnvelopeOptions::new(identity.correlation_id().as_uuid())?;
    if let Some(tenant_id) = owner.tenant_id() {
        options = options.with_tenant(JobTenantId::try_from(tenant_id.to_string())?);
    }
    Ok(options.with_idempotency_key(JobKey::try_from(format!(
        "mcp-task:{task_id}:generation:{}",
        generation.get()
    ))?))
}

fn execution_intent(
    task_id: TaskId,
    generation: TaskGeneration,
    owner: TaskOwner,
    identity: &TaskIdentity,
) -> Result<TaskOutboxIntent<TaskExecutionRequested>, Box<dyn Error>> {
    let job = JobEnvelope::new(
        TaskExecutionJob::new(task_id, generation),
        job_options(task_id, generation, owner, identity)?,
    )?;
    let event = EventEnvelope::new(
        TaskExecutionRequested::new(job),
        event_options(task_id, owner, identity)?,
        EventLimits::default(),
    )?;
    Ok(TaskOutboxIntent::new(
        event,
        Destination::try_from("mcp.tasks.execute".to_owned())?,
    ))
}

fn cancellation_intent(
    snapshot: &TaskSnapshot,
) -> Result<TaskOutboxIntent<TaskCancellationRequested>, Box<dyn Error>> {
    let task_id = snapshot.task_id();
    let generation = snapshot.generation();
    let owner = snapshot.owner();
    let identity = snapshot.identity();
    let job = JobEnvelope::new(
        TaskCancellationJob::new(task_id, generation),
        job_options(task_id, generation, owner, identity)?,
    )?;
    let event = EventEnvelope::new(
        TaskCancellationRequested::new(job),
        event_options(task_id, owner, identity)?,
        EventLimits::default(),
    )?;
    Ok(TaskOutboxIntent::new(
        event,
        Destination::try_from("mcp.tasks.cancel".to_owned())?,
    ))
}

fn create_request(
    owner: TaskOwner,
    key: &str,
    input: Value,
    now: OffsetDateTime,
) -> Result<AtomicCreate, Box<dyn Error>> {
    let capability = capability()?;
    let idempotency_key = IdempotencyKey::new(key.to_owned())?;
    let fingerprint = RequestFingerprint::for_invocation(&capability, &input)?;
    let execution = TaskExecution::new(
        capability.clone(),
        TenantMode::Tenant,
        ConfirmationEvidence::NotRequiredByPolicy,
        input,
        idempotency_key.clone(),
        budget()?,
    )?;
    let identity_request = RequestId::new();
    let identity = TaskIdentity::new(
        identity_request,
        CorrelationId::from_uuid(identity_request.as_uuid()),
        None,
    );
    let task_id = TaskId::new();
    let intent = execution_intent(task_id, TaskGeneration::INITIAL, owner, &identity)?;
    let snapshot = TaskSnapshot::initial(
        task_id,
        owner,
        capability,
        identity,
        TaskIdempotency::new(idempotency_key, fingerprint),
        execution.budget().clone(),
        intent.event().data().job().id(),
        now,
        TaskConfig::new(Duration::from_secs(600), Duration::from_millis(250), 64)?,
    );
    Ok(AtomicCreate::new(
        StoredTask::new(snapshot, execution),
        intent,
    ))
}

fn input_round() -> Result<InputRound, Box<dyn Error>> {
    let exchanges = BTreeMap::from([(
        InputKey::new("approval".to_owned())?,
        InputExchange::pending(json!({
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": "approve durable execution",
                "requestedSchema": {
                    "type": "object",
                    "properties": {"approved": {"type": "boolean"}},
                    "required": ["approved"]
                }
            }
        }))?,
    )]);
    Ok(InputRound::new(
        1,
        TaskRequestState::new("postgres-contract-round-1".to_owned())?,
        exchanges,
    )?)
}

async fn create_one(
    repository: &PostgresTaskRepository,
    owner: TaskOwner,
    key: &str,
    input: Value,
    now: OffsetDateTime,
) -> Result<TaskSnapshot, Box<dyn Error>> {
    match repository
        .create_atomic(create_request(owner, key, input, now)?)
        .await?
    {
        CreateOutcome::Created(snapshot) => Ok(snapshot),
        CreateOutcome::Existing(_) | CreateOutcome::FingerprintConflict => {
            Err("expected a fresh task".into())
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one opt-in isolated database lifecycle proves the complete repository transaction contract"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_repository_preserves_restart_dedup_tenant_cas_and_delivery_atomicity()
-> Result<(), Box<dyn Error>> {
    if !matches!(std::env::var(RUN_POSTGRES_CONTRACT).as_deref(), Ok("1")) {
        return Ok(());
    }

    let database = test_database().await?;
    let protector: Arc<dyn TaskPayloadProtector> = Arc::new(TestPayloadProtector::default());
    let initial_repository = repository(&database.pool, Arc::clone(&protector))?;
    let subject_id = SubjectId::new();
    let owner = TaskOwner::new(subject_id, Some(TenantId::new()));
    let base = OffsetDateTime::now_utc();
    let protected_marker = "secret-test-argument-never-outboxed";
    let original = create_one(
        &initial_repository,
        owner,
        "secret-contract-create-key-never-stored",
        json!({"document": protected_marker}),
        base,
    )
    .await?;
    drop(initial_repository);
    let restarted = repository(&database.pool, Arc::clone(&protector))?;
    let visible = restarted
        .get(owner, original.task_id())
        .await?
        .ok_or("created task was not restart-visible")?;
    assert_eq!(visible.task_id(), original.task_id());

    let duplicate = restarted
        .create_atomic(create_request(
            owner,
            "secret-contract-create-key-never-stored",
            json!({"document": protected_marker}),
            base + time::Duration::milliseconds(1),
        )?)
        .await?;
    match duplicate {
        CreateOutcome::Existing(snapshot) => assert_eq!(snapshot.task_id(), original.task_id()),
        CreateOutcome::Created(_) | CreateOutcome::FingerprintConflict => {
            return Err("exact idempotency replay was not classified as existing".into());
        }
    }
    let conflict = restarted
        .create_atomic(create_request(
            owner,
            "secret-contract-create-key-never-stored",
            json!({"document": "different"}),
            base + time::Duration::milliseconds(2),
        )?)
        .await?;
    assert!(matches!(conflict, CreateOutcome::FingerprintConflict));

    let other_tenant = TaskOwner::new(subject_id, Some(TenantId::new()));
    assert!(
        restarted
            .get(other_tenant, original.task_id())
            .await?
            .is_none()
    );

    let input_task = create_one(
        &restarted,
        owner,
        "contract-input-key",
        json!({"document": "input-cas"}),
        base + time::Duration::seconds(1),
    )
    .await?;
    let input_lease = match restarted
        .claim_execution(ExecutionClaim::new(
            input_task.task_id(),
            input_task.generation(),
            input_task.current_job_id(),
            base + time::Duration::seconds(2),
        ))
        .await?
    {
        ClaimOutcome::Leased(lease) => lease,
        ClaimOutcome::Inactive | ClaimOutcome::Stale | ClaimOutcome::NotFound => {
            return Err("current input task was not leased".into());
        }
    };
    let stale_version = TaskVersion::new(input_lease.version().get() + 1)?;
    let stale = restarted
        .require_input(RequireInput::new(
            input_task.task_id(),
            input_task.generation(),
            stale_version,
            input_lease.claimed_at(),
            input_task.current_job_id(),
            input_round()?,
            base + time::Duration::seconds(3),
        ))
        .await?;
    assert!(matches!(stale, SettlementOutcome::Stale));
    let paused = restarted
        .require_input(RequireInput::new(
            input_task.task_id(),
            input_task.generation(),
            input_lease.version(),
            input_lease.claimed_at(),
            input_task.current_job_id(),
            input_round()?,
            base + time::Duration::seconds(4),
        ))
        .await?;
    let SettlementOutcome::Applied(paused) = paused else {
        return Err("legal input-required CAS did not apply".into());
    };
    assert!(matches!(paused.state(), TaskState::InputRequired { .. }));
    let next_generation = paused
        .generation()
        .next()
        .ok_or("task generation exhausted")?;
    let input_response_marker = "secret-input-response-never-stored";
    let responses = InputResponses::new(BTreeMap::from([(
        "approval".to_owned(),
        json!({
            "action": "accept",
            "content": {
                "approved": true,
                "marker": input_response_marker
            }
        }),
    )]))?;
    let resumed = restarted
        .update_input_atomic(AtomicInputUpdate::new(
            owner,
            paused.task_id(),
            paused.version(),
            paused.generation(),
            1,
            responses,
            execution_intent(paused.task_id(), next_generation, owner, paused.identity())?,
            base + time::Duration::seconds(5),
        ))
        .await?;
    let InputUpdateOutcome::Resumed(resumed) = resumed else {
        return Err("complete input update did not resume the task".into());
    };
    assert_eq!(resumed.generation(), next_generation);

    let cancel_task = create_one(
        &restarted,
        owner,
        "contract-cancel-key",
        json!({"document": "cancel-race"}),
        base + time::Duration::seconds(5),
    )
    .await?;
    let cancel_lease = match restarted
        .claim_execution(ExecutionClaim::new(
            cancel_task.task_id(),
            cancel_task.generation(),
            cancel_task.current_job_id(),
            base + time::Duration::seconds(6),
        ))
        .await?
    {
        ClaimOutcome::Leased(lease) => lease,
        ClaimOutcome::Inactive | ClaimOutcome::Stale | ClaimOutcome::NotFound => {
            return Err("current cancellation task was not leased".into());
        }
    };
    let cancellation = restarted
        .cancel_atomic(AtomicCancellation::new(
            owner,
            cancel_task.task_id(),
            cancel_task.version(),
            cancel_task.generation(),
            cancellation_intent(&cancel_task)?,
            base + time::Duration::seconds(7),
        ))
        .await?;
    assert!(matches!(cancellation, CancellationOutcome::Signalled(_)));
    let settled = restarted
        .settle_execution(SettleExecution::new(
            cancel_task.task_id(),
            cancel_task.generation(),
            cancel_lease.version(),
            cancel_lease.claimed_at(),
            cancel_task.current_job_id(),
            TerminalSettlement::Cancelled,
            base + time::Duration::seconds(8),
        ))
        .await?;
    let SettlementOutcome::Applied(cancelled) = settled else {
        return Err("same-generation cancellation successor did not settle".into());
    };
    assert!(matches!(cancelled.state(), TaskState::Cancelled));

    let retry_task = create_one(
        &restarted,
        owner,
        "contract-retry-key",
        json!({"document": "retry-fence"}),
        base + time::Duration::seconds(9),
    )
    .await?;
    let first_retry_lease = match restarted
        .claim_execution(ExecutionClaim::new(
            retry_task.task_id(),
            retry_task.generation(),
            retry_task.current_job_id(),
            base + time::Duration::seconds(10),
        ))
        .await?
    {
        ClaimOutcome::Leased(lease) => lease,
        ClaimOutcome::Inactive | ClaimOutcome::Stale | ClaimOutcome::NotFound => {
            return Err("retry task was not initially leased".into());
        }
    };
    let abandoned = restarted
        .abandon_execution(AbandonExecution::new(
            retry_task.task_id(),
            retry_task.generation(),
            first_retry_lease.version(),
            first_retry_lease.claimed_at(),
            retry_task.current_job_id(),
            base + time::Duration::seconds(11),
        ))
        .await?;
    assert_eq!(abandoned, AbandonOutcome::Released);
    let second_retry_lease = match restarted
        .claim_execution(ExecutionClaim::new(
            retry_task.task_id(),
            retry_task.generation(),
            retry_task.current_job_id(),
            base + time::Duration::seconds(12),
        ))
        .await?
    {
        ClaimOutcome::Leased(lease) => lease,
        ClaimOutcome::Inactive | ClaimOutcome::Stale | ClaimOutcome::NotFound => {
            return Err("released receipt could not be claimed again".into());
        }
    };
    let raw_pool = database.pool.sqlx_pool();
    let expired_lease = sqlx::query(
        "UPDATE public.mcp_tasks
         SET lease_claimed_at = clock_timestamp() - INTERVAL '2 seconds',
             lease_expires_at = clock_timestamp() - INTERVAL '1 second'
         WHERE task_id = $1",
    )
    .bind(retry_task.task_id().as_uuid())
    .execute(&raw_pool)
    .await?;
    assert_eq!(expired_lease.rows_affected(), 1);
    let recovered_lease = match restarted
        .claim_execution(ExecutionClaim::new(
            retry_task.task_id(),
            retry_task.generation(),
            retry_task.current_job_id(),
            base + time::Duration::seconds(13),
        ))
        .await?
    {
        ClaimOutcome::Leased(lease) => lease,
        ClaimOutcome::Inactive | ClaimOutcome::Stale | ClaimOutcome::NotFound => {
            return Err("expired lease receipt was not recovered".into());
        }
    };
    assert_eq!(recovered_lease.version(), second_retry_lease.version());
    let stale_attempt = restarted
        .settle_execution(SettleExecution::new(
            retry_task.task_id(),
            retry_task.generation(),
            second_retry_lease.version(),
            second_retry_lease.claimed_at(),
            retry_task.current_job_id(),
            TerminalSettlement::Failed(omnius_mcp_tasks::TaskFailureCode::Indeterminate),
            base + time::Duration::seconds(14),
        ))
        .await?;
    assert!(matches!(stale_attempt, SettlementOutcome::Stale));
    let recovered = restarted
        .settle_execution(SettleExecution::new(
            retry_task.task_id(),
            retry_task.generation(),
            recovered_lease.version(),
            recovered_lease.claimed_at(),
            retry_task.current_job_id(),
            TerminalSettlement::Failed(omnius_mcp_tasks::TaskFailureCode::Indeterminate),
            base + time::Duration::seconds(14),
        ))
        .await?;
    assert!(matches!(recovered, SettlementOutcome::Applied(_)));

    let task_count: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_tasks")
        .fetch_one(&raw_pool)
        .await?;
    assert_eq!(task_count, 4);
    let outbox_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.outbox_events WHERE aggregate_type = 'mcp_task'",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(outbox_count, 6);
    let protected_task_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tasks
         WHERE task_algorithm = 'aes-256-gcm' AND octet_length(task_ciphertext) > 16",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(protected_task_count, 4);
    let protected_round_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_task_input_rounds
         WHERE round_algorithm = 'aes-256-gcm' AND octet_length(round_ciphertext) > 16",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(protected_round_count, 1);
    for marker in [
        protected_marker,
        input_response_marker,
        "secret-contract-create-key-never-stored",
    ] {
        let leaked_payload_count: i64 = sqlx::query_scalar(
            "SELECT
                 (SELECT count(*) FROM public.mcp_tasks
                  WHERE to_jsonb(mcp_tasks)::text LIKE $1)
               + (SELECT count(*) FROM public.mcp_task_input_rounds
                  WHERE to_jsonb(mcp_task_input_rounds)::text LIKE $1)
               + (SELECT count(*) FROM public.outbox_events
                  WHERE aggregate_type = 'mcp_task' AND payload::text LIKE $1)
               + (SELECT count(*) FROM public.mcp_task_events
                  WHERE to_jsonb(mcp_task_events)::text LIKE $1)
               + (SELECT count(*) FROM public.mcp_task_idempotency
                  WHERE to_jsonb(mcp_task_idempotency)::text LIKE $1)
               + (SELECT count(*) FROM public.mcp_task_input_keys
                  WHERE to_jsonb(mcp_task_input_keys)::text LIKE $1)
               + (SELECT count(*) FROM public.inbox_receipts
                  WHERE producer = 'omnius.mcp.tasks.worker'
                    AND to_jsonb(inbox_receipts)::text LIKE $1)",
        )
        .bind(format!("%{marker}%"))
        .fetch_one(&raw_pool)
        .await?;
        assert_eq!(leaked_payload_count, 0, "plaintext marker leaked");
    }
    let completed_receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.inbox_receipts
         WHERE producer = 'omnius.mcp.tasks.worker' AND processed_at IS NOT NULL",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(completed_receipts, 3);
    let unprocessed_receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.inbox_receipts
         WHERE producer = 'omnius.mcp.tasks.worker' AND processed_at IS NULL",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(unprocessed_receipts, 0);
    let persisted_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_task_events
         WHERE event_kind IN ('created', 'input_required', 'cancellation_requested', 'cancelled')",
    )
    .fetch_one(&raw_pool)
    .await?;
    assert_eq!(persisted_events, 7);

    Ok(())
}
