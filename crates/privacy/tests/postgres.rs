//! PostgreSQL concurrency, restart, legal-hold, consent, and moderation contracts.

use std::{
    error::Error,
    num::NonZeroU16,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use rsk_audit::{AuditConfig, PostgresAuditSink};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_config::{DeploymentEnvironment, SecretString};
use rsk_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use rsk_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use rsk_privacy::{
    AdapterEvidence, AdapterFailure, AdapterFailureCode, AdapterFuture, AdapterName, AdapterWork,
    AddModerationEvidence, AppealDecisionKind, AuthorizationDenied, AutomatedModerationPolicy,
    ConsentDocumentKind, ConsentEvidenceFormat, ConsentPolicy, ConsentRule, ConsentSource,
    ConsentTransport, ConsentWithdrawalRule, CreateLegalHold, CreateLifecycleRequest,
    DataInventoryAdapter, DeadLetterCommand, DecideAppeal, EvidenceDigest, EvidenceKind,
    InventoryCategory, InventoryDescriptor, InventoryEffect, InventoryRegistry,
    InventoryRequirement, Jurisdiction, LegalHoldBasis, LegalHoldState, LifecycleKind,
    LifecycleTarget, ModerationActionId, ModerationActionKind, ModerationAuthorizationAction,
    ModerationDuration, ObjectReference, PolicyVersion, PrivacyAuthorizationAction,
    PrivacyAuthorizer, PrivacyError, PrivacyResource, PrivacyStore, PrivacyStorePolicies,
    ReasonCode, ReconcileResult, RecordConsent, RecordModerationAction, ReleaseLegalHold, ReportId,
    RequiredInventoryManifest, RetryPolicy, SubmitAppeal, SubmitReport, WithdrawConsent, WorkerId,
};
use rsk_test_support::PostgresFixture;
use sqlx::{Connection as _, Row as _};
use time::OffsetDateTime;

const FIRST_MIGRATION: i64 = 2_026_082_301;

struct TestDatabase {
    pool: PostgresPool,
    fixture: PostgresFixture,
    tenant: TenantId,
    owner: SubjectId,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 6,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_mins(1),
        max_lifetime_jitter: Duration::from_secs(5),
        application_name: "rsk-privacy-test".to_owned(),
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

async fn database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    let runner = MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(FIRST_MIGRATION, rsk_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(20),
        },
        DeploymentEnvironment::Test,
    )?;
    runner.run().await?;
    let tenant = TenantId::new();
    let owner = SubjectId::new();
    let now = OffsetDateTime::now_utc();
    let mut connection = pool.acquire().await?;
    let mut transaction = connection.begin().await?;
    sqlx::query("INSERT INTO public.users (id, created_at) VALUES ($1, $2)")
        .bind(owner.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "INSERT INTO public.organizations
         (id, name, status, version, created_at, updated_at, deleted_at)
         VALUES ($1, 'Privacy tenant', 'active', 1, $2, $2, NULL)",
    )
    .bind(tenant.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO public.memberships
         (organization_id, user_id, role, status, grant_version, created_at, updated_at)
         VALUES ($1, $2, 'owner', 'active', 1, $3, $3)",
    )
    .bind(tenant.as_uuid())
    .bind(owner.as_uuid())
    .bind(now)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(TestDatabase {
        pool,
        fixture,
        tenant,
        owner,
    })
}

fn principal(
    subject_id: SubjectId,
    tenant_id: TenantId,
    kind: PrincipalKind,
) -> Result<Principal, rsk_auth_core::PrincipalError> {
    Principal::new(
        subject_id,
        kind,
        Some(tenant_id),
        AuthMethod::Session,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal2,
        Vec::new(),
    )
}

#[derive(Default)]
struct AllowAuthorizer {
    actions: Mutex<Vec<PrivacyAuthorizationAction>>,
    resources: Mutex<Vec<PrivacyResource>>,
}

impl AllowAuthorizer {
    fn actions(&self) -> Result<Vec<PrivacyAuthorizationAction>, PrivacyError> {
        self.actions
            .lock()
            .map(|actions| actions.clone())
            .map_err(|_| PrivacyError::InvalidState)
    }

    fn resources(&self) -> Result<Vec<PrivacyResource>, PrivacyError> {
        self.resources
            .lock()
            .map(|resources| resources.clone())
            .map_err(|_| PrivacyError::InvalidState)
    }
}

impl PrivacyAuthorizer for AllowAuthorizer {
    fn authorize(
        &self,
        _principal: &Principal,
        action: PrivacyAuthorizationAction,
        resource: PrivacyResource,
    ) -> Result<(), AuthorizationDenied> {
        self.actions
            .lock()
            .map_err(|_| AuthorizationDenied)?
            .push(action);
        self.resources
            .lock()
            .map_err(|_| AuthorizationDenied)?
            .push(resource);
        Ok(())
    }
}

struct ContractAdapter {
    descriptor: InventoryDescriptor,
    failure: Option<AdapterFailureCode>,
    calls: AtomicUsize,
}

impl ContractAdapter {
    fn shared(
        name: &str,
        category: InventoryCategory,
        failure: Option<AdapterFailureCode>,
    ) -> Result<Arc<dyn DataInventoryAdapter>, rsk_privacy::PrivacyValueError> {
        Ok(Arc::new(Self {
            descriptor: InventoryDescriptor::new(AdapterName::new(name)?, category),
            failure,
            calls: AtomicUsize::new(0),
        }))
    }
}

impl DataInventoryAdapter for ContractAdapter {
    fn descriptor(&self) -> &InventoryDescriptor {
        &self.descriptor
    }

    fn reconcile<'a>(&'a self, work: &'a AdapterWork) -> AdapterFuture<'a> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(code) = self.failure {
                return Err(AdapterFailure::new(code));
            }
            let effect = if work.operation == LifecycleKind::Export {
                InventoryEffect::Exported(rsk_privacy::ArtifactId::new())
            } else {
                InventoryEffect::Mutated
            };
            Ok(AdapterEvidence::new(
                effect,
                1,
                EvidenceDigest::hash(b"typed-test-reconciliation"),
            ))
        })
    }
}

fn retry_policy() -> Result<RetryPolicy, rsk_privacy::RetryPolicyError> {
    RetryPolicy::new(
        3,
        Duration::from_secs(10),
        Duration::from_secs(5),
        Duration::from_secs(30),
        Duration::from_secs(30),
    )
}

fn consent_policy(document_version: &str) -> Result<ConsentPolicy, PrivacyError> {
    ConsentPolicy::new(
        vec![ConsentRule {
            document_kind: ConsentDocumentKind::Marketing,
            document_version: PolicyVersion::new(document_version)
                .map_err(|_| PrivacyError::InvalidState)?,
            jurisdiction: Jurisdiction::new("US-CA").map_err(|_| PrivacyError::InvalidState)?,
            actor_kind: PrincipalKind::User,
            transport: ConsentTransport::Web,
            source: ConsentSource::Web,
            evidence_format: ConsentEvidenceFormat::Checkbox,
            withdrawal_permitted: true,
        }],
        vec![ConsentWithdrawalRule {
            jurisdiction: Jurisdiction::new("US-CA").map_err(|_| PrivacyError::InvalidState)?,
            actor_kind: PrincipalKind::User,
            transport: ConsentTransport::Web,
            source: ConsentSource::Web,
            evidence_format: ConsentEvidenceFormat::Checkbox,
        }],
    )
    .map_err(|_| PrivacyError::InvalidState)
}

fn store(
    database: &TestDatabase,
    authorizer: Arc<AllowAuthorizer>,
    adapters: Vec<Arc<dyn DataInventoryAdapter>>,
) -> Result<PrivacyStore, PrivacyError> {
    store_with_consent(
        database,
        authorizer,
        adapters,
        consent_policy("marketing-4")?,
    )
}

fn store_with_consent(
    database: &TestDatabase,
    authorizer: Arc<AllowAuthorizer>,
    adapters: Vec<Arc<dyn DataInventoryAdapter>>,
    consent: ConsentPolicy,
) -> Result<PrivacyStore, PrivacyError> {
    let manifest = RequiredInventoryManifest::new(adapters.iter().map(|adapter| {
        let descriptor = adapter.descriptor();
        InventoryRequirement::new(
            descriptor.name().clone(),
            descriptor.category(),
            NonZeroU16::MIN,
        )
    }))
    .map_err(|_| PrivacyError::InvalidState)?;
    let inventory =
        InventoryRegistry::new(manifest, adapters).map_err(|_| PrivacyError::InvalidState)?;
    let automated_moderation =
        AutomatedModerationPolicy::new(Vec::new()).map_err(|_| PrivacyError::InvalidState)?;
    PrivacyStore::new(
        database.pool.clone(),
        PostgresAuditSink::new(AuditConfig { enabled: true }),
        authorizer,
        inventory,
        PrivacyStorePolicies {
            consent,
            automated_moderation,
        },
        retry_policy().map_err(|_| PrivacyError::InvalidState)?,
    )
}

#[tokio::test]
async fn concurrent_workers_only_publish_one_fenced_completion() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let request = service
        .create_lifecycle_request(
            &principal(database.owner, database.tenant, PrincipalKind::User)?,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    let first = service.clone();
    let second = service.clone();
    let worker_a = WorkerId::new("privacy-worker-a")?;
    let worker_b = WorkerId::new("privacy-worker-b")?;
    let (left, right) = tokio::join!(
        first.reconcile_next(&worker_a),
        second.reconcile_next(&worker_b)
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ReconcileResult::Completed(request.id))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ReconcileResult::Idle)
            .count(),
        1
    );
    let mut connection = database.pool.acquire().await?;
    let state: String =
        sqlx::query_scalar("SELECT state FROM public.privacy_lifecycle_requests WHERE id = $1")
            .bind(request.id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(state, "completed");
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn expired_fence_restarts_and_finalizes_already_reconciled_inventory()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let request = service
        .create_lifecycle_request(
            &principal(database.owner, database.tenant, PrincipalKind::User)?,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    let now = OffsetDateTime::now_utc();
    let expired = now - time::Duration::seconds(1);
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE public.privacy_lifecycle_requests
         SET state = 'running', attempt_count = 1, fence = 1,
             lease_owner = 'crashed-worker', lease_expires_at = $2,
             next_attempt_at = NULL, updated_at = $3
         WHERE id = $1",
    )
    .bind(request.id.as_uuid())
    .bind(expired)
    .bind(now)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE public.privacy_inventory_reconciliations
         SET state = 'succeeded', attempt_count = 1, evidence_effect = 'mutated',
             artifact_id = NULL, evidence_sha256 = $2, affected_records = 1,
             failure_code = NULL, reconciled_at = $3, updated_at = $3
         WHERE request_id = $1",
    )
    .bind(request.id.as_uuid())
    .bind(
        EvidenceDigest::hash(b"committed-before-crash")
            .as_bytes()
            .as_slice(),
    )
    .bind(now)
    .execute(&mut *connection)
    .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("restart-worker")?)
            .await?,
        ReconcileResult::Completed(request.id)
    );
    let fence: i64 =
        sqlx::query_scalar("SELECT fence FROM public.privacy_lifecycle_requests WHERE id = $1")
            .bind(request.id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(fence, 2);
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn missing_or_failed_inventory_adapter_prevents_completion() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let creator = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "snapshotted-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let missing_request = creator
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::export(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    let restarted_without_adapter = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "different-adapter",
            InventoryCategory::Object,
            None,
        )?],
    )?;
    assert_eq!(
        restarted_without_adapter
            .reconcile_next(&WorkerId::new("privacy-restarted")?)
            .await?,
        ReconcileResult::RetryScheduled(missing_request.id)
    );
    let terminal_store = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "terminal-provider",
            InventoryCategory::Provider,
            Some(AdapterFailureCode::PermissionDenied),
        )?],
    )?;
    let failed_request = terminal_store
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    assert_eq!(
        terminal_store
            .reconcile_next(&WorkerId::new("privacy-terminal")?)
            .await?,
        ReconcileResult::DeadLettered(failed_request.id)
    );
    let mut connection = database.pool.acquire().await?;
    let rows =
        sqlx::query("SELECT id, state FROM public.privacy_lifecycle_requests WHERE id = ANY($1)")
            .bind(vec![
                missing_request.id.as_uuid(),
                failed_request.id.as_uuid(),
            ])
            .fetch_all(&mut *connection)
            .await?;
    assert!(rows.iter().all(|row| {
        row.try_get::<String, _>("state")
            .is_ok_and(|state| state != "completed")
    }));
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn legal_hold_blocks_destructive_work_until_release_reconciles() -> Result<(), Box<dyn Error>>
{
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let (hold_id, hold_request) = service
        .create_legal_hold(
            &principal,
            &CreateLegalHold {
                target: LifecycleTarget::subject(database.tenant, database.owner),
                basis: LegalHoldBasis::Litigation,
                policy_version: PolicyVersion::new("hold-2026-08")?,
            },
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("privacy-hold")?)
            .await?,
        ReconcileResult::Completed(hold_request.id)
    );
    assert_eq!(
        service
            .legal_hold(&principal, database.tenant, hold_id)
            .await?
            .state,
        LegalHoldState::Active
    );
    let deletion = service
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("privacy-held-delete")?)
            .await?,
        ReconcileResult::Idle
    );
    let release = service
        .release_legal_hold(
            &principal,
            ReleaseLegalHold {
                hold_id,
                tenant_id: database.tenant,
            },
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("privacy-release")?)
            .await?,
        ReconcileResult::Completed(release.id)
    );
    let mut connection = database.pool.acquire().await?;
    let provenance_update =
        sqlx::query("UPDATE public.privacy_legal_holds SET basis = 'regulatory' WHERE id = $1")
            .bind(hold_id.as_uuid())
            .execute(&mut *connection)
            .await;
    assert!(provenance_update.is_err());
    assert_eq!(
        service
            .legal_hold(&principal, database.tenant, hold_id)
            .await?
            .state,
        LegalHoldState::Released
    );
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("privacy-after-release")?)
            .await?,
        ReconcileResult::Completed(deletion.id)
    );
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn consent_evidence_and_withdrawal_are_immutable_and_versioned() -> Result<(), Box<dyn Error>>
{
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let consent = service
        .record_consent(
            &principal,
            ConsentTransport::Web,
            &RecordConsent {
                tenant_id: database.tenant,
                subject_id: database.owner,
                document_kind: ConsentDocumentKind::Marketing,
                document_version: PolicyVersion::new("marketing-4")?,
                jurisdiction: Jurisdiction::new("US-CA")?,
                evidence_digest: EvidenceDigest::hash(b"consent-ceremony"),
            },
        )
        .await?;
    assert_eq!(consent.source, ConsentSource::Web);
    assert_eq!(consent.evidence_format, ConsentEvidenceFormat::Checkbox);
    assert!(consent.withdrawal_permitted);
    assert!(authorizer.resources()?.iter().any(|resource| {
        resource.consent.as_ref().is_some_and(|context| {
            context.source == ConsentSource::Web
                && context.transport == ConsentTransport::Web
                && context.evidence_format == ConsentEvidenceFormat::Checkbox
                && context.effective_at == consent.accepted_at
                && context.withdrawal_permitted
        })
    }));
    let withdrawal_command = WithdrawConsent {
        consent_id: consent.id,
        tenant_id: database.tenant,
        subject_id: database.owner,
        jurisdiction: Jurisdiction::new("US-CA")?,
        evidence_digest: EvidenceDigest::hash(b"withdrawal-ceremony"),
    };
    let rolled_policy_service = store_with_consent(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
        consent_policy("marketing-5")?,
    )?;
    rolled_policy_service
        .withdraw_consent(&principal, ConsentTransport::Web, &withdrawal_command)
        .await?;
    assert!(authorizer.resources()?.iter().any(|resource| {
        resource.consent.as_ref().is_some_and(|context| {
            context.grant_source == Some(ConsentSource::Web)
                && context.grant_evidence_format == Some(ConsentEvidenceFormat::Checkbox)
                && context.withdrawal_permitted
        })
    }));
    assert_eq!(
        rolled_policy_service
            .withdraw_consent(&principal, ConsentTransport::Web, &withdrawal_command)
            .await,
        Err(PrivacyError::Conflict)
    );
    let mut connection = database.pool.acquire().await?;
    let update =
        sqlx::query("UPDATE public.privacy_consent_records SET source = 'api' WHERE id = $1")
            .bind(consent.id.as_uuid())
            .execute(&mut *connection)
            .await;
    assert!(update.is_err());
    database.fixture.cleanup().await?;
    Ok(())
}

struct ModerationActors {
    reporter: Principal,
    subject: Principal,
    moderator: Principal,
    administrator: Principal,
}

struct ModeratedCase {
    report: ReportId,
    action: ModerationActionId,
    subject: SubjectId,
}

fn moderation_actors(
    database: &TestDatabase,
) -> Result<ModerationActors, rsk_auth_core::PrincipalError> {
    Ok(ModerationActors {
        reporter: principal(database.owner, database.tenant, PrincipalKind::User)?,
        subject: principal(SubjectId::new(), database.tenant, PrincipalKind::User)?,
        moderator: principal(SubjectId::new(), database.tenant, PrincipalKind::User)?,
        administrator: principal(SubjectId::new(), database.tenant, PrincipalKind::User)?,
    })
}

async fn moderate_case(
    service: &PrivacyStore,
    database: &TestDatabase,
    actors: &ModerationActors,
) -> Result<ModeratedCase, Box<dyn Error>> {
    let subject_id = actors.subject.subject_id;
    let report = service
        .submit_report(
            &actors.reporter,
            &SubmitReport {
                tenant_id: database.tenant,
                subject_id,
                reason_code: ReasonCode::new("harassment")?,
                policy_version: PolicyVersion::new("moderation-12")?,
            },
        )
        .await?;
    service
        .begin_moderator_review(&actors.moderator, database.tenant, report.id)
        .await?;
    service
        .add_moderator_evidence(
            &actors.moderator,
            &AddModerationEvidence {
                report_id: report.id,
                tenant_id: database.tenant,
                appeal_id: None,
                evidence_kind: EvidenceKind::Content,
                object_reference: ObjectReference::new("moderation/content/object-77")?,
                evidence_digest: EvidenceDigest::hash(b"governed-content-evidence"),
                policy_version: PolicyVersion::new("moderation-12")?,
            },
        )
        .await?;
    let action = service
        .record_moderator_action(
            &actors.moderator,
            &RecordModerationAction {
                report_id: report.id,
                tenant_id: database.tenant,
                subject_id,
                action_kind: ModerationActionKind::Warning,
                reason_code: ReasonCode::new("policy-violation")?,
                policy_version: PolicyVersion::new("moderation-12")?,
                effective_until: None,
            },
        )
        .await?;
    Ok(ModeratedCase {
        report: report.id,
        action: action.id,
        subject: subject_id,
    })
}

async fn appeal_and_decide_case(
    service: &PrivacyStore,
    database: &TestDatabase,
    actors: &ModerationActors,
    case: &ModeratedCase,
) -> Result<(), Box<dyn Error>> {
    let appeal = service
        .submit_appeal(
            &actors.subject,
            &SubmitAppeal {
                report_id: case.report,
                action_id: case.action,
                tenant_id: database.tenant,
                subject_id: case.subject,
                reason_code: ReasonCode::new("context-missing")?,
                policy_version: PolicyVersion::new("moderation-12")?,
            },
        )
        .await?;
    service
        .decide_administrator_appeal(
            &actors.administrator,
            &DecideAppeal {
                appeal_id: appeal.id,
                tenant_id: database.tenant,
                decision: AppealDecisionKind::Upheld,
                reason_code: ReasonCode::new("insufficient-evidence")?,
                policy_version: PolicyVersion::new("moderation-12")?,
            },
        )
        .await?;
    Ok(())
}

fn assert_moderation_authorization_actions(
    authorizer: &AllowAuthorizer,
) -> Result<(), PrivacyError> {
    let actions = authorizer.actions()?;
    let expected = [
        ModerationAuthorizationAction::ReporterSubmitReport,
        ModerationAuthorizationAction::ModeratorBeginReview,
        ModerationAuthorizationAction::ModeratorAddEvidence,
        ModerationAuthorizationAction::ModeratorRecordAction,
        ModerationAuthorizationAction::SubjectSubmitAppeal,
        ModerationAuthorizationAction::AdministratorDecideAppeal,
    ];
    assert!(
        expected
            .into_iter()
            .all(|action| actions.contains(&PrivacyAuthorizationAction::Moderation(action)))
    );
    assert!(authorizer.resources()?.iter().any(|resource| {
        resource.moderation.as_ref().is_some_and(|context| {
            context.action_kind == Some(ModerationActionKind::Warning)
                && context.policy_version.as_str() == "moderation-12"
                && context.reason_code.as_str() == "policy-violation"
                && context.duration == Some(ModerationDuration::Permanent)
        })
    }));
    Ok(())
}

#[tokio::test]
async fn moderation_uses_explicit_reporter_moderator_subject_and_admin_actions()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let actors = moderation_actors(&database)?;
    let moderated = moderate_case(&service, &database, &actors).await?;
    appeal_and_decide_case(&service, &database, &actors, &moderated).await?;
    assert_moderation_authorization_actions(&authorizer)?;
    let mut connection = database.pool.acquire().await?;
    let report_update = sqlx::query(
        "UPDATE public.privacy_moderation_reports SET reason_code = 'rewritten' WHERE id = $1",
    )
    .bind(moderated.report.as_uuid())
    .execute(&mut *connection)
    .await;
    assert!(report_update.is_err());
    let state_rewrite = sqlx::query(
        "UPDATE public.privacy_moderation_reports
         SET state = 'submitted', version = version + 1, updated_at = $2
         WHERE id = $1",
    )
    .bind(moderated.report.as_uuid())
    .bind(OffsetDateTime::now_utc())
    .execute(&mut *connection)
    .await;
    assert!(state_rewrite.is_err());
    let appeal_update = sqlx::query(
        "UPDATE public.privacy_moderation_appeals
         SET reason_code = 'rewritten' WHERE report_id = $1",
    )
    .bind(moderated.report.as_uuid())
    .execute(&mut *connection)
    .await;
    assert!(appeal_update.is_err());
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn legal_hold_atomically_pauses_and_fences_a_live_destructive_lease()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let deletion = service
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    let now = OffsetDateTime::now_utc();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE public.privacy_lifecycle_requests
         SET state = 'running', attempt_count = 1, fence = 1, lease_owner = 'live-worker',
             lease_expires_at = $2, next_attempt_at = NULL, updated_at = $3
         WHERE id = $1",
    )
    .bind(deletion.id.as_uuid())
    .bind(now + time::Duration::minutes(5))
    .bind(now)
    .execute(&mut *connection)
    .await?;
    let (hold_id, hold_request) = service
        .create_legal_hold(
            &principal,
            &CreateLegalHold {
                target: LifecycleTarget::subject(database.tenant, database.owner),
                basis: LegalHoldBasis::Investigation,
                policy_version: PolicyVersion::new("hold-race-1")?,
            },
        )
        .await?;
    let paused = sqlx::query(
        "SELECT state, fence, lease_owner
         FROM public.privacy_lifecycle_requests WHERE id = $1",
    )
    .bind(deletion.id.as_uuid())
    .fetch_one(&mut *connection)
    .await?;
    assert_eq!(paused.try_get::<String, _>("state")?, "hold_wait");
    assert_eq!(paused.try_get::<i64, _>("fence")?, 2);
    assert!(
        paused
            .try_get::<Option<String>, _>("lease_owner")?
            .is_none()
    );
    assert_eq!(
        service
            .legal_hold(&principal, database.tenant, hold_id)
            .await?
            .state,
        LegalHoldState::PendingActive
    );
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("hold-race-worker")?)
            .await?,
        ReconcileResult::Completed(hold_request.id)
    );
    let release = service
        .release_legal_hold(
            &principal,
            ReleaseLegalHold {
                hold_id,
                tenant_id: database.tenant,
            },
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("hold-race-release")?)
            .await?,
        ReconcileResult::Completed(release.id)
    );
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("hold-race-resumed")?)
            .await?,
        ReconcileResult::Completed(deletion.id)
    );
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn legal_hold_dead_letter_can_be_reviewed_and_redriven_without_direct_mutation()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let failing = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            Some(AdapterFailureCode::PermissionDenied),
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let (hold_id, request) = failing
        .create_legal_hold(
            &principal,
            &CreateLegalHold {
                target: LifecycleTarget::subject(database.tenant, database.owner),
                basis: LegalHoldBasis::Regulatory,
                policy_version: PolicyVersion::new("hold-redrive-1")?,
            },
        )
        .await?;
    assert_eq!(
        failing
            .reconcile_next(&WorkerId::new("hold-dead-letter")?)
            .await?,
        ReconcileResult::DeadLettered(request.id)
    );
    let recovered = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let command = DeadLetterCommand {
        request_id: request.id,
        tenant_id: database.tenant,
    };
    recovered.review_dead_letter(&principal, command).await?;
    let redriven = recovered.redrive_dead_letter(&principal, command).await?;
    assert!(redriven.fence > request.fence);
    assert_eq!(
        recovered
            .reconcile_next(&WorkerId::new("hold-redrive")?)
            .await?,
        ReconcileResult::Completed(request.id)
    );
    assert_eq!(
        recovered
            .legal_hold(&principal, database.tenant, hold_id)
            .await?
            .state,
        LegalHoldState::Active
    );
    let actions = authorizer.actions()?;
    assert!(actions.contains(&PrivacyAuthorizationAction::LifecycleDeadLetterReview));
    assert!(actions.contains(&PrivacyAuthorizationAction::LifecycleDeadLetterRedrive));
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn completed_export_exposes_only_an_authorized_bounded_manifest_and_immutable_evidence()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        Arc::clone(&authorizer),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let request = service
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::export(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("export-manifest")?)
            .await?,
        ReconcileResult::Completed(request.id)
    );
    let manifest = service
        .export_manifest(&principal, database.tenant, request.id)
        .await?;
    assert_eq!(manifest.entries.len(), 1);
    assert!(manifest.entries[0].artifact_id.is_some());
    assert_eq!(manifest.entries[0].affected_records, 1);
    assert!(
        authorizer
            .actions()?
            .contains(&PrivacyAuthorizationAction::ExportManifestViewOwnSubject)
    );
    let mut connection = database.pool.acquire().await?;
    let evidence_update = sqlx::query(
        "UPDATE public.privacy_inventory_reconciliations
         SET evidence_sha256 = $2 WHERE request_id = $1",
    )
    .bind(request.id.as_uuid())
    .bind(EvidenceDigest::hash(b"forged").as_bytes().as_slice())
    .execute(&mut *connection)
    .await;
    assert!(evidence_update.is_err());
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn moderation_rejects_past_expiry_and_non_allowlisted_automation()
-> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let authorizer = Arc::new(AllowAuthorizer::default());
    let service = store(
        &database,
        authorizer,
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let reporter = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let subject_id = SubjectId::new();
    let report = service
        .submit_report(
            &reporter,
            &SubmitReport {
                tenant_id: database.tenant,
                subject_id,
                reason_code: ReasonCode::new("abuse")?,
                policy_version: PolicyVersion::new("moderation-12")?,
            },
        )
        .await?;
    let moderator = principal(SubjectId::new(), database.tenant, PrincipalKind::User)?;
    service
        .begin_moderator_review(&moderator, database.tenant, report.id)
        .await?;
    let command = RecordModerationAction {
        report_id: report.id,
        tenant_id: database.tenant,
        subject_id,
        action_kind: ModerationActionKind::Warning,
        reason_code: ReasonCode::new("expired")?,
        policy_version: PolicyVersion::new("moderation-12")?,
        effective_until: Some(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
    };
    assert_eq!(
        service.record_moderator_action(&moderator, &command).await,
        Err(PrivacyError::InvalidState)
    );
    let automated = principal(
        SubjectId::new(),
        database.tenant,
        PrincipalKind::ServiceAccount,
    )?;
    assert_eq!(
        service
            .record_automated_action(
                &automated,
                &RecordModerationAction {
                    effective_until: None,
                    ..command
                }
            )
            .await,
        Err(PrivacyError::AutomatedActionNotAllowed)
    );
    database.fixture.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn held_permanent_adapter_failure_resumes_as_dead_letter() -> Result<(), Box<dyn Error>> {
    let database = database().await?;
    let service = store(
        &database,
        Arc::new(AllowAuthorizer::default()),
        vec![ContractAdapter::shared(
            "primary-db",
            InventoryCategory::PostgreSql,
            None,
        )?],
    )?;
    let principal = principal(database.owner, database.tenant, PrincipalKind::User)?;
    let deletion = service
        .create_lifecycle_request(
            &principal,
            CreateLifecycleRequest::delete(LifecycleTarget::subject(
                database.tenant,
                database.owner,
            )),
        )
        .await?;
    let now = OffsetDateTime::now_utc();
    let mut connection = database.pool.acquire().await?;
    sqlx::query(
        "UPDATE public.privacy_lifecycle_requests
         SET state = 'running', attempt_count = 1, fence = 1, lease_owner = 'failed-worker',
             lease_expires_at = $2, next_attempt_at = NULL, updated_at = $3
         WHERE id = $1",
    )
    .bind(deletion.id.as_uuid())
    .bind(now + time::Duration::minutes(5))
    .bind(now)
    .execute(&mut *connection)
    .await?;
    sqlx::query(
        "UPDATE public.privacy_inventory_reconciliations
         SET state = 'permanent_failed', attempt_count = 1,
             failure_code = 'permission_denied', updated_at = $2
         WHERE request_id = $1",
    )
    .bind(deletion.id.as_uuid())
    .bind(now)
    .execute(&mut *connection)
    .await?;
    let (hold_id, hold_request) = service
        .create_legal_hold(
            &principal,
            &CreateLegalHold {
                target: LifecycleTarget::subject(database.tenant, database.owner),
                basis: LegalHoldBasis::Investigation,
                policy_version: PolicyVersion::new("hold-permanent-1")?,
            },
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("permanent-hold-apply")?)
            .await?,
        ReconcileResult::Completed(hold_request.id)
    );
    let release = service
        .release_legal_hold(
            &principal,
            ReleaseLegalHold {
                hold_id,
                tenant_id: database.tenant,
            },
        )
        .await?;
    assert_eq!(
        service
            .reconcile_next(&WorkerId::new("permanent-hold-release")?)
            .await?,
        ReconcileResult::Completed(release.id)
    );
    let state: String =
        sqlx::query_scalar("SELECT state FROM public.privacy_lifecycle_requests WHERE id = $1")
            .bind(deletion.id.as_uuid())
            .fetch_one(&mut *connection)
            .await?;
    assert_eq!(state, "dead_letter");
    database.fixture.cleanup().await?;
    Ok(())
}
