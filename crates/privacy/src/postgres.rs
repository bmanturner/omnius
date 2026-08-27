use std::sync::Arc;

use omnius_audit::{
    AuditEvent, AuditEventType, AuditOutcome, AuditResourceId, AuditScope, AuditSinkError,
    PostgresAuditSink,
};
use omnius_auth_core::{Principal, PrincipalKind, SubjectId, TenantId};
use omnius_authz_basic::{Action, ResourceKind};
use omnius_postgres::{PostgresError, PostgresPool};
use sqlx::{Connection as _, Postgres, Row as _, Transaction, postgres::PgRow};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    ActorIdentity, AdapterEvidence, AdapterFailureCode, AdapterName, AdapterWork,
    AddModerationEvidence, AppealDecision, AppealDecisionId, AppealId, AppealRecord, AppealState,
    ArtifactId, AuthorizationDenied, AutomatedModerationPolicy, ConsentAuthorizationContext,
    ConsentDocumentKind, ConsentEvidenceFormat, ConsentId, ConsentPolicy, ConsentPolicyError,
    ConsentRecord, ConsentSource, ConsentTransport, ConsentWithdrawal, ConsentWithdrawalId,
    CreateLegalHold, CreateLifecycleRequest, DeadLetterCommand, DecideAppeal, EvidenceDigest,
    EvidenceId, EvidenceKind, ExportManifest, ExportManifestEntry, InventoryCategory,
    InventoryRegistry, LegalHoldBasis, LegalHoldId, LegalHoldRecord, LegalHoldState,
    LifecycleFailureCode, LifecycleKind, LifecycleLease, LifecycleRequest, LifecycleRequestId,
    LifecycleState, LifecycleTarget, ModerationAction, ModerationActionId, ModerationActionKind,
    ModerationActorRole, ModerationAuthorizationAction, ModerationAuthorizationContext,
    ModerationDuration, ModerationEvidence, ModerationReport, PolicyVersion,
    PrivacyAuthorizationAction, PrivacyAuthorizer, PrivacyResource, ReasonCode, RecordConsent,
    RecordModerationAction, ReleaseLegalHold, ReportId, ReportState, RetryPolicy, SubmitAppeal,
    SubmitReport, WithdrawConsent, WorkerId,
};

/// Redaction-safe privacy application and persistence failures.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrivacyError {
    /// The injected policy denied the explicit application action.
    #[error("privacy action is not authorized")]
    Unauthorized,
    /// A referenced privacy record does not exist in the expected tenant.
    #[error("privacy record was not found")]
    NotFound,
    /// Durable state does not permit the requested transition.
    #[error("privacy record is in an incompatible state")]
    InvalidState,
    /// Another request already owns the unique operation or record.
    #[error("privacy operation conflicts with existing durable state")]
    Conflict,
    /// The current lifecycle fence or lease is no longer authoritative.
    #[error("privacy lifecycle lease was lost")]
    LostLease,
    /// The consent record does not permit withdrawal.
    #[error("consent record does not permit withdrawal")]
    WithdrawalNotPermitted,
    /// Trusted consent policy has no matching rule for the command.
    #[error("consent command does not match configured policy")]
    ConsentPolicyMismatch,
    /// Server policy does not allow the requested automated moderation action.
    #[error("automated moderation action is not allowed")]
    AutomatedActionNotAllowed,
    /// A bounded public number cannot be represented durably.
    #[error("privacy value exceeds a durable numeric bound")]
    NumericBound,
    /// Persisted data violated this crate's closed contract.
    #[error("privacy persistence contains invalid state")]
    CorruptState,
    /// PostgreSQL was unavailable or rejected the operation.
    #[error("privacy persistence is unavailable")]
    Database,
    /// The required append-only audit record could not be committed.
    #[error("privacy audit append failed")]
    Audit,
    /// Audit persistence must be enabled for this store.
    #[error("privacy store requires enabled audit persistence")]
    AuditDisabled,
}

impl From<AuthorizationDenied> for PrivacyError {
    fn from(_: AuthorizationDenied) -> Self {
        Self::Unauthorized
    }
}

impl From<PostgresError> for PrivacyError {
    fn from(_: PostgresError) -> Self {
        Self::Database
    }
}
impl From<ConsentPolicyError> for PrivacyError {
    fn from(_: ConsentPolicyError) -> Self {
        Self::ConsentPolicyMismatch
    }
}

/// Outcome of one database-authoritative reconciliation pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileResult {
    /// No eligible request exists; held destructive requests remain pending.
    Idle,
    /// Every snapshotted adapter reconciled and the request completed.
    Completed(LifecycleRequestId),
    /// At least one retryable adapter failure was durably scheduled.
    RetryScheduled(LifecycleRequestId),
    /// A terminal failure or exhausted attempts dead-lettered the request.
    DeadLettered(LifecycleRequestId),
    /// A legal hold paused and fenced the destructive request.
    PausedByLegalHold(LifecycleRequestId),
}

/// Server-owned policies injected into the privacy application service.
#[derive(Clone, Debug)]
pub struct PrivacyStorePolicies {
    /// Trusted consent evidence derivation rules.
    pub consent: ConsentPolicy,
    /// Explicit automated moderation action allowlist.
    pub automated_moderation: AutomatedModerationPolicy,
}

/// Audited PostgreSQL privacy application service and lifecycle worker.
#[derive(Clone)]
pub struct PrivacyStore {
    pool: PostgresPool,
    audit: PostgresAuditSink,
    authorizer: Arc<dyn PrivacyAuthorizer>,
    inventory: InventoryRegistry,
    policies: PrivacyStorePolicies,
    retry: RetryPolicy,
}

struct PassSummary {
    attempt: u16,
    max_attempts: u16,
    total: u64,
    succeeded: u64,
    permanent: u64,
    failure_code: Option<String>,
}

struct PassDecision {
    state: LifecycleState,
    failure_code: Option<String>,
    completed_at: Option<OffsetDateTime>,
    next_attempt_at: Option<OffsetDateTime>,
    result: ReconcileResult,
    outcome: AuditOutcome,
    event_type: &'static str,
    action: &'static str,
}
struct ResumedRequest {
    id: LifecycleRequestId,
    target: LifecycleTarget,
    fence: u64,
    state: LifecycleState,
    failure_code: Option<String>,
}

struct StoredConsentGrant {
    document_kind: ConsentDocumentKind,
    document_version: PolicyVersion,
    source: ConsentSource,
    evidence_format: ConsentEvidenceFormat,
    withdrawal_permitted: bool,
    accepted_at: OffsetDateTime,
}

struct WithdrawalPolicyFacts {
    source: ConsentSource,
    evidence_format: ConsentEvidenceFormat,
}

struct AppealableCase {
    report: ModerationReport,
    action_kind: ModerationActionKind,
    duration: ModerationDuration,
}

struct DecidableAppeal {
    report_id: ReportId,
    subject_id: SubjectId,
    reporter_subject_id: SubjectId,
    action_kind: ModerationActionKind,
    duration: ModerationDuration,
}

impl PrivacyStore {
    /// Creates a privacy service with an exact data inventory and mandatory audit sink.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::AuditDisabled`] when audit persistence is disabled.
    pub fn new(
        pool: PostgresPool,
        audit: PostgresAuditSink,
        authorizer: Arc<dyn PrivacyAuthorizer>,
        inventory: InventoryRegistry,
        policies: PrivacyStorePolicies,
        retry: RetryPolicy,
    ) -> Result<Self, PrivacyError> {
        if !audit.config().enabled {
            return Err(PrivacyError::AuditDisabled);
        }
        Ok(Self {
            pool,
            audit,
            authorizer,
            inventory,
            policies,
            retry,
        })
    }

    /// Returns the immutable process inventory used for new request snapshots and reconciliation.
    #[must_use]
    pub const fn inventory(&self) -> &InventoryRegistry {
        &self.inventory
    }

    /// Reads one lifecycle request after an explicit own-subject or tenant status decision.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when absent, denied, unavailable, or corrupt.
    pub async fn lifecycle_request(
        &self,
        principal: &Principal,
        request_id: LifecycleRequestId,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let row = sqlx::query("SELECT * FROM public.privacy_lifecycle_requests WHERE id = $1")
            .bind(request_id.as_uuid())
            .fetch_optional(&mut *connection)
            .await
            .map_err(map_database)?
            .ok_or(PrivacyError::NotFound)?;
        let request = lifecycle_from_row(&row)?;
        let action = if request.target.subject_id == Some(principal.subject_id) {
            PrivacyAuthorizationAction::LifecycleViewOwnSubject
        } else {
            PrivacyAuthorizationAction::LifecycleViewTenant
        };
        self.authorizer
            .authorize(principal, action, privacy_resource(request.target))?;
        Ok(request)
    }
    /// Reviews a tenant-scoped dead letter and records the administrative read atomically.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when absent, not dead-lettered, denied, unavailable, or corrupt.
    pub async fn review_dead_letter(
        &self,
        principal: &Principal,
        command: DeadLetterCommand,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "SELECT * FROM public.privacy_lifecycle_requests
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(command.request_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        let request = lifecycle_from_row(&row)?;
        if request.state != LifecycleState::DeadLetter {
            return Err(PrivacyError::InvalidState);
        }
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::LifecycleDeadLetterReview,
            privacy_resource(request.target),
        )?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.dead_letter_reviewed",
            ActorIdentity::from_principal(principal),
            request.target,
            "privacy.lifecycle.dead_letter_review",
            "privacy_lifecycle_request",
            request.id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(request)
    }

    /// Redrives a dead letter with a new fence while preserving every successful adapter result.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when absent, not dead-lettered, denied, unavailable, or corrupt.
    pub async fn redrive_dead_letter(
        &self,
        principal: &Principal,
        command: DeadLetterCommand,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let actor = ActorIdentity::from_principal(principal);
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "SELECT * FROM public.privacy_lifecycle_requests
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(command.request_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        let prior = lifecycle_from_row(&row)?;
        if prior.state != LifecycleState::DeadLetter {
            return Err(PrivacyError::InvalidState);
        }
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::LifecycleDeadLetterRedrive,
            privacy_resource(prior.target),
        )?;
        sqlx::query(
            "UPDATE public.privacy_inventory_reconciliations
             SET state = 'pending', attempt_count = 0, evidence_effect = NULL,
                 artifact_id = NULL, evidence_sha256 = NULL, affected_records = NULL,
                 failure_code = NULL, reconciled_at = NULL, updated_at = $2
             WHERE request_id = $1 AND state <> 'succeeded'",
        )
        .bind(command.request_id.as_uuid())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_database)?;
        let row = sqlx::query(
            "UPDATE public.privacy_lifecycle_requests
             SET state = 'pending', attempt_count = 0, fence = fence + 1,
                 lease_owner = NULL, lease_expires_at = NULL, next_attempt_at = $2,
                 last_failure_code = NULL, updated_at = $2, completed_at = NULL
             WHERE id = $1 AND state = 'dead_letter'
             RETURNING *",
        )
        .bind(command.request_id.as_uuid())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::InvalidState)?;
        let request = lifecycle_from_row(&row)?;
        insert_transition(
            &mut transaction,
            request.id,
            Some(LifecycleState::DeadLetter),
            LifecycleState::Pending,
            request.fence,
            actor.kind_str(),
            None,
            now,
        )
        .await?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.dead_letter_redriven",
            actor,
            request.target,
            "privacy.lifecycle.dead_letter_redrive",
            "privacy_lifecycle_request",
            request.id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(request)
    }

    /// Reads an authorized redaction-safe manifest for one completed export.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when absent, incomplete, not an export, denied, or corrupt.
    pub async fn export_manifest(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        request_id: LifecycleRequestId,
    ) -> Result<ExportManifest, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "SELECT * FROM public.privacy_lifecycle_requests
             WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
        )
        .bind(request_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        let request = lifecycle_from_row(&row)?;
        if request.operation != LifecycleKind::Export || request.state != LifecycleState::Completed
        {
            return Err(PrivacyError::InvalidState);
        }
        let action = if request.target.subject_id == Some(principal.subject_id) {
            PrivacyAuthorizationAction::ExportManifestViewOwnSubject
        } else {
            PrivacyAuthorizationAction::ExportManifestViewTenant
        };
        self.authorizer
            .authorize(principal, action, privacy_resource(request.target))?;
        let rows = sqlx::query(
            "SELECT adapter_name, category, adapter_revision, evidence_effect, artifact_id,
                    evidence_sha256, affected_records, reconciled_at
             FROM public.privacy_inventory_reconciliations
             WHERE request_id = $1 AND state = 'succeeded'
             ORDER BY adapter_name
             LIMIT 65",
        )
        .bind(request_id.as_uuid())
        .fetch_all(&mut *transaction)
        .await
        .map_err(map_database)?;
        if rows.len() != usize::from(request.inventory_count) || rows.len() > 64 {
            return Err(PrivacyError::CorruptState);
        }
        let mut entries = Vec::with_capacity(rows.len());
        for row in rows {
            entries.push(export_manifest_entry(&row)?);
        }
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.export_manifest_viewed",
            ActorIdentity::from_principal(principal),
            request.target,
            "privacy.lifecycle.export_manifest_view",
            "privacy_lifecycle_request",
            request.id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(ExportManifest {
            request_id,
            target: request.target,
            entries,
        })
    }

    /// Reads one legal hold after a tenant-scoped legal-hold status decision.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when absent, denied, unavailable, or corrupt.
    pub async fn legal_hold(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        hold_id: LegalHoldId,
    ) -> Result<LegalHoldRecord, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT * FROM public.privacy_legal_holds WHERE id = $1 AND tenant_id = $2",
        )
        .bind(hold_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        let target = target_from_row(&row)?;
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::LegalHoldView,
            privacy_resource(target),
        )?;
        let basis = LegalHoldBasis::parse(
            row.try_get::<&str, _>("basis")
                .map_err(|_| PrivacyError::CorruptState)?,
        )
        .ok_or(PrivacyError::CorruptState)?;
        let policy_version = PolicyVersion::new(
            row.try_get::<String, _>("policy_version")
                .map_err(|_| PrivacyError::CorruptState)?,
        )
        .map_err(|_| PrivacyError::CorruptState)?;
        let state = LegalHoldState::parse(
            row.try_get::<&str, _>("state")
                .map_err(|_| PrivacyError::CorruptState)?,
        )
        .ok_or(PrivacyError::CorruptState)?;
        Ok(LegalHoldRecord {
            id: hold_id,
            target,
            basis,
            policy_version,
            state,
            requested_at: row
                .try_get("requested_at")
                .map_err(|_| PrivacyError::CorruptState)?,
            activated_at: row
                .try_get("activated_at")
                .map_err(|_| PrivacyError::CorruptState)?,
            released_at: row
                .try_get("released_at")
                .map_err(|_| PrivacyError::CorruptState)?,
        })
    }

    /// Creates an audited export, deletion, anonymization, or retention request and snapshots every
    /// registered adapter in the same transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] on authorization, persistence, or audit failure.
    pub async fn create_lifecycle_request(
        &self,
        principal: &Principal,
        command: CreateLifecycleRequest,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let target = command.target();
        let authorization_action = if target.subject_id == Some(principal.subject_id) {
            PrivacyAuthorizationAction::LifecycleRequestOwnSubject
        } else {
            PrivacyAuthorizationAction::LifecycleRequestTenant
        };
        self.authorizer
            .authorize(principal, authorization_action, privacy_resource(target))?;
        let now = OffsetDateTime::now_utc();
        if command
            .retention_before()
            .is_some_and(|cutoff| cutoff >= now)
        {
            return Err(PrivacyError::InvalidState);
        }
        self.insert_lifecycle_request(
            ActorIdentity::from_principal(principal),
            target,
            command.operation(),
            command.retention_before(),
            None,
            now,
        )
        .await
    }

    /// Places an immediately blocking legal hold and starts inventory reconciliation atomically.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] on denial, an existing open hold, persistence, or audit failure.
    pub async fn create_legal_hold(
        &self,
        principal: &Principal,
        command: &CreateLegalHold,
    ) -> Result<(LegalHoldId, LifecycleRequest), PrivacyError> {
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::LegalHoldPlace,
            privacy_resource(command.target),
        )?;
        let actor = ActorIdentity::from_principal(principal);
        let hold_id = LegalHoldId::new();
        let request_id = LifecycleRequestId::new();
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let tenant_locked = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM public.organizations WHERE id = $1 FOR UPDATE",
        )
        .bind(command.target.tenant_id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?;
        if tenant_locked.is_none() {
            return Err(PrivacyError::NotFound);
        }
        let inserted = sqlx::query(
            "INSERT INTO public.privacy_legal_holds (
                id, tenant_id, subject_id, basis, policy_version, state, requested_at,
                activated_at, release_requested_at, released_at,
                created_by_kind, created_by_subject_id
             ) VALUES ($1, $2, $3, $4, $5, 'pending_active', $6, NULL, NULL, NULL, $7, $8)",
        )
        .bind(hold_id.as_uuid())
        .bind(command.target.tenant_id.as_uuid())
        .bind(command.target.subject_id.map(SubjectId::as_uuid))
        .bind(command.basis.as_str())
        .bind(command.policy_version.as_str())
        .bind(now)
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .execute(&mut *transaction)
        .await;
        if let Err(error) = inserted {
            return Err(map_insert_error(&error));
        }
        self.pause_overlapping_destructive(
            &mut transaction,
            command.target,
            ActorIdentity::from_principal(principal),
            now,
        )
        .await?;
        let request = self
            .insert_lifecycle_with(
                &mut transaction,
                request_id,
                actor,
                command.target,
                LifecycleKind::LegalHoldApply,
                None,
                Some(hold_id),
                now,
            )
            .await?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.legal_hold.requested",
            actor,
            command.target,
            "privacy.legal_hold.place",
            "privacy_legal_hold",
            hold_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok((hold_id, request))
    }

    /// Keeps a hold blocking, marks it release-pending, and starts release reconciliation.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when denied or unless the exact tenant hold is active.
    pub async fn release_legal_hold(
        &self,
        principal: &Principal,
        command: ReleaseLegalHold,
    ) -> Result<LifecycleRequest, PrivacyError> {
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::LegalHoldRelease,
            PrivacyResource::tenant(command.tenant_id),
        )?;
        let actor = ActorIdentity::from_principal(principal);
        let request_id = LifecycleRequestId::new();
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "UPDATE public.privacy_legal_holds
             SET state = 'release_pending', release_requested_at = $3
             WHERE id = $1 AND tenant_id = $2 AND state = 'active'
             RETURNING subject_id",
        )
        .bind(command.hold_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::InvalidState)?;
        let subject_id = optional_subject(&row, "subject_id")?;
        let target = LifecycleTarget {
            tenant_id: command.tenant_id,
            subject_id,
        };
        let request = self
            .insert_lifecycle_with(
                &mut transaction,
                request_id,
                actor,
                target,
                LifecycleKind::LegalHoldRelease,
                None,
                Some(command.hold_id),
                now,
            )
            .await?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.legal_hold.release_requested",
            actor,
            target,
            "privacy.legal_hold.release",
            "privacy_legal_hold",
            command.hold_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(request)
    }
    async fn pause_overlapping_destructive(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        hold_target: LifecycleTarget,
        actor: ActorIdentity,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        loop {
            let rows = sqlx::query(
                "WITH blocked AS (
                     SELECT id, state AS prior_state
                     FROM public.privacy_lifecycle_requests
                     WHERE tenant_id = $1
                       AND operation IN ('delete', 'anonymize', 'retention')
                       AND state = 'running'
                       AND (
                           subject_id IS NULL
                           OR $2::uuid IS NULL
                           OR subject_id = $2
                       )
                     ORDER BY id
                     FOR UPDATE
                     LIMIT 64
                 )
                 UPDATE public.privacy_lifecycle_requests AS request
                 SET state = 'hold_wait', fence = request.fence + 1,
                     lease_owner = NULL, lease_expires_at = NULL, next_attempt_at = NULL,
                     last_failure_code = NULL, updated_at = $3
                 FROM blocked
                 WHERE request.id = blocked.id
                 RETURNING request.id, request.tenant_id, request.subject_id, request.fence,
                           blocked.prior_state",
            )
            .bind(hold_target.tenant_id.as_uuid())
            .bind(hold_target.subject_id.map(SubjectId::as_uuid))
            .bind(now)
            .fetch_all(&mut **transaction)
            .await
            .map_err(map_database)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let request_id = lifecycle_id(&row, "id")?;
                let target = target_from_row(&row)?;
                let prior_state = LifecycleState::parse(
                    row.try_get::<&str, _>("prior_state")
                        .map_err(|_| PrivacyError::CorruptState)?,
                )
                .ok_or(PrivacyError::CorruptState)?;
                let fence = nonnegative_u64(&row, "fence")?;
                insert_transition(
                    transaction,
                    request_id,
                    Some(prior_state),
                    LifecycleState::HoldWait,
                    fence,
                    actor.kind_str(),
                    None,
                    now,
                )
                .await?;
                append_audit(
                    &self.audit,
                    transaction,
                    "privacy.lifecycle.paused_by_legal_hold",
                    actor,
                    target,
                    "privacy.lifecycle.pause",
                    "privacy_lifecycle_request",
                    request_id.to_string(),
                    AuditOutcome::Succeeded,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn insert_lifecycle_request(
        &self,
        actor: ActorIdentity,
        target: LifecycleTarget,
        operation: LifecycleKind,
        retention_before: Option<OffsetDateTime>,
        hold_id: Option<LegalHoldId>,
        now: OffsetDateTime,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let request_id = LifecycleRequestId::new();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let request = self
            .insert_lifecycle_with(
                &mut transaction,
                request_id,
                actor,
                target,
                operation,
                retention_before,
                hold_id,
                now,
            )
            .await?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.requested",
            actor,
            target,
            "privacy.lifecycle.request",
            "privacy_lifecycle_request",
            request_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(request)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the durable lifecycle row requires every invariant-bearing field explicitly"
    )]
    async fn insert_lifecycle_with(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        request_id: LifecycleRequestId,
        actor: ActorIdentity,
        target: LifecycleTarget,
        operation: LifecycleKind,
        retention_before: Option<OffsetDateTime>,
        hold_id: Option<LegalHoldId>,
        now: OffsetDateTime,
    ) -> Result<LifecycleRequest, PrivacyError> {
        let inventory_count =
            i16::try_from(self.inventory.len()).map_err(|_| PrivacyError::NumericBound)?;
        sqlx::query(
            "INSERT INTO public.privacy_lifecycle_requests (
                id, tenant_id, subject_id, operation, retention_before, legal_hold_id, state,
                attempt_count, max_attempts, inventory_count, fence, lease_owner, lease_expires_at,
                next_attempt_at, last_failure_code, created_by_kind, created_by_subject_id,
                created_at, updated_at, completed_at
             ) VALUES (
                $1, $2, $3, $4, $5, $6, 'pending', 0, $7, $8, 0, NULL, NULL,
                $9, NULL, $10, $11, $9, $9, NULL
             )",
        )
        .bind(request_id.as_uuid())
        .bind(target.tenant_id.as_uuid())
        .bind(target.subject_id.map(SubjectId::as_uuid))
        .bind(operation.as_str())
        .bind(retention_before)
        .bind(hold_id.map(LegalHoldId::as_uuid))
        .bind(i16::try_from(self.retry.max_attempts()).map_err(|_| PrivacyError::NumericBound)?)
        .bind(inventory_count)
        .bind(now)
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        for requirement in self.inventory.requirements() {
            sqlx::query(
                "INSERT INTO public.privacy_inventory_reconciliations (
                    request_id, adapter_name, category, adapter_revision, state, attempt_count,
                    evidence_effect, artifact_id, evidence_sha256, affected_records, failure_code,
                    reconciled_at, updated_at
                 ) VALUES ($1, $2, $3, $4, 'pending', 0, NULL, NULL, NULL, NULL, NULL, NULL, $5)",
            )
            .bind(request_id.as_uuid())
            .bind(requirement.name().as_str())
            .bind(requirement.category().as_str())
            .bind(i32::from(requirement.minimum_revision().get()))
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(map_database)?;
        }
        insert_transition(
            transaction,
            request_id,
            None,
            LifecycleState::Pending,
            0,
            actor.kind_str(),
            None,
            now,
        )
        .await?;
        Ok(LifecycleRequest {
            id: request_id,
            target,
            operation,
            retention_before,
            legal_hold_id: hold_id,
            state: LifecycleState::Pending,
            attempt_count: 0,
            inventory_count: u16::try_from(inventory_count)
                .map_err(|_| PrivacyError::NumericBound)?,
            max_attempts: self.retry.max_attempts(),
            fence: 0,
            last_failure_code: None,
            created_at: now,
            completed_at: None,
        })
    }

    /// Leases and reconciles at most one eligible request without holding a database transaction
    /// across adapter calls.
    ///
    /// Missing snapshotted adapters are recorded as retryable failures. Adapter success is
    /// published only under the current unexpired fence. All successful rows are preserved across
    /// process restarts.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] for database, audit, corrupt-state, or lost-lease failures.
    pub async fn reconcile_next(
        &self,
        worker_id: &WorkerId,
    ) -> Result<ReconcileResult, PrivacyError> {
        let Some(mut lease) = self.acquire_next(worker_id).await? else {
            return Ok(ReconcileResult::Idle);
        };
        let work = AdapterWork {
            request_id: lease.request.id,
            tenant_id: lease.request.target.tenant_id,
            subject_id: lease.request.target.subject_id,
            operation: lease.request.operation,
            retention_before: lease.request.retention_before,
            legal_hold_id: lease.request.legal_hold_id,
            attempt: lease.request.attempt_count,
            fence: lease.request.fence,
        };
        for index in 0..lease.pending_adapters.len() {
            if lease.request.operation.is_destructive() && self.pause_if_held(&lease).await? {
                return Ok(ReconcileResult::PausedByLegalHold(lease.request.id));
            }
            lease.expires_at = self.renew_lease(&lease).await?;
            let (name, expected_category, expected_revision) = &lease.pending_adapters[index];
            let Some(adapter) = self.inventory.get(name) else {
                self.record_adapter_failure(&lease, name, AdapterFailureCode::AdapterMissing)
                    .await?;
                continue;
            };
            if adapter.descriptor().category() != *expected_category {
                self.record_adapter_failure(&lease, name, AdapterFailureCode::InvalidState)
                    .await?;
                continue;
            }
            if adapter.descriptor().revision().get() < *expected_revision {
                self.record_adapter_failure(&lease, name, AdapterFailureCode::IncompatibleRevision)
                    .await?;
                continue;
            }
            let outcome =
                tokio::time::timeout(self.retry.adapter_timeout(), adapter.reconcile(&work)).await;
            match outcome {
                Ok(Ok(evidence)) if evidence.valid_for(lease.request.operation) => {
                    self.record_adapter_success(&lease, name, evidence).await?;
                }
                Ok(Ok(_)) => {
                    self.record_adapter_failure(&lease, name, AdapterFailureCode::InvalidState)
                        .await?;
                }
                Ok(Err(failure)) => {
                    self.record_adapter_failure(&lease, name, failure.code())
                        .await?;
                }
                Err(_) => {
                    self.record_adapter_failure(&lease, name, AdapterFailureCode::Timeout)
                        .await?;
                }
            }
        }
        self.finalize_pass(&lease).await
    }

    async fn acquire_next(
        &self,
        worker_id: &WorkerId,
    ) -> Result<Option<LifecycleLease>, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let lease_expires_at = add_std_duration(now, self.retry.lease_duration())?;
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        self.dead_letter_exhausted(&mut transaction, now).await?;
        let Some((request, prior_state)) =
            Self::claim_request(&mut transaction, worker_id, now, lease_expires_at).await?
        else {
            transaction.commit().await.map_err(map_database)?;
            return Ok(None);
        };
        let pending_adapters = Self::load_pending_inventory(&mut transaction, request.id).await?;
        insert_transition(
            &mut transaction,
            request.id,
            Some(prior_state),
            LifecycleState::Running,
            request.fence,
            "system",
            None,
            now,
        )
        .await?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.leased",
            ActorIdentity::System,
            request.target,
            "privacy.lifecycle.lease",
            "privacy_lifecycle_request",
            request.id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(Some(LifecycleLease {
            request,
            worker_id: worker_id.clone(),
            expires_at: lease_expires_at,
            pending_adapters,
        }))
    }

    async fn claim_request(
        transaction: &mut Transaction<'_, Postgres>,
        worker_id: &WorkerId,
        now: OffsetDateTime,
        lease_expires_at: OffsetDateTime,
    ) -> Result<Option<(LifecycleRequest, LifecycleState)>, PrivacyError> {
        let row = sqlx::query(
            "WITH candidate AS (
                SELECT request.id, request.state AS prior_state
                FROM public.privacy_lifecycle_requests AS request
                JOIN public.organizations AS tenant ON tenant.id = request.tenant_id
                WHERE (
                    (request.state IN ('pending', 'retry_wait') AND request.next_attempt_at <= $1)
                    OR (
                        request.state = 'running'
                        AND request.lease_expires_at <= $1
                        AND request.attempt_count < request.max_attempts
                    )
                )
                AND NOT (
                    request.operation IN ('delete', 'anonymize', 'retention')
                    AND EXISTS (
                        SELECT 1 FROM public.privacy_legal_holds AS hold
                        WHERE hold.tenant_id = request.tenant_id
                          AND hold.state IN ('pending_active', 'active', 'release_pending')
                          AND (
                              hold.subject_id IS NULL
                              OR request.subject_id IS NULL
                              OR hold.subject_id = request.subject_id
                          )
                    )
                )
                ORDER BY COALESCE(request.next_attempt_at, request.lease_expires_at),
                         request.created_at, request.id
                FOR UPDATE OF request, tenant SKIP LOCKED
                LIMIT 1
             )
             UPDATE public.privacy_lifecycle_requests AS request
             SET state = 'running', attempt_count = request.attempt_count + 1,
                 fence = request.fence + 1, lease_owner = $2, lease_expires_at = $3,
                 next_attempt_at = NULL, last_failure_code = NULL, updated_at = $1
             FROM candidate
             WHERE request.id = candidate.id
             RETURNING request.*, candidate.prior_state",
        )
        .bind(now)
        .bind(worker_id.as_str())
        .bind(lease_expires_at)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database)?;
        row.map(|row| {
            let prior_state = LifecycleState::parse(
                row.try_get::<&str, _>("prior_state")
                    .map_err(|_| PrivacyError::CorruptState)?,
            )
            .ok_or(PrivacyError::CorruptState)?;
            Ok((lifecycle_from_row(&row)?, prior_state))
        })
        .transpose()
    }

    async fn load_pending_inventory(
        transaction: &mut Transaction<'_, Postgres>,
        request_id: LifecycleRequestId,
    ) -> Result<Vec<(AdapterName, InventoryCategory, u16)>, PrivacyError> {
        let rows = sqlx::query(
            "SELECT adapter_name, category, adapter_revision
             FROM public.privacy_inventory_reconciliations
             WHERE request_id = $1 AND state <> 'succeeded'
             ORDER BY adapter_name
             LIMIT 65",
        )
        .bind(request_id.as_uuid())
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_database)?;
        if rows.len() > 64 {
            return Err(PrivacyError::CorruptState);
        }
        let mut adapters = Vec::with_capacity(rows.len());
        for row in rows {
            let name = AdapterName::new(
                row.try_get::<String, _>("adapter_name")
                    .map_err(|_| PrivacyError::CorruptState)?,
            )
            .map_err(|_| PrivacyError::CorruptState)?;
            let category = InventoryCategory::parse(
                row.try_get::<&str, _>("category")
                    .map_err(|_| PrivacyError::CorruptState)?,
            )
            .ok_or(PrivacyError::CorruptState)?;
            let revision = row
                .try_get::<i32, _>("adapter_revision")
                .ok()
                .and_then(|value| u16::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or(PrivacyError::CorruptState)?;
            adapters.push((name, category, revision));
        }
        Ok(adapters)
    }

    async fn dead_letter_exhausted(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        let rows = sqlx::query(
            "WITH exhausted AS (
                 SELECT id
                 FROM public.privacy_lifecycle_requests
                 WHERE state = 'running' AND lease_expires_at <= $1
                   AND attempt_count >= max_attempts
                 ORDER BY lease_expires_at, id
                 FOR UPDATE SKIP LOCKED
                 LIMIT 64
             )
             UPDATE public.privacy_lifecycle_requests AS request
             SET state = 'dead_letter', lease_owner = NULL, lease_expires_at = NULL,
                 next_attempt_at = NULL, last_failure_code = 'lease_expired',
                 updated_at = $1, completed_at = $1
             FROM exhausted
             WHERE request.id = exhausted.id
             RETURNING request.id, request.tenant_id, request.subject_id, request.fence",
        )
        .bind(now)
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_database)?;
        for row in rows {
            let request_id = lifecycle_id(&row, "id")?;
            let target = target_from_row(&row)?;
            let fence = nonnegative_u64(&row, "fence")?;
            insert_transition(
                transaction,
                request_id,
                Some(LifecycleState::Running),
                LifecycleState::DeadLetter,
                fence,
                "system",
                Some("lease_expired"),
                now,
            )
            .await?;
            append_audit(
                &self.audit,
                transaction,
                "privacy.lifecycle.dead_lettered",
                ActorIdentity::System,
                target,
                "privacy.lifecycle.dead_letter",
                "privacy_lifecycle_request",
                request_id.to_string(),
                AuditOutcome::Failed,
            )
            .await?;
        }
        Ok(())
    }
    async fn pause_if_held(&self, lease: &LifecycleLease) -> Result<bool, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let row = sqlx::query(
            "UPDATE public.privacy_lifecycle_requests AS request
             SET state = 'hold_wait', fence = request.fence + 1,
                 lease_owner = NULL, lease_expires_at = NULL, next_attempt_at = NULL,
                 last_failure_code = NULL, updated_at = $4
             WHERE request.id = $1 AND request.state = 'running' AND request.lease_owner = $2
               AND request.fence = $3 AND request.lease_expires_at > $4
               AND EXISTS (
                   SELECT 1 FROM public.privacy_legal_holds AS hold
                   WHERE hold.tenant_id = request.tenant_id
                     AND hold.state IN ('pending_active', 'active', 'release_pending')
                     AND (
                         hold.subject_id IS NULL
                         OR request.subject_id IS NULL
                         OR hold.subject_id = request.subject_id
                     )
               )
             RETURNING request.fence",
        )
        .bind(lease.request.id.as_uuid())
        .bind(lease.worker_id.as_str())
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?;
        if let Some(row) = row {
            let fence = nonnegative_u64(&row, "fence")?;
            insert_transition(
                &mut transaction,
                lease.request.id,
                Some(LifecycleState::Running),
                LifecycleState::HoldWait,
                fence,
                "system",
                None,
                now,
            )
            .await?;
            append_audit(
                &self.audit,
                &mut transaction,
                "privacy.lifecycle.paused_by_legal_hold",
                ActorIdentity::System,
                lease.request.target,
                "privacy.lifecycle.pause",
                "privacy_lifecycle_request",
                lease.request.id.to_string(),
                AuditOutcome::Succeeded,
            )
            .await?;
            transaction.commit().await.map_err(map_database)?;
            return Ok(true);
        }
        let state = sqlx::query_scalar::<_, String>(
            "SELECT state FROM public.privacy_lifecycle_requests WHERE id = $1",
        )
        .bind(lease.request.id.as_uuid())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::LostLease)?;
        transaction.commit().await.map_err(map_database)?;
        if state == "hold_wait" {
            Ok(true)
        } else if state == "running" {
            Ok(false)
        } else {
            Err(PrivacyError::LostLease)
        }
    }

    async fn renew_lease(&self, lease: &LifecycleLease) -> Result<OffsetDateTime, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let expires_at = add_std_duration(now, self.retry.lease_duration())?;
        let mut connection = self.pool.acquire().await?;
        let result = sqlx::query(
            "UPDATE public.privacy_lifecycle_requests
             SET lease_expires_at = $4, updated_at = $3
             WHERE id = $1 AND state = 'running' AND lease_owner = $2
               AND fence = $5 AND lease_expires_at > $3",
        )
        .bind(lease.request.id.as_uuid())
        .bind(lease.worker_id.as_str())
        .bind(now)
        .bind(expires_at)
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .execute(&mut *connection)
        .await
        .map_err(map_database)?;
        if result.rows_affected() != 1 {
            return Err(PrivacyError::LostLease);
        }
        Ok(expires_at)
    }

    async fn record_adapter_success(
        &self,
        lease: &LifecycleLease,
        name: &AdapterName,
        evidence: AdapterEvidence,
    ) -> Result<(), PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let records =
            i64::try_from(evidence.affected_records()).map_err(|_| PrivacyError::NumericBound)?;
        let artifact_id = evidence
            .effect()
            .artifact_id()
            .map(crate::ArtifactId::as_uuid);
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let result = sqlx::query(
            "UPDATE public.privacy_inventory_reconciliations AS item
             SET state = 'succeeded', attempt_count = item.attempt_count + 1,
                 evidence_effect = $4, artifact_id = $5, evidence_sha256 = $6,
                 affected_records = $7, failure_code = NULL, reconciled_at = $8, updated_at = $8
             WHERE item.request_id = $1 AND item.adapter_name = $2 AND item.state <> 'succeeded'
               AND EXISTS (
                   SELECT 1 FROM public.privacy_lifecycle_requests AS request
                   WHERE request.id = item.request_id AND request.state = 'running'
                     AND request.lease_owner = $3 AND request.fence = $9
                     AND request.lease_expires_at > $8
               )",
        )
        .bind(lease.request.id.as_uuid())
        .bind(name.as_str())
        .bind(lease.worker_id.as_str())
        .bind(evidence.effect().as_str())
        .bind(artifact_id)
        .bind(evidence.digest().as_bytes().as_slice())
        .bind(records)
        .bind(now)
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database)?;
        if result.rows_affected() != 1 {
            return Err(PrivacyError::LostLease);
        }
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.adapter_reconciled",
            ActorIdentity::System,
            lease.request.target,
            "privacy.lifecycle.reconcile_adapter",
            "privacy_inventory_adapter",
            format!("{}:{}", lease.request.id, name.as_str()),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)
    }

    async fn record_adapter_failure(
        &self,
        lease: &LifecycleLease,
        name: &AdapterName,
        code: AdapterFailureCode,
    ) -> Result<(), PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let state = if code.is_retryable() {
            "retryable_failed"
        } else {
            "permanent_failed"
        };
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let result = sqlx::query(
            "UPDATE public.privacy_inventory_reconciliations AS item
             SET state = $4, attempt_count = item.attempt_count + 1,
                 evidence_effect = NULL, artifact_id = NULL, evidence_sha256 = NULL,
                 affected_records = NULL, failure_code = $5, reconciled_at = NULL, updated_at = $6
             WHERE item.request_id = $1 AND item.adapter_name = $2 AND item.state <> 'succeeded'
               AND EXISTS (
                   SELECT 1 FROM public.privacy_lifecycle_requests AS request
                   WHERE request.id = item.request_id AND request.state = 'running'
                     AND request.lease_owner = $3 AND request.fence = $7
                     AND request.lease_expires_at > $6
               )",
        )
        .bind(lease.request.id.as_uuid())
        .bind(name.as_str())
        .bind(lease.worker_id.as_str())
        .bind(state)
        .bind(code.as_str())
        .bind(now)
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .execute(&mut *transaction)
        .await
        .map_err(map_database)?;
        if result.rows_affected() != 1 {
            return Err(PrivacyError::LostLease);
        }
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.lifecycle.adapter_failed",
            ActorIdentity::System,
            lease.request.target,
            "privacy.lifecycle.reconcile_adapter",
            "privacy_inventory_adapter",
            format!("{}:{}", lease.request.id, name.as_str()),
            AuditOutcome::Failed,
        )
        .await?;
        transaction.commit().await.map_err(map_database)
    }

    async fn finalize_pass(&self, lease: &LifecycleLease) -> Result<ReconcileResult, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let summary = Self::load_pass_summary(&mut transaction, lease, now).await?;
        let decision = self.decide_pass(lease.request.id, summary, now)?;
        self.persist_pass_decision(&mut transaction, lease, &decision, now)
            .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(decision.result)
    }

    async fn load_pass_summary(
        transaction: &mut Transaction<'_, Postgres>,
        lease: &LifecycleLease,
        now: OffsetDateTime,
    ) -> Result<PassSummary, PrivacyError> {
        let locked = sqlx::query(
            "SELECT attempt_count, max_attempts, inventory_count
             FROM public.privacy_lifecycle_requests
             WHERE id = $1 AND state = 'running' AND lease_owner = $2 AND fence = $3
               AND lease_expires_at > $4
             FOR UPDATE",
        )
        .bind(lease.request.id.as_uuid())
        .bind(lease.worker_id.as_str())
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::LostLease)?;
        let attempt = positive_u16(&locked, "attempt_count")?;
        let max_attempts = positive_u16(&locked, "max_attempts")?;
        let expected_inventory = u64::from(positive_u16(&locked, "inventory_count")?);
        let counts = sqlx::query(
            "SELECT
                 count(*) AS total,
                 count(*) FILTER (WHERE state = 'succeeded') AS succeeded,
                 count(*) FILTER (WHERE state = 'permanent_failed') AS permanent,
                 min(failure_code) FILTER (WHERE state <> 'succeeded') AS failure_code
             FROM public.privacy_inventory_reconciliations
             WHERE request_id = $1",
        )
        .bind(lease.request.id.as_uuid())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database)?;
        let total = nonnegative_u64(&counts, "total")?;
        if total != expected_inventory {
            return Err(PrivacyError::CorruptState);
        }
        Ok(PassSummary {
            attempt,
            max_attempts,
            total,
            succeeded: nonnegative_u64(&counts, "succeeded")?,
            permanent: nonnegative_u64(&counts, "permanent")?,
            failure_code: counts
                .try_get("failure_code")
                .map_err(|_| PrivacyError::CorruptState)?,
        })
    }

    fn decide_pass(
        &self,
        request_id: LifecycleRequestId,
        summary: PassSummary,
        now: OffsetDateTime,
    ) -> Result<PassDecision, PrivacyError> {
        if summary.total == summary.succeeded {
            return Ok(PassDecision {
                state: LifecycleState::Completed,
                failure_code: None,
                completed_at: Some(now),
                next_attempt_at: None,
                result: ReconcileResult::Completed(request_id),
                outcome: AuditOutcome::Succeeded,
                event_type: "privacy.lifecycle.completed",
                action: "privacy.lifecycle.complete",
            });
        }
        if summary.permanent > 0 || summary.attempt >= summary.max_attempts {
            return Ok(PassDecision {
                state: LifecycleState::DeadLetter,
                failure_code: Some(
                    summary
                        .failure_code
                        .unwrap_or_else(|| "attempts_exhausted".to_owned()),
                ),
                completed_at: Some(now),
                next_attempt_at: None,
                result: ReconcileResult::DeadLettered(request_id),
                outcome: AuditOutcome::Failed,
                event_type: "privacy.lifecycle.dead_lettered",
                action: "privacy.lifecycle.dead_letter",
            });
        }
        Ok(PassDecision {
            state: LifecycleState::RetryWait,
            failure_code: Some(
                summary
                    .failure_code
                    .unwrap_or_else(|| "unavailable".to_owned()),
            ),
            completed_at: None,
            next_attempt_at: Some(add_std_duration(now, self.retry.backoff(summary.attempt))?),
            result: ReconcileResult::RetryScheduled(request_id),
            outcome: AuditOutcome::Failed,
            event_type: "privacy.lifecycle.retry_scheduled",
            action: "privacy.lifecycle.retry",
        })
    }

    async fn persist_pass_decision(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        lease: &LifecycleLease,
        decision: &PassDecision,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        let updated = sqlx::query(
            "UPDATE public.privacy_lifecycle_requests
             SET state = $4, lease_owner = NULL, lease_expires_at = NULL,
                 next_attempt_at = $5, last_failure_code = $6,
                 updated_at = $7, completed_at = $8
             WHERE id = $1 AND lease_owner = $2 AND fence = $3 AND state = 'running'",
        )
        .bind(lease.request.id.as_uuid())
        .bind(lease.worker_id.as_str())
        .bind(i64::try_from(lease.request.fence).map_err(|_| PrivacyError::NumericBound)?)
        .bind(decision.state.as_str())
        .bind(decision.next_attempt_at)
        .bind(decision.failure_code.as_deref())
        .bind(now)
        .bind(decision.completed_at)
        .execute(&mut **transaction)
        .await
        .map_err(map_database)?;
        if updated.rows_affected() != 1 {
            return Err(PrivacyError::LostLease);
        }
        if decision.state == LifecycleState::Completed {
            self.finalize_completed_hold(transaction, lease, now)
                .await?;
        }
        insert_transition(
            transaction,
            lease.request.id,
            Some(LifecycleState::Running),
            decision.state,
            lease.request.fence,
            "system",
            decision.failure_code.as_deref(),
            now,
        )
        .await?;
        append_audit(
            &self.audit,
            transaction,
            decision.event_type,
            ActorIdentity::System,
            lease.request.target,
            decision.action,
            "privacy_lifecycle_request",
            lease.request.id.to_string(),
            decision.outcome,
        )
        .await
    }

    async fn finalize_completed_hold(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        lease: &LifecycleLease,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        let Some(hold_id) = lease.request.legal_hold_id else {
            return Ok(());
        };
        let (query, hold_event, hold_action) = match lease.request.operation {
            LifecycleKind::LegalHoldApply => (
                "UPDATE public.privacy_legal_holds
                 SET state = 'active', activated_at = $2
                 WHERE id = $1 AND state = 'pending_active'",
                "privacy.legal_hold.activated",
                "privacy.legal_hold.activate",
            ),
            LifecycleKind::LegalHoldRelease => (
                "UPDATE public.privacy_legal_holds
                 SET state = 'released', released_at = $2
                 WHERE id = $1 AND state = 'release_pending'",
                "privacy.legal_hold.released",
                "privacy.legal_hold.release_complete",
            ),
            LifecycleKind::Export
            | LifecycleKind::Delete
            | LifecycleKind::Anonymize
            | LifecycleKind::Retention => return Err(PrivacyError::CorruptState),
        };
        let hold_result = sqlx::query(query)
            .bind(hold_id.as_uuid())
            .bind(now)
            .execute(&mut **transaction)
            .await
            .map_err(map_database)?;
        if hold_result.rows_affected() != 1 {
            return Err(PrivacyError::CorruptState);
        }
        if lease.request.operation == LifecycleKind::LegalHoldRelease {
            self.resume_unblocked_destructive(transaction, lease.request.target.tenant_id, now)
                .await?;
        }
        append_audit(
            &self.audit,
            transaction,
            hold_event,
            ActorIdentity::System,
            lease.request.target,
            hold_action,
            "privacy_legal_hold",
            hold_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await
    }
    async fn resume_unblocked_destructive(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        tenant_id: TenantId,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        loop {
            let resumed = Self::resume_unblocked_batch(transaction, tenant_id, now).await?;
            if resumed.is_empty() {
                return Ok(());
            }
            self.record_resume_events(transaction, &resumed, now)
                .await?;
        }
    }

    async fn resume_unblocked_batch(
        transaction: &mut Transaction<'_, Postgres>,
        tenant_id: TenantId,
        now: OffsetDateTime,
    ) -> Result<Vec<ResumedRequest>, PrivacyError> {
        let rows = sqlx::query(
            "WITH resumable AS (
                 SELECT request.id,
                        EXISTS (
                            SELECT 1
                            FROM public.privacy_inventory_reconciliations AS item
                            WHERE item.request_id = request.id
                              AND item.state = 'permanent_failed'
                        ) AS has_permanent_failure,
                        (
                            SELECT COALESCE(item.failure_code, 'invalid_state')
                            FROM public.privacy_inventory_reconciliations AS item
                            WHERE item.request_id = request.id
                              AND item.state = 'permanent_failed'
                            ORDER BY item.adapter_name
                            LIMIT 1
                        ) AS permanent_failure_code
                 FROM public.privacy_lifecycle_requests AS request
                 WHERE request.tenant_id = $1 AND request.state = 'hold_wait'
                   AND NOT EXISTS (
                       SELECT 1 FROM public.privacy_legal_holds AS hold
                       WHERE hold.tenant_id = request.tenant_id
                         AND hold.state IN ('pending_active', 'active', 'release_pending')
                         AND (
                             hold.subject_id IS NULL
                             OR request.subject_id IS NULL
                             OR hold.subject_id = request.subject_id
                         )
                   )
                 ORDER BY request.id
                 FOR UPDATE
                 LIMIT 64
             )
             UPDATE public.privacy_lifecycle_requests AS request
             SET state = CASE
                     WHEN resumable.has_permanent_failure
                         OR request.attempt_count >= request.max_attempts
                     THEN 'dead_letter'
                     ELSE 'pending'
                 END,
                 fence = request.fence + 1,
                 next_attempt_at = CASE
                     WHEN resumable.has_permanent_failure
                         OR request.attempt_count >= request.max_attempts
                     THEN NULL
                     ELSE $2
                 END,
                 lease_owner = NULL, lease_expires_at = NULL,
                 last_failure_code = CASE
                     WHEN resumable.has_permanent_failure
                     THEN resumable.permanent_failure_code
                     WHEN request.attempt_count >= request.max_attempts THEN 'attempts_exhausted'
                     ELSE NULL
                 END,
                 updated_at = $2,
                 completed_at = CASE
                     WHEN resumable.has_permanent_failure
                         OR request.attempt_count >= request.max_attempts
                     THEN $2
                     ELSE NULL
                 END
             FROM resumable
             WHERE request.id = resumable.id
             RETURNING request.id, request.tenant_id, request.subject_id, request.fence,
                       request.state, request.last_failure_code",
        )
        .bind(tenant_id.as_uuid())
        .bind(now)
        .fetch_all(&mut **transaction)
        .await
        .map_err(map_database)?;
        rows.iter().map(resumed_request_from_row).collect()
    }

    async fn record_resume_events(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        resumed: &[ResumedRequest],
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        for request in resumed {
            insert_transition(
                transaction,
                request.id,
                Some(LifecycleState::HoldWait),
                request.state,
                request.fence,
                "system",
                request.failure_code.as_deref(),
                now,
            )
            .await?;
            let (event_type, action, outcome) = resume_audit_facts(request.state);
            append_audit(
                &self.audit,
                transaction,
                event_type,
                ActorIdentity::System,
                request.target,
                action,
                "privacy_lifecycle_request",
                request.id.to_string(),
                outcome,
            )
            .await?;
        }
        Ok(())
    }

    /// Appends immutable, versioned consent evidence and its audit record atomically.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] on denial, duplicate document evidence, persistence, or audit failure.
    pub async fn record_consent(
        &self,
        principal: &Principal,
        transport: ConsentTransport,
        command: &RecordConsent,
    ) -> Result<ConsentRecord, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let rule = self.policies.consent.resolve_grant(
            principal,
            transport,
            command.document_kind,
            &command.document_version,
            &command.jurisdiction,
        )?;
        let source = rule.source;
        let evidence_format = rule.evidence_format;
        let withdrawal_permitted = rule.withdrawal_permitted;
        let action = if command.subject_id == principal.subject_id {
            PrivacyAuthorizationAction::ConsentRecordSelf
        } else {
            PrivacyAuthorizationAction::ConsentRecordAdministrative
        };
        self.authorizer.authorize(
            principal,
            action,
            PrivacyResource::subject(command.tenant_id, command.subject_id).with_consent(
                ConsentAuthorizationContext {
                    document_kind: command.document_kind,
                    document_version: command.document_version.clone(),
                    jurisdiction: command.jurisdiction.clone(),
                    transport,
                    source,
                    evidence_format,
                    effective_at: now,
                    withdrawal_permitted,
                    grant_source: None,
                    grant_evidence_format: None,
                },
            ),
        )?;
        let id = ConsentId::new();
        let actor = ActorIdentity::from_principal(principal);
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        sqlx::query(
            "INSERT INTO public.privacy_consent_records (
                id, tenant_id, subject_id, document_kind, document_version, jurisdiction,
                source, evidence_format, evidence_sha256, withdrawal_permitted, accepted_at,
                recorded_by_kind, recorded_by_subject_id, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .bind(command.document_kind.as_str())
        .bind(command.document_version.as_str())
        .bind(command.jurisdiction.as_str())
        .bind(source.as_str())
        .bind(evidence_format.as_str())
        .bind(command.evidence_digest.as_bytes().as_slice())
        .bind(withdrawal_permitted)
        .bind(now)
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.consent.recorded",
            actor,
            LifecycleTarget::subject(command.tenant_id, command.subject_id),
            "privacy.consent.record",
            "privacy_consent",
            id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(ConsentRecord {
            id,
            tenant_id: command.tenant_id,
            subject_id: command.subject_id,
            document_kind: command.document_kind,
            document_version: command.document_version.clone(),
            jurisdiction: command.jurisdiction.clone(),
            source,
            evidence_format,
            evidence_digest: command.evidence_digest,
            withdrawal_permitted,
            accepted_at: now,
            recorded_by: actor,
            created_at: now,
        })
    }

    /// Appends one immutable withdrawal after checking the exact tenant, subject, and permission.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] when denied, absent, non-withdrawable, duplicate, or unavailable.
    pub async fn withdraw_consent(
        &self,
        principal: &Principal,
        transport: ConsentTransport,
        command: &WithdrawConsent,
    ) -> Result<ConsentWithdrawal, PrivacyError> {
        let actor = ActorIdentity::from_principal(principal);
        let id = ConsentWithdrawalId::new();
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let grant = Self::load_consent_grant(&mut transaction, command).await?;
        let facts =
            self.authorize_consent_withdrawal(principal, transport, command, &grant, now)?;
        let withdrawal = self
            .persist_consent_withdrawal(&mut transaction, command, actor, id, facts, now)
            .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(withdrawal)
    }

    async fn load_consent_grant(
        transaction: &mut Transaction<'_, Postgres>,
        command: &WithdrawConsent,
    ) -> Result<StoredConsentGrant, PrivacyError> {
        let row = sqlx::query(
            "SELECT document_kind, document_version, source, evidence_format,
                    withdrawal_permitted, accepted_at
             FROM public.privacy_consent_records
             WHERE id = $1 AND tenant_id = $2 AND subject_id = $3
             FOR SHARE",
        )
        .bind(command.consent_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        stored_consent_grant_from_row(&row)
    }

    fn authorize_consent_withdrawal(
        &self,
        principal: &Principal,
        transport: ConsentTransport,
        command: &WithdrawConsent,
        grant: &StoredConsentGrant,
        now: OffsetDateTime,
    ) -> Result<WithdrawalPolicyFacts, PrivacyError> {
        if grant.accepted_at > now {
            return Err(PrivacyError::CorruptState);
        }
        let rule = self.policies.consent.resolve_withdrawal(
            principal,
            transport,
            &command.jurisdiction,
        )?;
        let facts = WithdrawalPolicyFacts {
            source: rule.source,
            evidence_format: rule.evidence_format,
        };
        let action = if command.subject_id == principal.subject_id {
            PrivacyAuthorizationAction::ConsentWithdrawSelf
        } else {
            PrivacyAuthorizationAction::ConsentWithdrawAdministrative
        };
        self.authorizer.authorize(
            principal,
            action,
            PrivacyResource::subject(command.tenant_id, command.subject_id).with_consent(
                ConsentAuthorizationContext {
                    document_kind: grant.document_kind,
                    document_version: grant.document_version.clone(),
                    jurisdiction: command.jurisdiction.clone(),
                    transport,
                    source: facts.source,
                    evidence_format: facts.evidence_format,
                    effective_at: now,
                    withdrawal_permitted: grant.withdrawal_permitted,
                    grant_source: Some(grant.source),
                    grant_evidence_format: Some(grant.evidence_format),
                },
            ),
        )?;
        if !grant.withdrawal_permitted {
            return Err(PrivacyError::WithdrawalNotPermitted);
        }
        Ok(facts)
    }

    async fn persist_consent_withdrawal(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        command: &WithdrawConsent,
        actor: ActorIdentity,
        id: ConsentWithdrawalId,
        facts: WithdrawalPolicyFacts,
        now: OffsetDateTime,
    ) -> Result<ConsentWithdrawal, PrivacyError> {
        sqlx::query(
            "INSERT INTO public.privacy_consent_withdrawals (
                id, consent_id, jurisdiction, source, evidence_format, evidence_sha256,
                withdrawn_at, recorded_by_kind, recorded_by_subject_id, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id.as_uuid())
        .bind(command.consent_id.as_uuid())
        .bind(command.jurisdiction.as_str())
        .bind(facts.source.as_str())
        .bind(facts.evidence_format.as_str())
        .bind(command.evidence_digest.as_bytes().as_slice())
        .bind(now)
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        append_audit(
            &self.audit,
            transaction,
            "privacy.consent.withdrawn",
            actor,
            LifecycleTarget::subject(command.tenant_id, command.subject_id),
            "privacy.consent.withdraw",
            "privacy_consent",
            command.consent_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        Ok(ConsentWithdrawal {
            id,
            consent_id: command.consent_id,
            jurisdiction: command.jurisdiction.clone(),
            source: facts.source,
            evidence_format: facts.evidence_format,
            evidence_digest: command.evidence_digest,
            withdrawn_at: now,
            recorded_by: actor,
            created_at: now,
        })
    }

    /// Reads a report under the reporter-owning authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] unless the principal is the human reporter or policy
    /// denies access, [`PrivacyError::NotFound`] when the tenant report is absent, and persistence
    /// or corrupt-state variants when the stored report cannot be read safely.
    pub async fn report_as_reporter(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let report = self.read_report(tenant_id, report_id).await?;
        if report.reporter_subject_id != principal.subject_id {
            return Err(PrivacyError::Unauthorized);
        }
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::ReporterViewOwnReport,
            ),
            report_resource(&report),
        )?;
        Ok(report)
    }

    /// Reads a report under the affected-subject authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] unless the principal is the affected human subject
    /// or policy denies access, [`PrivacyError::NotFound`] when the tenant report is absent, and
    /// persistence or corrupt-state variants when the stored report cannot be read safely.
    pub async fn report_as_subject(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let report = self.read_report(tenant_id, report_id).await?;
        if report.subject_id != principal.subject_id {
            return Err(PrivacyError::Unauthorized);
        }
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::SubjectViewReport,
            ),
            report_resource(&report),
        )?;
        Ok(report)
    }

    /// Reads a report under the moderator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied moderator,
    /// [`PrivacyError::NotFound`] when the tenant report is absent, and persistence or
    /// corrupt-state variants when the stored report cannot be read safely.
    pub async fn report_as_moderator(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let report = self.read_report(tenant_id, report_id).await?;
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::ModeratorViewReport,
            ),
            report_resource(&report),
        )?;
        Ok(report)
    }

    /// Reads a report under the administrator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied administrator,
    /// [`PrivacyError::NotFound`] when the tenant report is absent, and persistence or
    /// corrupt-state variants when the stored report cannot be read safely.
    pub async fn report_as_administrator(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let report = self.read_report(tenant_id, report_id).await?;
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::AdministratorViewReport,
            ),
            report_resource(&report),
        )?;
        Ok(report)
    }

    async fn read_report(
        &self,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT * FROM public.privacy_moderation_reports
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(report_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *connection)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        moderation_report_from_row(&row)
    }

    /// Submits a report as the canonical human reporter without storing free-form text.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] on wrong actor class, denial, persistence, or audit failure.
    pub async fn submit_report(
        &self,
        principal: &Principal,
        command: &SubmitReport,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let resource = PrivacyResource::subject(command.tenant_id, command.subject_id)
            .reported_by(principal.subject_id)
            .with_moderation(ModerationAuthorizationContext {
                action_kind: None,
                policy_version: command.policy_version.clone(),
                reason_code: command.reason_code.clone(),
                duration: None,
            });
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::ReporterSubmitReport,
            ),
            resource,
        )?;
        let id = ReportId::new();
        let now = OffsetDateTime::now_utc();
        let actor = ActorIdentity::from_principal(principal);
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        sqlx::query(
            "INSERT INTO public.privacy_moderation_reports (
                id, tenant_id, reporter_subject_id, subject_id, reason_code, policy_version,
                state, version, created_at, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, 'submitted', 1, $7, $7)",
        )
        .bind(id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .bind(principal.subject_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .bind(command.reason_code.as_str())
        .bind(command.policy_version.as_str())
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.moderation.reported",
            actor,
            LifecycleTarget::subject(command.tenant_id, command.subject_id),
            "privacy.moderation.report.submit",
            "privacy_moderation_report",
            id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(ModerationReport {
            id,
            tenant_id: command.tenant_id,
            reporter_subject_id: principal.subject_id,
            subject_id: command.subject_id,
            reason_code: command.reason_code.clone(),
            policy_version: command.policy_version.clone(),
            state: ReportState::Submitted,
            version: 1,
            created_at: now,
            updated_at: now,
        })
    }

    /// Starts review under the explicit moderator authorization action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError`] unless a human moderator is authorized and the report is submitted.
    pub async fn begin_moderator_review(
        &self,
        principal: &Principal,
        tenant_id: TenantId,
        report_id: ReportId,
    ) -> Result<ModerationReport, PrivacyError> {
        require_human(principal)?;
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let current = report_for_update(&mut transaction, tenant_id, report_id).await?;
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::ModeratorBeginReview,
            ),
            report_resource(&current),
        )?;
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query(
            "UPDATE public.privacy_moderation_reports
             SET state = 'under_review', version = version + 1, updated_at = $3
             WHERE id = $1 AND tenant_id = $2 AND state = 'submitted'
             RETURNING *",
        )
        .bind(report_id.as_uuid())
        .bind(tenant_id.as_uuid())
        .bind(now)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::InvalidState)?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.moderation.review_started",
            ActorIdentity::from_principal(principal),
            LifecycleTarget::subject(tenant_id, current.subject_id),
            "privacy.moderation.report.review",
            "privacy_moderation_report",
            report_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        let report = moderation_report_from_row(&row)?;
        transaction.commit().await.map_err(map_database)?;
        Ok(report)
    }

    /// Adds evidence under the reporter-specific action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] unless the principal is the authorized human
    /// reporter, [`PrivacyError::NotFound`] for an absent report or appeal, and persistence,
    /// invalid-state, or audit variants when the immutable evidence cannot be committed.
    pub async fn add_reporter_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
    ) -> Result<ModerationEvidence, PrivacyError> {
        require_human(principal)?;
        self.add_evidence(
            principal,
            command,
            ModerationAuthorizationAction::ReporterAddEvidence,
        )
        .await
    }

    /// Adds appeal evidence under the affected-subject action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] unless the principal is the authorized affected
    /// human subject with an appeal, [`PrivacyError::NotFound`] for an absent report or appeal, and
    /// persistence, invalid-state, or audit variants when evidence cannot be committed.
    pub async fn add_subject_appeal_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
    ) -> Result<ModerationEvidence, PrivacyError> {
        require_human(principal)?;
        self.add_evidence(
            principal,
            command,
            ModerationAuthorizationAction::SubjectAddAppealEvidence,
        )
        .await
    }

    /// Adds evidence under the moderator-specific action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied moderator,
    /// [`PrivacyError::NotFound`] for an absent report or appeal, and persistence, invalid-state,
    /// or audit variants when the immutable evidence cannot be committed.
    pub async fn add_moderator_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
    ) -> Result<ModerationEvidence, PrivacyError> {
        require_human(principal)?;
        self.add_evidence(
            principal,
            command,
            ModerationAuthorizationAction::ModeratorAddEvidence,
        )
        .await
    }

    /// Adds evidence under the administrator-specific action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied administrator,
    /// [`PrivacyError::NotFound`] for an absent report or appeal, and persistence, invalid-state,
    /// or audit variants when the immutable evidence cannot be committed.
    pub async fn add_administrator_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
    ) -> Result<ModerationEvidence, PrivacyError> {
        require_human(principal)?;
        self.add_evidence(
            principal,
            command,
            ModerationAuthorizationAction::AdministratorAddEvidence,
        )
        .await
    }

    /// Adds provider attestation evidence under the automated-service action.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-service-account or denied actor,
    /// [`PrivacyError::InvalidState`] for non-attestation evidence, [`PrivacyError::NotFound`] for
    /// an absent report or appeal, and persistence or audit variants on commit failure.
    pub async fn add_automated_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
    ) -> Result<ModerationEvidence, PrivacyError> {
        require_service_account(principal)?;
        if command.evidence_kind != EvidenceKind::ProviderAttestation {
            return Err(PrivacyError::InvalidState);
        }
        self.add_evidence(
            principal,
            command,
            ModerationAuthorizationAction::AutomatedAddEvidence,
        )
        .await
    }

    async fn add_evidence(
        &self,
        principal: &Principal,
        command: &AddModerationEvidence,
        authorization_action: ModerationAuthorizationAction,
    ) -> Result<ModerationEvidence, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let report =
            report_for_update(&mut transaction, command.tenant_id, command.report_id).await?;
        let now = OffsetDateTime::now_utc();
        if report.created_at > now {
            return Err(PrivacyError::CorruptState);
        }
        if authorization_action == ModerationAuthorizationAction::ReporterAddEvidence
            && report.reporter_subject_id != principal.subject_id
        {
            return Err(PrivacyError::Unauthorized);
        }
        if authorization_action == ModerationAuthorizationAction::SubjectAddAppealEvidence
            && (report.subject_id != principal.subject_id || command.appeal_id.is_none())
        {
            return Err(PrivacyError::Unauthorized);
        }
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(authorization_action),
            report_resource(&report).with_moderation(ModerationAuthorizationContext {
                action_kind: None,
                policy_version: command.policy_version.clone(),
                reason_code: report.reason_code.clone(),
                duration: None,
            }),
        )?;
        if let Some(appeal_id) = command.appeal_id {
            let exists = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS (
                    SELECT 1 FROM public.privacy_moderation_appeals
                    WHERE id = $1 AND report_id = $2
                 )",
            )
            .bind(appeal_id.as_uuid())
            .bind(command.report_id.as_uuid())
            .fetch_one(&mut *transaction)
            .await
            .map_err(map_database)?;
            if !exists {
                return Err(PrivacyError::NotFound);
            }
        }
        let actor = ActorIdentity::from_principal(principal);
        let id = EvidenceId::new();
        sqlx::query(
            "INSERT INTO public.privacy_moderation_evidence (
                id, report_id, appeal_id, evidence_kind, object_reference, evidence_sha256,
                policy_version, collected_by_kind, collected_by_subject_id, collected_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id.as_uuid())
        .bind(command.report_id.as_uuid())
        .bind(command.appeal_id.map(AppealId::as_uuid))
        .bind(command.evidence_kind.as_str())
        .bind(command.object_reference.as_str())
        .bind(command.evidence_digest.as_bytes().as_slice())
        .bind(command.policy_version.as_str())
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.moderation.evidence_added",
            actor,
            LifecycleTarget::subject(command.tenant_id, report.subject_id),
            "privacy.moderation.evidence.add",
            "privacy_moderation_report",
            command.report_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(ModerationEvidence {
            id,
            report_id: command.report_id,
            appeal_id: command.appeal_id,
            evidence_kind: command.evidence_kind,
            object_reference: command.object_reference.clone(),
            evidence_digest: command.evidence_digest,
            policy_version: command.policy_version.clone(),
            collected_by: actor,
            collected_at: now,
        })
    }

    /// Records an action under the explicit moderator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied moderator,
    /// [`PrivacyError::NotFound`] for an absent report, [`PrivacyError::InvalidState`] for a report
    /// or subject mismatch, and persistence or audit variants on commit failure.
    pub async fn record_moderator_action(
        &self,
        principal: &Principal,
        command: &RecordModerationAction,
    ) -> Result<ModerationAction, PrivacyError> {
        require_human(principal)?;
        self.record_action(
            principal,
            command,
            ModerationActorRole::Moderator,
            ModerationAuthorizationAction::ModeratorRecordAction,
        )
        .await
    }

    /// Records an action under the explicit administrator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied administrator,
    /// [`PrivacyError::NotFound`] for an absent report, [`PrivacyError::InvalidState`] for a report
    /// or subject mismatch, and persistence or audit variants on commit failure.
    pub async fn record_administrator_action(
        &self,
        principal: &Principal,
        command: &RecordModerationAction,
    ) -> Result<ModerationAction, PrivacyError> {
        require_human(principal)?;
        self.record_action(
            principal,
            command,
            ModerationActorRole::Administrator,
            ModerationAuthorizationAction::AdministratorRecordAction,
        )
        .await
    }

    /// Records an action under the explicit automated-service authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-service-account or denied actor,
    /// [`PrivacyError::NotFound`] for an absent report, [`PrivacyError::InvalidState`] for a report
    /// or subject mismatch, and persistence or audit variants on commit failure.
    pub async fn record_automated_action(
        &self,
        principal: &Principal,
        command: &RecordModerationAction,
    ) -> Result<ModerationAction, PrivacyError> {
        require_service_account(principal)?;
        if !self
            .policies
            .automated_moderation
            .permits(command.action_kind)
        {
            return Err(PrivacyError::AutomatedActionNotAllowed);
        }
        self.record_action(
            principal,
            command,
            ModerationActorRole::Automated,
            ModerationAuthorizationAction::AutomatedRecordAction,
        )
        .await
    }

    async fn record_action(
        &self,
        principal: &Principal,
        command: &RecordModerationAction,
        actor_role: ModerationActorRole,
        authorization_action: ModerationAuthorizationAction,
    ) -> Result<ModerationAction, PrivacyError> {
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let report =
            report_for_update(&mut transaction, command.tenant_id, command.report_id).await?;
        if report.subject_id != command.subject_id
            || !matches!(
                report.state,
                ReportState::Submitted | ReportState::UnderReview
            )
        {
            return Err(PrivacyError::InvalidState);
        }
        let now = OffsetDateTime::now_utc();
        if command.effective_until.is_some_and(|until| until <= now) {
            return Err(PrivacyError::InvalidState);
        }
        let duration = command
            .effective_until
            .map_or(ModerationDuration::Permanent, ModerationDuration::Until);
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(authorization_action),
            report_resource(&report).with_moderation(ModerationAuthorizationContext {
                action_kind: Some(command.action_kind),
                policy_version: command.policy_version.clone(),
                reason_code: command.reason_code.clone(),
                duration: Some(duration),
            }),
        )?;
        let actor = ActorIdentity::from_principal(principal);
        let id = ModerationActionId::new();
        sqlx::query(
            "INSERT INTO public.privacy_moderation_actions (
                id, report_id, subject_id, actor_role, actor_kind, actor_subject_id,
                action_kind, reason_code, policy_version, effective_until, created_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id.as_uuid())
        .bind(command.report_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .bind(actor_role.as_str())
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .bind(command.action_kind.as_str())
        .bind(command.reason_code.as_str())
        .bind(command.policy_version.as_str())
        .bind(command.effective_until)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        let report_state = if command.action_kind == ModerationActionKind::ReportDismissed {
            "dismissed"
        } else {
            "actioned"
        };
        sqlx::query(
            "UPDATE public.privacy_moderation_reports
             SET state = $2, version = version + 1, updated_at = $3
             WHERE id = $1",
        )
        .bind(command.report_id.as_uuid())
        .bind(report_state)
        .bind(now)
        .execute(&mut *transaction)
        .await
        .map_err(map_database)?;
        append_audit(
            &self.audit,
            &mut transaction,
            "privacy.moderation.action_recorded",
            actor,
            LifecycleTarget::subject(command.tenant_id, command.subject_id),
            "privacy.moderation.action.record",
            "privacy_moderation_action",
            id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(ModerationAction {
            id,
            report_id: command.report_id,
            subject_id: command.subject_id,
            actor_role,
            actor,
            action_kind: command.action_kind,
            reason_code: command.reason_code.clone(),
            policy_version: command.policy_version.clone(),
            effective_until: command.effective_until,
            created_at: now,
        })
    }

    /// Submits an appeal under the affected-subject authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] unless the principal is the authorized affected
    /// human subject, [`PrivacyError::NotFound`] for an absent report or action,
    /// [`PrivacyError::InvalidState`] unless the report is actionable, and persistence or audit
    /// variants on commit failure.
    pub async fn submit_appeal(
        &self,
        principal: &Principal,
        command: &SubmitAppeal,
    ) -> Result<AppealRecord, PrivacyError> {
        require_human(principal)?;
        if principal.subject_id != command.subject_id {
            return Err(PrivacyError::Unauthorized);
        }
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let case = Self::load_appealable_case(&mut transaction, command, now).await?;
        self.authorize_appeal_submission(principal, command, &case)?;
        let appeal = self
            .persist_appeal_submission(&mut transaction, principal, command, now)
            .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(appeal)
    }

    async fn load_appealable_case(
        transaction: &mut Transaction<'_, Postgres>,
        command: &SubmitAppeal,
        now: OffsetDateTime,
    ) -> Result<AppealableCase, PrivacyError> {
        let report = report_for_update(transaction, command.tenant_id, command.report_id).await?;
        if report.subject_id != command.subject_id || report.state != ReportState::Actioned {
            return Err(PrivacyError::InvalidState);
        }
        let row = sqlx::query(
            "SELECT action_kind, effective_until, created_at
             FROM public.privacy_moderation_actions
             WHERE id = $1 AND report_id = $2 AND subject_id = $3",
        )
        .bind(command.action_id.as_uuid())
        .bind(command.report_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::NotFound)?;
        let action_kind = ModerationActionKind::parse(
            row.try_get::<&str, _>("action_kind")
                .map_err(|_| PrivacyError::CorruptState)?,
        )
        .ok_or(PrivacyError::CorruptState)?;
        let created_at = row
            .try_get::<OffsetDateTime, _>("created_at")
            .map_err(|_| PrivacyError::CorruptState)?;
        if created_at > now {
            return Err(PrivacyError::CorruptState);
        }
        let duration = row
            .try_get::<Option<OffsetDateTime>, _>("effective_until")
            .map_err(|_| PrivacyError::CorruptState)?
            .map_or(ModerationDuration::Permanent, ModerationDuration::Until);
        Ok(AppealableCase {
            report,
            action_kind,
            duration,
        })
    }

    fn authorize_appeal_submission(
        &self,
        principal: &Principal,
        command: &SubmitAppeal,
        case: &AppealableCase,
    ) -> Result<(), PrivacyError> {
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(
                ModerationAuthorizationAction::SubjectSubmitAppeal,
            ),
            report_resource(&case.report).with_moderation(ModerationAuthorizationContext {
                action_kind: Some(case.action_kind),
                policy_version: command.policy_version.clone(),
                reason_code: command.reason_code.clone(),
                duration: Some(case.duration),
            }),
        )?;
        Ok(())
    }

    async fn persist_appeal_submission(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        principal: &Principal,
        command: &SubmitAppeal,
        now: OffsetDateTime,
    ) -> Result<AppealRecord, PrivacyError> {
        let id = AppealId::new();
        sqlx::query(
            "INSERT INTO public.privacy_moderation_appeals (
                id, report_id, action_id, subject_id, reason_code, policy_version,
                state, version, submitted_at, decided_at
             ) VALUES ($1, $2, $3, $4, $5, $6, 'submitted', 1, $7, NULL)",
        )
        .bind(id.as_uuid())
        .bind(command.report_id.as_uuid())
        .bind(command.action_id.as_uuid())
        .bind(command.subject_id.as_uuid())
        .bind(command.reason_code.as_str())
        .bind(command.policy_version.as_str())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        sqlx::query(
            "UPDATE public.privacy_moderation_reports
             SET state = 'appealed', version = version + 1, updated_at = $2
             WHERE id = $1",
        )
        .bind(command.report_id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(map_database)?;
        append_audit(
            &self.audit,
            transaction,
            "privacy.moderation.appeal_submitted",
            ActorIdentity::from_principal(principal),
            LifecycleTarget::subject(command.tenant_id, command.subject_id),
            "privacy.moderation.appeal.submit",
            "privacy_moderation_appeal",
            id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        Ok(AppealRecord {
            id,
            report_id: command.report_id,
            action_id: command.action_id,
            subject_id: command.subject_id,
            reason_code: command.reason_code.clone(),
            policy_version: command.policy_version.clone(),
            state: AppealState::Submitted,
            version: 1,
            submitted_at: now,
            decided_at: None,
        })
    }

    /// Decides an appeal under the explicit moderator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied moderator,
    /// [`PrivacyError::InvalidState`] unless the tenant appeal is submitted, and persistence,
    /// conflict, or audit variants when the immutable decision cannot be committed.
    pub async fn decide_moderator_appeal(
        &self,
        principal: &Principal,
        command: &DecideAppeal,
    ) -> Result<AppealDecision, PrivacyError> {
        require_human(principal)?;
        self.decide_appeal(
            principal,
            command,
            ModerationActorRole::Moderator,
            ModerationAuthorizationAction::ModeratorDecideAppeal,
        )
        .await
    }

    /// Decides an appeal under the explicit administrator authorization path.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::Unauthorized`] for a non-human or denied administrator,
    /// [`PrivacyError::InvalidState`] unless the tenant appeal is submitted, and persistence,
    /// conflict, or audit variants when the immutable decision cannot be committed.
    pub async fn decide_administrator_appeal(
        &self,
        principal: &Principal,
        command: &DecideAppeal,
    ) -> Result<AppealDecision, PrivacyError> {
        require_human(principal)?;
        self.decide_appeal(
            principal,
            command,
            ModerationActorRole::Administrator,
            ModerationAuthorizationAction::AdministratorDecideAppeal,
        )
        .await
    }

    async fn decide_appeal(
        &self,
        principal: &Principal,
        command: &DecideAppeal,
        actor_role: ModerationActorRole,
        authorization_action: ModerationAuthorizationAction,
    ) -> Result<AppealDecision, PrivacyError> {
        let now = OffsetDateTime::now_utc();
        let mut connection = self.pool.acquire().await?;
        let mut transaction = connection.begin().await.map_err(map_database)?;
        let appeal = Self::load_decidable_appeal(&mut transaction, command, now).await?;
        self.authorize_appeal_decision(principal, command, authorization_action, &appeal)?;
        let decision = self
            .persist_appeal_decision(
                &mut transaction,
                principal,
                command,
                actor_role,
                &appeal,
                now,
            )
            .await?;
        transaction.commit().await.map_err(map_database)?;
        Ok(decision)
    }

    async fn load_decidable_appeal(
        transaction: &mut Transaction<'_, Postgres>,
        command: &DecideAppeal,
        now: OffsetDateTime,
    ) -> Result<DecidableAppeal, PrivacyError> {
        let row = sqlx::query(
            "SELECT appeal.report_id, appeal.subject_id, appeal.submitted_at,
                    report.reporter_subject_id, action.action_kind, action.effective_until
             FROM public.privacy_moderation_appeals AS appeal
             JOIN public.privacy_moderation_reports AS report ON report.id = appeal.report_id
             JOIN public.privacy_moderation_actions AS action ON action.id = appeal.action_id
             WHERE appeal.id = $1 AND report.tenant_id = $2 AND appeal.state = 'submitted'
             FOR UPDATE OF appeal, report",
        )
        .bind(command.appeal_id.as_uuid())
        .bind(command.tenant_id.as_uuid())
        .fetch_optional(&mut **transaction)
        .await
        .map_err(map_database)?
        .ok_or(PrivacyError::InvalidState)?;
        let submitted_at = row
            .try_get::<OffsetDateTime, _>("submitted_at")
            .map_err(|_| PrivacyError::CorruptState)?;
        if submitted_at > now {
            return Err(PrivacyError::CorruptState);
        }
        let action_kind = ModerationActionKind::parse(
            row.try_get::<&str, _>("action_kind")
                .map_err(|_| PrivacyError::CorruptState)?,
        )
        .ok_or(PrivacyError::CorruptState)?;
        let duration = row
            .try_get::<Option<OffsetDateTime>, _>("effective_until")
            .map_err(|_| PrivacyError::CorruptState)?
            .map_or(ModerationDuration::Permanent, ModerationDuration::Until);
        Ok(DecidableAppeal {
            report_id: ReportId::from_uuid(
                row.try_get::<Uuid, _>("report_id")
                    .map_err(|_| PrivacyError::CorruptState)?,
            )
            .map_err(|_| PrivacyError::CorruptState)?,
            subject_id: subject(&row, "subject_id")?,
            reporter_subject_id: subject(&row, "reporter_subject_id")?,
            action_kind,
            duration,
        })
    }

    fn authorize_appeal_decision(
        &self,
        principal: &Principal,
        command: &DecideAppeal,
        authorization_action: ModerationAuthorizationAction,
        appeal: &DecidableAppeal,
    ) -> Result<(), PrivacyError> {
        self.authorizer.authorize(
            principal,
            PrivacyAuthorizationAction::Moderation(authorization_action),
            PrivacyResource::subject(command.tenant_id, appeal.subject_id)
                .reported_by(appeal.reporter_subject_id)
                .with_moderation(ModerationAuthorizationContext {
                    action_kind: Some(appeal.action_kind),
                    policy_version: command.policy_version.clone(),
                    reason_code: command.reason_code.clone(),
                    duration: Some(appeal.duration),
                }),
        )?;
        Ok(())
    }

    async fn persist_appeal_decision(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        principal: &Principal,
        command: &DecideAppeal,
        actor_role: ModerationActorRole,
        appeal: &DecidableAppeal,
        now: OffsetDateTime,
    ) -> Result<AppealDecision, PrivacyError> {
        let actor = ActorIdentity::from_principal(principal);
        let id = AppealDecisionId::new();
        sqlx::query(
            "INSERT INTO public.privacy_moderation_appeal_decisions (
                id, appeal_id, actor_role, actor_kind, actor_subject_id, decision,
                reason_code, policy_version, decided_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id.as_uuid())
        .bind(command.appeal_id.as_uuid())
        .bind(actor_role.as_str())
        .bind(actor.kind_str())
        .bind(actor.subject_id().map(SubjectId::as_uuid))
        .bind(command.decision.as_str())
        .bind(command.reason_code.as_str())
        .bind(command.policy_version.as_str())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(|error| map_insert_error(&error))?;
        Self::transition_decided_appeal(transaction, command, appeal.report_id, now).await?;
        append_audit(
            &self.audit,
            transaction,
            "privacy.moderation.appeal_decided",
            actor,
            LifecycleTarget::subject(command.tenant_id, appeal.subject_id),
            "privacy.moderation.appeal.decide",
            "privacy_moderation_appeal",
            command.appeal_id.to_string(),
            AuditOutcome::Succeeded,
        )
        .await?;
        Ok(AppealDecision {
            id,
            appeal_id: command.appeal_id,
            actor_role,
            actor,
            decision: command.decision,
            reason_code: command.reason_code.clone(),
            policy_version: command.policy_version.clone(),
            decided_at: now,
        })
    }

    async fn transition_decided_appeal(
        transaction: &mut Transaction<'_, Postgres>,
        command: &DecideAppeal,
        report_id: ReportId,
        now: OffsetDateTime,
    ) -> Result<(), PrivacyError> {
        sqlx::query(
            "UPDATE public.privacy_moderation_appeals
             SET state = $2, version = version + 1, decided_at = $3
             WHERE id = $1",
        )
        .bind(command.appeal_id.as_uuid())
        .bind(command.decision.as_str())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(map_database)?;
        sqlx::query(
            "UPDATE public.privacy_moderation_reports
             SET state = 'resolved', version = version + 1, updated_at = $2
             WHERE id = $1",
        )
        .bind(report_id.as_uuid())
        .bind(now)
        .execute(&mut **transaction)
        .await
        .map_err(map_database)?;
        Ok(())
    }
}
fn resumed_request_from_row(row: &PgRow) -> Result<ResumedRequest, PrivacyError> {
    let state = LifecycleState::parse(
        row.try_get::<&str, _>("state")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    Ok(ResumedRequest {
        id: lifecycle_id(row, "id")?,
        target: target_from_row(row)?,
        fence: nonnegative_u64(row, "fence")?,
        state,
        failure_code: row
            .try_get::<Option<String>, _>("last_failure_code")
            .map_err(|_| PrivacyError::CorruptState)?,
    })
}

fn resume_audit_facts(state: LifecycleState) -> (&'static str, &'static str, AuditOutcome) {
    if state == LifecycleState::DeadLetter {
        (
            "privacy.lifecycle.dead_lettered",
            "privacy.lifecycle.dead_letter",
            AuditOutcome::Failed,
        )
    } else {
        (
            "privacy.lifecycle.resumed_after_legal_hold",
            "privacy.lifecycle.resume",
            AuditOutcome::Succeeded,
        )
    }
}

fn stored_consent_grant_from_row(row: &PgRow) -> Result<StoredConsentGrant, PrivacyError> {
    let document_kind = parse_consent_document_kind(
        row.try_get::<&str, _>("document_kind")
            .map_err(|_| PrivacyError::CorruptState)?,
    )?;
    let document_version = PolicyVersion::new(
        row.try_get::<String, _>("document_version")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)?;
    let source = ConsentSource::parse(
        row.try_get::<&str, _>("source")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    let evidence_format = ConsentEvidenceFormat::parse(
        row.try_get::<&str, _>("evidence_format")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    Ok(StoredConsentGrant {
        document_kind,
        document_version,
        source,
        evidence_format,
        withdrawal_permitted: row
            .try_get("withdrawal_permitted")
            .map_err(|_| PrivacyError::CorruptState)?,
        accepted_at: row
            .try_get("accepted_at")
            .map_err(|_| PrivacyError::CorruptState)?,
    })
}

fn parse_consent_document_kind(value: &str) -> Result<ConsentDocumentKind, PrivacyError> {
    ConsentDocumentKind::parse(value).ok_or(PrivacyError::CorruptState)
}

fn privacy_resource(target: LifecycleTarget) -> PrivacyResource {
    match target.subject_id {
        Some(subject_id) => PrivacyResource::subject(target.tenant_id, subject_id),
        None => PrivacyResource::tenant(target.tenant_id),
    }
}
fn export_manifest_entry(row: &PgRow) -> Result<ExportManifestEntry, PrivacyError> {
    let adapter_name = AdapterName::new(
        row.try_get::<String, _>("adapter_name")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)?;
    let category = InventoryCategory::parse(
        row.try_get::<&str, _>("category")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    let minimum_revision = row
        .try_get::<i32, _>("adapter_revision")
        .ok()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(PrivacyError::CorruptState)?;
    let effect = row
        .try_get::<&str, _>("evidence_effect")
        .map_err(|_| PrivacyError::CorruptState)?;
    let artifact_id = row
        .try_get::<Option<Uuid>, _>("artifact_id")
        .map_err(|_| PrivacyError::CorruptState)?
        .map(ArtifactId::from_uuid)
        .transpose()
        .map_err(|_| PrivacyError::CorruptState)?;
    let affected_records = nonnegative_u64(row, "affected_records")?;
    match effect {
        "no_data" if artifact_id.is_none() && affected_records == 0 => {}
        "exported" if artifact_id.is_some() => {}
        _ => return Err(PrivacyError::CorruptState),
    }
    let digest = row
        .try_get::<Vec<u8>, _>("evidence_sha256")
        .map_err(|_| PrivacyError::CorruptState)?;
    let digest: [u8; 32] = digest.try_into().map_err(|_| PrivacyError::CorruptState)?;
    Ok(ExportManifestEntry {
        adapter_name,
        category,
        minimum_revision,
        artifact_id,
        evidence_digest: EvidenceDigest::from_sha256(digest),
        affected_records,
        reconciled_at: row
            .try_get("reconciled_at")
            .map_err(|_| PrivacyError::CorruptState)?,
    })
}

fn report_resource(report: &ModerationReport) -> PrivacyResource {
    PrivacyResource::subject(report.tenant_id, report.subject_id)
        .reported_by(report.reporter_subject_id)
        .with_moderation(ModerationAuthorizationContext {
            action_kind: None,
            policy_version: report.policy_version.clone(),
            reason_code: report.reason_code.clone(),
            duration: None,
        })
}

fn require_human(principal: &Principal) -> Result<(), PrivacyError> {
    if principal.kind == PrincipalKind::User {
        Ok(())
    } else {
        Err(PrivacyError::Unauthorized)
    }
}

fn require_service_account(principal: &Principal) -> Result<(), PrivacyError> {
    if principal.kind == PrincipalKind::ServiceAccount {
        Ok(())
    } else {
        Err(PrivacyError::Unauthorized)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "audit events intentionally require all invariant-bearing fields"
)]
async fn append_audit(
    audit: &PostgresAuditSink,
    transaction: &mut Transaction<'_, Postgres>,
    event_type: &'static str,
    actor: ActorIdentity,
    target: LifecycleTarget,
    action: &'static str,
    resource_kind: &'static str,
    resource_id: String,
    outcome: AuditOutcome,
) -> Result<(), PrivacyError> {
    let event_type = AuditEventType::new(event_type).map_err(|_| PrivacyError::CorruptState)?;
    let action = Action::new(action).map_err(|_| PrivacyError::CorruptState)?;
    let resource_kind = ResourceKind::new(resource_kind).map_err(|_| PrivacyError::CorruptState)?;
    let resource_id = AuditResourceId::new(resource_id).map_err(|_| PrivacyError::CorruptState)?;
    let mut builder = AuditEvent::builder(
        event_type,
        OffsetDateTime::now_utc(),
        actor.audit_actor(),
        AuditScope::Tenant(target.tenant_id),
        action,
        resource_kind,
        outcome,
    )
    .resource_id(resource_id);
    if let Some(subject_id) = target.subject_id {
        builder = builder.subject_id(subject_id);
    }
    audit
        .append_with(transaction, &builder.build())
        .await
        .map(|_| ())
        .map_err(map_audit)
}

#[expect(
    clippy::too_many_arguments,
    reason = "transition history intentionally stores every state-machine dimension"
)]
async fn insert_transition(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: LifecycleRequestId,
    from: Option<LifecycleState>,
    to: LifecycleState,
    fence: u64,
    actor_kind: &str,
    failure_code: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), PrivacyError> {
    sqlx::query(
        "INSERT INTO public.privacy_lifecycle_transitions (
            id, request_id, from_state, to_state, fence, actor_kind, failure_code, occurred_at
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(Uuid::now_v7())
    .bind(request_id.as_uuid())
    .bind(from.map(LifecycleState::as_str))
    .bind(to.as_str())
    .bind(i64::try_from(fence).map_err(|_| PrivacyError::NumericBound)?)
    .bind(actor_kind)
    .bind(failure_code)
    .bind(now)
    .execute(&mut **transaction)
    .await
    .map_err(map_database)?;
    Ok(())
}

async fn report_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    tenant_id: TenantId,
    report_id: ReportId,
) -> Result<ModerationReport, PrivacyError> {
    let row = sqlx::query(
        "SELECT * FROM public.privacy_moderation_reports
         WHERE id = $1 AND tenant_id = $2
         FOR UPDATE",
    )
    .bind(report_id.as_uuid())
    .bind(tenant_id.as_uuid())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(map_database)?
    .ok_or(PrivacyError::NotFound)?;
    moderation_report_from_row(&row)
}

fn moderation_report_from_row(row: &PgRow) -> Result<ModerationReport, PrivacyError> {
    let id = ReportId::from_uuid(
        row.try_get::<Uuid, _>("id")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)?;
    let tenant_id = tenant(row, "tenant_id")?;
    let reporter_subject_id = subject(row, "reporter_subject_id")?;
    let subject_id = subject(row, "subject_id")?;
    let reason_code = ReasonCode::new(
        row.try_get::<String, _>("reason_code")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)?;
    let policy_version = PolicyVersion::new(
        row.try_get::<String, _>("policy_version")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)?;
    let state = ReportState::parse(
        row.try_get::<&str, _>("state")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    Ok(ModerationReport {
        id,
        tenant_id,
        reporter_subject_id,
        subject_id,
        reason_code,
        policy_version,
        state,
        version: positive_u64(row, "version")?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| PrivacyError::CorruptState)?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|_| PrivacyError::CorruptState)?,
    })
}

fn lifecycle_from_row(row: &PgRow) -> Result<LifecycleRequest, PrivacyError> {
    let operation = LifecycleKind::parse(
        row.try_get::<&str, _>("operation")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    let state = LifecycleState::parse(
        row.try_get::<&str, _>("state")
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .ok_or(PrivacyError::CorruptState)?;
    let hold_uuid = row
        .try_get::<Option<Uuid>, _>("legal_hold_id")
        .map_err(|_| PrivacyError::CorruptState)?;
    let legal_hold_id = hold_uuid
        .map(LegalHoldId::from_uuid)
        .transpose()
        .map_err(|_| PrivacyError::CorruptState)?;
    let last_failure_code = row
        .try_get::<Option<&str>, _>("last_failure_code")
        .map_err(|_| PrivacyError::CorruptState)?
        .map(|value| LifecycleFailureCode::parse(value).ok_or(PrivacyError::CorruptState))
        .transpose()?;
    Ok(LifecycleRequest {
        id: lifecycle_id(row, "id")?,
        target: target_from_row(row)?,
        operation,
        retention_before: row
            .try_get("retention_before")
            .map_err(|_| PrivacyError::CorruptState)?,
        legal_hold_id,
        state,
        attempt_count: nonnegative_u16(row, "attempt_count")?,
        max_attempts: positive_u16(row, "max_attempts")?,
        fence: nonnegative_u64(row, "fence")?,
        last_failure_code,
        inventory_count: positive_u16(row, "inventory_count")?,
        created_at: row
            .try_get("created_at")
            .map_err(|_| PrivacyError::CorruptState)?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|_| PrivacyError::CorruptState)?,
    })
}

fn target_from_row(row: &PgRow) -> Result<LifecycleTarget, PrivacyError> {
    Ok(LifecycleTarget {
        tenant_id: tenant(row, "tenant_id")?,
        subject_id: optional_subject(row, "subject_id")?,
    })
}

fn tenant(row: &PgRow, column: &str) -> Result<TenantId, PrivacyError> {
    TenantId::from_uuid(
        row.try_get::<Uuid, _>(column)
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)
}

fn subject(row: &PgRow, column: &str) -> Result<SubjectId, PrivacyError> {
    SubjectId::from_uuid(
        row.try_get::<Uuid, _>(column)
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)
}

fn optional_subject(row: &PgRow, column: &str) -> Result<Option<SubjectId>, PrivacyError> {
    row.try_get::<Option<Uuid>, _>(column)
        .map_err(|_| PrivacyError::CorruptState)?
        .map(SubjectId::from_uuid)
        .transpose()
        .map_err(|_| PrivacyError::CorruptState)
}

fn lifecycle_id(row: &PgRow, column: &str) -> Result<LifecycleRequestId, PrivacyError> {
    LifecycleRequestId::from_uuid(
        row.try_get::<Uuid, _>(column)
            .map_err(|_| PrivacyError::CorruptState)?,
    )
    .map_err(|_| PrivacyError::CorruptState)
}

fn positive_u16(row: &PgRow, column: &str) -> Result<u16, PrivacyError> {
    let value = row
        .try_get::<i16, _>(column)
        .map_err(|_| PrivacyError::CorruptState)?;
    u16::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(PrivacyError::CorruptState)
}

fn nonnegative_u16(row: &PgRow, column: &str) -> Result<u16, PrivacyError> {
    let value = row
        .try_get::<i16, _>(column)
        .map_err(|_| PrivacyError::CorruptState)?;
    u16::try_from(value).map_err(|_| PrivacyError::CorruptState)
}

fn positive_u64(row: &PgRow, column: &str) -> Result<u64, PrivacyError> {
    nonnegative_u64(row, column).and_then(|value| {
        (value > 0)
            .then_some(value)
            .ok_or(PrivacyError::CorruptState)
    })
}

fn nonnegative_u64(row: &PgRow, column: &str) -> Result<u64, PrivacyError> {
    let value = row
        .try_get::<i64, _>(column)
        .map_err(|_| PrivacyError::CorruptState)?;
    u64::try_from(value).map_err(|_| PrivacyError::CorruptState)
}

fn add_std_duration(
    instant: OffsetDateTime,
    duration: std::time::Duration,
) -> Result<OffsetDateTime, PrivacyError> {
    let duration = time::Duration::try_from(duration).map_err(|_| PrivacyError::NumericBound)?;
    instant
        .checked_add(duration)
        .ok_or(PrivacyError::NumericBound)
}

fn map_database(_: sqlx::Error) -> PrivacyError {
    PrivacyError::Database
}

fn map_insert_error(error: &sqlx::Error) -> PrivacyError {
    match error
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .as_deref()
    {
        Some("23505") => PrivacyError::Conflict,
        Some("23503" | "23514" | "22001") => PrivacyError::InvalidState,
        _ => PrivacyError::Database,
    }
}

fn map_audit(_: AuditSinkError) -> PrivacyError {
    PrivacyError::Audit
}
