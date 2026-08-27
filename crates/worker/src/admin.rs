use std::sync::Arc;

use omnius_admin::{
    AdminAuthorityResolver, AdminConfig, AdminLineage, AdminPermission, admin_policy_rules,
};
use omnius_audit::{
    AuditActor, AuditAppendOutcome, AuditEvent, AuditMetadata, AuditMetadataField, AuditOutcome,
    AuditReasonCode, AuditResourceId, AuditScope, PostgresAuditSink, SecurityEventName,
};
use omnius_auth_core::{AssuranceLevel, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::{AuthorizationProvider, AuthorizationService, Decision, Resource};
use omnius_core::Clock;
use omnius_postgres::PostgresPool;
use sha2::{Digest as _, Sha256};
use sqlx::Connection as _;
use thiserror::Error;
use time::OffsetDateTime;

const HEX: &[u8; 16] = b"0123456789abcdef";

use crate::{
    BackendId, ControlStatus, DeadRecord, ReplayReceipt, WorkerDiagnostics, WorkerOperationError,
    WorkerStatus,
};

/// Protected worker administration construction failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerAdminBuildError {
    /// Administration configuration was invalid.
    #[error("worker administration configuration is invalid")]
    InvalidConfig,
    /// A static permission identifier or policy rule was invalid.
    #[error("worker administration policy is invalid")]
    InvalidPolicy,
}

/// Stable protected worker administration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkerAdminError {
    /// Protected administration is disabled.
    #[error("worker administration is disabled")]
    Disabled,
    /// The caller was not a human administrator.
    #[error("worker administration requires a human administrator")]
    HumanAdministratorRequired,
    /// The caller did not authenticate at AAL2.
    #[error("worker administration requires AAL2")]
    InsufficientAssurance,
    /// The authentication time was in the future or outside the bounded recency window.
    #[error("worker administrator authentication is not recent")]
    AuthenticationNotRecent,
    /// Current authoritative grants could not be loaded.
    #[error("worker administrator authority is unavailable")]
    AuthorityUnavailable,
    /// Policy denied the dedicated worker permission.
    #[error("worker administration is not authorized")]
    AuthorizationDenied,
    /// The request or provider-native record identity was invalid.
    #[error("worker administration request is invalid")]
    InvalidRequest,
    /// A requested logical provider or record was not found.
    #[error("worker administration target was not found")]
    NotFound,
    /// A revision-fenced control mutation conflicted.
    #[error("worker administration control revision conflicted")]
    Conflict,
    /// Replay requires the selected provider to be paused.
    #[error("worker administration replay requires paused leasing")]
    NotPaused,
    /// A selected provider could not complete its bounded operation.
    #[error("worker administration operation is unavailable")]
    OperationUnavailable,
    /// A required audit row could not be durably committed.
    #[error("worker administration audit is unavailable")]
    AuditUnavailable,
    /// The provider effect completed but its completion audit could not be confirmed.
    #[error("worker administration outcome is uncertain")]
    OutcomeUncertain,
    /// A static internal identifier violated its compile-time contract.
    #[error("worker administration internal contract failed")]
    InternalContract,
}

#[derive(Clone, Copy)]
struct AuditAdministrator {
    kind: PrincipalKind,
    subject_id: SubjectId,
}

impl From<&Principal> for AuditAdministrator {
    fn from(principal: &Principal) -> Self {
        Self {
            kind: principal.kind,
            subject_id: principal.subject_id,
        }
    }
}

#[derive(Clone)]
struct AuditWriter {
    clock: Arc<dyn Clock>,
    sink: PostgresAuditSink,
    pool: PostgresPool,
}

/// AAL2 protected, authorization-backed and durably audited worker operations.
pub struct ProtectedWorkerAdmin<P, R> {
    authorization: AuthorizationService<P>,
    authority: R,
    diagnostics: WorkerDiagnostics,
    clock: Arc<dyn Clock>,
    audit: PostgresAuditSink,
    audit_pool: PostgresPool,
    config: AdminConfig,
    recent_authentication_window: time::Duration,
}

impl<P, R> std::fmt::Debug for ProtectedWorkerAdmin<P, R> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtectedWorkerAdmin")
            .field("diagnostics", &self.diagnostics)
            .field("admin_enabled", &self.config.enabled)
            .finish_non_exhaustive()
    }
}

impl<P, R> ProtectedWorkerAdmin<P, R>
where
    P: AuthorizationProvider,
    R: AdminAuthorityResolver + Send + Sync,
{
    /// Composes protected operations from the shared administration policy and audit sink.
    ///
    /// `admin_policy_rules()` must be included in the selected authorization provider's matrix.
    /// Construction validates the same bounded administration windows used by the core admin
    /// service and verifies the worker permission declarations.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminBuildError`] for unsafe configuration or invalid static policy.
    pub fn new(
        provider: P,
        authority: R,
        diagnostics: WorkerDiagnostics,
        clock: Arc<dyn Clock>,
        audit: PostgresAuditSink,
        audit_pool: PostgresPool,
        config: AdminConfig,
    ) -> Result<Self, WorkerAdminBuildError> {
        config
            .validate()
            .map_err(|_| WorkerAdminBuildError::InvalidConfig)?;
        let rules = admin_policy_rules().map_err(|_| WorkerAdminBuildError::InvalidPolicy)?;
        if rules.is_empty() {
            return Err(WorkerAdminBuildError::InvalidPolicy);
        }
        for permission in [
            AdminPermission::WorkerStatus,
            AdminPermission::WorkerDeadList,
            AdminPermission::WorkerPause,
            AdminPermission::WorkerResume,
            AdminPermission::WorkerReplay,
        ] {
            permission
                .action()
                .and_then(|_| permission.capability())
                .and_then(|_| permission.resource_kind())
                .map_err(|_| WorkerAdminBuildError::InvalidPolicy)?;
        }
        let recent_authentication_window =
            time::Duration::try_from(config.recent_authentication_window)
                .map_err(|_| WorkerAdminBuildError::InvalidConfig)?;
        Ok(Self {
            authorization: AuthorizationService::new(provider),
            authority,
            diagnostics,
            clock,
            audit,
            audit_pool,
            config,
            recent_authentication_window,
        })
    }

    /// Reads the full provider-explicit worker status after authorization and durable audit.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminError`] when authorization, audit, or a selected provider fails.
    pub async fn status(
        &self,
        administrator: &Principal,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<WorkerStatus, WorkerAdminError> {
        self.authorize_and_audit(
            administrator,
            AdminPermission::WorkerStatus,
            "worker",
            reason.clone(),
            lineage,
        )
        .await?;
        let diagnostics = self.diagnostics.clone();
        let audit = self.audit_writer();
        let audit_administrator = AuditAdministrator::from(administrator);
        tokio::spawn(async move {
            let result = diagnostics.status().await.map_err(map_operation_error);
            let audit_result = audit
                .finish(
                    audit_administrator,
                    AdminPermission::WorkerStatus,
                    "worker",
                    reason,
                    lineage,
                    result.is_ok(),
                )
                .await;
            finish_owned_operation(result, audit_result)
        })
        .await
        .map_err(|_| WorkerAdminError::OutcomeUncertain)?
    }

    /// Reads a bounded redacted dead-record list for one explicit provider.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminError`] for denied, unaudited, invalid, or unavailable operations.
    pub async fn dead_records(
        &self,
        administrator: &Principal,
        backend_id: &BackendId,
        limit: u16,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<Vec<DeadRecord>, WorkerAdminError> {
        self.authorize_and_audit(
            administrator,
            AdminPermission::WorkerDeadList,
            backend_id.as_str(),
            reason.clone(),
            lineage,
        )
        .await?;
        let diagnostics = self.diagnostics.clone();
        let backend_id = backend_id.clone();
        let audit = self.audit_writer();
        let audit_administrator = AuditAdministrator::from(administrator);
        tokio::spawn(async move {
            let result = diagnostics
                .dead_records(&backend_id, limit)
                .await
                .map_err(map_operation_error);
            let audit_result = audit
                .finish(
                    audit_administrator,
                    AdminPermission::WorkerDeadList,
                    backend_id.as_str(),
                    reason,
                    lineage,
                    result.is_ok(),
                )
                .await;
            finish_owned_operation(result, audit_result)
        })
        .await
        .map_err(|_| WorkerAdminError::OutcomeUncertain)?
    }

    /// Revision-fences a provider-native leasing pause.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminError`] for denied, unaudited, conflicting, or unavailable operations.
    pub async fn pause(
        &self,
        administrator: &Principal,
        backend_id: &BackendId,
        expected_revision: u64,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<ControlStatus, WorkerAdminError> {
        self.set_paused(
            administrator,
            backend_id,
            true,
            expected_revision,
            AdminPermission::WorkerPause,
            reason,
            lineage,
        )
        .await
    }

    /// Revision-fences a provider-native leasing resume.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminError`] for denied, unaudited, conflicting, or unavailable operations.
    pub async fn resume(
        &self,
        administrator: &Principal,
        backend_id: &BackendId,
        expected_revision: u64,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<ControlStatus, WorkerAdminError> {
        self.set_paused(
            administrator,
            backend_id,
            false,
            expected_revision,
            AdminPermission::WorkerResume,
            reason,
            lineage,
        )
        .await
    }

    /// Replays one exact provider-native dead record with explicit identity semantics.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerAdminError`] for denied, unaudited, invalid, conflicting, or unavailable
    /// operations.
    pub async fn replay(
        &self,
        administrator: &Principal,
        backend_id: &BackendId,
        record_id: &str,
        expected_revision: u64,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<ReplayReceipt, WorkerAdminError> {
        let resource_id = replay_resource_id(backend_id, record_id)?;
        self.authorize_and_audit(
            administrator,
            AdminPermission::WorkerReplay,
            &resource_id,
            reason.clone(),
            lineage,
        )
        .await?;
        let diagnostics = self.diagnostics.clone();
        let backend_id = backend_id.clone();
        let record_id = record_id.to_owned();
        let audit = self.audit_writer();
        let audit_administrator = AuditAdministrator::from(administrator);
        tokio::spawn(async move {
            let result = diagnostics
                .replay_dead(&backend_id, &record_id, expected_revision)
                .await
                .map_err(map_operation_error);
            let audit_result = audit
                .finish(
                    audit_administrator,
                    AdminPermission::WorkerReplay,
                    &resource_id,
                    reason,
                    lineage,
                    result.is_ok(),
                )
                .await;
            finish_owned_operation(result, audit_result)
        })
        .await
        .map_err(|_| WorkerAdminError::OutcomeUncertain)?
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "protected mutation keeps provider target, fence, reason, and lineage explicit"
    )]
    async fn set_paused(
        &self,
        administrator: &Principal,
        backend_id: &BackendId,
        paused: bool,
        expected_revision: u64,
        permission: AdminPermission,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<ControlStatus, WorkerAdminError> {
        self.authorize_and_audit(
            administrator,
            permission,
            backend_id.as_str(),
            reason.clone(),
            lineage,
        )
        .await?;
        let diagnostics = self.diagnostics.clone();
        let backend_id = backend_id.clone();
        let audit = self.audit_writer();
        let audit_administrator = AuditAdministrator::from(administrator);
        tokio::spawn(async move {
            let result = diagnostics
                .set_paused(&backend_id, paused, expected_revision)
                .await
                .map_err(map_operation_error);
            let audit_result = audit
                .finish(
                    audit_administrator,
                    permission,
                    backend_id.as_str(),
                    reason,
                    lineage,
                    result.is_ok(),
                )
                .await;
            finish_owned_operation(result, audit_result)
        })
        .await
        .map_err(|_| WorkerAdminError::OutcomeUncertain)?
    }

    async fn authorize_and_audit(
        &self,
        administrator: &Principal,
        permission: AdminPermission,
        resource_id: &str,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<(), WorkerAdminError> {
        if !self.config.enabled {
            return Err(WorkerAdminError::Disabled);
        }
        let now = self.clock.now_utc();
        if let Err(error) = self.authorize(administrator, permission, now) {
            self.commit_audit(
                administrator,
                permission,
                resource_id,
                AuditOutcome::Denied,
                denial_reason(error)?,
                lineage,
                now,
                SecurityEventName::WorkerOperationCompleted,
            )
            .await?;
            return Err(error);
        }
        self.commit_audit(
            administrator,
            permission,
            resource_id,
            AuditOutcome::Succeeded,
            reason,
            lineage,
            now,
            SecurityEventName::WorkerOperationAuthorized,
        )
        .await
    }

    fn authorize(
        &self,
        administrator: &Principal,
        permission: AdminPermission,
        now: OffsetDateTime,
    ) -> Result<(), WorkerAdminError> {
        if administrator.kind != PrincipalKind::User {
            return Err(WorkerAdminError::HumanAdministratorRequired);
        }
        if administrator.assurance < AssuranceLevel::Aal2 {
            return Err(WorkerAdminError::InsufficientAssurance);
        }
        if administrator.authenticated_at > now
            || now - administrator.authenticated_at > self.recent_authentication_window
        {
            return Err(WorkerAdminError::AuthenticationNotRecent);
        }
        let context = self
            .authority
            .resolve(administrator)
            .ok_or(WorkerAdminError::AuthorityUnavailable)?;
        let action = permission
            .action()
            .map_err(|_| WorkerAdminError::InternalContract)?;
        let kind = permission
            .resource_kind()
            .map_err(|_| WorkerAdminError::InternalContract)?;
        match self
            .authorization
            .authorize(administrator, &action, &Resource::new(kind), &context)
        {
            Decision::Allow => Ok(()),
            Decision::Deny(_) => Err(WorkerAdminError::AuthorizationDenied),
        }
    }

    fn audit_writer(&self) -> AuditWriter {
        AuditWriter {
            clock: Arc::clone(&self.clock),
            sink: self.audit,
            pool: self.audit_pool.clone(),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction keeps every security field and operation phase explicit"
    )]
    async fn commit_audit(
        &self,
        administrator: &Principal,
        permission: AdminPermission,
        resource_id: &str,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        event_name: SecurityEventName,
    ) -> Result<(), WorkerAdminError> {
        self.audit_writer()
            .commit(
                AuditAdministrator::from(administrator),
                permission,
                resource_id,
                outcome,
                reason,
                lineage,
                occurred_at,
                event_name,
            )
            .await
    }
}

impl AuditWriter {
    async fn finish(
        &self,
        administrator: AuditAdministrator,
        permission: AdminPermission,
        resource_id: &str,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        succeeded: bool,
    ) -> Result<(), WorkerAdminError> {
        self.commit(
            administrator,
            permission,
            resource_id,
            if succeeded {
                AuditOutcome::Succeeded
            } else {
                AuditOutcome::Failed
            },
            reason,
            lineage,
            self.clock.now_utc(),
            SecurityEventName::WorkerOperationCompleted,
        )
        .await
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction keeps every security field and operation phase explicit"
    )]
    async fn commit(
        &self,
        administrator: AuditAdministrator,
        permission: AdminPermission,
        resource_id: &str,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        event_name: SecurityEventName,
    ) -> Result<(), WorkerAdminError> {
        let action = permission
            .action()
            .map_err(|_| WorkerAdminError::InternalContract)?;
        let resource_kind = permission
            .resource_kind()
            .map_err(|_| WorkerAdminError::InternalContract)?;
        let resource_id =
            AuditResourceId::new(resource_id).map_err(|_| WorkerAdminError::InternalContract)?;
        let actor = match administrator.kind {
            PrincipalKind::User => AuditActor::User(administrator.subject_id),
            PrincipalKind::ServiceAccount => AuditActor::ServiceAccount(administrator.subject_id),
        };
        let mut event = AuditEvent::builder(
            event_name,
            occurred_at,
            actor,
            AuditScope::Global,
            action,
            resource_kind,
            outcome,
        )
        .resource_id(resource_id)
        .request_id(lineage.request_id)
        .correlation_id(lineage.correlation_id)
        .reason(reason)
        .metadata(
            AuditMetadata::try_from_fields([AuditMetadataField::Interactive(matches!(
                administrator.kind,
                PrincipalKind::User
            ))])
            .map_err(|_| WorkerAdminError::InternalContract)?,
        );
        if let Some(causation_id) = lineage.causation_id {
            event = event.causation_id(causation_id);
        }
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|_| WorkerAdminError::AuditUnavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| WorkerAdminError::AuditUnavailable)?;
        match self
            .sink
            .append_with(&mut transaction, &event.build())
            .await
            .map_err(|_| WorkerAdminError::AuditUnavailable)?
        {
            AuditAppendOutcome::Appended => {}
            AuditAppendOutcome::Disabled => return Err(WorkerAdminError::AuditUnavailable),
        }
        transaction
            .commit()
            .await
            .map_err(|_| WorkerAdminError::AuditUnavailable)
    }
}

fn denial_reason(error: WorkerAdminError) -> Result<AuditReasonCode, WorkerAdminError> {
    let reason = match error {
        WorkerAdminError::HumanAdministratorRequired => "human_administrator_required",
        WorkerAdminError::InsufficientAssurance => "insufficient_assurance",
        WorkerAdminError::AuthenticationNotRecent => "authentication_not_recent",
        WorkerAdminError::AuthorityUnavailable => "authority_unavailable",
        WorkerAdminError::AuthorizationDenied => "authorization_denied",
        _ => "worker_admin_denied",
    };
    AuditReasonCode::new(reason).map_err(|_| WorkerAdminError::InternalContract)
}

fn map_operation_error(error: WorkerOperationError) -> WorkerAdminError {
    match error {
        WorkerOperationError::NotFound => WorkerAdminError::NotFound,
        WorkerOperationError::InvalidRequest => WorkerAdminError::InvalidRequest,
        WorkerOperationError::Conflict => WorkerAdminError::Conflict,
        WorkerOperationError::NotPaused => WorkerAdminError::NotPaused,
        WorkerOperationError::Unavailable => WorkerAdminError::OperationUnavailable,
    }
}

fn finish_owned_operation<T>(
    result: Result<T, WorkerAdminError>,
    audit_result: Result<(), WorkerAdminError>,
) -> Result<T, WorkerAdminError> {
    match (result, audit_result) {
        (Ok(value), Ok(())) => Ok(value),
        (Ok(_), Err(_)) => Err(WorkerAdminError::OutcomeUncertain),
        (Err(error), Ok(())) => Err(error),
        (Err(_), Err(audit_error)) => Err(audit_error),
    }
}

fn replay_resource_id(backend_id: &BackendId, record_id: &str) -> Result<String, WorkerAdminError> {
    let valid = if backend_id.as_str().starts_with("redis:") {
        !record_id.is_empty()
            && record_id.len() <= 64
            && record_id.bytes().all(|byte| byte.is_ascii_alphanumeric())
    } else if backend_id.as_str().starts_with("pgmq:") {
        record_id
            .parse::<i64>()
            .is_ok_and(|value| value > 0 && value.to_string() == record_id)
    } else {
        false
    };
    if !valid {
        return Err(WorkerAdminError::InvalidRequest);
    }
    let mut digest = Sha256::new();
    digest.update(backend_id.as_str().as_bytes());
    digest.update([0]);
    digest.update(record_id.as_bytes());
    let bytes = digest.finalize();
    let mut resource_id = String::with_capacity(14 + bytes.len() * 2);
    resource_id.push_str("worker_replay:");
    for byte in bytes {
        resource_id.push(char::from(HEX[usize::from(byte >> 4)]));
        resource_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(resource_id)
}
