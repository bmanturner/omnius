//! Fail-closed protected-administration policy and audited impersonation contexts.
//!
//! This crate is transport-independent. HTTP deployments must mount callers on a separately
//! protected listener and must not expose a generic command or SQL execution endpoint.

use std::{sync::Arc, time::Duration};

use metrics::counter;
use rsk_audit::{
    AuditActor, AuditAppendOutcome, AuditEvent, AuditMetadata, AuditMetadataField, AuditOutcome,
    AuditReasonCode, AuditResourceId, AuditScope, AuditSinkError, PostgresAuditSink,
    SecurityEventName,
};
use rsk_auth_core::{AssuranceLevel, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationService, Capability,
    Decision, DenyReason, Grant, IdentifierError, PolicyError, PolicyRule, Resource, ResourceKind,
};
use rsk_core::{CausationId, Clock, CorrelationId, RequestId};
use rsk_postgres::{PostgresPool, RetryableSqlState, RetryableTransactionError};
use serde::Deserialize;
use sqlx::{Connection as _, PgConnection};
use thiserror::Error;
use time::OffsetDateTime;

const MAX_RECENT_AUTHENTICATION_WINDOW: Duration = Duration::from_hours(1);
const MAX_IMPERSONATION_LIFETIME: Duration = Duration::from_hours(1);

/// Strict runtime controls for the protected administration module.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    /// Whether protected administration is available.
    pub enabled: bool,
    /// Maximum age of the administrator's high-assurance authentication.
    #[serde(with = "humantime_serde")]
    pub recent_authentication_window: Duration,
    /// Maximum lifetime of one impersonation context.
    #[serde(with = "humantime_serde")]
    pub maximum_impersonation_lifetime: Duration,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            recent_authentication_window: Duration::from_mins(5),
            maximum_impersonation_lifetime: Duration::from_mins(15),
        }
    }
}

impl AdminConfig {
    /// Validates non-zero, short administration windows.
    ///
    /// # Errors
    ///
    /// Returns [`AdminConfigError`] for zero or greater-than-one-hour windows.
    pub fn validate(self) -> Result<(), AdminConfigError> {
        if self.recent_authentication_window.is_zero()
            || self.recent_authentication_window > MAX_RECENT_AUTHENTICATION_WINDOW
        {
            return Err(AdminConfigError::RecentAuthenticationWindow);
        }
        if self.maximum_impersonation_lifetime.is_zero()
            || self.maximum_impersonation_lifetime > MAX_IMPERSONATION_LIFETIME
        {
            return Err(AdminConfigError::ImpersonationLifetime);
        }
        Ok(())
    }
}

/// Protected administration configuration was unsafe.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminConfigError {
    /// The recency window was zero or exceeded one hour.
    #[error("admin recent-authentication window must be between zero and one hour")]
    RecentAuthenticationWindow,
    /// The impersonation lifetime was zero or exceeded one hour.
    #[error("admin impersonation lifetime must be between zero and one hour")]
    ImpersonationLifetime,
}

/// Dedicated protected-administration permissions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AdminPermission {
    /// Look up a user.
    UserLookup,
    /// Look up a tenant.
    TenantLookup,
    /// Suspend a user.
    UserSuspension,
    /// Suspend a tenant.
    TenantSuspension,
    /// Execute a predefined, typed repair.
    SafeRepair,
    /// Apply a controlled feature override.
    FeatureOverride,
    /// Read worker, provider, scheduler, outbox, and event-consumer status.
    WorkerStatus,
    /// Read a bounded redacted worker dead-record list.
    WorkerDeadList,
    /// Pause worker leasing for one explicit provider.
    WorkerPause,
    /// Resume worker leasing for one explicit provider.
    WorkerResume,
    /// Replay one dead record through its owning provider.
    WorkerReplay,
    /// Start a bounded impersonation context.
    StartImpersonation,
    /// End an impersonation context.
    EndImpersonation,
}

impl AdminPermission {
    const ALL: [Self; 13] = [
        Self::UserLookup,
        Self::TenantLookup,
        Self::UserSuspension,
        Self::TenantSuspension,
        Self::SafeRepair,
        Self::FeatureOverride,
        Self::WorkerStatus,
        Self::WorkerDeadList,
        Self::WorkerPause,
        Self::WorkerResume,
        Self::WorkerReplay,
        Self::StartImpersonation,
        Self::EndImpersonation,
    ];

    const fn action_name(self) -> &'static str {
        match self {
            Self::UserLookup => "admin:user:lookup",
            Self::TenantLookup => "admin:tenant:lookup",
            Self::UserSuspension => "admin:user:suspend",
            Self::TenantSuspension => "admin:tenant:suspend",
            Self::SafeRepair => "admin:repair:execute",
            Self::FeatureOverride => "admin:feature:override",
            Self::WorkerStatus => "admin:worker:status",
            Self::WorkerDeadList => "admin:worker:dead:list",
            Self::WorkerPause => "admin:worker:pause",
            Self::WorkerResume => "admin:worker:resume",
            Self::WorkerReplay => "admin:worker:replay",
            Self::StartImpersonation => "admin:impersonation:start",
            Self::EndImpersonation => "admin:impersonation:end",
        }
    }

    const fn capability_name(self) -> &'static str {
        match self {
            Self::UserLookup => "admin_user_lookup",
            Self::TenantLookup => "admin_tenant_lookup",
            Self::UserSuspension => "admin_user_suspend",
            Self::TenantSuspension => "admin_tenant_suspend",
            Self::SafeRepair => "admin_safe_repair",
            Self::FeatureOverride => "admin_feature_override",
            Self::WorkerStatus => "admin_worker_status",
            Self::WorkerDeadList => "admin_worker_dead_list",
            Self::WorkerPause => "admin_worker_pause",
            Self::WorkerResume => "admin_worker_resume",
            Self::WorkerReplay => "admin_worker_replay",
            Self::StartImpersonation => "admin_impersonate",
            Self::EndImpersonation => "admin_end_impersonation",
        }
    }

    const fn resource_kind_name(self) -> &'static str {
        match self {
            Self::TenantLookup | Self::TenantSuspension | Self::FeatureOverride => "admin_tenant",
            Self::SafeRepair => "admin_repair",
            Self::WorkerStatus
            | Self::WorkerDeadList
            | Self::WorkerPause
            | Self::WorkerResume
            | Self::WorkerReplay => "admin_worker",
            Self::UserLookup
            | Self::UserSuspension
            | Self::StartImpersonation
            | Self::EndImpersonation => "admin_user",
        }
    }

    /// Returns the stable action identifier.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] only if the static action identifier is invalid.
    pub fn action(self) -> Result<Action, IdentifierError> {
        Action::new(self.action_name())
    }

    /// Returns the dedicated administrative capability.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] only if the static capability identifier is invalid.
    pub fn capability(self) -> Result<Capability, IdentifierError> {
        Capability::new(self.capability_name())
    }

    /// Returns the protected resource class.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] only if the static resource identifier is invalid.
    pub fn resource_kind(self) -> Result<ResourceKind, IdentifierError> {
        ResourceKind::new(self.resource_kind_name())
    }
}

/// Builds the administration rows added to the machine-readable permission matrix.
///
/// # Errors
///
/// Returns [`AdminPolicyError`] only if a static identifier or policy invariant is invalid.
pub fn admin_policy_rules() -> Result<Vec<PolicyRule>, AdminPolicyError> {
    AdminPermission::ALL
        .into_iter()
        .map(|permission| {
            Ok(PolicyRule::new(
                permission.action()?,
                permission.resource_kind()?,
                vec![Grant::AdministrativeCapability(permission.capability()?)],
            )?
            .with_minimum_assurance(AssuranceLevel::Aal2))
        })
        .collect()
}

/// Resolves authoritative administrative capabilities and impersonation targets.
///
/// Implementations belong at the trusted application composition boundary and must fail closed
/// when current grants or canonical identity/tenancy facts cannot be loaded.
pub trait AdminAuthorityResolver {
    /// Returns current authoritative administrator facts, or `None` when they cannot be trusted.
    fn resolve(&self, principal: &Principal) -> Option<AuthorizationContext>;

    /// Resolves a request into canonical identity or active tenant-membership authority.
    fn resolve_target(
        &self,
        target: ImpersonationTarget,
    ) -> Option<AuthorityResolvedImpersonationTarget>;
}

/// A static administration policy declaration was invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminPolicyError {
    /// A static identifier violated the shared portable grammar.
    #[error("admin policy contains an invalid static identifier")]
    Identifier(#[from] IdentifierError),
    /// A static permission row violated a policy invariant.
    #[error("admin policy contains an invalid rule")]
    Policy(#[from] PolicyError),
}

/// The closed operation classes available while impersonating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImpersonatedOperation {
    /// Read user support information.
    UserLookup,
    /// Read tenant support information.
    TenantLookup,
    /// Suspend a user.
    UserSuspension,
    /// Suspend a tenant.
    TenantSuspension,
    /// Execute a predefined typed repair.
    SafeRepair,
    /// Apply a controlled feature override.
    FeatureOverride,
    /// Change or issue credentials.
    CredentialManagement,
    /// Perform a payment operation.
    Payment,
    /// Enroll or modify a security factor.
    SecurityEnrollment,
}

impl ImpersonatedOperation {
    const fn permission(self) -> Option<AdminPermission> {
        match self {
            Self::UserLookup => Some(AdminPermission::UserLookup),
            Self::TenantLookup => Some(AdminPermission::TenantLookup),
            Self::UserSuspension => Some(AdminPermission::UserSuspension),
            Self::TenantSuspension => Some(AdminPermission::TenantSuspension),
            Self::SafeRepair => Some(AdminPermission::SafeRepair),
            Self::FeatureOverride => Some(AdminPermission::FeatureOverride),
            Self::CredentialManagement | Self::Payment | Self::SecurityEnrollment => None,
        }
    }

    const fn action_name(self) -> &'static str {
        match self {
            Self::UserLookup => "admin:user:read",
            Self::TenantLookup => "admin:tenant:read",
            Self::UserSuspension => "admin:user:suspend",
            Self::TenantSuspension => "admin:tenant:suspend",
            Self::SafeRepair => "admin:repair:execute",
            Self::FeatureOverride => "admin:feature:override",
            Self::CredentialManagement => "admin:credential:manage",
            Self::Payment => "admin:payment:manage",
            Self::SecurityEnrollment => "admin:security:enroll",
        }
    }

    const fn resource_kind_name(self) -> &'static str {
        match self {
            Self::TenantLookup | Self::TenantSuspension | Self::FeatureOverride => "admin_tenant",
            Self::SafeRepair => "admin_repair",
            Self::UserLookup
            | Self::UserSuspension
            | Self::CredentialManagement
            | Self::Payment
            | Self::SecurityEnrollment => "admin_user",
        }
    }

    const fn metric_label(self) -> &'static str {
        match self {
            Self::UserLookup => "user_lookup",
            Self::TenantLookup => "tenant_lookup",
            Self::UserSuspension => "user_suspension",
            Self::TenantSuspension => "tenant_suspension",
            Self::SafeRepair => "safe_repair",
            Self::FeatureOverride => "feature_override",
            Self::CredentialManagement => "credential_management",
            Self::Payment => "payment",
            Self::SecurityEnrollment => "security_enrollment",
        }
    }
}

/// A requested human-user target. The service resolves it through [`AdminAuthorityResolver`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImpersonationTarget {
    subject_id: SubjectId,
    tenant_id: Option<TenantId>,
}

impl ImpersonationTarget {
    /// Requests a global human-user target.
    #[must_use]
    pub const fn global(subject_id: SubjectId) -> Self {
        Self {
            subject_id,
            tenant_id: None,
        }
    }

    /// Requests a human-user target in one tenant.
    #[must_use]
    pub const fn tenant(subject_id: SubjectId, tenant_id: TenantId) -> Self {
        Self {
            subject_id,
            tenant_id: Some(tenant_id),
        }
    }

    /// Returns the requested subject identifier for authority lookup.
    #[must_use]
    pub const fn subject_id(self) -> SubjectId {
        self.subject_id
    }

    /// Returns the requested tenant identifier for authority lookup.
    #[must_use]
    pub const fn tenant_id(self) -> Option<TenantId> {
        self.tenant_id
    }

    fn validate_resolved(
        self,
        resolved: &AuthorityResolvedImpersonationTarget,
    ) -> Result<(), ImpersonationTargetError> {
        match (self.tenant_id, resolved) {
            (None, AuthorityResolvedImpersonationTarget::Global(principal)) => {
                if principal.kind != PrincipalKind::User {
                    return Err(ImpersonationTargetError::HumanUserRequired);
                }
                if principal.tenant_id.is_some() {
                    return Err(ImpersonationTargetError::AuthoritativeTenantRequired);
                }
                if principal.subject_id != self.subject_id {
                    return Err(ImpersonationTargetError::IncoherentTenantContext);
                }
                Ok(())
            }
            (Some(expected_tenant), AuthorityResolvedImpersonationTarget::Tenant(context)) => {
                let principal = context.principal();
                if principal.kind != PrincipalKind::User {
                    return Err(ImpersonationTargetError::HumanUserRequired);
                }
                let tenant_id = principal
                    .tenant_id
                    .ok_or(ImpersonationTargetError::AuthoritativeTenantRequired)?;
                if principal.subject_id != self.subject_id
                    || tenant_id != expected_tenant
                    || context.membership().user_id != principal.subject_id
                    || context.membership().organization_id != tenant_id
                {
                    return Err(ImpersonationTargetError::IncoherentTenantContext);
                }
                Ok(())
            }
            _ => Err(ImpersonationTargetError::IncoherentTenantContext),
        }
    }
}

/// Canonical target authority returned only by the trusted resolver.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityResolvedImpersonationTarget {
    /// A canonical global human principal.
    Global(Principal),
    /// A canonical principal with an active tenant membership.
    Tenant(rsk_tenancy::TenantContext),
}

/// A target was not established by the canonical identity/tenancy boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ImpersonationTargetError {
    /// Only human-user identities may be impersonated.
    #[error("impersonation target must be a human user")]
    HumanUserRequired,
    /// Tenant-scoped targets require an authority-resolved tenant context.
    #[error("impersonation target requires authoritative tenant context")]
    AuthoritativeTenantRequired,
    /// Tenant identity and active membership facts disagreed.
    #[error("impersonation tenant context is incoherent")]
    IncoherentTenantContext,
}

/// Required request lineage for an impersonation action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminLineage {
    /// Originating HTTP request identity.
    pub request_id: RequestId,
    /// Cross-transport correlation identity.
    pub correlation_id: CorrelationId,
    /// Optional causing work identity.
    pub causation_id: Option<CausationId>,
}

/// Prominent, bounded context carried for every impersonated operation.
#[derive(Debug, Eq, PartialEq)]
pub struct ImpersonationContext {
    effective_subject_id: SubjectId,
    impersonator_subject_id: SubjectId,
    effective_tenant_id: Option<TenantId>,
    reason: AuditReasonCode,
    issued_at: OffsetDateTime,
    expires_at: OffsetDateTime,
}

/// Prominent, non-authoritative identity information for transport banners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImpersonationDisplay {
    /// Effective human-user subject shown to the operator.
    pub effective_subject_id: SubjectId,
    /// Administrator shown to the operator.
    pub impersonator_subject_id: SubjectId,
    /// Effective tenant shown to the operator.
    pub effective_tenant_id: Option<TenantId>,
    /// Exclusive expiry shown to the operator.
    pub expires_at: OffsetDateTime,
}

impl ImpersonationContext {
    /// Returns non-authoritative values for a prominent transport banner.
    #[must_use]
    pub const fn display(&self) -> ImpersonationDisplay {
        ImpersonationDisplay {
            effective_subject_id: self.effective_subject_id,
            impersonator_subject_id: self.impersonator_subject_id,
            effective_tenant_id: self.effective_tenant_id,
            expires_at: self.expires_at,
        }
    }

    /// Returns the required bounded audit reason.
    #[must_use]
    pub const fn reason(&self) -> &AuditReasonCode {
        &self.reason
    }

    /// Returns context creation time.
    #[must_use]
    pub const fn issued_at(&self) -> OffsetDateTime {
        self.issued_at
    }

    /// Returns the exclusive expiry boundary.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Returns the deliberately prominent transport-facing status label.
    #[must_use]
    pub const fn status_label(&self) -> &'static str {
        "IMPERSONATION ACTIVE"
    }

    fn check_operation(
        &self,
        operation: ImpersonatedOperation,
        now: OffsetDateTime,
    ) -> Result<AdminPermission, ImpersonationUseError> {
        if now >= self.expires_at {
            return Err(ImpersonationUseError::Expired);
        }
        operation
            .permission()
            .ok_or(ImpersonationUseError::Restricted)
    }
}

/// An operation was unsafe under impersonation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ImpersonationUseError {
    /// The context reached its exclusive expiry boundary.
    #[error("impersonation context is expired")]
    Expired,
    /// The operation class is always blocked during impersonation.
    #[error("operation is restricted during impersonation")]
    Restricted,
}

/// Transaction-scoped proof that an impersonated operation passed every service guard.
///
/// Values can only be created while an [`AdminService`] invokes its configured typed operation
/// backend and cannot outlive that operation call.
#[derive(Debug)]
pub struct AuthorizedImpersonation<'context> {
    context: &'context ImpersonationContext,
}

impl AuthorizedImpersonation<'_> {
    /// Returns the authority-resolved effective human-user subject.
    #[must_use]
    pub const fn subject_id(&self) -> SubjectId {
        self.context.effective_subject_id
    }

    /// Returns the authority-resolved effective tenant, when scoped.
    #[must_use]
    pub const fn tenant_id(&self) -> Option<TenantId> {
        self.context.effective_tenant_id
    }
}

/// Trusted typed backend for the six administrative operations allowed during impersonation.
///
/// The backend is fixed when [`AdminService`] is composed. Request handlers cannot supply SQL or
/// callbacks, and repair/feature requests are backend-defined types rather than generic commands.
#[expect(
    async_fn_in_trait,
    reason = "admin backends are awaited in-place and do not require a Send future contract"
)]
pub trait AdminOperationHandler: Send + Sync {
    /// Typed result shared by this backend's closed operations.
    type Output;
    /// Backend-defined closed safe-repair request.
    type RepairRequest;
    /// Backend-defined closed feature-override request.
    type FeatureOverrideRequest;
    /// Backend operation failure.
    type Error;

    /// Looks up the effective user.
    async fn lookup_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error>;
    /// Looks up the effective tenant.
    async fn lookup_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error>;
    /// Suspends the effective user.
    async fn suspend_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error>;
    /// Suspends the effective tenant.
    async fn suspend_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error>;
    /// Executes one backend-defined typed safe repair.
    async fn execute_safe_repair(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        request: Self::RepairRequest,
    ) -> Result<Self::Output, Self::Error>;
    /// Applies one backend-defined typed feature override.
    async fn apply_feature_override(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        request: Self::FeatureOverrideRequest,
    ) -> Result<Self::Output, Self::Error>;
}

/// Protected administration service with a fail-closed authorization boundary.
pub struct AdminService<P, R, O> {
    authorization: AuthorizationService<P>,
    authority: R,
    operations: O,
    clock: Arc<dyn Clock>,
    audit: PostgresAuditSink,
    config: AdminConfig,
    recent_authentication_window: time::Duration,
    maximum_impersonation_lifetime: time::Duration,
    start_action: Action,
    target_kind: ResourceKind,
}

impl<P, R, O> AdminService<P, R, O>
where
    P: AuthorizationProvider,
    R: AdminAuthorityResolver,
    O: AdminOperationHandler,
{
    /// Creates a validated service.
    ///
    /// # Errors
    ///
    /// Returns [`AdminBuildError`] for unsafe configuration or invalid static identifiers.
    pub fn new(
        provider: P,
        authority: R,
        operations: O,
        clock: Arc<dyn Clock>,
        audit: PostgresAuditSink,
        config: AdminConfig,
    ) -> Result<Self, AdminBuildError> {
        config.validate()?;
        Ok(Self {
            authorization: AuthorizationService::new(provider),
            authority,
            operations,
            clock,
            audit,
            config,
            recent_authentication_window: time::Duration::try_from(
                config.recent_authentication_window,
            )
            .map_err(|_| AdminConfigError::RecentAuthenticationWindow)?,
            maximum_impersonation_lifetime: time::Duration::try_from(
                config.maximum_impersonation_lifetime,
            )
            .map_err(|_| AdminConfigError::ImpersonationLifetime)?,
            start_action: AdminPermission::StartImpersonation.action()?,
            target_kind: AdminPermission::StartImpersonation.resource_kind()?,
        })
    }

    /// Starts impersonation only after authorization, recency, lifetime, and committed audit.
    ///
    /// This method owns the audit transaction. It never returns an active context, or a denied
    /// result, until the corresponding audit transaction commits.
    ///
    /// # Errors
    ///
    /// Returns a stable [`AdminError`] and durably audits every enabled start outcome.
    pub async fn start_impersonation(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        target: ImpersonationTarget,
        reason: AuditReasonCode,
        requested_lifetime: Duration,
        lineage: AdminLineage,
    ) -> Result<ImpersonationContext, AdminError> {
        if !self.config.enabled {
            record_start("disabled");
            return Err(AdminError::Disabled);
        }

        let now = self.clock.now_utc();
        if let Err(error) = self.validate_start(administrator, target, requested_lifetime, now) {
            let audit_result = self
                .commit_start_audit(
                    pool,
                    administrator,
                    target,
                    AuditOutcome::Denied,
                    failure_reason(error)?,
                    lineage,
                    now,
                    false,
                )
                .await;
            if let Err(audit_error) = audit_result {
                record_start(audit_error.metric_label());
                return Err(audit_error);
            }
            record_start(error.metric_label());
            return Err(error);
        }

        let lifetime = time::Duration::try_from(requested_lifetime)
            .map_err(|_| AdminError::InvalidLifetime)?;
        let context = ImpersonationContext {
            effective_subject_id: target.subject_id,
            impersonator_subject_id: administrator.subject_id,
            effective_tenant_id: target.tenant_id,
            reason: reason.clone(),
            issued_at: now,
            expires_at: now + lifetime,
        };
        let audit_result = self
            .commit_start_audit(
                pool,
                administrator,
                target,
                AuditOutcome::Succeeded,
                reason,
                lineage,
                now,
                true,
            )
            .await;
        if let Err(error) = audit_result {
            record_start(error.metric_label());
            return Err(error);
        }
        record_start("succeeded");
        Ok(context)
    }

    fn validate_start(
        &self,
        administrator: &Principal,
        target: ImpersonationTarget,
        requested_lifetime: Duration,
        now: OffsetDateTime,
    ) -> Result<(), AdminError> {
        if administrator.kind != PrincipalKind::User {
            return Err(AdminError::HumanAdministratorRequired);
        }
        if administrator.subject_id == target.subject_id {
            return Err(AdminError::DistinctSubjectRequired);
        }
        if administrator.assurance < AssuranceLevel::Aal2 {
            return Err(AdminError::InsufficientAssurance);
        }
        if administrator.authenticated_at > now {
            return Err(AdminError::FutureAuthentication);
        }
        if now - administrator.authenticated_at > self.recent_authentication_window {
            return Err(AdminError::StaleAuthentication);
        }
        if requested_lifetime.is_zero()
            || time::Duration::try_from(requested_lifetime).map_or(true, |lifetime| {
                lifetime > self.maximum_impersonation_lifetime
            })
        {
            return Err(AdminError::InvalidLifetime);
        }

        let mut resource = Resource::new(self.target_kind.clone()).owned_by(target.subject_id);
        if let Some(tenant_id) = target.tenant_id {
            resource = resource.in_tenant(tenant_id);
        }
        let authorization_context = self
            .authority
            .resolve(administrator)
            .ok_or(AdminError::AuthorityUnavailable)?;
        match self.authorization.authorize(
            administrator,
            &self.start_action,
            &resource,
            &authorization_context,
        ) {
            Decision::Allow => {}
            Decision::Deny(reason) => return Err(AdminError::AuthorizationDenied(reason)),
        }
        let resolved_target = self
            .authority
            .resolve_target(target)
            .ok_or(AdminError::TargetUnavailable)?;
        target
            .validate_resolved(&resolved_target)
            .map_err(|_| AdminError::TargetUnavailable)
    }

    /// Looks up the effective user through the trusted typed backend.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn lookup_user(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::UserLookup,
            reason,
            lineage,
            async |connection, authority| self.operations.lookup_user(connection, authority).await,
        )
        .await
    }

    /// Looks up the effective tenant through the trusted typed backend.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn lookup_tenant(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::TenantLookup,
            reason,
            lineage,
            async |connection, authority| {
                self.operations.lookup_tenant(connection, authority).await
            },
        )
        .await
    }

    /// Suspends the effective user through the trusted typed backend.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn suspend_user(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::UserSuspension,
            reason,
            lineage,
            async |connection, authority| self.operations.suspend_user(connection, authority).await,
        )
        .await
    }

    /// Suspends the effective tenant through the trusted typed backend.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn suspend_tenant(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::TenantSuspension,
            reason,
            lineage,
            async |connection, authority| {
                self.operations.suspend_tenant(connection, authority).await
            },
        )
        .await
    }

    /// Executes one backend-defined safe repair.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn execute_safe_repair(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        request: O::RepairRequest,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::SafeRepair,
            reason,
            lineage,
            async |connection, authority| {
                self.operations
                    .execute_safe_repair(connection, authority, request)
                    .await
            },
        )
        .await
    }

    /// Applies one backend-defined feature override.
    ///
    /// # Errors
    ///
    /// Returns [`AdminExecutionError`] when guards, the typed backend, or committed audit fails.
    pub async fn apply_feature_override(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        request: O::FeatureOverrideRequest,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<O::Output, AdminExecutionError<O::Error>> {
        self.execute_impersonated_operation(
            pool,
            administrator,
            context,
            ImpersonatedOperation::FeatureOverride,
            reason,
            lineage,
            async |connection, authority| {
                self.operations
                    .apply_feature_override(connection, authority, request)
                    .await
            },
        )
        .await
    }

    /// Runs an internally selected typed operation and commits its audit atomically.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "one transaction keeps authorization, execution, and audit ordering visible"
    )]
    async fn execute_impersonated_operation<T, E, F>(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        operation: ImpersonatedOperation,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        execute: F,
    ) -> Result<T, AdminExecutionError<E>>
    where
        F: for<'connection> AsyncFnOnce(
            &'connection mut PgConnection,
            &'connection AuthorizedImpersonation<'_>,
        ) -> Result<T, E>,
    {
        if !self.config.enabled {
            record_operation(operation, "disabled");
            return Err(AdminError::Disabled.into());
        }
        let now = self.clock.now_utc();
        let permission = match context.check_operation(operation, now) {
            Ok(permission) => permission,
            Err(error) => {
                let admin_error = AdminError::from(error);
                self.commit_impersonation_audit(
                    pool,
                    SecurityEventName::AdministrativeIdentityAction,
                    administrator,
                    context,
                    operation.action_name(),
                    operation.resource_kind_name(),
                    AuditOutcome::Denied,
                    failure_reason(admin_error)?,
                    lineage,
                    now,
                    false,
                )
                .await?;
                record_operation(operation, admin_error.metric_label());
                return Err(admin_error.into());
            }
        };
        if let Err(error) =
            self.validate_impersonated_permission(administrator, context, permission, now)
        {
            self.commit_impersonation_audit(
                pool,
                SecurityEventName::AdministrativeIdentityAction,
                administrator,
                context,
                operation.action_name(),
                operation.resource_kind_name(),
                AuditOutcome::Denied,
                failure_reason(error)?,
                lineage,
                now,
                false,
            )
            .await?;
            record_operation(operation, error.metric_label());
            return Err(error.into());
        }

        let mut connection = pool
            .acquire()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        let authority = AuthorizedImpersonation { context };
        match execute(&mut transaction, &authority).await {
            Ok(value) => {
                self.append_impersonation_audit(
                    &mut transaction,
                    SecurityEventName::AdministrativeIdentityAction,
                    administrator,
                    context,
                    operation.action_name(),
                    operation.resource_kind_name(),
                    AuditOutcome::Succeeded,
                    reason,
                    lineage,
                    now,
                    true,
                )
                .await?;
                transaction
                    .commit()
                    .await
                    .map_err(|_| AdminError::DatabaseUnavailable)?;
                record_operation(operation, "succeeded");
                Ok(value)
            }
            Err(error) => {
                transaction
                    .rollback()
                    .await
                    .map_err(|_| AdminError::DatabaseUnavailable)?;
                self.commit_impersonation_audit(
                    pool,
                    SecurityEventName::AdministrativeIdentityAction,
                    administrator,
                    context,
                    operation.action_name(),
                    operation.resource_kind_name(),
                    AuditOutcome::Failed,
                    reason,
                    lineage,
                    now,
                    true,
                )
                .await?;
                record_operation(operation, "failed");
                Err(AdminExecutionError::Operation(error))
            }
        }
    }

    /// Ends an impersonation context with cancellation-safe ownership.
    ///
    /// The context is consumed on success or future cancellation. Ordinary failures return it in
    /// [`EndImpersonationError`] so an audited end can be retried.
    ///
    /// # Errors
    ///
    /// Returns [`EndImpersonationError`] if authorization or the committed end audit fails.
    /// Expired contexts remain endable.
    pub async fn end_impersonation(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: ImpersonationContext,
        reason: AuditReasonCode,
        lineage: AdminLineage,
    ) -> Result<(), EndImpersonationError> {
        if !self.config.enabled {
            return Err(EndImpersonationError::context_returned(
                AdminError::Disabled,
                context,
            ));
        }
        let now = self.clock.now_utc();
        if let Err(error) = self.validate_impersonated_permission(
            administrator,
            &context,
            AdminPermission::EndImpersonation,
            now,
        ) {
            let audit_reason = match failure_reason(error) {
                Ok(reason) => reason,
                Err(audit_error) => {
                    return Err(EndImpersonationError::context_returned(
                        audit_error,
                        context,
                    ));
                }
            };
            return match self
                .commit_end_audit(
                    pool,
                    administrator,
                    &context,
                    AuditOutcome::Denied,
                    audit_reason,
                    lineage,
                    now,
                    false,
                )
                .await
            {
                Ok(()) => Err(EndImpersonationError::context_returned(error, context)),
                Err(EndAuditCommitError::ContextSafe(audit_error)) => Err(
                    EndImpersonationError::context_returned(audit_error, context),
                ),
                Err(EndAuditCommitError::OutcomeUncertain(audit_error)) => {
                    Err(EndImpersonationError::outcome_uncertain(audit_error))
                }
            };
        }
        match self
            .commit_end_audit(
                pool,
                administrator,
                &context,
                AuditOutcome::Succeeded,
                reason,
                lineage,
                now,
                true,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(EndAuditCommitError::ContextSafe(error)) => {
                Err(EndImpersonationError::context_returned(error, context))
            }
            Err(EndAuditCommitError::OutcomeUncertain(error)) => {
                Err(EndImpersonationError::outcome_uncertain(error))
            }
        }
    }

    fn validate_impersonated_permission(
        &self,
        administrator: &Principal,
        context: &ImpersonationContext,
        permission: AdminPermission,
        now: OffsetDateTime,
    ) -> Result<(), AdminError> {
        if administrator.kind != PrincipalKind::User
            || administrator.subject_id != context.impersonator_subject_id
        {
            return Err(AdminError::ContextMismatch);
        }
        if administrator.assurance < AssuranceLevel::Aal2 {
            return Err(AdminError::InsufficientAssurance);
        }
        if administrator.authenticated_at > now {
            return Err(AdminError::FutureAuthentication);
        }
        if now - administrator.authenticated_at > self.recent_authentication_window {
            return Err(AdminError::StaleAuthentication);
        }
        let authorization_context = self
            .authority
            .resolve(administrator)
            .ok_or(AdminError::AuthorityUnavailable)?;
        let action = permission
            .action()
            .map_err(|_| AdminError::InternalContract)?;
        let mut resource = Resource::new(
            permission
                .resource_kind()
                .map_err(|_| AdminError::InternalContract)?,
        )
        .owned_by(context.effective_subject_id);
        if let Some(tenant_id) = context.effective_tenant_id {
            resource = resource.in_tenant(tenant_id);
        }
        match self.authorization.authorize(
            administrator,
            &action,
            &resource,
            &authorization_context,
        ) {
            Decision::Allow => Ok(()),
            Decision::Deny(reason) => Err(AdminError::AuthorizationDenied(reason)),
        }
    }
    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction names every security field"
    )]
    async fn commit_start_audit(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        target: ImpersonationTarget,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        active_impersonation: bool,
    ) -> Result<(), AdminError> {
        let mut connection = pool
            .acquire()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        self.append_start_audit(
            &mut transaction,
            administrator,
            target,
            outcome,
            reason,
            lineage,
            occurred_at,
            active_impersonation,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction names every security field"
    )]
    async fn append_start_audit(
        &self,
        connection: &mut PgConnection,
        administrator: &Principal,
        target: ImpersonationTarget,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        active_impersonation: bool,
    ) -> Result<(), AdminError> {
        let scope = target
            .tenant_id
            .map_or(AuditScope::Global, AuditScope::Tenant);
        let actor = if active_impersonation {
            AuditActor::User(target.subject_id)
        } else {
            match administrator.kind {
                PrincipalKind::User => AuditActor::User(administrator.subject_id),
                PrincipalKind::ServiceAccount => {
                    AuditActor::ServiceAccount(administrator.subject_id)
                }
            }
        };
        let mut event = AuditEvent::builder(
            SecurityEventName::ImpersonationStarted,
            occurred_at,
            actor,
            scope,
            self.start_action.clone(),
            self.target_kind.clone(),
            outcome,
        )
        .subject_id(target.subject_id)
        .resource_id(
            AuditResourceId::new(target.subject_id.to_string())
                .map_err(|_| AdminError::InternalContract)?,
        )
        .request_id(lineage.request_id)
        .correlation_id(lineage.correlation_id)
        .reason(reason)
        .metadata(
            AuditMetadata::try_from_fields([AuditMetadataField::Interactive(true)])
                .map_err(|_| AdminError::InternalContract)?,
        );
        if let Some(causation_id) = lineage.causation_id {
            event = event.causation_id(causation_id);
        }
        if active_impersonation {
            event = event
                .impersonator_subject_id(administrator.subject_id)
                .map_err(|_| AdminError::InternalContract)?;
        }
        match self.audit.append_with(connection, &event.build()).await? {
            AuditAppendOutcome::Appended => Ok(()),
            AuditAppendOutcome::Disabled => Err(AdminError::AuditDisabled),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "commit classification and complete audit lineage are explicit"
    )]
    async fn commit_end_audit(
        &self,
        pool: &PostgresPool,
        administrator: &Principal,
        context: &ImpersonationContext,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        active_impersonation: bool,
    ) -> Result<(), EndAuditCommitError> {
        let mut connection = pool
            .acquire()
            .await
            .map_err(|_| EndAuditCommitError::ContextSafe(AdminError::DatabaseUnavailable))?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| EndAuditCommitError::ContextSafe(AdminError::DatabaseUnavailable))?;
        self.append_impersonation_audit(
            &mut transaction,
            SecurityEventName::ImpersonationEnded,
            administrator,
            context,
            "admin:impersonation:end",
            "admin_user",
            outcome,
            reason,
            lineage,
            occurred_at,
            active_impersonation,
        )
        .await
        .map_err(EndAuditCommitError::ContextSafe)?;
        transaction
            .commit()
            .await
            .map_err(|_| EndAuditCommitError::OutcomeUncertain(AdminError::DatabaseUnavailable))
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction names every security field"
    )]
    async fn commit_impersonation_audit(
        &self,
        pool: &PostgresPool,
        event_name: SecurityEventName,
        administrator: &Principal,
        context: &ImpersonationContext,
        action_name: &'static str,
        resource_kind_name: &'static str,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        active_impersonation: bool,
    ) -> Result<(), AdminError> {
        let mut connection = pool
            .acquire()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        let mut transaction = connection
            .begin()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)?;
        self.append_impersonation_audit(
            &mut transaction,
            event_name,
            administrator,
            context,
            action_name,
            resource_kind_name,
            outcome,
            reason,
            lineage,
            occurred_at,
            active_impersonation,
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|_| AdminError::DatabaseUnavailable)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "audit construction names every security field"
    )]
    async fn append_impersonation_audit(
        &self,
        connection: &mut PgConnection,
        event_name: SecurityEventName,
        administrator: &Principal,
        context: &ImpersonationContext,
        action_name: &'static str,
        resource_kind_name: &'static str,
        outcome: AuditOutcome,
        reason: AuditReasonCode,
        lineage: AdminLineage,
        occurred_at: OffsetDateTime,
        active_impersonation: bool,
    ) -> Result<(), AdminError> {
        let action = Action::new(action_name).map_err(|_| AdminError::InternalContract)?;
        let resource_kind =
            ResourceKind::new(resource_kind_name).map_err(|_| AdminError::InternalContract)?;
        let scope = context
            .effective_tenant_id
            .map_or(AuditScope::Global, AuditScope::Tenant);
        let actor = if active_impersonation {
            AuditActor::User(context.effective_subject_id)
        } else {
            match administrator.kind {
                PrincipalKind::User => AuditActor::User(administrator.subject_id),
                PrincipalKind::ServiceAccount => {
                    AuditActor::ServiceAccount(administrator.subject_id)
                }
            }
        };
        let mut event = AuditEvent::builder(
            event_name,
            occurred_at,
            actor,
            scope,
            action,
            resource_kind,
            outcome,
        )
        .subject_id(context.effective_subject_id)
        .resource_id(
            AuditResourceId::new(context.effective_subject_id.to_string())
                .map_err(|_| AdminError::InternalContract)?,
        )
        .request_id(lineage.request_id)
        .correlation_id(lineage.correlation_id)
        .reason(reason)
        .metadata(
            AuditMetadata::try_from_fields([AuditMetadataField::Interactive(true)])
                .map_err(|_| AdminError::InternalContract)?,
        );
        if active_impersonation {
            event = event
                .impersonator_subject_id(context.impersonator_subject_id)
                .map_err(|_| AdminError::InternalContract)?;
        }
        if let Some(causation_id) = lineage.causation_id {
            event = event.causation_id(causation_id);
        }
        match self.audit.append_with(connection, &event.build()).await? {
            AuditAppendOutcome::Appended => Ok(()),
            AuditAppendOutcome::Disabled => Err(AdminError::AuditDisabled),
        }
    }
}

/// Protected admin service construction failed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminBuildError {
    /// Configuration was unsafe.
    #[error(transparent)]
    Config(#[from] AdminConfigError),
    /// A static action/resource identifier was invalid.
    #[error("admin service contains an invalid static identifier")]
    Identifier(#[from] IdentifierError),
}

/// An impersonated operation failed at the administration or business boundary.
#[derive(Debug, Error)]
pub enum AdminExecutionError<E> {
    /// Authorization, context, persistence, or audit failed.
    #[error(transparent)]
    Admin(#[from] AdminError),
    /// The authorized business callback failed and was rolled back.
    #[error("impersonated operation failed")]
    Operation(E),
}

/// An impersonation end failed, with explicit context-retry safety.
#[derive(Debug, Error)]
pub enum EndImpersonationError {
    /// No commit was attempted, or a denied end committed; the context is safe to retry.
    #[error("impersonation end failed with retryable context")]
    ContextReturned {
        /// Underlying administration failure.
        #[source]
        error: AdminError,
        /// Original active context.
        context: ImpersonationContext,
    },
    /// The database commit outcome is uncertain, so the context was consumed.
    #[error("impersonation end commit outcome is uncertain")]
    OutcomeUncertain(#[source] AdminError),
}

impl EndImpersonationError {
    const fn context_returned(error: AdminError, context: ImpersonationContext) -> Self {
        Self::ContextReturned { error, context }
    }

    const fn outcome_uncertain(error: AdminError) -> Self {
        Self::OutcomeUncertain(error)
    }

    /// Returns the stable underlying administration failure.
    #[must_use]
    pub const fn error(&self) -> AdminError {
        match self {
            Self::ContextReturned { error, .. } | Self::OutcomeUncertain(error) => *error,
        }
    }

    /// Returns the context only when no successful end commit may have occurred.
    #[must_use]
    pub fn into_context(self) -> Option<ImpersonationContext> {
        match self {
            Self::ContextReturned { context, .. } => Some(context),
            Self::OutcomeUncertain(_) => None,
        }
    }
}
/// A protected impersonation start failed.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdminError {
    /// The module was disabled.
    #[error("protected administration is disabled")]
    Disabled,
    /// Only human users may administer impersonation.
    #[error("impersonation requires a human administrator")]
    HumanAdministratorRequired,
    /// The operator and target identities must differ.
    #[error("impersonation requires a distinct target subject")]
    DistinctSubjectRequired,
    /// Authentication assurance was below AAL2.
    #[error("impersonation requires high-assurance authentication")]
    InsufficientAssurance,
    /// Authentication time was in the future.
    #[error("administrator authentication time is invalid")]
    FutureAuthentication,
    /// High-assurance authentication was no longer recent.
    #[error("administrator authentication is stale")]
    StaleAuthentication,
    /// Requested lifetime was zero or too long.
    #[error("requested impersonation lifetime is invalid")]
    InvalidLifetime,
    /// Dedicated permission was denied.
    #[error("impersonation authorization was denied")]
    AuthorizationDenied(DenyReason),
    /// The supplied administrator does not own this impersonation context.
    #[error("administrator does not match impersonation context")]
    ContextMismatch,
    /// The impersonation context reached its expiry boundary.
    #[error("impersonation context is expired")]
    ImpersonationExpired,
    /// The operation class is prohibited under impersonation.
    #[error("operation is restricted during impersonation")]
    RestrictedOperation,
    /// The configured audit sink was disabled.
    #[error("required impersonation audit is disabled")]
    AuditDisabled,
    /// Authoritative administrative grants could not be resolved.
    #[error("administrative authority is unavailable")]
    AuthorityUnavailable,
    /// Canonical target identity or active membership could not be resolved.
    #[error("impersonation target authority is unavailable")]
    TargetUnavailable,
    /// Audit persistence failed.
    #[error("required impersonation audit failed")]
    Audit(#[from] AuditSinkError),
    /// The service could not acquire, begin, or commit its audit transaction.
    #[error("admin audit transaction is unavailable")]
    DatabaseUnavailable,
    /// A static internal invariant was violated.
    #[error("admin service invariant failed")]
    InternalContract,
}

impl AdminError {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::HumanAdministratorRequired => "invalid_actor",
            Self::DistinctSubjectRequired => "same_subject",
            Self::InsufficientAssurance => "insufficient_assurance",
            Self::FutureAuthentication => "future_authentication",
            Self::StaleAuthentication => "stale_authentication",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::InvalidLifetime => "invalid_lifetime",
            Self::TargetUnavailable => "target_unavailable",
            Self::AuthorizationDenied(_) => "authorization_denied",
            Self::ContextMismatch => "context_mismatch",
            Self::ImpersonationExpired => "expired",
            Self::RestrictedOperation => "restricted",
            Self::AuditDisabled => "audit_disabled",
            Self::Audit(_) => "audit_failed",
            Self::DatabaseUnavailable => "database_unavailable",
            Self::InternalContract => "internal_contract",
        }
    }
}

impl RetryableTransactionError for AdminError {
    fn retryable_sql_state(&self) -> Option<RetryableSqlState> {
        match self {
            Self::Audit(error) => error.retryable_sql_state(),
            Self::Disabled
            | Self::HumanAdministratorRequired
            | Self::DistinctSubjectRequired
            | Self::InsufficientAssurance
            | Self::FutureAuthentication
            | Self::StaleAuthentication
            | Self::AuthorityUnavailable
            | Self::InvalidLifetime
            | Self::TargetUnavailable
            | Self::AuthorizationDenied(_)
            | Self::ContextMismatch
            | Self::ImpersonationExpired
            | Self::RestrictedOperation
            | Self::AuditDisabled
            | Self::DatabaseUnavailable
            | Self::InternalContract => None,
        }
    }
}
#[derive(Debug)]
enum EndAuditCommitError {
    ContextSafe(AdminError),
    OutcomeUncertain(AdminError),
}

fn failure_reason(error: AdminError) -> Result<AuditReasonCode, AdminError> {
    let value = match error {
        AdminError::HumanAdministratorRequired => "admin.invalid_actor",
        AdminError::DistinctSubjectRequired => "admin.same_subject",
        AdminError::InsufficientAssurance => "admin.insufficient_assurance",
        AdminError::FutureAuthentication => "admin.future_authentication",
        AdminError::StaleAuthentication => "admin.stale_authentication",
        AdminError::InvalidLifetime => "admin.invalid_lifetime",
        AdminError::TargetUnavailable => "admin.target_unavailable",
        AdminError::AuthorizationDenied(_) => "authorization.denied",
        AdminError::ContextMismatch => "admin.context_mismatch",
        AdminError::ImpersonationExpired => "admin.impersonation_expired",
        AdminError::RestrictedOperation => "admin.impersonation_restricted",
        AdminError::Disabled
        | AdminError::AuthorityUnavailable
        | AdminError::AuditDisabled
        | AdminError::Audit(_)
        | AdminError::DatabaseUnavailable
        | AdminError::InternalContract => "admin.failed",
    };
    AuditReasonCode::new(value).map_err(|_| AdminError::InternalContract)
}

impl From<ImpersonationUseError> for AdminError {
    fn from(error: ImpersonationUseError) -> Self {
        match error {
            ImpersonationUseError::Expired => Self::ImpersonationExpired,
            ImpersonationUseError::Restricted => Self::RestrictedOperation,
        }
    }
}

fn record_operation(operation: ImpersonatedOperation, result: &'static str) {
    counter!(
        "rsk_admin_impersonated_operations_total",
        "operation" => operation.metric_label(),
        "result" => result
    )
    .increment(1);
}
fn record_start(result: &'static str) {
    counter!("rsk_admin_impersonation_starts_total", "result" => result).increment(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsk_auth_core::{AuthMethod, Scope};
    use rsk_authz_basic::{BasicPolicy, PolicyMatrix};
    struct TestClock(OffsetDateTime);

    impl Clock for TestClock {
        fn now_utc(&self) -> OffsetDateTime {
            self.0
        }
    }
    struct TestOperations;

    #[expect(
        clippy::unused_async_trait_impl,
        reason = "the in-memory test backend implements the production async contract"
    )]
    impl AdminOperationHandler for TestOperations {
        type Output = SubjectId;
        type RepairRequest = ();
        type FeatureOverrideRequest = ();
        type Error = std::convert::Infallible;

        async fn lookup_user(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }

        async fn lookup_tenant(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }

        async fn suspend_user(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }

        async fn suspend_tenant(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }

        async fn execute_safe_repair(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
            (): Self::RepairRequest,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }

        async fn apply_feature_override(
            &self,
            _connection: &mut PgConnection,
            authority: &AuthorizedImpersonation<'_>,
            (): Self::FeatureOverrideRequest,
        ) -> Result<Self::Output, Self::Error> {
            Ok(authority.subject_id())
        }
    }

    #[derive(Clone)]
    struct FixedAuthority {
        context: Option<AuthorizationContext>,
        now: OffsetDateTime,
    }

    impl AdminAuthorityResolver for FixedAuthority {
        fn resolve(&self, _principal: &Principal) -> Option<AuthorizationContext> {
            self.context.clone()
        }

        fn resolve_target(
            &self,
            target: ImpersonationTarget,
        ) -> Option<AuthorityResolvedImpersonationTarget> {
            if target.tenant_id.is_some() {
                return None;
            }
            Principal::new(
                target.subject_id,
                PrincipalKind::User,
                None,
                AuthMethod::WebAuthn,
                self.now,
                AssuranceLevel::Aal2,
                Vec::<Scope>::new(),
            )
            .ok()
            .map(AuthorityResolvedImpersonationTarget::Global)
        }
    }

    fn principal(
        now: OffsetDateTime,
        assurance: AssuranceLevel,
    ) -> Result<Principal, Box<dyn std::error::Error>> {
        Ok(Principal::new(
            SubjectId::new(),
            PrincipalKind::User,
            None,
            AuthMethod::WebAuthn,
            now,
            assurance,
            Vec::<Scope>::new(),
        )?)
    }

    fn service_with_authority(
        now: OffsetDateTime,
        authority: Option<AuthorizationContext>,
    ) -> Result<AdminService<BasicPolicy, FixedAuthority, TestOperations>, Box<dyn std::error::Error>>
    {
        let matrix = PolicyMatrix::new(admin_policy_rules()?)?;
        Ok(AdminService::new(
            BasicPolicy::new(matrix),
            FixedAuthority {
                context: authority,
                now,
            },
            TestOperations,
            Arc::new(TestClock(now)),
            PostgresAuditSink::default(),
            AdminConfig::default(),
        )?)
    }

    fn service(
        now: OffsetDateTime,
    ) -> Result<AdminService<BasicPolicy, FixedAuthority, TestOperations>, Box<dyn std::error::Error>>
    {
        let authority = AuthorizationContext::new(
            vec![],
            vec![],
            vec![AdminPermission::StartImpersonation.capability()?],
            vec![],
        )?;
        service_with_authority(now, Some(authority))
    }

    #[test]
    fn config_bounds_are_strict() {
        let config = AdminConfig {
            recent_authentication_window: Duration::ZERO,
            ..AdminConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(AdminConfigError::RecentAuthenticationWindow)
        );
        let config = AdminConfig {
            maximum_impersonation_lifetime: Duration::from_secs(3_601),
            ..AdminConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err(AdminConfigError::ImpersonationLifetime)
        );
    }

    #[test]
    fn target_constructors_require_canonical_human_scope() -> Result<(), Box<dyn std::error::Error>>
    {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let user = principal(now, AssuranceLevel::Aal2)?;
        let target = ImpersonationTarget::global(user.subject_id);
        assert_eq!(
            target.validate_resolved(&AuthorityResolvedImpersonationTarget::Global(user)),
            Ok(())
        );
        let service_account = Principal::new(
            SubjectId::new(),
            PrincipalKind::ServiceAccount,
            None,
            AuthMethod::ApiKey,
            now,
            AssuranceLevel::Aal2,
            Vec::<Scope>::new(),
        )?;
        assert_eq!(
            target.validate_resolved(&AuthorityResolvedImpersonationTarget::Global(
                service_account
            )),
            Err(ImpersonationTargetError::HumanUserRequired)
        );
        let tenant_user = Principal::new(
            target.subject_id,
            PrincipalKind::User,
            Some(TenantId::new()),
            AuthMethod::WebAuthn,
            now,
            AssuranceLevel::Aal2,
            Vec::<Scope>::new(),
        )?;
        assert_eq!(
            target.validate_resolved(&AuthorityResolvedImpersonationTarget::Global(tenant_user)),
            Err(ImpersonationTargetError::AuthoritativeTenantRequired)
        );
        Ok(())
    }

    #[test]
    fn policy_requires_dedicated_capability_and_aal2() -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let service = service(now)?;
        let administrator = principal(now, AssuranceLevel::Aal2)?;
        let target = ImpersonationTarget {
            subject_id: SubjectId::new(),
            tenant_id: None,
        };
        let resource = Resource::new(service.target_kind.clone()).owned_by(target.subject_id);
        let empty = AuthorizationContext::default();
        assert_eq!(
            service.authorization.authorize(
                &administrator,
                &service.start_action,
                &resource,
                &empty
            ),
            Decision::Deny(DenyReason::NotEntitled)
        );
        let context = AuthorizationContext::new(
            vec![],
            vec![],
            vec![AdminPermission::StartImpersonation.capability()?],
            vec![],
        )?;
        let low = principal(now, AssuranceLevel::Aal1)?;
        assert_eq!(
            service
                .authorization
                .authorize(&low, &service.start_action, &resource, &context),
            Decision::Deny(DenyReason::InsufficientAssurance)
        );
        assert_eq!(
            service.authorization.authorize(
                &administrator,
                &service.start_action,
                &resource,
                &context
            ),
            Decision::Allow
        );
        Ok(())
    }

    #[test]
    fn start_validation_fails_closed_on_every_security_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let service = service(now)?;
        let administrator = principal(now, AssuranceLevel::Aal2)?;
        let target = ImpersonationTarget {
            subject_id: SubjectId::new(),
            tenant_id: None,
        };
        assert_eq!(
            service.validate_start(&administrator, target, Duration::from_mins(15), now),
            Ok(())
        );
        assert_eq!(
            service.validate_start(
                &principal(now, AssuranceLevel::Aal1)?,
                target,
                Duration::from_mins(15),
                now
            ),
            Err(AdminError::InsufficientAssurance)
        );
        assert_eq!(
            service.validate_start(
                &principal(now - time::Duration::minutes(6), AssuranceLevel::Aal2)?,
                target,
                Duration::from_mins(15),
                now
            ),
            Err(AdminError::StaleAuthentication)
        );
        assert_eq!(
            service.validate_start(
                &principal(now + time::Duration::seconds(1), AssuranceLevel::Aal2)?,
                target,
                Duration::from_mins(15),
                now
            ),
            Err(AdminError::FutureAuthentication)
        );
        assert_eq!(
            service.validate_start(&administrator, target, Duration::ZERO, now),
            Err(AdminError::InvalidLifetime)
        );
        assert_eq!(
            service.validate_start(&administrator, target, Duration::from_mins(16), now),
            Err(AdminError::InvalidLifetime)
        );
        let unauthorized_service =
            service_with_authority(now, Some(AuthorizationContext::default()))?;
        assert_eq!(
            unauthorized_service.validate_start(
                &administrator,
                target,
                Duration::from_mins(15),
                now
            ),
            Err(AdminError::AuthorizationDenied(DenyReason::NotEntitled))
        );
        let unavailable_service = service_with_authority(now, None)?;
        assert_eq!(
            unavailable_service.validate_start(
                &administrator,
                target,
                Duration::from_mins(15),
                now
            ),
            Err(AdminError::AuthorityUnavailable)
        );
        let same_target = ImpersonationTarget {
            subject_id: administrator.subject_id,
            tenant_id: None,
        };
        assert_eq!(
            service.validate_start(&administrator, same_target, Duration::from_mins(15), now),
            Err(AdminError::DistinctSubjectRequired)
        );
        Ok(())
    }
    #[test]
    fn context_is_prominent_expires_and_restricts_sensitive_classes()
    -> Result<(), Box<dyn std::error::Error>> {
        let issued_at = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let context = ImpersonationContext {
            effective_subject_id: SubjectId::new(),
            impersonator_subject_id: SubjectId::new(),
            effective_tenant_id: Some(TenantId::new()),
            reason: AuditReasonCode::new("support.case_42")?,
            issued_at,
            expires_at: issued_at + time::Duration::minutes(15),
        };
        assert_eq!(context.status_label(), "IMPERSONATION ACTIVE");
        assert!(
            context
                .check_operation(ImpersonatedOperation::UserLookup, issued_at)
                .is_ok()
        );
        for operation in [
            ImpersonatedOperation::CredentialManagement,
            ImpersonatedOperation::Payment,
            ImpersonatedOperation::SecurityEnrollment,
        ] {
            assert_eq!(
                context.check_operation(operation, issued_at),
                Err(ImpersonationUseError::Restricted)
            );
        }
        assert_eq!(
            context.check_operation(ImpersonatedOperation::UserLookup, context.expires_at()),
            Err(ImpersonationUseError::Expired)
        );
        Ok(())
    }
}
