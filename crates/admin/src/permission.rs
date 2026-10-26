use omnius_auth_core::AssuranceLevel;
use omnius_authz_basic::{
    Action, Capability, Grant, IdentifierError, PolicyError, PolicyRule, ResourceKind,
};
use thiserror::Error;

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
    /// Read content-free LLM usage and audit reconciliation projections.
    LlmUsageView,
    /// Display one policy-enabled, redacted diagnostic capture through the protected seam.
    LlmDiagnosticCaptureView,
    /// Start a bounded impersonation context.
    StartImpersonation,
    /// End an impersonation context.
    EndImpersonation,
}

impl AdminPermission {
    const ALL: [Self; 15] = [
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
        Self::LlmUsageView,
        Self::LlmDiagnosticCaptureView,
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
            Self::LlmUsageView => "admin:llm:usage:view",
            Self::LlmDiagnosticCaptureView => "admin:llm:diagnostic_capture:view",
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
            Self::LlmUsageView => "admin_llm_usage_view",
            Self::LlmDiagnosticCaptureView => "admin_llm_diagnostic_capture_view",
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
            Self::LlmUsageView => "admin_llm_usage",
            Self::LlmDiagnosticCaptureView => "admin_llm_diagnostic_capture",
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
