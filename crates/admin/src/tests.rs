use super::*;
use omnius_auth_core::{AuthMethod, Scope};
use omnius_authz_basic::{BasicPolicy, PolicyMatrix};
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
) -> Result<AdminService<BasicPolicy, FixedAuthority, TestOperations>, Box<dyn std::error::Error>> {
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
) -> Result<AdminService<BasicPolicy, FixedAuthority, TestOperations>, Box<dyn std::error::Error>> {
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
fn target_constructors_require_canonical_human_scope() -> Result<(), Box<dyn std::error::Error>> {
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
        service
            .authorization
            .authorize(&administrator, &service.start_action, &resource, &empty),
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
        service
            .authorization
            .authorize(&administrator, &service.start_action, &resource, &context),
        Decision::Allow
    );
    Ok(())
}

#[test]
fn start_validation_fails_closed_on_every_security_gate() -> Result<(), Box<dyn std::error::Error>>
{
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
    let unauthorized_service = service_with_authority(now, Some(AuthorizationContext::default()))?;
    assert_eq!(
        unauthorized_service.validate_start(&administrator, target, Duration::from_mins(15), now),
        Err(AdminError::AuthorizationDenied(DenyReason::NotEntitled))
    );
    let unavailable_service = service_with_authority(now, None)?;
    assert_eq!(
        unavailable_service.validate_start(&administrator, target, Duration::from_mins(15), now),
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
