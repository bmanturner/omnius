//! Security-focused conformance tests for the built-in authorization provider.

use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::{
    Action, AttributeKey, AttributeValue, AuthorizationContext, AuthorizationProvider,
    AuthorizationRequest, AuthorizationService, BasicAuthorizer, BasicPolicy, Capability,
    Condition, Decision, DenyReason, Grant, PolicyMatrix, PolicyRule, Resource, ResourceKind, Role,
};
use time::OffsetDateTime;
use uuid::Uuid;

const SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const OTHER_SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0010);
const OTHER_TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0020);

struct BrokenProvider;

impl AuthorizationProvider for BrokenProvider {
    type Error = ();

    fn evaluate(&self, _request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        Err(())
    }
}

fn subject(value: Uuid) -> Result<SubjectId, Box<dyn std::error::Error>> {
    Ok(SubjectId::from_uuid(value)?)
}

fn tenant(value: Uuid) -> Result<TenantId, Box<dyn std::error::Error>> {
    Ok(TenantId::from_uuid(value)?)
}

fn principal(
    subject_id: Uuid,
    tenant_id: Uuid,
    assurance: AssuranceLevel,
    scopes: &[&str],
) -> Result<Principal, Box<dyn std::error::Error>> {
    Ok(Principal::new(
        subject(subject_id)?,
        PrincipalKind::User,
        Some(tenant(tenant_id)?),
        AuthMethod::Jwt,
        OffsetDateTime::UNIX_EPOCH,
        assurance,
        scopes
            .iter()
            .map(|scope| Scope::new(*scope))
            .collect::<Result<Vec<_>, _>>()?,
    )?)
}

fn document_authorizer()
-> Result<(BasicAuthorizer, Action, ResourceKind), Box<dyn std::error::Error>> {
    let action = Action::new("document:update")?;
    let resource_kind = ResourceKind::new("document")?;
    let rule = PolicyRule::new(
        action.clone(),
        resource_kind.clone(),
        vec![
            Grant::Owner,
            Grant::Role(Role::new("editor")?),
            Grant::AdministrativeCapability(Capability::new("documents:admin")?),
        ],
    )?
    .with_required_scopes(vec![Scope::new("documents:write")?])?
    .with_minimum_assurance(AssuranceLevel::Aal2)
    .requiring_tenant_membership();
    let policy = BasicPolicy::new(PolicyMatrix::new(vec![rule])?);
    Ok((AuthorizationService::new(policy), action, resource_kind))
}

#[test]
fn declared_owner_action_allows_with_all_security_gates() -> Result<(), Box<dyn std::error::Error>>
{
    let (authorizer, action, resource_kind) = document_authorizer()?;
    let principal = principal(SUBJECT, TENANT, AssuranceLevel::Aal2, &["documents:write"])?;
    let resource = Resource::new(resource_kind.clone())
        .owned_by(subject(SUBJECT)?)
        .in_tenant(tenant(TENANT)?);
    let context = AuthorizationContext::new(vec![], vec![tenant(TENANT)?], vec![], vec![])?;

    assert_eq!(
        authorizer.authorize(&principal, &action, &resource, &context),
        Decision::Allow
    );

    let role_context = AuthorizationContext::new(
        vec![Role::new("editor")?],
        vec![tenant(TENANT)?],
        vec![],
        vec![],
    )?;
    let resource_without_owner = Resource::new(resource_kind).in_tenant(tenant(TENANT)?);
    assert_eq!(
        authorizer.authorize(&principal, &action, &resource_without_owner, &role_context,),
        Decision::Allow
    );
    Ok(())
}

#[test]
fn horizontal_access_to_another_owners_resource_denies() -> Result<(), Box<dyn std::error::Error>> {
    let action = Action::new("document:update")?;
    let resource_kind = ResourceKind::new("document")?;
    let rule = PolicyRule::new(action.clone(), resource_kind.clone(), vec![Grant::Owner])?
        .requiring_tenant_membership();
    let authorizer = AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
    let principal = principal(SUBJECT, TENANT, AssuranceLevel::Aal1, &[])?;
    let resource = Resource::new(resource_kind)
        .owned_by(subject(OTHER_SUBJECT)?)
        .in_tenant(tenant(TENANT)?);
    let context = AuthorizationContext::new(vec![], vec![tenant(TENANT)?], vec![], vec![])?;

    assert_eq!(
        authorizer.authorize(&principal, &action, &resource, &context),
        Decision::Deny(DenyReason::NotEntitled)
    );
    Ok(())
}

#[test]
fn vertical_role_scope_and_assurance_escalations_deny() -> Result<(), Box<dyn std::error::Error>> {
    let (authorizer, action, resource_kind) = document_authorizer()?;
    let resource = Resource::new(resource_kind)
        .owned_by(subject(OTHER_SUBJECT)?)
        .in_tenant(tenant(TENANT)?);
    let member_context = AuthorizationContext::new(vec![], vec![tenant(TENANT)?], vec![], vec![])?;

    let no_scope = principal(SUBJECT, TENANT, AssuranceLevel::Aal2, &[])?;
    assert_eq!(
        authorizer.authorize(&no_scope, &action, &resource, &member_context),
        Decision::Deny(DenyReason::InsufficientScope)
    );

    let low_assurance = principal(SUBJECT, TENANT, AssuranceLevel::Aal1, &["documents:write"])?;
    assert_eq!(
        authorizer.authorize(&low_assurance, &action, &resource, &member_context),
        Decision::Deny(DenyReason::InsufficientAssurance)
    );

    let not_entitled = principal(SUBJECT, TENANT, AssuranceLevel::Aal2, &["documents:write"])?;
    assert_eq!(
        authorizer.authorize(&not_entitled, &action, &resource, &member_context),
        Decision::Deny(DenyReason::NotEntitled)
    );
    Ok(())
}

#[test]
fn cross_tenant_and_missing_resource_context_deny() -> Result<(), Box<dyn std::error::Error>> {
    let (authorizer, action, resource_kind) = document_authorizer()?;
    let principal = principal(SUBJECT, TENANT, AssuranceLevel::Aal2, &["documents:write"])?;
    let membership = AuthorizationContext::new(
        vec![Role::new("editor")?],
        vec![tenant(TENANT)?, tenant(OTHER_TENANT)?],
        vec![],
        vec![],
    )?;

    let cross_tenant = Resource::new(resource_kind.clone())
        .owned_by(subject(SUBJECT)?)
        .in_tenant(tenant(OTHER_TENANT)?);
    assert_eq!(
        authorizer.authorize(&principal, &action, &cross_tenant, &membership),
        Decision::Deny(DenyReason::TenantMismatch)
    );

    let missing_tenant = Resource::new(resource_kind.clone()).owned_by(subject(SUBJECT)?);
    assert_eq!(
        authorizer.authorize(&principal, &action, &missing_tenant, &membership),
        Decision::Deny(DenyReason::MissingTenantContext)
    );

    let no_memberships = AuthorizationContext::default();
    let tenant_resource = Resource::new(resource_kind.clone())
        .owned_by(subject(SUBJECT)?)
        .in_tenant(tenant(TENANT)?);
    assert_eq!(
        authorizer.authorize(&principal, &action, &tenant_resource, &no_memberships),
        Decision::Deny(DenyReason::NotTenantMember)
    );

    let missing_owner = Resource::new(resource_kind).in_tenant(tenant(TENANT)?);
    let member_without_role =
        AuthorizationContext::new(vec![], vec![tenant(TENANT)?], vec![], vec![])?;
    assert_eq!(
        authorizer.authorize(&principal, &action, &missing_owner, &member_without_role,),
        Decision::Deny(DenyReason::MissingResourceContext)
    );
    Ok(())
}
#[test]
fn role_capability_and_bounded_condition_paths_are_enforced()
-> Result<(), Box<dyn std::error::Error>> {
    let action = Action::new("document:publish")?;
    let resource_kind = ResourceKind::new("document")?;
    let condition = Condition::equals(
        AttributeKey::new("release_channel")?,
        AttributeValue::new("production")?,
    );
    let rule = PolicyRule::new(
        action.clone(),
        resource_kind.clone(),
        vec![
            Grant::Role(Role::new("publisher")?),
            Grant::AdministrativeCapability(Capability::new("documents:admin")?),
        ],
    )?
    .with_condition(condition)?;
    let authorizer = AuthorizationService::new(BasicPolicy::new(PolicyMatrix::new(vec![rule])?));
    let principal = principal(SUBJECT, TENANT, AssuranceLevel::Aal1, &[])?;
    let resource = Resource::new(resource_kind);

    let role_context = AuthorizationContext::new(
        vec![Role::new("publisher")?],
        vec![],
        vec![],
        vec![(
            AttributeKey::new("release_channel")?,
            AttributeValue::new("production")?,
        )],
    )?;
    assert_eq!(
        authorizer.authorize(&principal, &action, &resource, &role_context),
        Decision::Allow
    );

    let capability_context = AuthorizationContext::new(
        vec![],
        vec![],
        vec![Capability::new("documents:admin")?],
        vec![(
            AttributeKey::new("release_channel")?,
            AttributeValue::new("production")?,
        )],
    )?;
    assert_eq!(
        authorizer.authorize(&principal, &action, &resource, &capability_context),
        Decision::Allow
    );

    let wrong_condition = AuthorizationContext::new(
        vec![Role::new("publisher")?],
        vec![],
        vec![],
        vec![(
            AttributeKey::new("release_channel")?,
            AttributeValue::new("preview")?,
        )],
    )?;
    assert_eq!(
        authorizer.authorize(&principal, &action, &resource, &wrong_condition),
        Decision::Deny(DenyReason::ContextCondition)
    );
    Ok(())
}

#[test]
fn unknown_action_missing_policy_and_provider_failure_deny()
-> Result<(), Box<dyn std::error::Error>> {
    let (authorizer, action, resource_kind) = document_authorizer()?;
    let principal = principal(SUBJECT, TENANT, AssuranceLevel::Aal2, &["documents:write"])?;
    let context = AuthorizationContext::new(vec![], vec![tenant(TENANT)?], vec![], vec![])?;
    let resource = Resource::new(resource_kind)
        .owned_by(subject(SUBJECT)?)
        .in_tenant(tenant(TENANT)?);

    assert_eq!(
        authorizer.authorize(
            &principal,
            &Action::new("document:delete")?,
            &resource,
            &context,
        ),
        Decision::Deny(DenyReason::UnknownAction)
    );
    assert_eq!(
        authorizer.authorize(
            &principal,
            &action,
            &Resource::new(ResourceKind::new("organization")?),
            &context,
        ),
        Decision::Deny(DenyReason::MissingPolicy)
    );

    let broken = AuthorizationService::new(BrokenProvider);
    assert_eq!(
        broken.authorize(&principal, &action, &resource, &context),
        Decision::Deny(DenyReason::EvaluatorFailure)
    );
    Ok(())
}
