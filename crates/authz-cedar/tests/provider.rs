//! Contract tests for validated activation, centralized entities, shadowing, and fail-closed use.

use omnius_auth_core::testing::TestPrincipalFactory;
use omnius_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationRequest,
    AuthorizationService, Decision, DenyReason, Resource, ResourceKind, Role,
};
use omnius_authz_cedar::{
    BundleValidationError, BundleVersion, CedarActivationError, CedarBundleSource, CedarProvider,
    CedarProviderConfig, ValidatedCedarBundle,
};

const SCHEMA: &str = r#"
entity Subject;
entity Role;
entity Tenant;
entity Capability;
entity Human in [Subject, Role, Tenant, Capability] {
    subject: Subject,
    assurance: Long,
    scopes: Set<String>,
    roles: Set<String>,
    tenantMemberships: Set<String>,
    capabilities: Set<String>,
    attributes: Set<String>,
    tenant?: String
};
entity ServiceAccount in [Subject, Role, Tenant, Capability] {
    subject: Subject,
    assurance: Long,
    scopes: Set<String>,
    roles: Set<String>,
    tenantMemberships: Set<String>,
    capabilities: Set<String>,
    attributes: Set<String>,
    tenant?: String
};
entity ProtectedResource in [Subject, Tenant] {
    kind: String,
    owner?: Subject,
    tenant?: String
};
action "record:read" appliesTo {
    principal: [Human, ServiceAccount],
    resource: [ProtectedResource],
    context: {}
};
"#;

const ALLOW_READER: &str = r#"
permit(principal, action == Action::"record:read", resource)
when {
    principal in Role::"reader" &&
    resource has tenant &&
    principal.tenantMemberships.contains(resource.tenant)
};
"#;

const ALLOW_OWNER: &str = r#"
permit(principal, action == Action::"record:read", resource)
when {
    resource has owner &&
    principal.subject == resource.owner
};
"#;

fn source(policies: &str) -> Result<CedarBundleSource, Box<dyn std::error::Error>> {
    Ok(CedarBundleSource {
        schema_version: BundleVersion::new("schema-1")?,
        policy_version: BundleVersion::new("policy-1")?,
        schema: SCHEMA.to_owned(),
        policies: policies.to_owned(),
    })
}

fn enabled(shadow_evaluation: bool) -> CedarProviderConfig {
    CedarProviderConfig {
        enabled: true,
        shadow_evaluation,
    }
}

#[test]
fn validates_schema_and_policies_before_activation() -> Result<(), Box<dyn std::error::Error>> {
    let invalid_policy = r#"
        permit(principal, action, resource)
        when { principal.undeclaredAttribute == "reader" };
    "#;
    assert!(matches!(
        ValidatedCedarBundle::validate(source(invalid_policy)?),
        Err(BundleValidationError::PolicySchemaMismatch)
    ));
    assert!(matches!(
        CedarProvider::activate(enabled(false), source(invalid_policy)?, None),
        Err(CedarActivationError::ActiveBundle)
    ));
    Ok(())
}

#[test]
fn rejects_policy_warnings_and_incompatible_schema_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let impossible = r#"
        permit(principal, action == Action::"record:read", resource)
        when { false };
    "#;
    assert!(matches!(
        ValidatedCedarBundle::validate(source(impossible)?),
        Err(BundleValidationError::PolicyWarning)
    ));

    let incompatible = CedarBundleSource {
        schema: r#"
            entity User;
            entity Resource;
            action "record:read" appliesTo {
                principal: [User],
                resource: [Resource],
                context: {}
            };
        "#
        .to_owned(),
        ..source("")?
    };
    assert!(matches!(
        ValidatedCedarBundle::validate(incompatible),
        Err(BundleValidationError::AdapterContract)
    ));

    let required_optional_facts = CedarBundleSource {
        schema: SCHEMA.replace("tenant?: String", "tenant: String"),
        ..source("")?
    };
    assert!(matches!(
        ValidatedCedarBundle::validate(required_optional_facts),
        Err(BundleValidationError::AdapterContract)
    ));
    Ok(())
}

#[test]
fn centralized_entities_support_relationship_and_tenant_policy()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = TestPrincipalFactory::default().build()?;
    let tenant = principal
        .tenant_id
        .ok_or_else(|| std::io::Error::other("fixture tenant is missing"))?;
    let action = Action::new("record:read")?;
    let resource = Resource::new(ResourceKind::new("record")?).in_tenant(tenant);
    let context = AuthorizationContext::new(
        vec![Role::new("reader")?],
        vec![tenant],
        Vec::new(),
        Vec::new(),
    )?;
    let provider = CedarProvider::activate(enabled(false), source(ALLOW_READER)?, None)?;

    assert_eq!(
        provider.evaluate(AuthorizationRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &context,
        })?,
        Decision::Allow
    );

    let no_roles = AuthorizationContext::default();
    assert_eq!(
        provider.evaluate(AuthorizationRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &no_roles,
        })?,
        Decision::Deny(DenyReason::NotEntitled)
    );
    Ok(())
}

#[test]
fn entity_valued_subject_facts_support_owner_authorization()
-> Result<(), Box<dyn std::error::Error>> {
    let principal = TestPrincipalFactory::default().build()?;
    let action = Action::new("record:read")?;
    let resource = Resource::new(ResourceKind::new("record")?).owned_by(principal.subject_id);
    let provider = CedarProvider::activate(enabled(false), source(ALLOW_OWNER)?, None)?;

    assert_eq!(
        provider.evaluate(AuthorizationRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &AuthorizationContext::default(),
        })?,
        Decision::Allow
    );
    Ok(())
}

#[test]
fn shadow_bundle_never_changes_the_active_decision() -> Result<(), Box<dyn std::error::Error>> {
    let principal = TestPrincipalFactory::default().build()?;
    let tenant = principal
        .tenant_id
        .ok_or_else(|| std::io::Error::other("fixture tenant is missing"))?;
    let action = Action::new("record:read")?;
    let resource = Resource::new(ResourceKind::new("record")?).in_tenant(tenant);
    let context = AuthorizationContext::new(
        vec![Role::new("reader")?],
        vec![tenant],
        Vec::new(),
        Vec::new(),
    )?;
    let provider =
        CedarProvider::activate(enabled(true), source(ALLOW_READER)?, Some(source("")?))?;

    assert_eq!(
        provider.evaluate(AuthorizationRequest {
            principal: &principal,
            action: &action,
            resource: &resource,
            context: &context,
        })?,
        Decision::Allow
    );
    Ok(())
}

#[test]
fn provider_failures_are_denied_by_the_shared_service_boundary()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = CedarProvider::activate(
        CedarProviderConfig {
            enabled: false,
            shadow_evaluation: false,
        },
        source(ALLOW_READER)?,
        None,
    )?;
    let service = AuthorizationService::new(provider);
    let principal = TestPrincipalFactory::default().build()?;
    let action = Action::new("record:read")?;
    let resource = Resource::new(ResourceKind::new("record")?);

    assert_eq!(
        service.authorize(
            &principal,
            &action,
            &resource,
            &AuthorizationContext::default()
        ),
        Decision::Deny(DenyReason::EvaluatorFailure)
    );
    Ok(())
}

#[test]
fn invalid_shadow_bundle_prevents_activation() -> Result<(), Box<dyn std::error::Error>> {
    let invalid_shadow = CedarBundleSource {
        schema: "not a schema".to_owned(),
        ..source("")?
    };
    assert!(matches!(
        CedarProvider::activate(enabled(true), source(ALLOW_READER)?, Some(invalid_shadow)),
        Err(CedarActivationError::ShadowBundle)
    ));
    Ok(())
}
