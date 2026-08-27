//! Fail-closed, service-layer authorization for roles, ownership, tenants, scopes, and assurance.
//!
//! Transport adapters authenticate callers, then application services pass the canonical
//! [`Principal`] and resource facts to [`AuthorizationService::authorize`]. This keeps the same
//! policy boundary available to HTTP, jobs, CLI, GraphQL, gRPC, and realtime transports.

use std::{collections::BTreeMap, convert::Infallible, fmt, str::FromStr};

use metrics::counter;
use omnius_auth_core::{AssuranceLevel, Principal, Scope, SubjectId, TenantId};
use serde::Serialize;
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ATTRIBUTE_VALUE_BYTES: usize = 256;
const MAX_RULES: usize = 512;
const MAX_GRANTS: usize = 32;
const MAX_RULE_SCOPES: usize = 128;
const MAX_CONDITIONS: usize = 32;
const MAX_CONTEXT_ITEMS: usize = 128;
const MAX_ATTRIBUTES: usize = 32;

/// A bounded policy identifier was invalid.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum IdentifierError {
    /// The identifier was empty.
    #[error("policy identifier must not be empty")]
    Empty,
    /// The identifier exceeded 128 bytes.
    #[error("policy identifier exceeds 128 bytes")]
    TooLong,
    /// The identifier contained a character outside the portable policy grammar.
    #[error("policy identifier contains an invalid character")]
    InvalidCharacter,
}

fn validate_identifier(value: &str) -> Result<(), IdentifierError> {
    if value.is_empty() {
        return Err(IdentifierError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentifierError::TooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'.' | b'_' | b'-'))
    {
        return Err(IdentifierError::InvalidCharacter);
    }
    Ok(())
}

macro_rules! policy_identifier {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and owns the identifier.
            ///
            /// # Errors
            ///
            /// Returns [`IdentifierError`] for empty, oversized, or non-portable values.
            pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Returns the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdentifierError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

policy_identifier!(Action, "A declared application-service operation.");
policy_identifier!(ResourceKind, "A declared class of protected resource.");
policy_identifier!(Role, "A role considered by the built-in policy.");
policy_identifier!(
    Capability,
    "An administrative capability considered by the built-in policy."
);
policy_identifier!(AttributeKey, "A bounded contextual attribute name.");

/// A bounded contextual attribute value.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttributeValue(String);

impl AttributeValue {
    /// Validates and owns an attribute value.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when the value is empty, exceeds 256 bytes, or contains a
    /// control character.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if value.len() > MAX_ATTRIBUTE_VALUE_BYTES {
            return Err(IdentifierError::TooLong);
        }
        if value.chars().any(char::is_control) {
            return Err(IdentifierError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the value as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One way a principal may be entitled to perform an action.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Grant {
    /// The authorization context contains this role.
    Role(Role),
    /// The principal owns the target resource.
    Owner,
    /// The authorization context contains this administrative capability.
    AdministrativeCapability(Capability),
}

/// A bounded contextual equality condition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Condition {
    key: AttributeKey,
    value: AttributeValue,
}

impl Condition {
    /// Creates an equality condition.
    #[must_use]
    pub const fn equals(key: AttributeKey, value: AttributeValue) -> Self {
        Self { key, value }
    }
}

/// An invalid built-in policy matrix.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// A rule did not contain an entitlement path.
    #[error("authorization rule must declare at least one grant")]
    MissingGrant,
    /// A bounded policy collection exceeded its limit.
    #[error("authorization policy exceeds a bounded collection limit")]
    CollectionLimit,
    /// More than one rule declared the same action and resource kind.
    #[error("authorization policy contains a duplicate action/resource rule")]
    DuplicateRule,
}

/// A machine-readable permission-matrix row.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyRule {
    action: Action,
    resource_kind: ResourceKind,
    grants: Vec<Grant>,
    required_scopes: Vec<Scope>,
    minimum_assurance: AssuranceLevel,
    require_tenant_membership: bool,
    conditions: Vec<Condition>,
}

impl PolicyRule {
    /// Creates a rule with one or more alternative grant paths.
    ///
    /// Scopes, tenant membership, assurance, and conditions are gates applied before grants.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] when no grant is supplied or the grant bound is exceeded.
    pub fn new(
        action: Action,
        resource_kind: ResourceKind,
        mut grants: Vec<Grant>,
    ) -> Result<Self, PolicyError> {
        grants.sort_unstable();
        grants.dedup();
        if grants.is_empty() {
            return Err(PolicyError::MissingGrant);
        }
        if grants.len() > MAX_GRANTS {
            return Err(PolicyError::CollectionLimit);
        }
        Ok(Self {
            action,
            resource_kind,
            grants,
            required_scopes: Vec::new(),
            minimum_assurance: AssuranceLevel::Aal1,
            require_tenant_membership: false,
            conditions: Vec::new(),
        })
    }

    /// Requires all listed API scopes.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CollectionLimit`] for more than 128 distinct scopes.
    pub fn with_required_scopes(mut self, mut scopes: Vec<Scope>) -> Result<Self, PolicyError> {
        scopes.sort_unstable();
        scopes.dedup();
        if scopes.len() > MAX_RULE_SCOPES {
            return Err(PolicyError::CollectionLimit);
        }
        self.required_scopes = scopes;
        Ok(self)
    }

    /// Requires at least the supplied authentication assurance level.
    #[must_use]
    pub const fn with_minimum_assurance(mut self, assurance: AssuranceLevel) -> Self {
        self.minimum_assurance = assurance;
        self
    }

    /// Requires the principal's active tenant and authoritative membership to match the resource.
    #[must_use]
    pub const fn requiring_tenant_membership(mut self) -> Self {
        self.require_tenant_membership = true;
        self
    }

    /// Requires a bounded contextual equality condition.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::CollectionLimit`] after 32 conditions.
    pub fn with_condition(mut self, condition: Condition) -> Result<Self, PolicyError> {
        if self.conditions.len() >= MAX_CONDITIONS {
            return Err(PolicyError::CollectionLimit);
        }
        self.conditions.push(condition);
        Ok(self)
    }

    /// Returns the declared action.
    #[must_use]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the declared resource kind.
    #[must_use]
    pub const fn resource_kind(&self) -> &ResourceKind {
        &self.resource_kind
    }
}

/// The validated, machine-readable built-in permission matrix.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PolicyMatrix(Vec<PolicyRule>);

impl PolicyMatrix {
    /// Validates a permission matrix.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] for more than 512 rules or a duplicate action/resource pair.
    pub fn new(mut rules: Vec<PolicyRule>) -> Result<Self, PolicyError> {
        if rules.len() > MAX_RULES {
            return Err(PolicyError::CollectionLimit);
        }
        rules.sort_unstable_by(|left, right| {
            (&left.action, &left.resource_kind).cmp(&(&right.action, &right.resource_kind))
        });
        if rules.windows(2).any(|pair| {
            pair[0].action == pair[1].action && pair[0].resource_kind == pair[1].resource_kind
        }) {
            return Err(PolicyError::DuplicateRule);
        }
        Ok(Self(rules))
    }

    /// Returns the permission-matrix rows in stable action/resource order.
    #[must_use]
    pub fn rules(&self) -> &[PolicyRule] {
        &self.0
    }
}

/// Facts about the target resource required for authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    /// The declared resource class.
    pub kind: ResourceKind,
    /// The owning subject when ownership rules apply.
    pub owner_id: Option<SubjectId>,
    /// The tenant containing the resource when tenant rules apply.
    pub tenant_id: Option<TenantId>,
}

impl Resource {
    /// Creates a resource with no ownership or tenant facts.
    #[must_use]
    pub const fn new(kind: ResourceKind) -> Self {
        Self {
            kind,
            owner_id: None,
            tenant_id: None,
        }
    }

    /// Attaches the canonical owning subject.
    #[must_use]
    pub const fn owned_by(mut self, owner_id: SubjectId) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    /// Attaches the canonical containing tenant.
    #[must_use]
    pub const fn in_tenant(mut self, tenant_id: TenantId) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }
}

/// Invalid or excessive authoritative context supplied to the evaluator.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("authorization context exceeds a bounded collection limit")]
pub struct ContextError;

/// Authoritative request facts that do not belong in authentication credentials.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorizationContext {
    roles: Vec<Role>,
    tenant_memberships: Vec<TenantId>,
    administrative_capabilities: Vec<Capability>,
    attributes: Vec<(AttributeKey, AttributeValue)>,
}

impl AuthorizationContext {
    /// Creates normalized, bounded authorization context.
    ///
    /// Duplicate values are removed. Duplicate attribute keys retain the last supplied value.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when a normalized collection exceeds its fixed bound.
    pub fn new(
        mut roles: Vec<Role>,
        mut tenant_memberships: Vec<TenantId>,
        mut administrative_capabilities: Vec<Capability>,
        attributes: Vec<(AttributeKey, AttributeValue)>,
    ) -> Result<Self, ContextError> {
        roles.sort_unstable();
        roles.dedup();
        tenant_memberships.sort_unstable();
        tenant_memberships.dedup();
        administrative_capabilities.sort_unstable();
        administrative_capabilities.dedup();

        let attributes = attributes
            .into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect::<Vec<_>>();

        if roles.len() > MAX_CONTEXT_ITEMS
            || tenant_memberships.len() > MAX_CONTEXT_ITEMS
            || administrative_capabilities.len() > MAX_CONTEXT_ITEMS
            || attributes.len() > MAX_ATTRIBUTES
        {
            return Err(ContextError);
        }

        Ok(Self {
            roles,
            tenant_memberships,
            administrative_capabilities,
            attributes,
        })
    }

    /// Returns the normalized roles in stable order.
    #[must_use]
    pub fn roles(&self) -> &[Role] {
        &self.roles
    }

    /// Returns the authoritative tenant memberships in stable order.
    #[must_use]
    pub fn tenant_memberships(&self) -> &[TenantId] {
        &self.tenant_memberships
    }

    /// Returns the administrative capabilities in stable order.
    #[must_use]
    pub fn administrative_capabilities(&self) -> &[Capability] {
        &self.administrative_capabilities
    }

    /// Returns the bounded contextual attributes in stable key order.
    #[must_use]
    pub fn attributes(&self) -> &[(AttributeKey, AttributeValue)] {
        &self.attributes
    }

    /// Looks up one bounded contextual attribute.
    #[must_use]
    pub fn attribute(&self, key: &AttributeKey) -> Option<&AttributeValue> {
        self.attributes
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|index| &self.attributes[index].1)
    }
}

/// A complete service-layer authorization request.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizationRequest<'a> {
    /// The canonical authenticated identity.
    pub principal: &'a Principal,
    /// The declared service operation.
    pub action: &'a Action,
    /// Authoritative facts about the target resource.
    pub resource: &'a Resource,
    /// Authoritative roles, memberships, capabilities, and bounded conditions.
    pub context: &'a AuthorizationContext,
}

/// A stable, low-cardinality reason for a denied decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// No matrix row declares the action.
    UnknownAction,
    /// The action is known but has no policy for this resource kind.
    MissingPolicy,
    /// An ownership policy was evaluated without authoritative owner data.
    MissingResourceContext,
    /// A tenant policy was evaluated without an authoritative resource tenant.
    MissingTenantContext,
    /// The principal's active tenant differs from the resource tenant.
    TenantMismatch,
    /// Authoritative membership does not include the resource tenant.
    NotTenantMember,
    /// The credential lacks at least one required API scope.
    InsufficientScope,
    /// Authentication assurance is below the rule's minimum.
    InsufficientAssurance,
    /// A required bounded contextual condition is absent or unequal.
    ContextCondition,
    /// No role, ownership, or administrative-capability grant matched.
    NotEntitled,
    /// The configured provider failed to evaluate the request.
    EvaluatorFailure,
}

impl DenyReason {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::UnknownAction => "unknown_action",
            Self::MissingPolicy => "missing_policy",
            Self::MissingResourceContext => "missing_resource_context",
            Self::MissingTenantContext => "missing_tenant_context",
            Self::TenantMismatch => "tenant_mismatch",
            Self::NotTenantMember => "not_tenant_member",
            Self::InsufficientScope => "insufficient_scope",
            Self::InsufficientAssurance => "insufficient_assurance",
            Self::ContextCondition => "context_condition",
            Self::NotEntitled => "not_entitled",
            Self::EvaluatorFailure => "evaluator_failure",
        }
    }
}

/// A fail-closed authorization decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "decision", content = "reason")]
pub enum Decision {
    /// The request is authorized.
    Allow,
    /// The request is rejected for a stable reason.
    Deny(DenyReason),
}

/// A pluggable policy evaluator. Provider errors are converted to deny by the service boundary.
pub trait AuthorizationProvider {
    /// Provider-specific evaluation failure.
    type Error;

    /// Evaluates a complete authorization request.
    ///
    /// # Errors
    ///
    /// Returns a provider-specific error when evaluation cannot produce a trustworthy decision.
    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error>;
}

/// The transport-independent authorization boundary used by application services.
#[derive(Clone, Debug)]
pub struct AuthorizationService<P> {
    provider: P,
}

impl<P> AuthorizationService<P>
where
    P: AuthorizationProvider,
{
    /// Wraps an authorization provider with fail-closed behavior and bounded decision metrics.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Authorizes `principal`, `action`, `resource`, and `context`.
    ///
    /// Provider failure always becomes [`DenyReason::EvaluatorFailure`]. Metrics contain only
    /// fixed outcome and reason labels; subject, tenant, action, and resource values are omitted.
    #[must_use]
    pub fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        context: &AuthorizationContext,
    ) -> Decision {
        let request = AuthorizationRequest {
            principal,
            action,
            resource,
            context,
        };
        let decision = self
            .provider
            .evaluate(request)
            .unwrap_or(Decision::Deny(DenyReason::EvaluatorFailure));
        record_decision(decision);
        decision
    }
}

fn record_decision(decision: Decision) {
    match decision {
        Decision::Allow => counter!(
            "authorization_decisions_total",
            "outcome" => "allow",
            "reason" => "none"
        )
        .increment(1),
        Decision::Deny(reason) => counter!(
            "authorization_decisions_total",
            "outcome" => "deny",
            "reason" => reason.metric_label()
        )
        .increment(1),
    }
}

/// The built-in policy provider.
#[derive(Clone, Debug)]
pub struct BasicPolicy {
    matrix: PolicyMatrix,
}

impl BasicPolicy {
    /// Creates the built-in provider from a validated machine-readable matrix.
    #[must_use]
    pub const fn new(matrix: PolicyMatrix) -> Self {
        Self { matrix }
    }

    /// Returns the active permission matrix.
    #[must_use]
    pub const fn matrix(&self) -> &PolicyMatrix {
        &self.matrix
    }
}

impl AuthorizationProvider for BasicPolicy {
    type Error = Infallible;

    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        Ok(evaluate_matrix(&self.matrix, request))
    }
}

/// The built-in authorization service.
pub type BasicAuthorizer = AuthorizationService<BasicPolicy>;

fn evaluate_matrix(matrix: &PolicyMatrix, request: AuthorizationRequest<'_>) -> Decision {
    let Some(rule) = matrix
        .rules()
        .iter()
        .find(|rule| rule.action == *request.action && rule.resource_kind == request.resource.kind)
    else {
        return if matrix
            .rules()
            .iter()
            .any(|rule| rule.action == *request.action)
        {
            Decision::Deny(DenyReason::MissingPolicy)
        } else {
            Decision::Deny(DenyReason::UnknownAction)
        };
    };

    if rule
        .required_scopes
        .iter()
        .any(|required| request.principal.scopes.binary_search(required).is_err())
    {
        return Decision::Deny(DenyReason::InsufficientScope);
    }
    if request.principal.assurance < rule.minimum_assurance {
        return Decision::Deny(DenyReason::InsufficientAssurance);
    }
    if rule
        .conditions
        .iter()
        .any(|condition| request.context.attribute(&condition.key) != Some(&condition.value))
    {
        return Decision::Deny(DenyReason::ContextCondition);
    }

    if rule.require_tenant_membership {
        let Some(tenant_id) = request.resource.tenant_id else {
            return Decision::Deny(DenyReason::MissingTenantContext);
        };
        if request.principal.tenant_id != Some(tenant_id) {
            return Decision::Deny(DenyReason::TenantMismatch);
        }
        if request
            .context
            .tenant_memberships
            .binary_search(&tenant_id)
            .is_err()
        {
            return Decision::Deny(DenyReason::NotTenantMember);
        }
    }

    let has_owner_grant = rule.grants.contains(&Grant::Owner);
    let entitled = rule.grants.iter().any(|grant| match grant {
        Grant::Role(required_role) => request.context.roles.binary_search(required_role).is_ok(),
        Grant::Owner => request.resource.owner_id == Some(request.principal.subject_id),
        Grant::AdministrativeCapability(capability) => request
            .context
            .administrative_capabilities
            .binary_search(capability)
            .is_ok(),
    });

    if entitled {
        Decision::Allow
    } else if has_owner_grant && request.resource.owner_id.is_none() {
        Decision::Deny(DenyReason::MissingResourceContext)
    } else {
        Decision::Deny(DenyReason::NotEntitled)
    }
}
