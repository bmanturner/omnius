//! Validated Cedar authorization with centralized entity construction and optional shadow rollout.
//!
//! Policy bundles use Cedar schema syntax and the following entity contract:
//! `Human` and `ServiceAccount` principals, `ProtectedResource` resources, and `Subject`, `Role`,
//! `Tenant`, and `Capability` relationship entities. Principal attributes are `subject`,
//! `assurance`, `scopes`, `roles`, `tenantMemberships`, `capabilities`, `attributes`, and optional
//! `tenant`; resource attributes are `kind`, optional entity-valued `owner`, and optional `tenant`.
//! A contextual attribute is encoded as one `key=value` string. Application invariants remain
//! outside Cedar.

use std::{collections::BTreeSet, str::FromStr};

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    Schema, ValidationMode, Validator,
};
use metrics::counter;
use omnius_auth_core::{AssuranceLevel, PrincipalKind};
use omnius_authz_basic::{
    AuthorizationProvider, AuthorizationRequest, Decision, DenyReason, IdentifierError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

const MAX_VERSION_BYTES: usize = 64;
const DECISION_METRIC: &str = "omnius_authz_cedar_decisions_total";
const SHADOW_METRIC: &str = "omnius_authz_cedar_shadow_evaluations_total";

/// A bounded version identifying a Cedar schema or policy set.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct BundleVersion(String);

impl BundleVersion {
    /// Validates and owns a bundle version.
    ///
    /// # Errors
    ///
    /// Returns [`IdentifierError`] when the version is empty, exceeds 64 bytes, or contains a
    /// character outside the portable identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentifierError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentifierError::Empty);
        }
        if value.len() > MAX_VERSION_BYTES {
            return Err(IdentifierError::TooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(IdentifierError::InvalidCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the version as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for BundleVersion {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// An untrusted Cedar schema and policy source loaded from persistence or a policy provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CedarBundleSource {
    /// Version of the entity and action schema.
    pub schema_version: BundleVersion,
    /// Version of the policy set.
    pub policy_version: BundleVersion,
    /// Cedar schema-language source.
    pub schema: String,
    /// Cedar policy-language source.
    pub policies: String,
}

/// A policy bundle failed validation before activation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BundleValidationError {
    /// The Cedar schema could not be parsed.
    #[error("Cedar schema is invalid")]
    InvalidSchema,
    /// The schema produced warnings and was rejected by strict activation.
    #[error("Cedar schema produced validation warnings")]
    SchemaWarning,
    /// The Cedar policies could not be parsed.
    #[error("Cedar policy set is invalid")]
    InvalidPolicy,
    /// The policies did not typecheck against the schema.
    #[error("Cedar policy set does not validate against its schema")]
    PolicySchemaMismatch,
    /// The policies typechecked but produced warnings under strict validation.
    #[error("Cedar policy set produced validation warnings")]
    PolicyWarning,
    /// The schema cannot represent the adapter's canonical entities and request shape.
    #[error("Cedar schema does not implement the authorization adapter contract")]
    AdapterContract,
}

/// A parsed, schema-checked Cedar bundle safe to activate.
#[derive(Clone, Debug)]
pub struct ValidatedCedarBundle {
    schema_version: BundleVersion,
    policy_version: BundleVersion,
    schema: Schema,
    policies: PolicySet,
}

impl ValidatedCedarBundle {
    /// Parses and strictly validates a bundle before it can be activated.
    ///
    /// # Errors
    ///
    /// Returns [`BundleValidationError`] for schema syntax or warnings, policy syntax, policy
    /// validation errors or warnings, or an incompatible adapter schema contract.
    pub fn validate(source: CedarBundleSource) -> Result<Self, BundleValidationError> {
        let (schema, warnings) = Schema::from_cedarschema_str(&source.schema)
            .map_err(|_| BundleValidationError::InvalidSchema)?;
        if warnings.into_iter().next().is_some() {
            return Err(BundleValidationError::SchemaWarning);
        }
        let policies = source
            .policies
            .parse::<PolicySet>()
            .map_err(|_| BundleValidationError::InvalidPolicy)?;
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(BundleValidationError::PolicySchemaMismatch);
        }
        if !validation.validation_passed_without_warnings() {
            return Err(BundleValidationError::PolicyWarning);
        }
        validate_schema_contract(&schema)?;
        Ok(Self {
            schema_version: source.schema_version,
            policy_version: source.policy_version,
            schema,
            policies,
        })
    }

    /// Returns the activated schema version.
    #[must_use]
    pub const fn schema_version(&self) -> &BundleVersion {
        &self.schema_version
    }

    /// Returns the activated policy version.
    #[must_use]
    pub const fn policy_version(&self) -> &BundleVersion {
        &self.policy_version
    }
}

/// Runtime behavior for the optional Cedar provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CedarProviderConfig {
    /// Whether Cedar evaluation is enabled.
    pub enabled: bool,
    /// Whether a supplied shadow bundle should be evaluated without enforcing its result.
    pub shadow_evaluation: bool,
}

/// A Cedar provider could not be activated.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CedarActivationError {
    /// The active policy bundle was invalid.
    #[error("active Cedar bundle failed validation")]
    ActiveBundle,
    /// The shadow policy bundle was invalid.
    #[error("shadow Cedar bundle failed validation")]
    ShadowBundle,
    /// Shadow evaluation was enabled without a shadow bundle.
    #[error("shadow evaluation requires a shadow Cedar bundle")]
    MissingShadowBundle,
    /// A shadow bundle was supplied while shadow evaluation was disabled.
    #[error("shadow Cedar bundle supplied while shadow evaluation is disabled")]
    UnexpectedShadowBundle,
}

/// A Cedar request could not produce a trustworthy decision.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CedarEvaluationError {
    /// The runtime toggle disabled this optional provider.
    #[error("Cedar authorization provider is disabled")]
    Disabled,
    /// Canonical authorization facts did not conform to the active schema.
    #[error("Cedar entity construction failed")]
    EntityConstruction,
    /// The request did not conform to the active schema.
    #[error("Cedar request construction failed")]
    RequestConstruction,
    /// Cedar reported a policy evaluation error.
    #[error("Cedar policy evaluation failed")]
    Evaluation,
}

/// Validated Cedar implementation of the shared service-layer authorization provider seam.
#[derive(Clone, Debug)]
pub struct CedarProvider {
    config: CedarProviderConfig,
    active: ValidatedCedarBundle,
    shadow: Option<ValidatedCedarBundle>,
}

impl CedarProvider {
    /// Validates every configured bundle and atomically constructs an activatable provider.
    ///
    /// # Errors
    ///
    /// Returns [`CedarActivationError`] when a bundle is invalid or shadow configuration is
    /// inconsistent. No invalid bundle can be installed in a provider.
    pub fn activate(
        config: CedarProviderConfig,
        active: CedarBundleSource,
        shadow: Option<CedarBundleSource>,
    ) -> Result<Self, CedarActivationError> {
        match (config.shadow_evaluation, shadow.is_some()) {
            (true, false) => return Err(CedarActivationError::MissingShadowBundle),
            (false, true) => return Err(CedarActivationError::UnexpectedShadowBundle),
            _ => {}
        }
        let active = ValidatedCedarBundle::validate(active)
            .map_err(|_| CedarActivationError::ActiveBundle)?;
        let shadow = shadow
            .map(ValidatedCedarBundle::validate)
            .transpose()
            .map_err(|_| CedarActivationError::ShadowBundle)?;
        Ok(Self {
            config,
            active,
            shadow,
        })
    }

    /// Returns the active validated bundle.
    #[must_use]
    pub const fn active_bundle(&self) -> &ValidatedCedarBundle {
        &self.active
    }

    fn evaluate_bundle(
        bundle: &ValidatedCedarBundle,
        request: AuthorizationRequest<'_>,
    ) -> Result<Decision, CedarEvaluationError> {
        let (principal, resource, entities) = cedar_entities(request, &bundle.schema)?;
        let action = entity_uid("Action", request.action.as_str())
            .ok_or(CedarEvaluationError::RequestConstruction)?;
        let request = Request::new(
            principal,
            action,
            resource,
            Context::empty(),
            Some(&bundle.schema),
        )
        .map_err(|_| CedarEvaluationError::RequestConstruction)?;
        let response = Authorizer::new().is_authorized(&request, &bundle.policies, &entities);
        if response.diagnostics().errors().next().is_some() {
            return Err(CedarEvaluationError::Evaluation);
        }
        Ok(match response.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny => Decision::Deny(DenyReason::NotEntitled),
        })
    }
}

impl AuthorizationProvider for CedarProvider {
    type Error = CedarEvaluationError;

    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        if !self.config.enabled {
            counter!(DECISION_METRIC, "outcome" => "error").increment(1);
            return Err(CedarEvaluationError::Disabled);
        }

        let active = Self::evaluate_bundle(&self.active, request);
        match active {
            Ok(decision) => {
                counter!(
                    DECISION_METRIC,
                    "outcome" => match decision {
                        Decision::Allow => "allow",
                        Decision::Deny(_) => "deny",
                    }
                )
                .increment(1);
                if let Some(shadow) = &self.shadow {
                    let alignment = match Self::evaluate_bundle(shadow, request) {
                        Ok(shadow_decision) if shadow_decision == decision => "match",
                        Ok(_) => "mismatch",
                        Err(_) => "error",
                    };
                    counter!(SHADOW_METRIC, "alignment" => alignment).increment(1);
                }
                Ok(decision)
            }
            Err(error) => {
                counter!(DECISION_METRIC, "outcome" => "error").increment(1);
                Err(error)
            }
        }
    }
}

fn validate_schema_contract(schema: &Schema) -> Result<(), BundleValidationError> {
    let subject = entity_ref("Subject", "subject");
    let relationship_parents = vec![
        subject.clone(),
        entity_ref("Role", "role"),
        entity_ref("Tenant", "tenant"),
        entity_ref("Capability", "capability"),
    ];
    let principal_attrs = json!({
        "subject": subject,
        "assurance": 1,
        "scopes": ["scope"],
        "roles": ["role"],
        "tenantMemberships": ["tenant"],
        "capabilities": ["capability"],
        "attributes": ["key=value"],
        "tenant": "tenant",
    });
    let mut principal_attrs_without_tenant = principal_attrs.clone();
    let Value::Object(attrs_without_tenant) = &mut principal_attrs_without_tenant else {
        return Err(BundleValidationError::AdapterContract);
    };
    attrs_without_tenant.remove("tenant");
    let resource_attrs = json!({
        "kind": "resource",
        "owner": entity_ref("Subject", "subject"),
        "tenant": "tenant",
    });
    let values = vec![
        empty_entity_json("Subject", "subject"),
        empty_entity_json("Role", "role"),
        empty_entity_json("Tenant", "tenant"),
        empty_entity_json("Capability", "capability"),
        entity_json_value("Human", "human", &principal_attrs, &relationship_parents),
        entity_json_value(
            "ServiceAccount",
            "service",
            &principal_attrs,
            &relationship_parents,
        ),
        entity_json_value(
            "Human",
            "human-no-tenant",
            &principal_attrs_without_tenant,
            &relationship_parents,
        ),
        entity_json_value(
            "ServiceAccount",
            "service-no-tenant",
            &principal_attrs_without_tenant,
            &relationship_parents,
        ),
        entity_json_value(
            "ProtectedResource",
            "resource",
            &resource_attrs,
            &[
                entity_ref("Subject", "subject"),
                entity_ref("Tenant", "tenant"),
            ],
        ),
        entity_json_value(
            "ProtectedResource",
            "resource-without-owner-or-tenant",
            &json!({ "kind": "resource" }),
            &[],
        ),
    ];
    Entities::from_json_value(Value::Array(values), Some(schema))
        .map_err(|_| BundleValidationError::AdapterContract)?;

    validate_action_contract(schema)
}

fn validate_action_contract(schema: &Schema) -> Result<(), BundleValidationError> {
    let actions = schema
        .action_entities()
        .map_err(|_| BundleValidationError::AdapterContract)?;
    let human = entity_uid("Human", "human").ok_or(BundleValidationError::AdapterContract)?;
    let service =
        entity_uid("ServiceAccount", "service").ok_or(BundleValidationError::AdapterContract)?;
    let resource = entity_uid("ProtectedResource", "resource")
        .ok_or(BundleValidationError::AdapterContract)?;
    let mut has_action = false;
    for action in actions.iter() {
        has_action = true;
        let action = action.uid();
        let accepts_human = Request::new(
            human.clone(),
            action.clone(),
            resource.clone(),
            Context::empty(),
            Some(schema),
        )
        .is_ok();
        let accepts_service = Request::new(
            service.clone(),
            action,
            resource.clone(),
            Context::empty(),
            Some(schema),
        )
        .is_ok();
        if !accepts_human && !accepts_service {
            return Err(BundleValidationError::AdapterContract);
        }
    }
    if !has_action {
        return Err(BundleValidationError::AdapterContract);
    }
    Ok(())
}

fn cedar_entities(
    request: AuthorizationRequest<'_>,
    schema: &Schema,
) -> Result<(EntityUid, EntityUid, Entities), CedarEvaluationError> {
    let principal_type = match request.principal.kind {
        PrincipalKind::User => "Human",
        PrincipalKind::ServiceAccount => "ServiceAccount",
    };
    let subject = request.principal.subject_id.to_string();
    let actor =
        entity_uid(principal_type, &subject).ok_or(CedarEvaluationError::EntityConstruction)?;
    let target_key = format!(
        "{}:{}:{}",
        request.resource.kind.as_str(),
        request
            .resource
            .owner_id
            .as_ref()
            .map_or("none".to_owned(), ToString::to_string),
        request
            .resource
            .tenant_id
            .as_ref()
            .map_or("none".to_owned(), ToString::to_string),
    );
    let target = entity_uid("ProtectedResource", &target_key)
        .ok_or(CedarEvaluationError::EntityConstruction)?;

    let (principal, mut relationships) = principal_entity(request, principal_type, &subject);
    if let Some(tenant) = &request.resource.tenant_id {
        relationships.insert(("Tenant", tenant.to_string()));
    }
    if let Some(owner) = &request.resource.owner_id {
        relationships.insert(("Subject", owner.to_string()));
    }
    let mut values = relationships
        .into_iter()
        .map(|(kind, id)| empty_entity_json(kind, &id))
        .collect::<Vec<_>>();
    values.push(principal);
    values.push(resource_entity(request, &target_key));
    let entities = Entities::from_json_value(Value::Array(values), Some(schema))
        .map_err(|_| CedarEvaluationError::EntityConstruction)?;
    Ok((actor, target, entities))
}

fn principal_entity(
    request: AuthorizationRequest<'_>,
    principal_type: &'static str,
    subject: &str,
) -> (Value, BTreeSet<(&'static str, String)>) {
    let roles = request
        .context
        .roles()
        .iter()
        .map(|role| role.as_str().to_owned())
        .collect::<Vec<_>>();
    let memberships = request
        .context
        .tenant_memberships()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let capabilities = request
        .context
        .administrative_capabilities()
        .iter()
        .map(|capability| capability.as_str().to_owned())
        .collect::<Vec<_>>();
    let attributes = request
        .context
        .attributes()
        .iter()
        .map(|(key, value)| format!("{}={}", key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let scopes = request
        .principal
        .scopes
        .iter()
        .map(|scope| scope.as_str().to_owned())
        .collect::<Vec<_>>();

    let mut relationships = BTreeSet::<(&str, String)>::new();
    relationships.extend(roles.iter().cloned().map(|id| ("Role", id)));
    relationships.extend(memberships.iter().cloned().map(|id| ("Tenant", id)));
    relationships.extend(capabilities.iter().cloned().map(|id| ("Capability", id)));
    relationships.insert(("Subject", subject.to_owned()));
    let parent_refs = relationships
        .iter()
        .map(|(kind, id)| entity_ref(kind, id))
        .collect::<Vec<_>>();

    let mut attrs = serde_json::Map::new();
    attrs.insert("subject".to_owned(), entity_ref("Subject", subject));
    attrs.insert(
        "assurance".to_owned(),
        json!(assurance_number(request.principal.assurance)),
    );
    attrs.insert("scopes".to_owned(), json!(scopes));
    attrs.insert("roles".to_owned(), json!(roles));
    attrs.insert("tenantMemberships".to_owned(), json!(memberships));
    attrs.insert("capabilities".to_owned(), json!(capabilities));
    attrs.insert("attributes".to_owned(), json!(attributes));
    if let Some(tenant) = &request.principal.tenant_id {
        attrs.insert("tenant".to_owned(), json!(tenant.to_string()));
    }
    (
        entity_json(principal_type, subject, &attrs, &parent_refs),
        relationships,
    )
}

fn resource_entity(request: AuthorizationRequest<'_>, target_key: &str) -> Value {
    let mut attrs = serde_json::Map::new();
    attrs.insert("kind".to_owned(), json!(request.resource.kind.as_str()));
    let mut parents = Vec::with_capacity(2);
    if let Some(owner) = &request.resource.owner_id {
        let owner = owner.to_string();
        attrs.insert("owner".to_owned(), entity_ref("Subject", &owner));
        parents.push(entity_ref("Subject", &owner));
    }
    if let Some(tenant) = &request.resource.tenant_id {
        let tenant = tenant.to_string();
        attrs.insert("tenant".to_owned(), json!(&tenant));
        parents.push(entity_ref("Tenant", &tenant));
    }
    entity_json("ProtectedResource", target_key, &attrs, &parents)
}

fn assurance_number(assurance: AssuranceLevel) -> i64 {
    match assurance {
        AssuranceLevel::Aal1 => 1,
        AssuranceLevel::Aal2 => 2,
        AssuranceLevel::Aal3 => 3,
    }
}

fn entity_uid(kind: &str, id: &str) -> Option<EntityUid> {
    format!(r#"{kind}::"{id}""#).parse().ok()
}

fn entity_ref(kind: &str, id: &str) -> Value {
    json!({ "type": kind, "id": id })
}

fn empty_entity_json(kind: &str, id: &str) -> Value {
    json!({
        "uid": entity_ref(kind, id),
        "attrs": {},
        "parents": [],
    })
}

fn entity_json_value(kind: &str, id: &str, attrs: &Value, parents: &[Value]) -> Value {
    json!({
        "uid": entity_ref(kind, id),
        "attrs": attrs,
        "parents": parents,
    })
}

fn entity_json(
    kind: &str,
    id: &str,
    attrs: &serde_json::Map<String, Value>,
    parents: &[Value],
) -> Value {
    json!({
        "uid": entity_ref(kind, id),
        "attrs": attrs,
        "parents": parents,
    })
}
