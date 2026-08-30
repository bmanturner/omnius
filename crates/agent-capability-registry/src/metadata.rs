use std::{borrow::Cow, cmp::Ordering, collections::BTreeMap, fmt, io};

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use serde_json::Value;
use thiserror::Error;

use crate::value::{
    CapabilityDescription, CapabilityId, CapabilityTitle, CapabilityVersion, Permission,
};

/// JSON Schema dialect accepted when a declaration explicitly names its dialect.
pub const JSON_SCHEMA_DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
/// Maximum number of required permissions per capability.
pub const MAX_PERMISSIONS: usize = 128;
/// Maximum number of tenant modes per capability.
pub const MAX_TENANT_MODES: usize = 3;
/// Maximum number of transport projections per capability.
pub const MAX_EXPOSURES: usize = 7;
/// Maximum serialized byte length of each input or output schema.
pub const MAX_SCHEMA_BYTES: usize = 65_536;
/// Maximum structural depth of each input or output schema.
pub const MAX_SCHEMA_DEPTH: usize = 64;
/// Maximum number of JSON values in each input or output schema.
pub const MAX_SCHEMA_NODES: usize = 4_096;

/// The application behavior category of a capability.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityKind {
    /// An operation whose primary purpose is to change state.
    Command,
    /// A read-only operation.
    Query,
    /// A potentially multi-step application workflow.
    Workflow,
}

/// The externally observable side-effect class of a capability.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SideEffect {
    /// The capability has no externally observable side effect.
    None,
    /// Repetition has the same externally observable result as one execution.
    Idempotent,
    /// The capability mutates application state.
    Mutating,
    /// The capability can irreversibly delete or destroy state.
    Destructive,
    /// The capability causes effects in an external system.
    External,
}

/// Confirmation required before handler execution.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ConfirmationPolicy {
    /// Confirmation is neither needed nor accepted as an authorization substitute.
    Never,
    /// Policy evaluation determines whether confirmation is required.
    Policy,
    /// Explicit confirmation is always required.
    Always,
}

/// Idempotency-key policy for a capability.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum IdempotencyPolicy {
    /// An idempotency key has no meaning for this capability.
    NotApplicable,
    /// A caller may supply an idempotency key.
    Optional,
    /// A caller must supply an idempotency key.
    Required,
}

/// The data-scope mode selected for an invocation.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum TenantMode {
    /// The capability operates outside a tenant data scope.
    Global,
    /// The capability operates in the canonical tenant context.
    Tenant,
    /// The capability operates on data scoped to the principal.
    Principal,
}

/// A supported projection into an adapter or protocol surface.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Exposure {
    /// An HTTP endpoint projection.
    Http,
    /// A durable-job projection.
    Job,
    /// An LLM tool projection.
    LlmTool,
    /// An MCP tool projection.
    McpTool,
    /// An MCP resource projection.
    McpResource,
    /// An MCP prompt projection.
    McpPrompt,
    /// A browser-facing projection.
    Browser,
}

impl Exposure {
    pub(crate) const fn metric_label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Job => "job",
            Self::LlmTool => "llm_tool",
            Self::McpTool => "mcp_tool",
            Self::McpResource => "mcp_resource",
            Self::McpPrompt => "mcp_prompt",
            Self::Browser => "browser",
        }
    }
}

/// A JSON object used as an input or output JSON Schema document.
#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ObjectSchema(BTreeMap<String, Value>);

impl ObjectSchema {
    /// Creates an object schema from a deterministically ordered JSON map.
    #[must_use]
    pub fn new(properties: BTreeMap<String, Value>) -> Self {
        Self(properties)
    }

    /// Borrows the schema object.
    #[must_use]
    pub const fn as_map(&self) -> &BTreeMap<String, Value> {
        &self.0
    }

    fn validate(&self) -> Result<(), DeclarationError> {
        if let Some(dialect) = self.0.get("$schema")
            && dialect.as_str() != Some(JSON_SCHEMA_DRAFT_2020_12)
        {
            return Err(DeclarationError::UnsupportedSchemaDialect);
        }
        validate_schema_shape(&self.0)?;
        if !serialized_within_limit(&self.0, MAX_SCHEMA_BYTES) {
            return Err(DeclarationError::SchemaTooLarge);
        }
        Ok(())
    }
}

impl fmt::Debug for ObjectSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObjectSchema([redacted])")
    }
}

impl TryFrom<Value> for ObjectSchema {
    type Error = SchemaValueError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let Value::Object(object) = value else {
            return Err(SchemaValueError);
        };
        Ok(Self(object.into_iter().collect()))
    }
}

impl From<ObjectSchema> for Value {
    fn from(schema: ObjectSchema) -> Self {
        Self::Object(schema.0.into_iter().collect())
    }
}

impl<'de> Deserialize<'de> for ObjectSchema {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value =
            Value::deserialize(deserializer).map_err(|_| D::Error::custom(SchemaValueError))?;
        Self::try_from(value).map_err(D::Error::custom)
    }
}

impl JsonSchema for ObjectSchema {
    fn schema_name() -> Cow<'static, str> {
        "ObjectSchema".into()
    }

    fn schema_id() -> Cow<'static, str> {
        concat!(module_path!(), "::ObjectSchema").into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        schemars::json_schema!({
            "type": "object",
            "additionalProperties": true
        })
    }
}

/// A schema value was not a JSON object.
///
/// The rejected value is deliberately absent from this error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("schema must be a JSON object")]
pub struct SchemaValueError;

/// Stable identity of one capability revision.
#[derive(
    Clone, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(deny_unknown_fields)]
pub struct CapabilityKey {
    id: CapabilityId,
    version: CapabilityVersion,
}

impl CapabilityKey {
    /// Creates a capability revision key.
    #[must_use]
    pub fn new(id: CapabilityId, version: CapabilityVersion) -> Self {
        Self { id, version }
    }

    /// Returns the stable capability identifier.
    #[must_use]
    pub const fn id(&self) -> &CapabilityId {
        &self.id
    }

    /// Returns the capability revision.
    #[must_use]
    pub const fn version(&self) -> &CapabilityVersion {
        &self.version
    }
}

/// Canonical transport-independent capability metadata.
///
/// The serialized field names and enum values conform to
/// `agent-capability.schema.json`. Call [`Self::validate`] before publication.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityDocument {
    /// Stable capability identifier.
    pub id: CapabilityId,
    /// Capability contract version.
    pub version: CapabilityVersion,
    /// Human-readable title.
    pub title: CapabilityTitle,
    /// Application behavior category.
    pub kind: CapabilityKind,
    /// Optional bounded explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<CapabilityDescription>,
    /// JSON object containing the input JSON Schema.
    pub input_schema: ObjectSchema,
    /// JSON object containing the output JSON Schema.
    pub output_schema: ObjectSchema,
    /// Sorted, duplicate-free required permissions.
    pub permissions: Vec<Permission>,
    /// Side-effect classification.
    pub side_effect: SideEffect,
    /// Confirmation policy.
    pub confirmation: ConfirmationPolicy,
    /// Idempotency-key policy.
    pub idempotency: IdempotencyPolicy,
    /// Sorted, duplicate-free, nonempty supported tenant modes.
    pub tenant_modes: Vec<TenantMode>,
    /// Sorted, duplicate-free supported projections.
    pub exposures: Vec<Exposure>,
    /// Whether callers should migrate away from this revision.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deprecated: bool,
}

impl CapabilityDocument {
    /// Returns the stable key for this declaration.
    #[must_use]
    pub fn key(&self) -> CapabilityKey {
        CapabilityKey::new(self.id.clone(), self.version.clone())
    }

    /// Validates bounds, canonical ordering, and semantic safety guardrails.
    ///
    /// Full JSON Schema instance validation is deliberately outside this crate.
    ///
    /// # Errors
    ///
    /// Returns [`DeclarationError`] for malformed schema objects, excessive or
    /// noncanonical lists, or an unsafe policy combination.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        self.input_schema.validate()?;
        self.output_schema.validate()?;

        if self.permissions.len() > MAX_PERMISSIONS {
            return Err(DeclarationError::TooManyPermissions);
        }
        validate_sorted_unique(&self.permissions)?;

        if self.tenant_modes.is_empty() {
            return Err(DeclarationError::EmptyTenantModes);
        }
        if self.tenant_modes.len() > MAX_TENANT_MODES {
            return Err(DeclarationError::TooManyTenantModes);
        }
        validate_sorted_unique(&self.tenant_modes)?;

        if self.exposures.len() > MAX_EXPOSURES {
            return Err(DeclarationError::TooManyExposures);
        }
        validate_sorted_unique(&self.exposures)?;

        self.validate_semantics()
    }

    fn validate_semantics(&self) -> Result<(), DeclarationError> {
        if self.kind == CapabilityKind::Query && self.side_effect != SideEffect::None {
            return Err(DeclarationError::UnsafePolicyCombination);
        }

        let valid = match self.side_effect {
            SideEffect::None => {
                self.confirmation == ConfirmationPolicy::Never
                    && self.idempotency == IdempotencyPolicy::NotApplicable
            }
            SideEffect::Idempotent => self.idempotency != IdempotencyPolicy::NotApplicable,
            SideEffect::Mutating => {
                self.confirmation != ConfirmationPolicy::Never
                    && self.idempotency != IdempotencyPolicy::NotApplicable
            }
            SideEffect::Destructive => {
                self.confirmation == ConfirmationPolicy::Always
                    && self.idempotency == IdempotencyPolicy::Required
            }
            SideEffect::External => {
                self.confirmation != ConfirmationPolicy::Never
                    && self.idempotency == IdempotencyPolicy::Required
            }
        };
        if !valid {
            return Err(DeclarationError::UnsafePolicyCombination);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CapabilityDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)
            .map_err(|_| D::Error::custom(DeclarationDecodeError))?;
        let Value::Object(object) = &value else {
            return Err(D::Error::custom(DeclarationDecodeError));
        };
        if object.keys().any(|key| !is_document_field(key)) {
            return Err(D::Error::custom(DeclarationDecodeError));
        }
        let wire: CapabilityDocumentWire =
            serde_json::from_value(value).map_err(|_| D::Error::custom(DeclarationDecodeError))?;
        Ok(Self {
            id: wire.id,
            version: wire.version,
            title: wire.title,
            kind: wire.kind,
            description: wire.description,
            input_schema: wire.input_schema,
            output_schema: wire.output_schema,
            permissions: wire.permissions,
            side_effect: wire.side_effect,
            confirmation: wire.confirmation,
            idempotency: wire.idempotency,
            tenant_modes: wire.tenant_modes,
            exposures: wire.exposures,
            deprecated: wire.deprecated,
        })
    }
}

#[derive(Deserialize)]
struct CapabilityDocumentWire {
    id: CapabilityId,
    version: CapabilityVersion,
    title: CapabilityTitle,
    kind: CapabilityKind,
    #[serde(default)]
    description: Option<CapabilityDescription>,
    input_schema: ObjectSchema,
    output_schema: ObjectSchema,
    permissions: Vec<Permission>,
    side_effect: SideEffect,
    confirmation: ConfirmationPolicy,
    idempotency: IdempotencyPolicy,
    tenant_modes: Vec<TenantMode>,
    exposures: Vec<Exposure>,
    #[serde(default)]
    deprecated: bool,
}

/// A capability declaration failed safe structural or semantic validation.
///
/// No variant retains declaration content.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DeclarationError {
    /// A schema explicitly selected a dialect other than JSON Schema 2020-12.
    #[error("capability schema uses an unsupported dialect")]
    UnsupportedSchemaDialect,
    /// A schema exceeded its fixed serialized-size bound.
    #[error("capability schema exceeds its fixed size bound")]
    SchemaTooLarge,
    /// A schema exceeded its fixed structural-depth bound.
    #[error("capability schema exceeds its fixed depth bound")]
    SchemaTooDeep,
    /// A schema exceeded its fixed node-count bound.
    #[error("capability schema exceeds its fixed node-count bound")]
    TooManySchemaNodes,
    /// Required permissions exceeded the fixed count bound.
    #[error("capability has too many permissions")]
    TooManyPermissions,
    /// No tenant mode was declared.
    #[error("capability must declare at least one tenant mode")]
    EmptyTenantModes,
    /// Tenant modes exceeded their fixed count bound.
    #[error("capability has too many tenant modes")]
    TooManyTenantModes,
    /// Exposures exceeded their fixed count bound.
    #[error("capability has too many exposures")]
    TooManyExposures,
    /// A declaration list contains a duplicate.
    #[error("capability list contains a duplicate")]
    DuplicateListItem,
    /// A declaration list is not in canonical order.
    #[error("capability list is not sorted")]
    UnsortedList,
    /// Side-effect, kind, confirmation, and idempotency policies disagree.
    #[error("capability policy combination is unsafe")]
    UnsafePolicyCombination,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("capability document is malformed")]
struct DeclarationDecodeError;

fn validate_sorted_unique<T: Ord>(values: &[T]) -> Result<(), DeclarationError> {
    for pair in values.windows(2) {
        match pair[0].cmp(&pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => return Err(DeclarationError::DuplicateListItem),
            Ordering::Greater => return Err(DeclarationError::UnsortedList),
        }
    }
    Ok(())
}

fn validate_schema_shape(root: &BTreeMap<String, Value>) -> Result<(), DeclarationError> {
    let mut nodes = 1_usize;
    let mut stack = root
        .values()
        .map(|value| (2_usize, value))
        .collect::<Vec<_>>();
    while let Some((depth, value)) = stack.pop() {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(DeclarationError::SchemaTooDeep);
        }
        nodes = nodes.saturating_add(1);
        if nodes > MAX_SCHEMA_NODES {
            return Err(DeclarationError::TooManySchemaNodes);
        }
        match value {
            Value::Array(values) => {
                stack.extend(values.iter().map(|child| (depth + 1, child)));
            }
            Value::Object(values) => {
                stack.extend(values.values().map(|child| (depth + 1, child)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    Ok(())
}

fn serialized_within_limit<T: Serialize>(value: &T, limit: usize) -> bool {
    let mut writer = LimitWriter { remaining: limit };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct LimitWriter {
    remaining: usize,
}

impl io::Write for LimitWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("serialized value exceeds fixed bound"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde's skip predicate contract passes a reference"
)]
const fn is_false(value: &bool) -> bool {
    !*value
}

fn is_document_field(field: &str) -> bool {
    matches!(
        field,
        "id" | "version"
            | "title"
            | "kind"
            | "description"
            | "input_schema"
            | "output_schema"
            | "permissions"
            | "side_effect"
            | "confirmation"
            | "idempotency"
            | "tenant_modes"
            | "exposures"
            | "deprecated"
    )
}
