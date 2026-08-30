use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use omnius_agent_capability_registry::ConfirmationEvidence;
use omnius_mcp_server_core::McpRequestContext;
use omnius_validation::{JsonSchemaAdapter, JsonValidationLimits};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

/// Exact MCP extension identifier required for MRTR elicitation.
pub const MRTR_EXTENSION_ID: &str = "io.modelcontextprotocol/mrtr";
/// Exact MCP extension revision implemented by this crate.
pub const MRTR_EXTENSION_REVISION: &str = "2026-07-28";
/// Maximum requests in one elicitation round.
pub const MAX_INPUT_REQUESTS: usize = 8;
/// Maximum fields in one form request.
pub const MAX_FORM_FIELDS: usize = 32;
/// Maximum supported MRTR rounds.
pub const MAX_MRTR_ROUNDS: u16 = 10;
/// Maximum lifetime of one request-state handle.
pub const MAX_REQUEST_STATE_TTL: Duration = Duration::from_mins(15);

const MAX_MESSAGE_BYTES: usize = 1_024;
const MAX_KEY_BYTES: usize = 64;
const MAX_POINTER_DEPTH: usize = 16;
const MAX_POINTER_SEGMENT_BYTES: usize = 128;
const MAX_ELICITATION_ID_BYTES: usize = 128;

/// Runtime policy for the MRTR lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrtrConfig {
    /// Whether the extension is enabled by application composition.
    pub enabled: bool,
    /// Lifetime of each signed request-state handle.
    pub request_state_ttl: Duration,
    /// Largest canonical original-argument document accepted for binding.
    pub max_argument_bytes: usize,
}

impl Default for MrtrConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            request_state_ttl: Duration::from_mins(5),
            max_argument_bytes: 1024 * 1024,
        }
    }
}

impl MrtrConfig {
    /// Validates bounded runtime settings.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a bound is zero or exceeds its hard ceiling.
    pub fn validate(self) -> Result<Self, ConfigError> {
        if self.request_state_ttl.is_zero()
            || self.request_state_ttl > MAX_REQUEST_STATE_TTL
            || self.max_argument_bytes == 0
            || self.max_argument_bytes > 4 * 1024 * 1024
        {
            return Err(ConfigError::InvalidBounds);
        }
        Ok(self)
    }
}

/// Invalid lifecycle configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConfigError {
    /// One or more bounded settings are invalid.
    #[error("MRTR configuration bounds are invalid")]
    InvalidBounds,
    /// The request-state signing key is too short.
    #[error("MRTR request-state signing key is invalid")]
    InvalidSigningKey,
}

/// MCP methods allowed to return an `input_required` result.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MrtrMethod {
    /// `tools/call`.
    ToolCall,
    /// `prompts/get`.
    PromptGet,
    /// `resources/read`.
    ResourceRead,
}

impl MrtrMethod {
    /// Returns the MCP wire method.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolCall => "tools/call",
            Self::PromptGet => "prompts/get",
            Self::ResourceRead => "resources/read",
        }
    }
}

/// Client-advertised elicitation modes for one request.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientElicitationCapabilities {
    form: bool,
    form_schema_validation: bool,
    url: bool,
}

impl ClientElicitationCapabilities {
    /// Declares form support. Client-side validation is advisory only.
    #[must_use]
    pub const fn form(schema_validation: bool) -> Self {
        Self {
            form: true,
            form_schema_validation: schema_validation,
            url: false,
        }
    }

    /// Declares URL support.
    #[must_use]
    pub const fn url() -> Self {
        Self {
            form: false,
            form_schema_validation: false,
            url: true,
        }
    }

    /// Declares both supported modes.
    #[must_use]
    pub const fn form_and_url(schema_validation: bool) -> Self {
        Self {
            form: true,
            form_schema_validation: schema_validation,
            url: true,
        }
    }

    /// Whether form mode was advertised.
    #[must_use]
    pub const fn supports_form(self) -> bool {
        self.form
    }

    /// Whether URL mode was advertised.
    #[must_use]
    pub const fn supports_url(self) -> bool {
        self.url
    }

    /// Whether the client claims it validates form schemas.
    #[must_use]
    pub const fn advertises_schema_validation(self) -> bool {
        self.form_schema_validation
    }
}

/// Original MCP method and exact capability binding for one normal invocation.
#[derive(Clone, Eq, PartialEq)]
pub struct InvocationBinding {
    method: MrtrMethod,
    capability_key: String,
    capability_revision: String,
}

impl InvocationBinding {
    /// Constructs an invocation binding from canonical capability identifiers.
    #[must_use]
    pub fn new(
        method: MrtrMethod,
        capability_key: impl Into<String>,
        capability_revision: impl Into<String>,
    ) -> Self {
        Self {
            method,
            capability_key: capability_key.into(),
            capability_revision: capability_revision.into(),
        }
    }

    /// Returns the originating MCP method.
    #[must_use]
    pub const fn method(&self) -> MrtrMethod {
        self.method
    }

    /// Returns the canonical capability key.
    #[must_use]
    pub fn capability_key(&self) -> &str {
        &self.capability_key
    }

    /// Returns the exact capability revision.
    #[must_use]
    pub fn capability_revision(&self) -> &str {
        &self.capability_revision
    }

    pub(crate) fn validate(&self) -> bool {
        valid_identifier(&self.capability_key, 256)
            && valid_identifier(&self.capability_revision, 128)
    }
}

impl fmt::Debug for InvocationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvocationBinding")
            .field("method", &self.method)
            .field("capability_key", &self.capability_key)
            .field("capability_revision", &self.capability_revision)
            .finish()
    }
}

/// Original request material passed back to the normal capability invocation boundary.
#[derive(Clone)]
pub struct OriginalInvocation {
    binding: InvocationBinding,
    arguments: Value,
    idempotency_key: Option<String>,
}

impl OriginalInvocation {
    /// Creates one original invocation snapshot from the current retry request.
    #[must_use]
    pub fn new(
        binding: InvocationBinding,
        arguments: Value,
        idempotency_key: Option<String>,
    ) -> Self {
        Self {
            binding,
            arguments,
            idempotency_key,
        }
    }

    /// Returns the immutable binding.
    #[must_use]
    pub const fn binding(&self) -> &InvocationBinding {
        &self.binding
    }

    /// Returns the original arguments.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        &self.arguments
    }

    /// Returns the ordinary invocation idempotency key, if the original request supplied one.
    #[must_use]
    pub fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    pub(crate) fn into_parts(self) -> (InvocationBinding, Value, Option<String>) {
        (self.binding, self.arguments, self.idempotency_key)
    }
}

impl fmt::Debug for OriginalInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OriginalInvocation")
            .field("binding", &self.binding)
            .field("arguments", &"[REDACTED]")
            .field(
                "idempotency_key",
                &self.idempotency_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Sensitivity classification required for every elicited field or URL flow.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Sensitivity {
    /// No confidential or personal data.
    Public,
    /// Personal data that must not enter logs or audit metadata.
    Personal,
    /// Confidential application data.
    Confidential,
    /// A broad credential, provider key, or bearer secret.
    Credential,
    /// A password or password-equivalent value.
    Password,
}

/// Protection required before a form may collect non-public data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormProtection {
    /// Ordinary client form presentation.
    Ordinary,
    /// Core has obtained an explicit stronger confirmation for this form.
    StrongConfirmation,
}

/// Behavior when a user declines a valid elicitation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclineBehavior {
    /// Finish normally with a declined outcome and do not invoke the capability.
    CompleteDeclined,
    /// Reinvoke the original capability without fields from declined requests.
    InvokeWithoutInput,
}

/// Stable key for one entry in `inputRequests` and `inputResponses`.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InputRequestKey(String);

impl InputRequestKey {
    /// Validates and constructs a stable input request key.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError::InvalidRequestKey`] for an empty, oversized, or unsafe key.
    pub fn try_new(value: impl Into<String>) -> Result<Self, PlanError> {
        let value = value.into();
        if !valid_key(&value, MAX_KEY_BYTES) {
            return Err(PlanError::InvalidRequestKey);
        }
        Ok(Self(value))
    }

    /// Returns the wire key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for InputRequestKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("InputRequestKey")
            .field(&self.0)
            .finish()
    }
}

/// Mapping and sensitivity for one form response field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldPlan {
    name: String,
    argument_pointer: String,
    sensitivity: Sensitivity,
}

impl FieldPlan {
    /// Creates one validated response-field mapping.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] when the field name or object-only JSON pointer is invalid.
    pub fn try_new(
        name: impl Into<String>,
        argument_pointer: impl Into<String>,
        sensitivity: Sensitivity,
    ) -> Result<Self, PlanError> {
        let name = name.into();
        let argument_pointer = argument_pointer.into();
        if !valid_key(&name, MAX_KEY_BYTES) {
            return Err(PlanError::InvalidField);
        }
        validate_object_pointer(&argument_pointer)?;
        Ok(Self {
            name,
            argument_pointer,
            sensitivity,
        })
    }

    /// Returns the response property name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the destination JSON pointer in the original arguments.
    #[must_use]
    pub fn argument_pointer(&self) -> &str {
        &self.argument_pointer
    }

    /// Returns the declared sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

/// One validated form-mode elicitation request.
#[derive(Clone)]
pub struct FormElicitationPlan {
    message: String,
    schema: Value,
    fields: BTreeMap<String, FieldPlan>,
    protection: FormProtection,
    validator: JsonSchemaAdapter,
}

impl FormElicitationPlan {
    /// Creates a narrow object-schema form with explicit field mappings.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] for invalid schemas, mappings, bounds, or sensitive policy.
    pub fn try_new(
        message: impl Into<String>,
        schema: Value,
        fields: Vec<FieldPlan>,
        protection: FormProtection,
    ) -> Result<Self, PlanError> {
        let message = message.into();
        validate_message(&message)?;
        if mentions_credential(&message) {
            return Err(PlanError::ProhibitedCredentialForm);
        }
        let schema_bytes = serde_json::to_vec(&schema).map_err(|_| PlanError::InvalidSchema)?;
        let validator = JsonSchemaAdapter::compile(&schema_bytes, JsonValidationLimits::default())
            .map_err(|_| PlanError::InvalidSchema)?;
        let requested_schema = rmcp::model::ElicitationSchema::from_json_schema(
            schema
                .as_object()
                .cloned()
                .ok_or(PlanError::InvalidSchema)?,
        )
        .map_err(|_| PlanError::InvalidSchema)?;
        let converted_schema =
            serde_json::to_value(requested_schema).map_err(|_| PlanError::LossySchema)?;
        if converted_schema != schema {
            return Err(PlanError::LossySchema);
        }

        let schema_object = schema.as_object().ok_or(PlanError::InvalidSchema)?;
        if schema_object.get("type") != Some(&Value::String("object".to_owned())) {
            return Err(PlanError::InvalidSchema);
        }
        let properties = schema_object
            .get("properties")
            .and_then(Value::as_object)
            .ok_or(PlanError::InvalidSchema)?;
        if properties.is_empty() || properties.len() > MAX_FORM_FIELDS {
            return Err(PlanError::InvalidFieldCount);
        }

        let mut mapped = BTreeMap::new();
        let mut destinations = BTreeSet::new();
        for field in fields {
            if mapped.insert(field.name.clone(), field.clone()).is_some()
                || !destinations.insert(field.argument_pointer.clone())
            {
                return Err(PlanError::DuplicateField);
            }
        }
        if mapped.len() != properties.len()
            || !properties.keys().all(|name| mapped.contains_key(name))
        {
            return Err(PlanError::SchemaMappingMismatch);
        }

        validate_required(schema_object, &mapped)?;
        for (name, property_schema) in properties {
            let field = mapped.get(name).ok_or(PlanError::SchemaMappingMismatch)?;
            let prohibited_name = mentions_credential(name)
                || mentions_credential(field.argument_pointer())
                || schema_mentions_credential(property_schema);
            if prohibited_name
                || matches!(
                    field.sensitivity,
                    Sensitivity::Credential | Sensitivity::Password
                )
            {
                return Err(PlanError::ProhibitedCredentialForm);
            }
            if matches!(
                field.sensitivity,
                Sensitivity::Personal | Sensitivity::Confidential
            ) && protection != FormProtection::StrongConfirmation
            {
                return Err(PlanError::StrongConfirmationRequired);
            }
        }

        Ok(Self {
            message,
            schema,
            fields: mapped,
            protection,
            validator,
        })
    }

    /// Returns the user-facing message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the narrow response schema.
    #[must_use]
    pub const fn schema(&self) -> &Value {
        &self.schema
    }

    /// Returns the explicit field mappings.
    #[must_use]
    pub const fn fields(&self) -> &BTreeMap<String, FieldPlan> {
        &self.fields
    }

    /// Returns the form protection mode.
    #[must_use]
    pub const fn protection(&self) -> FormProtection {
        self.protection
    }

    /// Returns the highest sensitivity in the form.
    #[must_use]
    pub fn sensitivity(&self) -> Sensitivity {
        self.fields
            .values()
            .map(FieldPlan::sensitivity)
            .max()
            .unwrap_or(Sensitivity::Public)
    }

    pub(crate) fn validate_content(&self, content: &Value) -> bool {
        serde_json::to_vec(content).is_ok_and(|bytes| self.validator.validate_bytes(&bytes).is_ok())
    }
}

impl PartialEq for FormElicitationPlan {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
            && self.schema == other.schema
            && self.fields == other.fields
            && self.protection == other.protection
    }
}

impl fmt::Debug for FormElicitationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FormElicitationPlan")
            .field("message", &self.message)
            .field("schema", &"[REDACTED SCHEMA]")
            .field("fields", &self.fields)
            .field("protection", &self.protection)
            .finish_non_exhaustive()
    }
}

/// One validated URL-mode elicitation request.
#[derive(Clone, Eq, PartialEq)]
pub struct UrlElicitationPlan {
    message: String,
    url: Url,
    elicitation_id: String,
    sensitivity: Sensitivity,
}

impl UrlElicitationPlan {
    /// Creates an HTTPS out-of-band elicitation without URL credentials, query, or fragment.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] when the URL, message, or identifier is unsafe.
    pub fn try_new(
        message: impl Into<String>,
        url: impl AsRef<str>,
        elicitation_id: impl Into<String>,
        sensitivity: Sensitivity,
    ) -> Result<Self, PlanError> {
        let message = message.into();
        validate_message(&message)?;
        let url = Url::parse(url.as_ref()).map_err(|_| PlanError::InvalidUrl)?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(PlanError::InvalidUrl);
        }
        let elicitation_id = elicitation_id.into();
        if !valid_key(&elicitation_id, MAX_ELICITATION_ID_BYTES) {
            return Err(PlanError::InvalidElicitationId);
        }
        Ok(Self {
            message,
            url,
            elicitation_id,
            sensitivity,
        })
    }

    /// Returns the user-facing message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Returns the static out-of-band URL.
    #[must_use]
    pub const fn url(&self) -> &Url {
        &self.url
    }

    /// Returns the non-secret correlation identifier.
    #[must_use]
    pub fn elicitation_id(&self) -> &str {
        &self.elicitation_id
    }

    /// Returns the flow sensitivity.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        self.sensitivity
    }
}

impl fmt::Debug for UrlElicitationPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UrlElicitationPlan")
            .field("message", &self.message)
            .field("url", &"[REDACTED URL]")
            .field("elicitation_id", &self.elicitation_id)
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

/// Transport-neutral elicitation request definition.
#[derive(Clone, Debug, PartialEq)]
pub enum PlannedElicitation {
    /// Structured form request.
    Form(FormElicitationPlan),
    /// Out-of-band URL request.
    Url(UrlElicitationPlan),
}

impl PlannedElicitation {
    /// Returns the request sensitivity.
    #[must_use]
    pub fn sensitivity(&self) -> Sensitivity {
        match self {
            Self::Form(form) => form.sensitivity(),
            Self::Url(url) => url.sensitivity(),
        }
    }
}

/// Bounded, versioned elicitation plan stored in the authoritative replay ledger.
#[derive(Clone, Debug, PartialEq)]
pub struct ElicitationPlan {
    version: u16,
    requests: BTreeMap<InputRequestKey, PlannedElicitation>,
    max_rounds: u16,
    decline_behavior: DeclineBehavior,
}

impl ElicitationPlan {
    /// Current persisted plan format version.
    pub const VERSION: u16 = 1;

    /// Creates a bounded plan with unique stable request keys.
    ///
    /// # Errors
    ///
    /// Returns [`PlanError`] for empty, duplicate, or excessive requests or rounds.
    pub fn try_new(
        requests: Vec<(InputRequestKey, PlannedElicitation)>,
        max_rounds: u16,
        decline_behavior: DeclineBehavior,
    ) -> Result<Self, PlanError> {
        if requests.is_empty() || requests.len() > MAX_INPUT_REQUESTS {
            return Err(PlanError::InvalidRequestCount);
        }
        if !(1..=MAX_MRTR_ROUNDS).contains(&max_rounds) {
            return Err(PlanError::InvalidRoundLimit);
        }
        let mut destinations: Vec<Vec<String>> = Vec::new();
        for (_, request) in &requests {
            if let PlannedElicitation::Form(form) = request {
                for field in form.fields().values() {
                    let path = decode_object_pointer(field.argument_pointer())?;
                    if destinations
                        .iter()
                        .any(|existing| existing.starts_with(&path) || path.starts_with(existing))
                    {
                        return Err(PlanError::DuplicateField);
                    }
                    destinations.push(path);
                }
            }
        }
        let mut mapped = BTreeMap::new();
        for (key, request) in requests {
            if mapped.insert(key, request).is_some() {
                return Err(PlanError::DuplicateRequestKey);
            }
        }
        Ok(Self {
            version: Self::VERSION,
            requests: mapped,
            max_rounds,
            decline_behavior,
        })
    }

    /// Returns the persisted plan format version.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }

    /// Returns the keyed request definitions.
    #[must_use]
    pub const fn requests(&self) -> &BTreeMap<InputRequestKey, PlannedElicitation> {
        &self.requests
    }

    /// Returns the total round ceiling.
    #[must_use]
    pub const fn max_rounds(&self) -> u16 {
        self.max_rounds
    }

    /// Returns decline behavior.
    #[must_use]
    pub const fn decline_behavior(&self) -> DeclineBehavior {
        self.decline_behavior
    }

    /// Returns the highest sensitivity represented by the plan.
    #[must_use]
    pub fn sensitivity(&self) -> Sensitivity {
        self.requests
            .values()
            .map(PlannedElicitation::sensitivity)
            .max()
            .unwrap_or(Sensitivity::Public)
    }
}

/// Plan construction failure without schema content or sensitive values.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PlanError {
    /// A request key is invalid.
    #[error("elicitation request key is invalid")]
    InvalidRequestKey,
    /// The number of requests is outside the supported bound.
    #[error("elicitation request count is invalid")]
    InvalidRequestCount,
    /// Request keys are not unique.
    #[error("elicitation request keys must be unique")]
    DuplicateRequestKey,
    /// The round ceiling is outside the supported bound.
    #[error("elicitation round limit is invalid")]
    InvalidRoundLimit,
    /// A message is empty or oversized.
    #[error("elicitation message is invalid")]
    InvalidMessage,
    /// A form field is invalid.
    #[error("elicitation form field is invalid")]
    InvalidField,
    /// Form field mappings are not unique.
    #[error("elicitation form fields or destinations are duplicated")]
    DuplicateField,
    /// The number of form fields is outside the supported bound.
    #[error("elicitation form field count is invalid")]
    InvalidFieldCount,
    /// The response schema is invalid or unsupported by MCP form mode.
    #[error("elicitation form schema is invalid")]
    InvalidSchema,
    /// The valid schema changes when adapted through the current RMCP schema type.
    #[error("elicitation form schema is not losslessly representable")]
    LossySchema,
    /// Schema properties and explicit mappings differ.
    #[error("elicitation schema and field mappings differ")]
    SchemaMappingMismatch,
    /// A JSON pointer is invalid or targets a non-object path.
    #[error("elicitation argument pointer is invalid")]
    InvalidArgumentPointer,
    /// Provider keys, passwords, and broad credentials cannot use ordinary form input.
    #[error("credential or password collection is prohibited in form mode")]
    ProhibitedCredentialForm,
    /// Non-public form input requires explicit stronger confirmation.
    #[error("sensitive form input requires stronger confirmation")]
    StrongConfirmationRequired,
    /// The out-of-band URL is unsafe.
    #[error("elicitation URL is invalid")]
    InvalidUrl,
    /// The out-of-band correlation identifier is invalid.
    #[error("elicitation identifier is invalid")]
    InvalidElicitationId,
}

/// SHA-256 digest used for binding and redacted persistence.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BindingDigest([u8; 32]);

impl BindingDigest {
    /// Computes a digest of one domain-separated byte sequence.
    #[must_use]
    pub fn of(domain: &[u8], value: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
        Self(hasher.finalize().into())
    }

    /// Returns digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for BindingDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BindingDigest([REDACTED])")
    }
}

/// Redacted authoritative binding checked atomically during claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateBinding {
    /// Digest of the stable principal ID.
    pub principal_digest: BindingDigest,
    /// Digest of the stable tenant ID.
    pub tenant_digest: BindingDigest,
    /// Originating MCP method.
    pub method: MrtrMethod,
    /// Canonical capability key.
    pub capability_key: String,
    /// Exact capability revision.
    pub capability_revision: String,
    /// Canonical digest of the unchanged original arguments.
    pub arguments_digest: BindingDigest,
    /// Domain-separated digest of the original optional idempotency key.
    pub idempotency_digest: BindingDigest,
    /// Associated-data digest used by the signed token.
    pub associated_digest: BindingDigest,
}

/// Non-authorizing reference to application-owned durable continuation state.
///
/// The referenced state belongs to the normal capability repository. This identifier must not be
/// a bearer credential, must not bypass authorization on reinvocation, and is safe for the MRTR
/// replay ledger to retain. The MRTR ledger never retains the referenced input values.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct InvocationContinuation(Uuid);

impl InvocationContinuation {
    /// Wraps a server-minted application continuation identifier.
    #[must_use]
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }

    /// Returns the application continuation identifier.
    #[must_use]
    pub const fn id(self) -> Uuid {
        self.0
    }
}

impl fmt::Debug for InvocationContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvocationContinuation([REDACTED ID])")
    }
}

/// Pending authoritative MRTR record. It contains no original arguments or response content.
#[derive(Clone, Debug, PartialEq)]
pub struct PendingMrtrState {
    /// Server-minted state identifier.
    pub state_id: Uuid,
    /// Redacted request binding.
    pub binding: StateBinding,
    /// Bounded plan for this round.
    pub plan: ElicitationPlan,
    /// Optional non-authorizing reference to application-owned durable continuation state.
    pub continuation: Option<InvocationContinuation>,
    /// One-based current round.
    pub round: u16,
    /// Immutable total round ceiling.
    pub max_rounds: u16,
    /// Server issuance time.
    pub issued_at: OffsetDateTime,
    /// Server expiry time.
    pub expires_at: OffsetDateTime,
}

/// Atomic claim request supplied to the repository.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateClaim {
    /// State identifier authenticated by the token.
    pub state_id: Uuid,
    /// Complete expected binding derived from the retry request.
    pub expected_binding: StateBinding,
    /// Repository comparison time.
    pub now: OffsetDateTime,
}

/// Atomic repository claim result. Rejections intentionally collapse absence, expiry, replay, and mismatch.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimResult {
    /// The pending row was atomically claimed exactly once.
    Claimed(Box<PendingMrtrState>),
    /// No matching live pending row was claimable.
    Rejected,
}

/// Reason an old claimed handle was atomically replaced by a fresh bounded handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementReason {
    /// The client response was locally rejected and may be corrected.
    InvalidResponse,
    /// Normal capability execution explicitly requested another input round.
    MoreInput,
}

/// Terminal authoritative state of a claimed handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalStatus {
    /// Normal capability execution completed.
    Completed,
    /// The user declined and policy completed normally.
    Declined,
    /// The user cancelled.
    Cancelled,
    /// The response was rejected at the round ceiling.
    Exhausted,
    /// Normal invocation failed after claim.
    InvocationFailed,
    /// The claimed record was invalid or the current retry lost mode support.
    Rejected,
}

/// Signed opaque request-state string. Debug output never reveals the token.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestStateToken(String);

impl RequestStateToken {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Returns the token for the MCP wire adapter.
    #[must_use]
    pub fn expose_for_wire(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestStateToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestStateToken([REDACTED])")
    }
}

/// Transport-neutral `input_required` challenge.
#[derive(Clone, Debug, PartialEq)]
pub struct ElicitationChallenge {
    /// Bounded input requests for this round.
    pub plan: ElicitationPlan,
    /// Signed, expiring, single-use server handle.
    pub request_state: RequestStateToken,
    /// One-based current round.
    pub round: u16,
    /// Authoritative server expiry.
    pub expires_at: OffsetDateTime,
}

/// Raw response map after duplicate-preserving wire parsing.
pub type InputResponseMap = BTreeMap<String, Value>;

/// Correlation passed separately to the normal invocation port, never as idempotency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MrtrCorrelation {
    /// Claimed MRTR state ID.
    pub state_id: Uuid,
    /// Claimed one-based round.
    pub round: u16,
}

/// Request passed to the existing normal capability invocation boundary.
pub struct NormalInvocationRequest {
    /// Fresh canonical request context for normal authorization and lifecycle checks.
    pub context: McpRequestContext,
    /// Current canonical binding.
    pub binding: InvocationBinding,
    /// Original arguments plus locally validated mapped fields.
    pub arguments: Value,
    /// Original ordinary idempotency key, unchanged by MRTR.
    pub idempotency_key: Option<String>,
    /// Current server-authenticated confirmation evidence, rebound on every retry.
    pub confirmation_evidence: ConfirmationEvidence,
    /// Application-owned durable continuation from a prior accepted round, if any.
    pub continuation: Option<InvocationContinuation>,
    /// MRTR audit correlation, explicitly not an idempotency key.
    pub mrtr: MrtrCorrelation,
}

impl fmt::Debug for NormalInvocationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NormalInvocationRequest")
            .field("context", &self.context)
            .field("binding", &self.binding)
            .field("arguments", &"[REDACTED]")
            .field(
                "idempotency_key",
                &self.idempotency_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field("confirmation_evidence", &self.confirmation_evidence)
            .field("continuation", &self.continuation)
            .field("mrtr", &self.mrtr)
            .finish()
    }
}

/// Result returned by the normal capability invocation boundary.
#[derive(Debug)]
pub enum InvocationDisposition<T> {
    /// Canonical normal result from server core.
    Complete(T),
    /// Explicit bounded plan for one further MRTR round plus application-owned durable state.
    InputRequired {
        /// Next bounded elicitation plan.
        plan: ElicitationPlan,
        /// Non-authorizing application continuation created before requesting the next round.
        continuation: InvocationContinuation,
    },
}

/// Normal lifecycle outcome of a retry.
#[derive(Debug)]
pub enum ResumeOutcome<T> {
    /// Normal capability execution completed.
    Complete(T),
    /// A fresh, single-use bounded challenge was issued.
    InputRequired(ElicitationChallenge),
    /// The user declined and policy ended normally.
    Declined,
    /// The user cancelled normally.
    Cancelled,
    /// The finite round ceiling was reached without invocation.
    Exhausted,
}

/// Redacted audit event kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MrtrAuditKind {
    /// A new pending challenge was issued.
    Issued,
    /// A pending handle was atomically claimed for processing.
    Claimed,
    /// A retry token or authoritative claim was rejected.
    StateRejected,
    /// A claimed response was invalid and a fresh round was issued.
    ResponseRejected,
    /// A valid accepted response was passed to normal invocation.
    Accepted,
    /// Accepted values and one or more declines were passed to normal invocation.
    PartiallyAccepted,
    /// A valid decline completed normally.
    Declined,
    /// A valid cancellation completed normally.
    Cancelled,
    /// Normal invocation requested another round.
    Advanced,
    /// Normal invocation completed.
    Completed,
    /// Normal invocation failed.
    InvocationFailed,
    /// The finite round limit was exhausted.
    Exhausted,
}

/// Audit metadata that cannot contain request-state tokens, identities, raw arguments, or responses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrtrAuditEvent {
    /// Authenticated state ID, absent for untrusted token failures.
    pub state_id: Option<Uuid>,
    /// Lifecycle transition.
    pub kind: MrtrAuditKind,
    /// MCP method when authenticated.
    pub method: Option<MrtrMethod>,
    /// Capability key when authenticated.
    pub capability_key: Option<String>,
    /// Capability revision when authenticated.
    pub capability_revision: Option<String>,
    /// Original argument digest when authenticated.
    pub arguments_digest: Option<BindingDigest>,
    /// One-based round when authenticated.
    pub round: Option<u16>,
    /// Highest declared sensitivity; never a value.
    pub sensitivity: Option<Sensitivity>,
}

pub(crate) struct ArgumentObjectShape(BTreeSet<Vec<String>>);

pub(crate) fn argument_object_shape(arguments: &Value) -> ArgumentObjectShape {
    let mut object_paths = BTreeSet::new();
    capture_object_paths(arguments, &mut Vec::new(), &mut object_paths);
    ArgumentObjectShape(object_paths)
}

pub(crate) fn validate_mapping_shape(
    shape: &ArgumentObjectShape,
    plan: &ElicitationPlan,
) -> Result<(), PlanError> {
    for request in plan.requests.values() {
        if let PlannedElicitation::Form(form) = request {
            for field in form.fields.values() {
                let segments = decode_object_pointer(&field.argument_pointer)?;
                let parent = &segments[..segments.len() - 1];
                if !shape.0.contains(parent) {
                    return Err(PlanError::InvalidArgumentPointer);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_mapping_parents(
    arguments: &Value,
    plan: &ElicitationPlan,
) -> Result<(), PlanError> {
    for request in plan.requests.values() {
        if let PlannedElicitation::Form(form) = request {
            for field in form.fields.values() {
                let segments = decode_object_pointer(&field.argument_pointer)?;
                let parent_segments = &segments[..segments.len() - 1];
                let mut current = arguments;
                for segment in parent_segments {
                    current = current
                        .as_object()
                        .and_then(|object| object.get(segment))
                        .ok_or(PlanError::InvalidArgumentPointer)?;
                }
                if !current.is_object() {
                    return Err(PlanError::InvalidArgumentPointer);
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn set_object_pointer(
    arguments: &mut Value,
    pointer: &str,
    value: Value,
) -> Result<(), PlanError> {
    let segments = decode_object_pointer(pointer)?;
    let (last, parents) = segments
        .split_last()
        .ok_or(PlanError::InvalidArgumentPointer)?;
    let mut current = arguments;
    for segment in parents {
        current = current
            .as_object_mut()
            .and_then(|object| object.get_mut(segment))
            .ok_or(PlanError::InvalidArgumentPointer)?;
    }
    current
        .as_object_mut()
        .ok_or(PlanError::InvalidArgumentPointer)?
        .insert(last.clone(), value);
    Ok(())
}

fn capture_object_paths(
    value: &Value,
    path: &mut Vec<String>,
    object_paths: &mut BTreeSet<Vec<String>>,
) {
    let Some(object) = value.as_object() else {
        return;
    };
    object_paths.insert(path.clone());
    if path.len() >= MAX_POINTER_DEPTH - 1 {
        return;
    }
    for (key, value) in object {
        path.push(key.clone());
        capture_object_paths(value, path, object_paths);
        let _ = path.pop();
    }
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

fn valid_key(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn validate_message(message: &str) -> Result<(), PlanError> {
    if message.trim().is_empty()
        || message.len() > MAX_MESSAGE_BYTES
        || message.chars().any(char::is_control)
    {
        return Err(PlanError::InvalidMessage);
    }
    Ok(())
}

fn validate_required(
    schema: &serde_json::Map<String, Value>,
    fields: &BTreeMap<String, FieldPlan>,
) -> Result<(), PlanError> {
    let Some(required) = schema.get("required") else {
        return Ok(());
    };
    let required = required.as_array().ok_or(PlanError::InvalidSchema)?;
    let mut seen = BTreeSet::new();
    for value in required {
        let name = value.as_str().ok_or(PlanError::InvalidSchema)?;
        if !fields.contains_key(name) || !seen.insert(name) {
            return Err(PlanError::InvalidSchema);
        }
    }
    Ok(())
}

fn schema_mentions_credential(schema: &Value) -> bool {
    match schema {
        Value::String(value) => mentions_credential(value),
        Value::Array(values) => values.iter().any(schema_mentions_credential),
        Value::Object(object) => object
            .iter()
            .any(|(key, value)| mentions_credential(key) || schema_mentions_credential(value)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

fn mentions_credential(value: &str) -> bool {
    let normalized: String = value
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect();
    [
        "password",
        "passwd",
        "passphrase",
        "passcode",
        "apikey",
        "providerkey",
        "clientsecret",
        "oauthsecret",
        "secret",
        "accesskey",
        "accesstoken",
        "refreshtoken",
        "oauthtoken",
        "idtoken",
        "sessiontoken",
        "bearertoken",
        "authorization",
        "credential",
        "privatekey",
        "recoverycode",
        "mfacode",
        "onetimecode",
        "verificationcode",
        "securitycode",
        "2facode",
        "recoverykey",
        "authcode",
        "unlockcode",
        "seedphrase",
        "mnemonic",
    ]
    .iter()
    .any(|term| normalized.contains(term))
        || matches!(
            normalized.as_str(),
            "token" | "pat" | "seed" | "pin" | "otp" | "totp"
        )
        || normalized.ends_with("token")
        || normalized.ends_with("otp")
}

fn validate_object_pointer(pointer: &str) -> Result<(), PlanError> {
    decode_object_pointer(pointer).map(|_| ())
}

fn decode_object_pointer(pointer: &str) -> Result<Vec<String>, PlanError> {
    if !pointer.starts_with('/') {
        return Err(PlanError::InvalidArgumentPointer);
    }
    let raw_segments = pointer[1..].split('/').collect::<Vec<_>>();
    if raw_segments.is_empty() || raw_segments.len() > MAX_POINTER_DEPTH {
        return Err(PlanError::InvalidArgumentPointer);
    }
    let mut segments = Vec::with_capacity(raw_segments.len());
    for raw in raw_segments {
        if raw.is_empty() || raw.len() > MAX_POINTER_SEGMENT_BYTES || !raw.is_ascii() {
            return Err(PlanError::InvalidArgumentPointer);
        }
        let bytes = raw.as_bytes();
        let mut decoded = String::with_capacity(raw.len());
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] != b'~' {
                decoded.push(char::from(bytes[index]));
                index += 1;
                continue;
            }
            if index + 1 >= bytes.len() {
                return Err(PlanError::InvalidArgumentPointer);
            }
            match bytes[index + 1] {
                b'0' => decoded.push('~'),
                b'1' => decoded.push('/'),
                _ => return Err(PlanError::InvalidArgumentPointer),
            }
            index += 2;
        }
        segments.push(decoded);
    }
    Ok(segments)
}
