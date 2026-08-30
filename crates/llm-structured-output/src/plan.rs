use std::fmt;

use omnius_llm_core::{
    CapabilityEvidence, ModelCapability, ModelCapabilityDeclaration, ModelCapabilityKey,
    OutputMode, OutputRequest,
};
use omnius_validation::{JsonSchemaAdapter, JsonValidationLimits, SchemaAdapterError};
use thiserror::Error;

use crate::{
    bounded_json::{BoundedJsonEncodeError, encode_bounded},
    json_shape::validate_schema_shape,
};

/// One explicit structured-output implementation strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StructuredOutputStrategy {
    /// Provider-native strict JSON Schema output.
    NativeStrictSchema,
    /// Provider-native strict tool/function output.
    NativeStrictTool,
    /// An explicitly permitted constrained-generation implementation.
    ConstrainedFallback,
    /// Prompt-only JSON under an explicitly permitted weak-guarantee route.
    PromptJson,
}

/// Explicit permission for a non-native structured-output strategy.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FallbackPermission {
    /// The route does not permit this strategy.
    #[default]
    Deny,
    /// The route knowingly permits this strategy.
    Allow,
}

/// Route policy for non-native structured-output strategies.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StrategyPolicy {
    constrained_fallback: FallbackPermission,
    prompt_json: FallbackPermission,
}

impl StrategyPolicy {
    /// Creates an explicit policy for both fallback tiers.
    #[must_use]
    pub const fn new(
        constrained_fallback: FallbackPermission,
        prompt_json: FallbackPermission,
    ) -> Self {
        Self {
            constrained_fallback,
            prompt_json,
        }
    }

    /// Returns a policy that permits native strategies only.
    #[must_use]
    pub const fn native_only() -> Self {
        Self::new(FallbackPermission::Deny, FallbackPermission::Deny)
    }

    /// Returns the constrained-fallback permission.
    #[must_use]
    pub const fn constrained_fallback(self) -> FallbackPermission {
        self.constrained_fallback
    }

    /// Returns the prompt-only JSON permission.
    #[must_use]
    pub const fn prompt_json(self) -> FallbackPermission {
        self.prompt_json
    }
}

/// Why no structured-output strategy could preserve the request contract.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StrategySelectionError {
    /// No native strategy had capability evidence and no fallback was explicitly permitted.
    #[error("no evidenced or explicitly permitted structured-output strategy is available")]
    NoPermittedStrategy,
    /// Prompt-only JSON would weaken an explicit strict-output requirement.
    #[error("prompt-only JSON cannot satisfy an explicit strict-output requirement")]
    StrictPromptDowngrade,
}

/// An observable, evidence-backed or explicitly permitted strategy choice.
#[derive(Clone, PartialEq)]
pub struct StrategyDecision {
    strategy: StructuredOutputStrategy,
    evidence: Option<CapabilityEvidence>,
}

impl StrategyDecision {
    /// Selects the first supported strategy in normative preference order.
    ///
    /// Native tiers require exact T155 capability evidence. `Tools` alone is
    /// deliberately not treated as strict-tool evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed no-downgrade error when no strategy can preserve the request.
    pub fn select(
        declaration: &ModelCapabilityDeclaration,
        policy: StrategyPolicy,
        strict_required: bool,
    ) -> Result<Self, StrategySelectionError> {
        if let Some(evidence) = declaration
            .evidence()
            .get(&ModelCapability::StrictJsonSchema)
        {
            return Ok(Self {
                strategy: StructuredOutputStrategy::NativeStrictSchema,
                evidence: Some(evidence.clone()),
            });
        }
        if let Some(evidence) = declaration
            .evidence()
            .get(&ModelCapability::StrictToolOutput)
        {
            return Ok(Self {
                strategy: StructuredOutputStrategy::NativeStrictTool,
                evidence: Some(evidence.clone()),
            });
        }
        if policy.constrained_fallback == FallbackPermission::Allow {
            return Ok(Self {
                strategy: StructuredOutputStrategy::ConstrainedFallback,
                evidence: None,
            });
        }
        if policy.prompt_json == FallbackPermission::Allow {
            if strict_required {
                return Err(StrategySelectionError::StrictPromptDowngrade);
            }
            return Ok(Self {
                strategy: StructuredOutputStrategy::PromptJson,
                evidence: None,
            });
        }
        Err(StrategySelectionError::NoPermittedStrategy)
    }

    /// Returns the selected strategy.
    #[must_use]
    pub const fn strategy(&self) -> StructuredOutputStrategy {
        self.strategy
    }

    /// Borrows the exact capability evidence for a native strategy.
    ///
    /// Fallback strategies return `None`; their basis is the explicit route policy.
    #[must_use]
    pub const fn capability_evidence(&self) -> Option<&CapabilityEvidence> {
        self.evidence.as_ref()
    }

    /// Reports whether this decision depends on explicit fallback permission.
    #[must_use]
    pub const fn is_explicit_fallback(&self) -> bool {
        self.evidence.is_none()
    }
}

impl fmt::Debug for StrategyDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StrategyDecision")
            .field("strategy", &self.strategy)
            .field("has_capability_evidence", &self.evidence.is_some())
            .finish()
    }
}

/// Failure to prepare a bounded structured-output request.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum PreparationError {
    /// This boundary only prepares requests that require structured output.
    #[error("structured-output preparation requires structured output mode")]
    OutputMode,
    /// Structured output requires a schema.
    #[error("structured-output preparation requires a JSON Schema")]
    MissingSchema,
    /// The canonical schema could not be serialized.
    #[error("JSON Schema could not be encoded")]
    SchemaEncoding,
    /// Bounded local Draft 2020-12 compilation failed.
    #[error(transparent)]
    Schema(#[from] SchemaAdapterError),
    /// No strategy could preserve the request contract.
    #[error(transparent)]
    Strategy(#[from] StrategySelectionError),
}

/// A locally compiled schema and admitted provider strategy.
///
/// Provider adapters may inspect the canonical schema only after receiving this
/// value. `Debug` never renders the schema or schema identifier.
#[derive(Clone)]
pub struct PreparedStructuredOutput {
    pub(crate) validator: JsonSchemaAdapter,
    schema_json: Box<[u8]>,
    schema_id: Option<String>,
    strict: Option<bool>,
    decision: StrategyDecision,
    model_key: ModelCapabilityKey,
    registry_revision: String,
    mime_types: Vec<String>,
}

impl PreparedStructuredOutput {
    /// Compiles and admits one canonical structured-output request.
    ///
    /// # Errors
    ///
    /// Returns [`PreparationError`] before provider use when the mode, schema,
    /// safety bounds, capability evidence, or explicit route policy is insufficient.
    pub fn prepare(
        output: &OutputRequest,
        declaration: &ModelCapabilityDeclaration,
        policy: StrategyPolicy,
        limits: JsonValidationLimits,
    ) -> Result<Self, PreparationError> {
        if output.mode() != OutputMode::Structured {
            return Err(PreparationError::OutputMode);
        }
        let schema = output.schema().ok_or(PreparationError::MissingSchema)?;
        let strict_required = output.strict() == Some(true);
        let decision = StrategyDecision::select(declaration, policy, strict_required)?;
        let limits = limits
            .validate()
            .map_err(SchemaAdapterError::from)
            .map_err(PreparationError::Schema)?;
        validate_schema_shape(schema, limits)
            .map_err(SchemaAdapterError::Structure)
            .map_err(PreparationError::Schema)?;
        let schema_json = match encode_bounded(schema, limits.max_schema_bytes) {
            Ok(schema_json) => schema_json,
            Err(BoundedJsonEncodeError::TooLarge) => {
                return Err(PreparationError::Schema(SchemaAdapterError::TooLarge));
            }
            Err(BoundedJsonEncodeError::Encode) => {
                return Err(PreparationError::SchemaEncoding);
            }
        };
        let validator = JsonSchemaAdapter::compile(&schema_json, limits)?;
        Ok(Self {
            validator,
            schema_json,
            schema_id: output.schema_id().map(str::to_owned),
            strict: output.strict(),
            decision,
            model_key: declaration.key().clone(),
            registry_revision: declaration.registry_revision().to_owned(),
            mime_types: output.mime_types().to_vec(),
        })
    }

    /// Returns the selected provider strategy and its admission basis.
    #[must_use]
    pub const fn decision(&self) -> &StrategyDecision {
        &self.decision
    }

    /// Borrows the exact provider/model/revision identity whose evidence admitted the strategy.
    #[must_use]
    pub const fn model_key(&self) -> &ModelCapabilityKey {
        &self.model_key
    }

    /// Borrows the capability-registry revision used for admission.
    #[must_use]
    pub fn registry_revision(&self) -> &str {
        &self.registry_revision
    }

    /// Verifies the exact target and registry revision used for capability admission.
    #[must_use]
    pub fn authorizes_target(
        &self,
        model_key: &ModelCapabilityKey,
        registry_revision: &str,
    ) -> bool {
        &self.model_key == model_key && self.registry_revision == registry_revision
    }

    /// Returns the selected provider strategy.
    #[must_use]
    pub const fn strategy(&self) -> StructuredOutputStrategy {
        self.decision.strategy()
    }

    /// Borrows canonical schema JSON for a provider adapter.
    ///
    /// The bytes contain sensitive request schema and must not be logged.
    #[must_use]
    pub fn schema_json(&self) -> &[u8] {
        &self.schema_json
    }

    /// Borrows the optional canonical schema identifier.
    #[must_use]
    pub fn schema_id(&self) -> Option<&str> {
        self.schema_id.as_deref()
    }

    /// Borrows the exact ordered MIME constraints included in preparation.
    #[must_use]
    pub fn mime_types(&self) -> &[String] {
        &self.mime_types
    }

    /// Reports whether the caller explicitly required strict output.
    #[must_use]
    pub fn strict_required(&self) -> bool {
        self.strict == Some(true)
    }

    /// Verifies that this preparation belongs to an exact output request.
    ///
    /// Provider adapters should fail closed if this returns `false`, preventing
    /// a prepared schema from being paired with a different request.
    #[must_use]
    pub fn authorizes(&self, output: &OutputRequest) -> bool {
        if output.mode() != OutputMode::Structured
            || output.schema_id() != self.schema_id()
            || output.strict() != self.strict
            || output.mime_types() != self.mime_types.as_slice()
        {
            return false;
        }
        output.schema().is_some_and(|schema| {
            encode_bounded(schema, self.validator.limits().max_schema_bytes)
                .is_ok_and(|encoded| encoded.as_ref() == self.schema_json.as_ref())
        })
    }

    pub(crate) fn schema_id_owned(&self) -> Option<String> {
        self.schema_id.clone()
    }
}

impl fmt::Debug for PreparedStructuredOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedStructuredOutput")
            .field("decision", &self.decision)
            .field("schema_bytes", &self.schema_json.len())
            .field("has_schema_id", &self.schema_id.is_some())
            .field("strict_required", &self.strict_required())
            .finish_non_exhaustive()
    }
}
