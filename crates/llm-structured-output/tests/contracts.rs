//! Behavioral contracts for bounded structured output.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, ModelCapability, ModelCapabilityDeclaration,
    ModelCapabilityKey, OutputMode, OutputRequest, ProviderError, ProviderErrorKind,
    RawRetentionPolicy, RawRetentionState, RetryClass, SchemaDefinition, StructuredValidation,
    Usage,
};
use omnius_llm_structured_output::{
    CandidateInvalidKind, FallbackPermission, MAX_REPAIR_ATTEMPTS, PreparationError,
    PreparedStructuredOutput, RepairCandidate, RepairPolicy, RepairRequest, RepairToolPolicy,
    StrategyPolicy, StrategySelectionError, StructuredOutputError, StructuredOutputRepairPort,
    StructuredOutputStrategy, schema_definition_for,
};
use omnius_validation::{JsonValidationLimits, SchemaAdapterError};
use proptest::prelude::*;
use schemars::JsonSchema;
use serde_json::{Value, json};

#[derive(JsonSchema)]
struct OwnedContact {
    name: String,
    enabled: bool,
}

struct FakeRepairPort {
    responses: Mutex<VecDeque<RepairCandidate>>,
    calls: AtomicUsize,
    tool_policy_violation: AtomicBool,
    attempts: Mutex<Vec<u8>>,
    request_debug: Mutex<Vec<String>>,
}

impl FakeRepairPort {
    fn new(responses: Vec<RepairCandidate>) -> Self {
        Self {
            responses: Mutex::new(responses.into()),
            calls: AtomicUsize::new(0),
            tool_policy_violation: AtomicBool::new(false),
            attempts: Mutex::new(Vec::new()),
            request_debug: Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    fn tool_policy_violation(&self) -> bool {
        self.tool_policy_violation.load(Ordering::Relaxed)
    }

    fn attempts(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        self.attempts
            .lock()
            .map(|attempts| attempts.clone())
            .map_err(|_| std::io::Error::other("fake attempts unavailable").into())
    }

    fn request_debug(&self) -> Result<Vec<String>, Box<dyn Error>> {
        self.request_debug
            .lock()
            .map(|values| values.clone())
            .map_err(|_| std::io::Error::other("fake debug unavailable").into())
    }
}

#[async_trait]
impl StructuredOutputRepairPort for FakeRepairPort {
    async fn repair(&self, request: RepairRequest<'_>) -> Result<RepairCandidate, ProviderError> {
        let _ = self.calls.fetch_add(1, Ordering::Relaxed);
        if request.tool_policy() != RepairToolPolicy::Disabled {
            self.tool_policy_violation.store(true, Ordering::Relaxed);
        }
        self.attempts
            .lock()
            .map_err(|_| fake_provider_error())?
            .push(request.attempt());
        self.request_debug
            .lock()
            .map_err(|_| fake_provider_error())?
            .push(format!("{request:?}"));
        self.responses
            .lock()
            .map_err(|_| fake_provider_error())?
            .pop_front()
            .ok_or_else(fake_provider_error)
    }
}

struct FailingRepairPort {
    error_body: String,
}

#[async_trait]
impl StructuredOutputRepairPort for FailingRepairPort {
    async fn repair(&self, request: RepairRequest<'_>) -> Result<RepairCandidate, ProviderError> {
        if request.tool_policy() != RepairToolPolicy::Disabled {
            return Err(fake_provider_error());
        }
        Err(ProviderError::new(
            "fixture-provider".to_owned(),
            ProviderErrorKind::Provider,
            RetryClass::Never,
        )
        .with_transport_metadata(
            Some(500),
            None,
            None,
            omnius_llm_core::RetainedRaw::from_body(RawRetentionPolicy::Full, &self.error_body),
        ))
    }
}

fn fake_provider_error() -> ProviderError {
    ProviderError::new(
        "fixture-provider".to_owned(),
        ProviderErrorKind::Provider,
        RetryClass::Never,
    )
}

fn declaration(
    capabilities: &[ModelCapability],
) -> Result<ModelCapabilityDeclaration, Box<dyn Error>> {
    let evidence = capabilities
        .iter()
        .copied()
        .map(|capability| {
            CapabilityEvidence::new(CapabilityEvidenceSource::Configured, "fixture-revision")
                .map(|evidence| (capability, evidence))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(ModelCapabilityDeclaration::new(
        ModelCapabilityKey::new(
            "fixture-provider",
            "fixture-model",
            "fixture-model-revision",
        )?,
        "fixture-registry-revision",
        evidence,
        BTreeSet::new(),
        None,
        None,
    )?)
}

fn output_request(schema: Value, strict: Option<bool>) -> Result<OutputRequest, Box<dyn Error>> {
    let schema = serde_json::from_value::<SchemaDefinition>(schema)?;
    Ok(OutputRequest::new(OutputMode::Structured).with_schema(
        Some("fixture-schema".to_owned()),
        Some(schema),
        strict,
    )?)
}

fn prepare(
    schema: Value,
    strict: Option<bool>,
    capabilities: &[ModelCapability],
    policy: StrategyPolicy,
    limits: JsonValidationLimits,
) -> Result<PreparedStructuredOutput, PreparationError> {
    let output = output_request(schema, strict).map_err(|_| PreparationError::SchemaEncoding)?;
    let model = declaration(capabilities).map_err(|_| PreparationError::SchemaEncoding)?;
    PreparedStructuredOutput::prepare(&output, &model, policy, limits)
}

#[test]
fn schemars_owned_schema_compiles_as_draft_2020_12() -> Result<(), Box<dyn Error>> {
    let schema = schema_definition_for::<OwnedContact>()?;
    let request = OutputRequest::new(OutputMode::Structured).with_schema(
        Some("fixture-schema".to_owned()),
        Some(schema),
        Some(true),
    )?;
    let model = declaration(&[ModelCapability::StrictJsonSchema])?;
    let prepared = PreparedStructuredOutput::prepare(
        &request,
        &model,
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let owned = OwnedContact {
        name: "Ada".to_owned(),
        enabled: true,
    };
    assert!(owned.enabled && !owned.name.is_empty());

    assert_eq!(
        prepared.strategy(),
        StructuredOutputStrategy::NativeStrictSchema
    );
    let generated: Value = serde_json::from_slice(prepared.schema_json())?;
    assert_eq!(
        generated.get("$schema"),
        Some(&json!("https://json-schema.org/draft/2020-12/schema"))
    );
    Ok(())
}

#[tokio::test]
async fn local_reference_and_format_are_enforced() -> Result<(), Box<dyn Error>> {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {
            "address": {"type": "string", "format": "email"}
        },
        "$ref": "#/$defs/address"
    });
    let prepared = prepare(
        schema,
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FakeRepairPort::new(Vec::new());
    let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)?;

    let valid = prepared
        .validate_and_repair(
            "part-email".to_owned(),
            json!("person@example.com"),
            policy,
            &repair,
        )
        .await?;
    assert_eq!(valid.part().validation(), StructuredValidation::Valid);

    let invalid = prepared
        .validate_and_repair(
            "part-bad-email".to_owned(),
            json!("not-an-email"),
            policy,
            &repair,
        )
        .await;
    assert!(matches!(
        invalid,
        Err(StructuredOutputError::Invalid(error))
            if error.last_invalid_kind() == CandidateInvalidKind::SchemaMismatch
    ));
    Ok(())
}

#[test]
fn non_local_reference_fails_during_preparation() {
    let result = prepare(
        json!({"$ref": "https://schemas.example.invalid/secret.json"}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    );

    assert!(matches!(
        result,
        Err(PreparationError::Schema(
            SchemaAdapterError::NonLocalReference
        ))
    ));
}

#[test]
fn dynamic_non_local_reference_and_invalid_schema_fail_during_preparation() {
    let dynamic = prepare(
        json!({"$dynamicRef": "file:///private/schema.json"}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    );
    assert!(matches!(
        dynamic,
        Err(PreparationError::Schema(
            SchemaAdapterError::NonLocalReference
        ))
    ));

    let malformed = prepare(
        json!({"type": 42}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    );
    assert!(matches!(
        malformed,
        Err(PreparationError::Schema(SchemaAdapterError::InvalidSchema))
    ));
}

#[test]
fn schema_byte_bound_fails_during_preparation() {
    let limits = JsonValidationLimits {
        max_schema_bytes: 32,
        ..JsonValidationLimits::default()
    };
    let result = prepare(
        json!({"type": "string", "description": "long schema description"}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        limits,
    );

    assert!(matches!(
        result,
        Err(PreparationError::Schema(SchemaAdapterError::TooLarge))
    ));
}

#[tokio::test]
async fn payload_byte_and_structure_bounds_are_terminal_invalid_data() -> Result<(), Box<dyn Error>>
{
    let byte_limits = JsonValidationLimits {
        max_payload_bytes: 8,
        ..JsonValidationLimits::default()
    };
    let byte_prepared = prepare(
        json!(true),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        byte_limits,
    )?;
    let no_repairs = FakeRepairPort::new(Vec::new());
    let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)?;
    let byte_result = byte_prepared
        .validate_and_repair(
            "part-bytes".to_owned(),
            json!("more-than-eight-bytes"),
            policy,
            &no_repairs,
        )
        .await;
    assert!(matches!(
        byte_result,
        Err(StructuredOutputError::Invalid(error))
            if error.last_invalid_kind() == CandidateInvalidKind::PayloadTooLarge
    ));

    let structure_limits = JsonValidationLimits {
        max_array_items: 1,
        ..JsonValidationLimits::default()
    };
    let structure_prepared = prepare(
        json!(true),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        structure_limits,
    )?;
    let structure_result = structure_prepared
        .validate_and_repair(
            "part-structure".to_owned(),
            json!([1, 2]),
            policy,
            &no_repairs,
        )
        .await;
    assert!(matches!(
        structure_result,
        Err(StructuredOutputError::Invalid(error))
            if error.last_invalid_kind() == CandidateInvalidKind::StructureLimit
    ));
    Ok(())
}

#[tokio::test]
async fn boolean_schemas_and_non_object_instance_roots_are_supported() -> Result<(), Box<dyn Error>>
{
    let true_schema = prepare(
        json!(true),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let no_repairs = FakeRepairPort::new(Vec::new());
    let policy = RepairPolicy::new(0, RawRetentionPolicy::Discard)?;
    let scalar = true_schema
        .validate_and_repair("part-scalar".to_owned(), json!(42), policy, &no_repairs)
        .await?;
    assert_eq!(scalar.part().value(), &json!(42));

    let array_schema = prepare(
        json!({"type": "array", "items": {"type": "boolean"}}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let array = array_schema
        .validate_and_repair(
            "part-array".to_owned(),
            json!([true, false]),
            policy,
            &no_repairs,
        )
        .await?;
    assert_eq!(array.part().value(), &json!([true, false]));

    let false_schema = prepare(
        json!(false),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let rejected = false_schema
        .validate_and_repair("part-false".to_owned(), json!(null), policy, &no_repairs)
        .await;
    assert!(matches!(rejected, Err(StructuredOutputError::Invalid(_))));
    Ok(())
}

#[test]
fn strategy_precedence_uses_exact_capability_evidence() -> Result<(), Box<dyn Error>> {
    let both = declaration(&[
        ModelCapability::StrictJsonSchema,
        ModelCapability::StrictToolOutput,
    ])?;
    let decision = omnius_llm_structured_output::StrategyDecision::select(
        &both,
        StrategyPolicy::new(FallbackPermission::Allow, FallbackPermission::Allow),
        false,
    )?;
    assert_eq!(
        decision.strategy(),
        StructuredOutputStrategy::NativeStrictSchema
    );
    assert!(decision.capability_evidence().is_some());

    let tool_only = declaration(&[ModelCapability::StrictToolOutput])?;
    let decision = omnius_llm_structured_output::StrategyDecision::select(
        &tool_only,
        StrategyPolicy::new(FallbackPermission::Allow, FallbackPermission::Allow),
        false,
    )?;
    assert_eq!(
        decision.strategy(),
        StructuredOutputStrategy::NativeStrictTool
    );

    let tools_are_not_strict = declaration(&[ModelCapability::Tools])?;
    let result = omnius_llm_structured_output::StrategyDecision::select(
        &tools_are_not_strict,
        StrategyPolicy::native_only(),
        false,
    );
    assert_eq!(result, Err(StrategySelectionError::NoPermittedStrategy));
    Ok(())
}

#[test]
fn fallback_tiers_require_explicit_permission_and_never_weaken_strict_prompt_output()
-> Result<(), Box<dyn Error>> {
    let unsupported = declaration(&[])?;
    let none = omnius_llm_structured_output::StrategyDecision::select(
        &unsupported,
        StrategyPolicy::native_only(),
        false,
    );
    assert_eq!(none, Err(StrategySelectionError::NoPermittedStrategy));

    let constrained = omnius_llm_structured_output::StrategyDecision::select(
        &unsupported,
        StrategyPolicy::new(FallbackPermission::Allow, FallbackPermission::Allow),
        true,
    )?;
    assert_eq!(
        constrained.strategy(),
        StructuredOutputStrategy::ConstrainedFallback
    );
    assert!(constrained.is_explicit_fallback());

    let prompt = omnius_llm_structured_output::StrategyDecision::select(
        &unsupported,
        StrategyPolicy::new(FallbackPermission::Deny, FallbackPermission::Allow),
        false,
    )?;
    assert_eq!(prompt.strategy(), StructuredOutputStrategy::PromptJson);

    let strict_prompt = omnius_llm_structured_output::StrategyDecision::select(
        &unsupported,
        StrategyPolicy::new(FallbackPermission::Deny, FallbackPermission::Allow),
        true,
    );
    assert_eq!(
        strict_prompt,
        Err(StrategySelectionError::StrictPromptDowngrade)
    );
    Ok(())
}

#[test]
fn preparation_authorizes_only_the_exact_output_contract() -> Result<(), Box<dyn Error>> {
    let schema = json!({"type": "integer"});
    let request = output_request(schema.clone(), Some(false))?
        .with_mime_types(vec!["application/json".to_owned()])?;
    let model = declaration(&[ModelCapability::StrictJsonSchema])?;
    let prepared = PreparedStructuredOutput::prepare(
        &request,
        &model,
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    assert!(prepared.authorizes(&request));
    assert!(prepared.authorizes_target(model.key(), model.registry_revision()));

    let different_strictness = output_request(schema.clone(), None)?
        .with_mime_types(vec!["application/json".to_owned()])?;
    assert!(!prepared.authorizes(&different_strictness));

    let different_schema = output_request(json!({"type": "string"}), Some(false))?
        .with_mime_types(vec!["application/json".to_owned()])?;
    assert!(!prepared.authorizes(&different_schema));

    let different_mime = output_request(schema, Some(false))?;
    assert!(!prepared.authorizes(&different_mime));
    Ok(())
}

#[tokio::test]
async fn valid_first_candidate_returns_without_repair() -> Result<(), Box<dyn Error>> {
    let prepared = prepare(
        json!({"type": "integer", "minimum": 10}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FakeRepairPort::new(Vec::new());
    let output = prepared
        .validate_and_repair(
            "part-valid".to_owned(),
            json!(10),
            RepairPolicy::new(2, RawRetentionPolicy::Full)?,
            &repair,
        )
        .await?;

    assert_eq!(output.part().validation(), StructuredValidation::Valid);
    assert_eq!(output.part().repair_attempts(), 0);
    assert_eq!(output.part().schema_id(), Some("fixture-schema"));
    assert!(output.repair_metering().is_empty());
    assert_eq!(
        output.original_invalid().state(),
        RawRetentionState::Discarded
    );
    assert_eq!(repair.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn invalid_candidate_is_repaired_revalidated_and_metered_without_tools()
-> Result<(), Box<dyn Error>> {
    let prepared = prepare(
        json!({"type": "integer", "minimum": 10}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FakeRepairPort::new(vec![RepairCandidate::new(
        json!(11),
        Usage::new(Some(7), Some(3)),
    )]);
    let output = prepared
        .validate_and_repair(
            "part-repaired".to_owned(),
            json!(1),
            RepairPolicy::new(2, RawRetentionPolicy::Redacted)?,
            &repair,
        )
        .await?;

    assert_eq!(output.part().value(), &json!(11));
    assert_eq!(output.part().repair_attempts(), 1);
    assert_eq!(output.repair_metering().len(), 1);
    assert_eq!(output.repair_metering()[0].attempt(), 1);
    assert_eq!(output.repair_metering()[0].usage().input_tokens(), Some(7));
    assert_eq!(output.repair_metering()[0].usage().output_tokens(), Some(3));
    assert_eq!(
        output.original_invalid().state(),
        RawRetentionState::Redacted
    );
    assert_eq!(repair.calls(), 1);
    assert_eq!(repair.attempts()?, vec![1]);
    assert!(!repair.tool_policy_violation());
    Ok(())
}

#[tokio::test]
async fn zero_repair_budget_is_typed_terminal_invalid_without_provider_call()
-> Result<(), Box<dyn Error>> {
    let prepared = prepare(
        json!({"type": "integer", "minimum": 10}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FakeRepairPort::new(Vec::new());
    let result = prepared
        .validate_and_repair(
            "part-zero".to_owned(),
            json!(1),
            RepairPolicy::new(0, RawRetentionPolicy::Discard)?,
            &repair,
        )
        .await;

    assert!(matches!(
        result,
        Err(StructuredOutputError::Invalid(error))
            if error.repair_attempts() == 0 && error.repair_metering().is_empty()
    ));
    assert_eq!(repair.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn exhausted_repair_budget_returns_last_invalid_with_separate_metering()
-> Result<(), Box<dyn Error>> {
    let prepared = prepare(
        json!({"type": "integer", "minimum": 10}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FakeRepairPort::new(vec![
        RepairCandidate::new(json!(2), Usage::new(Some(2), Some(1))),
        RepairCandidate::new(json!(3), Usage::new(Some(4), Some(2))),
    ]);
    let result = prepared
        .validate_and_repair(
            "part-exhausted".to_owned(),
            json!(1),
            RepairPolicy::new(2, RawRetentionPolicy::Discard)?,
            &repair,
        )
        .await;

    let Err(StructuredOutputError::Invalid(error)) = result else {
        return Err(std::io::Error::other("expected terminal invalid data").into());
    };
    assert_eq!(error.repair_attempts(), 2);
    assert_eq!(error.repair_metering().len(), 2);
    assert_eq!(error.repair_metering()[0].usage().input_tokens(), Some(2));
    assert_eq!(error.repair_metering()[1].usage().input_tokens(), Some(4));
    assert_eq!(repair.attempts()?, vec![1, 2]);
    assert!(!repair.tool_policy_violation());
    Ok(())
}

#[test]
fn repair_budget_has_a_small_hard_ceiling() {
    let result = RepairPolicy::new(
        MAX_REPAIR_ATTEMPTS.saturating_add(1),
        RawRetentionPolicy::Discard,
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn errors_debug_and_raw_retention_are_redacted_by_default_and_explicit_when_full()
-> Result<(), Box<dyn Error>> {
    const SECRET: &str = "MODEL_SECRET_9d9f";
    let schema = json!({
        "type": "object",
        "required": [SECRET],
        "properties": {SECRET: {"type": "integer"}}
    });
    let prepared = prepare(
        schema,
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    assert!(!format!("{prepared:?}").contains(SECRET));

    let repair = FakeRepairPort::new(vec![RepairCandidate::new(
        json!({SECRET: "still-invalid"}),
        Usage::new(None, None),
    )]);
    let result = prepared
        .validate_and_repair(
            "part-redacted".to_owned(),
            json!({"payload": SECRET}),
            RepairPolicy::new(1, RawRetentionPolicy::Redacted)?,
            &repair,
        )
        .await;
    let Err(StructuredOutputError::Invalid(error)) = result else {
        return Err(std::io::Error::other("expected invalid data").into());
    };
    assert!(!format!("{error:?}").contains(SECRET));
    assert!(!error.to_string().contains(SECRET));
    assert_eq!(
        error.original_invalid().state(),
        RawRetentionState::Redacted
    );
    assert!(error.original_invalid().full_payload().is_none());
    assert!(
        repair
            .request_debug()?
            .iter()
            .all(|debug| !debug.contains(SECRET))
    );

    let full_repair = FakeRepairPort::new(Vec::new());
    let full = prepared
        .validate_and_repair(
            "part-full".to_owned(),
            json!({"payload": SECRET}),
            RepairPolicy::new(0, RawRetentionPolicy::Full)?,
            &full_repair,
        )
        .await;
    let Err(StructuredOutputError::Invalid(full_error)) = full else {
        return Err(std::io::Error::other("expected invalid data").into());
    };
    assert_eq!(
        full_error.original_invalid().state(),
        RawRetentionState::Full
    );
    assert!(full_error.original_invalid().full_payload().is_some());
    assert!(!format!("{full_error:?}").contains(SECRET));
    Ok(())
}

#[tokio::test]
async fn provider_failure_does_not_render_provider_body() -> Result<(), Box<dyn Error>> {
    const SECRET_BODY: &str = "provider-body-secret-314";
    let prepared = prepare(
        json!({"type": "integer", "minimum": 10}),
        Some(true),
        &[ModelCapability::StrictJsonSchema],
        StrategyPolicy::native_only(),
        JsonValidationLimits::default(),
    )?;
    let repair = FailingRepairPort {
        error_body: SECRET_BODY.to_owned(),
    };
    let result = prepared
        .validate_and_repair(
            "part-provider-failure".to_owned(),
            json!(1),
            RepairPolicy::new(1, RawRetentionPolicy::Discard)?,
            &repair,
        )
        .await;
    let Err(StructuredOutputError::RepairProvider(error)) = result else {
        return Err(std::io::Error::other("expected repair provider failure").into());
    };
    assert!(!format!("{error:?}").contains(SECRET_BODY));
    assert!(!error.to_string().contains(SECRET_BODY));
    Ok(())
}

proptest! {
    #[test]
    fn native_strict_schema_precedes_every_other_permitted_tier(
        allow_constrained in any::<bool>(),
        allow_prompt in any::<bool>(),
        strict_required in any::<bool>(),
    ) {
        let model = declaration(&[
            ModelCapability::StrictJsonSchema,
            ModelCapability::StrictToolOutput,
        ]).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let policy = StrategyPolicy::new(
            if allow_constrained { FallbackPermission::Allow } else { FallbackPermission::Deny },
            if allow_prompt { FallbackPermission::Allow } else { FallbackPermission::Deny },
        );
        let decision = omnius_llm_structured_output::StrategyDecision::select(
            &model,
            policy,
            strict_required,
        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(decision.strategy(), StructuredOutputStrategy::NativeStrictSchema);
    }
}
