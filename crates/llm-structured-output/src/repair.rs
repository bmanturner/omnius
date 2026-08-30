use std::{error::Error, fmt};

use async_trait::async_trait;
use omnius_llm_core::{
    ProviderError, RawRetentionPolicy, RetainedRaw, StructuredOutputPart, StructuredValidation,
    Usage,
};
use omnius_validation::{JsonPayloadError, JsonSchemaAdapter};
use serde_json::Value;
use thiserror::Error;

use crate::{
    PreparedStructuredOutput, StructuredOutputStrategy,
    bounded_json::{BoundedJsonEncodeError, encode_bounded},
    json_shape::validate_value_shape,
};

/// Hard ceiling for provider repair calls made for one structured value.
pub const MAX_REPAIR_ATTEMPTS: u8 = 8;

/// Why a complete JSON candidate failed local admission.
///
/// The categories intentionally contain no schema paths or model-produced values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateInvalidKind {
    /// The canonical serialized value exceeded the configured payload byte limit.
    PayloadTooLarge,
    /// The complete value exceeded a configured structural limit.
    StructureLimit,
    /// The complete value did not satisfy the compiled schema.
    SchemaMismatch,
}

/// Invalid repair-budget configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("structured-output repair budget exceeds the hard limit")]
pub struct RepairBudgetError;

/// Bounded repair and original-invalid-value retention policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairPolicy {
    max_attempts: u8,
    raw_retention: RawRetentionPolicy,
}

impl RepairPolicy {
    /// Creates a bounded policy. Zero attempts is valid and disables repair.
    ///
    /// # Errors
    ///
    /// Returns [`RepairBudgetError`] above [`MAX_REPAIR_ATTEMPTS`].
    pub const fn new(
        max_attempts: u8,
        raw_retention: RawRetentionPolicy,
    ) -> Result<Self, RepairBudgetError> {
        if max_attempts > MAX_REPAIR_ATTEMPTS {
            return Err(RepairBudgetError);
        }
        Ok(Self {
            max_attempts,
            raw_retention,
        })
    }

    /// Returns the maximum number of provider repair calls.
    #[must_use]
    pub const fn max_attempts(self) -> u8 {
        self.max_attempts
    }

    /// Returns the explicit original-invalid-value retention policy.
    #[must_use]
    pub const fn raw_retention(self) -> RawRetentionPolicy {
        self.raw_retention
    }
}

/// Tool policy enforced for every repair request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairToolPolicy {
    /// Tool declarations and execution are disabled.
    Disabled,
}

/// One provider-neutral repair request over a complete JSON value.
pub struct RepairRequest<'a> {
    attempt: u8,
    strategy: StructuredOutputStrategy,
    schema_json: &'a [u8],
    schema_id: Option<&'a str>,
    invalid_value: &'a Value,
    invalid_kind: CandidateInvalidKind,
}

impl RepairRequest<'_> {
    /// Returns the one-based repair attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    /// Returns the admitted strategy used for the original provider call.
    #[must_use]
    pub const fn strategy(&self) -> StructuredOutputStrategy {
        self.strategy
    }

    /// Borrows canonical schema JSON for the repair adapter.
    ///
    /// These bytes are sensitive and must not be logged.
    #[must_use]
    pub const fn schema_json(&self) -> &[u8] {
        self.schema_json
    }

    /// Borrows the optional canonical schema identifier.
    #[must_use]
    pub const fn schema_id(&self) -> Option<&str> {
        self.schema_id
    }

    /// Borrows the complete invalid value for provider repair.
    ///
    /// This value is sensitive and must not be logged.
    #[must_use]
    pub const fn invalid_value(&self) -> &Value {
        self.invalid_value
    }

    /// Returns the content-free local failure category.
    #[must_use]
    pub const fn invalid_kind(&self) -> CandidateInvalidKind {
        self.invalid_kind
    }

    /// Returns the invariant tool policy for repair calls.
    #[must_use]
    pub const fn tool_policy(&self) -> RepairToolPolicy {
        RepairToolPolicy::Disabled
    }
}

impl fmt::Debug for RepairRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepairRequest")
            .field("attempt", &self.attempt)
            .field("strategy", &self.strategy)
            .field("schema_bytes", &self.schema_json.len())
            .field("has_schema_id", &self.schema_id.is_some())
            .field("invalid_kind", &self.invalid_kind)
            .field("tool_policy", &RepairToolPolicy::Disabled)
            .finish_non_exhaustive()
    }
}

/// One complete provider repair candidate and its separately reported usage.
pub struct RepairCandidate {
    value: Value,
    usage: Usage,
}

impl RepairCandidate {
    /// Creates a complete repair candidate with call-local usage evidence.
    #[must_use]
    pub const fn new(value: Value, usage: Usage) -> Self {
        Self { value, usage }
    }

    /// Borrows the complete candidate value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// Borrows usage attributable only to this repair call.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }

    fn into_parts(self) -> (Value, Usage) {
        (self.value, self.usage)
    }
}

impl fmt::Debug for RepairCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepairCandidate")
            .field("value", &"[REDACTED]")
            .field("usage", &self.usage)
            .finish()
    }
}

/// A small provider-neutral port for repairing complete structured values.
///
/// The request type cannot carry tool declarations and always reports
/// [`RepairToolPolicy::Disabled`]. Provider failures must use the canonical,
/// redacted [`ProviderError`] contract.
#[async_trait]
pub trait StructuredOutputRepairPort: Send + Sync {
    /// Attempts one repair without executing tools.
    async fn repair(&self, request: RepairRequest<'_>) -> Result<RepairCandidate, ProviderError>;
}

/// Metering evidence attributable to one completed repair provider call.
#[derive(Clone, PartialEq)]
pub struct RepairMetering {
    attempt: u8,
    usage: Usage,
}

impl RepairMetering {
    /// Returns the one-based repair attempt number.
    #[must_use]
    pub const fn attempt(&self) -> u8 {
        self.attempt
    }

    /// Borrows usage attributable only to this repair call.
    #[must_use]
    pub const fn usage(&self) -> &Usage {
        &self.usage
    }
}

impl fmt::Debug for RepairMetering {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepairMetering")
            .field("attempt", &self.attempt)
            .field("usage", &self.usage)
            .finish()
    }
}

/// A validated structured part plus bounded repair evidence.
pub struct ValidatedStructuredOutput {
    part: StructuredOutputPart,
    repair_metering: Box<[RepairMetering]>,
    original_invalid: RetainedRaw,
}

impl ValidatedStructuredOutput {
    /// Borrows the locally validated canonical output part.
    #[must_use]
    pub const fn part(&self) -> &StructuredOutputPart {
        &self.part
    }

    /// Borrows separately reported usage for every completed repair call.
    #[must_use]
    pub const fn repair_metering(&self) -> &[RepairMetering] {
        &self.repair_metering
    }

    /// Borrows policy-controlled retention of the original invalid value.
    #[must_use]
    pub const fn original_invalid(&self) -> &RetainedRaw {
        &self.original_invalid
    }

    /// Consumes the result into its canonical part and diagnostic evidence.
    #[must_use]
    pub fn into_parts(self) -> (StructuredOutputPart, Box<[RepairMetering]>, RetainedRaw) {
        (self.part, self.repair_metering, self.original_invalid)
    }
}

impl fmt::Debug for ValidatedStructuredOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedStructuredOutput")
            .field("repair_attempts", &self.part.repair_attempts())
            .field("metered_repairs", &self.repair_metering.len())
            .field("original_invalid_state", &self.original_invalid.state())
            .finish_non_exhaustive()
    }
}

/// Terminal invalid-structured-data outcome after zero or exhausted repairs.
pub struct InvalidStructuredOutput {
    last_invalid_kind: CandidateInvalidKind,
    repair_attempts: u8,
    repair_metering: Box<[RepairMetering]>,
    original_invalid: RetainedRaw,
}

impl InvalidStructuredOutput {
    /// Returns the final content-free validation failure category.
    #[must_use]
    pub const fn last_invalid_kind(&self) -> CandidateInvalidKind {
        self.last_invalid_kind
    }

    /// Returns the number of completed repair calls.
    #[must_use]
    pub const fn repair_attempts(&self) -> u8 {
        self.repair_attempts
    }

    /// Borrows separately reported usage for every completed repair call.
    #[must_use]
    pub const fn repair_metering(&self) -> &[RepairMetering] {
        &self.repair_metering
    }

    /// Borrows policy-controlled retention of the original invalid value.
    #[must_use]
    pub const fn original_invalid(&self) -> &RetainedRaw {
        &self.original_invalid
    }
}

impl fmt::Debug for InvalidStructuredOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvalidStructuredOutput")
            .field("last_invalid_kind", &self.last_invalid_kind)
            .field("repair_attempts", &self.repair_attempts)
            .field("metered_repairs", &self.repair_metering.len())
            .field("original_invalid_state", &self.original_invalid.state())
            .finish()
    }
}

impl fmt::Display for InvalidStructuredOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("structured output remained invalid after bounded local validation")
    }
}

impl Error for InvalidStructuredOutput {}

/// A repair provider failed before returning a complete candidate.
pub struct RepairProviderFailure {
    repair_attempt: u8,
    repair_metering: Box<[RepairMetering]>,
    original_invalid: RetainedRaw,
    source: ProviderError,
}

impl RepairProviderFailure {
    /// Returns the one-based provider call that failed.
    #[must_use]
    pub const fn repair_attempt(&self) -> u8 {
        self.repair_attempt
    }

    /// Borrows evidence for completed repair calls preceding the failure.
    #[must_use]
    pub const fn repair_metering(&self) -> &[RepairMetering] {
        &self.repair_metering
    }

    /// Borrows policy-controlled retention of the original invalid value.
    #[must_use]
    pub const fn original_invalid(&self) -> &RetainedRaw {
        &self.original_invalid
    }

    /// Borrows the canonical redacted provider error.
    #[must_use]
    pub const fn provider_error(&self) -> &ProviderError {
        &self.source
    }
}

impl fmt::Debug for RepairProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RepairProviderFailure")
            .field("repair_attempt", &self.repair_attempt)
            .field("metered_repairs", &self.repair_metering.len())
            .field("original_invalid_state", &self.original_invalid.state())
            .field("provider_error_kind", &self.source.kind())
            .field("provider_retry_class", &self.source.retry_class())
            .finish()
    }
}

impl fmt::Display for RepairProviderFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("structured-output repair provider call failed")
    }
}

impl Error for RepairProviderFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// Terminal orchestration failure.
#[derive(Debug, Error)]
pub enum StructuredOutputError {
    /// The candidate remained invalid after the configured budget.
    #[error(transparent)]
    Invalid(#[from] InvalidStructuredOutput),
    /// A repair provider call failed before returning a complete candidate.
    #[error(transparent)]
    RepairProvider(Box<RepairProviderFailure>),
    /// A complete `serde_json::Value` could not be encoded for local validation.
    #[error("structured-output candidate could not be encoded for local validation")]
    CandidateEncoding,
    /// A validated value could not satisfy the canonical output-part contract.
    #[error("validated structured output could not be represented canonically")]
    ResultContract,
}

impl PreparedStructuredOutput {
    /// Locally validates one complete candidate and performs bounded, tool-free repair.
    ///
    /// Partial JSON cannot enter this API because candidates are complete
    /// [`serde_json::Value`] values. Every initial and repaired candidate is locally
    /// revalidated before a [`StructuredOutputPart`] is returned.
    ///
    /// # Errors
    ///
    /// Returns a typed invalid-data terminal error on a zero or exhausted budget,
    /// a redacted provider failure, or a value-free canonical contract error.
    pub async fn validate_and_repair<R>(
        &self,
        part_id: String,
        candidate: Value,
        policy: RepairPolicy,
        repair_port: &R,
    ) -> Result<ValidatedStructuredOutput, StructuredOutputError>
    where
        R: StructuredOutputRepairPort + ?Sized,
    {
        let initial_invalid_kind = match locally_validate(&self.validator, &candidate)? {
            LocalValidation::Valid(value) => {
                return self.validated_result(
                    part_id,
                    value,
                    0,
                    Vec::new(),
                    RetainedRaw::discarded(),
                );
            }
            LocalValidation::Invalid(kind) => kind,
        };

        let original_invalid = candidate;
        if policy.max_attempts == 0 {
            return Err(InvalidStructuredOutput {
                last_invalid_kind: initial_invalid_kind,
                repair_attempts: 0,
                repair_metering: Box::default(),
                original_invalid: RetainedRaw::from_value(policy.raw_retention, original_invalid),
            }
            .into());
        }

        let mut last_invalid_kind = initial_invalid_kind;
        let mut current_repair: Option<Value> = None;
        let mut metering = Vec::with_capacity(usize::from(policy.max_attempts));

        for attempt in 1..=policy.max_attempts {
            let invalid_value = current_repair.as_ref().unwrap_or(&original_invalid);
            let request = RepairRequest {
                attempt,
                strategy: self.strategy(),
                schema_json: self.schema_json(),
                schema_id: self.schema_id(),
                invalid_value,
                invalid_kind: last_invalid_kind,
            };
            let repair = match repair_port.repair(request).await {
                Ok(repair) => repair,
                Err(source) => {
                    return Err(StructuredOutputError::RepairProvider(Box::new(
                        RepairProviderFailure {
                            repair_attempt: attempt,
                            repair_metering: metering.into_boxed_slice(),
                            original_invalid: RetainedRaw::from_value(
                                policy.raw_retention,
                                original_invalid,
                            ),
                            source,
                        },
                    )));
                }
            };
            let (repaired_value, usage) = repair.into_parts();
            metering.push(RepairMetering { attempt, usage });

            match locally_validate(&self.validator, &repaired_value)? {
                LocalValidation::Valid(value) => {
                    return self.validated_result(
                        part_id,
                        value,
                        attempt,
                        metering,
                        RetainedRaw::from_value(policy.raw_retention, original_invalid),
                    );
                }
                LocalValidation::Invalid(kind) => {
                    last_invalid_kind = kind;
                    current_repair = Some(repaired_value);
                }
            }
        }

        Err(InvalidStructuredOutput {
            last_invalid_kind,
            repair_attempts: policy.max_attempts,
            repair_metering: metering.into_boxed_slice(),
            original_invalid: RetainedRaw::from_value(policy.raw_retention, original_invalid),
        }
        .into())
    }

    fn validated_result(
        &self,
        part_id: String,
        value: Value,
        repair_attempts: u8,
        repair_metering: Vec<RepairMetering>,
        original_invalid: RetainedRaw,
    ) -> Result<ValidatedStructuredOutput, StructuredOutputError> {
        let part = StructuredOutputPart::new(part_id, value, StructuredValidation::Valid)
            .and_then(|part| {
                part.with_validation_details(self.schema_id_owned(), u32::from(repair_attempts))
            })
            .map_err(|_| StructuredOutputError::ResultContract)?;
        Ok(ValidatedStructuredOutput {
            part,
            repair_metering: repair_metering.into_boxed_slice(),
            original_invalid,
        })
    }
}

enum LocalValidation {
    Valid(Value),
    Invalid(CandidateInvalidKind),
}

fn locally_validate(
    validator: &JsonSchemaAdapter,
    value: &Value,
) -> Result<LocalValidation, StructuredOutputError> {
    if validate_value_shape(value, validator.limits()).is_err() {
        return Ok(LocalValidation::Invalid(
            CandidateInvalidKind::StructureLimit,
        ));
    }
    let encoded = match encode_bounded(value, validator.limits().max_payload_bytes) {
        Ok(encoded) => encoded,
        Err(BoundedJsonEncodeError::TooLarge) => {
            return Ok(LocalValidation::Invalid(
                CandidateInvalidKind::PayloadTooLarge,
            ));
        }
        Err(BoundedJsonEncodeError::Encode) => {
            return Err(StructuredOutputError::CandidateEncoding);
        }
    };
    match validator.validate_bytes(&encoded) {
        Ok(validated) => Ok(LocalValidation::Valid(validated.into_inner())),
        Err(JsonPayloadError::TooLarge) => Ok(LocalValidation::Invalid(
            CandidateInvalidKind::PayloadTooLarge,
        )),
        Err(JsonPayloadError::Structure(_)) => Ok(LocalValidation::Invalid(
            CandidateInvalidKind::StructureLimit,
        )),
        Err(JsonPayloadError::Validation(_)) => Ok(LocalValidation::Invalid(
            CandidateInvalidKind::SchemaMismatch,
        )),
        Err(JsonPayloadError::Malformed) => Err(StructuredOutputError::CandidateEncoding),
    }
}
