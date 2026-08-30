use std::{collections::BTreeMap, fmt, io, sync::Arc};

use async_trait::async_trait;
use jsonschema::Validator;
use omnius_authz_basic::Decision;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    context::InvocationContext,
    metadata::{
        CapabilityDocument, CapabilityKey, DeclarationError, Exposure, IdempotencyPolicy,
        ObjectSchema, TenantMode,
    },
    value::IdempotencyKey,
};

const INVOCATION_METRIC: &str = "omnius_agent_capability_registry_invocations_total";

/// Canonical evidence for a capability's confirmation policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationEvidence {
    /// The caller supplied no confirmation evidence.
    NotProvided,
    /// The caller explicitly confirmed the operation.
    Confirmed,
    /// Authoritative policy evaluation established that confirmation was unnecessary.
    NotRequiredByPolicy,
}

/// A transport-independent request to execute one capability revision.
pub struct CapabilityInvocation {
    capability: CapabilityKey,
    context: InvocationContext,
    tenant_mode: TenantMode,
    input: Value,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
}

impl CapabilityInvocation {
    /// Creates an invocation. The registry validates every guardrail before dispatch.
    #[must_use]
    pub fn new(
        capability: CapabilityKey,
        context: InvocationContext,
        tenant_mode: TenantMode,
        input: Value,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
    ) -> Self {
        Self {
            capability,
            context,
            tenant_mode,
            input,
            confirmation,
            idempotency_key,
        }
    }

    /// Returns the targeted capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the canonical invocation context.
    #[must_use]
    pub const fn context(&self) -> &InvocationContext {
        &self.context
    }

    /// Returns the selected tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }

    /// Borrows the untrusted JSON input.
    #[must_use]
    pub const fn input(&self) -> &Value {
        &self.input
    }

    /// Returns confirmation evidence supplied by the adapter.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Returns the optional validated idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

impl fmt::Debug for CapabilityInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CapabilityInvocation([redacted])")
    }
}

/// The sole canonical request delivered to a capability handler.
pub struct HandlerInvocation {
    capability: CapabilityKey,
    exposure: Exposure,
    context: InvocationContext,
    tenant_mode: TenantMode,
    input: Value,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
}

impl HandlerInvocation {
    /// Returns the executed capability revision.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns the adapter projection that requested execution.
    #[must_use]
    pub const fn exposure(&self) -> Exposure {
        self.exposure
    }

    /// Returns the unchanged canonical invocation context.
    #[must_use]
    pub const fn context(&self) -> &InvocationContext {
        &self.context
    }

    /// Returns the selected tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }

    /// Borrows the untrusted JSON input.
    #[must_use]
    pub const fn input(&self) -> &Value {
        &self.input
    }

    /// Returns the confirmation evidence that passed registry policy.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Returns the optional idempotency key that passed registry policy.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
}

impl fmt::Debug for HandlerInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HandlerInvocation([redacted])")
    }
}

/// One asynchronous application capability implementation.
///
/// HTTP, jobs, LLM tools, MCP tools/resources/prompts, and browser projections
/// all reach implementations exclusively through [`CapabilityRegistry::invoke`].
#[async_trait]
pub trait CapabilityHandler: Send + Sync {
    /// Executes one already-authorized and guarded invocation.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerError`] with a fixed code safe to retain at the registry boundary.
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError>;
}

/// Fixed, value-free handler failure categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HandlerErrorCode {
    /// The application rejected otherwise structurally valid input.
    InvalidInput,
    /// Current application state conflicts with the operation.
    Conflict,
    /// A required application dependency is unavailable.
    DependencyUnavailable,
    /// The application denied the operation without exposing a policy distinction.
    Rejected,
    /// The application failed internally.
    Internal,
}

/// A redacted capability-handler failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("capability handler failed with a redacted error code")]
pub struct HandlerError {
    code: HandlerErrorCode,
}

impl HandlerError {
    /// Creates a redacted handler error from a fixed code.
    #[must_use]
    pub const fn new(code: HandlerErrorCode) -> Self {
        Self { code }
    }

    /// Returns the fixed handler failure category.
    #[must_use]
    pub const fn code(self) -> HandlerErrorCode {
        self.code
    }
}

/// Runtime reason a compiled capability cannot currently execute.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityReason {
    /// The capability is absent from the compiled registry.
    NotCompiled,
    /// Typed runtime configuration disabled the capability.
    DisabledByConfiguration,
    /// A required dependency is unavailable.
    DependencyUnavailable,
    /// The owning module is still starting.
    Starting,
    /// The owning module is draining during shutdown.
    Draining,
    /// Health evidence makes execution unsafe.
    Unhealthy,
    /// The current runtime environment cannot support the capability.
    UnsupportedEnvironment,
}

/// Runtime execution state of a compiled capability.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "reason")]
pub enum RuntimeAvailability {
    /// The handler may receive invocations.
    Available,
    /// The handler is fail-closed for the fixed reason.
    Unavailable(AvailabilityReason),
}

impl RuntimeAvailability {
    /// Returns whether runtime execution is admitted.
    #[must_use]
    pub const fn is_available(self) -> bool {
        matches!(self, Self::Available)
    }
}

/// Compiled and runtime availability for one capability revision.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityAvailability {
    capability: CapabilityKey,
    compiled: bool,
    runtime: RuntimeAvailability,
}

impl CapabilityAvailability {
    /// Returns the capability revision described by this status.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        &self.capability
    }

    /// Returns whether the capability is part of the compiled registry.
    #[must_use]
    pub const fn compiled(&self) -> bool {
        self.compiled
    }

    /// Returns current runtime availability.
    #[must_use]
    pub const fn runtime(&self) -> RuntimeAvailability {
        self.runtime
    }
}

/// Deterministically ordered registry availability evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AvailabilitySnapshot(Vec<CapabilityAvailability>);

impl AvailabilitySnapshot {
    /// Borrows statuses in capability-key order.
    #[must_use]
    pub fn capabilities(&self) -> &[CapabilityAvailability] {
        &self.0
    }
}

/// Mutable construction phase for an immutable [`CapabilityRegistry`].
#[derive(Default)]
pub struct CapabilityRegistryBuilder {
    entries: BTreeMap<CapabilityKey, RegistryEntry>,
}

impl CapabilityRegistryBuilder {
    /// Creates an empty registry builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Validates and registers one compiled capability and handler.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryBuildError`] for an invalid declaration or schema,
    /// duplicate key, or a compiled entry incorrectly marked `NotCompiled`.
    pub fn register<H>(
        &mut self,
        document: CapabilityDocument,
        runtime: RuntimeAvailability,
        handler: H,
    ) -> Result<&mut Self, RegistryBuildError>
    where
        H: CapabilityHandler + 'static,
    {
        document.validate()?;
        if runtime == RuntimeAvailability::Unavailable(AvailabilityReason::NotCompiled) {
            return Err(RegistryBuildError::InvalidAvailability);
        }
        let key = document.key();
        if self.entries.contains_key(&key) {
            return Err(RegistryBuildError::DuplicateCapability);
        }
        let input_validator = compile_schema(&document.input_schema)?;
        let output_validator = compile_schema(&document.output_schema)?;
        self.entries.insert(
            key,
            RegistryEntry {
                document,
                runtime,
                handler: Arc::new(handler),
                input_validator,
                output_validator,
            },
        );
        Ok(self)
    }

    /// Freezes the registry. No runtime mutation API is exposed after this call.
    #[must_use]
    pub fn build(self) -> CapabilityRegistry {
        CapabilityRegistry {
            entries: self.entries,
        }
    }
}

/// An immutable registry and the sole guarded capability execution boundary.
pub struct CapabilityRegistry {
    entries: BTreeMap<CapabilityKey, RegistryEntry>,
}

impl CapabilityRegistry {
    /// Returns the number of compiled capability revisions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether no capability revision was compiled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns canonical metadata for a compiled capability revision.
    #[must_use]
    pub fn document(&self, capability: &CapabilityKey) -> Option<&CapabilityDocument> {
        self.entries.get(capability).map(|entry| &entry.document)
    }

    /// Reports compiled and runtime state for a requested capability revision.
    #[must_use]
    pub fn availability(&self, capability: &CapabilityKey) -> CapabilityAvailability {
        self.entries.get(capability).map_or_else(
            || CapabilityAvailability {
                capability: capability.clone(),
                compiled: false,
                runtime: RuntimeAvailability::Unavailable(AvailabilityReason::NotCompiled),
            },
            |entry| CapabilityAvailability {
                capability: capability.clone(),
                compiled: true,
                runtime: entry.runtime,
            },
        )
    }

    /// Returns a deterministic snapshot of every compiled capability revision.
    #[must_use]
    pub fn availability_snapshot(&self) -> AvailabilitySnapshot {
        AvailabilitySnapshot(
            self.entries
                .iter()
                .map(|(capability, entry)| CapabilityAvailability {
                    capability: capability.clone(),
                    compiled: true,
                    runtime: entry.runtime,
                })
                .collect(),
        )
    }

    /// Enforces every registry guardrail and invokes exactly one handler.
    ///
    /// The supplied [`Exposure`] is the only difference between projection paths.
    /// Handler execution is bounded by both the absolute deadline and cooperative
    /// cancellation token retained in [`InvocationContext`].
    ///
    /// # Errors
    ///
    /// Returns [`InvocationError`] before handler dispatch for an unavailable or
    /// undeclared exposure, denied authorization, tenant disagreement, missing
    /// confirmation/idempotency evidence, invalid input, exhausted budget,
    /// deadline, or cancellation. Invalid output and handler failures are returned
    /// only as fixed redacted categories.
    pub async fn invoke(
        &self,
        exposure: Exposure,
        invocation: CapabilityInvocation,
    ) -> Result<InvocationResult, InvocationError> {
        let Some(entry) = self.entries.get(&invocation.capability) else {
            return reject(exposure, InvocationError::UnknownCapability);
        };
        if !entry.runtime.is_available() {
            return reject(exposure, InvocationError::Unavailable);
        }
        if entry.document.exposures.binary_search(&exposure).is_err() {
            return reject(exposure, InvocationError::ExposureNotDeclared);
        }
        if invocation.context.authorization() != Decision::Allow {
            return reject(exposure, InvocationError::Denied);
        }
        if entry
            .document
            .tenant_modes
            .binary_search(&invocation.tenant_mode)
            .is_err()
            || !tenant_mode_agrees(&invocation)
        {
            return reject(exposure, InvocationError::TenantModeMismatch);
        }
        if !confirmation_agrees(entry.document.confirmation, invocation.confirmation) {
            return reject(exposure, InvocationError::ConfirmationRequired);
        }
        if !idempotency_agrees(
            entry.document.idempotency,
            invocation.idempotency_key.as_ref(),
        ) {
            return reject(exposure, InvocationError::IdempotencyMismatch);
        }
        if !json_fits_budget(
            &invocation.input,
            invocation.context.budget().max_input_bytes(),
        ) {
            return reject(exposure, InvocationError::InputBudgetExceeded);
        }
        if !entry.input_validator.is_valid(&invocation.input) {
            return reject(exposure, InvocationError::InputSchemaMismatch);
        }
        if invocation.context.cancellation_token().is_cancelled() {
            return reject(exposure, InvocationError::Cancelled);
        }
        let remaining = invocation.context.remaining_duration();
        if remaining.is_zero() {
            return reject(exposure, InvocationError::DeadlineExceeded);
        }

        let cancellation = invocation.context.cancellation_token().clone();
        let output_budget = invocation.context.budget().max_output_bytes();
        let absolute_deadline = invocation.context.deadline();
        let handler_invocation = HandlerInvocation {
            capability: invocation.capability,
            exposure,
            context: invocation.context,
            tenant_mode: invocation.tenant_mode,
            input: invocation.input,
            confirmation: invocation.confirmation,
            idempotency_key: invocation.idempotency_key,
        };
        let sleep = tokio::time::sleep(remaining);
        tokio::pin!(sleep);
        let handler = entry.handler.invoke(handler_invocation);
        tokio::pin!(handler);

        let output = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return reject(exposure, InvocationError::Cancelled);
            }
            () = &mut sleep => {
                return reject(exposure, InvocationError::DeadlineExceeded);
            }
            result = &mut handler => match result {
                Ok(output) => output,
                Err(error) => {
                    return reject(exposure, InvocationError::HandlerFailed(error.code()));
                }
            }
        };

        if !json_fits_budget(&output, output_budget) {
            return reject(exposure, InvocationError::OutputBudgetExceeded);
        }
        if !entry.output_validator.is_valid(&output) {
            return reject(exposure, InvocationError::OutputSchemaMismatch);
        }
        if cancellation.is_cancelled() {
            return reject(exposure, InvocationError::Cancelled);
        }
        if time::OffsetDateTime::now_utc() >= absolute_deadline {
            return reject(exposure, InvocationError::DeadlineExceeded);
        }
        record_outcome(exposure, InvocationOutcome::Succeeded);
        Ok(InvocationResult { output })
    }
}

struct RegistryEntry {
    document: CapabilityDocument,
    runtime: RuntimeAvailability,
    handler: Arc<dyn CapabilityHandler>,
    input_validator: Validator,
    output_validator: Validator,
}

/// An immutable successful capability result.
pub struct InvocationResult {
    output: Value,
}

impl InvocationResult {
    /// Borrows the handler's JSON output.
    #[must_use]
    pub const fn output(&self) -> &Value {
        &self.output
    }

    /// Consumes the result and returns the JSON output.
    #[must_use]
    pub fn into_output(self) -> Value {
        self.output
    }
}

impl fmt::Debug for InvocationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvocationResult([redacted])")
    }
}

/// A fixed, redacted registry rejection or execution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InvocationError {
    /// The requested capability revision was not compiled.
    #[error("capability is not registered")]
    UnknownCapability,
    /// Runtime state does not currently admit execution.
    #[error("capability is unavailable")]
    Unavailable,
    /// The requested projection was not declared.
    #[error("capability exposure is not declared")]
    ExposureNotDeclared,
    /// Canonical authorization did not allow execution.
    #[error("capability invocation was denied")]
    Denied,
    /// The selected tenant mode was undeclared or disagreed with canonical context.
    #[error("capability tenant mode does not agree with canonical context")]
    TenantModeMismatch,
    /// Confirmation evidence did not satisfy capability policy.
    #[error("capability confirmation requirement was not satisfied")]
    ConfirmationRequired,
    /// Idempotency evidence did not satisfy capability policy.
    #[error("capability idempotency requirement was not satisfied")]
    IdempotencyMismatch,
    /// Serialized input exceeded immutable budget bounds.
    #[error("capability input exceeds its budget")]
    InputBudgetExceeded,
    /// Input did not satisfy the capability's compiled JSON Schema.
    #[error("capability input does not satisfy its schema")]
    InputSchemaMismatch,
    /// Serialized output exceeded immutable budget bounds.
    #[error("capability output exceeds its budget")]
    OutputBudgetExceeded,
    /// Handler output did not satisfy the capability's compiled JSON Schema.
    #[error("capability output does not satisfy its schema")]
    OutputSchemaMismatch,
    /// The absolute deadline elapsed before completion.
    #[error("capability deadline was exceeded")]
    DeadlineExceeded,
    /// Cooperative cancellation was requested before completion.
    #[error("capability invocation was cancelled")]
    Cancelled,
    /// The handler failed with a fixed redacted code.
    #[error("capability handler failed")]
    HandlerFailed(HandlerErrorCode),
}

/// A capability could not be admitted to the immutable registry.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RegistryBuildError {
    /// The declaration failed validation.
    #[error(transparent)]
    InvalidDeclaration(#[from] DeclarationError),
    /// An input or output JSON Schema could not be compiled.
    #[error("capability declaration contains an invalid schema")]
    InvalidSchema,
    /// The capability revision key was already registered.
    #[error("capability revision is already registered")]
    DuplicateCapability,
    /// A compiled handler cannot have a `NotCompiled` runtime reason.
    #[error("compiled capability has an invalid availability state")]
    InvalidAvailability,
}

#[derive(Clone, Copy)]
enum InvocationOutcome {
    Succeeded,
    UnknownCapability,
    Unavailable,
    ExposureNotDeclared,
    Denied,
    TenantModeMismatch,
    ConfirmationRequired,
    IdempotencyMismatch,
    InputBudgetExceeded,
    InputSchemaMismatch,
    OutputBudgetExceeded,
    OutputSchemaMismatch,
    DeadlineExceeded,
    Cancelled,
    HandlerFailed,
}

impl InvocationOutcome {
    const fn metric_label(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::UnknownCapability => "unknown_capability",
            Self::Unavailable => "unavailable",
            Self::ExposureNotDeclared => "exposure_not_declared",
            Self::Denied => "denied",
            Self::TenantModeMismatch => "tenant_mode_mismatch",
            Self::ConfirmationRequired => "confirmation_required",
            Self::IdempotencyMismatch => "idempotency_mismatch",
            Self::InputBudgetExceeded => "input_budget_exceeded",
            Self::InputSchemaMismatch => "input_schema_mismatch",
            Self::OutputBudgetExceeded => "output_budget_exceeded",
            Self::OutputSchemaMismatch => "output_schema_mismatch",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::HandlerFailed => "handler_failed",
        }
    }
}

fn confirmation_agrees(
    policy: crate::metadata::ConfirmationPolicy,
    evidence: ConfirmationEvidence,
) -> bool {
    match policy {
        crate::metadata::ConfirmationPolicy::Never => true,
        crate::metadata::ConfirmationPolicy::Policy => matches!(
            evidence,
            ConfirmationEvidence::Confirmed | ConfirmationEvidence::NotRequiredByPolicy
        ),
        crate::metadata::ConfirmationPolicy::Always => evidence == ConfirmationEvidence::Confirmed,
    }
}

fn idempotency_agrees(policy: IdempotencyPolicy, key: Option<&IdempotencyKey>) -> bool {
    match policy {
        IdempotencyPolicy::NotApplicable => key.is_none(),
        IdempotencyPolicy::Optional => true,
        IdempotencyPolicy::Required => key.is_some(),
    }
}

fn tenant_mode_agrees(invocation: &CapabilityInvocation) -> bool {
    match invocation.tenant_mode {
        TenantMode::Global => invocation.context.tenant_id().is_none(),
        TenantMode::Tenant => {
            let Some(tenant_id) = invocation.context.tenant_id() else {
                return false;
            };
            invocation.context.principal().tenant_id == Some(tenant_id)
        }
        TenantMode::Principal => true,
    }
}

fn compile_schema(schema: &ObjectSchema) -> Result<Validator, RegistryBuildError> {
    let schema = serde_json::to_value(schema).map_err(|_| RegistryBuildError::InvalidSchema)?;
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|_| RegistryBuildError::InvalidSchema)
}

fn json_fits_budget(value: &Value, limit: u64) -> bool {
    let mut writer = BudgetWriter { remaining: limit };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct BudgetWriter {
    remaining: u64,
}

impl io::Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Ok(byte_count) = u64::try_from(bytes.len()) else {
            return Err(io::Error::other("serialized value exceeds fixed budget"));
        };
        if byte_count > self.remaining {
            return Err(io::Error::other("serialized value exceeds fixed budget"));
        }
        self.remaining -= byte_count;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn reject<T>(exposure: Exposure, error: InvocationError) -> Result<T, InvocationError> {
    record_outcome(exposure, outcome_for_error(error));
    Err(error)
}

const fn outcome_for_error(error: InvocationError) -> InvocationOutcome {
    match error {
        InvocationError::UnknownCapability => InvocationOutcome::UnknownCapability,
        InvocationError::Unavailable => InvocationOutcome::Unavailable,
        InvocationError::ExposureNotDeclared => InvocationOutcome::ExposureNotDeclared,
        InvocationError::Denied => InvocationOutcome::Denied,
        InvocationError::TenantModeMismatch => InvocationOutcome::TenantModeMismatch,
        InvocationError::ConfirmationRequired => InvocationOutcome::ConfirmationRequired,
        InvocationError::IdempotencyMismatch => InvocationOutcome::IdempotencyMismatch,
        InvocationError::InputBudgetExceeded => InvocationOutcome::InputBudgetExceeded,
        InvocationError::InputSchemaMismatch => InvocationOutcome::InputSchemaMismatch,
        InvocationError::OutputBudgetExceeded => InvocationOutcome::OutputBudgetExceeded,
        InvocationError::OutputSchemaMismatch => InvocationOutcome::OutputSchemaMismatch,
        InvocationError::DeadlineExceeded => InvocationOutcome::DeadlineExceeded,
        InvocationError::Cancelled => InvocationOutcome::Cancelled,
        InvocationError::HandlerFailed(_) => InvocationOutcome::HandlerFailed,
    }
}

fn record_outcome(exposure: Exposure, outcome: InvocationOutcome) {
    metrics::counter!(
        INVOCATION_METRIC,
        "exposure" => exposure.metric_label(),
        "outcome" => outcome.metric_label()
    )
    .increment(1);
}
