use std::{
    collections::BTreeMap,
    fmt, io,
    num::{NonZeroU64, NonZeroUsize},
    sync::Mutex,
};

use async_trait::async_trait;
use omnius_agent_capability_registry::{
    CapabilityInvocation, CapabilityKey, CapabilityRegistry, ConfirmationEvidence, Exposure,
    IdempotencyKey, IdempotencyPolicy, InvocationContext, InvocationError, Permission, SideEffect,
    TenantMode,
};
use omnius_authz_basic::Decision;
use omnius_llm_core::LlmRequestId;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AgentLoopBudget, CompleteToolCall, ExecutedToolResult, LoopBudgetError, ToolCallIdentity,
    ToolCatalog, ToolCatalogError,
};

const MAX_JSON_DEPTH: usize = 64;
const MAX_JSON_NODES: usize = 4_096;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Fixed runtime ceilings independent of per-invocation registry budgets.
#[allow(clippy::struct_field_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ToolRuntimeLimits {
    max_catalog_tools: NonZeroUsize,
    max_tracked_calls: NonZeroUsize,
    max_argument_bytes: NonZeroU64,
    max_output_bytes: NonZeroU64,
}

impl ToolRuntimeLimits {
    /// Creates positive catalog, identity, input, and output ceilings.
    #[must_use]
    pub const fn new(
        max_catalog_tools: NonZeroUsize,
        max_tracked_calls: NonZeroUsize,
        max_argument_bytes: NonZeroU64,
        max_output_bytes: NonZeroU64,
    ) -> Self {
        Self {
            max_catalog_tools,
            max_tracked_calls,
            max_argument_bytes,
            max_output_bytes,
        }
    }

    /// Returns the catalog entry ceiling.
    #[must_use]
    pub const fn max_catalog_tools(self) -> usize {
        self.max_catalog_tools.get()
    }

    /// Returns the request-local unique call identity ceiling.
    #[must_use]
    pub const fn max_tracked_calls(self) -> usize {
        self.max_tracked_calls.get()
    }

    /// Returns the complete serialized argument byte ceiling.
    #[must_use]
    pub const fn max_argument_bytes(self) -> u64 {
        self.max_argument_bytes.get()
    }

    /// Returns the complete serialized result byte ceiling.
    #[must_use]
    pub const fn max_output_bytes(self) -> u64 {
        self.max_output_bytes.get()
    }
}

/// Trusted non-model evidence presented for one complete tool call.
///
/// Confirmation and idempotency values remain evidence to be checked; neither
/// grants authorization. Exact authorization comes only from
/// [`ToolAuthorizationPort`].
pub struct ToolExecutionEvidence {
    tenant_mode: TenantMode,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
    request_id: LlmRequestId,
}

impl ToolExecutionEvidence {
    /// Creates typed execution evidence supplied by the owning application flow.
    #[must_use]
    pub fn new(
        tenant_mode: TenantMode,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
        request_id: LlmRequestId,
    ) -> Self {
        Self {
            tenant_mode,
            confirmation,
            idempotency_key,
            request_id,
        }
    }

    /// Returns the requested canonical tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }

    /// Returns explicit confirmation evidence.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Borrows an explicitly supplied validated idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key.as_ref()
    }
    /// Borrows the canonical request identity that scopes derived idempotency.
    #[must_use]
    pub const fn request_id(&self) -> &LlmRequestId {
        &self.request_id
    }
}

impl fmt::Debug for ToolExecutionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolExecutionEvidence([redacted])")
    }
}

/// Exact authorization question sent to the authoritative async policy port.
pub struct ToolAuthorizationRequest<'a> {
    capability: &'a CapabilityKey,
    identity: &'a ToolCallIdentity,
    arguments: &'a Value,
    required_permissions: &'a [Permission],
    side_effect: SideEffect,
    tenant_mode: TenantMode,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<&'a IdempotencyKey>,
}
/// Opaque digest binding an authorization grant to the complete policy question.
#[derive(Clone, Eq, PartialEq)]
pub struct ToolAuthorizationBinding([u8; 32]);

impl fmt::Debug for ToolAuthorizationBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ToolAuthorizationBinding([redacted])")
    }
}

impl ToolAuthorizationRequest<'_> {
    /// Borrows the exact capability revision being authorized.
    #[must_use]
    pub const fn capability(&self) -> &CapabilityKey {
        self.capability
    }

    /// Borrows the complete provider call identity.
    #[must_use]
    pub const fn identity(&self) -> &ToolCallIdentity {
        self.identity
    }

    /// Borrows the complete locally schema-validated arguments.
    ///
    /// The policy port may resolve an exact resource from these untrusted values;
    /// argument content itself never constitutes authorization.
    #[must_use]
    pub const fn arguments(&self) -> &Value {
        self.arguments
    }

    /// Borrows registry-owned required permissions.
    ///
    /// These names describe the policy question; they never constitute a grant.
    #[must_use]
    pub const fn required_permissions(&self) -> &[Permission] {
        self.required_permissions
    }

    /// Returns the registry-owned side-effect class.
    #[must_use]
    pub const fn side_effect(&self) -> SideEffect {
        self.side_effect
    }

    /// Returns the exact requested tenant mode.
    #[must_use]
    pub const fn tenant_mode(&self) -> TenantMode {
        self.tenant_mode
    }

    /// Returns the typed confirmation evidence to verify.
    #[must_use]
    pub const fn confirmation(&self) -> ConfirmationEvidence {
        self.confirmation
    }

    /// Borrows the supplied or deterministically derived idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        self.idempotency_key
    }
    /// Computes an opaque binding over the exact capability, call, arguments,
    /// permissions, side effect, tenant, confirmation, and idempotency evidence.
    #[must_use]
    pub fn binding(&self) -> ToolAuthorizationBinding {
        authorization_binding(self)
    }
}

impl fmt::Debug for ToolAuthorizationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolAuthorizationRequest")
            .field("capability", &self.capability)
            .field("identity", &self.identity)
            .field("side_effect", &self.side_effect)
            .field("tenant_mode", &self.tenant_mode)
            .field(
                "required_permission_count",
                &self.required_permissions.len(),
            )
            .finish_non_exhaustive()
    }
}

/// Authoritative side-effect policy outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SideEffectApproval {
    /// Registry metadata declares no side effect.
    NotRequired,
    /// Authoritative policy explicitly approved the declared side effect.
    Approved,
}

/// Fully authorized registry invocation material returned by the policy port.
pub struct AuthorizedToolInvocation {
    capability: CapabilityKey,
    context: InvocationContext,
    tenant_mode: TenantMode,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<IdempotencyKey>,
    side_effect_approval: SideEffectApproval,
    authorization_binding: ToolAuthorizationBinding,
}

impl AuthorizedToolInvocation {
    /// Creates a grant bound to every exact value in the authorization question.
    ///
    /// The runtime compares all values with the request before registry dispatch.
    #[must_use]
    pub fn new(
        capability: CapabilityKey,
        context: InvocationContext,
        tenant_mode: TenantMode,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<IdempotencyKey>,
        side_effect_approval: SideEffectApproval,
        authorization_binding: ToolAuthorizationBinding,
    ) -> Self {
        Self {
            capability,
            context,
            tenant_mode,
            confirmation,
            idempotency_key,
            side_effect_approval,
            authorization_binding,
        }
    }
}

impl fmt::Debug for AuthorizedToolInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedToolInvocation([redacted])")
    }
}

/// Fail-closed exact authorization boundary for LLM tool execution.
#[async_trait]
pub trait ToolAuthorizationPort: Send + Sync {
    /// Resolves one exact capability/resource/action authorization question.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`ToolAuthorizationError`] on denial or policy-service
    /// unavailability. Model annotations and arguments are intentionally absent.
    async fn authorize(
        &self,
        request: ToolAuthorizationRequest<'_>,
    ) -> Result<AuthorizedToolInvocation, ToolAuthorizationError>;
}

/// Fixed authorization-port failures with no policy details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolAuthorizationError {
    /// Authoritative policy denied the exact invocation.
    #[error("tool authorization was denied")]
    Denied,
    /// An authoritative decision could not be obtained.
    #[error("tool authorization is unavailable")]
    Unavailable,
}

/// Stable redacted audit outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ToolAuditOutcome {
    /// Registry execution and local output validation succeeded.
    Succeeded,
    /// No exact catalog tool matched.
    UnknownTool,
    /// Complete arguments failed type, size, or schema validation.
    InvalidArguments,
    /// Confirmation, tenant, idempotency, or side-effect policy failed.
    GuardRejected,
    /// Exact authorization denied or was unavailable.
    AuthorizationRejected,
    /// Call or correlation identity was duplicate, reentrant, or excessive.
    DuplicateCall,
    /// A deterministic loop budget rejected work.
    BudgetExhausted,
    /// Deadline or cooperative cancellation won.
    Interrupted,
    /// Registry dispatch failed with a redacted code.
    ExecutionFailed,
    /// Handler output exceeded a bound or failed schema validation.
    InvalidOutput,
    /// Internal fail-closed state prevented execution.
    InternalFailure,
}

/// One synchronously recorded audit fact without arguments, output, or error text.
pub struct ToolAuditRecord {
    identity: ToolCallIdentity,
    capability: Option<CapabilityKey>,
    outcome: ToolAuditOutcome,
}

impl ToolAuditRecord {
    /// Borrows the attempted complete call identity.
    #[must_use]
    pub const fn identity(&self) -> &ToolCallIdentity {
        &self.identity
    }

    /// Borrows exact revision provenance when catalog resolution succeeded.
    #[must_use]
    pub const fn capability(&self) -> Option<&CapabilityKey> {
        self.capability.as_ref()
    }

    /// Returns the stable redacted outcome.
    #[must_use]
    pub const fn outcome(&self) -> ToolAuditOutcome {
        self.outcome
    }
}

impl fmt::Debug for ToolAuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolAuditRecord")
            .field("identity", &self.identity)
            .field("capability", &self.capability)
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Synchronous redacted audit sink.
pub trait ToolAuditPort: Send + Sync {
    /// Persists one redacted terminal outcome before execution returns to its caller.
    ///
    /// # Errors
    ///
    /// Returns [`ToolAuditError::Unavailable`] when durable audit recording fails.
    fn record(&self, record: ToolAuditRecord) -> Result<(), ToolAuditError>;
}

/// Fixed audit-port failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolAuditError {
    /// The required synchronous audit sink was unavailable.
    #[error("tool audit sink is unavailable")]
    Unavailable,
}

/// Request-local guarded LLM tool runtime.
pub struct ToolRuntime<'a, A, U> {
    registry: &'a CapabilityRegistry,
    authorization: A,
    audit: U,
    loop_budget: &'a AgentLoopBudget,
    limits: ToolRuntimeLimits,
    catalog: ToolCatalog,
    validators: BTreeMap<String, CompiledSchemas>,
    calls: Mutex<CallTracker>,
}

impl<'a, A, U> ToolRuntime<'a, A, U>
where
    A: ToolAuthorizationPort,
    U: ToolAuditPort,
{
    /// Projects the catalog and locally compiles every input and output schema.
    ///
    /// # Errors
    ///
    /// Returns [`ToolRuntimeBuildError`] if projection or local Draft 2020-12
    /// schema compilation fails. No provider receives an uncompiled definition.
    pub fn new(
        registry: &'a CapabilityRegistry,
        authorization: A,
        audit: U,
        loop_budget: &'a AgentLoopBudget,
        limits: ToolRuntimeLimits,
    ) -> Result<Self, ToolRuntimeBuildError> {
        let catalog = ToolCatalog::project(registry, limits.max_catalog_tools)?;
        let mut validators = BTreeMap::new();
        for tool in catalog.tools() {
            let input = compile_schema(&tool.document().input_schema)?;
            let output = compile_schema(&tool.document().output_schema)?;
            validators.insert(
                tool.definition().name().to_owned(),
                CompiledSchemas { input, output },
            );
        }
        Ok(Self {
            registry,
            authorization,
            audit,
            loop_budget,
            limits,
            catalog,
            validators,
            calls: Mutex::new(CallTracker::default()),
        })
    }

    /// Borrows the exact registry-derived catalog supplied to models.
    #[must_use]
    pub const fn catalog(&self) -> &ToolCatalog {
        &self.catalog
    }

    /// Executes one complete call through `CapabilityRegistry::invoke(LlmTool, ...)`.
    ///
    /// Every terminal outcome is synchronously audited before this method returns.
    /// A required idempotency key absent from trusted evidence is deterministically
    /// derived from exact capability and call provenance.
    ///
    /// # Errors
    ///
    /// Returns a fixed [`ToolRuntimeError`] for any pre-invocation guard, exact
    /// authorization, registry dispatch, bounded output, schema, or audit failure.
    pub async fn execute(
        &self,
        call: &CompleteToolCall,
        evidence: &ToolExecutionEvidence,
    ) -> Result<ExecutedToolResult, ToolRuntimeError> {
        let capability = self
            .catalog
            .get(call.name())
            .map(|tool| tool.capability().clone());
        let result = self
            .execute_inner(call, evidence, OffsetDateTime::now_utc())
            .await;
        let record = ToolAuditRecord {
            identity: call.identity().clone(),
            capability,
            outcome: result.as_ref().map_or_else(
                |error| (*error).audit_outcome(),
                |_| ToolAuditOutcome::Succeeded,
            ),
        };
        self.audit
            .record(record)
            .map_err(|_| ToolRuntimeError::AuditUnavailable)?;
        result
    }

    #[allow(clippy::too_many_lines)]
    async fn execute_inner(
        &self,
        call: &CompleteToolCall,
        evidence: &ToolExecutionEvidence,
        now: OffsetDateTime,
    ) -> Result<ExecutedToolResult, ToolRuntimeError> {
        let tool = self
            .catalog
            .get(call.name())
            .ok_or(ToolRuntimeError::UnknownTool)?;
        let schemas = self
            .validators
            .get(call.name())
            .ok_or(ToolRuntimeError::InternalState)?;
        if !call.arguments().is_object() {
            return Err(ToolRuntimeError::ArgumentsMustBeObject);
        }
        if !json_fits(call.arguments(), self.limits.max_argument_bytes()) {
            return Err(ToolRuntimeError::ArgumentsTooLarge);
        }
        if !json_shape_within(call.arguments(), MAX_JSON_DEPTH, MAX_JSON_NODES)
            || !schemas.input.is_valid(call.arguments())
        {
            return Err(ToolRuntimeError::ArgumentsInvalid);
        }
        if tool
            .document()
            .tenant_modes
            .binary_search(&evidence.tenant_mode)
            .is_err()
        {
            return Err(ToolRuntimeError::TenantGuardRejected);
        }
        if !confirmation_satisfied(tool.document().confirmation, evidence.confirmation) {
            return Err(ToolRuntimeError::ConfirmationGuardRejected);
        }
        let idempotency_key = prepare_idempotency(
            tool.document().idempotency,
            evidence.idempotency_key.as_ref(),
            tool.capability(),
            call.identity(),
            evidence.request_id(),
        )?;

        self.loop_budget
            .reserve_tool_call_at(now)
            .map_err(ToolRuntimeError::from_loop_budget)?;
        let _concurrency = self
            .loop_budget
            .try_reserve_concurrency_at(now)
            .map_err(ToolRuntimeError::from_loop_budget)?;

        let authorization_request = ToolAuthorizationRequest {
            capability: tool.capability(),
            identity: call.identity(),
            arguments: call.arguments(),
            required_permissions: &tool.document().permissions,
            side_effect: tool.document().side_effect,
            tenant_mode: evidence.tenant_mode,
            confirmation: evidence.confirmation,
            idempotency_key: idempotency_key.as_ref(),
        };
        let authorization_binding = authorization_request.binding();
        let authorization_remaining = remaining_until(self.loop_budget.deadline());
        if authorization_remaining.is_zero() {
            return Err(ToolRuntimeError::LoopBudget(
                crate::LoopBudgetDimension::WallClock,
            ));
        }
        let authorization_deadline = tokio::time::sleep(authorization_remaining);
        tokio::pin!(authorization_deadline);
        let authorization = self.authorization.authorize(authorization_request);
        tokio::pin!(authorization);
        let grant = tokio::select! {
            biased;
            () = &mut authorization_deadline => {
                return Err(ToolRuntimeError::LoopBudget(
                    crate::LoopBudgetDimension::WallClock,
                ));
            }
            result = &mut authorization => {
                result.map_err(ToolRuntimeError::Authorization)?
            }
        };
        validate_grant(
            &grant,
            tool.capability(),
            tool.document().side_effect,
            evidence.tenant_mode,
            evidence.confirmation,
            idempotency_key.as_ref(),
            self.limits.max_output_bytes(),
            &authorization_binding,
        )?;

        let loop_remaining = remaining_until(self.loop_budget.deadline());
        if loop_remaining.is_zero() {
            return Err(ToolRuntimeError::LoopBudget(
                crate::LoopBudgetDimension::WallClock,
            ));
        }
        self.reserve_call(call.identity())?;
        let cancellation = grant.context.cancellation_token().clone();
        let invocation = CapabilityInvocation::new(
            grant.capability,
            grant.context,
            grant.tenant_mode,
            call.arguments().clone(),
            grant.confirmation,
            grant.idempotency_key,
        );
        let deadline = tokio::time::sleep(loop_remaining);
        tokio::pin!(deadline);
        let invocation = self.registry.invoke(Exposure::LlmTool, invocation);
        tokio::pin!(invocation);
        let output = tokio::select! {
            biased;
            () = &mut deadline => {
                cancellation.cancel();
                return Err(ToolRuntimeError::LoopBudget(
                    crate::LoopBudgetDimension::WallClock,
                ));
            }
            result = &mut invocation => {
                result.map_err(map_registry_error)?.into_output()
            }
        };
        if !json_fits(&output, self.limits.max_output_bytes()) {
            return Err(ToolRuntimeError::OutputTooLarge);
        }
        if !json_shape_within(&output, MAX_JSON_DEPTH, MAX_JSON_NODES)
            || !schemas.output.is_valid(&output)
        {
            return Err(ToolRuntimeError::OutputInvalid);
        }
        Ok(ExecutedToolResult::new(
            call.identity().clone(),
            tool.capability().clone(),
            output,
        ))
    }

    fn reserve_call(&self, identity: &ToolCallIdentity) -> Result<(), ToolRuntimeError> {
        let mut calls = self
            .calls
            .lock()
            .map_err(|_| ToolRuntimeError::InternalState)?;
        if calls.call_ids.contains_key(identity.call_id())
            || calls
                .correlation_ids
                .contains_key(identity.correlation_id())
        {
            return Err(ToolRuntimeError::DuplicateCall);
        }
        if calls.call_ids.len() >= self.limits.max_tracked_calls() {
            return Err(ToolRuntimeError::CallTrackingLimitExceeded);
        }
        calls.call_ids.insert(
            identity.call_id().to_owned(),
            identity.correlation_id().to_owned(),
        );
        calls.correlation_ids.insert(
            identity.correlation_id().to_owned(),
            identity.call_id().to_owned(),
        );
        Ok(())
    }
}

impl<A, U> fmt::Debug for ToolRuntime<'_, A, U> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ToolRuntime")
            .field("limits", &self.limits)
            .field("catalog", &self.catalog)
            .finish_non_exhaustive()
    }
}

struct CompiledSchemas {
    input: jsonschema::Validator,
    output: jsonschema::Validator,
}

#[derive(Default)]
struct CallTracker {
    call_ids: BTreeMap<String, String>,
    correlation_ids: BTreeMap<String, String>,
}

/// A tool runtime could not safely initialize.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolRuntimeBuildError {
    /// Registry catalog projection failed closed.
    #[error("registry LLM tool catalog projection failed")]
    Catalog(ToolCatalogError),
    /// A registry tool schema failed local Draft 2020-12 compilation.
    #[error("registry LLM tool schema failed local compilation")]
    InvalidSchema,
}

impl From<ToolCatalogError> for ToolRuntimeBuildError {
    fn from(error: ToolCatalogError) -> Self {
        Self::Catalog(error)
    }
}

/// Fixed runtime failures that never retain arguments, output, or policy details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ToolRuntimeError {
    /// No exact registry-derived tool matched the complete call name.
    #[error("complete tool call does not match the registry catalog")]
    UnknownTool,
    /// Complete function arguments were not a JSON object.
    #[error("complete tool arguments must be a JSON object")]
    ArgumentsMustBeObject,
    /// Complete arguments exceeded the runtime byte ceiling.
    #[error("complete tool arguments exceed the runtime byte ceiling")]
    ArgumentsTooLarge,
    /// Complete arguments failed the registry input schema.
    #[error("complete tool arguments failed local schema validation")]
    ArgumentsInvalid,
    /// The requested tenant mode was absent from registry metadata.
    #[error("tool tenant guard rejected the invocation")]
    TenantGuardRejected,
    /// Confirmation evidence did not meet registry policy.
    #[error("tool confirmation guard rejected the invocation")]
    ConfirmationGuardRejected,
    /// Idempotency evidence disagreed with registry policy.
    #[error("tool idempotency guard rejected the invocation")]
    IdempotencyGuardRejected,
    /// A call or correlation identity was duplicate or reentrant.
    #[error("tool call identity is duplicate or reentrant")]
    DuplicateCall,
    /// Request-local call identity storage reached its fixed ceiling.
    #[error("tool call identity ceiling was exceeded")]
    CallTrackingLimitExceeded,
    /// One deterministic loop budget rejected the invocation.
    #[error("tool invocation exceeded an agent loop budget")]
    LoopBudget(crate::LoopBudgetDimension),
    /// Exact authorization denied or was unavailable.
    #[error("exact tool authorization failed")]
    Authorization(ToolAuthorizationError),
    /// The authorization grant did not bind the exact policy question.
    #[error("tool authorization grant does not match the exact request")]
    AuthorizationGrantMismatch,
    /// Authoritative side-effect approval did not match registry metadata.
    #[error("tool side-effect approval is missing or inconsistent")]
    SideEffectApprovalRejected,
    /// The authorized invocation was already cancelled.
    #[error("authorized tool invocation was cancelled")]
    Cancelled,
    /// The authorized invocation deadline elapsed.
    #[error("authorized tool invocation deadline elapsed")]
    DeadlineExceeded,
    /// The authorized output budget exceeded the runtime ceiling.
    #[error("authorized tool output limit exceeds the runtime ceiling")]
    OutputLimitNotEnforced,
    /// The sole registry invocation boundary rejected or failed execution.
    #[error("capability registry rejected or failed tool execution")]
    Registry(InvocationError),
    /// Handler output exceeded the runtime byte ceiling.
    #[error("tool output exceeds the runtime byte ceiling")]
    OutputTooLarge,
    /// Handler output failed the registry output schema.
    #[error("tool output failed local schema validation")]
    OutputInvalid,
    /// Required synchronous audit recording failed.
    #[error("required tool audit recording failed")]
    AuditUnavailable,
    /// Internal request-local fail-closed state was unavailable.
    #[error("tool runtime state is unavailable")]
    InternalState,
}

impl ToolRuntimeError {
    fn from_loop_budget(error: LoopBudgetError) -> Self {
        match error {
            LoopBudgetError::Exhausted(dimension) => Self::LoopBudget(dimension),
            LoopBudgetError::InternalState => Self::InternalState,
        }
    }

    const fn audit_outcome(self) -> ToolAuditOutcome {
        match self {
            Self::UnknownTool => ToolAuditOutcome::UnknownTool,
            Self::ArgumentsMustBeObject | Self::ArgumentsTooLarge | Self::ArgumentsInvalid => {
                ToolAuditOutcome::InvalidArguments
            }
            Self::TenantGuardRejected
            | Self::ConfirmationGuardRejected
            | Self::IdempotencyGuardRejected
            | Self::AuthorizationGrantMismatch
            | Self::SideEffectApprovalRejected
            | Self::OutputLimitNotEnforced => ToolAuditOutcome::GuardRejected,
            Self::DuplicateCall | Self::CallTrackingLimitExceeded => {
                ToolAuditOutcome::DuplicateCall
            }
            Self::LoopBudget(_) => ToolAuditOutcome::BudgetExhausted,
            Self::Authorization(_) => ToolAuditOutcome::AuthorizationRejected,
            Self::Cancelled | Self::DeadlineExceeded => ToolAuditOutcome::Interrupted,
            Self::Registry(_) => ToolAuditOutcome::ExecutionFailed,
            Self::OutputTooLarge | Self::OutputInvalid => ToolAuditOutcome::InvalidOutput,
            Self::AuditUnavailable | Self::InternalState => ToolAuditOutcome::InternalFailure,
        }
    }
}

fn compile_schema(
    schema: &omnius_agent_capability_registry::ObjectSchema,
) -> Result<jsonschema::Validator, ToolRuntimeBuildError> {
    let value = serde_json::to_value(schema).map_err(|_| ToolRuntimeBuildError::InvalidSchema)?;
    if has_non_local_reference(&value) {
        return Err(ToolRuntimeBuildError::InvalidSchema);
    }
    jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&value)
        .map_err(|_| ToolRuntimeBuildError::InvalidSchema)
}

fn confirmation_satisfied(
    policy: omnius_agent_capability_registry::ConfirmationPolicy,
    evidence: ConfirmationEvidence,
) -> bool {
    match policy {
        omnius_agent_capability_registry::ConfirmationPolicy::Never => {
            evidence == ConfirmationEvidence::NotProvided
        }
        omnius_agent_capability_registry::ConfirmationPolicy::Policy => matches!(
            evidence,
            ConfirmationEvidence::Confirmed | ConfirmationEvidence::NotRequiredByPolicy
        ),
        omnius_agent_capability_registry::ConfirmationPolicy::Always => {
            evidence == ConfirmationEvidence::Confirmed
        }
    }
}

fn prepare_idempotency(
    policy: IdempotencyPolicy,
    supplied: Option<&IdempotencyKey>,
    capability: &CapabilityKey,
    identity: &ToolCallIdentity,
    request_id: &LlmRequestId,
) -> Result<Option<IdempotencyKey>, ToolRuntimeError> {
    match (policy, supplied) {
        (IdempotencyPolicy::NotApplicable, None) => Ok(None),
        (IdempotencyPolicy::NotApplicable, Some(_)) => {
            Err(ToolRuntimeError::IdempotencyGuardRejected)
        }
        (IdempotencyPolicy::Optional, value) => Ok(value.cloned()),
        (IdempotencyPolicy::Required, Some(value)) => Ok(Some(value.clone())),
        (IdempotencyPolicy::Required, None) => {
            let mut hasher = Sha256::new();
            hasher.update(request_id.as_str().as_bytes());
            hasher.update([0_u8]);
            hasher.update(capability.id().as_str().as_bytes());
            hasher.update([0_u8]);
            hasher.update(capability.version().as_str().as_bytes());
            hasher.update([0_u8]);
            hasher.update(identity.call_id().as_bytes());
            hasher.update([0_u8]);
            hasher.update(identity.correlation_id().as_bytes());
            let digest = hasher.finalize();
            let mut value = String::with_capacity(68);
            value.push_str("llm-");
            for byte in digest {
                value.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
                value.push(char::from(LOWER_HEX[usize::from(byte & 0x0f)]));
            }
            IdempotencyKey::new(value)
                .map(Some)
                .map_err(|_| ToolRuntimeError::IdempotencyGuardRejected)
        }
    }
}

fn authorization_binding(request: &ToolAuthorizationRequest<'_>) -> ToolAuthorizationBinding {
    #[derive(serde::Serialize)]
    struct BindingMaterial<'a> {
        capability_id: &'a str,
        capability_version: &'a str,
        call_id: &'a str,
        correlation_id: &'a str,
        arguments: &'a Value,
        required_permissions: &'a [Permission],
        side_effect: SideEffect,
        tenant_mode: TenantMode,
        confirmation: ConfirmationEvidence,
        idempotency_key: Option<&'a str>,
    }

    let material = BindingMaterial {
        capability_id: request.capability.id().as_str(),
        capability_version: request.capability.version().as_str(),
        call_id: request.identity.call_id(),
        correlation_id: request.identity.correlation_id(),
        arguments: request.arguments,
        required_permissions: request.required_permissions,
        side_effect: request.side_effect,
        tenant_mode: request.tenant_mode,
        confirmation: request.confirmation,
        idempotency_key: request.idempotency_key.map(IdempotencyKey::as_str),
    };
    let mut hasher = Sha256::new();
    {
        let mut writer = DigestWriter(&mut hasher);
        if serde_json::to_writer(&mut writer, &material).is_err() {
            hasher.update(b"authorization-binding-serialization-failed");
        }
    }
    ToolAuthorizationBinding(hasher.finalize().into())
}

struct DigestWriter<'a>(&'a mut Sha256);

impl io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

const fn map_registry_error(error: InvocationError) -> ToolRuntimeError {
    match error {
        InvocationError::Cancelled => ToolRuntimeError::Cancelled,
        InvocationError::DeadlineExceeded => ToolRuntimeError::DeadlineExceeded,
        InvocationError::OutputSchemaMismatch => ToolRuntimeError::OutputInvalid,
        other => ToolRuntimeError::Registry(other),
    }
}

// Every argument is an independently verified policy dimension.
#[allow(clippy::too_many_arguments)]
fn validate_grant(
    grant: &AuthorizedToolInvocation,
    capability: &CapabilityKey,
    side_effect: SideEffect,
    tenant_mode: TenantMode,
    confirmation: ConfirmationEvidence,
    idempotency_key: Option<&IdempotencyKey>,
    max_output_bytes: u64,
    authorization_binding: &ToolAuthorizationBinding,
) -> Result<(), ToolRuntimeError> {
    if &grant.capability != capability
        || grant.tenant_mode != tenant_mode
        || grant.confirmation != confirmation
        || grant.idempotency_key.as_ref() != idempotency_key
        || &grant.authorization_binding != authorization_binding
        || grant.context.authorization() != Decision::Allow
    {
        return Err(ToolRuntimeError::AuthorizationGrantMismatch);
    }
    if !tenant_agrees(tenant_mode, &grant.context) {
        return Err(ToolRuntimeError::TenantGuardRejected);
    }
    let approval_matches = match side_effect {
        SideEffect::None => grant.side_effect_approval == SideEffectApproval::NotRequired,
        SideEffect::Idempotent
        | SideEffect::Mutating
        | SideEffect::Destructive
        | SideEffect::External => grant.side_effect_approval == SideEffectApproval::Approved,
    };
    if !approval_matches {
        return Err(ToolRuntimeError::SideEffectApprovalRejected);
    }
    if grant.context.cancellation_token().is_cancelled() {
        return Err(ToolRuntimeError::Cancelled);
    }
    if grant.context.remaining_duration().is_zero() {
        return Err(ToolRuntimeError::DeadlineExceeded);
    }
    if grant.context.budget().max_output_bytes() > max_output_bytes {
        return Err(ToolRuntimeError::OutputLimitNotEnforced);
    }
    Ok(())
}

fn tenant_agrees(mode: TenantMode, context: &InvocationContext) -> bool {
    match mode {
        TenantMode::Global => context.tenant_id().is_none(),
        TenantMode::Tenant => context
            .tenant_id()
            .is_some_and(|tenant| context.principal().tenant_id == Some(tenant)),
        TenantMode::Principal => true,
    }
}

fn remaining_until(deadline: OffsetDateTime) -> std::time::Duration {
    let remaining = deadline - OffsetDateTime::now_utc();
    if remaining.is_positive() {
        remaining.unsigned_abs()
    } else {
        std::time::Duration::ZERO
    }
}

fn json_shape_within(value: &Value, max_depth: usize, max_nodes: usize) -> bool {
    let mut stack = vec![(value, 0_usize)];
    let mut nodes = 0_usize;
    while let Some((current, depth)) = stack.pop() {
        nodes = match nodes.checked_add(1) {
            Some(nodes) if nodes <= max_nodes => nodes,
            Some(_) | None => return false,
        };
        if depth > max_depth {
            return false;
        }
        let Some(next_depth) = depth.checked_add(1) else {
            return false;
        };
        match current {
            Value::Array(items) => {
                stack.extend(items.iter().map(|item| (item, next_depth)));
            }
            Value::Object(properties) => {
                stack.extend(properties.values().map(|item| (item, next_depth)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn has_non_local_reference(value: &Value) -> bool {
    let mut stack = vec![value];
    while let Some(current) = stack.pop() {
        match current {
            Value::Object(properties) => {
                for (name, child) in properties {
                    if matches!(name.as_str(), "$ref" | "$dynamicRef")
                        && child
                            .as_str()
                            .is_some_and(|target| !target.starts_with('#'))
                    {
                        return true;
                    }
                    stack.push(child);
                }
            }
            Value::Array(items) => stack.extend(items),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    false
}

fn json_fits(value: &Value, limit: u64) -> bool {
    let mut writer = BudgetWriter { remaining: limit };
    serde_json::to_writer(&mut writer, value).is_ok()
}

struct BudgetWriter {
    remaining: u64,
}

impl io::Write for BudgetWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let byte_count = u64::try_from(bytes.len())
            .map_err(|_| io::Error::other("serialized value exceeds fixed budget"))?;
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
