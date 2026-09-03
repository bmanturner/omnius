//! Authenticated, tenant-scoped LLM HTTP, streaming, job, and conversation surfaces.
#![allow(
    missing_docs,
    reason = "wire DTO and port semantics are defined by their generated OpenAPI schemas and tests"
)]

use std::{
    convert::Infallible,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    Extension, Json, Router,
    extract::rejection::{ExtensionRejection, JsonRejection, PathRejection, QueryRejection},
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
    routing::{get, patch, post},
};
use futures::{Stream, StreamExt, future::BoxFuture};
use omnius_auth_core::{Principal, SubjectId, TenantId};
use omnius_http::ExpectedOperation;
use omnius_jobs_core::JobId;
use omnius_llm_conversations::{
    AppendMessage, AppendMessageOutcome, CiphertextDigest, ContinuationEncryptionAlgorithm,
    Conversation, ConversationAuthorization, ConversationContractError, ConversationId,
    ConversationMessage, ConversationMessageId, ConversationMessageRevision,
    ConversationRepository, ConversationRepositoryError, ConversationRevision, ConversationStatus,
    CreateConversation, CreateConversationOutcome, DeleteMessage, DeleteMessageOutcome,
    DeleteProviderState, DeleteProviderStateOutcome, DeletionRequestId,
    EncryptedContinuationReference, FenceConversationDeletion, FenceConversationDeletionOutcome,
    MessageCursor, MessagePageRequest, MessagePageSize, MessageSequence, ProviderStateId,
    ProviderStateRecord, ProviderStateRevision, ProviderStateValue, ReadMessagesOutcome,
    SanctionedReasoningSummary, SaveProviderState, SaveProviderStateOutcome, UpdateMessage,
    UpdateMessageOutcome,
};
use omnius_llm_core::{
    JsonObject, LlmMessage, LlmRequest, LlmRequestId, LlmResponse, ProviderErrorKind,
    RawRetentionState, ReasoningOutputPart, Usage,
};
use omnius_llm_runtime::{LlmRuntime, RuntimeDispatch, RuntimeError, RuntimeStreamSettlement};
use omnius_llm_streaming::{LlmStreamEvent, LlmStreamValidator, StreamLimits, StreamTerminalState};
use omnius_openapi::OpenApiError;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

pub const AI_ROUTES_PATH: &str = "/api/ai/routes";
pub const AI_RESPONSES_PATH: &str = "/api/ai/responses";
pub const AI_RESPONSE_STREAM_PATH: &str = "/api/ai/responses/stream";
pub const AI_JOBS_PATH: &str = "/api/ai/jobs";
pub const AI_JOB_PATH: &str = "/api/ai/jobs/{job_id}";
pub const AI_JOB_RESULT_PATH: &str = "/api/ai/jobs/{job_id}/result";
pub const AI_CONVERSATIONS_PATH: &str = "/api/ai/conversations";
pub const AI_CONVERSATION_PATH: &str = "/api/ai/conversations/{conversation_id}";
pub const AI_CONVERSATION_MESSAGES_PATH: &str = "/api/ai/conversations/{conversation_id}/messages";
pub const AI_CONVERSATION_MESSAGE_PATH: &str =
    "/api/ai/conversations/{conversation_id}/messages/{message_id}";
pub const AI_CONVERSATION_PROVIDER_STATE_PATH: &str =
    "/api/ai/conversations/{conversation_id}/provider-state/{state_id}";
const MAX_HTTP_STREAM_EVENTS: usize = 4_096;
const DEFAULT_MESSAGE_PAGE_SIZE: u16 = 50;
const AI_TAG: &str = "ai";
const CONVERSATION_TAG: &str = "ai-conversations";

/// Deterministic operation catalog in the same order used by [`augment_openapi`].
pub const LLM_HTTP_OPERATIONS: &[ExpectedOperation] = &[
    ExpectedOperation::new("get", AI_ROUTES_PATH, "aiRoutesList", AI_TAG),
    ExpectedOperation::new("post", AI_RESPONSES_PATH, "aiResponseCreate", AI_TAG),
    ExpectedOperation::new("post", AI_RESPONSE_STREAM_PATH, "aiResponseStream", AI_TAG),
    ExpectedOperation::new("post", AI_JOBS_PATH, "aiJobSubmit", AI_TAG),
    ExpectedOperation::new("get", AI_JOB_PATH, "aiJobGet", AI_TAG),
    ExpectedOperation::new("delete", AI_JOB_PATH, "aiJobCancel", AI_TAG),
    ExpectedOperation::new("get", AI_JOB_RESULT_PATH, "aiJobResult", AI_TAG),
    ExpectedOperation::new(
        "post",
        AI_CONVERSATIONS_PATH,
        "aiConversationCreate",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "get",
        AI_CONVERSATION_PATH,
        "aiConversationGet",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "delete",
        AI_CONVERSATION_PATH,
        "aiConversationDelete",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "get",
        AI_CONVERSATION_MESSAGES_PATH,
        "aiConversationMessagesList",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "post",
        AI_CONVERSATION_MESSAGES_PATH,
        "aiConversationMessageAppend",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "patch",
        AI_CONVERSATION_MESSAGE_PATH,
        "aiConversationMessageUpdate",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "delete",
        AI_CONVERSATION_MESSAGE_PATH,
        "aiConversationMessageDelete",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "get",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        "aiConversationProviderStateGet",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "put",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        "aiConversationProviderStatePut",
        CONVERSATION_TAG,
    ),
    ExpectedOperation::new(
        "delete",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        "aiConversationProviderStateDelete",
        CONVERSATION_TAG,
    ),
];

/// Exact tenant and principal scope supplied to every service port.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RequestScope {
    tenant_id: TenantId,
    principal_id: SubjectId,
}
impl RequestScope {
    #[must_use]
    pub const fn new(tenant_id: TenantId, principal_id: SubjectId) -> Self {
        Self {
            tenant_id,
            principal_id,
        }
    }
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }
    #[must_use]
    pub const fn principal_id(self) -> SubjectId {
        self.principal_id
    }
    #[must_use]
    pub const fn conversation_authorization(self) -> ConversationAuthorization {
        ConversationAuthorization::new(self.tenant_id, self.principal_id)
    }
}
/// Authoritative scope binding applied after authentication and before runtime dispatch.
pub trait RuntimeScopeBinder: Send + Sync {
    /// Resolves application-owned attributes for the authenticated scope.
    ///
    /// The returned binding must have been constructed for the exact supplied scope.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeBindingError`] when authoritative request scope cannot be bound.
    fn bind(&self, scope: RequestScope) -> Result<RuntimeScopeBinding, ScopeBindingError>;
}
/// Canonical runtime identity contexts bound to one authenticated request scope.
pub struct RuntimeScopeBinding {
    scope: RequestScope,
    principal_context: JsonObject,
    tenant_context: JsonObject,
}
impl RuntimeScopeBinding {
    /// Creates canonical identity contexts while reserving the authoritative identity keys.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeBindingError::ReservedIdentityAttribute`] when application attributes try
    /// to replace the authenticated subject or tenant identity.
    pub fn new(
        scope: RequestScope,
        mut principal_context: JsonObject,
        mut tenant_context: JsonObject,
    ) -> Result<Self, ScopeBindingError> {
        if principal_context.contains_key("subject_id") || tenant_context.contains_key("tenant_id")
        {
            return Err(ScopeBindingError::ReservedIdentityAttribute);
        }
        principal_context.insert(
            "subject_id".to_owned(),
            Value::String(scope.principal_id().as_uuid().to_string()),
        );
        tenant_context.insert(
            "tenant_id".to_owned(),
            Value::String(scope.tenant_id().as_uuid().to_string()),
        );
        Ok(Self {
            scope,
            principal_context,
            tenant_context,
        })
    }
}
/// Fail-closed authenticated scope binding error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ScopeBindingError {
    /// Application attributes attempted to replace an authenticated identity.
    #[error("LLM scope binding contains a reserved identity attribute")]
    ReservedIdentityAttribute,
    /// The binder returned a context for a different authenticated scope.
    #[error("LLM scope binding does not match the authenticated request")]
    ScopeMismatch,
    /// Authoritative scope attributes could not be resolved.
    #[error("LLM scope binding is unavailable")]
    Unavailable,
}

/// Opaque accepted budget reservation.
#[derive(Clone, Eq, PartialEq)]
pub struct BudgetReservation(Uuid);
impl BudgetReservation {
    #[must_use]
    pub const fn new(id: Uuid) -> Self {
        Self(id)
    }
    #[must_use]
    pub const fn id(&self) -> Uuid {
        self.0
    }
}
impl std::fmt::Debug for BudgetReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BudgetReservation([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BudgetError {
    #[error("LLM budget was rejected")]
    Rejected,
    #[error("LLM budget service is unavailable")]
    Unavailable,
    #[error("LLM budget state is invalid")]
    InvalidState,
}
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExecutionError {
    #[error("LLM provider is unavailable")]
    ProviderUnavailable,
    #[error("LLM request was rejected before dispatch")]
    InvalidRequest,
    #[error("LLM execution failed")]
    Failed,
    #[error("LLM stream violated the canonical contract")]
    InvalidStream,
}
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReadinessError {
    #[error("no LLM provider is ready")]
    ProviderUnavailable,
    #[error("LLM route readiness is unavailable")]
    Unavailable,
}
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum DurableJobError {
    #[error("durable LLM jobs are unavailable")]
    Unavailable,
    #[error("durable LLM job state is invalid")]
    InvalidState,
    #[error("durable LLM job operation conflicted")]
    Conflict,
}

/// Explicit dispatch outcome: only `PreDispatchFailed` permits release.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing canonical responses would add an allocation to every provider dispatch"
)]
pub enum DispatchOutcome<T> {
    PreDispatchFailed(ExecutionError),
    Dispatched {
        result: Result<T, ExecutionError>,
        actual_usage: Option<Usage>,
    },
}
impl<T> DispatchOutcome<T> {
    #[must_use]
    pub const fn pre_dispatch_failed(error: ExecutionError) -> Self {
        Self::PreDispatchFailed(error)
    }
    #[must_use]
    pub const fn dispatched(
        result: Result<T, ExecutionError>,
        actual_usage: Option<Usage>,
    ) -> Self {
        Self::Dispatched {
            result,
            actual_usage,
        }
    }
}

/// Live events paired with terminal provider settlement evidence.
pub struct StreamDispatch {
    events: CanonicalEventStream,
    settlement: BoxFuture<'static, StreamDispatchSettlement>,
}

impl StreamDispatch {
    /// Creates a live dispatch without claiming provider usage before the producer settles.
    #[must_use]
    pub fn new(
        events: CanonicalEventStream,
        settlement: BoxFuture<'static, StreamDispatchSettlement>,
    ) -> Self {
        Self { events, settlement }
    }

    fn into_parts(
        self,
    ) -> (
        CanonicalEventStream,
        BoxFuture<'static, StreamDispatchSettlement>,
    ) {
        (self.events, self.settlement)
    }
}

/// Terminal stream result and complete orchestration metering evidence.
pub struct StreamDispatchSettlement {
    result: Result<(), ExecutionError>,
    observed_usage: Option<Usage>,
    exact: bool,
    attempts_started: u32,
    hedged: bool,
    repair_usage: Arc<[Usage]>,
    retained_raw_state: Option<RawRetentionState>,
}

impl StreamDispatchSettlement {
    /// Creates terminal stream settlement evidence.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        result: Result<(), ExecutionError>,
        observed_usage: Option<Usage>,
        exact: bool,
        attempts_started: u32,
        hedged: bool,
        repair_usage: Arc<[Usage]>,
        retained_raw_state: Option<RawRetentionState>,
    ) -> Self {
        Self {
            result,
            observed_usage,
            exact,
            attempts_started,
            hedged,
            repair_usage,
            retained_raw_state,
        }
    }

    /// Borrows the terminal producer result.
    pub const fn result(&self) -> &Result<(), ExecutionError> {
        &self.result
    }

    /// Borrows final provider usage when observed.
    #[must_use]
    pub const fn observed_usage(&self) -> Option<&Usage> {
        self.observed_usage.as_ref()
    }

    /// Reports whether metering is complete rather than ambiguous.
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.exact
    }

    /// Returns every started provider attempt.
    #[must_use]
    pub const fn attempts_started(&self) -> u32 {
        self.attempts_started
    }

    /// Reports whether duplicate hedge work was admitted.
    #[must_use]
    pub const fn hedged(&self) -> bool {
        self.hedged
    }

    /// Borrows separately attributed repair usage.
    #[must_use]
    pub fn repair_usage(&self) -> &[Usage] {
        &self.repair_usage
    }

    /// Returns policy-controlled terminal provider retention state.
    #[must_use]
    pub const fn retained_raw_state(&self) -> Option<RawRetentionState> {
        self.retained_raw_state
    }
}

/// T159 reservation lifecycle boundary.
///
/// Implementations must derive a tenant/principal-scoped idempotency key and
/// dispatch fingerprint from the canonical request identity and full request.
/// Exact replays return the same reservation; changed request facts for the
/// same identity fail closed.
pub trait BudgetPort: Send + Sync {
    fn reserve<'a>(
        &'a self,
        scope: RequestScope,
        request: &'a LlmRequest,
    ) -> BoxFuture<'a, Result<BudgetReservation, BudgetError>>;
    fn commit<'a>(
        &'a self,
        reservation: BudgetReservation,
        actual_usage: Option<&'a Usage>,
    ) -> BoxFuture<'a, Result<(), BudgetError>>;
    fn release(&self, reservation: BudgetReservation) -> BoxFuture<'_, Result<(), BudgetError>>;
}
/// Provider orchestration boundary with an explicit dispatch fact.
///
/// An implementation must return [`DispatchOutcome::PreDispatchFailed`] only
/// when no provider work was incurred.
pub trait ExecutionPort: Send + Sync {
    fn dispatch_sync(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<LlmResponse>>;
    fn dispatch_stream(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<StreamDispatch>>;
}
/// Tenant-scoped route readiness boundary.
pub trait RouteReadinessPort: Send + Sync {
    fn list_ready_routes(
        &self,
        scope: RequestScope,
    ) -> BoxFuture<'_, Result<Vec<AiRoute>, ReadinessError>>;
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableJobStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableJobRecord {
    #[schemars(with = "String")]
    pub job_id: JobId,
    pub status: DurableJobStatus,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelJobOutcome {
    Cancelled,
    AlreadyTerminal,
    NotFound,
}
/// Durable job ownership, cancellation, and canonical-result boundary.
///
/// Implementations must use the canonical request identity for scoped
/// idempotency, persist exact prompt/route/schema/tool revisions, execute
/// through the same budgeted dispatch service, and return the unchanged
/// canonical response from [`DurableJobPort::result`].
pub trait DurableJobPort: Send + Sync {
    fn submit(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, Result<DurableJobRecord, DurableJobError>>;
    fn get(
        &self,
        scope: RequestScope,
        job_id: JobId,
    ) -> BoxFuture<'_, Result<Option<DurableJobRecord>, DurableJobError>>;
    fn cancel(
        &self,
        scope: RequestScope,
        job_id: JobId,
    ) -> BoxFuture<'_, Result<CancelJobOutcome, DurableJobError>>;
    fn result(
        &self,
        scope: RequestScope,
        job_id: JobId,
    ) -> BoxFuture<'_, Result<Option<LlmResponse>, DurableJobError>>;
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BudgetedExecutionError {
    #[error("LLM budget operation failed")]
    Budget(BudgetError),
    #[error("LLM provider execution failed")]
    Execution(ExecutionError),
}

/// Enforces reserve-before-dispatch and explicit settlement for every execution.
pub struct BudgetedLlmService {
    budget: Arc<dyn BudgetPort>,
    execution: Arc<dyn ExecutionPort>,
}
impl BudgetedLlmService {
    #[must_use]
    pub fn new(budget: Arc<dyn BudgetPort>, execution: Arc<dyn ExecutionPort>) -> Self {
        Self { budget, execution }
    }
    /// Executes one synchronous request after reserving its budget and settles actual usage.
    ///
    /// # Errors
    ///
    /// Returns a budget or provider execution failure after applying the settlement contract.
    pub async fn execute(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> Result<LlmResponse, BudgetedExecutionError> {
        let reservation = self
            .budget
            .reserve(scope, &request)
            .await
            .map_err(BudgetedExecutionError::Budget)?;
        let outcome = self.execution.dispatch_sync(scope, request).await;
        self.settle(reservation, outcome).await
    }
    /// Starts one canonical event stream after reserving its budget and settles actual usage.
    ///
    /// # Errors
    ///
    /// Returns a budget, provider, or canonical-stream validation failure.
    pub async fn stream(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> Result<CanonicalEventStream, BudgetedExecutionError> {
        let reservation = self
            .budget
            .reserve(scope, &request)
            .await
            .map_err(BudgetedExecutionError::Budget)?;
        let outcome = self.execution.dispatch_stream(scope, request).await;
        self.settle_stream(reservation, outcome).await
    }

    async fn settle_stream(
        &self,
        reservation: BudgetReservation,
        outcome: DispatchOutcome<StreamDispatch>,
    ) -> Result<CanonicalEventStream, BudgetedExecutionError> {
        match outcome {
            DispatchOutcome::PreDispatchFailed(error) => {
                self.budget
                    .release(reservation)
                    .await
                    .map_err(BudgetedExecutionError::Budget)?;
                Err(BudgetedExecutionError::Execution(error))
            }
            DispatchOutcome::Dispatched {
                result: Err(error),
                actual_usage,
            } => {
                self.budget
                    .commit(reservation, actual_usage.as_ref())
                    .await
                    .map_err(BudgetedExecutionError::Budget)?;
                Err(BudgetedExecutionError::Execution(error))
            }
            DispatchOutcome::Dispatched {
                result: Ok(dispatch),
                actual_usage: None,
            } => {
                let (events, settlement) = dispatch.into_parts();
                let budget = Arc::clone(&self.budget);
                tokio::spawn(async move {
                    let settlement = settlement.await;
                    let usage = if settlement.is_exact() {
                        settlement.observed_usage()
                    } else {
                        None
                    };
                    let _ = budget.commit(reservation, usage).await;
                });
                Ok(events)
            }
            DispatchOutcome::Dispatched {
                result: Ok(_),
                actual_usage: Some(actual_usage),
            } => {
                self.budget
                    .commit(reservation, Some(&actual_usage))
                    .await
                    .map_err(BudgetedExecutionError::Budget)?;
                Err(BudgetedExecutionError::Execution(ExecutionError::Failed))
            }
        }
    }
    async fn settle<T>(
        &self,
        reservation: BudgetReservation,
        outcome: DispatchOutcome<T>,
    ) -> Result<T, BudgetedExecutionError> {
        match outcome {
            DispatchOutcome::PreDispatchFailed(error) => {
                self.budget
                    .release(reservation)
                    .await
                    .map_err(BudgetedExecutionError::Budget)?;
                Err(BudgetedExecutionError::Execution(error))
            }
            DispatchOutcome::Dispatched {
                result,
                actual_usage,
            } => {
                self.budget
                    .commit(reservation, actual_usage.as_ref())
                    .await
                    .map_err(BudgetedExecutionError::Budget)?;
                result.map_err(BudgetedExecutionError::Execution)
            }
        }
    }
}

/// Incrementally validated, bounded canonical events from a live asynchronous producer.
pub struct CanonicalEventStream {
    events: Pin<Box<dyn Stream<Item = Result<LlmStreamEvent, ExecutionError>> + Send + 'static>>,
    validator: LlmStreamValidator,
    source_finished: bool,
}
impl CanonicalEventStream {
    /// Wraps a live producer without buffering its events.
    #[must_use]
    pub fn new<S>(request_id: LlmRequestId, events: S) -> Self
    where
        S: Stream<Item = Result<LlmStreamEvent, ExecutionError>> + Send + 'static,
    {
        let limits = StreamLimits::new(
            NonZeroU64::new(MAX_HTTP_STREAM_EVENTS as u64).unwrap_or(NonZeroU64::MIN),
            NonZeroUsize::new(MAX_HTTP_STREAM_EVENTS).unwrap_or(NonZeroUsize::MIN),
            NonZeroUsize::new(MAX_HTTP_STREAM_EVENTS).unwrap_or(NonZeroUsize::MIN),
            NonZeroUsize::new(16 * 1_024 * 1_024).unwrap_or(NonZeroUsize::MIN),
        );
        Self {
            events: Box::pin(events),
            validator: LlmStreamValidator::new(request_id, limits),
            source_finished: false,
        }
    }
}
impl Stream for CanonicalEventStream {
    type Item = Result<String, ExecutionError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.source_finished {
            return Poll::Ready(None);
        }
        match this.events.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(event))) => {
                if this.validator.accept(&event).is_err() {
                    this.source_finished = true;
                    return Poll::Ready(Some(Err(ExecutionError::InvalidStream)));
                }
                Poll::Ready(Some(
                    serde_json::to_string(&event).map_err(|_| ExecutionError::InvalidStream),
                ))
            }
            Poll::Ready(Some(Err(error))) => {
                this.source_finished = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.source_finished = true;
                if this.validator.finish().is_err() {
                    Poll::Ready(Some(Err(ExecutionError::InvalidStream)))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Concrete provider-neutral runtime adapter for the authenticated HTTP execution port.
pub struct RuntimeExecutionPort {
    runtime: LlmRuntime,
    scope_binder: Arc<dyn RuntimeScopeBinder>,
}

impl RuntimeExecutionPort {
    /// Creates an adapter that always binds authenticated scope before provider selection.
    #[must_use]
    pub fn new(runtime: LlmRuntime, scope_binder: Arc<dyn RuntimeScopeBinder>) -> Self {
        Self {
            runtime,
            scope_binder,
        }
    }

    fn bind_request(
        scope_binder: &dyn RuntimeScopeBinder,
        scope: RequestScope,
        request: LlmRequest,
    ) -> Result<LlmRequest, ExecutionError> {
        let binding = scope_binder
            .bind(scope)
            .map_err(|_| ExecutionError::InvalidRequest)?;
        if binding.scope != scope {
            return Err(ExecutionError::InvalidRequest);
        }
        let metadata = request.metadata().cloned();
        let data_policy = request.data_policy().cloned();
        Ok(request.with_context(
            metadata,
            data_policy,
            Some(binding.principal_context),
            Some(binding.tenant_context),
        ))
    }
}

impl ExecutionPort for RuntimeExecutionPort {
    fn dispatch_sync(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<LlmResponse>> {
        let runtime = self.runtime.clone();
        let scope_binder = Arc::clone(&self.scope_binder);
        Box::pin(async move {
            let request = match Self::bind_request(scope_binder.as_ref(), scope, request) {
                Ok(request) => request,
                Err(error) => return DispatchOutcome::pre_dispatch_failed(error),
            };
            match runtime.complete(request).await {
                RuntimeDispatch::PreDispatchFailed(error) => {
                    DispatchOutcome::pre_dispatch_failed(map_runtime_error(error))
                }
                RuntimeDispatch::Dispatched { result, metering } => {
                    let usage = if metering.is_exact() {
                        metering.observed_usage().cloned()
                    } else {
                        None
                    };
                    DispatchOutcome::dispatched(
                        result
                            .map(omnius_llm_runtime::RuntimeCompletion::into_response)
                            .map_err(map_runtime_error),
                        usage,
                    )
                }
            }
        })
    }

    fn dispatch_stream(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<StreamDispatch>> {
        let runtime = self.runtime.clone();
        let scope_binder = Arc::clone(&self.scope_binder);
        Box::pin(async move {
            let request = match Self::bind_request(scope_binder.as_ref(), scope, request) {
                Ok(request) => request,
                Err(error) => return DispatchOutcome::pre_dispatch_failed(error),
            };
            let request_id = request.request_id().clone();
            match runtime.stream(request).await {
                RuntimeDispatch::PreDispatchFailed(error) => {
                    DispatchOutcome::pre_dispatch_failed(map_runtime_error(error))
                }
                RuntimeDispatch::Dispatched { result, .. } => match result {
                    Ok(stream) => {
                        let (events, settlement) = stream.into_parts();
                        let events = CanonicalEventStream::new(
                            request_id,
                            events.map(|event| event.map_err(map_runtime_error)),
                        );
                        let settlement =
                            Box::pin(
                                async move { map_runtime_stream_settlement(settlement.await) },
                            );
                        DispatchOutcome::dispatched(
                            Ok(StreamDispatch::new(events, settlement)),
                            None,
                        )
                    }
                    Err(error) => DispatchOutcome::dispatched(Err(map_runtime_error(error)), None),
                },
            }
        })
    }
}

fn map_runtime_stream_settlement(settlement: RuntimeStreamSettlement) -> StreamDispatchSettlement {
    let RuntimeStreamSettlement {
        result,
        metering,
        retained_raw_state,
    } = settlement;
    StreamDispatchSettlement::new(
        result.map_err(map_runtime_error),
        metering.observed_usage().cloned(),
        metering.is_exact(),
        metering.attempts_started(),
        metering.hedged(),
        Arc::from(metering.repair_usage().to_vec()),
        retained_raw_state,
    )
}

fn map_runtime_error(error: RuntimeError) -> ExecutionError {
    match error {
        RuntimeError::RouteUnavailable
        | RuntimeError::InvalidRequest
        | RuntimeError::StructuredOutputRejected => ExecutionError::InvalidRequest,
        RuntimeError::NoEligibleCandidate => ExecutionError::ProviderUnavailable,
        RuntimeError::InvalidProviderStream | RuntimeError::Delivery(_) => {
            ExecutionError::InvalidStream
        }
        RuntimeError::Provider(error) => match error.kind() {
            ProviderErrorKind::Unsupported
            | ProviderErrorKind::Safety
            | ProviderErrorKind::Schema => ExecutionError::InvalidRequest,
            ProviderErrorKind::Provider
            | ProviderErrorKind::Transport
            | ProviderErrorKind::Timeout
            | ProviderErrorKind::Throttling => ExecutionError::ProviderUnavailable,
        },
        RuntimeError::InvalidRuntimeState
        | RuntimeError::MissingRequiredPort
        | RuntimeError::Cancelled => ExecutionError::Failed,
    }
}

#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiRoute {
    pub route: String,
    pub provider: String,
    pub model: String,
    pub ready: bool,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiRoutesResponse {
    pub routes: Vec<AiRoute>,
}

#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationCreateRequest {
    #[schemars(with = "String")]
    pub conversation_id: Uuid,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ConversationStatusDto {
    Active,
    DeletionFenced {
        #[schemars(with = "String")]
        request_id: Uuid,
        #[schemars(with = "String")]
        fenced_at: OffsetDateTime,
    },
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationDto {
    #[schemars(with = "String")]
    pub conversation_id: Uuid,
    pub revision: u64,
    pub last_message_sequence: Option<u64>,
    pub status: ConversationStatusDto,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
    #[schemars(with = "String")]
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationEnvelope {
    pub conversation: ConversationDto,
    pub replayed: bool,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationDeleteRequest {
    #[schemars(with = "String")]
    pub request_id: Uuid,
    pub expected_conversation_revision: u64,
    #[schemars(with = "String")]
    pub fenced_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageAppendRequest {
    #[schemars(with = "String")]
    pub message_id: Uuid,
    pub expected_conversation_revision: u64,
    pub message: LlmMessage,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageUpdateRequest {
    pub expected_conversation_revision: u64,
    pub expected_message_revision: u64,
    pub message: LlmMessage,
    #[schemars(with = "String")]
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageDeleteRequest {
    pub expected_conversation_revision: u64,
    pub expected_message_revision: u64,
    #[schemars(with = "String")]
    pub deleted_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageDto {
    #[schemars(with = "String")]
    pub conversation_id: Uuid,
    #[schemars(with = "String")]
    pub message_id: Uuid,
    pub sequence: u64,
    pub revision: u64,
    pub message: LlmMessage,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
    #[schemars(with = "String")]
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageEnvelope {
    pub message: ConversationMessageDto,
    pub conversation_revision: u64,
    pub replayed: bool,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationRevisionEnvelope {
    pub conversation_revision: u64,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessagesQuery {
    pub after_sequence: Option<u64>,
    pub limit: Option<u16>,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessagesPage {
    pub items: Vec<ConversationMessageDto>,
    pub next_after_sequence: Option<u64>,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationEncryptionAlgorithmDto {
    Aes256Gcm,
    XChaCha20Poly1305,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedContinuationDto {
    pub reference: String,
    pub key_id: String,
    pub key_revision: u32,
    pub algorithm: ContinuationEncryptionAlgorithmDto,
    pub ciphertext_digest: [u8; 32],
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderStateInput {
    ReasoningSummary {
        summary: ReasoningOutputPart,
        signature: Option<ReasoningOutputPart>,
    },
    EncryptedContinuation(EncryptedContinuationDto),
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ProviderStateValueResponse {
    ReasoningSummary {
        summary: String,
        signature: Option<String>,
    },
    EncryptedContinuation(EncryptedContinuationDto),
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStatePutRequest {
    pub expected_conversation_revision: u64,
    pub expected_state_revision: Option<u64>,
    pub value: ProviderStateInput,
    #[schemars(with = "String")]
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateDeleteRequest {
    pub expected_conversation_revision: u64,
    pub expected_state_revision: u64,
    #[schemars(with = "String")]
    pub deleted_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateDto {
    #[schemars(with = "String")]
    pub conversation_id: Uuid,
    #[schemars(with = "String")]
    pub state_id: Uuid,
    pub revision: u64,
    pub value: ProviderStateValueResponse,
    #[schemars(with = "String")]
    pub created_at: OffsetDateTime,
    #[schemars(with = "String")]
    pub updated_at: OffsetDateTime,
}
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderStateEnvelope {
    pub state: ProviderStateDto,
    pub conversation_revision: Option<u64>,
    pub replayed: bool,
}
#[derive(Clone, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AiProblem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub code: String,
    pub request_id: String,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum LlmHttpError {
    #[error("authentication is required")]
    AuthenticationRequired,
    #[error("tenant context is required")]
    TenantRequired,
    #[error("request is invalid")]
    InvalidRequest,
    #[error("resource was not found")]
    NotFound,
    #[error("operation conflicted")]
    Conflict,
    #[error("request budget was exhausted")]
    BudgetRejected,
    #[error("service is unavailable")]
    Unavailable,
    #[error("internal service failure")]
    Internal,
}
impl LlmHttpError {
    const fn status(self) -> StatusCode {
        match self {
            Self::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            Self::TenantRequired => StatusCode::FORBIDDEN,
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::BudgetRejected => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    const fn code(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "AUTHENTICATION_REQUIRED",
            Self::TenantRequired => "TENANT_CONTEXT_REQUIRED",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::BudgetRejected => "BUDGET_REJECTED",
            Self::Unavailable => "SERVICE_UNAVAILABLE",
            Self::Internal => "INTERNAL",
        }
    }
    const fn title(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "Authentication required",
            Self::TenantRequired => "Tenant context required",
            Self::InvalidRequest => "Invalid request",
            Self::NotFound => "Resource not found",
            Self::Conflict => "Request conflict",
            Self::BudgetRejected => "Budget rejected",
            Self::Unavailable => "Service unavailable",
            Self::Internal => "Internal server error",
        }
    }
}
impl IntoResponse for LlmHttpError {
    fn into_response(self) -> Response {
        let status = self.status();
        let problem = AiProblem {
            problem_type: format!(
                "https://errors.omnius.invalid/{}",
                self.code().to_ascii_lowercase()
            ),
            title: self.title().to_owned(),
            status: status.as_u16(),
            code: self.code().to_owned(),
            request_id: "not-disclosed".to_owned(),
        };
        let mut response = (status, Json(problem)).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
impl From<BudgetedExecutionError> for LlmHttpError {
    fn from(error: BudgetedExecutionError) -> Self {
        match error {
            BudgetedExecutionError::Budget(BudgetError::Rejected) => Self::BudgetRejected,
            BudgetedExecutionError::Budget(BudgetError::Unavailable) => Self::Unavailable,
            BudgetedExecutionError::Budget(BudgetError::InvalidState)
            | BudgetedExecutionError::Execution(
                ExecutionError::Failed | ExecutionError::InvalidStream,
            ) => Self::Internal,
            BudgetedExecutionError::Execution(ExecutionError::InvalidRequest) => {
                Self::InvalidRequest
            }
            BudgetedExecutionError::Execution(ExecutionError::ProviderUnavailable) => {
                Self::Unavailable
            }
        }
    }
}
impl From<ReadinessError> for LlmHttpError {
    fn from(_: ReadinessError) -> Self {
        Self::Unavailable
    }
}
impl From<DurableJobError> for LlmHttpError {
    fn from(error: DurableJobError) -> Self {
        match error {
            DurableJobError::Unavailable => Self::Unavailable,
            DurableJobError::InvalidState => Self::Internal,
            DurableJobError::Conflict => Self::Conflict,
        }
    }
}
impl From<ConversationRepositoryError> for LlmHttpError {
    fn from(error: ConversationRepositoryError) -> Self {
        match error {
            ConversationRepositoryError::Unavailable | ConversationRepositoryError::Timeout => {
                Self::Unavailable
            }
            ConversationRepositoryError::InvalidData => Self::Internal,
        }
    }
}
impl From<ConversationContractError> for LlmHttpError {
    fn from(_: ConversationContractError) -> Self {
        Self::InvalidRequest
    }
}

/// Required state: no provider or persistence fallback is permitted.
#[derive(Clone)]
pub struct LlmHttpState {
    service: Arc<BudgetedLlmService>,
    readiness: Arc<dyn RouteReadinessPort>,
    jobs: Arc<dyn DurableJobPort>,
    conversations: Arc<dyn ConversationRepository>,
}
impl LlmHttpState {
    #[must_use]
    pub fn new(
        budget: Arc<dyn BudgetPort>,
        execution: Arc<dyn ExecutionPort>,
        readiness: Arc<dyn RouteReadinessPort>,
        jobs: Arc<dyn DurableJobPort>,
        conversations: Arc<dyn ConversationRepository>,
    ) -> Self {
        Self {
            service: Arc::new(BudgetedLlmService::new(budget, execution)),
            readiness,
            jobs,
            conversations,
        }
    }
    #[must_use]
    pub fn service(&self) -> &Arc<BudgetedLlmService> {
        &self.service
    }
}

pub fn llm_http_router(state: LlmHttpState) -> Router {
    Router::new()
        .route(AI_ROUTES_PATH, get(routes_list))
        .route(AI_RESPONSES_PATH, post(response_create))
        .route(AI_RESPONSE_STREAM_PATH, post(response_stream))
        .route(AI_JOBS_PATH, post(job_submit))
        .route(AI_JOB_PATH, get(job_get).delete(job_cancel))
        .route(AI_JOB_RESULT_PATH, get(job_result))
        .route(AI_CONVERSATIONS_PATH, post(conversation_create))
        .route(
            AI_CONVERSATION_PATH,
            get(conversation_get).delete(conversation_delete),
        )
        .route(
            AI_CONVERSATION_MESSAGES_PATH,
            get(conversation_messages_list).post(conversation_message_append),
        )
        .route(
            AI_CONVERSATION_MESSAGE_PATH,
            patch(conversation_message_update).delete(conversation_message_delete),
        )
        .route(
            AI_CONVERSATION_PROVIDER_STATE_PATH,
            get(conversation_provider_state_get)
                .put(conversation_provider_state_put)
                .delete(conversation_provider_state_delete),
        )
        .with_state(state)
}
fn required_scope(
    principal: Result<Extension<Principal>, ExtensionRejection>,
) -> Result<RequestScope, LlmHttpError> {
    let Extension(principal) = principal.map_err(|_| LlmHttpError::AuthenticationRequired)?;
    Ok(RequestScope::new(
        principal.tenant_id.ok_or(LlmHttpError::TenantRequired)?,
        principal.subject_id,
    ))
}
fn json_body<T>(payload: Result<Json<T>, JsonRejection>) -> Result<T, LlmHttpError> {
    payload
        .map(|Json(value)| value)
        .map_err(|_| LlmHttpError::InvalidRequest)
}

async fn routes_list(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
) -> Result<Json<AiRoutesResponse>, LlmHttpError> {
    let routes = state
        .readiness
        .list_ready_routes(required_scope(principal)?)
        .await?;
    if routes.is_empty() {
        return Err(LlmHttpError::Unavailable);
    }
    Ok(Json(AiRoutesResponse { routes }))
}
async fn response_create(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    payload: Result<Json<LlmRequest>, JsonRejection>,
) -> Result<Json<LlmResponse>, LlmHttpError> {
    let response = state
        .service
        .execute(required_scope(principal)?, json_body(payload)?)
        .await?;
    Ok(Json(response))
}
async fn response_stream(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    headers: HeaderMap,
    payload: Result<Json<LlmRequest>, JsonRejection>,
) -> Result<Response, LlmHttpError> {
    if headers.contains_key("last-event-id") {
        return Err(LlmHttpError::InvalidRequest);
    }
    let events = state
        .service
        .stream(required_scope(principal)?, json_body(payload)?)
        .await?;
    let mut response = Sse::new(CanonicalSseStream { events }).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}
struct CanonicalSseStream {
    events: CanonicalEventStream,
}
impl Stream for CanonicalSseStream {
    type Item = Result<Event, Infallible>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.events).poll_next(cx) {
            Poll::Ready(Some(Ok(payload))) => Poll::Ready(Some(Ok(Event::default().data(payload)))),
            Poll::Ready(Some(Err(_))) => Poll::Ready(Some(Ok(Event::default()
                .event("error")
                .data(r#"{"type":"about:blank","title":"LLM stream failed","status":502}"#)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[derive(Deserialize)]
struct JobPath {
    job_id: Uuid,
}
fn job_id(path: Result<Path<JobPath>, PathRejection>) -> Result<JobId, LlmHttpError> {
    let Path(path) = path.map_err(|_| LlmHttpError::InvalidRequest)?;
    JobId::from_uuid(path.job_id).map_err(|_| LlmHttpError::InvalidRequest)
}
async fn job_submit(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    payload: Result<Json<LlmRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<DurableJobRecord>), LlmHttpError> {
    let job = state
        .jobs
        .submit(required_scope(principal)?, json_body(payload)?)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(job)))
}
async fn job_get(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<JobPath>, PathRejection>,
) -> Result<Json<DurableJobRecord>, LlmHttpError> {
    let job = state
        .jobs
        .get(required_scope(principal)?, job_id(path)?)
        .await?
        .ok_or(LlmHttpError::NotFound)?;
    Ok(Json(job))
}
async fn job_cancel(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<JobPath>, PathRejection>,
) -> Result<StatusCode, LlmHttpError> {
    match state
        .jobs
        .cancel(required_scope(principal)?, job_id(path)?)
        .await?
    {
        CancelJobOutcome::Cancelled => Ok(StatusCode::NO_CONTENT),
        CancelJobOutcome::AlreadyTerminal => Err(LlmHttpError::Conflict),
        CancelJobOutcome::NotFound => Err(LlmHttpError::NotFound),
    }
}
async fn job_result(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<JobPath>, PathRejection>,
) -> Result<Json<LlmResponse>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let response = state
        .jobs
        .result(scope, job_id(path)?)
        .await?
        .ok_or(LlmHttpError::NotFound)?;
    Ok(Json(response))
}

#[derive(Deserialize)]
struct ConversationPath {
    conversation_id: Uuid,
}
#[derive(Deserialize)]
struct ConversationMessagePath {
    conversation_id: Uuid,
    message_id: Uuid,
}
#[derive(Deserialize)]
struct ConversationProviderStatePath {
    conversation_id: Uuid,
    state_id: Uuid,
}
fn conversation_id(
    path: Result<Path<ConversationPath>, PathRejection>,
) -> Result<ConversationId, LlmHttpError> {
    let Path(path) = path.map_err(|_| LlmHttpError::InvalidRequest)?;
    ConversationId::from_uuid(path.conversation_id).map_err(Into::into)
}
fn message_path(
    path: Result<Path<ConversationMessagePath>, PathRejection>,
) -> Result<(ConversationId, ConversationMessageId), LlmHttpError> {
    let Path(path) = path.map_err(|_| LlmHttpError::InvalidRequest)?;
    Ok((
        ConversationId::from_uuid(path.conversation_id)?,
        ConversationMessageId::from_uuid(path.message_id)?,
    ))
}
fn provider_state_path(
    path: Result<Path<ConversationProviderStatePath>, PathRejection>,
) -> Result<(ConversationId, ProviderStateId), LlmHttpError> {
    let Path(path) = path.map_err(|_| LlmHttpError::InvalidRequest)?;
    Ok((
        ConversationId::from_uuid(path.conversation_id)?,
        ProviderStateId::from_uuid(path.state_id)?,
    ))
}

async fn conversation_create(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    payload: Result<Json<ConversationCreateRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ConversationEnvelope>), LlmHttpError> {
    let scope = required_scope(principal)?;
    let p = json_body(payload)?;
    let command =
        CreateConversation::new(ConversationId::from_uuid(p.conversation_id)?, p.created_at)?;
    match state
        .conversations
        .create_conversation(&scope.conversation_authorization(), &command)
        .await?
    {
        CreateConversationOutcome::Created(value) => Ok((
            StatusCode::CREATED,
            Json(ConversationEnvelope {
                conversation: (&value).into(),
                replayed: false,
            }),
        )),
        CreateConversationOutcome::Replayed(value) => Ok((
            StatusCode::OK,
            Json(ConversationEnvelope {
                conversation: (&value).into(),
                replayed: true,
            }),
        )),
        CreateConversationOutcome::IdempotencyConflict => Err(LlmHttpError::Conflict),
    }
}
async fn conversation_get(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationPath>, PathRejection>,
) -> Result<Json<ConversationEnvelope>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let value = state
        .conversations
        .read_conversation(&scope.conversation_authorization(), conversation_id(path)?)
        .await?
        .ok_or(LlmHttpError::NotFound)?;
    Ok(Json(ConversationEnvelope {
        conversation: (&value).into(),
        replayed: false,
    }))
}
async fn conversation_delete(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationPath>, PathRejection>,
    payload: Result<Json<ConversationDeleteRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ConversationEnvelope>), LlmHttpError> {
    let scope = required_scope(principal)?;
    let p = json_body(payload)?;
    let command = FenceConversationDeletion::new(
        conversation_id(path)?,
        DeletionRequestId::from_uuid(p.request_id)?,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        p.fenced_at,
    )?;
    match state
        .conversations
        .fence_conversation_deletion(&scope.conversation_authorization(), command)
        .await?
    {
        FenceConversationDeletionOutcome::Fenced { conversation, .. } => Ok((
            StatusCode::ACCEPTED,
            Json(ConversationEnvelope {
                conversation: (&conversation).into(),
                replayed: false,
            }),
        )),
        FenceConversationDeletionOutcome::Replayed { conversation, .. } => Ok((
            StatusCode::OK,
            Json(ConversationEnvelope {
                conversation: (&conversation).into(),
                replayed: true,
            }),
        )),
        FenceConversationDeletionOutcome::NotFound => Err(LlmHttpError::NotFound),
        FenceConversationDeletionOutcome::IdempotencyConflict
        | FenceConversationDeletionOutcome::AlreadyFenced
        | FenceConversationDeletionOutcome::VersionConflict => Err(LlmHttpError::Conflict),
    }
}
async fn conversation_messages_list(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationPath>, PathRejection>,
    query: Result<Query<ConversationMessagesQuery>, QueryRejection>,
) -> Result<Json<ConversationMessagesPage>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let conversation_id = conversation_id(path)?;
    let Query(query) = query.map_err(|_| LlmHttpError::InvalidRequest)?;
    let limit = MessagePageSize::new(query.limit.unwrap_or(DEFAULT_MESSAGE_PAGE_SIZE))?;
    let request = match query.after_sequence {
        Some(sequence) => MessagePageRequest::after(
            conversation_id,
            MessageCursor::new(conversation_id, MessageSequence::from_u64(sequence)?),
            limit,
        )?,
        None => MessagePageRequest::first(conversation_id, limit),
    };
    match state
        .conversations
        .read_messages(&scope.conversation_authorization(), request)
        .await?
    {
        ReadMessagesOutcome::Found(page) => Ok(Json(ConversationMessagesPage {
            items: page.items().iter().map(Into::into).collect(),
            next_after_sequence: page
                .next_cursor()
                .map(|cursor| cursor.after_sequence().get()),
        })),
        ReadMessagesOutcome::NotFound => Err(LlmHttpError::NotFound),
    }
}
async fn conversation_message_append(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationPath>, PathRejection>,
    payload: Result<Json<ConversationMessageAppendRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ConversationMessageEnvelope>), LlmHttpError> {
    let scope = required_scope(principal)?;
    let p = json_body(payload)?;
    let command = AppendMessage::new(
        conversation_id(path)?,
        ConversationMessageId::from_uuid(p.message_id)?,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        p.message,
        p.created_at,
    )?;
    match state
        .conversations
        .append_message(&scope.conversation_authorization(), &command)
        .await?
    {
        AppendMessageOutcome::Appended {
            message,
            conversation_revision,
        } => Ok((
            StatusCode::CREATED,
            Json(ConversationMessageEnvelope {
                message: (&message).into(),
                conversation_revision: conversation_revision.get(),
                replayed: false,
            }),
        )),
        AppendMessageOutcome::Replayed {
            message,
            conversation_revision,
        } => Ok((
            StatusCode::OK,
            Json(ConversationMessageEnvelope {
                message: (&message).into(),
                conversation_revision: conversation_revision.get(),
                replayed: true,
            }),
        )),
        AppendMessageOutcome::NotFound => Err(LlmHttpError::NotFound),
        AppendMessageOutcome::VersionConflict
        | AppendMessageOutcome::IdempotencyConflict
        | AppendMessageOutcome::DeletionFenced => Err(LlmHttpError::Conflict),
    }
}
async fn conversation_message_update(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationMessagePath>, PathRejection>,
    payload: Result<Json<ConversationMessageUpdateRequest>, JsonRejection>,
) -> Result<Json<ConversationMessageEnvelope>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let (conversation_id, message_id) = message_path(path)?;
    let p = json_body(payload)?;
    let command = UpdateMessage::new(
        conversation_id,
        message_id,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        ConversationMessageRevision::from_u64(p.expected_message_revision)?,
        p.message,
        p.updated_at,
    )?;
    match state
        .conversations
        .update_message(&scope.conversation_authorization(), &command)
        .await?
    {
        UpdateMessageOutcome::Updated {
            message,
            conversation_revision,
        } => Ok(Json(ConversationMessageEnvelope {
            message: (&message).into(),
            conversation_revision: conversation_revision.get(),
            replayed: false,
        })),
        UpdateMessageOutcome::NotFound => Err(LlmHttpError::NotFound),
        UpdateMessageOutcome::VersionConflict | UpdateMessageOutcome::DeletionFenced => {
            Err(LlmHttpError::Conflict)
        }
    }
}
async fn conversation_message_delete(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationMessagePath>, PathRejection>,
    payload: Result<Json<ConversationMessageDeleteRequest>, JsonRejection>,
) -> Result<Json<ConversationRevisionEnvelope>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let (conversation_id, message_id) = message_path(path)?;
    let p = json_body(payload)?;
    let command = DeleteMessage::new(
        conversation_id,
        message_id,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        ConversationMessageRevision::from_u64(p.expected_message_revision)?,
        p.deleted_at,
    )?;
    match state
        .conversations
        .delete_message(&scope.conversation_authorization(), &command)
        .await?
    {
        DeleteMessageOutcome::Deleted {
            conversation_revision,
        } => Ok(Json(ConversationRevisionEnvelope {
            conversation_revision: conversation_revision.get(),
        })),
        DeleteMessageOutcome::NotFound => Err(LlmHttpError::NotFound),
        DeleteMessageOutcome::VersionConflict | DeleteMessageOutcome::DeletionFenced => {
            Err(LlmHttpError::Conflict)
        }
    }
}
async fn conversation_provider_state_get(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationProviderStatePath>, PathRejection>,
) -> Result<Json<ProviderStateEnvelope>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let (conversation_id, state_id) = provider_state_path(path)?;
    let record = state
        .conversations
        .read_provider_state(
            &scope.conversation_authorization(),
            conversation_id,
            state_id,
        )
        .await?
        .ok_or(LlmHttpError::NotFound)?;
    Ok(Json(ProviderStateEnvelope {
        state: (&record).into(),
        conversation_revision: None,
        replayed: false,
    }))
}
async fn conversation_provider_state_put(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationProviderStatePath>, PathRejection>,
    payload: Result<Json<ProviderStatePutRequest>, JsonRejection>,
) -> Result<(StatusCode, Json<ProviderStateEnvelope>), LlmHttpError> {
    let scope = required_scope(principal)?;
    let (conversation_id, state_id) = provider_state_path(path)?;
    let p = json_body(payload)?;
    let expected = p
        .expected_state_revision
        .map(ProviderStateRevision::from_u64)
        .transpose()?;
    let created = expected.is_none();
    let command = SaveProviderState::new(
        conversation_id,
        state_id,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        expected,
        provider_state_value(p.value)?,
        p.updated_at,
    )?;
    match state
        .conversations
        .save_provider_state(&scope.conversation_authorization(), &command)
        .await?
    {
        SaveProviderStateOutcome::Saved {
            state,
            conversation_revision,
        } => Ok((
            if created {
                StatusCode::CREATED
            } else {
                StatusCode::OK
            },
            Json(ProviderStateEnvelope {
                state: (&state).into(),
                conversation_revision: Some(conversation_revision.get()),
                replayed: false,
            }),
        )),
        SaveProviderStateOutcome::Replayed {
            state,
            conversation_revision,
        } => Ok((
            StatusCode::OK,
            Json(ProviderStateEnvelope {
                state: (&state).into(),
                conversation_revision: Some(conversation_revision.get()),
                replayed: true,
            }),
        )),
        SaveProviderStateOutcome::NotFound => Err(LlmHttpError::NotFound),
        SaveProviderStateOutcome::VersionConflict
        | SaveProviderStateOutcome::IdempotencyConflict
        | SaveProviderStateOutcome::DeletionFenced => Err(LlmHttpError::Conflict),
    }
}
async fn conversation_provider_state_delete(
    State(state): State<LlmHttpState>,
    principal: Result<Extension<Principal>, ExtensionRejection>,
    path: Result<Path<ConversationProviderStatePath>, PathRejection>,
    payload: Result<Json<ProviderStateDeleteRequest>, JsonRejection>,
) -> Result<Json<ConversationRevisionEnvelope>, LlmHttpError> {
    let scope = required_scope(principal)?;
    let (conversation_id, state_id) = provider_state_path(path)?;
    let p = json_body(payload)?;
    let command = DeleteProviderState::new(
        conversation_id,
        state_id,
        ConversationRevision::from_u64(p.expected_conversation_revision)?,
        ProviderStateRevision::from_u64(p.expected_state_revision)?,
        p.deleted_at,
    )?;
    match state
        .conversations
        .delete_provider_state(&scope.conversation_authorization(), &command)
        .await?
    {
        DeleteProviderStateOutcome::Deleted {
            conversation_revision,
        } => Ok(Json(ConversationRevisionEnvelope {
            conversation_revision: conversation_revision.get(),
        })),
        DeleteProviderStateOutcome::NotFound => Err(LlmHttpError::NotFound),
        DeleteProviderStateOutcome::VersionConflict
        | DeleteProviderStateOutcome::DeletionFenced => Err(LlmHttpError::Conflict),
    }
}

fn provider_state_value(input: ProviderStateInput) -> Result<ProviderStateValue, LlmHttpError> {
    match input {
        ProviderStateInput::ReasoningSummary { summary, signature } => {
            Ok(ProviderStateValue::ReasoningSummary(
                SanctionedReasoningSummary::from_canonical(&summary, signature.as_ref())?,
            ))
        }
        ProviderStateInput::EncryptedContinuation(value) => {
            let algorithm = match value.algorithm {
                ContinuationEncryptionAlgorithmDto::Aes256Gcm => {
                    ContinuationEncryptionAlgorithm::Aes256Gcm
                }
                ContinuationEncryptionAlgorithmDto::XChaCha20Poly1305 => {
                    ContinuationEncryptionAlgorithm::XChaCha20Poly1305
                }
            };
            Ok(ProviderStateValue::EncryptedContinuation(
                EncryptedContinuationReference::new(
                    value.reference,
                    value.key_id,
                    value.key_revision,
                    algorithm,
                    CiphertextDigest::new(value.ciphertext_digest)?,
                )?,
            ))
        }
    }
}
impl From<&Conversation> for ConversationDto {
    fn from(value: &Conversation) -> Self {
        let status = match value.status() {
            ConversationStatus::Active => ConversationStatusDto::Active,
            ConversationStatus::DeletionFenced {
                request_id,
                fenced_at,
            } => ConversationStatusDto::DeletionFenced {
                request_id: request_id.as_uuid(),
                fenced_at,
            },
        };
        Self {
            conversation_id: value.id().as_uuid(),
            revision: value.revision().get(),
            last_message_sequence: value.last_message_sequence().map(MessageSequence::get),
            status,
            created_at: value.created_at(),
            updated_at: value.updated_at(),
        }
    }
}
impl From<&ConversationMessage> for ConversationMessageDto {
    fn from(value: &ConversationMessage) -> Self {
        Self {
            conversation_id: value.conversation_id().as_uuid(),
            message_id: value.message_id().as_uuid(),
            sequence: value.sequence().get(),
            revision: value.revision().get(),
            message: value.message().clone(),
            created_at: value.created_at(),
            updated_at: value.updated_at(),
        }
    }
}
impl From<&ProviderStateRecord> for ProviderStateDto {
    fn from(value: &ProviderStateRecord) -> Self {
        let state = match value.value() {
            ProviderStateValue::ReasoningSummary(summary) => {
                ProviderStateValueResponse::ReasoningSummary {
                    summary: summary.summary().to_owned(),
                    signature: summary
                        .signature()
                        .map(|signature| signature.as_str().to_owned()),
                }
            }
            ProviderStateValue::EncryptedContinuation(reference) => {
                ProviderStateValueResponse::EncryptedContinuation(EncryptedContinuationDto {
                    reference: reference.reference().to_owned(),
                    key_id: reference.key_id().to_owned(),
                    key_revision: reference.key_revision(),
                    algorithm: match reference.algorithm() {
                        ContinuationEncryptionAlgorithm::Aes256Gcm => {
                            ContinuationEncryptionAlgorithmDto::Aes256Gcm
                        }
                        ContinuationEncryptionAlgorithm::XChaCha20Poly1305 => {
                            ContinuationEncryptionAlgorithmDto::XChaCha20Poly1305
                        }
                    },
                    ciphertext_digest: *reference.ciphertext_digest().as_bytes(),
                })
            }
        };
        Self {
            conversation_id: value.conversation_id().as_uuid(),
            state_id: value.state_id().as_uuid(),
            revision: value.revision().get(),
            value: state,
            created_at: value.created_at(),
            updated_at: value.updated_at(),
        }
    }
}

/// Inserts fixed operations and actual schemars-derived components.
///
/// # Errors
///
/// Returns [`OpenApiError`] when the document shape or a generated schema cannot be serialized.
#[allow(
    clippy::too_many_lines,
    reason = "the explicit deterministic operation catalog is intentionally visible in one function"
)]
pub fn augment_openapi(document: &mut Value) -> Result<(), OpenApiError> {
    let root = document
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?;
    let components = root
        .entry("components")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?;
    let schemas = components
        .entry("schemas")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?;
    insert_schema::<LlmRequest>(schemas, "LlmRequest")?;
    insert_schema::<LlmResponse>(schemas, "LlmResponse")?;
    insert_schema::<LlmStreamEvent>(schemas, "LlmStreamEvent")?;
    insert_schema::<StreamTerminalState>(schemas, "LlmStreamTerminalState")?;
    insert_schema::<AiProblem>(schemas, "AiProblem")?;
    insert_schema::<AiRoute>(schemas, "AiRoute")?;
    insert_schema::<AiRoutesResponse>(schemas, "LlmRouteList")?;
    insert_schema::<DurableJobRecord>(schemas, "LlmJobSubmission")?;
    insert_schema::<DurableJobRecord>(schemas, "LlmJob")?;
    insert_schema::<ConversationCreateRequest>(schemas, "ConversationCreateRequest")?;
    insert_schema::<ConversationDeleteRequest>(schemas, "ConversationDeleteRequest")?;
    insert_schema::<ConversationDto>(schemas, "LlmConversation")?;
    insert_schema::<ConversationEnvelope>(schemas, "ConversationEnvelope")?;
    insert_schema::<ConversationMessagesPage>(schemas, "LlmConversationMessagePage")?;
    insert_schema::<ConversationMessageAppendRequest>(schemas, "ConversationMessageAppendRequest")?;
    insert_schema::<ConversationMessageUpdateRequest>(schemas, "ConversationMessageUpdateRequest")?;
    insert_schema::<ConversationMessageDeleteRequest>(schemas, "ConversationMessageDeleteRequest")?;
    insert_schema::<ConversationMessageDto>(schemas, "LlmConversationMessage")?;
    insert_schema::<ConversationMessageEnvelope>(schemas, "ConversationMessageEnvelope")?;
    insert_schema::<ConversationRevisionEnvelope>(schemas, "ConversationRevisionEnvelope")?;
    insert_schema::<ProviderStatePutRequest>(schemas, "ProviderStatePutRequest")?;
    insert_schema::<ProviderStateDeleteRequest>(schemas, "ProviderStateDeleteRequest")?;
    insert_schema::<ProviderStateDto>(schemas, "LlmProviderState")?;
    insert_schema::<ProviderStateEnvelope>(schemas, "ProviderStateEnvelope")?;
    let paths = root
        .entry("paths")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?;
    add(
        paths,
        "get",
        AI_ROUTES_PATH,
        operation(
            "aiRoutesList",
            AI_TAG,
            None,
            json_response("200", "LlmRouteList"),
            vec![],
        ),
    )?;
    add(
        paths,
        "post",
        AI_RESPONSES_PATH,
        operation(
            "aiResponseCreate",
            AI_TAG,
            Some("LlmRequest"),
            json_response("200", "LlmResponse"),
            vec![],
        ),
    )?;
    add(
        paths,
        "post",
        AI_RESPONSE_STREAM_PATH,
        operation(
            "aiResponseStream",
            AI_TAG,
            Some("LlmRequest"),
            sse_response(),
            vec![],
        ),
    )?;
    add(
        paths,
        "post",
        AI_JOBS_PATH,
        operation(
            "aiJobSubmit",
            AI_TAG,
            Some("LlmRequest"),
            json_response("202", "LlmJobSubmission"),
            vec![],
        ),
    )?;
    add(
        paths,
        "get",
        AI_JOB_PATH,
        operation(
            "aiJobGet",
            AI_TAG,
            None,
            json_response("200", "LlmJob"),
            vec![uuid_path("job_id")],
        ),
    )?;
    add(
        paths,
        "delete",
        AI_JOB_PATH,
        operation(
            "aiJobCancel",
            AI_TAG,
            None,
            empty_response("204"),
            vec![uuid_path("job_id")],
        ),
    )?;
    add(
        paths,
        "get",
        AI_JOB_RESULT_PATH,
        operation(
            "aiJobResult",
            AI_TAG,
            None,
            json_response("200", "LlmResponse"),
            vec![uuid_path("job_id")],
        ),
    )?;
    add(
        paths,
        "post",
        AI_CONVERSATIONS_PATH,
        with_json_response(
            operation(
                "aiConversationCreate",
                CONVERSATION_TAG,
                Some("ConversationCreateRequest"),
                json_response("201", "ConversationEnvelope"),
                vec![],
            ),
            "200",
            "ConversationEnvelope",
        ),
    )?;
    add(
        paths,
        "get",
        AI_CONVERSATION_PATH,
        operation(
            "aiConversationGet",
            CONVERSATION_TAG,
            None,
            json_response("200", "ConversationEnvelope"),
            vec![uuid_path("conversation_id")],
        ),
    )?;
    add(
        paths,
        "delete",
        AI_CONVERSATION_PATH,
        with_json_response(
            operation(
                "aiConversationDelete",
                CONVERSATION_TAG,
                Some("ConversationDeleteRequest"),
                json_response("202", "ConversationEnvelope"),
                vec![uuid_path("conversation_id")],
            ),
            "200",
            "ConversationEnvelope",
        ),
    )?;
    add(
        paths,
        "get",
        AI_CONVERSATION_MESSAGES_PATH,
        operation(
            "aiConversationMessagesList",
            CONVERSATION_TAG,
            None,
            json_response("200", "LlmConversationMessagePage"),
            vec![
                uuid_path("conversation_id"),
                integer_query("after_sequence"),
                integer_query("limit"),
            ],
        ),
    )?;
    add(
        paths,
        "post",
        AI_CONVERSATION_MESSAGES_PATH,
        with_json_response(
            operation(
                "aiConversationMessageAppend",
                CONVERSATION_TAG,
                Some("ConversationMessageAppendRequest"),
                json_response("201", "ConversationMessageEnvelope"),
                vec![uuid_path("conversation_id")],
            ),
            "200",
            "ConversationMessageEnvelope",
        ),
    )?;
    add(
        paths,
        "patch",
        AI_CONVERSATION_MESSAGE_PATH,
        operation(
            "aiConversationMessageUpdate",
            CONVERSATION_TAG,
            Some("ConversationMessageUpdateRequest"),
            json_response("200", "ConversationMessageEnvelope"),
            vec![uuid_path("conversation_id"), uuid_path("message_id")],
        ),
    )?;
    add(
        paths,
        "delete",
        AI_CONVERSATION_MESSAGE_PATH,
        operation(
            "aiConversationMessageDelete",
            CONVERSATION_TAG,
            Some("ConversationMessageDeleteRequest"),
            json_response("200", "ConversationRevisionEnvelope"),
            vec![uuid_path("conversation_id"), uuid_path("message_id")],
        ),
    )?;
    add(
        paths,
        "get",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        operation(
            "aiConversationProviderStateGet",
            CONVERSATION_TAG,
            None,
            json_response("200", "ProviderStateEnvelope"),
            vec![uuid_path("conversation_id"), uuid_path("state_id")],
        ),
    )?;
    add(
        paths,
        "put",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        with_json_response(
            operation(
                "aiConversationProviderStatePut",
                CONVERSATION_TAG,
                Some("ProviderStatePutRequest"),
                json_response("200", "ProviderStateEnvelope"),
                vec![uuid_path("conversation_id"), uuid_path("state_id")],
            ),
            "201",
            "ProviderStateEnvelope",
        ),
    )?;
    add(
        paths,
        "delete",
        AI_CONVERSATION_PROVIDER_STATE_PATH,
        operation(
            "aiConversationProviderStateDelete",
            CONVERSATION_TAG,
            Some("ProviderStateDeleteRequest"),
            json_response("200", "ConversationRevisionEnvelope"),
            vec![uuid_path("conversation_id"), uuid_path("state_id")],
        ),
    )?;
    Ok(())
}
fn insert_schema<T: JsonSchema>(
    schemas: &mut Map<String, Value>,
    name: &str,
) -> Result<(), OpenApiError> {
    let mut schema = serde_json::to_value(schemars::schema_for!(T))
        .map_err(|_| OpenApiError::SerializationFailed)?;
    let definitions = schema
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?
        .remove("$defs")
        .map(|value| {
            value
                .as_object()
                .cloned()
                .ok_or(OpenApiError::SerializationFailed)
        })
        .transpose()?
        .unwrap_or_default();
    rewrite_refs(&mut schema);
    if let Some(definition_name) = schema
        .get("$ref")
        .and_then(Value::as_str)
        .and_then(|reference| reference.strip_prefix("#/components/schemas/"))
        && let Some(definition) = definitions.get(definition_name)
    {
        schema = definition.clone();
        rewrite_refs(&mut schema);
    }
    normalize_boolean_schema_keywords(&mut schema);
    for (definition_name, mut definition) in definitions {
        rewrite_refs(&mut definition);
        normalize_boolean_schema_keywords(&mut definition);
        schemas.entry(definition_name).or_insert(definition);
    }
    schemas.insert(name.to_owned(), schema);
    Ok(())
}
fn rewrite_refs(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(Value::String(reference)) = object.get_mut("$ref")
                && let Some(name) = reference.strip_prefix("#/$defs/")
            {
                *reference = format!("#/components/schemas/{name}");
            }
            for nested in object.values_mut() {
                rewrite_refs(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                rewrite_refs(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
fn normalize_boolean_schema_keywords(value: &mut Value) {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                if matches!(
                    key.as_str(),
                    "additionalProperties"
                        | "contains"
                        | "else"
                        | "if"
                        | "items"
                        | "not"
                        | "propertyNames"
                        | "then"
                        | "unevaluatedProperties"
                ) && *nested == Value::Bool(true)
                {
                    *nested = json!({});
                }
                if matches!(key.as_str(), "properties" | "patternProperties")
                    && let Value::Object(schemas) = nested
                {
                    for schema in schemas.values_mut() {
                        if *schema == Value::Bool(true) {
                            *schema = json!({});
                        }
                        normalize_boolean_schema_keywords(schema);
                    }
                } else if matches!(key.as_str(), "allOf" | "anyOf" | "oneOf" | "prefixItems")
                    && let Value::Array(schemas) = nested
                {
                    for schema in schemas {
                        if *schema == Value::Bool(true) {
                            *schema = json!({});
                        }
                        normalize_boolean_schema_keywords(schema);
                    }
                } else {
                    normalize_boolean_schema_keywords(nested);
                }
            }
        }
        Value::Array(values) => {
            for nested in values {
                normalize_boolean_schema_keywords(nested);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}
fn add(
    paths: &mut Map<String, Value>,
    method: &str,
    path: &str,
    operation: Value,
) -> Result<(), OpenApiError> {
    paths
        .entry(path.to_owned())
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or(OpenApiError::SerializationFailed)?
        .insert(method.to_owned(), operation);
    Ok(())
}
fn with_json_response(mut operation: Value, status: &str, schema: &str) -> Value {
    if let Some(responses) = operation
        .get_mut("responses")
        .and_then(Value::as_object_mut)
    {
        let (status, response) = json_response(status, schema);
        responses.insert(status, response);
    }
    operation
}
fn operation(
    operation_id: &str,
    tag: &str,
    request_schema: Option<&str>,
    success: (String, Value),
    parameters: Vec<Value>,
) -> Value {
    let (success_status, success_response) = success;
    let mut responses = Map::new();
    responses.insert(success_status, success_response);
    for status in ["400", "401", "403", "404", "409", "429", "500", "503"] {
        responses.insert(status.to_owned(), problem_response());
    }
    let mut operation = json!({"operationId": operation_id, "tags": [tag], "security": [{"session_cookie": []}, {"bearer_auth": []}, {"api_key_auth": []}], "responses": responses});
    if let Some(object) = operation.as_object_mut() {
        if let Some(schema) = request_schema {
            object.insert("requestBody".to_owned(), json!({"required": true, "content": {"application/json": {"schema": schema_ref(schema)}}}));
        }
        if !parameters.is_empty() {
            object.insert("parameters".to_owned(), Value::Array(parameters));
        }
    }
    operation
}
fn json_response(status: &str, schema: &str) -> (String, Value) {
    (
        status.to_owned(),
        json!({"description": "Canonical response", "content": {"application/json": {"schema": schema_ref(schema)}}}),
    )
}
fn sse_response() -> (String, Value) {
    (
        "200".to_owned(),
        json!({"description": "Canonical bounded event stream", "content": {"text/event-stream": {"schema": schema_ref("LlmStreamEvent")}}}),
    )
}
fn empty_response(status: &str) -> (String, Value) {
    (
        status.to_owned(),
        json!({"description": "Operation completed"}),
    )
}
fn problem_response() -> Value {
    json!({"description": "RFC 9457 problem", "content": {"application/problem+json": {"schema": schema_ref("AiProblem")}}})
}
fn schema_ref(name: &str) -> Value {
    json!({"$ref": format!("#/components/schemas/{name}")})
}
fn uuid_path(name: &str) -> Value {
    json!({"name": name, "in": "path", "required": true, "schema": {"type": "string", "format": "uuid"}})
}
fn integer_query(name: &str) -> Value {
    json!({"name": name, "in": "query", "required": false, "schema": {"type": "integer", "minimum": 1}})
}
