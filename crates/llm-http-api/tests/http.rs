//! LLM HTTP authentication, budgeting, streaming, job, and conversation contracts.
#![allow(
    clippy::expect_used,
    reason = "poisoned test mutexes and absent configured fixtures are unrecoverable test failures"
)]

use std::{
    collections::BTreeSet,
    error::Error,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use axum::{
    Extension,
    body::Body,
    http::{Request, StatusCode},
};
use futures::{StreamExt, future::BoxFuture};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use omnius_jobs_core::JobId;
use omnius_llm_conversations::*;
use omnius_llm_core::{LlmRequest, LlmResponse, Usage};
use omnius_llm_http_api::{
    AI_RESPONSE_STREAM_PATH, AI_RESPONSES_PATH, AiRoute, BudgetError, BudgetPort,
    BudgetReservation, BudgetedExecutionError, BudgetedLlmService, CancelJobOutcome,
    CanonicalEventStream, DispatchOutcome, DurableJobError, DurableJobPort, DurableJobRecord,
    DurableJobStatus, ExecutionError, ExecutionPort, LlmHttpState, ReadinessError, RequestScope,
    RouteReadinessPort, StreamDispatch, llm_http_router,
};
use omnius_llm_streaming::{
    LlmStreamAssembler, LlmStreamEvent, LlmStreamEventData, StreamInterruption, StreamLimits,
    StreamPartKind, StreamTerminalState,
};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const REQUEST_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/llm-request.example.json");
const RESPONSE_EXAMPLE: &str =
    include_str!("../../../specs/examples/llm-mcp-suite/llm-response.example.json");

fn canonical_request() -> Result<LlmRequest, Box<dyn Error>> {
    Ok(serde_json::from_str(REQUEST_EXAMPLE)?)
}
fn canonical_response() -> Result<LlmResponse, Box<dyn Error>> {
    Ok(serde_json::from_str(RESPONSE_EXAMPLE)?)
}
fn scope() -> RequestScope {
    RequestScope::new(TenantId::new(), SubjectId::new())
}

struct RecordingBudget {
    calls: Arc<Mutex<Vec<&'static str>>>,
}
impl BudgetPort for RecordingBudget {
    fn reserve<'a>(
        &'a self,
        _scope: RequestScope,
        _request: &'a LlmRequest,
    ) -> BoxFuture<'a, Result<BudgetReservation, BudgetError>> {
        self.calls.lock().expect("call log").push("reserve");
        Box::pin(async { Ok(BudgetReservation::new(Uuid::now_v7())) })
    }
    fn commit<'a>(
        &'a self,
        _reservation: BudgetReservation,
        usage: Option<&'a Usage>,
    ) -> BoxFuture<'a, Result<(), BudgetError>> {
        self.calls
            .lock()
            .expect("call log")
            .push(if usage.is_some() {
                "commit_actual"
            } else {
                "commit_missing"
            });
        Box::pin(async { Ok(()) })
    }
    fn release(&self, _reservation: BudgetReservation) -> BoxFuture<'_, Result<(), BudgetError>> {
        self.calls.lock().expect("call log").push("release");
        Box::pin(async { Ok(()) })
    }
}

struct RecordingExecution {
    calls: Arc<Mutex<Vec<&'static str>>>,
    sync: Mutex<Option<DispatchOutcome<LlmResponse>>>,
    stream: Mutex<Option<DispatchOutcome<StreamDispatch>>>,
    scopes: Arc<Mutex<Vec<RequestScope>>>,
    requests: Arc<Mutex<Vec<LlmRequest>>>,
}
impl RecordingExecution {
    fn sync(outcome: DispatchOutcome<LlmResponse>, calls: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            calls,
            sync: Mutex::new(Some(outcome)),
            stream: Mutex::new(None),
            scopes: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
}
impl ExecutionPort for RecordingExecution {
    fn dispatch_sync(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<LlmResponse>> {
        self.calls.lock().expect("call log").push("dispatch");
        self.scopes.lock().expect("scopes").push(scope);
        self.requests.lock().expect("requests").push(request);
        let outcome = self
            .sync
            .lock()
            .expect("sync outcome")
            .take()
            .expect("configured sync outcome");
        Box::pin(async move { outcome })
    }
    fn dispatch_stream(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, DispatchOutcome<StreamDispatch>> {
        self.calls.lock().expect("call log").push("dispatch_stream");
        self.scopes.lock().expect("scopes").push(scope);
        self.requests.lock().expect("requests").push(request);
        let outcome = self
            .stream
            .lock()
            .expect("stream outcome")
            .take()
            .expect("configured stream outcome");
        Box::pin(async move { outcome })
    }
}

#[tokio::test]
async fn sync_reserves_before_dispatch_and_commits_actual_usage_without_changing_response()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = canonical_response()?;
    let execution = Arc::new(RecordingExecution::sync(
        DispatchOutcome::dispatched(Ok(response.clone()), Some(response.usage().clone())),
        Arc::clone(&calls),
    ));
    let service = BudgetedLlmService::new(
        Arc::new(RecordingBudget {
            calls: Arc::clone(&calls),
        }),
        execution,
    );

    let returned = service.execute(scope(), canonical_request()?).await?;

    assert_eq!(returned, response);
    assert_eq!(
        *calls.lock().expect("call log"),
        ["reserve", "dispatch", "commit_actual"]
    );
    Ok(())
}

#[tokio::test]
async fn predispatch_failure_releases_and_never_commits() -> Result<(), Box<dyn Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let execution = Arc::new(RecordingExecution::sync(
        DispatchOutcome::pre_dispatch_failed(ExecutionError::ProviderUnavailable),
        Arc::clone(&calls),
    ));
    let service = BudgetedLlmService::new(
        Arc::new(RecordingBudget {
            calls: Arc::clone(&calls),
        }),
        execution,
    );

    let result = service.execute(scope(), canonical_request()?).await;

    assert!(matches!(
        result,
        Err(BudgetedExecutionError::Execution(
            ExecutionError::ProviderUnavailable
        ))
    ));
    assert_eq!(
        *calls.lock().expect("call log"),
        ["reserve", "dispatch", "release"]
    );
    Ok(())
}

fn terminal_events(
    request: &LlmRequest,
    state: StreamTerminalState,
) -> Result<Vec<LlmStreamEvent>, Box<dyn Error>> {
    let mut assembler =
        LlmStreamAssembler::new(request.request_id().clone(), StreamLimits::default());
    let mut events = vec![assembler.emit(LlmStreamEventData::ResponseStart {
        response_id: "response-1".to_owned(),
    })?];
    if matches!(state, StreamTerminalState::PartialInterrupted(_)) {
        events.push(assembler.emit(LlmStreamEventData::PartStart {
            part_id: "text-1".to_owned(),
            kind: StreamPartKind::Text,
        })?);
        events.push(assembler.emit(LlmStreamEventData::TextDelta {
            part_id: "text-1".to_owned(),
            text: "accepted".to_owned(),
        })?);
    }
    events.push(assembler.terminate(state)?);
    Ok(events)
}

#[tokio::test]
async fn stream_preserves_request_identity_and_canonical_terminal_assembly()
-> Result<(), Box<dyn Error>> {
    let request = canonical_request()?;
    let events = terminal_events(&request, StreamTerminalState::Completed)?;
    let stream = CanonicalEventStream::new(
        request.request_id().clone(),
        futures::stream::iter(events.into_iter().map(Ok)),
    );
    let decoded = stream
        .map(|payload| {
            payload.and_then(|payload| {
                serde_json::from_str::<LlmStreamEvent>(&payload)
                    .map_err(|_| ExecutionError::InvalidStream)
            })
        })
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    assert!(
        decoded
            .iter()
            .all(|event| event.request_id() == request.request_id())
    );
    assert!(
        decoded
            .last()
            .is_some_and(|event| event.terminal().is_some())
    );
    Ok(())
}

#[test]
fn terminal_refusal_cancel_and_partial_states_remain_distinguishable() -> Result<(), Box<dyn Error>>
{
    let request = canonical_request()?;
    let states = [
        StreamTerminalState::Completed,
        StreamTerminalState::ProviderRefused,
        StreamTerminalState::SafetyRefused,
        StreamTerminalState::Cancelled,
        StreamTerminalState::PartialInterrupted(StreamInterruption::Transport),
    ];
    let serialized = states
        .into_iter()
        .map(|state| {
            let events = terminal_events(&request, state)?;
            Ok(serde_json::to_string(
                events.last().ok_or("missing terminal")?,
            )?)
        })
        .collect::<Result<BTreeSet<_>, Box<dyn Error>>>()?;

    assert_eq!(serialized.len(), 5);
    Ok(())
}

struct FakeJobs {
    captured: Arc<Mutex<Vec<(RequestScope, LlmRequest)>>>,
    job_id: JobId,
    response: LlmResponse,
}
impl DurableJobPort for FakeJobs {
    fn submit(
        &self,
        scope: RequestScope,
        request: LlmRequest,
    ) -> BoxFuture<'_, Result<DurableJobRecord, DurableJobError>> {
        self.captured
            .lock()
            .expect("captured jobs")
            .push((scope, request.clone()));
        let job = DurableJobRecord {
            job_id: self.job_id,
            status: DurableJobStatus::Pending,
        };
        Box::pin(async move { Ok(job) })
    }
    fn get(
        &self,
        _scope: RequestScope,
        _job_id: JobId,
    ) -> BoxFuture<'_, Result<Option<DurableJobRecord>, DurableJobError>> {
        Box::pin(async { Ok(None) })
    }
    fn cancel(
        &self,
        _scope: RequestScope,
        _job_id: JobId,
    ) -> BoxFuture<'_, Result<CancelJobOutcome, DurableJobError>> {
        Box::pin(async { Ok(CancelJobOutcome::NotFound) })
    }
    fn result(
        &self,
        _scope: RequestScope,
        job_id: JobId,
    ) -> BoxFuture<'_, Result<Option<LlmResponse>, DurableJobError>> {
        let response = (job_id == self.job_id).then(|| self.response.clone());
        Box::pin(async move { Ok(response) })
    }
}

#[tokio::test]
async fn durable_job_request_and_result_keep_canonical_values_equal() -> Result<(), Box<dyn Error>>
{
    let request = canonical_request()?;
    let response = canonical_response()?;
    let expected_scope = scope();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let jobs = FakeJobs {
        captured: Arc::clone(&captured),
        job_id: JobId::new(),
        response: response.clone(),
    };

    let submitted = jobs.submit(expected_scope, request.clone()).await?;
    let result = jobs
        .result(expected_scope, submitted.job_id)
        .await?
        .ok_or("missing result")?;
    let captured = captured.lock().expect("captured jobs");

    assert!(captured[0].0 == expected_scope && captured[0].1 == request);
    assert_eq!(result, response);
    Ok(())
}

struct Ready;
impl RouteReadinessPort for Ready {
    fn list_ready_routes(
        &self,
        _scope: RequestScope,
    ) -> BoxFuture<'_, Result<Vec<AiRoute>, ReadinessError>> {
        Box::pin(async {
            Ok(vec![AiRoute {
                route: "default".to_owned(),
                provider: "test".to_owned(),
                model: "test".to_owned(),
                ready: true,
            }])
        })
    }
}

struct UnavailableConversations;
#[async_trait]
impl ConversationRepository for UnavailableConversations {
    async fn create_conversation(
        &self,
        _: &ConversationAuthorization,
        _: &CreateConversation,
    ) -> ConversationRepositoryResult<CreateConversationOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn read_conversation(
        &self,
        _: &ConversationAuthorization,
        _: ConversationId,
    ) -> ConversationRepositoryResult<Option<Conversation>> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn append_message(
        &self,
        _: &ConversationAuthorization,
        _: &AppendMessage,
    ) -> ConversationRepositoryResult<AppendMessageOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn read_messages(
        &self,
        _: &ConversationAuthorization,
        _: MessagePageRequest,
    ) -> ConversationRepositoryResult<ReadMessagesOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn update_message(
        &self,
        _: &ConversationAuthorization,
        _: &UpdateMessage,
    ) -> ConversationRepositoryResult<UpdateMessageOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn delete_message(
        &self,
        _: &ConversationAuthorization,
        _: &DeleteMessage,
    ) -> ConversationRepositoryResult<DeleteMessageOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn save_provider_state(
        &self,
        _: &ConversationAuthorization,
        _: &SaveProviderState,
    ) -> ConversationRepositoryResult<SaveProviderStateOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn read_provider_state(
        &self,
        _: &ConversationAuthorization,
        _: ConversationId,
        _: ProviderStateId,
    ) -> ConversationRepositoryResult<Option<ProviderStateRecord>> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn delete_provider_state(
        &self,
        _: &ConversationAuthorization,
        _: &DeleteProviderState,
    ) -> ConversationRepositoryResult<DeleteProviderStateOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn save_job_reference_snapshot(
        &self,
        _: &ConversationAuthorization,
        _: &SaveJobReferenceSnapshot,
    ) -> ConversationRepositoryResult<SaveJobReferenceSnapshotOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn read_job_reference_snapshot(
        &self,
        _: &ConversationAuthorization,
        _: ConversationId,
        _: JobId,
    ) -> ConversationRepositoryResult<Option<DurableJobReferenceSnapshot>> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn fence_conversation_deletion(
        &self,
        _: &ConversationAuthorization,
        _: FenceConversationDeletion,
    ) -> ConversationRepositoryResult<FenceConversationDeletionOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn record_retention_inventory(
        &self,
        _: &ConversationAuthorization,
        _: &RetentionInventoryEvent,
    ) -> ConversationRepositoryResult<RecordRetentionInventoryOutcome> {
        Err(ConversationRepositoryError::Unavailable)
    }
    async fn read_retention_inventory(
        &self,
        _: &ConversationAuthorization,
        _: ConversationId,
        _: DeletionFenceEventId,
    ) -> ConversationRepositoryResult<Option<RetentionInventoryEvent>> {
        Err(ConversationRepositoryError::Unavailable)
    }
}

fn principal(
    tenant_id: Option<TenantId>,
    subject_id: SubjectId,
) -> Result<Principal, Box<dyn Error>> {
    Ok(Principal::new(
        subject_id,
        PrincipalKind::User,
        tenant_id,
        AuthMethod::Jwt,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

fn http_state(
    execution: Arc<RecordingExecution>,
    jobs: Arc<FakeJobs>,
    calls: Arc<Mutex<Vec<&'static str>>>,
) -> LlmHttpState {
    LlmHttpState::new(
        Arc::new(RecordingBudget { calls }),
        execution,
        Arc::new(Ready),
        jobs,
        Arc::new(UnavailableConversations),
    )
}

#[tokio::test]
async fn tenantless_principal_fails_closed_before_any_port_dispatch() -> Result<(), Box<dyn Error>>
{
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = canonical_response()?;
    let execution = Arc::new(RecordingExecution::sync(
        DispatchOutcome::dispatched(Ok(response.clone()), None),
        Arc::clone(&calls),
    ));
    let jobs = Arc::new(FakeJobs {
        captured: Arc::new(Mutex::new(Vec::new())),
        job_id: JobId::new(),
        response,
    });
    let app = llm_http_router(http_state(execution, jobs, Arc::clone(&calls)))
        .layer(Extension(principal(None, SubjectId::new())?));
    let body = serde_json::to_vec(&canonical_request()?)?;

    let response = app
        .oneshot(
            Request::post(AI_RESPONSES_PATH)
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(calls.lock().expect("call log").is_empty());
    Ok(())
}

#[tokio::test]
async fn authenticated_scope_passes_exact_principal_and_tenant_to_provider()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = canonical_response()?;
    let execution = Arc::new(RecordingExecution::sync(
        DispatchOutcome::dispatched(Ok(response.clone()), None),
        Arc::clone(&calls),
    ));
    let captured_scopes = Arc::clone(&execution.scopes);
    let jobs = Arc::new(FakeJobs {
        captured: Arc::new(Mutex::new(Vec::new())),
        job_id: JobId::new(),
        response,
    });
    let tenant_id = TenantId::new();
    let subject_id = SubjectId::new();
    let app = llm_http_router(http_state(execution, jobs, calls))
        .layer(Extension(principal(Some(tenant_id), subject_id)?));
    let body = serde_json::to_vec(&canonical_request()?)?;

    let response = app
        .oneshot(
            Request::post(AI_RESPONSES_PATH)
                .header("content-type", "application/json")
                .body(Body::from(body))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        captured_scopes.lock().expect("scopes").as_slice()
            == [RequestScope::new(tenant_id, subject_id)]
    );
    Ok(())
}

#[tokio::test]
async fn stream_replay_header_is_rejected_before_budget_or_provider_dispatch()
-> Result<(), Box<dyn Error>> {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let response = canonical_response()?;
    let execution = Arc::new(RecordingExecution::sync(
        DispatchOutcome::dispatched(Ok(response.clone()), None),
        Arc::clone(&calls),
    ));
    let jobs = Arc::new(FakeJobs {
        captured: Arc::new(Mutex::new(Vec::new())),
        job_id: JobId::new(),
        response,
    });
    let app = llm_http_router(http_state(execution, jobs, Arc::clone(&calls))).layer(Extension(
        principal(Some(TenantId::new()), SubjectId::new())?,
    ));
    let request = Request::post(AI_RESPONSE_STREAM_PATH)
        .header("content-type", "application/json")
        .header("last-event-id", "1")
        .body(Body::from(serde_json::to_vec(&canonical_request()?)?))?;

    let response = app.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(calls.lock().expect("call log").is_empty());
    Ok(())
}
