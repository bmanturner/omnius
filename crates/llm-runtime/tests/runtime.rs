//! Provider-neutral runtime orchestration and lifecycle coverage.
#![allow(clippy::expect_used)] // Fixed fixture literals should fail loudly if their contract changes.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use omnius_llm_core::{
    CapabilityEvidence, CapabilityEvidenceSource, CompletionStatus, LlmInputPart, LlmMessage,
    LlmOutputPart, LlmProvider, LlmRequest, LlmRequestId, LlmResponse, MessageRole,
    ModelCapability, ModelCapabilityDeclaration, ModelCapabilityKey, ModelCapabilityRegistry,
    OutputMode, OutputRequest, ProviderCompletionDiagnostics, ProviderCompletionResult,
    ProviderError, ProviderErrorKind, ProviderStream, ProviderStreamEvent, RawRetentionPolicy,
    RawRetentionState, RequestLimits, RetainedRaw, RetryClass, Route, SchemaDefinition,
    StructuredOutputPart, StructuredValidation, TextOutputPart, Usage,
};
use omnius_llm_routing::{
    CandidateId, CandidateLimits, CandidateRank, CircuitPolicy, DataClassification, DeadlinePolicy,
    EndpointId, FallbackPolicy, HedgePolicy, ObservabilityName, Region, Residency, RetryPolicy,
    RouteCandidate, RouteDefinition, RouteId, RouteLimits, RoutePolicy, RouteRevision,
    SafetyPolicyRevision, SemanticBoundary,
};
use omnius_llm_runtime::{
    LlmRuntime, ProviderBinding, ProviderRegistry, RuntimeApplicationPorts, RuntimeDefinition,
    RuntimeDispatch, RuntimeError, StreamPolicy, StructuredPolicy,
};
use omnius_llm_streaming::{StreamLimits, StreamTerminalState};
use omnius_llm_structured_output::{
    FallbackPermission, RepairCandidate, RepairPolicy, RepairRequest, StrategyPolicy,
    StructuredOutputRepairPort,
};
use omnius_validation::JsonValidationLimits;
use time::OffsetDateTime;

struct DeterministicProvider {
    provider: &'static str,
    model: &'static str,
    complete_calls: AtomicUsize,
    completions: Mutex<VecDeque<Result<(), ProviderErrorKind>>>,
    stream_mode: StreamMode,
    stream_polls: Arc<AtomicUsize>,
}

enum StreamMode {
    Terminal,
    Pending(Arc<AtomicBool>),
}

impl DeterministicProvider {
    fn successful(provider: &'static str, model: &'static str) -> Self {
        Self {
            provider,
            model,
            complete_calls: AtomicUsize::new(0),
            completions: Mutex::new(VecDeque::new()),
            stream_mode: StreamMode::Terminal,
            stream_polls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn sequenced(
        provider: &'static str,
        model: &'static str,
        outcomes: impl IntoIterator<Item = Result<(), ProviderErrorKind>>,
    ) -> Self {
        Self {
            provider,
            model,
            complete_calls: AtomicUsize::new(0),
            completions: Mutex::new(outcomes.into_iter().collect()),
            stream_mode: StreamMode::Terminal,
            stream_polls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn pending(provider: &'static str, model: &'static str, dropped: Arc<AtomicBool>) -> Self {
        Self {
            provider,
            model,
            complete_calls: AtomicUsize::new(0),
            completions: Mutex::new(VecDeque::new()),
            stream_mode: StreamMode::Pending(dropped),
            stream_polls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn completion(&self, request: &LlmRequest) -> Result<ProviderCompletionResult, ProviderError> {
        let output = if request.output().mode() == OutputMode::Structured {
            let part = StructuredOutputPart::new(
                "structured-1".to_owned(),
                serde_json::json!({"invalid": true}),
                StructuredValidation::Invalid,
            )
            .map_err(|_| provider_error(self.provider, ProviderErrorKind::Schema))?;
            vec![LlmOutputPart::Structured(part)]
        } else {
            let part = TextOutputPart::new("text-1".to_owned(), "done".to_owned(), None)
                .map_err(|_| provider_error(self.provider, ProviderErrorKind::Schema))?;
            vec![LlmOutputPart::Text(part)]
        };
        let response = LlmResponse::new(
            request.request_id().clone(),
            "response-1".to_owned(),
            self.provider.to_owned(),
            self.model.to_owned(),
            CompletionStatus::Completed,
            None,
            output,
            Usage::new(Some(2), Some(1)),
            OffsetDateTime::UNIX_EPOCH,
        )
        .map_err(|_| provider_error(self.provider, ProviderErrorKind::Schema))?;
        Ok(ProviderCompletionResult::new(
            response,
            RetainedRaw::discarded(),
            ProviderCompletionDiagnostics::new(
                self.provider.to_owned(),
                RawRetentionState::Discarded,
                0,
                0,
            ),
        ))
    }
}

#[async_trait]
impl LlmProvider for DeterministicProvider {
    async fn complete(
        &self,
        request: LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        self.complete_calls.fetch_add(1, Ordering::SeqCst);
        let outcome = self
            .completions
            .lock()
            .map_err(|_| provider_error(self.provider, ProviderErrorKind::Provider))?
            .pop_front()
            .unwrap_or(Ok(()));
        match outcome {
            Ok(()) => self.completion(&request),
            Err(kind) => Err(provider_error(self.provider, kind)),
        }
    }

    async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        match &self.stream_mode {
            StreamMode::Terminal => {
                let result = self.completion(&request)?;
                Ok(ProviderStream::new(
                    self.provider.to_owned(),
                    TerminalProviderStream {
                        events: VecDeque::from([
                            Ok(ProviderStreamEvent::TextDelta {
                                sequence: 0,
                                text: "done".to_owned(),
                            }),
                            Ok(ProviderStreamEvent::Terminal {
                                sequence: 1,
                                result: Box::new(result),
                            }),
                        ]),
                        polls: Arc::clone(&self.stream_polls),
                    },
                ))
            }
            StreamMode::Pending(dropped) => Ok(ProviderStream::new(
                self.provider.to_owned(),
                DropTrackedPending {
                    dropped: Arc::clone(dropped),
                },
            )),
        }
    }
}

struct TerminalProviderStream {
    events: VecDeque<Result<ProviderStreamEvent, ProviderError>>,
    polls: Arc<AtomicUsize>,
}

impl Stream for TerminalProviderStream {
    type Item = Result<ProviderStreamEvent, ProviderError>;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(self.events.pop_front())
    }
}

struct DropTrackedPending {
    dropped: Arc<AtomicBool>,
}

impl Stream for DropTrackedPending {
    type Item = Result<ProviderStreamEvent, ProviderError>;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Pending
    }
}

impl Drop for DropTrackedPending {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

struct RejectingRepair {
    calls: AtomicUsize,
}

#[async_trait]
impl StructuredOutputRepairPort for RejectingRepair {
    async fn repair(&self, _request: RepairRequest<'_>) -> Result<RepairCandidate, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(provider_error("repair", ProviderErrorKind::Schema))
    }
}

#[tokio::test]
async fn selected_candidate_dispatches_only_its_exact_provider_binding()
-> Result<(), Box<dyn Error>> {
    let provider_a = Arc::new(DeterministicProvider::successful("provider-a", "model-a"));
    let provider_b = Arc::new(DeterministicProvider::successful("provider-b", "model-b"));
    let runtime = runtime(
        vec![
            candidate("candidate-a", "provider-a", "model-a", 20),
            candidate("candidate-b", "provider-b", "model-b", 10),
        ],
        vec![
            binding("candidate-a", "provider-a", "model-a", provider_a.clone()),
            binding("candidate-b", "provider-b", "model-b", provider_b.clone()),
        ],
        capabilities([
            (
                "provider-a",
                "model-a",
                &[ModelCapability::TextInput, ModelCapability::TextOutput],
            ),
            (
                "provider-b",
                "model-b",
                &[ModelCapability::TextInput, ModelCapability::TextOutput],
            ),
        ]),
        CircuitPolicy::default(),
        None,
    )?;

    let RuntimeDispatch::Dispatched {
        result: Ok(completion),
        ..
    } = runtime.complete(text_request()).await
    else {
        return Err("expected a dispatched completion".into());
    };

    assert_eq!(completion.response().provider(), "provider-a");
    assert_eq!(provider_a.complete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider_b.complete_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn half_open_probe_settles_once_and_releases_the_next_request() -> Result<(), Box<dyn Error>>
{
    let provider = Arc::new(DeterministicProvider::sequenced(
        "provider-a",
        "model-a",
        [
            Err(ProviderErrorKind::Transport),
            Ok(()),
            Err(ProviderErrorKind::Transport),
            Err(ProviderErrorKind::Transport),
            Ok(()),
        ],
    ));
    let runtime = runtime(
        vec![candidate("candidate-a", "provider-a", "model-a", 20)],
        vec![binding(
            "candidate-a",
            "provider-a",
            "model-a",
            provider.clone(),
        )],
        capabilities([(
            "provider-a",
            "model-a",
            &[ModelCapability::TextInput, ModelCapability::TextOutput],
        )]),
        CircuitPolicy::new(32, 4, Duration::from_secs(1), 1, Duration::from_nanos(1), 1)?,
        None,
    )?;

    assert!(matches!(
        runtime.complete(text_request()).await,
        RuntimeDispatch::Dispatched {
            result: Err(RuntimeError::Provider(_)),
            ..
        }
    ));
    assert!(matches!(
        runtime.complete(text_request()).await,
        RuntimeDispatch::Dispatched { result: Ok(_), .. }
    ));
    assert!(matches!(
        runtime.complete(text_request()).await,
        RuntimeDispatch::Dispatched {
            result: Err(RuntimeError::Provider(_)),
            ..
        }
    ));
    assert!(matches!(
        runtime.complete(text_request()).await,
        RuntimeDispatch::Dispatched {
            result: Err(RuntimeError::Provider(_)),
            ..
        }
    ));
    assert!(matches!(
        runtime.complete(text_request()).await,
        RuntimeDispatch::Dispatched { result: Ok(_), .. }
    ));
    assert_eq!(provider.complete_calls.load(Ordering::SeqCst), 5);
    Ok(())
}

#[tokio::test]
async fn live_stream_is_bounded_cancellable_and_emits_one_final_terminal()
-> Result<(), Box<dyn Error>> {
    let provider = Arc::new(DeterministicProvider::successful("provider-a", "model-a"));
    let active_runtime = runtime(
        vec![candidate("candidate-a", "provider-a", "model-a", 20)],
        vec![binding(
            "candidate-a",
            "provider-a",
            "model-a",
            provider.clone(),
        )],
        capabilities([(
            "provider-a",
            "model-a",
            &[
                ModelCapability::TextInput,
                ModelCapability::TextOutput,
                ModelCapability::Streaming,
            ],
        )]),
        CircuitPolicy::default(),
        None,
    )?;
    let RuntimeDispatch::Dispatched {
        result: Ok(stream), ..
    } = active_runtime.stream(text_request()).await
    else {
        return Err("expected a dispatched stream".into());
    };
    let (events, settlement) = stream.into_parts();
    tokio::task::yield_now().await;
    assert_eq!(provider.stream_polls.load(Ordering::SeqCst), 1);
    let events = events
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let settled = settlement.await;

    assert_eq!(provider.stream_polls.load(Ordering::SeqCst), 2);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.terminal().is_some())
            .count(),
        1
    );
    assert!(events.last().is_some_and(|event| {
        event
            .terminal()
            .is_some_and(|terminal| terminal.state() == StreamTerminalState::Completed)
    }));
    assert!(settled.result.is_ok());

    let dropped = Arc::new(AtomicBool::new(false));
    let pending = Arc::new(DeterministicProvider::pending(
        "provider-pending",
        "model-pending",
        Arc::clone(&dropped),
    ));
    let pending_runtime = runtime(
        vec![candidate(
            "candidate-pending",
            "provider-pending",
            "model-pending",
            20,
        )],
        vec![binding(
            "candidate-pending",
            "provider-pending",
            "model-pending",
            pending,
        )],
        capabilities([(
            "provider-pending",
            "model-pending",
            &[
                ModelCapability::TextInput,
                ModelCapability::TextOutput,
                ModelCapability::Streaming,
            ],
        )]),
        CircuitPolicy::default(),
        None,
    )?;
    let RuntimeDispatch::Dispatched {
        result: Ok(stream), ..
    } = pending_runtime.stream(text_request()).await
    else {
        return Err("expected a pending stream".into());
    };
    let (events, settlement) = stream.into_parts();
    drop(events);
    let settled = tokio::time::timeout(Duration::from_secs(1), settlement).await?;

    assert!(matches!(settled.result, Err(RuntimeError::Cancelled)));
    assert!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn strict_structured_output_never_downgrades_without_exact_evidence()
-> Result<(), Box<dyn Error>> {
    let provider = Arc::new(DeterministicProvider::successful("provider-a", "model-a"));
    let repair = Arc::new(RejectingRepair {
        calls: AtomicUsize::new(0),
    });
    let runtime = runtime(
        vec![candidate("candidate-a", "provider-a", "model-a", 20)],
        vec![binding(
            "candidate-a",
            "provider-a",
            "model-a",
            provider.clone(),
        )],
        capabilities([(
            "provider-a",
            "model-a",
            &[
                ModelCapability::TextInput,
                ModelCapability::StructuredOutput,
                ModelCapability::StrictJsonSchema,
            ],
        )]),
        CircuitPolicy::default(),
        Some(repair.clone()),
    )?;

    let outcome = runtime.complete(structured_request()).await;

    assert!(matches!(
        outcome,
        RuntimeDispatch::Dispatched {
            result: Err(RuntimeError::StructuredOutputRejected),
            ..
        }
    ));
    assert_eq!(provider.complete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(repair.calls.load(Ordering::SeqCst), 1);
    Ok(())
}

fn runtime(
    candidates: Vec<RouteCandidate>,
    bindings: Vec<ProviderBinding>,
    capabilities: ModelCapabilityRegistry,
    circuit_policy: CircuitPolicy,
    repair_port: Option<Arc<dyn StructuredOutputRepairPort>>,
) -> Result<LlmRuntime, Box<dyn Error>> {
    let stream_policy = StreamPolicy {
        limits: StreamLimits::default(),
        delivery_capacity: std::num::NonZeroUsize::new(1).ok_or("capacity")?,
    };
    let structured_policy = StructuredPolicy {
        validation_limits: JsonValidationLimits::default(),
        strategy: StrategyPolicy::new(FallbackPermission::Deny, FallbackPermission::Deny),
        repair: RepairPolicy::new(1, RawRetentionPolicy::Discard)?,
    };
    Ok(LlmRuntime::new(RuntimeDefinition {
        providers: ProviderRegistry::new(bindings)?,
        capabilities,
        routes: vec![route(candidates)?],
        circuit_policy,
        stream_policy,
        structured_policy,
        repair_port,
        application_ports: RuntimeApplicationPorts::default(),
    })?)
}

fn route(candidates: Vec<RouteCandidate>) -> Result<RouteDefinition, Box<dyn Error>> {
    let deadlines = DeadlinePolicy::new(
        Duration::from_millis(100),
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(1),
    )?;
    let policy = RoutePolicy::new(
        true,
        BTreeSet::new(),
        BTreeSet::new(),
        Residency::new("eu-only")?,
        DataClassification::Confidential,
        Duration::from_secs(1),
        RouteLimits::new(4_096, 512, Some(1_000_000), Some(1_000_000), Some(100))?,
        RetryPolicy::new(
            1,
            Duration::from_millis(1),
            Duration::from_millis(1),
            0,
            deadlines,
        )?,
        FallbackPolicy::disabled(),
        HedgePolicy::disabled(),
    )?;
    Ok(RouteDefinition::new(
        RouteId::new("route-a")?,
        RouteRevision::new(7)?,
        ObservabilityName::new("route-a-observable")?,
        policy,
        candidates,
    )?)
}

fn candidate(id: &str, provider: &str, model: &str, quality: u16) -> RouteCandidate {
    RouteCandidate::new(
        CandidateId::new(id).expect("valid candidate id"),
        ModelCapabilityKey::new(provider, model, "v1").expect("valid model key"),
        EndpointId::new("endpoint").expect("valid endpoint"),
        Region::new("eu-west-1").expect("valid region"),
        SemanticBoundary::new(
            Residency::new("eu-only").expect("valid residency"),
            DataClassification::Confidential,
            SafetyPolicyRevision::new("safety-v1").expect("valid safety revision"),
        ),
        CandidateLimits::new(8_192, 1_024, Some(2_000_000), Some(2_000_000))
            .expect("valid candidate limits"),
        CandidateRank::new(quality, Duration::from_millis(10), 10).expect("valid candidate rank"),
        true,
    )
    .expect("valid candidate")
}

fn binding(
    candidate: &str,
    provider: &str,
    model: &str,
    implementation: Arc<DeterministicProvider>,
) -> ProviderBinding {
    ProviderBinding::new(
        CandidateId::new(candidate).expect("valid candidate id"),
        ModelCapabilityKey::new(provider, model, "v1").expect("valid model key"),
        implementation,
    )
}

fn capabilities<const N: usize>(
    declarations: [(&str, &str, &[ModelCapability]); N],
) -> ModelCapabilityRegistry {
    ModelCapabilityRegistry::new(
        declarations
            .into_iter()
            .map(|(provider, model, capabilities)| {
                let evidence = capabilities
                    .iter()
                    .copied()
                    .map(|capability| {
                        (
                            capability,
                            CapabilityEvidence::new(
                                CapabilityEvidenceSource::Configured,
                                "evidence-v1",
                            )
                            .expect("valid evidence"),
                        )
                    })
                    .collect::<BTreeMap<_, _>>();
                ModelCapabilityDeclaration::new(
                    ModelCapabilityKey::new(provider, model, "v1").expect("valid model key"),
                    "registry-v1",
                    evidence,
                    BTreeSet::from(["eu-west-1".to_owned()]),
                    Some(8_192),
                    Some(1_024),
                )
                .expect("valid capability declaration")
            }),
    )
    .expect("valid capability registry")
}

fn text_request() -> LlmRequest {
    request(OutputRequest::new(OutputMode::Text))
}

fn structured_request() -> LlmRequest {
    let output = OutputRequest::new(OutputMode::Structured)
        .with_schema(None, Some(SchemaDefinition::Boolean(false)), Some(true))
        .expect("valid structured output request");
    request(output)
}

fn request(output: OutputRequest) -> LlmRequest {
    LlmRequest::new(
        LlmRequestId::new("request-a".to_owned()).expect("valid request id"),
        Route::new("route-a".to_owned(), Some(7), Vec::new(), Vec::new())
            .expect("valid route request"),
        vec![
            LlmMessage::new(
                MessageRole::User,
                vec![LlmInputPart::text("prompt".to_owned())],
            )
            .expect("valid message"),
        ],
        output,
        RequestLimits::new(5_000, 1, 0).expect("valid request limits"),
    )
    .expect("valid request")
}

fn provider_error(provider: &str, kind: ProviderErrorKind) -> ProviderError {
    ProviderError::new(provider.to_owned(), kind, RetryClass::Never)
}
