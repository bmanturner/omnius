use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{Stream, StreamExt, future::BoxFuture};
use omnius_llm_core::{
    CompletionStatus, LlmOutputPart, LlmRequest, LlmResponse, ModelCapability,
    ModelCapabilityRegistry, ProviderCompletionDiagnostics, ProviderError, ProviderErrorKind,
    RawRetentionState, RetainedRaw, RetryClass, Usage,
};
use omnius_llm_media::MediaWorkflow;
use omnius_llm_routing::{
    CandidateId, CircuitBreaker, CircuitOutcome, CircuitPolicy, CircuitProbePermit,
    FailureIsolation, FallbackReason, HedgeRejectionReason, JitterSample, LoserCancellationPolicy,
    RetryContext, RetryDecision, RouteDefinition, SelectedCandidate, admit_hedge, decide_retry,
    prove_fallback, select_candidate,
};
use omnius_llm_streaming::{
    ConsumerOwnership, DeliveryError, LlmStreamAssembler, LlmStreamEvent, LlmStreamEventData,
    StreamFailureKind, StreamInterruption, StreamLimits, StreamPartKind, StreamTerminalState,
    StreamToolCallDelta, bounded_stream,
};
use omnius_llm_structured_output::{
    PreparedStructuredOutput, RepairPolicy, StrategyPolicy, StructuredOutputRepairPort,
};
use omnius_llm_tool_runtime::{ToolAuditPort, ToolAuthorizationPort};
use omnius_validation::JsonValidationLimits;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use crate::{ProviderRegistry, ProviderRegistryError};

/// Finite live-stream construction policy.
#[derive(Clone, Copy, Debug)]
pub struct StreamPolicy {
    /// Canonical stream state bounds.
    pub limits: StreamLimits,
    /// Finite producer-to-consumer capacity.
    pub delivery_capacity: NonZeroUsize,
}

/// Structured-output admission and bounded repair policy.
#[derive(Clone, Copy, Debug)]
pub struct StructuredPolicy {
    /// Local schema and value limits.
    pub validation_limits: JsonValidationLimits,
    /// Explicit strategy downgrade policy.
    pub strategy: StrategyPolicy,
    /// Bounded repair and invalid-value retention policy.
    pub repair: RepairPolicy,
}

/// Application-owned ports needed by routes that expose tool or media capabilities.
#[derive(Default)]
pub struct RuntimeApplicationPorts {
    /// Exact tool authorization boundary.
    pub tool_authorization: Option<Arc<dyn ToolAuthorizationPort>>,
    /// Synchronous tool audit boundary.
    pub tool_audit: Option<Arc<dyn ToolAuditPort>>,
    /// Quarantine, scanner, authorization, and object-storage workflow.
    pub media_workflow: Option<Arc<MediaWorkflow>>,
}

/// Complete immutable runtime construction input.
pub struct RuntimeDefinition {
    /// Candidate-to-provider bindings.
    pub providers: ProviderRegistry,
    /// Evidence-backed exact model declarations.
    pub capabilities: ModelCapabilityRegistry,
    /// Immutable route revisions.
    pub routes: Vec<RouteDefinition>,
    /// Shared bounded circuit policy.
    pub circuit_policy: CircuitPolicy,
    /// Live stream bounds.
    pub stream_policy: StreamPolicy,
    /// Structured output policy.
    pub structured_policy: StructuredPolicy,
    /// Tool-free repair provider boundary.
    pub repair_port: Option<Arc<dyn StructuredOutputRepairPort>>,
    /// Application-owned tool and media ports.
    pub application_ports: RuntimeApplicationPorts,
}

/// Provider-neutral LLM orchestration over immutable routes and bindings.
#[derive(Clone)]
pub struct LlmRuntime {
    providers: ProviderRegistry,
    capabilities: Arc<ModelCapabilityRegistry>,
    routes: Arc<BTreeMap<(String, u64), Arc<RouteDefinition>>>,
    circuits: CircuitBreaker,
    stream_policy: StreamPolicy,
    structured_policy: StructuredPolicy,
    repair_port: Option<Arc<dyn StructuredOutputRepairPort>>,
    _application_ports: Arc<RuntimeApplicationPorts>,
}

impl LlmRuntime {
    /// Validates and constructs an immutable execution runtime.
    ///
    /// # Errors
    ///
    /// Returns a typed build failure for duplicate routes, absent provider bindings, missing exact
    /// capability evidence, or absent application ports required by the declared capabilities.
    pub fn new(definition: RuntimeDefinition) -> Result<Self, RuntimeBuildError> {
        let mut routes = BTreeMap::new();
        let mut candidate_ids = BTreeSet::new();
        let mut needs_tools = false;
        let mut needs_media = false;
        let mut needs_structured = false;
        for route in definition.routes {
            definition.providers.validate_route(&route)?;
            for candidate in route.candidates() {
                if !candidate_ids.insert(candidate.id().clone()) {
                    return Err(RuntimeBuildError::DuplicateCandidate);
                }
                let declaration = definition
                    .capabilities
                    .get(candidate.target())
                    .ok_or(RuntimeBuildError::MissingCapabilityDeclaration)?;
                needs_tools |= declaration.supports(ModelCapability::Tools);
                needs_structured |= declaration.supports(ModelCapability::StructuredOutput);
                needs_media |= [
                    ModelCapability::ImageInput,
                    ModelCapability::AudioInput,
                    ModelCapability::VideoInput,
                    ModelCapability::FileInput,
                    ModelCapability::ImageOutput,
                    ModelCapability::AudioOutput,
                    ModelCapability::VideoOutput,
                    ModelCapability::FileOutput,
                ]
                .into_iter()
                .any(|capability| declaration.supports(capability));
            }
            let key = (route.id().as_str().to_owned(), route.revision().get());
            if routes.insert(key, Arc::new(route)).is_some() {
                return Err(RuntimeBuildError::DuplicateRoute);
            }
        }
        if routes.is_empty() {
            return Err(RuntimeBuildError::NoRoutes);
        }
        if needs_tools
            && (definition.application_ports.tool_authorization.is_none()
                || definition.application_ports.tool_audit.is_none())
        {
            return Err(RuntimeBuildError::MissingToolPorts);
        }
        if needs_media && definition.application_ports.media_workflow.is_none() {
            return Err(RuntimeBuildError::MissingMediaPorts);
        }
        if needs_structured && definition.repair_port.is_none() {
            return Err(RuntimeBuildError::MissingRepairPort);
        }
        definition
            .structured_policy
            .validation_limits
            .validate()
            .map_err(|_| RuntimeBuildError::InvalidStructuredPolicy)?;
        Ok(Self {
            providers: definition.providers,
            capabilities: Arc::new(definition.capabilities),
            routes: Arc::new(routes),
            circuits: CircuitBreaker::new(definition.circuit_policy),
            stream_policy: definition.stream_policy,
            structured_policy: definition.structured_policy,
            repair_port: definition.repair_port,
            _application_ports: Arc::new(definition.application_ports),
        })
    }

    /// Executes one canonical request with deterministic selection, retry, fallback, circuit, and
    /// structured-output handling.
    pub async fn complete(&self, request: LlmRequest) -> RuntimeDispatch<RuntimeCompletion> {
        let Some(route) = self.route(&request) else {
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::RouteUnavailable);
        };
        let report = match select_candidate(
            &route,
            &request,
            &self.capabilities,
            &self.circuits,
            Instant::now(),
        ) {
            Ok(report) => report,
            Err(_) => return RuntimeDispatch::PreDispatchFailed(RuntimeError::InvalidRequest),
        };
        let Some(selected) = report.into_selected() else {
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::NoEligibleCandidate);
        };
        let selected_id = selected.candidate_id().clone();
        let prepared = match self.prepare_structured(&route, &request, &selected_id) {
            Ok(prepared) => prepared,
            Err(error) => return RuntimeDispatch::PreDispatchFailed(error),
        };
        let idempotent = request.tools().is_none() && request.tool_policy().is_none();
        let dispatched = self
            .dispatch_with_reliability(Arc::clone(&route), request, selected, idempotent)
            .await;
        match dispatched {
            CandidateDispatch::Success {
                result,
                attempts,
                hedged,
            } => {
                let finalized = self.finalize_completion(result, prepared).await;
                match finalized {
                    Ok((response, raw, diagnostics, repair_usage)) => {
                        let metering = RuntimeMetering {
                            attempts_started: attempts,
                            hedged,
                            observed_usage: Some(response.usage().clone()),
                            repair_usage,
                        };
                        RuntimeDispatch::Dispatched {
                            result: Ok(RuntimeCompletion {
                                response,
                                retained_raw: raw,
                                diagnostics,
                                metering: metering.clone(),
                            }),
                            metering,
                        }
                    }
                    Err(error) => RuntimeDispatch::Dispatched {
                        result: Err(error),
                        metering: RuntimeMetering {
                            attempts_started: attempts,
                            hedged,
                            observed_usage: None,
                            repair_usage: Vec::new().into(),
                        },
                    },
                }
            }
            CandidateDispatch::Failure { error, attempts } => RuntimeDispatch::Dispatched {
                result: Err(RuntimeError::Provider(error)),
                metering: RuntimeMetering {
                    attempts_started: attempts,
                    hedged: false,
                    observed_usage: None,
                    repair_usage: Vec::new().into(),
                },
            },
        }
    }

    /// Opens a bounded live canonical stream. Provider work is cancelled when the returned
    /// interactive consumer is dropped.
    pub async fn stream(&self, request: LlmRequest) -> RuntimeDispatch<RuntimeStream> {
        let Some(route) = self.route(&request) else {
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::RouteUnavailable);
        };
        let report = match select_candidate(
            &route,
            &request,
            &self.capabilities,
            &self.circuits,
            Instant::now(),
        ) {
            Ok(report) => report,
            Err(_) => return RuntimeDispatch::PreDispatchFailed(RuntimeError::InvalidRequest),
        };
        let Some(mut selected) = report.into_selected() else {
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::NoEligibleCandidate);
        };
        let candidate_id = selected.candidate_id().clone();
        let Some(candidate) = route.candidate(&candidate_id) else {
            selected.release_probe();
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::InvalidRuntimeState);
        };
        let Some(binding) = self.providers.get(&candidate_id) else {
            selected.release_probe();
            return RuntimeDispatch::PreDispatchFailed(RuntimeError::InvalidRuntimeState);
        };
        let provider_stream = match binding.provider.stream(request.clone()).await {
            Ok(stream) => stream,
            Err(error) => {
                let outcome = CircuitOutcome::from_provider_error(&error, FailureIsolation::Shared);
                self.record_outcome(candidate, outcome);
                selected.complete_probe(Instant::now(), outcome);
                return RuntimeDispatch::Dispatched {
                    result: Err(RuntimeError::Provider(error)),
                    metering: RuntimeMetering::one_missing(),
                };
            }
        };
        let cancellation = CancellationToken::new();
        let deadline_ms = request.limits().deadline_ms();
        let deadline = OffsetDateTime::now_utc()
            + time::Duration::milliseconds(i64::try_from(deadline_ms).unwrap_or(i64::MAX));
        let (sender, receiver) = bounded_stream(
            self.stream_policy.delivery_capacity,
            deadline,
            cancellation.clone(),
            ConsumerOwnership::Interactive,
        );
        let (settlement_sender, settlement_receiver) = oneshot::channel();
        let limits = self.stream_policy.limits;
        let request_id = request.request_id().clone();
        let candidate = candidate.clone();
        let circuits = self.circuits.clone();
        tokio::spawn(async move {
            let settlement = translate_provider_stream(
                provider_stream,
                request_id,
                limits,
                sender,
                cancellation,
                &candidate,
                &circuits,
                &mut selected,
            )
            .await;
            let _ = settlement_sender.send(settlement);
        });
        let events = futures::stream::unfold(receiver, |mut receiver| async move {
            match receiver.recv().await {
                Ok(Some(event)) => Some((Ok(event), receiver)),
                Ok(None) => None,
                Err(error) => Some((Err(RuntimeError::Delivery(error)), receiver)),
            }
        });
        RuntimeDispatch::Dispatched {
            result: Ok(RuntimeStream {
                events: RuntimeEventStream {
                    inner: Box::pin(events),
                },
                settlement: Box::pin(async move {
                    settlement_receiver
                        .await
                        .unwrap_or_else(|_| RuntimeStreamSettlement {
                            result: Err(RuntimeError::InvalidRuntimeState),
                            metering: RuntimeMetering::one_missing(),
                            retained_raw_state: None,
                        })
                }),
            }),
            metering: RuntimeMetering::one_missing(),
        }
    }

    fn route(&self, request: &LlmRequest) -> Option<Arc<RouteDefinition>> {
        let revision = request.route().revision()?;
        self.routes
            .get(&(request.route().id().to_owned(), revision))
            .cloned()
    }

    fn prepare_structured(
        &self,
        route: &RouteDefinition,
        request: &LlmRequest,
        candidate_id: &CandidateId,
    ) -> Result<Option<PreparedStructuredOutput>, RuntimeError> {
        if request.output().mode() != omnius_llm_core::OutputMode::Structured {
            return Ok(None);
        }
        let candidate = route
            .candidate(candidate_id)
            .ok_or(RuntimeError::InvalidRuntimeState)?;
        let declaration = self
            .capabilities
            .get(candidate.target())
            .ok_or(RuntimeError::InvalidRuntimeState)?;
        PreparedStructuredOutput::prepare(
            request.output(),
            declaration,
            self.structured_policy.strategy,
            self.structured_policy.validation_limits,
        )
        .map(Some)
        .map_err(|_| RuntimeError::StructuredOutputRejected)
    }

    async fn finalize_completion(
        &self,
        result: omnius_llm_core::ProviderCompletionResult,
        prepared: Option<PreparedStructuredOutput>,
    ) -> Result<
        (
            LlmResponse,
            RetainedRaw,
            ProviderCompletionDiagnostics,
            Arc<[Usage]>,
        ),
        RuntimeError,
    > {
        let (mut response, raw, diagnostics) = result.into_parts();
        let Some(prepared) = prepared else {
            return Ok((response, raw, diagnostics, Arc::from([])));
        };
        let structured = response
            .output()
            .iter()
            .find_map(|part| match part {
                LlmOutputPart::Structured(part) => Some(part),
                _ => None,
            })
            .ok_or(RuntimeError::StructuredOutputRejected)?;
        let repair_port = self
            .repair_port
            .as_deref()
            .ok_or(RuntimeError::MissingRequiredPort)?;
        let validated = prepared
            .validate_and_repair(
                structured.id().to_owned(),
                structured.value().clone(),
                self.structured_policy.repair,
                repair_port,
            )
            .await
            .map_err(|_| RuntimeError::StructuredOutputRejected)?;
        let (part, repair_metering, _) = validated.into_parts();
        let usage = repair_metering
            .iter()
            .map(|metering| metering.usage().clone())
            .collect::<Vec<_>>()
            .into();
        response = response
            .replace_output_part(LlmOutputPart::Structured(part))
            .map_err(|_| RuntimeError::StructuredOutputRejected)?;
        Ok((response, raw, diagnostics, usage))
    }

    async fn dispatch_with_reliability(
        &self,
        route: Arc<RouteDefinition>,
        request: LlmRequest,
        selected: SelectedCandidate,
        idempotent: bool,
    ) -> CandidateDispatch {
        if let Ok(admission) = admit_hedge(route.policy().hedge(), &request, idempotent) {
            if admission.loser_cancellation() != LoserCancellationPolicy::AbortProviderRequest {
                return CandidateDispatch::Failure {
                    error: ProviderError::new(
                        "runtime".to_owned(),
                        ProviderErrorKind::Unsupported,
                        RetryClass::Never,
                    ),
                    attempts: 0,
                };
            }
            if let Some((fallback_id, fallback_probe)) = self.fallback_candidate(
                &route,
                &request,
                selected.candidate_id(),
                FallbackReason::DeadlineRisk,
            ) {
                let primary_id = selected.candidate_id().clone();
                let primary = self.run_candidate(
                    Arc::clone(&route),
                    request.clone(),
                    primary_id,
                    ProbeOwnership::Selected(selected),
                    idempotent,
                );
                let secondary = async {
                    tokio::time::sleep(admission.delay()).await;
                    self.run_candidate(
                        Arc::clone(&route),
                        request,
                        fallback_id,
                        ProbeOwnership::Direct(fallback_probe),
                        idempotent,
                    )
                    .await
                };
                tokio::pin!(primary);
                tokio::pin!(secondary);
                return tokio::select! {
                    first = &mut primary => match first {
                        CandidateDispatch::Success { result, attempts, .. } => CandidateDispatch::Success { result, attempts, hedged: true },
                        CandidateDispatch::Failure { attempts: first_attempts, .. } => match secondary.await {
                            CandidateDispatch::Success { result, attempts, .. } => CandidateDispatch::Success { result, attempts: attempts.saturating_add(first_attempts), hedged: true },
                            CandidateDispatch::Failure { error, attempts } => CandidateDispatch::Failure { error, attempts: attempts.saturating_add(first_attempts) },
                        },
                    },
                    second = &mut secondary => match second {
                        CandidateDispatch::Success { result, attempts, .. } => CandidateDispatch::Success { result, attempts, hedged: true },
                        CandidateDispatch::Failure { attempts: second_attempts, .. } => match primary.await {
                            CandidateDispatch::Success { result, attempts, .. } => CandidateDispatch::Success { result, attempts: attempts.saturating_add(second_attempts), hedged: true },
                            CandidateDispatch::Failure { error, attempts } => CandidateDispatch::Failure { error, attempts: attempts.saturating_add(second_attempts) },
                        },
                    },
                };
            }
        } else if !matches!(
            admit_hedge(route.policy().hedge(), &request, idempotent),
            Err(HedgeRejectionReason::Disabled
                | HedgeRejectionReason::ToolRequest
                | HedgeRejectionReason::NonIdempotent)
        ) {
            return CandidateDispatch::Failure {
                error: ProviderError::new(
                    "runtime".to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                ),
                attempts: 0,
            };
        }
        let primary_id = selected.candidate_id().clone();
        let primary = self
            .run_candidate(
                Arc::clone(&route),
                request.clone(),
                primary_id.clone(),
                ProbeOwnership::Selected(selected),
                idempotent,
            )
            .await;
        let CandidateDispatch::Failure { error, attempts } = primary else {
            return primary;
        };
        let reason = if error.kind() == ProviderErrorKind::Timeout {
            FallbackReason::DeadlineRisk
        } else {
            FallbackReason::RetryExhausted
        };
        let Some((fallback_id, fallback_probe)) =
            self.fallback_candidate(&route, &request, &primary_id, reason)
        else {
            return CandidateDispatch::Failure { error, attempts };
        };
        match self
            .run_candidate(
                route,
                request,
                fallback_id,
                ProbeOwnership::Direct(fallback_probe),
                idempotent,
            )
            .await
        {
            CandidateDispatch::Success {
                result,
                attempts: fallback_attempts,
                ..
            } => CandidateDispatch::Success {
                result,
                attempts: attempts.saturating_add(fallback_attempts),
                hedged: false,
            },
            CandidateDispatch::Failure {
                error,
                attempts: fallback_attempts,
            } => CandidateDispatch::Failure {
                error,
                attempts: attempts.saturating_add(fallback_attempts),
            },
        }
    }

    fn fallback_candidate(
        &self,
        route: &RouteDefinition,
        request: &LlmRequest,
        from: &CandidateId,
        reason: FallbackReason,
    ) -> Option<(CandidateId, CircuitProbePermit)> {
        route
            .fallback_policy()
            .rules()
            .iter()
            .filter(|rule| rule.from() == from)
            .find_map(|rule| {
                prove_fallback(
                    route,
                    request,
                    &self.capabilities,
                    from,
                    rule.to(),
                    reason,
                    true,
                )
                .ok()?;
                let candidate = route.candidate(rule.to())?;
                let permit = self
                    .circuits
                    .try_acquire_candidate(candidate.circuit_scopes(), Instant::now())?;
                Some((rule.to().clone(), permit))
            })
    }

    async fn run_candidate(
        &self,
        route: Arc<RouteDefinition>,
        request: LlmRequest,
        candidate_id: CandidateId,
        mut probe: ProbeOwnership,
        idempotent: bool,
    ) -> CandidateDispatch {
        let Some(candidate) = route.candidate(&candidate_id) else {
            probe.release();
            return CandidateDispatch::Failure {
                error: ProviderError::new(
                    "runtime".to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                ),
                attempts: 0,
            };
        };
        let Some(binding) = self.providers.get(&candidate_id) else {
            probe.release();
            return CandidateDispatch::Failure {
                error: ProviderError::new(
                    "runtime".to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                ),
                attempts: 0,
            };
        };
        let started = Instant::now();
        let retry = route.policy().retry();
        let full_deadline = retry
            .deadlines()
            .total()
            .min(Duration::from_millis(request.limits().deadline_ms()));
        let mut attempts = 0u32;
        loop {
            attempts = attempts.saturating_add(1);
            let remaining = full_deadline.saturating_sub(started.elapsed());
            let result = if remaining.is_zero() {
                Err(ProviderError::new(
                    binding.target.provider().to_owned(),
                    ProviderErrorKind::Timeout,
                    RetryClass::Never,
                ))
            } else {
                match tokio::time::timeout(remaining, binding.provider.complete(request.clone()))
                    .await
                {
                    Ok(result) => result,
                    Err(_) => Err(ProviderError::new(
                        binding.target.provider().to_owned(),
                        ProviderErrorKind::Timeout,
                        RetryClass::Safe,
                    )),
                }
            };
            match result {
                Ok(result) => {
                    self.record_outcome(candidate, CircuitOutcome::Success);
                    probe.complete(CircuitOutcome::Success);
                    return CandidateDispatch::Success {
                        result,
                        attempts,
                        hedged: false,
                    };
                }
                Err(error) => {
                    let outcome =
                        CircuitOutcome::from_provider_error(&error, FailureIsolation::Shared);
                    self.record_outcome(candidate, outcome);
                    probe.complete(outcome);
                    let jitter = JitterSample::new(5_000).unwrap_or_else(|_| unreachable!());
                    let context = RetryContext::for_request(
                        retry,
                        &request,
                        attempts,
                        started.elapsed(),
                        idempotent,
                        false,
                        jitter,
                    );
                    match decide_retry(retry, &error, context) {
                        RetryDecision::RetryAfter { delay } => tokio::time::sleep(delay).await,
                        RetryDecision::Stop(_) => {
                            return CandidateDispatch::Failure { error, attempts };
                        }
                    }
                }
            }
        }
    }

    fn record_outcome(
        &self,
        candidate: &omnius_llm_routing::RouteCandidate,
        outcome: CircuitOutcome,
    ) {
        let observed_at = Instant::now();
        for scope in candidate.circuit_scopes() {
            let _ = self.circuits.record(scope.clone(), observed_at, outcome);
        }
    }
}

enum ProbeOwnership {
    Selected(SelectedCandidate),
    Direct(CircuitProbePermit),
}

impl ProbeOwnership {
    fn complete(&mut self, outcome: CircuitOutcome) {
        match self {
            Self::Selected(selected) => selected.complete_probe(Instant::now(), outcome),
            Self::Direct(permit) => permit.complete(Instant::now(), outcome),
        }
    }

    fn release(&mut self) {
        match self {
            Self::Selected(selected) => selected.release_probe(),
            Self::Direct(permit) => permit.release(),
        }
    }
}

enum CandidateDispatch {
    Success {
        result: omnius_llm_core::ProviderCompletionResult,
        attempts: u32,
        hedged: bool,
    },
    Failure {
        error: ProviderError,
        attempts: u32,
    },
}

async fn translate_provider_stream(
    mut provider_stream: omnius_llm_core::ProviderStream,
    request_id: omnius_llm_core::LlmRequestId,
    limits: StreamLimits,
    sender: omnius_llm_streaming::StreamSender,
    cancellation: CancellationToken,
    candidate: &omnius_llm_routing::RouteCandidate,
    circuits: &CircuitBreaker,
    selected: &mut SelectedCandidate,
) -> RuntimeStreamSettlement {
    let mut assembler = LlmStreamAssembler::new(request_id, limits);
    if send_event(
        &sender,
        assembler.emit(LlmStreamEventData::ResponseStart {
            response_id: "stream".to_owned(),
        }),
    )
    .await
    .is_err()
    {
        selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
        return RuntimeStreamSettlement::failed(RuntimeError::Cancelled);
    }
    let mut expected_sequence = 0u64;
    let mut text_started = false;
    let mut visible = false;
    let mut tool_parts = BTreeSet::new();
    loop {
        let next = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
                return RuntimeStreamSettlement::failed(RuntimeError::Cancelled);
            }
            next = provider_stream.next() => next,
        };
        let Some(next) = next else {
            let terminal =
                terminal_for_interruption(&mut assembler, visible, StreamInterruption::Protocol);
            let _ = send_event(&sender, terminal).await;
            selected.complete_probe(Instant::now(), CircuitOutcome::ProviderFailure);
            record_candidate_outcome(circuits, candidate, CircuitOutcome::ProviderFailure);
            return RuntimeStreamSettlement::failed(RuntimeError::InvalidProviderStream);
        };
        let event = match next {
            Ok(event) if event.sequence() == expected_sequence => event,
            Ok(_) => {
                let terminal = terminal_for_interruption(
                    &mut assembler,
                    visible,
                    StreamInterruption::Protocol,
                );
                let _ = send_event(&sender, terminal).await;
                selected.complete_probe(Instant::now(), CircuitOutcome::ProviderFailure);
                record_candidate_outcome(circuits, candidate, CircuitOutcome::ProviderFailure);
                return RuntimeStreamSettlement::failed(RuntimeError::InvalidProviderStream);
            }
            Err(error) => {
                let outcome = CircuitOutcome::from_provider_error(&error, FailureIsolation::Shared);
                let interruption = if error.kind() == ProviderErrorKind::Transport {
                    StreamInterruption::Transport
                } else {
                    StreamInterruption::Protocol
                };
                let terminal = terminal_for_interruption(&mut assembler, visible, interruption);
                let _ = send_event(&sender, terminal).await;
                selected.complete_probe(Instant::now(), outcome);
                record_candidate_outcome(circuits, candidate, outcome);
                return RuntimeStreamSettlement::failed(RuntimeError::Provider(error));
            }
        };
        expected_sequence = expected_sequence.saturating_add(1);
        let translated = match event {
            omnius_llm_core::ProviderStreamEvent::TextDelta { text, .. } => {
                let mut events = Vec::with_capacity(2);
                if !text_started {
                    events.push(assembler.emit(LlmStreamEventData::PartStart {
                        part_id: "assistant-text".to_owned(),
                        kind: StreamPartKind::Text,
                    }));
                    text_started = true;
                }
                visible = true;
                events.push(assembler.emit(LlmStreamEventData::TextDelta {
                    part_id: "assistant-text".to_owned(),
                    text,
                }));
                events
            }
            omnius_llm_core::ProviderStreamEvent::ToolCallDelta {
                correlation_id,
                delta,
                ..
            } => {
                let part_id = format!("tool-{correlation_id}");
                let delta = match delta {
                    omnius_llm_core::ProviderToolCallDelta::Name(name) => {
                        StreamToolCallDelta::Name(name)
                    }
                    omnius_llm_core::ProviderToolCallDelta::ArgumentsFragment(value) => {
                        StreamToolCallDelta::ArgumentsFragment(value)
                    }
                };
                let mut events = Vec::with_capacity(2);
                if tool_parts.insert(part_id.clone()) {
                    events.push(assembler.emit(LlmStreamEventData::PartStart {
                        part_id: part_id.clone(),
                        kind: StreamPartKind::ToolCall,
                    }));
                }
                events.push(assembler.emit(LlmStreamEventData::ToolCallDelta {
                    part_id,
                    correlation_id,
                    delta,
                }));
                events
            }
            omnius_llm_core::ProviderStreamEvent::ToolCall {
                correlation_id,
                call_id,
                name,
                arguments,
                ..
            } => {
                let part_id = format!("tool-{correlation_id}");
                let part = omnius_llm_core::ToolCallOutputPart::new(
                    part_id.clone(),
                    call_id,
                    name,
                    arguments,
                );
                match part {
                    Ok(part) => {
                        let mut events = Vec::with_capacity(3);
                        if tool_parts.insert(part_id.clone()) {
                            events.push(assembler.emit(LlmStreamEventData::PartStart {
                                part_id: part_id.clone(),
                                kind: StreamPartKind::ToolCall,
                            }));
                        }
                        events.push(assembler.emit(LlmStreamEventData::ToolCallComplete {
                            correlation_id,
                            part,
                        }));
                        events.push(assembler.emit(LlmStreamEventData::PartComplete { part_id }));
                        events
                    }
                    Err(_) => vec![Err(
                        omnius_llm_streaming::StreamInvariantError::InvalidIdentity,
                    )],
                }
            }
            omnius_llm_core::ProviderStreamEvent::Reasoning {
                sequence,
                representation,
                data,
                ..
            } => {
                let part_id = format!("reasoning-{sequence}");
                match omnius_llm_core::ReasoningOutputPart::new(
                    part_id.clone(),
                    representation,
                    data,
                ) {
                    Ok(part) => vec![
                        assembler.emit(LlmStreamEventData::PartStart {
                            part_id: part_id.clone(),
                            kind: StreamPartKind::SafeReasoning,
                        }),
                        assembler.emit(LlmStreamEventData::SafeReasoning(part)),
                        assembler.emit(LlmStreamEventData::PartComplete { part_id }),
                    ],
                    Err(_) => vec![Err(
                        omnius_llm_streaming::StreamInvariantError::InvalidIdentity,
                    )],
                }
            }
            omnius_llm_core::ProviderStreamEvent::PrivateReasoningDelta { .. }
            | omnius_llm_core::ProviderStreamEvent::PrivateReasoning { .. } => {
                vec![assembler.emit(LlmStreamEventData::Warning(
                    omnius_llm_streaming::StreamWarningCode::PrivateReasoningOmitted,
                ))]
            }
            omnius_llm_core::ProviderStreamEvent::UnknownProviderItem { .. } => {
                vec![assembler.emit(LlmStreamEventData::Warning(
                    omnius_llm_streaming::StreamWarningCode::ProviderExtensionOmitted,
                ))]
            }
            omnius_llm_core::ProviderStreamEvent::Terminal { result, .. } => {
                if text_started
                    && send_event(
                        &sender,
                        assembler.emit(LlmStreamEventData::PartComplete {
                            part_id: "assistant-text".to_owned(),
                        }),
                    )
                    .await
                    .is_err()
                {
                    selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
                    return RuntimeStreamSettlement::failed(RuntimeError::Cancelled);
                }
                let usage = result.response().usage().clone();
                if send_event(
                    &sender,
                    assembler.emit(LlmStreamEventData::Usage(usage.clone())),
                )
                .await
                .is_err()
                {
                    selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
                    return RuntimeStreamSettlement::failed(RuntimeError::Cancelled);
                }
                let state = match result.response().status() {
                    CompletionStatus::Completed => StreamTerminalState::Completed,
                    CompletionStatus::Refused => StreamTerminalState::ProviderRefused,
                    CompletionStatus::Cancelled => StreamTerminalState::Cancelled,
                    CompletionStatus::Partial if visible => {
                        StreamTerminalState::PartialInterrupted(StreamInterruption::Protocol)
                    }
                    CompletionStatus::Partial | CompletionStatus::Failed => {
                        StreamTerminalState::Failed(StreamFailureKind::Protocol)
                    }
                };
                if send_event(&sender, assembler.terminate(state))
                    .await
                    .is_err()
                {
                    selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
                    return RuntimeStreamSettlement::failed(RuntimeError::Cancelled);
                }
                selected.complete_probe(Instant::now(), CircuitOutcome::Success);
                record_candidate_outcome(circuits, candidate, CircuitOutcome::Success);
                return RuntimeStreamSettlement {
                    result: Ok(()),
                    metering: RuntimeMetering {
                        attempts_started: 1,
                        hedged: false,
                        observed_usage: Some(usage),
                        repair_usage: Arc::from([]),
                    },
                    retained_raw_state: Some(result.retained_raw().state()),
                };
            }
        };
        for event in translated {
            if send_event(&sender, event).await.is_err() {
                selected.complete_probe(Instant::now(), CircuitOutcome::CallerFailure);
                return RuntimeStreamSettlement::failed(RuntimeError::InvalidProviderStream);
            }
        }
    }
}

async fn send_event(
    sender: &omnius_llm_streaming::StreamSender,
    event: Result<LlmStreamEvent, omnius_llm_streaming::StreamInvariantError>,
) -> Result<(), RuntimeError> {
    let event = event.map_err(|_| RuntimeError::InvalidProviderStream)?;
    sender.send(event).await.map_err(RuntimeError::Delivery)
}

fn terminal_for_interruption(
    assembler: &mut LlmStreamAssembler,
    visible: bool,
    interruption: StreamInterruption,
) -> Result<LlmStreamEvent, omnius_llm_streaming::StreamInvariantError> {
    if visible {
        assembler.terminate(StreamTerminalState::PartialInterrupted(interruption))
    } else {
        assembler.terminate(StreamTerminalState::Failed(StreamFailureKind::Protocol))
    }
}

fn record_candidate_outcome(
    circuits: &CircuitBreaker,
    candidate: &omnius_llm_routing::RouteCandidate,
    outcome: CircuitOutcome,
) {
    let now = Instant::now();
    for scope in candidate.circuit_scopes() {
        let _ = circuits.record(scope.clone(), now, outcome);
    }
}

/// Dispatch classification preserving the pre-dispatch/release boundary.
pub enum RuntimeDispatch<T> {
    /// No provider work was started.
    PreDispatchFailed(RuntimeError),
    /// Provider work was started; metering must be committed even when the result failed.
    Dispatched {
        /// Terminal result.
        result: Result<T, RuntimeError>,
        /// Observable metering evidence.
        metering: RuntimeMetering,
    },
}

/// Successful completion with retained provider and repair evidence.
pub struct RuntimeCompletion {
    response: LlmResponse,
    retained_raw: RetainedRaw,
    diagnostics: ProviderCompletionDiagnostics,
    metering: RuntimeMetering,
}

impl RuntimeCompletion {
    /// Borrows the canonical response.
    #[must_use]
    pub const fn response(&self) -> &LlmResponse {
        &self.response
    }
    /// Consumes the completion into the HTTP-safe canonical response.
    #[must_use]
    pub fn into_response(self) -> LlmResponse {
        self.response
    }
    /// Borrows policy-controlled raw state.
    #[must_use]
    pub const fn retained_raw(&self) -> &RetainedRaw {
        &self.retained_raw
    }
    /// Borrows redacted provider diagnostics.
    #[must_use]
    pub const fn diagnostics(&self) -> &ProviderCompletionDiagnostics {
        &self.diagnostics
    }
    /// Borrows attempt and repair metering.
    #[must_use]
    pub const fn metering(&self) -> &RuntimeMetering {
        &self.metering
    }
}

/// Metering evidence retained across retry, fallback, hedge, and repair.
#[derive(Clone)]
pub struct RuntimeMetering {
    attempts_started: u32,
    hedged: bool,
    observed_usage: Option<Usage>,
    repair_usage: Arc<[Usage]>,
}

impl RuntimeMetering {
    fn one_missing() -> Self {
        Self {
            attempts_started: 1,
            hedged: false,
            observed_usage: None,
            repair_usage: Arc::from([]),
        }
    }
    /// Returns every provider attempt started, including retry/fallback attempts.
    #[must_use]
    pub const fn attempts_started(&self) -> u32 {
        self.attempts_started
    }
    /// Reports whether duplicate hedge work was admitted.
    #[must_use]
    pub const fn hedged(&self) -> bool {
        self.hedged
    }
    /// Borrows final provider usage when supplied.
    #[must_use]
    pub const fn observed_usage(&self) -> Option<&Usage> {
        self.observed_usage.as_ref()
    }
    /// Borrows separately attributed structured repair usage.
    #[must_use]
    pub fn repair_usage(&self) -> &[Usage] {
        &self.repair_usage
    }
    /// Returns whether observed usage is complete enough for exact accounting.
    #[must_use]
    pub fn is_exact(&self) -> bool {
        self.attempts_started == 1
            && !self.hedged
            && self.repair_usage.is_empty()
            && self.observed_usage.is_some()
    }
}

/// Live stream plus terminal metering/retention settlement.
pub struct RuntimeStream {
    events: RuntimeEventStream,
    settlement: BoxFuture<'static, RuntimeStreamSettlement>,
}

impl RuntimeStream {
    /// Consumes the stream into its event and settlement halves.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        RuntimeEventStream,
        BoxFuture<'static, RuntimeStreamSettlement>,
    ) {
        (self.events, self.settlement)
    }
}

/// Live canonical event receiver.
pub struct RuntimeEventStream {
    inner: Pin<Box<dyn Stream<Item = Result<LlmStreamEvent, RuntimeError>> + Send + 'static>>,
}

impl Stream for RuntimeEventStream {
    type Item = Result<LlmStreamEvent, RuntimeError>;
    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().inner.as_mut().poll_next(context)
    }
}

/// Terminal stream accounting and retention evidence.
pub struct RuntimeStreamSettlement {
    /// Producer terminal result.
    pub result: Result<(), RuntimeError>,
    /// Attempt and provider usage evidence.
    pub metering: RuntimeMetering,
    /// Policy-controlled terminal raw retention state.
    pub retained_raw_state: Option<RawRetentionState>,
}

impl RuntimeStreamSettlement {
    fn failed(error: RuntimeError) -> Self {
        Self {
            result: Err(error),
            metering: RuntimeMetering::one_missing(),
            retained_raw_state: None,
        }
    }
}

/// Runtime construction failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RuntimeBuildError {
    /// No route was supplied.
    #[error("LLM runtime has no route definitions")]
    NoRoutes,
    /// A route revision appears more than once.
    #[error("LLM route revision is duplicated")]
    DuplicateRoute,
    /// Candidate identities must be globally unique for immutable provider bindings.
    #[error("LLM candidate identity is duplicated across routes")]
    DuplicateCandidate,
    /// A candidate lacks exact capability evidence.
    #[error("LLM candidate has no capability declaration")]
    MissingCapabilityDeclaration,
    /// A tools-capable route lacks authorization or audit.
    #[error("LLM tools route requires authorization and audit ports")]
    MissingToolPorts,
    /// A media-capable route lacks the real media workflow.
    #[error("LLM media route requires a media workflow")]
    MissingMediaPorts,
    /// A structured route lacks a repair provider boundary.
    #[error("LLM structured route requires a repair port")]
    MissingRepairPort,
    /// Structured validation bounds are invalid.
    #[error("LLM structured-output policy is invalid")]
    InvalidStructuredPolicy,
    /// Provider registry validation failed.
    #[error(transparent)]
    ProviderRegistry(#[from] ProviderRegistryError),
}

/// Redacted execution failure.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The exact route revision is absent.
    #[error("LLM route is unavailable")]
    RouteUnavailable,
    /// The request does not match the selected immutable route.
    #[error("LLM request is invalid")]
    InvalidRequest,
    /// Hard policy removed every candidate.
    #[error("no eligible LLM candidate is available")]
    NoEligibleCandidate,
    /// Runtime construction invariants were violated.
    #[error("LLM runtime state is invalid")]
    InvalidRuntimeState,
    /// A required typed application port is absent.
    #[error("LLM runtime required port is absent")]
    MissingRequiredPort,
    /// Structured output could not be admitted or locally validated.
    #[error("LLM structured output was rejected")]
    StructuredOutputRejected,
    /// Provider stream ordering or canonical translation failed.
    #[error("LLM provider stream is invalid")]
    InvalidProviderStream,
    /// Interactive work was cancelled.
    #[error("LLM execution was cancelled")]
    Cancelled,
    /// Provider operation failed with a redacted typed error.
    #[error(transparent)]
    Provider(#[from] ProviderError),
    /// Bounded stream delivery failed.
    #[error(transparent)]
    Delivery(#[from] DeliveryError),
}
