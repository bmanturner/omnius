use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures::StreamExt;
use omnius_config::ExposeSecret;
use omnius_llm_core::{
    LlmOutputPart, LlmProvider, LlmRequest, LlmRequestId, ProviderCompletionDiagnostics,
    ProviderCompletionResult, ProviderError, ProviderErrorKind, ProviderStream,
    ProviderStreamEvent, ProviderToolCallDelta, RawRetentionPolicy, ReasoningRepresentation,
    RetainedRaw, RetryClass,
};
use rig_core::{
    completion::{CompletionError, CompletionModel, CompletionRequest, CompletionResponse},
    message::ReasoningContent,
    providers::{anthropic, gemini, openai, openrouter},
    streaming::{StreamedAssistantContent, StreamingCompletionResponse, ToolCallDeltaContent},
};
use time::{OffsetDateTime, format_description::well_known::Rfc2822};
use tokio::time::Instant;

use crate::{
    DirectProvider, RigProviderConfig, RigProviderDiagnostics,
    config::RigProviderConfigParts,
    http::{RigHttpClient, RigHttpFailure, failure_from_http_error, with_response_body_limit},
    normalize::normalize_response,
    raw::serialized_len,
    request::{PreparedRequest, prepare_request},
};

const STREAM_BUFFER_CAPACITY: usize = 32;

#[async_trait]
trait Driver: Send + Sync {
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, CompletionError>;

    async fn stream(
        &self,
        request: CompletionRequest,
    ) -> Result<StreamingCompletionResponse, CompletionError>;
}

struct ModelDriver<M> {
    model: M,
}

impl<M> ModelDriver<M> {
    const fn new(model: M) -> Self {
        Self { model }
    }
}

#[async_trait]
impl<M> Driver for ModelDriver<M>
where
    M: CompletionModel + Send + Sync + 'static,
{
    async fn complete(
        &self,
        request: CompletionRequest,
    ) -> Result<CompletionResponse, CompletionError> {
        self.model.completion(request).await
    }

    async fn stream(
        &self,
        request: CompletionRequest,
    ) -> Result<StreamingCompletionResponse, CompletionError> {
        self.model.stream(request).await
    }
}

/// Non-generic direct provider whose concrete Rig model remains private.
pub struct RigProvider {
    provider: DirectProvider,
    model: String,
    raw_retention: RawRetentionPolicy,
    driver: Arc<dyn Driver>,
}

impl RigProvider {
    /// Constructs the selected direct API client and completion model.
    ///
    /// # Errors
    ///
    /// Returns a redacted schema error when Rig rejects client construction.
    pub fn new(config: RigProviderConfig) -> Result<Self, ProviderError> {
        let RigProviderConfigParts {
            provider,
            model,
            api_key,
            outbound_http,
            raw_retention,
        } = config.into_parts();
        let driver = build_driver(
            provider,
            &model,
            api_key.expose_secret(),
            RigHttpClient::new(outbound_http),
        )?;
        Ok(Self {
            provider,
            model,
            raw_retention,
            driver,
        })
    }

    /// Validates that a canonical request is faithfully representable without sending it.
    ///
    /// # Errors
    ///
    /// Returns a typed unsupported, schema, or safety error for the first rejected semantic.
    pub fn validate_request(&self, request: &LlmRequest) -> Result<(), ProviderError> {
        prepare_request(self.provider, &self.model, request).map(|_| ())
    }

    /// Executes one canonical non-streaming completion.
    ///
    /// # Errors
    ///
    /// Returns typed unsupported, provider, transport, timeout, throttling,
    /// safety, or schema errors. Provider bodies are retained only according to
    /// the configured raw-retention policy.
    pub async fn complete(
        &self,
        request: &LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        let timeout = Duration::from_millis(request.limits().deadline_ms());
        let deadline = Instant::now() + timeout;
        tokio::time::timeout(timeout, self.complete_before_deadline(request, deadline))
            .await
            .map_err(|_| {
                ProviderError::new(
                    self.provider.as_str().to_owned(),
                    ProviderErrorKind::Timeout,
                    RetryClass::Safe,
                )
            })?
    }

    async fn complete_before_deadline(
        &self,
        request: &LlmRequest,
        deadline: Instant,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        let prepared = prepare_request(self.provider, &self.model, request);
        ensure_deadline(self.provider, deadline)?;
        let PreparedRequest {
            request: rig_request,
            max_tool_calls,
            max_output_bytes,
            tool_capabilities,
        } = prepared?;

        let completion =
            with_response_body_limit(max_output_bytes, self.driver.complete(rig_request)).await;
        ensure_deadline(self.provider, deadline)?;
        let completion = completion
            .map_err(|error| map_completion_error(self.provider, self.raw_retention, &error))?;

        let normalized = normalize_response(
            self.provider,
            &self.model,
            request.request_id(),
            &tool_capabilities,
            self.raw_retention,
            OffsetDateTime::now_utc(),
            completion,
        );
        ensure_deadline(self.provider, deadline)?;
        let normalized = normalized?;

        let tool_calls = normalized
            .response
            .output()
            .iter()
            .filter(|part| matches!(part, LlmOutputPart::ToolCall(_)))
            .count();
        if tool_calls > usize::try_from(max_tool_calls).unwrap_or(usize::MAX)
            || max_output_bytes.is_some_and(|limit| serialized_len(&normalized.response) > limit)
        {
            return Err(ProviderError::new(
                self.provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
            .with_transport_metadata(None, None, None, normalized.raw));
        }
        ensure_deadline(self.provider, deadline)?;

        let diagnostics = ProviderCompletionDiagnostics::new(
            self.provider.as_str().to_owned(),
            normalized.raw.state(),
            normalized.unmodeled_parts,
            normalized.private_reasoning_blocks,
        );
        let result =
            ProviderCompletionResult::new(normalized.response, normalized.raw, diagnostics);
        ensure_deadline(self.provider, deadline)?;
        Ok(result)
    }

    /// Opens one bounded non-blocking completion stream.
    ///
    /// # Errors
    ///
    /// Returns a typed error when request preparation or provider stream connection fails.
    pub async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        let timeout = Duration::from_millis(request.limits().deadline_ms());
        let deadline = Instant::now() + timeout;
        tokio::time::timeout(timeout, self.open_stream_before_deadline(request, deadline))
            .await
            .map_err(|_| {
                ProviderError::new(
                    self.provider.as_str().to_owned(),
                    ProviderErrorKind::Timeout,
                    RetryClass::Safe,
                )
            })?
    }

    async fn open_stream_before_deadline(
        &self,
        request: LlmRequest,
        deadline: Instant,
    ) -> Result<ProviderStream, ProviderError> {
        let prepared = prepare_request(self.provider, &self.model, &request);
        ensure_deadline(self.provider, deadline)?;
        let PreparedRequest {
            request: rig_request,
            max_tool_calls,
            max_output_bytes,
            tool_capabilities,
        } = prepared?;
        let request_id = request.request_id().clone();

        let stream =
            with_response_body_limit(max_output_bytes, self.driver.stream(rig_request)).await;
        ensure_deadline(self.provider, deadline)?;
        let stream = stream
            .map_err(|error| map_completion_error(self.provider, self.raw_retention, &error))?;

        let (sender, receiver) = tokio::sync::mpsc::channel(STREAM_BUFFER_CAPACITY);
        let (terminal_error_sender, terminal_error_receiver) = tokio::sync::oneshot::channel();
        let drain = StreamDrain {
            provider: self.provider,
            model: self.model.clone(),
            raw_retention: self.raw_retention,
            request_id,
            max_tool_calls,
            max_output_bytes,
            tool_capabilities,
            deadline,
            stream,
            sender,
            terminal_error_sender: Some(terminal_error_sender),
        };
        tokio::spawn(with_response_body_limit(
            max_output_bytes,
            drain_provider_stream(drain),
        ));
        let receiver = ProviderStreamReceiver {
            receiver,
            terminal_error_receiver: Some(terminal_error_receiver),
        };
        let stream = futures::stream::unfold(receiver, receive_provider_item);
        Ok(ProviderStream::new(
            self.provider.as_str().to_owned(),
            stream,
        ))
    }

    /// Returns non-secret provider construction diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> RigProviderDiagnostics {
        RigProviderDiagnostics::new(self.provider, self.model.clone(), self.raw_retention)
    }
}

impl fmt::Debug for RigProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RigProvider")
            .field("provider", &self.provider)
            .field("model", &"[REDACTED]")
            .field("raw_retention", &self.raw_retention)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl LlmProvider for RigProvider {
    async fn complete(
        &self,
        request: LlmRequest,
    ) -> Result<ProviderCompletionResult, ProviderError> {
        RigProvider::complete(self, &request).await
    }

    async fn stream(&self, request: LlmRequest) -> Result<ProviderStream, ProviderError> {
        RigProvider::stream(self, request).await
    }
}

struct StreamDrain {
    provider: DirectProvider,
    model: String,
    raw_retention: RawRetentionPolicy,
    request_id: LlmRequestId,
    max_tool_calls: u32,
    max_output_bytes: Option<u64>,
    tool_capabilities: BTreeMap<String, Option<String>>,
    deadline: Instant,
    stream: StreamingCompletionResponse,
    sender: tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
    terminal_error_sender: Option<tokio::sync::oneshot::Sender<ProviderError>>,
}

struct ProviderStreamReceiver {
    receiver: tokio::sync::mpsc::Receiver<Result<ProviderStreamEvent, ProviderError>>,
    terminal_error_receiver: Option<tokio::sync::oneshot::Receiver<ProviderError>>,
}

#[derive(Default)]
struct StreamProgress {
    sequence: u64,
    streamed_bytes: u64,
    completed_tool_calls: u32,
    unknown_items: u32,
}

#[derive(Clone, Copy)]
struct StreamTerminalContext<'a> {
    provider: DirectProvider,
    model: &'a str,
    raw_retention: RawRetentionPolicy,
    request_id: &'a LlmRequestId,
    max_tool_calls: u32,
    max_output_bytes: Option<u64>,
    tool_capabilities: &'a BTreeMap<String, Option<String>>,
    deadline: Instant,
    sender: &'a tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
}
impl StreamProgress {
    fn account(
        &mut self,
        provider: DirectProvider,
        bytes: u64,
        limit: Option<u64>,
    ) -> Result<(), ProviderError> {
        let total = self.streamed_bytes.checked_add(bytes).ok_or_else(|| {
            ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
            .with_transport_metadata(None, None, None, RetainedRaw::discarded())
        })?;
        if limit.is_some_and(|limit| total > limit) {
            return Err(ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
            .with_transport_metadata(None, None, None, RetainedRaw::discarded()));
        }
        self.streamed_bytes = total;
        Ok(())
    }

    fn next_sequence(&mut self, provider: DirectProvider) -> Result<u64, ProviderError> {
        let current = self.sequence;
        self.sequence = self.sequence.checked_add(1).ok_or_else(|| {
            ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
            .with_transport_metadata(None, None, None, RetainedRaw::discarded())
        })?;
        Ok(current)
    }

    fn next_tool_index(&mut self, provider: DirectProvider) -> Result<u32, ProviderError> {
        let current = self.completed_tool_calls;
        self.completed_tool_calls = self.completed_tool_calls.checked_add(1).ok_or_else(|| {
            ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
        })?;
        Ok(current)
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive Rig event mapping stays explicit for auditability"
)]
fn normalize_incremental_events(
    content: StreamedAssistantContent,
    provider: DirectProvider,
    request_id: &LlmRequestId,
    raw_retention: RawRetentionPolicy,
    max_tool_calls: u32,
    max_output_bytes: Option<u64>,
    progress: &mut StreamProgress,
) -> Result<Vec<ProviderStreamEvent>, ProviderError> {
    let mut events = Vec::new();
    match content {
        StreamedAssistantContent::Text(text) => {
            progress.account(
                provider,
                u64::try_from(text.text.len()).unwrap_or(u64::MAX),
                max_output_bytes,
            )?;
            events.push(ProviderStreamEvent::TextDelta {
                sequence: progress.next_sequence(provider)?,
                text: text.text,
            });
        }
        StreamedAssistantContent::ToolCallDelta {
            internal_call_id,
            content,
        } => {
            let delta = match content {
                ToolCallDeltaContent::Name(name) => {
                    progress.account(
                        provider,
                        u64::try_from(name.len()).unwrap_or(u64::MAX),
                        max_output_bytes,
                    )?;
                    ProviderToolCallDelta::Name(name)
                }
                ToolCallDeltaContent::Delta(fragment) => {
                    progress.account(
                        provider,
                        u64::try_from(fragment.len()).unwrap_or(u64::MAX),
                        max_output_bytes,
                    )?;
                    ProviderToolCallDelta::ArgumentsFragment(fragment)
                }
            };
            events.push(ProviderStreamEvent::ToolCallDelta {
                sequence: progress.next_sequence(provider)?,
                correlation_id: internal_call_id,
                delta,
            });
        }
        StreamedAssistantContent::ToolCall {
            tool_call,
            internal_call_id,
        } => {
            let tool_index = progress.next_tool_index(provider)?;
            if tool_index >= max_tool_calls {
                return Err(ProviderError::new(
                    provider.as_str().to_owned(),
                    ProviderErrorKind::Safety,
                    RetryClass::Never,
                ));
            }
            let call_id = tool_call
                .provider
                .as_ref()
                .map(|provider| provider.call_id.as_str())
                .filter(|call_id| !call_id.trim().is_empty())
                .map_or_else(
                    || format!("{}-call-{tool_index}", request_id.as_str()),
                    str::to_owned,
                );
            let mut raw_metadata = serde_json::Map::new();
            if let Some(provider_id) = &tool_call.provider
                && let Some(item_id) = &provider_id.item_id
            {
                raw_metadata.insert(
                    "provider_item_id".to_owned(),
                    serde_json::Value::String(item_id.clone()),
                );
            }
            if let Some(signature) = tool_call.signature {
                raw_metadata.insert("signature".to_owned(), serde_json::Value::String(signature));
            }
            if let Some(additional) = tool_call.additional_params {
                raw_metadata.insert("additional_params".to_owned(), additional);
            }
            let raw_value = serde_json::Value::Object(raw_metadata);
            let raw = if raw_value.as_object().is_some_and(serde_json::Map::is_empty) {
                RetainedRaw::discarded()
            } else {
                progress.account(provider, serialized_len(&raw_value), max_output_bytes)?;
                RetainedRaw::from_value(raw_retention, raw_value)
            };
            progress.account(
                provider,
                u64::try_from(tool_call.function.name.len()).unwrap_or(u64::MAX),
                max_output_bytes,
            )?;
            progress.account(
                provider,
                serialized_len(&tool_call.function.arguments),
                max_output_bytes,
            )?;
            events.push(ProviderStreamEvent::ToolCall {
                sequence: progress.next_sequence(provider)?,
                correlation_id: internal_call_id,
                call_id,
                name: tool_call.function.name,
                arguments: tool_call.function.arguments,
                raw,
            });
        }
        StreamedAssistantContent::ReasoningDelta { id, reasoning, .. } => {
            let byte_count = u64::try_from(reasoning.len()).unwrap_or(u64::MAX);
            progress.account(provider, byte_count, max_output_bytes)?;
            events.push(ProviderStreamEvent::PrivateReasoningDelta {
                sequence: progress.next_sequence(provider)?,
                correlation_id: id,
                byte_count,
            });
        }
        StreamedAssistantContent::Reasoning { reasoning, id } => {
            if reasoning.content.is_empty() {
                events.push(ProviderStreamEvent::PrivateReasoning {
                    sequence: progress.next_sequence(provider)?,
                    correlation_id: id.clone(),
                    byte_count: 0,
                });
            }
            for content in reasoning.content {
                match content {
                    ReasoningContent::Text { text, signature } => {
                        let byte_count = u64::try_from(text.len()).unwrap_or(u64::MAX);
                        progress.account(provider, byte_count, max_output_bytes)?;
                        events.push(ProviderStreamEvent::PrivateReasoning {
                            sequence: progress.next_sequence(provider)?,
                            correlation_id: id.clone(),
                            byte_count,
                        });
                        if let Some(signature) = signature {
                            progress.account(
                                provider,
                                u64::try_from(signature.len()).unwrap_or(u64::MAX),
                                max_output_bytes,
                            )?;
                            events.push(ProviderStreamEvent::Reasoning {
                                sequence: progress.next_sequence(provider)?,
                                correlation_id: id.clone(),
                                representation: ReasoningRepresentation::Signature,
                                data: signature,
                            });
                        }
                    }
                    ReasoningContent::Encrypted(data) | ReasoningContent::Redacted { data } => {
                        progress.account(
                            provider,
                            u64::try_from(data.len()).unwrap_or(u64::MAX),
                            max_output_bytes,
                        )?;
                        events.push(ProviderStreamEvent::Reasoning {
                            sequence: progress.next_sequence(provider)?,
                            correlation_id: id.clone(),
                            representation: ReasoningRepresentation::OpaqueEncrypted,
                            data,
                        });
                    }
                    ReasoningContent::Summary(data) => {
                        progress.account(
                            provider,
                            u64::try_from(data.len()).unwrap_or(u64::MAX),
                            max_output_bytes,
                        )?;
                        events.push(ProviderStreamEvent::Reasoning {
                            sequence: progress.next_sequence(provider)?,
                            correlation_id: id.clone(),
                            representation: ReasoningRepresentation::Summary,
                            data,
                        });
                    }
                }
            }
        }
        StreamedAssistantContent::Unknown(unknown) => {
            let value = serde_json::to_value(unknown).map_err(|_| {
                ProviderError::new(
                    provider.as_str().to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                )
            })?;
            progress.account(provider, serialized_len(&value), max_output_bytes)?;
            progress.unknown_items = progress.unknown_items.saturating_add(1);
            events.push(ProviderStreamEvent::UnknownProviderItem {
                sequence: progress.next_sequence(provider)?,
                kind: "unmodeled_provider_item",
                raw: RetainedRaw::from_value(raw_retention, value),
            });
        }
        StreamedAssistantContent::Final(_) => {}
    }
    Ok(events)
}

async fn drain_provider_stream(state: StreamDrain) {
    let StreamDrain {
        provider,
        model,
        raw_retention,
        request_id,
        max_tool_calls,
        max_output_bytes,
        tool_capabilities,
        deadline,
        mut stream,
        sender,
        mut terminal_error_sender,
    } = state;
    let mut progress = StreamProgress::default();

    loop {
        let item = tokio::select! {
            () = sender.closed() => {
                stream.cancel();
                return;
            }
            () = tokio::time::sleep_until(deadline) => {
                report_stream_error(
                    &sender,
                    &mut terminal_error_sender,
                    timeout_error(provider),
                );
                stream.cancel();
                return;
            }
            item = stream.next() => item,
        };
        let Some(item) = item else {
            break;
        };
        let events = match item {
            Ok(content) => match normalize_incremental_events(
                content,
                provider,
                &request_id,
                raw_retention,
                max_tool_calls,
                max_output_bytes,
                &mut progress,
            ) {
                Ok(events) => events,
                Err(error) => {
                    report_stream_error(&sender, &mut terminal_error_sender, error);
                    stream.cancel();
                    return;
                }
            },
            Err(error) => {
                let error = map_completion_error(provider, raw_retention, &error);
                report_stream_error(&sender, &mut terminal_error_sender, error);
                stream.cancel();
                return;
            }
        };
        for event in events {
            match send_stream_item(&sender, deadline, Ok(event)).await {
                StreamSendOutcome::Sent => {}
                StreamSendOutcome::Closed => {
                    stream.cancel();
                    return;
                }
                StreamSendOutcome::Deadline => {
                    report_stream_error(
                        &sender,
                        &mut terminal_error_sender,
                        timeout_error(provider),
                    );
                    stream.cancel();
                    return;
                }
            }
        }
    }

    if let Some(error) = finish_provider_stream(
        StreamTerminalContext {
            provider,
            model: &model,
            raw_retention,
            request_id: &request_id,
            max_tool_calls,
            max_output_bytes,
            tool_capabilities: &tool_capabilities,
            deadline,
            sender: &sender,
        },
        stream,
        &mut progress,
    )
    .await
    {
        report_stream_error(&sender, &mut terminal_error_sender, error);
    }
}

async fn finish_provider_stream(
    context: StreamTerminalContext<'_>,
    stream: StreamingCompletionResponse,
    progress: &mut StreamProgress,
) -> Option<ProviderError> {
    let StreamTerminalContext {
        provider,
        deadline,
        sender,
        ..
    } = context;
    if stream.response.is_none() {
        return Some(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Transport,
            RetryClass::Safe,
        ));
    }
    let terminal_raw = stream
        .response
        .as_ref()
        .map_or(serde_json::Value::Null, |response| response.raw.clone());
    let mut completion = CompletionResponse::from(stream);
    completion.raw = terminal_raw;
    if ensure_deadline(provider, deadline).is_err() {
        return Some(timeout_error(provider));
    }
    let result = normalize_stream_terminal(&context, progress.unknown_items, completion);
    let event = match result {
        Ok(result) => {
            progress
                .next_sequence(provider)
                .map(|current| ProviderStreamEvent::Terminal {
                    sequence: current,
                    result: Box::new(result),
                })
        }
        Err(error) => return Some(error),
    };
    match event {
        Ok(event) => match send_stream_item(sender, deadline, Ok(event)).await {
            StreamSendOutcome::Sent | StreamSendOutcome::Closed => None,
            StreamSendOutcome::Deadline => Some(timeout_error(provider)),
        },
        Err(error) => Some(error),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StreamSendOutcome {
    Sent,
    Closed,
    Deadline,
}

async fn send_stream_item(
    sender: &tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
    deadline: Instant,
    item: Result<ProviderStreamEvent, ProviderError>,
) -> StreamSendOutcome {
    if Instant::now() >= deadline {
        return StreamSendOutcome::Deadline;
    }
    tokio::select! {
        () = sender.closed() => StreamSendOutcome::Closed,
        () = tokio::time::sleep_until(deadline) => StreamSendOutcome::Deadline,
        result = sender.send(item) => {
            if result.is_ok() {
                StreamSendOutcome::Sent
            } else {
                StreamSendOutcome::Closed
            }
        },
    }
}

fn report_stream_error(
    sender: &tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
    terminal_error_sender: &mut Option<tokio::sync::oneshot::Sender<ProviderError>>,
    error: ProviderError,
) {
    match sender.try_send(Err(error)) {
        Ok(()) | Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            terminal_error_sender.take();
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(item)) => {
            let Err(error) = item else {
                unreachable!("stream errors are the only values reported through this path");
            };
            if let Some(sender) = terminal_error_sender.take() {
                let _ = sender.send(error);
            }
        }
    }
}

async fn receive_provider_item(
    mut state: ProviderStreamReceiver,
) -> Option<(
    Result<ProviderStreamEvent, ProviderError>,
    ProviderStreamReceiver,
)> {
    if let Some(item) = state.receiver.recv().await {
        return Some((item, state));
    }
    let receiver = state.terminal_error_receiver.take()?;
    receiver.await.ok().map(|error| (Err(error), state))
}

fn timeout_error(provider: DirectProvider) -> ProviderError {
    ProviderError::new(
        provider.as_str().to_owned(),
        ProviderErrorKind::Timeout,
        RetryClass::Safe,
    )
}

fn normalize_stream_terminal(
    context: &StreamTerminalContext<'_>,
    unknown_items: u32,
    completion: CompletionResponse,
) -> Result<ProviderCompletionResult, ProviderError> {
    let StreamTerminalContext {
        provider,
        model,
        raw_retention,
        request_id,
        max_tool_calls,
        max_output_bytes,
        tool_capabilities,
        ..
    } = *context;
    let normalized = normalize_response(
        provider,
        model,
        request_id,
        tool_capabilities,
        raw_retention,
        OffsetDateTime::now_utc(),
        completion,
    )?;
    let tool_calls = normalized
        .response
        .output()
        .iter()
        .filter(|part| matches!(part, LlmOutputPart::ToolCall(_)))
        .count();
    if tool_calls > usize::try_from(max_tool_calls).unwrap_or(usize::MAX)
        || max_output_bytes.is_some_and(|limit| serialized_len(&normalized.response) > limit)
    {
        return Err(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Safety,
            RetryClass::Never,
        )
        .with_transport_metadata(None, None, None, normalized.raw));
    }
    let diagnostics = ProviderCompletionDiagnostics::new(
        provider.as_str().to_owned(),
        normalized.raw.state(),
        normalized.unmodeled_parts.saturating_add(unknown_items),
        normalized.private_reasoning_blocks,
    );
    Ok(ProviderCompletionResult::new(
        normalized.response,
        normalized.raw,
        diagnostics,
    ))
}

fn build_driver(
    provider: DirectProvider,
    model: &str,
    api_key: &str,
    http_client: RigHttpClient,
) -> Result<Arc<dyn Driver>, ProviderError> {
    match provider {
        DirectProvider::OpenAi => {
            let client = openai::Client::builder()
                .api_key(api_key.to_owned())
                .http_client(http_client)
                .build()
                .map_err(|_| {
                    ProviderError::new(
                        provider.as_str().to_owned(),
                        ProviderErrorKind::Schema,
                        RetryClass::Never,
                    )
                })?;
            Ok(Arc::new(ModelDriver::new(
                openai::responses_api::ResponsesCompletionModel::new(client, model.to_owned()),
            )))
        }
        DirectProvider::Anthropic => {
            let client = anthropic::Client::builder()
                .api_key(api_key.to_owned())
                .http_client(http_client)
                .build()
                .map_err(|_| {
                    ProviderError::new(
                        provider.as_str().to_owned(),
                        ProviderErrorKind::Schema,
                        RetryClass::Never,
                    )
                })?;
            Ok(Arc::new(ModelDriver::new(
                anthropic::completion::CompletionModel::new(client, model.to_owned()),
            )))
        }
        DirectProvider::Gemini => {
            let client = gemini::Client::builder()
                .api_key(api_key.to_owned())
                .http_client(http_client)
                .build()
                .map_err(|_| {
                    ProviderError::new(
                        provider.as_str().to_owned(),
                        ProviderErrorKind::Schema,
                        RetryClass::Never,
                    )
                })?;
            Ok(Arc::new(ModelDriver::new(gemini::CompletionModel::new(
                client,
                model.to_owned(),
            ))))
        }
        DirectProvider::OpenRouter => {
            let client = openrouter::Client::builder()
                .api_key(api_key.to_owned())
                .http_client(http_client)
                .build()
                .map_err(|_| {
                    ProviderError::new(
                        provider.as_str().to_owned(),
                        ProviderErrorKind::Schema,
                        RetryClass::Never,
                    )
                })?;
            Ok(Arc::new(ModelDriver::new(
                openrouter::CompletionModel::new(client, model.to_owned()),
            )))
        }
    }
}

fn ensure_deadline(provider: DirectProvider, deadline: Instant) -> Result<(), ProviderError> {
    if Instant::now() >= deadline {
        Err(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Timeout,
            RetryClass::Safe,
        ))
    } else {
        Ok(())
    }
}

fn map_completion_error(
    provider: DirectProvider,
    raw_policy: RawRetentionPolicy,
    error: &CompletionError,
) -> ProviderError {
    if let CompletionError::HttpError(error) = error
        && let Some(failure) = failure_from_http_error(error)
    {
        return match failure {
            RigHttpFailure::ResponseTooLarge => ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Safety,
                RetryClass::Never,
            )
            .with_transport_metadata(None, None, None, RetainedRaw::discarded()),
            RigHttpFailure::Timeout => ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Timeout,
                RetryClass::Safe,
            ),
            RigHttpFailure::Rejected | RigHttpFailure::Unsupported => ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Transport,
                RetryClass::Never,
            ),
            RigHttpFailure::Transport => ProviderError::new(
                provider.as_str().to_owned(),
                ProviderErrorKind::Transport,
                RetryClass::Safe,
            ),
        };
    }

    let status_code = error
        .provider_response_status()
        .map(|status| status.as_u16());
    let retry_after = error
        .provider_response_headers()
        .and_then(|headers| headers.get("retry-after"))
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_retry_after(value, OffsetDateTime::now_utc()));
    let provider_request_id = error.provider_request_id().map(str::to_owned);
    let body_kind = error
        .provider_response_body()
        .and_then(classify_provider_body);
    let raw = error
        .provider_response_body()
        .map_or_else(RetainedRaw::discarded, |body| {
            RetainedRaw::from_body(raw_policy, body)
        });

    let (kind, retry) = body_kind.map_or_else(
        || {
            status_code.map_or_else(
                || match error {
                    CompletionError::HttpError(_) => {
                        (ProviderErrorKind::Transport, RetryClass::Safe)
                    }
                    CompletionError::JsonError(_)
                    | CompletionError::UrlError(_)
                    | CompletionError::RequestError(_)
                    | CompletionError::ResponseError(_) => {
                        (ProviderErrorKind::Schema, RetryClass::Never)
                    }
                    CompletionError::ProviderError(_) | CompletionError::ProviderResponse(_) => {
                        (ProviderErrorKind::Provider, RetryClass::Never)
                    }
                },
                |status| classify_status(status, retry_after.is_some()),
            )
        },
        |kind| match kind {
            ProviderErrorKind::Throttling => (
                kind,
                if retry_after.is_some() {
                    RetryClass::AfterRetryAfter
                } else {
                    RetryClass::Safe
                },
            ),
            _ => (kind, RetryClass::Never),
        },
    );
    ProviderError::new(provider.as_str().to_owned(), kind, retry).with_transport_metadata(
        status_code,
        retry_after,
        provider_request_id,
        raw,
    )
}

fn classify_status(status: u16, has_retry_after: bool) -> (ProviderErrorKind, RetryClass) {
    match status {
        408 | 504 => (ProviderErrorKind::Timeout, RetryClass::Safe),
        429 => (
            ProviderErrorKind::Throttling,
            if has_retry_after {
                RetryClass::AfterRetryAfter
            } else {
                RetryClass::Safe
            },
        ),
        422 => (ProviderErrorKind::Schema, RetryClass::Never),
        451 => (ProviderErrorKind::Safety, RetryClass::Never),
        500..=599 => (ProviderErrorKind::Provider, RetryClass::Safe),
        _ => (ProviderErrorKind::Provider, RetryClass::Never),
    }
}

const PROVIDER_SIGNAL_POINTERS: [&str; 8] = [
    "/error/type",
    "/error/code",
    "/error/status",
    "/error/reason",
    "/type",
    "/code",
    "/status",
    "/reason",
];

fn classify_provider_body(body: &str) -> Option<ProviderErrorKind> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    if PROVIDER_SIGNAL_POINTERS
        .iter()
        .filter_map(|pointer| value.pointer(pointer).and_then(serde_json::Value::as_str))
        .any(|signal| matches_signal(signal, &PERMANENT_PROVIDER_SIGNALS))
    {
        return Some(ProviderErrorKind::Provider);
    }
    PROVIDER_SIGNAL_POINTERS
        .iter()
        .filter_map(|pointer| value.pointer(pointer).and_then(serde_json::Value::as_str))
        .find_map(classify_provider_signal)
}

const PERMANENT_PROVIDER_SIGNALS: [&str; 15] = [
    "billing-inactive",
    "billing_inactive",
    "billing_not_active",
    "billing_disabled",
    "credit-exhausted",
    "credit_exhausted",
    "credits_exhausted",
    "exhausted-credit",
    "exhausted_credit",
    "exhausted_credits",
    "insufficient_quota",
    "spend-limit-exceeded",
    "spend_limit_exceeded",
    "spend_limit_reached",
    "spending_limit_exceeded",
];
const THROTTLING_SIGNALS: [&str; 5] = [
    "rate_limit_error",
    "rate_limit_exceeded",
    "resource_exhausted",
    "throttled",
    "throttling",
];
const SAFETY_SIGNALS: [&str; 6] = [
    "blocked",
    "content_filter",
    "content_policy_violation",
    "policy_violation",
    "safety",
    "safety_violation",
];
const SCHEMA_SIGNALS: [&str; 5] = [
    "invalid_argument",
    "invalid_request_error",
    "json_schema_error",
    "response_format_error",
    "schema_validation_error",
];

fn classify_provider_signal(signal: &str) -> Option<ProviderErrorKind> {
    if signal.len() > 128 || !signal.is_ascii() {
        return None;
    }
    if matches_signal(signal, &PERMANENT_PROVIDER_SIGNALS) {
        Some(ProviderErrorKind::Provider)
    } else if matches_signal(signal, &THROTTLING_SIGNALS) {
        Some(ProviderErrorKind::Throttling)
    } else if matches_signal(signal, &SAFETY_SIGNALS) {
        Some(ProviderErrorKind::Safety)
    } else if matches_signal(signal, &SCHEMA_SIGNALS) {
        Some(ProviderErrorKind::Schema)
    } else {
        None
    }
}

fn matches_signal(signal: &str, known: &[&str]) -> bool {
    known
        .iter()
        .any(|candidate| signal.eq_ignore_ascii_case(candidate))
}

fn parse_retry_after(value: &str, now: OffsetDateTime) -> Option<Duration> {
    if let Ok(seconds) = value.trim().parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    let retry_at = OffsetDateTime::parse(value.trim(), &Rfc2822).ok()?;
    let seconds = (retry_at - now).whole_seconds();
    u64::try_from(seconds).ok().map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        error::Error,
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll},
        time::Duration,
    };

    use futures::Stream;
    use omnius_llm_core::{
        CompletionStatus, LlmRequestId, ProviderError, ProviderErrorKind, ProviderStreamEvent,
        ProviderToolCallDelta, RawRetentionPolicy, RawRetentionState, ReasoningRepresentation,
        RetainedRaw, RetryClass,
    };
    use omnius_outbound_http::StatusCode;
    use rig_core::{
        ProviderResponseError,
        completion::{CompletionError, FinishReason, Usage},
        message::ReasoningContent,
        streaming::{
            RawStreamingChoice, StreamFinal, StreamPartId, StreamingCompletionResponse,
            StreamingResult, ToolCallDeltaContent, ToolInputEnd, UnknownPayload,
            UnparseableToolInput,
        },
    };
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    use tokio::time::Instant;

    use super::{
        ProviderStreamReceiver, StreamDrain, classify_provider_body, classify_status,
        drain_provider_stream, map_completion_error, parse_retry_after, receive_provider_item,
    };
    use crate::DirectProvider;
    use crate::http::{RigHttpFailure, error_for_test};

    #[test]
    fn retry_after_accepts_delta_seconds_and_http_dates() {
        let now = OffsetDateTime::parse("2026-08-29T12:00:00Z", &Rfc3339)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        assert_eq!(parse_retry_after("17", now), Some(Duration::from_secs(17)));
        assert_eq!(
            parse_retry_after("Sat, 29 Aug 2026 12:00:23 GMT", now),
            Some(Duration::from_secs(23))
        );
    }

    #[test]
    fn statuses_have_stable_typed_retry_classification() {
        assert_eq!(
            classify_status(429, true),
            (ProviderErrorKind::Throttling, RetryClass::AfterRetryAfter)
        );
        assert_eq!(
            classify_status(503, false),
            (ProviderErrorKind::Provider, RetryClass::Safe)
        );
        assert_eq!(
            classify_status(422, false),
            (ProviderErrorKind::Schema, RetryClass::Never)
        );
        assert_eq!(
            classify_status(451, false),
            (ProviderErrorKind::Safety, RetryClass::Never)
        );
    }

    #[test]
    fn provider_error_codes_distinguish_quota_throttling_safety_and_schema() {
        assert_eq!(
            classify_provider_body(r#"{"error":{"type":"rate_limit_error"}}"#),
            Some(ProviderErrorKind::Throttling)
        );
        assert_eq!(
            classify_provider_body(r#"{"error":{"code":"insufficient_quota"}}"#),
            Some(ProviderErrorKind::Provider)
        );
        assert_eq!(
            classify_provider_body(r#"{"error":{"status":"SPEND_LIMIT_EXCEEDED"}}"#),
            Some(ProviderErrorKind::Provider)
        );
        assert_eq!(
            classify_provider_body(r#"{"error":{"reason":"billing_inactive"}}"#),
            Some(ProviderErrorKind::Provider)
        );
        assert_eq!(
            classify_provider_body(r#"{"error":{"code":"content_filter"}}"#),
            Some(ProviderErrorKind::Safety)
        );
        assert_eq!(
            classify_provider_body(r#"{"error":{"status":"INVALID_ARGUMENT"}}"#),
            Some(ProviderErrorKind::Schema)
        );
    }

    #[test]
    fn quota_signal_overrides_generic_429_retry_classification() {
        let source = CompletionError::ProviderResponse(ProviderResponseError::new(
            StatusCode::TOO_MANY_REQUESTS,
            r#"{"error":{"type":"rate_limit_error","code":"insufficient_quota"}}"#,
        ));
        let error =
            map_completion_error(DirectProvider::OpenAi, RawRetentionPolicy::Discard, &source);
        assert_eq!(error.kind(), ProviderErrorKind::Provider);
        assert_eq!(error.retry_class(), RetryClass::Never);
    }

    #[test]
    fn oversized_transport_response_is_safety_and_never_retryable() {
        let source = CompletionError::HttpError(error_for_test(RigHttpFailure::ResponseTooLarge));
        let error =
            map_completion_error(DirectProvider::Gemini, RawRetentionPolicy::Discard, &source);
        assert_eq!(error.kind(), ProviderErrorKind::Safety);
        assert_eq!(error.retry_class(), RetryClass::Never);
    }
    #[test]
    fn provider_error_payload_and_request_id_follow_policy_without_debug_leakage() {
        let source = CompletionError::ProviderResponse(
            ProviderResponseError::without_status(r#"{"error":"provider-body-secret"}"#)
                .with_provider_request_id(Some("transport-request-1".to_owned())),
        );
        let discarded =
            map_completion_error(DirectProvider::OpenAi, RawRetentionPolicy::Discard, &source);
        let redacted = map_completion_error(
            DirectProvider::OpenAi,
            RawRetentionPolicy::Redacted,
            &source,
        );
        let full = map_completion_error(DirectProvider::OpenAi, RawRetentionPolicy::Full, &source);
        assert_eq!(
            discarded.retained_raw().state(),
            RawRetentionState::Discarded
        );
        assert_eq!(redacted.retained_raw().state(), RawRetentionState::Redacted);
        assert_eq!(full.retained_raw().state(), RawRetentionState::Full);
        assert_eq!(full.provider_request_id(), Some("transport-request-1"));
        assert!(!format!("{full:?}").contains("provider-body-secret"));
        assert!(!full.to_string().contains("provider-body-secret"));
    }

    struct PendingDropStream {
        dropped: Arc<AtomicBool>,
    }

    impl Stream for PendingDropStream {
        type Item = Result<RawStreamingChoice<StreamFinal>, CompletionError>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }

    impl Drop for PendingDropStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    struct ErrorAfterTextStream {
        step: u8,
        dropped: Arc<AtomicBool>,
    }

    impl Stream for ErrorAfterTextStream {
        type Item = Result<RawStreamingChoice<StreamFinal>, CompletionError>;

        fn poll_next(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            let item = match self.step {
                0 => Ok(RawStreamingChoice::Message("partial-text".to_owned())),
                1 => Err(CompletionError::HttpError(error_for_test(
                    RigHttpFailure::Transport,
                ))),
                _ => return Poll::Pending,
            };
            self.step = self.step.saturating_add(1);
            Poll::Ready(Some(item))
        }
    }

    impl Drop for ErrorAfterTextStream {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    fn stream_drain(
        stream: StreamingCompletionResponse,
        sender: tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
        deadline: Instant,
        raw_retention: RawRetentionPolicy,
    ) -> Result<StreamDrain, Box<dyn Error>> {
        let (terminal_error_sender, _terminal_error_receiver) = tokio::sync::oneshot::channel();
        stream_drain_with_terminal_error(
            stream,
            sender,
            terminal_error_sender,
            deadline,
            raw_retention,
        )
    }

    fn stream_drain_with_terminal_error(
        stream: StreamingCompletionResponse,
        sender: tokio::sync::mpsc::Sender<Result<ProviderStreamEvent, ProviderError>>,
        terminal_error_sender: tokio::sync::oneshot::Sender<ProviderError>,
        deadline: Instant,
        raw_retention: RawRetentionPolicy,
    ) -> Result<StreamDrain, Box<dyn Error>> {
        Ok(StreamDrain {
            provider: DirectProvider::OpenAi,
            model: "fixture-model".to_owned(),
            raw_retention,
            request_id: LlmRequestId::new("stream-request".to_owned())?,
            max_tool_calls: 4,
            max_output_bytes: Some(16_384),
            tool_capabilities: BTreeMap::new(),
            deadline,
            stream,
            sender,
            terminal_error_sender: Some(terminal_error_sender),
        })
    }
    #[tokio::test]
    async fn stream_drain_orders_text_retains_unknown_and_normalizes_terminal()
    -> Result<(), Box<dyn Error>> {
        let items: Vec<Result<RawStreamingChoice<StreamFinal>, CompletionError>> = vec![
            Ok(RawStreamingChoice::Message("SENSITIVE-TEXT-A".to_owned())),
            Ok(RawStreamingChoice::Message("SENSITIVE-TEXT-B".to_owned())),
            Ok(RawStreamingChoice::Unknown(UnknownPayload::new(
                serde_json::json!({"novel":"secret-provider-value"}),
            ))),
            Ok(RawStreamingChoice::FinalResponse(
                StreamFinal::new("openai", Usage::default()).with_finish_reason(FinishReason::Stop),
            )),
        ];
        let inner: StreamingResult = Box::pin(futures::stream::iter(items));
        let stream = StreamingCompletionResponse::stream("openai", inner);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        drain_provider_stream(stream_drain(
            stream,
            sender,
            Instant::now() + Duration::from_secs(1),
            RawRetentionPolicy::Redacted,
        )?)
        .await;

        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            events.push(event?);
        }
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].sequence(), 0);
        assert_eq!(events[0].text(), Some("SENSITIVE-TEXT-A"));
        assert_eq!(events[1].sequence(), 1);
        assert_eq!(events[1].text(), Some("SENSITIVE-TEXT-B"));
        assert_eq!(events[2].sequence(), 2);
        assert_eq!(
            events[2].retained_raw().map(RetainedRaw::state),
            Some(RawRetentionState::Redacted)
        );
        assert_eq!(events[3].sequence(), 3);
        let terminal = events[3].terminal().ok_or("missing terminal event")?;
        assert_eq!(terminal.response().status(), CompletionStatus::Completed);
        assert_eq!(terminal.diagnostics().unmodeled_parts(), 1);
        let debug = format!("{events:?}");
        assert!(!debug.contains("secret-provider-value"));
        assert!(!debug.contains("SENSITIVE-TEXT-A"));
        assert!(!debug.contains("SENSITIVE-TEXT-B"));
        Ok(())
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one ordered fixture verifies every sensitive streaming event class"
    )]
    async fn stream_preserves_interleaved_tool_and_safe_reasoning_events()
    -> Result<(), Box<dyn Error>> {
        let tool_id = StreamPartId::wire("provider-call-1");
        let mut tool_end = ToolInputEnd::new(tool_id.clone(), UnparseableToolInput::Error);
        tool_end.signature = Some("tool-signature-secret".to_owned());
        tool_end.additional_params = Some(serde_json::json!({"metadata":"tool-metadata-secret"}));
        let items: Vec<Result<RawStreamingChoice<StreamFinal>, CompletionError>> = vec![
            Ok(RawStreamingChoice::Message("visible-text".to_owned())),
            Ok(RawStreamingChoice::ToolCallDelta {
                id: tool_id.clone(),
                content: ToolCallDeltaContent::Name("lookup".to_owned()),
            }),
            Ok(RawStreamingChoice::ToolCallDelta {
                id: tool_id.clone(),
                content: ToolCallDeltaContent::Delta("{\"city\":\"".to_owned()),
            }),
            Ok(RawStreamingChoice::ToolCallDelta {
                id: tool_id,
                content: ToolCallDeltaContent::Delta(r#"Paris"}"#.to_owned()),
            }),
            Ok(RawStreamingChoice::ToolInputEnd(tool_end)),
            Ok(RawStreamingChoice::ReasoningDelta {
                id: StreamPartId::wire("reason-private"),
                provider_id: None,
                reasoning: "private-chain-of-thought-secret".to_owned(),
            }),
            Ok(RawStreamingChoice::Reasoning {
                id: StreamPartId::wire("reason-private"),
                provider_id: None,
                content: ReasoningContent::Text {
                    text: "private-complete-thought-secret".to_owned(),
                    signature: Some("safe-signature-state".to_owned()),
                },
            }),
            Ok(RawStreamingChoice::Reasoning {
                id: StreamPartId::wire("reason-summary"),
                provider_id: None,
                content: ReasoningContent::Summary("safe-summary".to_owned()),
            }),
            Ok(RawStreamingChoice::Reasoning {
                id: StreamPartId::wire("reason-encrypted"),
                provider_id: None,
                content: ReasoningContent::Encrypted("opaque-encrypted-state".to_owned()),
            }),
            Ok(RawStreamingChoice::Unknown(UnknownPayload::new(
                serde_json::json!({"novel":"unknown-provider-secret"}),
            ))),
            Ok(RawStreamingChoice::FinalResponse(
                StreamFinal::new("openai", Usage::default()).with_finish_reason(FinishReason::Stop),
            )),
        ];
        let stream =
            StreamingCompletionResponse::stream("openai", Box::pin(futures::stream::iter(items)));
        let (sender, mut receiver) = tokio::sync::mpsc::channel(16);
        drain_provider_stream(stream_drain(
            stream,
            sender,
            Instant::now() + Duration::from_secs(1),
            RawRetentionPolicy::Redacted,
        )?)
        .await;

        let mut events = Vec::new();
        while let Some(event) = receiver.recv().await {
            events.push(event?);
        }
        assert_eq!(events.len(), 12);
        for (sequence, event) in events.iter().enumerate() {
            assert_eq!(event.sequence(), u64::try_from(sequence)?);
        }
        assert_eq!(events[0].text(), Some("visible-text"));
        assert_eq!(
            events[1]
                .tool_call_delta()
                .and_then(ProviderToolCallDelta::name),
            Some("lookup")
        );
        assert_eq!(
            events[2]
                .tool_call_delta()
                .and_then(ProviderToolCallDelta::arguments_fragment),
            Some("{\"city\":\"")
        );
        assert_eq!(
            events[3]
                .tool_call_delta()
                .and_then(ProviderToolCallDelta::arguments_fragment),
            Some(r#"Paris"}"#)
        );
        assert_eq!(events[1].correlation_id(), events[2].correlation_id());
        assert_eq!(events[2].correlation_id(), events[3].correlation_id());
        assert_eq!(events[3].correlation_id(), events[4].correlation_id());
        let (call_id, name, arguments) =
            events[4].tool_call().ok_or("completed tool call missing")?;
        assert_eq!(call_id, "provider-call-1");
        assert_eq!(name, "lookup");
        assert_eq!(arguments, &serde_json::json!({"city":"Paris"}));
        assert_eq!(
            events[4].retained_raw().map(RetainedRaw::state),
            Some(RawRetentionState::Redacted)
        );
        assert_eq!(
            events[5].private_reasoning_byte_count(),
            Some(u64::try_from("private-chain-of-thought-secret".len())?)
        );
        assert_eq!(
            events[6].private_reasoning_byte_count(),
            Some(u64::try_from("private-complete-thought-secret".len())?)
        );
        assert_eq!(
            events[7].reasoning(),
            Some((ReasoningRepresentation::Signature, "safe-signature-state"))
        );
        assert_eq!(
            events[8].reasoning(),
            Some((ReasoningRepresentation::Summary, "safe-summary"))
        );
        assert_eq!(
            events[9].reasoning(),
            Some((
                ReasoningRepresentation::OpaqueEncrypted,
                "opaque-encrypted-state"
            ))
        );
        assert_eq!(
            events[10].retained_raw().map(RetainedRaw::state),
            Some(RawRetentionState::Redacted)
        );
        assert_eq!(
            events[11]
                .terminal()
                .ok_or("terminal event missing")?
                .response()
                .status(),
            CompletionStatus::Completed
        );
        let debug = format!("{events:?}");
        for secret in [
            "visible-text",
            "lookup",
            "Paris",
            "private-chain-of-thought-secret",
            "private-complete-thought-secret",
            "safe-signature-state",
            "safe-summary",
            "opaque-encrypted-state",
            "tool-signature-secret",
            "tool-metadata-secret",
            "unknown-provider-secret",
        ] {
            assert!(!debug.contains(secret));
        }
        Ok(())
    }

    #[tokio::test]
    async fn first_stream_error_ends_after_delivered_partial_output() -> Result<(), Box<dyn Error>>
    {
        let dropped = Arc::new(AtomicBool::new(false));
        let inner: StreamingResult = Box::pin(ErrorAfterTextStream {
            step: 0,
            dropped: Arc::clone(&dropped),
        });
        let stream = StreamingCompletionResponse::stream("openai", inner);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
        drain_provider_stream(stream_drain(
            stream,
            sender,
            Instant::now() + Duration::from_secs(1),
            RawRetentionPolicy::Discard,
        )?)
        .await;

        let text = receiver.recv().await.ok_or("text delta missing")??;
        assert_eq!(text.sequence(), 0);
        assert_eq!(text.text(), Some("partial-text"));
        let error = receiver
            .recv()
            .await
            .ok_or("stream error missing")?
            .err()
            .ok_or("stream error unexpectedly succeeded")?;
        assert_eq!(error.kind(), ProviderErrorKind::Transport);
        assert!(receiver.recv().await.is_none());
        assert!(dropped.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn receiver_drop_cancels_pending_provider_stream() -> Result<(), Box<dyn Error>> {
        let dropped = Arc::new(AtomicBool::new(false));
        let inner: StreamingResult = Box::pin(PendingDropStream {
            dropped: Arc::clone(&dropped),
        });
        let stream = StreamingCompletionResponse::stream("openai", inner);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        drop(receiver);
        drain_provider_stream(stream_drain(
            stream,
            sender,
            Instant::now() + Duration::from_secs(1),
            RawRetentionPolicy::Discard,
        )?)
        .await;
        assert!(dropped.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn stream_deadline_cancels_pending_provider_stream_with_typed_timeout()
    -> Result<(), Box<dyn Error>> {
        let dropped = Arc::new(AtomicBool::new(false));
        let inner: StreamingResult = Box::pin(PendingDropStream {
            dropped: Arc::clone(&dropped),
        });
        let stream = StreamingCompletionResponse::stream("openai", inner);
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        drain_provider_stream(stream_drain(
            stream,
            sender,
            Instant::now() + Duration::from_millis(1),
            RawRetentionPolicy::Discard,
        )?)
        .await;
        let error = receiver
            .recv()
            .await
            .ok_or("timeout event missing")?
            .err()
            .ok_or("timeout unexpectedly succeeded")?;
        assert_eq!(error.kind(), ProviderErrorKind::Timeout);
        assert!(dropped.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn saturated_event_queue_still_delivers_terminal_timeout() -> Result<(), Box<dyn Error>> {
        let items: Vec<Result<RawStreamingChoice<StreamFinal>, CompletionError>> = vec![
            Ok(RawStreamingChoice::Message("buffered".to_owned())),
            Ok(RawStreamingChoice::Message("blocked".to_owned())),
        ];
        let stream =
            StreamingCompletionResponse::stream("openai", Box::pin(futures::stream::iter(items)));
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let (terminal_error_sender, terminal_error_receiver) = tokio::sync::oneshot::channel();
        drain_provider_stream(stream_drain_with_terminal_error(
            stream,
            sender,
            terminal_error_sender,
            Instant::now() + Duration::from_millis(10),
            RawRetentionPolicy::Discard,
        )?)
        .await;

        let receiver = ProviderStreamReceiver {
            receiver,
            terminal_error_receiver: Some(terminal_error_receiver),
        };
        let (first, receiver) = receive_provider_item(receiver)
            .await
            .ok_or("buffered event missing")?;
        assert_eq!(first?.text(), Some("buffered"));
        let (error, receiver) = receive_provider_item(receiver)
            .await
            .ok_or("terminal timeout missing")?;
        assert_eq!(
            error
                .err()
                .ok_or("terminal timeout unexpectedly succeeded")?
                .kind(),
            ProviderErrorKind::Timeout
        );
        assert!(receive_provider_item(receiver).await.is_none());
        Ok(())
    }
}
