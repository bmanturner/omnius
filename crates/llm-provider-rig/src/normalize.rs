use std::{collections::BTreeMap, fmt::Write as _, io};

use base64::prelude::{BASE64_STANDARD, Engine as _};
use omnius_llm_core::{
    BinarySource, Candidate, CompletionStatus, ImageOutputPart, JsonObject, LlmOutputPart,
    LlmRequestId, LlmResponse, ProviderError, ProviderErrorKind, RawRetentionPolicy,
    ReasoningOutputPart, ReasoningRepresentation, RetainedRaw, RetryClass, TextFormat,
    TextOutputPart, ToolCallOutputPart, UnknownOutputPart, Usage,
};
use rig_core::{
    completion::{CompletionResponse, FinishReason},
    message::{
        AssistantContent, DocumentSourceKind, Image, MimeType, Reasoning, ReasoningContent,
        ToolCall,
    },
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::CatalogProvider;

pub(crate) struct NormalizedCompletion {
    pub(crate) response: LlmResponse,
    pub(crate) raw: RetainedRaw,
    pub(crate) unmodeled_parts: u32,
    pub(crate) private_reasoning_blocks: u32,
}

struct ResponseIdentity {
    status: CompletionStatus,
    stop_reason: Option<String>,
    finish_warning: Option<&'static str>,
    provider_response_id: Option<String>,
    provider_request_id: Option<String>,
    message_id: Option<String>,
    model: String,
    response_id: String,
}

struct NormalizationContext<'a> {
    provider: CatalogProvider,
    raw_policy: RawRetentionPolicy,
    response_id: &'a str,
    capabilities: &'a BTreeMap<String, Option<String>>,
    raw: &'a Value,
}

impl NormalizationContext<'_> {
    fn schema_error(&self) -> ProviderError {
        schema_error_with_raw(self.provider, self.raw_policy, self.raw.clone())
    }
}

struct NormalizationState {
    output: Vec<LlmOutputPart>,
    warnings: Vec<String>,
    unmodeled_parts: u32,
    private_reasoning_blocks: u32,
}

impl NormalizationState {
    fn new(capacity: usize, warnings: Vec<String>) -> Self {
        Self {
            output: Vec::with_capacity(capacity),
            warnings,
            unmodeled_parts: 0,
            private_reasoning_blocks: 0,
        }
    }

    fn retain_unknown(
        &mut self,
        context: &NormalizationContext<'_>,
        index: usize,
        subindex: usize,
        provider_kind: &str,
        payload: Value,
    ) -> Result<(), ProviderError> {
        if context.raw_policy == RawRetentionPolicy::Full {
            let part = UnknownOutputPart::new(
                part_id(context.response_id, index, subindex),
                provider_kind.to_owned(),
                payload,
            )
            .map_err(|_| {
                ProviderError::new(
                    context.provider.as_str().to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                )
            })?;
            self.output.push(LlmOutputPart::Unknown(part));
        } else {
            push_warning_once(
                &mut self.warnings,
                "unmodeled provider content omitted by raw-retention policy",
            );
        }
        Ok(())
    }
}

pub(crate) fn normalize_response(
    expected_provider: CatalogProvider,
    configured_model: &str,
    request_id: &LlmRequestId,
    tool_capabilities: &BTreeMap<String, Option<String>>,
    raw_policy: RawRetentionPolicy,
    created_at: OffsetDateTime,
    mut completion: CompletionResponse,
) -> Result<NormalizedCompletion, ProviderError> {
    if completion.provider != expected_provider.rig_descriptor() {
        return Err(schema_error_with_raw(
            expected_provider,
            raw_policy,
            completion.raw,
        ));
    }
    let identity = response_identity(
        expected_provider,
        configured_model,
        request_id,
        &mut completion,
    );
    let mut warnings = if raw_policy == RawRetentionPolicy::Full {
        raw_warnings(&completion.raw)
    } else {
        Vec::new()
    };
    if let Some(warning) = identity.finish_warning {
        push_warning_once(&mut warnings, warning);
    }
    let choices = std::mem::take(&mut completion.choice);
    let context = NormalizationContext {
        provider: expected_provider,
        raw_policy,
        response_id: &identity.response_id,
        capabilities: tool_capabilities,
        raw: &completion.raw,
    };
    let state = normalize_content(&context, choices, warnings)?;
    let usage = normalize_usage(completion.usage);
    let retained_raw = RetainedRaw::from_value(raw_policy, std::mem::take(&mut completion.raw));
    let unmodeled_parts = state.unmodeled_parts;
    let private_reasoning_blocks = state.private_reasoning_blocks;
    let response = assemble_response(
        expected_provider,
        request_id,
        identity,
        state,
        usage,
        &retained_raw,
        created_at,
    )?;
    Ok(NormalizedCompletion {
        response,
        raw: retained_raw,
        unmodeled_parts,
        private_reasoning_blocks,
    })
}

fn response_identity(
    provider: CatalogProvider,
    configured_model: &str,
    request_id: &LlmRequestId,
    completion: &mut CompletionResponse,
) -> ResponseIdentity {
    let (status, stop_reason, finish_warning) =
        normalize_finish_reason(completion.finish_reason().as_ref());
    let provider_response_id = completion
        .response_id
        .take()
        .filter(|value| !value.trim().is_empty());
    let provider_request_id = completion
        .provider_request_id
        .take()
        .filter(|value| !value.trim().is_empty());
    let message_id = completion
        .message_id
        .take()
        .filter(|value| !value.trim().is_empty());
    let model = completion
        .model
        .take()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| configured_model.to_owned());
    let response_id = stable_response_id(
        request_id,
        provider,
        &model,
        provider_response_id.as_deref(),
        provider_request_id.as_deref(),
        message_id.as_deref(),
        completion,
    );
    ResponseIdentity {
        status,
        stop_reason,
        finish_warning,
        provider_response_id,
        provider_request_id,
        message_id,
        model,
        response_id,
    }
}

fn normalize_content(
    context: &NormalizationContext<'_>,
    choices: Vec<AssistantContent>,
    warnings: Vec<String>,
) -> Result<NormalizationState, ProviderError> {
    let mut state = NormalizationState::new(choices.len(), warnings);
    for (index, content) in choices.into_iter().enumerate() {
        match content {
            AssistantContent::Text(text) => {
                normalize_text(context, index, text, &mut state)?;
            }
            AssistantContent::ToolCall(call) => {
                normalize_tool_call(context, index, call, &mut state)?;
            }
            AssistantContent::Reasoning(reasoning) => {
                normalize_reasoning(context, index, reasoning, &mut state)?;
            }
            AssistantContent::Image(image) => {
                normalize_image(context, index, image, &mut state)?;
            }
        }
    }
    Ok(state)
}

fn normalize_text(
    context: &NormalizationContext<'_>,
    index: usize,
    text: rig_core::message::Text,
    state: &mut NormalizationState,
) -> Result<(), ProviderError> {
    let rig_core::message::Text {
        text,
        additional_params,
    } = text;
    let id = part_id(context.response_id, index, 0);
    let part = TextOutputPart::new(id, text, Some(TextFormat::Plain))
        .map_err(|_| context.schema_error())?;
    state.output.push(LlmOutputPart::Text(part));
    if let Some(additional) = additional_params {
        state.unmodeled_parts = state.unmodeled_parts.saturating_add(1);
        let payload = serde_json::to_value(additional).map_err(|_| context.schema_error())?;
        state.retain_unknown(context, index, 1, "rig_text_additional_params", payload)?;
    }
    Ok(())
}

fn assemble_response(
    provider: CatalogProvider,
    request_id: &LlmRequestId,
    identity: ResponseIdentity,
    state: NormalizationState,
    usage: Usage,
    retained_raw: &RetainedRaw,
    created_at: OffsetDateTime,
) -> Result<LlmResponse, ProviderError> {
    let NormalizationState {
        output, warnings, ..
    } = state;
    let mut response = LlmResponse::new(
        request_id.clone(),
        identity.response_id,
        provider.as_str().to_owned(),
        identity.model,
        identity.status,
        identity.stop_reason.clone(),
        output,
        usage,
        created_at,
    )
    .map_err(|_| {
        retained_schema_error(provider, identity.provider_request_id.clone(), retained_raw)
    })?
    .with_provider_ids(
        identity.provider_response_id,
        identity.provider_request_id.clone(),
    )
    .map_err(|_| {
        retained_schema_error(provider, identity.provider_request_id.clone(), retained_raw)
    })?;
    if let Some(message_id) = identity.message_id {
        let candidate = Candidate::new(0, identity.status, response.output().to_vec())
            .and_then(|candidate| {
                candidate.with_details(Some(message_id), identity.stop_reason, None)
            })
            .map_err(|_| {
                retained_schema_error(provider, identity.provider_request_id, retained_raw)
            })?;
        response = response
            .with_candidates(Some(0), vec![candidate])
            .map_err(|_| retained_schema_error(provider, None, retained_raw))?;
    }
    response = response.with_metadata((!warnings.is_empty()).then_some(warnings), None);
    response.validate().map_err(|_| {
        retained_schema_error(
            provider,
            response.provider_request_id().map(str::to_owned),
            retained_raw,
        )
    })?;
    Ok(response)
}

fn retained_schema_error(
    provider: CatalogProvider,
    provider_request_id: Option<String>,
    retained_raw: &RetainedRaw,
) -> ProviderError {
    ProviderError::new(
        provider.as_str().to_owned(),
        ProviderErrorKind::Schema,
        RetryClass::Never,
    )
    .with_transport_metadata(None, None, provider_request_id, retained_raw.clone())
}

fn normalize_tool_call(
    context: &NormalizationContext<'_>,
    index: usize,
    call: ToolCall,
    state: &mut NormalizationState,
) -> Result<(), ProviderError> {
    let id = part_id(context.response_id, index, 0);
    let call_id = call
        .provider
        .as_ref()
        .map(|provider| provider.call_id.as_str())
        .filter(|call_id| !call_id.trim().is_empty())
        .map_or_else(
            || format!("{}-call-{index}", context.response_id),
            str::to_owned,
        );
    let capability_id = context
        .capabilities
        .get(&call.function.name)
        .and_then(Clone::clone);
    let mut metadata = JsonObject::new();
    if let Some(provider_id) = &call.provider {
        metadata.insert(
            "provider_call_id".to_owned(),
            Value::String(provider_id.call_id.clone()),
        );
        if let Some(item_id) = &provider_id.item_id {
            metadata.insert(
                "provider_item_id".to_owned(),
                Value::String(item_id.clone()),
            );
        }
    }
    if let Some(signature) = &call.signature {
        metadata.insert(
            "provider_signature".to_owned(),
            Value::String(signature.clone()),
        );
    }
    let part = ToolCallOutputPart::new(id, call_id, call.function.name, call.function.arguments)
        .and_then(|part| {
            part.with_provenance(
                capability_id,
                None,
                (!metadata.is_empty()).then_some(metadata),
            )
        })
        .map_err(|_| context.schema_error())?;
    state.output.push(LlmOutputPart::ToolCall(part));
    if let Some(additional) = call.additional_params {
        state.unmodeled_parts = state.unmodeled_parts.saturating_add(1);
        state.retain_unknown(
            context,
            index,
            1,
            "rig_tool_call_additional_params",
            additional,
        )?;
    }
    Ok(())
}

fn normalize_reasoning(
    context: &NormalizationContext<'_>,
    index: usize,
    reasoning: Reasoning,
    state: &mut NormalizationState,
) -> Result<(), ProviderError> {
    let mut metadata = JsonObject::new();
    if let Some(reasoning_id) = reasoning.id {
        metadata.insert(
            "provider_reasoning_id".to_owned(),
            Value::String(reasoning_id),
        );
    }
    let metadata = (!metadata.is_empty()).then_some(metadata);
    for (subindex, content) in reasoning.content.into_iter().enumerate() {
        let part = match content {
            ReasoningContent::Text { signature, .. } => {
                state.private_reasoning_blocks = state.private_reasoning_blocks.saturating_add(1);
                push_warning_once(&mut state.warnings, "private reasoning text omitted");
                let Some(signature) = signature else {
                    continue;
                };
                Some((ReasoningRepresentation::Signature, signature))
            }
            ReasoningContent::Encrypted(data) | ReasoningContent::Redacted { data } => {
                Some((ReasoningRepresentation::OpaqueEncrypted, data))
            }
            ReasoningContent::Summary(summary) => Some((ReasoningRepresentation::Summary, summary)),
        };
        let Some((representation, data)) = part else {
            continue;
        };
        let part = ReasoningOutputPart::new(
            part_id(context.response_id, index, subindex),
            representation,
            data,
        )
        .and_then(|part| part.with_metadata(None, metadata.clone()))
        .map_err(|_| context.schema_error())?;
        state.output.push(LlmOutputPart::Reasoning(part));
    }
    Ok(())
}

fn normalize_image(
    context: &NormalizationContext<'_>,
    index: usize,
    image: Image,
    state: &mut NormalizationState,
) -> Result<(), ProviderError> {
    let raw_image = serde_json::to_value(&image).map_err(|_| context.schema_error())?;
    let Some(media_type) = image.media_type.as_ref().map(MimeType::to_mime_type) else {
        state.unmodeled_parts = state.unmodeled_parts.saturating_add(1);
        return state.retain_unknown(context, index, 0, "rig_image", raw_image);
    };
    let source = match image.data {
        DocumentSourceKind::Url(url) => BinarySource::url(url),
        DocumentSourceKind::Base64(data) => BinarySource::inline(data),
        DocumentSourceKind::Raw(bytes) => BinarySource::inline(BASE64_STANDARD.encode(bytes)),
        DocumentSourceKind::FileId(_)
        | DocumentSourceKind::String(_)
        | DocumentSourceKind::Unknown => {
            state.unmodeled_parts = state.unmodeled_parts.saturating_add(1);
            return state.retain_unknown(context, index, 0, "rig_image", raw_image);
        }
    }
    .map_err(|_| context.schema_error())?;
    let part = ImageOutputPart::new(
        part_id(context.response_id, index, 0),
        media_type.to_owned(),
        source,
    )
    .map_err(|_| context.schema_error())?;
    state.output.push(LlmOutputPart::Image(part));
    if image.detail.is_some() || image.additional_params.is_some() {
        state.unmodeled_parts = state.unmodeled_parts.saturating_add(1);
        state.retain_unknown(context, index, 1, "rig_image_additional_params", raw_image)?;
    }
    Ok(())
}

fn normalize_usage(usage: rig_core::completion::Usage) -> Usage {
    let known = usage.has_values();
    let token = |value| (known && value != 0).then_some(value);
    let cached = token(usage.cached_input_tokens);
    let mut provider_units = JsonObject::new();
    if usage.total_tokens != 0 {
        provider_units.insert(
            "rig_total_tokens".to_owned(),
            Value::from(usage.total_tokens),
        );
    }
    if usage.tool_use_prompt_tokens != 0 {
        provider_units.insert(
            "rig_tool_use_prompt_tokens".to_owned(),
            Value::from(usage.tool_use_prompt_tokens),
        );
    }
    Usage::new(token(usage.input_tokens), token(usage.output_tokens))
        .with_token_details(
            cached,
            cached,
            token(usage.cache_creation_input_tokens),
            token(usage.reasoning_tokens),
            None,
            None,
        )
        .with_costs(
            None,
            None,
            (!provider_units.is_empty()).then_some(provider_units),
        )
}

fn normalize_finish_reason(
    reason: Option<&FinishReason>,
) -> (CompletionStatus, Option<String>, Option<&'static str>) {
    match reason {
        None => (CompletionStatus::Completed, None, None),
        Some(FinishReason::Stop) => (CompletionStatus::Completed, Some("stop".to_owned()), None),
        Some(FinishReason::Length) => (CompletionStatus::Partial, Some("length".to_owned()), None),
        Some(FinishReason::ToolCalls) => (
            CompletionStatus::Completed,
            Some("tool_calls".to_owned()),
            None,
        ),
        Some(FinishReason::ContentFilter) => (
            CompletionStatus::Refused,
            Some("content_filter".to_owned()),
            None,
        ),
        Some(FinishReason::Other(reason)) => {
            let (status, warning) = if ["cancel", "cancelled", "canceled"]
                .iter()
                .any(|known| reason.eq_ignore_ascii_case(known))
            {
                (CompletionStatus::Cancelled, None)
            } else if ["failed", "error"]
                .iter()
                .any(|known| reason.eq_ignore_ascii_case(known))
            {
                (CompletionStatus::Failed, None)
            } else if reason.eq_ignore_ascii_case("interrupted") {
                (CompletionStatus::Partial, None)
            } else {
                (
                    CompletionStatus::Failed,
                    Some("unknown provider finish reason treated as failed"),
                )
            };
            (status, Some(reason.clone()), warning)
        }
    }
}

fn raw_warnings(raw: &Value) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(values) = raw.get("warnings").and_then(Value::as_array) {
        warnings.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(warning) = raw.get("warning").and_then(Value::as_str) {
        warnings.push(warning.to_owned());
    }
    warnings
}

fn push_warning_once(warnings: &mut Vec<String>, warning: &str) {
    if !warnings.iter().any(|current| current == warning) {
        warnings.push(warning.to_owned());
    }
}

fn part_id(response_id: &str, index: usize, subindex: usize) -> String {
    format!("{response_id}-part-{index}-{subindex}")
}

fn stable_response_id(
    request_id: &LlmRequestId,
    provider: CatalogProvider,
    model: &str,
    provider_response_id: Option<&str>,
    provider_request_id: Option<&str>,
    message_id: Option<&str>,
    completion: &CompletionResponse,
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        request_id.as_str(),
        provider.as_str(),
        model,
        provider_response_id.unwrap_or_default(),
        message_id.unwrap_or_default(),
        provider_request_id.unwrap_or_default(),
    ] {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(value.as_bytes());
    }
    let _ = serde_json::to_writer(DigestWriter(&mut hasher), &completion.raw);
    let digest = hasher.finalize();
    let mut id = String::with_capacity(45);
    id.push_str("rig-response-");
    for byte in digest.iter().take(16) {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

struct DigestWriter<'a>(&'a mut Sha256);

impl io::Write for DigestWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0.update(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn schema_error_with_raw(
    provider: CatalogProvider,
    policy: RawRetentionPolicy,
    raw: Value,
) -> ProviderError {
    ProviderError::new(
        provider.as_str().to_owned(),
        ProviderErrorKind::Schema,
        RetryClass::Never,
    )
    .with_transport_metadata(None, None, None, RetainedRaw::from_value(policy, raw))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, error::Error};

    use omnius_llm_core::{
        CompletionStatus, LlmOutputPart, LlmRequestId, RawRetentionPolicy, RawRetentionState,
        ReasoningRepresentation,
    };
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    use crate::CatalogProvider;
    use rig_core::completion::{CompletionResponse, FinishReason};

    use super::{NormalizedCompletion, normalize_finish_reason, normalize_response};
    const OPENAI: &str = include_str!("../tests/fixtures/openai-rig-response.json");
    const ANTHROPIC: &str = include_str!("../tests/fixtures/anthropic-rig-response.json");
    const GEMINI: &str = include_str!("../tests/fixtures/gemini-rig-response.json");
    const GEMINI_IDLESS_TOOL: &str =
        include_str!("../tests/fixtures/gemini-idless-tool-rig-response.json");
    const OPENROUTER: &str = include_str!("../tests/fixtures/openrouter-rig-response.json");
    const BEDROCK: &str =
        include_str!("../../llm-provider-bedrock/tests/fixtures/bedrock-rig-response.json");
    const VERTEX: &str =
        include_str!("../../llm-provider-vertex/tests/fixtures/vertex-rig-response.json");

    fn normalized(
        provider: CatalogProvider,
        cassette: &str,
        policy: RawRetentionPolicy,
    ) -> Result<NormalizedCompletion, Box<dyn Error>> {
        let completion: CompletionResponse = serde_json::from_str(cassette)?;
        let created_at = OffsetDateTime::parse("2026-08-29T12:00:00Z", &Rfc3339)?;
        normalize_response(
            provider,
            "configured-model",
            &LlmRequestId::new("canonical-request-1".to_owned())?,
            &BTreeMap::new(),
            policy,
            created_at,
            completion,
        )
        .map_err(Into::into)
    }

    #[test]
    fn all_direct_provider_cassettes_normalize_deterministically() -> Result<(), Box<dyn Error>> {
        for (provider, cassette) in [
            (CatalogProvider::OpenAi, OPENAI),
            (CatalogProvider::Anthropic, ANTHROPIC),
            (CatalogProvider::Gemini, GEMINI),
            (CatalogProvider::OpenRouter, OPENROUTER),
        ] {
            let first = normalized(provider, cassette, RawRetentionPolicy::Full)?;
            let second = normalized(provider, cassette, RawRetentionPolicy::Full)?;
            assert_eq!(
                serde_json::to_value(&first.response)?,
                serde_json::to_value(&second.response)?
            );
        }
        Ok(())
    }

    #[test]
    fn companion_terminal_cassettes_normalize_ids_usage_and_raw_payloads()
    -> Result<(), Box<dyn Error>> {
        for (
            provider,
            cassette,
            model,
            provider_request_id,
            provider_response_id,
            input_tokens,
            output_tokens,
        ) in [
            (
                CatalogProvider::Bedrock,
                BEDROCK,
                "bedrock-runtime-fixture",
                Some("aws-request-fixture-1"),
                None,
                17,
                6,
            ),
            (
                CatalogProvider::Vertex,
                VERTEX,
                "vertex-runtime-fixture",
                None,
                Some("vertex-response-fixture-1"),
                13,
                4,
            ),
        ] {
            let first = normalized(provider, cassette, RawRetentionPolicy::Full)?;
            let second = normalized(provider, cassette, RawRetentionPolicy::Full)?;
            assert_eq!(first.response.provider(), provider.as_str());
            assert_eq!(first.response.model(), model);
            assert_eq!(first.response.provider_request_id(), provider_request_id);
            assert_eq!(first.response.provider_response_id(), provider_response_id);
            assert_eq!(first.response.status(), CompletionStatus::Completed);
            assert_eq!(first.response.usage().input_tokens(), Some(input_tokens));
            assert_eq!(first.response.usage().output_tokens(), Some(output_tokens));
            assert_eq!(first.raw.state(), RawRetentionState::Full);
            assert_eq!(
                serde_json::to_value(&first.response)?,
                serde_json::to_value(&second.response)?
            );
        }
        Ok(())
    }

    #[test]
    fn openai_cassette_preserves_ids_usage_warnings_and_safe_reasoning()
    -> Result<(), Box<dyn Error>> {
        let normalized = normalized(CatalogProvider::OpenAi, OPENAI, RawRetentionPolicy::Full)?;
        let response = &normalized.response;
        assert_eq!(response.provider_response_id(), Some("resp_openai_1"));
        assert_eq!(response.provider_request_id(), Some("req_openai_1"));
        assert_eq!(response.stop_reason(), Some("stop"));
        assert_eq!(response.status(), CompletionStatus::Completed);
        assert_eq!(response.usage().input_tokens(), Some(21));
        assert_eq!(response.usage().output_tokens(), Some(9));
        assert_eq!(response.usage().cached_input_tokens(), Some(5));
        assert_eq!(response.usage().cache_read_tokens(), Some(5));
        assert_eq!(response.usage().cache_write_tokens(), Some(2));
        assert_eq!(response.usage().reasoning_tokens(), Some(4));
        assert_eq!(
            response
                .candidates()
                .and_then(|values| values.first())
                .and_then(omnius_llm_core::Candidate::id),
            Some("msg_openai_1")
        );
        assert!(response.warnings().is_some_and(|warnings| {
            warnings.iter().any(|warning| warning == "provider warning")
                && warnings
                    .iter()
                    .any(|warning| warning == "private reasoning text omitted")
        }));
        assert!(response.output().iter().any(|part| {
            matches!(
                part,
                LlmOutputPart::Reasoning(reasoning)
                    if reasoning.representation() == ReasoningRepresentation::Summary
            )
        }));
        assert!(response.output().iter().any(|part| {
            matches!(
                part,
                LlmOutputPart::Reasoning(reasoning)
                    if reasoning.representation() == ReasoningRepresentation::Signature
                        && reasoning.data() == "sig_1"
            )
        }));
        assert_eq!(normalized.unmodeled_parts, 1);
        assert_eq!(normalized.private_reasoning_blocks, 1);
        Ok(())
    }

    #[test]
    fn cassettes_cover_partial_tool_image_and_opaque_reasoning_parts() -> Result<(), Box<dyn Error>>
    {
        let anthropic = normalized(
            CatalogProvider::Anthropic,
            ANTHROPIC,
            RawRetentionPolicy::Full,
        )?;
        assert_eq!(anthropic.response.status(), CompletionStatus::Partial);
        assert!(anthropic.response.output().iter().any(|part| {
            matches!(
                part,
                LlmOutputPart::Reasoning(reasoning)
                    if reasoning.representation() == ReasoningRepresentation::OpaqueEncrypted
            )
        }));

        let gemini = normalized(CatalogProvider::Gemini, GEMINI, RawRetentionPolicy::Full)?;
        assert!(
            gemini
                .response
                .output()
                .iter()
                .any(|part| matches!(part, LlmOutputPart::Image(_)))
        );
        assert_eq!(gemini.response.status(), CompletionStatus::Failed);
        assert_eq!(gemini.response.stop_reason(), Some("SAFETY_REVIEWED"));
        assert!(gemini.response.warnings().is_some_and(|warnings| {
            warnings
                .iter()
                .any(|warning| warning == "unknown provider finish reason treated as failed")
        }));

        let openrouter = normalized(
            CatalogProvider::OpenRouter,
            OPENROUTER,
            RawRetentionPolicy::Full,
        )?;
        assert_eq!(openrouter.response.stop_reason(), Some("tool_calls"));
        assert!(
            openrouter
                .response
                .output()
                .iter()
                .any(|part| matches!(part, LlmOutputPart::ToolCall(_)))
        );
        assert!(openrouter.response.output().iter().any(|part| {
            matches!(
                part,
                LlmOutputPart::ToolCall(call) if call.call_id() == "call_router_1"
            )
        }));
        Ok(())
    }

    #[test]
    fn other_finish_reasons_only_map_known_terminal_signals() {
        assert_eq!(
            normalize_finish_reason(Some(&FinishReason::Other("cancelled".to_owned()))).0,
            CompletionStatus::Cancelled
        );
        assert_eq!(
            normalize_finish_reason(Some(&FinishReason::Other("failed".to_owned()))).0,
            CompletionStatus::Failed
        );
        assert_eq!(
            normalize_finish_reason(Some(&FinishReason::Other("interrupted".to_owned()))).0,
            CompletionStatus::Partial
        );
        let unknown = normalize_finish_reason(Some(&FinishReason::Other("new_reason".to_owned())));
        assert_eq!(unknown.0, CompletionStatus::Failed);
        assert!(unknown.2.is_some());
    }

    #[test]
    fn idless_gemini_tool_call_ids_ignore_rig_minted_ids() -> Result<(), Box<dyn Error>> {
        let mut first: serde_json::Value = serde_json::from_str(GEMINI_IDLESS_TOOL)?;
        let mut second = first.clone();
        first["choice"][0]["id"] = serde_json::Value::String("rig-minted-a".to_owned());
        second["choice"][0]["id"] = serde_json::Value::String("rig-minted-b".to_owned());

        let first = normalized(
            CatalogProvider::Gemini,
            &serde_json::to_string(&first)?,
            RawRetentionPolicy::Discard,
        )?;
        let second = normalized(
            CatalogProvider::Gemini,
            &serde_json::to_string(&second)?,
            RawRetentionPolicy::Discard,
        )?;
        assert_eq!(first.response.response_id(), second.response.response_id());
        let call_id = |normalized: &NormalizedCompletion| {
            normalized
                .response
                .output()
                .iter()
                .find_map(|part| match part {
                    LlmOutputPart::ToolCall(call) => Some(call.call_id().to_owned()),
                    _ => None,
                })
        };
        assert_eq!(call_id(&first), call_id(&second));
        Ok(())
    }

    #[test]
    fn raw_policy_is_explicit_and_debug_never_prints_payload() -> Result<(), Box<dyn Error>> {
        let discarded = normalized(CatalogProvider::OpenAi, OPENAI, RawRetentionPolicy::Discard)?;
        let redacted = normalized(
            CatalogProvider::OpenAi,
            OPENAI,
            RawRetentionPolicy::Redacted,
        )?;
        let full = normalized(CatalogProvider::OpenAi, OPENAI, RawRetentionPolicy::Full)?;
        assert_eq!(discarded.raw.state(), RawRetentionState::Discarded);
        assert!(!discarded.response.warnings().is_some_and(|warnings| {
            warnings.iter().any(|warning| warning == "provider warning")
        }));
        assert_eq!(redacted.raw.state(), RawRetentionState::Redacted);
        assert_eq!(full.raw.state(), RawRetentionState::Full);
        assert!(discarded.raw.full_payload().is_none());
        assert!(redacted.raw.redacted_summary().is_some());
        assert!(full.raw.full_payload().is_some());
        let debug = format!("{:?}", full.raw);
        assert!(!debug.contains("opaque_future"));
        assert!(!debug.contains("private chain"));
        Ok(())
    }
}
