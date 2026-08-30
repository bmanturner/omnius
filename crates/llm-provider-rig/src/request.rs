use std::collections::BTreeMap;

use omnius_llm_core::{
    GenerationConfig, LlmInputPart, LlmMessage, LlmRequest, MessageRole, OutputMode, ProviderError,
    ProviderErrorKind, RetainedRaw, RetryClass, SchemaDefinition, ToolDefinition,
    UnsupportedFeature,
};
use rig_core::{
    completion::{CompletionRequest, ToolDefinition as RigToolDefinition},
    message::{AssistantContent, Message, Text, ToolChoice, UserContent},
};
use serde_json::Value;

use crate::{DirectProvider, raw::serialized_len};

pub(crate) struct PreparedRequest {
    pub(crate) request: CompletionRequest,
    pub(crate) max_tool_calls: u32,
    pub(crate) max_output_bytes: Option<u64>,
    pub(crate) tool_capabilities: BTreeMap<String, Option<String>>,
}

struct PreparedTools {
    definitions: Vec<RigToolDefinition>,
    capabilities: BTreeMap<String, Option<String>>,
}

pub(crate) fn prepare_request(
    provider: DirectProvider,
    configured_model: &str,
    request: &LlmRequest,
) -> Result<PreparedRequest, ProviderError> {
    reject_untranslated_context(provider, request)?;
    reject_system_message_order(provider, configured_model, request.messages())?;

    let limits = request.limits();
    if limits.max_cost_microunits().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::CostLimit,
        ));
    }
    if limits
        .max_input_bytes()
        .is_some_and(|limit| serialized_len(request) > limit)
    {
        return Err(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Safety,
            RetryClass::Never,
        )
        .with_transport_metadata(None, None, None, RetainedRaw::discarded()));
    }

    let generation = request.generation();
    reject_unsupported_generation(provider, generation)?;
    let output_schema = output_schema(provider, request)?;
    let PreparedTools {
        definitions: tools,
        capabilities: tool_capabilities,
    } = tools(provider, request.tools())?;

    let chat_history = request
        .messages()
        .iter()
        .map(|message| message_to_rig(provider, message))
        .collect::<Result<Vec<_>, _>>()?;
    if chat_history.is_empty() {
        return Err(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Schema,
            RetryClass::Never,
        ));
    }

    let request = CompletionRequest {
        model: None,
        preamble: None,
        chat_history,
        documents: Vec::new(),
        tools,
        temperature: generation.and_then(GenerationConfig::temperature),
        max_tokens: generation.and_then(GenerationConfig::max_output_tokens),
        tool_choice: request
            .tools()
            .is_some_and(|tools| !tools.is_empty() && limits.max_tool_calls() == 0)
            .then_some(ToolChoice::None),
        additional_params: None,
        output_schema,
        record_telemetry_content: false,
    };
    request.validate_message_content().map_err(|_| {
        ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Schema,
            RetryClass::Never,
        )
    })?;

    Ok(PreparedRequest {
        request,
        max_tool_calls: limits.max_tool_calls(),
        max_output_bytes: limits.max_output_bytes(),
        tool_capabilities,
    })
}

fn reject_untranslated_context(
    provider: DirectProvider,
    request: &LlmRequest,
) -> Result<(), ProviderError> {
    if request.tool_policy().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::ToolPolicy,
        ));
    }
    if request.metadata().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::RequestMetadata,
        ));
    }
    if request.data_policy().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::DataPolicy,
        ));
    }
    if request.principal_context().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::PrincipalContext,
        ));
    }
    if request.tenant_context().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::TenantContext,
        ));
    }
    Ok(())
}

fn reject_unsupported_generation(
    provider: DirectProvider,
    generation: Option<&GenerationConfig>,
) -> Result<(), ProviderError> {
    let Some(generation) = generation else {
        return Ok(());
    };
    if generation.top_p().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::TopP,
        ));
    }
    if generation.candidate_count().is_some_and(|count| count != 1) {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::CandidateCount,
        ));
    }
    if !generation.stop().is_empty() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::StopSequences,
        ));
    }
    if generation.seed().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::Seed,
        ));
    }
    Ok(())
}

fn output_schema(
    provider: DirectProvider,
    request: &LlmRequest,
) -> Result<Option<rig_core::schemars::Schema>, ProviderError> {
    let output = request.output();
    if output.strict().is_some()
        || output.schema().is_some()
        || output.schema_id().is_some()
        || output.mode() == OutputMode::Structured
    {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::StructuredOutputRequiresValidation,
        ));
    }
    if !output.mime_types().is_empty() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::OutputMimeTypes,
        ));
    }

    match output.mode() {
        OutputMode::Auto | OutputMode::Text => Ok(None),
        OutputMode::Structured => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::StructuredOutputRequiresValidation,
        )),
        OutputMode::Tools => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::ToolOutputMode,
        )),
        OutputMode::Media => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::MediaOutputMode,
        )),
    }
}

fn reject_system_message_order(
    provider: DirectProvider,
    configured_model: &str,
    messages: &[LlmMessage],
) -> Result<(), ProviderError> {
    if configured_model.trim().is_empty() {
        return Err(ProviderError::new(
            provider.as_str().to_owned(),
            ProviderErrorKind::Schema,
            RetryClass::Never,
        ));
    }
    if !matches!(provider, DirectProvider::Anthropic | DirectProvider::Gemini) {
        return Ok(());
    }

    let mut saw_non_system = false;
    for message in messages {
        if message.role() == MessageRole::System {
            if saw_non_system {
                return Err(ProviderError::unsupported(
                    provider.as_str().to_owned(),
                    UnsupportedFeature::SystemMessageOrder,
                ));
            }
        } else {
            saw_non_system = true;
        }
    }
    Ok(())
}

fn schema_value(schema: &SchemaDefinition) -> Value {
    match schema {
        SchemaDefinition::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        ),
        SchemaDefinition::Boolean(value) => Value::Bool(*value),
    }
}

fn tools(
    provider: DirectProvider,
    definitions: Option<&[ToolDefinition]>,
) -> Result<PreparedTools, ProviderError> {
    let Some(definitions) = definitions else {
        return Ok(PreparedTools {
            definitions: Vec::new(),
            capabilities: BTreeMap::new(),
        });
    };
    let mut tools = Vec::with_capacity(definitions.len());
    let mut capabilities = BTreeMap::new();
    for definition in definitions {
        if definition.output_schema().is_some() {
            return Err(ProviderError::unsupported(
                provider.as_str().to_owned(),
                UnsupportedFeature::ToolOutputSchema,
            ));
        }
        tools.push(RigToolDefinition {
            name: definition.name().to_owned(),
            description: definition.description().unwrap_or_default().to_owned(),
            parameters: schema_value(definition.input_schema()),
        });
        capabilities.insert(
            definition.name().to_owned(),
            definition.capability_id().map(str::to_owned),
        );
    }
    Ok(PreparedTools {
        definitions: tools,
        capabilities,
    })
}

fn message_to_rig(
    provider: DirectProvider,
    message: &LlmMessage,
) -> Result<Message, ProviderError> {
    if message.name().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::MessageName,
        ));
    }
    if message.metadata().is_some() {
        return Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::MessageMetadata,
        ));
    }

    match message.role() {
        MessageRole::System => {
            if message.id().is_some() {
                return Err(ProviderError::unsupported(
                    provider.as_str().to_owned(),
                    UnsupportedFeature::MessageIdentity,
                ));
            }
            if message.content().len() != 1 {
                return Err(ProviderError::unsupported(
                    provider.as_str().to_owned(),
                    UnsupportedFeature::SystemContentShape,
                ));
            }
            Ok(Message::System {
                content: text_content(provider, &message.content()[0])?,
            })
        }
        MessageRole::Developer => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::DeveloperMessage,
        )),
        MessageRole::User => {
            if message.id().is_some() {
                return Err(ProviderError::unsupported(
                    provider.as_str().to_owned(),
                    UnsupportedFeature::MessageIdentity,
                ));
            }
            let content = message
                .content()
                .iter()
                .map(|part| {
                    text_content(provider, part).map(|text| UserContent::Text(Text::new(text)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if content.is_empty() {
                return Err(ProviderError::new(
                    provider.as_str().to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                ));
            }
            Ok(Message::User { content })
        }
        MessageRole::Assistant => {
            let content = message
                .content()
                .iter()
                .map(|part| {
                    text_content(provider, part).map(|text| AssistantContent::Text(Text::new(text)))
                })
                .collect::<Result<Vec<_>, _>>()?;
            if content.is_empty() {
                return Err(ProviderError::new(
                    provider.as_str().to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                ));
            }
            Ok(Message::Assistant {
                id: message.id().map(str::to_owned),
                content,
            })
        }
        MessageRole::Tool => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::ToolMessage,
        )),
    }
}

fn text_content(provider: DirectProvider, part: &LlmInputPart) -> Result<String, ProviderError> {
    match part {
        LlmInputPart::Text(text) => Ok(text.text().to_owned()),
        LlmInputPart::Structured(structured) => {
            serde_json::to_string(structured.value()).map_err(|_| {
                ProviderError::new(
                    provider.as_str().to_owned(),
                    ProviderErrorKind::Schema,
                    RetryClass::Never,
                )
            })
        }
        LlmInputPart::Image(_) | LlmInputPart::Audio(_) | LlmInputPart::Video(_) => {
            Err(ProviderError::unsupported(
                provider.as_str().to_owned(),
                UnsupportedFeature::MediaInput,
            ))
        }
        LlmInputPart::File(_) => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::FileInput,
        )),
        LlmInputPart::Resource(_) => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::ResourceInput,
        )),
        LlmInputPart::ToolResult(_) => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::ToolResultInput,
        )),
        _ => Err(ProviderError::unsupported(
            provider.as_str().to_owned(),
            UnsupportedFeature::UnknownInputPart,
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use omnius_llm_core::{
        JsonObject, LlmInputPart, LlmMessage, LlmRequest, LlmRequestId, MessageRole, OutputMode,
        OutputRequest, RequestLimits, Route, SchemaDefinition, ToolDefinition, UnsupportedFeature,
    };
    use rig_core::message::{Message, UserContent};
    use serde_json::{Value, json};

    use super::prepare_request;
    use crate::DirectProvider;

    #[test]
    fn conversion_preserves_text_structured_order_and_tool_schema() -> Result<(), Box<dyn Error>> {
        let message = LlmMessage::new(
            MessageRole::User,
            vec![
                LlmInputPart::text("first".to_owned()),
                LlmInputPart::structured(json!({"second": 2})),
                LlmInputPart::text("third".to_owned()),
            ],
        )?;
        let mut input_schema = JsonObject::new();
        input_schema.insert("type".to_owned(), Value::String("object".to_owned()));
        let tool =
            ToolDefinition::new("lookup".to_owned(), SchemaDefinition::Object(input_schema))?
                .with_details(
                    Some("Lookup a value".to_owned()),
                    Some("capability.lookup".to_owned()),
                    None,
                )?;
        let request = LlmRequest::new(
            LlmRequestId::new("request-order".to_owned())?,
            Route::new("direct".to_owned(), None, Vec::new(), Vec::new())?,
            vec![message],
            OutputRequest::new(OutputMode::Text),
            RequestLimits::new(1_000, 1, 4)?,
        )?
        .with_tools(vec![tool], None)?;

        let prepared = prepare_request(DirectProvider::OpenAi, "fixture-model", &request)?;
        let Message::User { content } = &prepared.request.chat_history[0] else {
            return Err("user role changed during conversion".into());
        };
        let text = content
            .iter()
            .map(|part| match part {
                UserContent::Text(text) => Some(text.text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            text,
            vec![Some("first"), Some("{\"second\":2}"), Some("third")]
        );
        assert_eq!(prepared.request.tools[0].name, "lookup");
        assert_eq!(
            prepared.request.tools[0].parameters,
            json!({"type": "object"})
        );
        assert_eq!(
            prepared
                .tool_capabilities
                .get("lookup")
                .and_then(Clone::clone)
                .as_deref(),
            Some("capability.lookup")
        );
        Ok(())
    }

    #[test]
    fn anthropic_and_gemini_reject_system_messages_after_conversation_starts()
    -> Result<(), Box<dyn Error>> {
        let messages = vec![
            LlmMessage::new(
                MessageRole::User,
                vec![LlmInputPart::text("question".to_owned())],
            )?,
            LlmMessage::new(
                MessageRole::System,
                vec![LlmInputPart::text("late instruction".to_owned())],
            )?,
        ];
        let request = LlmRequest::new(
            LlmRequestId::new("request-late-system".to_owned())?,
            Route::new("direct".to_owned(), None, Vec::new(), Vec::new())?,
            messages,
            OutputRequest::new(OutputMode::Text),
            RequestLimits::new(1_000, 1, 4)?,
        )?;

        for provider in [DirectProvider::Anthropic, DirectProvider::Gemini] {
            let Err(error) = prepare_request(provider, "fixture-model", &request) else {
                return Err("late system message was accepted".into());
            };
            assert_eq!(
                error.unsupported_feature(),
                Some(UnsupportedFeature::SystemMessageOrder)
            );
        }
        Ok(())
    }
}
