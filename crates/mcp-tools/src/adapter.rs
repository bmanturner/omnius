use std::{borrow::Cow, collections::BTreeMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use omnius_agent_capability_registry::ConfirmationEvidence;
use omnius_mcp_server_core::{
    McpRequestContext,
    sdk::{McpAdapterFuture, McpToolAdapter},
};
use rmcp::{
    ErrorData,
    model::{
        CacheScope, CallToolRequestParams, CallToolResponse, CallToolResult,
        ContentBlock as RmcpContentBlock, ElicitRequest, ElicitRequestParams, ElicitationSchema,
        InputRequest as RmcpInputRequest, InputRequiredResult, JsonObject, ListToolsResult,
        MetaObject, PaginatedRequestParams, ResourceContents, ResultType, Tool,
    },
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CanonicalToolResult, CatalogCacheScope, CompleteToolResult, ContentBlock,
    EmbeddedResourceContents, InputRequiredToolResult, ToolCallRequest, ToolDescriptor, ToolList,
    ToolName, ToolOutcome, ToolProjection, ToolProtocolError, ToolRepresentation,
    ToolResultAdapter,
};

/// Fixed value-free failure adapting a canonical result to MCP revision 2026-07-28.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ResultAdapterError {
    /// A canonical arbitrary schema cannot be represented by current form elicitation.
    #[error("input request schema is unsupported by the current MCP result model")]
    UnsupportedInputRequestSchema,
}

/// Adapter from the canonical result algebra to RMCP's MCP 2026-07-28 result model.
///
/// This is the only RMCP-dependent result boundary. Canonical result and content contracts remain
/// SDK-independent.
#[derive(Clone, Copy, Debug, Default)]
pub struct CurrentResultAdapter;

impl ToolResultAdapter for CurrentResultAdapter {
    type Output = CallToolResponse;
    type Error = ResultAdapterError;

    fn adapt(&self, result: CanonicalToolResult) -> Result<Self::Output, Self::Error> {
        match result {
            CanonicalToolResult::Complete(complete) => {
                Ok(CallToolResponse::Complete(adapt_complete(&complete)))
            }
            CanonicalToolResult::InputRequired(input_required) => Ok(
                CallToolResponse::InputRequired(adapt_input_required(&input_required)?),
            ),
        }
    }
}

/// Exact RMCP contribution for one authorization-filtered [`ToolProjection`].
#[derive(Clone)]
pub struct RmcpToolAdapter {
    projection: Arc<ToolProjection>,
}

impl RmcpToolAdapter {
    /// Wraps one canonical tool projection for installation in the core RMCP handler.
    #[must_use]
    pub const fn new(projection: Arc<ToolProjection>) -> Self {
        Self { projection }
    }

    /// Borrows the canonical projection used by this adapter.
    #[must_use]
    pub const fn projection(&self) -> &Arc<ToolProjection> {
        &self.projection
    }
}

impl McpToolAdapter for RmcpToolAdapter {
    fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListToolsResult> {
        Box::pin(async move {
            if request
                .as_ref()
                .and_then(|request| request.cursor.as_ref())
                .is_some()
            {
                return Err(invalid_tool_request());
            }
            let list = self
                .projection
                .list_tools(&context)
                .await
                .map_err(|_| unavailable_tool_execution())?;
            adapt_tool_list(&list)
        })
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, CallToolResponse> {
        Box::pin(async move {
            if request.input_responses.is_some() || request.request_state.is_some() {
                return Err(invalid_tool_request());
            }
            let name =
                ToolName::new(request.name.into_owned()).map_err(|_| invalid_tool_request())?;
            let input = Value::Object(request.arguments.unwrap_or_default());
            let result = self
                .projection
                .call(ToolCallRequest::new(
                    context,
                    name,
                    input,
                    ConfirmationEvidence::NotProvided,
                    None,
                ))
                .await
                .map_err(map_tool_protocol_error)?;
            CurrentResultAdapter
                .adapt(result)
                .map_err(|_| unavailable_tool_execution())
        })
    }
}

impl std::fmt::Debug for RmcpToolAdapter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RmcpToolAdapter([redacted])")
    }
}

fn adapt_tool_list(list: &ToolList) -> Result<ListToolsResult, ErrorData> {
    let tools = list
        .tools()
        .iter()
        .map(adapt_tool_descriptor)
        .collect::<Result<Vec<_>, ErrorData>>()?;
    let meta = serialize_meta(list.meta())?;
    let cache_scope = match list.meta().cache_scope() {
        CatalogCacheScope::Private => CacheScope::Private,
        CatalogCacheScope::Public => CacheScope::Public,
    };
    let mut result = ListToolsResult::with_all_items(tools)
        .with_ttl_ms(u64::from(list.meta().ttl_ms()))
        .with_cache_scope(cache_scope);
    result.meta = Some(meta);
    Ok(result)
}

fn adapt_tool_descriptor(descriptor: &ToolDescriptor) -> Result<Tool, ErrorData> {
    let input_schema = schema_object(descriptor.input_schema().document())?;
    let output_schema = schema_object(descriptor.output_schema().document())?;
    let Value::Object(mut metadata) =
        serde_json::to_value(descriptor).map_err(|_| unavailable_tool_execution())?
    else {
        return Err(unavailable_tool_execution());
    };
    for standard_field in [
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
    ] {
        metadata.remove(standard_field);
    }
    let description = descriptor
        .description()
        .map(|description| Cow::Owned(description.as_str().to_owned()));
    Ok(Tool::new_with_raw(
        descriptor.name().as_str().to_owned(),
        description,
        Arc::new(input_schema),
    )
    .with_title(descriptor.title().as_str())
    .with_raw_output_schema(Arc::new(output_schema))
    .with_meta(MetaObject(metadata)))
}

fn schema_object(schema: &Value) -> Result<JsonObject, ErrorData> {
    match schema {
        Value::Object(object) => Ok(object.clone()),
        Value::Bool(_) | Value::Null | Value::Number(_) | Value::String(_) | Value::Array(_) => {
            Err(unavailable_tool_execution())
        }
    }
}

fn serialize_meta(meta: &crate::CatalogMeta) -> Result<MetaObject, ErrorData> {
    match serde_json::to_value(meta).map_err(|_| unavailable_tool_execution())? {
        Value::Object(meta) => Ok(MetaObject(meta)),
        _ => Err(unavailable_tool_execution()),
    }
}

fn map_tool_protocol_error(_error: ToolProtocolError) -> ErrorData {
    invalid_tool_request()
}

fn invalid_tool_request() -> ErrorData {
    ErrorData::invalid_params("MCP tool request is invalid", None)
}

fn unavailable_tool_execution() -> ErrorData {
    ErrorData::internal_error("MCP tool execution is unavailable", None)
}

fn adapt_complete(complete: &CompleteToolResult) -> CallToolResult {
    let mut result = CallToolResult::default();
    result.result_type = Some(ResultType::COMPLETE);
    match complete.outcome() {
        ToolOutcome::Success { representation } => {
            result.is_error = Some(false);
            match representation {
                ToolRepresentation::ContentOnly { content } => {
                    result.content = adapt_content(content.blocks());
                }
                ToolRepresentation::StructuredOnly { structured } => {
                    result.structured_content = Some(structured.clone());
                }
                ToolRepresentation::AuthoritativeStructured {
                    structured,
                    supplementary_content,
                } => {
                    result.content = adapt_content(supplementary_content.blocks());
                    result.structured_content = Some(structured.clone());
                }
            }
        }
        ToolOutcome::Error { error } => {
            result.content = vec![RmcpContentBlock::text(error.message())];
            result.is_error = Some(true);
        }
    }
    result
}

fn adapt_content(content: &[ContentBlock]) -> Vec<RmcpContentBlock> {
    content.iter().map(adapt_content_block).collect()
}

fn adapt_content_block(content: &ContentBlock) -> RmcpContentBlock {
    match content {
        ContentBlock::Text { text } => RmcpContentBlock::text(text.as_str()),
        ContentBlock::Image { image } => RmcpContentBlock::image(
            BASE64_STANDARD.encode(image.data()),
            image.media_type().as_str(),
        ),
        ContentBlock::Audio { audio } => RmcpContentBlock::audio(
            BASE64_STANDARD.encode(audio.data()),
            audio.media_type().as_str(),
        ),
        ContentBlock::EmbeddedResource { resource } => {
            let uri = resource.uri().as_str().to_owned();
            let mime_type = resource
                .media_type()
                .map(|media_type| media_type.as_str().to_owned());
            let contents = match resource.contents() {
                EmbeddedResourceContents::Text { text } => ResourceContents::TextResourceContents {
                    uri,
                    mime_type,
                    text: text.as_str().to_owned(),
                    meta: None,
                },
                EmbeddedResourceContents::Binary { data } => {
                    ResourceContents::BlobResourceContents {
                        uri,
                        mime_type,
                        blob: BASE64_STANDARD.encode(data.data()),
                        meta: None,
                    }
                }
            };
            RmcpContentBlock::resource(contents)
        }
    }
}

fn adapt_input_required(
    input_required: &InputRequiredToolResult,
) -> Result<InputRequiredResult, ResultAdapterError> {
    let mut requests = BTreeMap::new();
    for request in input_required.requests() {
        let canonical_schema = request.schema().document();
        let Value::Object(schema) = canonical_schema.clone() else {
            return Err(ResultAdapterError::UnsupportedInputRequestSchema);
        };
        let requested_schema = ElicitationSchema::from_json_schema(schema)
            .map_err(|_| ResultAdapterError::UnsupportedInputRequestSchema)?;
        let converted_schema = serde_json::to_value(&requested_schema)
            .map_err(|_| ResultAdapterError::UnsupportedInputRequestSchema)?;
        if &converted_schema != canonical_schema {
            return Err(ResultAdapterError::UnsupportedInputRequestSchema);
        }
        let elicitation = ElicitRequest::new(ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: request.prompt().as_str().to_owned(),
            requested_schema,
        });
        requests.insert(
            request.id().as_str().to_owned(),
            RmcpInputRequest::Elicitation(elicitation),
        );
    }
    Ok(InputRequiredResult::new(
        Some(requests),
        Some(input_required.request_state().as_str().to_owned()),
    ))
}
