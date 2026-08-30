use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use rmcp::model::{
    CallToolResponse, CallToolResult, ContentBlock as RmcpContentBlock, ElicitRequest,
    ElicitRequestParams, ElicitationSchema, InputRequest as RmcpInputRequest, InputRequiredResult,
    ResourceContents, ResultType,
};
use serde_json::Value;
use thiserror::Error;

use crate::{
    CanonicalToolResult, CompleteToolResult, ContentBlock, EmbeddedResourceContents,
    InputRequiredToolResult, ToolOutcome, ToolRepresentation, ToolResultAdapter,
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
