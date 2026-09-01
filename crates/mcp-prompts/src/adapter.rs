use std::{fmt, sync::Arc};

use omnius_agent_capability_registry::ConfirmationEvidence;
use omnius_mcp_server_core::{
    McpRequestContext,
    sdk::{McpAdapterFuture, McpPromptAdapter},
};
use rmcp::{
    ErrorData,
    model::{
        CacheScope as RmcpCacheScope, GetPromptRequestParams, GetPromptResult, ListPromptsResult,
        MetaObject, PaginatedRequestParams, Prompt, PromptArgument, PromptMessage, Role,
    },
};
use serde_json::{Map, Value};

use crate::{
    AuthorizedListMetadata, AuthorizedPromptList, CacheScope, CanonicalPromptResult,
    McpPromptProjection, PromptAuthorizer, PromptGetRequest, PromptMetadata, PromptProjectionError,
    PromptProjectionErrorCode, PublicPromptName,
};

/// RMCP metadata key containing the exact immutable canonical prompt metadata and schema.
pub const META_PROMPT_METADATA: &str = "io.omnius.mcp/promptMetadata";

/// Exact RMCP prompts contribution over the authorization-filtered canonical projection.
pub struct RmcpPromptAdapter<A: PromptAuthorizer + ?Sized> {
    projection: Arc<McpPromptProjection<A>>,
}

impl<A: PromptAuthorizer + ?Sized> RmcpPromptAdapter<A> {
    /// Creates an RMCP contribution that delegates only to the canonical prompt projection.
    #[must_use]
    pub const fn new(projection: Arc<McpPromptProjection<A>>) -> Self {
        Self { projection }
    }

    /// Borrows the authorization-filtered canonical prompt projection.
    #[must_use]
    pub const fn projection(&self) -> &Arc<McpPromptProjection<A>> {
        &self.projection
    }
}

impl<A: PromptAuthorizer + ?Sized> Clone for RmcpPromptAdapter<A> {
    fn clone(&self) -> Self {
        Self {
            projection: Arc::clone(&self.projection),
        }
    }
}

impl<A: PromptAuthorizer + ?Sized> fmt::Debug for RmcpPromptAdapter<A> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RmcpPromptAdapter([redacted])")
    }
}

impl<A: PromptAuthorizer + ?Sized + 'static> McpPromptAdapter for RmcpPromptAdapter<A> {
    fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListPromptsResult> {
        Box::pin(async move {
            if request.is_some_and(|request| request.cursor.is_some()) {
                return Err(invalid_request());
            }
            let authorized = self
                .projection
                .list(&context)
                .await
                .map_err(adapt_projection_error)?;
            adapt_list(&authorized)
        })
    }

    fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, GetPromptResult> {
        Box::pin(async move {
            if request.input_responses.is_some() || request.request_state.is_some() {
                return Err(invalid_request());
            }
            let public_name =
                PublicPromptName::new(request.name).map_err(|_| rejected_request())?;
            let arguments = Value::Object(request.arguments.unwrap_or_default());
            let result = self
                .projection
                .get(PromptGetRequest::new(
                    context,
                    public_name,
                    ConfirmationEvidence::NotProvided,
                    None,
                    arguments,
                ))
                .await
                .map_err(adapt_projection_error)?;
            adapt_result(&result)
        })
    }
}

fn adapt_list(authorized: &AuthorizedPromptList<'_>) -> Result<ListPromptsResult, ErrorData> {
    let prompts = authorized
        .prompts()
        .iter()
        .map(adapt_prompt)
        .collect::<Result<Vec<_>, _>>()?;
    let mut result = ListPromptsResult::with_all_items(prompts)
        .with_ttl_ms(authorized.metadata().ttl_ms())
        .with_cache_scope(adapt_cache_scope(authorized.metadata().cache_scope()));
    result.meta = Some(metadata_object(authorized.metadata())?);
    Ok(result)
}

fn adapt_prompt(metadata: &PromptMetadata) -> Result<Prompt, ErrorData> {
    let mut prompt = Prompt::new(
        metadata.public_name().as_str(),
        Some(metadata.description()),
        adapt_arguments(metadata.argument_schema())?,
    )
    .with_title(metadata.title());
    let mut meta = MetaObject::new();
    meta.0.insert(
        META_PROMPT_METADATA.to_owned(),
        serde_json::to_value(metadata).map_err(|_| internal_error())?,
    );
    prompt.meta = Some(meta);
    Ok(prompt)
}

fn adapt_arguments(schema: &Value) -> Result<Option<Vec<PromptArgument>>, ErrorData> {
    let Value::Object(schema) = schema else {
        return Err(internal_error());
    };
    let properties = match schema.get("properties") {
        None => return Ok(None),
        Some(Value::Object(properties)) => properties,
        Some(_) => return Err(internal_error()),
    };
    let required = match schema.get("required") {
        None => Vec::new(),
        Some(Value::Array(required)) => required
            .iter()
            .map(|name| name.as_str().ok_or_else(internal_error))
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(internal_error()),
    };
    if required.iter().any(|name| !properties.contains_key(*name)) {
        return Err(internal_error());
    }
    let mut arguments = Vec::with_capacity(properties.len());
    for (name, property) in properties {
        let mut argument =
            PromptArgument::new(name).with_required(required.contains(&name.as_str()));
        match property {
            Value::Bool(_) => {}
            Value::Object(property) => {
                if let Some(title) = optional_string(property, "title")? {
                    argument = argument.with_title(title);
                }
                if let Some(description) = optional_string(property, "description")? {
                    argument = argument.with_description(description);
                }
            }
            _ => return Err(internal_error()),
        }
        arguments.push(argument);
    }
    Ok(Some(arguments))
}

fn optional_string<'value>(
    object: &'value Map<String, Value>,
    key: &str,
) -> Result<Option<&'value str>, ErrorData> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(internal_error()),
    }
}

fn adapt_result(result: &CanonicalPromptResult<'_>) -> Result<GetPromptResult, ErrorData> {
    if result.prompt().system().is_some() || result.prompt().developer().is_some() {
        return Err(internal_error());
    }
    let message = PromptMessage::new_text(Role::User, result.prompt().user().as_str());
    let mut adapted =
        GetPromptResult::new(vec![message]).with_description(result.metadata().description());
    let mut meta = MetaObject::new();
    meta.0.insert(
        META_PROMPT_METADATA.to_owned(),
        serde_json::to_value(result.metadata()).map_err(|_| internal_error())?,
    );
    adapted.meta = Some(meta);
    Ok(adapted)
}

fn metadata_object(metadata: &AuthorizedListMetadata<'_>) -> Result<MetaObject, ErrorData> {
    let Value::Object(metadata) = serde_json::to_value(metadata).map_err(|_| internal_error())?
    else {
        return Err(internal_error());
    };
    Ok(MetaObject(metadata))
}

const fn adapt_cache_scope(scope: CacheScope) -> RmcpCacheScope {
    match scope {
        CacheScope::Public => RmcpCacheScope::Public,
        CacheScope::Private => RmcpCacheScope::Private,
    }
}

fn adapt_projection_error(error: PromptProjectionError) -> ErrorData {
    match error.code() {
        PromptProjectionErrorCode::InvalidRequest => invalid_request(),
        PromptProjectionErrorCode::Rejected => rejected_request(),
        PromptProjectionErrorCode::Unavailable | PromptProjectionErrorCode::Internal => {
            internal_error()
        }
    }
}

fn invalid_request() -> ErrorData {
    ErrorData::invalid_params("MCP prompt request is invalid", None)
}

fn rejected_request() -> ErrorData {
    ErrorData::invalid_params("MCP prompt request was rejected", None)
}

fn internal_error() -> ErrorData {
    ErrorData::internal_error("MCP prompt projection is unavailable", None)
}
