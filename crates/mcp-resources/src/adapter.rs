use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use omnius_agent_capability_registry::ConfirmationEvidence;
use omnius_mcp_server_core::{
    McpRequestContext,
    sdk::{McpAdapterFuture, McpResourceAdapter},
};
use rmcp::{
    ErrorData,
    model::{
        CacheScope as RmcpCacheScope, ListResourceTemplatesResult, ListResourcesResult, MetaObject,
        PaginatedRequestParams, ReadResourceRequestParams, ReadResourceResult,
        Resource as RmcpResource, ResourceContents, ResourceTemplate as RmcpResourceTemplate,
    },
};
use serde_json::{Map, Value, json};

use crate::{
    AuthorizedCatalogMetadata, AuthorizedResource, AuthorizedResourceTemplate, CacheScope,
    ResourceCompatibility, ResourceContent, ResourceError, ResourceErrorCode, ResourceOperation,
    ResourceProjection, ResourceRequest, ResourceResult, ResourceUri, SchemaRevision,
};

/// Exact RMCP resource contribution backed exclusively by an authorized [`ResourceProjection`].
#[derive(Clone)]
pub struct ExactRmcpResourceAdapter {
    projection: Arc<ResourceProjection>,
}

impl ExactRmcpResourceAdapter {
    /// Creates an RMCP adapter over one immutable authorized resource projection.
    #[must_use]
    pub const fn new(projection: Arc<ResourceProjection>) -> Self {
        Self { projection }
    }

    /// Returns the canonical projection used by this adapter.
    #[must_use]
    pub const fn projection(&self) -> &Arc<ResourceProjection> {
        &self.projection
    }
}

impl McpResourceAdapter for ExactRmcpResourceAdapter {
    fn list_resources(
        &self,
        params: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListResourcesResult> {
        Box::pin(async move {
            reject_cursor(params.as_ref())?;
            let authorized = self
                .projection
                .list_authorized(&context)
                .await
                .map_err(map_resource_error)?;
            let resources = authorized.resources().iter().map(adapt_resource).collect();
            let mut result = ListResourcesResult::with_all_items(resources);
            apply_catalog_cache(
                &mut result.meta,
                &mut result.ttl_ms,
                &mut result.cache_scope,
                authorized.metadata(),
            );
            Ok(result)
        })
    }

    fn list_resource_templates(
        &self,
        params: Option<PaginatedRequestParams>,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ListResourceTemplatesResult> {
        Box::pin(async move {
            reject_cursor(params.as_ref())?;
            let authorized = self
                .projection
                .list_authorized(&context)
                .await
                .map_err(map_resource_error)?;
            let templates = authorized.templates().iter().map(adapt_template).collect();
            let mut result = ListResourceTemplatesResult::with_all_items(templates);
            apply_catalog_cache(
                &mut result.meta,
                &mut result.ttl_ms,
                &mut result.cache_scope,
                authorized.metadata(),
            );
            Ok(result)
        })
    }

    fn read_resource(
        &self,
        params: ReadResourceRequestParams,
        context: McpRequestContext,
    ) -> McpAdapterFuture<'_, ReadResourceResult> {
        Box::pin(async move {
            if params.input_responses.is_some() || params.request_state.is_some() {
                return Err(invalid_request());
            }
            let uri = ResourceUri::parse(params.uri).map_err(map_resource_error)?;
            let target = self
                .projection
                .catalog()
                .target_for_uri(&uri)
                .cloned()
                .ok_or_else(resource_unavailable)?;
            let request = ResourceRequest::new(
                context,
                ConfirmationEvidence::NotProvided,
                None,
                target,
                uri,
                ResourceOperation::Read,
                None,
            )
            .map_err(map_resource_error)?;
            let result = self
                .projection
                .read(request)
                .await
                .map_err(map_resource_error)?;
            adapt_read_result(&result)
        })
    }
}

fn reject_cursor(params: Option<&PaginatedRequestParams>) -> Result<(), ErrorData> {
    if params.and_then(|params| params.cursor.as_ref()).is_some() {
        return Err(invalid_request());
    }
    Ok(())
}

fn adapt_resource(resource: &AuthorizedResource) -> RmcpResource {
    let mut adapted = RmcpResource::new(resource.uri().as_str(), resource.name().as_str())
        .with_title(resource.title().as_str())
        .with_meta(declaration_meta(
            resource.schema_revision(),
            resource.compatibility(),
        ));
    if let Some(description) = resource.description() {
        adapted = adapted.with_description(description.as_str());
    }
    if let Some(mime_type) = resource.mime_type() {
        adapted = adapted.with_mime_type(mime_type.as_str());
    }
    adapted
}

fn adapt_template(template: &AuthorizedResourceTemplate) -> RmcpResourceTemplate {
    let mut adapted =
        RmcpResourceTemplate::new(template.uri_template().as_str(), template.name().as_str())
            .with_title(template.title().as_str())
            .with_meta(declaration_meta(
                template.schema_revision(),
                template.compatibility(),
            ));
    if let Some(description) = template.description() {
        adapted = adapted.with_description(description.as_str());
    }
    if let Some(mime_type) = template.mime_type() {
        adapted = adapted.with_mime_type(mime_type.as_str());
    }
    adapted
}

fn declaration_meta(
    schema_revision: &SchemaRevision,
    compatibility: &ResourceCompatibility,
) -> MetaObject {
    MetaObject(Map::from_iter([
        (
            "io.omnius.mcp/schemaRevision".to_owned(),
            Value::String(schema_revision.as_str().to_owned()),
        ),
        (
            "io.omnius.mcp/compatibility".to_owned(),
            json!(compatibility),
        ),
    ]))
}

fn apply_catalog_cache(
    meta: &mut Option<MetaObject>,
    ttl_ms: &mut Option<u64>,
    cache_scope: &mut Option<RmcpCacheScope>,
    metadata: &AuthorizedCatalogMetadata,
) {
    *meta = Some(MetaObject(metadata.adapter_meta().into_iter().collect()));
    *ttl_ms = Some(u64::from(metadata.cache_control().max_age_seconds()) * 1_000);
    *cache_scope = Some(RmcpCacheScope::Private);
}

fn adapt_read_result(result: &ResourceResult) -> Result<ReadResourceResult, ErrorData> {
    if result.range().is_some()
        || result.hierarchy().is_some()
        || result.object_reference().is_some()
    {
        return Err(internal_error());
    }
    let uri = result.uri().as_str().to_owned();
    let mime_type = Some(result.mime_type().as_str().to_owned());
    let meta = Some(read_meta(result));
    let contents = match result.content() {
        ResourceContent::Text(text) => ResourceContents::TextResourceContents {
            uri,
            mime_type,
            text: text.clone(),
            meta: None,
        },
        ResourceContent::Binary(bytes) => ResourceContents::BlobResourceContents {
            uri,
            mime_type,
            blob: STANDARD.encode(bytes),
            meta: None,
        },
    };
    let control = result.cache().control();
    let mut adapted = match control.scope() {
        CacheScope::Private => ReadResourceResult::new(vec![contents])
            .with_ttl_ms(u64::from(control.max_age_seconds()) * 1_000)
            .with_cache_scope(RmcpCacheScope::Private),
        CacheScope::Public => ReadResourceResult::new(vec![contents])
            .with_ttl_ms(u64::from(control.max_age_seconds()) * 1_000)
            .with_cache_scope(RmcpCacheScope::Public),
        CacheScope::NoStore => ReadResourceResult::new(vec![contents]).with_ttl_ms(0),
    };
    adapted.meta = meta;
    Ok(adapted)
}

fn read_meta(result: &ResourceResult) -> MetaObject {
    let control = result.cache().control();
    MetaObject(Map::from_iter([
        (
            "io.omnius.mcp/cacheControl".to_owned(),
            Value::String(control.header_value()),
        ),
        (
            "io.omnius.mcp/cacheScope".to_owned(),
            Value::String(
                match control.scope() {
                    CacheScope::Private => "private",
                    CacheScope::Public => "public",
                    CacheScope::NoStore => "no_store",
                }
                .to_owned(),
            ),
        ),
        (
            "io.omnius.mcp/checksum".to_owned(),
            Value::String(result.checksum().as_str().to_owned()),
        ),
        (
            "io.omnius.mcp/etag".to_owned(),
            Value::String(format!("\"{}\"", result.cache().etag().as_str())),
        ),
        (
            "io.omnius.mcp/ttlMs".to_owned(),
            Value::from(u64::from(control.max_age_seconds()) * 1_000),
        ),
    ]))
}

fn map_resource_error(error: ResourceError) -> ErrorData {
    match error.code() {
        ResourceErrorCode::InvalidValue | ResourceErrorCode::InvalidRequest => invalid_request(),
        ResourceErrorCode::Rejected => resource_unavailable(),
        ResourceErrorCode::InvalidDeclaration
        | ResourceErrorCode::Unavailable
        | ResourceErrorCode::InvalidOutput
        | ResourceErrorCode::Internal => internal_error(),
    }
}

fn invalid_request() -> ErrorData {
    ErrorData::invalid_params("MCP resource request is invalid", None)
}

fn resource_unavailable() -> ErrorData {
    ErrorData::invalid_params("MCP resource is unavailable", None)
}

fn internal_error() -> ErrorData {
    ErrorData::internal_error("MCP resource operation failed", None)
}
