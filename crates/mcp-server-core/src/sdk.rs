//! RMCP integration reserved for Omnius-owned MCP projection and transport crates.
//!
//! Application and composition code must use the SDK-free crate-root contracts.

use std::{borrow::Cow, future::Future, sync::Arc};

use omnius_agent_capability_registry::InvocationResult;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CancelTaskParams, ClientCapabilities,
        ClientNotification, ClientRequest, DiscoverResult, ErrorCode, GetPromptRequestParams,
        GetPromptResponse, GetTaskParams, GetTaskResult, Implementation, InitializeRequestParams,
        InitializeResult, InitializeResultMethod, JsonObject, ListPromptsResult,
        ListResourceTemplatesResult, ListResourcesResult, ListToolsResult, PaginatedRequestParams,
        PromptsCapability, ProtocolVersion, ReadResourceRequestParams, ReadResourceResponse,
        ResourcesCapability, ServerCapabilities, ServerInfo, ServerResult, SubscriptionFilter,
        TASKS_EXTENSION_ID, ToolsCapability, UpdateTaskParams,
    },
    service::{NotificationContext, RequestContext, Service, SubscriptionContext},
};
use thiserror::Error;

pub use crate::sdk_contributions::*;
use crate::{
    MCP_EXTENSION_REVISION_KEY, MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity,
    McpDispatch, McpDispatchError, McpDispatchRequest, McpExtension, McpExtensionCatalog,
    McpExtensionId, McpExtensionRevision, McpKernel, McpPrimitive, McpRequestContext,
    McpRequestMetadata,
};

const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[ProtocolVersion::V_2026_07_28];
const CLIENT_CAPABILITY_EXPERIMENTAL: &str = "experimental";
const CLIENT_CAPABILITY_ELICITATION: &str = "elicitation";

/// Resolves transport authentication and policy evidence into one canonical request context.
///
/// Implementations live at authenticated transport boundaries. They must build a fresh context for
/// every request and fail closed when identity, tenant, authorization, policy, lifecycle, or budget
/// evidence is absent.
pub trait CanonicalContextResolver: Send + Sync {
    /// Resolves one request's canonical identity and policy context.
    ///
    /// # Errors
    ///
    /// Returns a value-free error when trustworthy canonical context cannot be produced.
    fn resolve(
        &self,
        metadata: &McpRequestMetadata,
        request: &RequestContext<RoleServer>,
    ) -> Result<McpCanonicalContext, ContextResolutionError>;
}

/// Value-free canonical context resolution failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("MCP canonical request context could not be resolved")]
pub struct ContextResolutionError;

#[derive(Debug)]
struct RejectingContextResolver;

impl CanonicalContextResolver for RejectingContextResolver {
    fn resolve(
        &self,
        _metadata: &McpRequestMetadata,
        _request: &RequestContext<RoleServer>,
    ) -> Result<McpCanonicalContext, ContextResolutionError> {
        Err(ContextResolutionError)
    }
}

/// RMCP-facing adapter around the stateless SDK-free kernel.
///
/// This type stores no peer, initialization, or session state. Every non-deprecated request must
/// contain complete current metadata and pass the configured canonical context resolver before
/// RMCP handler routing.
#[derive(Clone)]
pub struct ServerAdapter {
    handler: StatelessHandlerAdapter,
}

impl ServerAdapter {
    /// Wraps a kernel with no bearer resolver and therefore rejects application requests.
    ///
    /// HTTP transport composition should use [`Self::with_bearer_context_resolver`] or
    /// [`Self::with_application_contributions`].
    #[must_use]
    pub fn new(kernel: McpKernel) -> Self {
        Self::with_bearer_context_resolver(kernel, Arc::new(RejectingContextResolver))
    }

    /// Wraps a stateless kernel with bearer context resolution but no primitive contributions.
    ///
    /// This constructor remains fail-closed: primitive and extension requests return method-not-
    /// found instead of plausible empty results.
    #[must_use]
    pub fn with_bearer_context_resolver(
        kernel: McpKernel,
        context_resolver: Arc<dyn CanonicalContextResolver>,
    ) -> Self {
        Self {
            handler: StatelessHandlerAdapter::with_bearer_context_resolver(
                kernel,
                context_resolver,
            ),
        }
    }

    /// Builds the complete static MCP handler for bearer-authenticated HTTP.
    #[must_use]
    pub fn with_application_contributions(
        contributions: McpApplicationContributions,
        extension_catalog: McpExtensionCatalog,
    ) -> Self {
        Self {
            handler: StatelessHandlerAdapter::with_application_contributions(
                contributions,
                extension_catalog,
            ),
        }
    }

    /// Invokes one canonical registry request for a later RMCP primitive projection.
    ///
    /// # Errors
    ///
    /// Returns only fixed redacted dispatch categories.
    pub async fn dispatch(
        &self,
        request: McpDispatchRequest,
    ) -> Result<InvocationResult, McpDispatchError> {
        if let Some(contributions) = &self.handler.contributions {
            contributions.dispatch.dispatch(request).await
        } else {
            McpDispatch::dispatch(&self.handler.kernel, request).await
        }
    }
}

/// RMCP handler facade for stateless bearer-authenticated HTTP services.
#[derive(Clone)]
pub struct StatelessHandlerAdapter {
    kernel: McpKernel,
    extension_catalog: McpExtensionCatalog,
    context_resolver: Arc<dyn CanonicalContextResolver>,
    contributions: Option<Arc<McpApplicationContributions>>,
}

impl StatelessHandlerAdapter {
    /// Creates a fail-closed handler with no bearer resolver or primitive contributions.
    #[must_use]
    pub fn new(kernel: McpKernel) -> Self {
        Self::with_bearer_context_resolver(kernel, Arc::new(RejectingContextResolver))
    }

    /// Creates a handler with bearer context resolution but no primitive contributions.
    #[must_use]
    pub fn with_bearer_context_resolver(
        kernel: McpKernel,
        context_resolver: Arc<dyn CanonicalContextResolver>,
    ) -> Self {
        Self {
            kernel,
            extension_catalog: McpExtensionCatalog::empty(),
            context_resolver,
            contributions: None,
        }
    }

    /// Creates a complete bearer-authenticated HTTP handler from validated contributions.
    #[must_use]
    pub fn with_application_contributions(
        contributions: McpApplicationContributions,
        extension_catalog: McpExtensionCatalog,
    ) -> Self {
        let extension_catalog = selected_extension_catalog(&contributions, extension_catalog);
        Self {
            kernel: contributions.kernel.clone(),
            extension_catalog,
            context_resolver: Arc::clone(&contributions.bearer_authenticator),
            contributions: Some(Arc::new(contributions)),
        }
    }

    fn prepare_context(&self, context: &mut RequestContext<RoleServer>) -> Result<(), ErrorData> {
        if context.extensions.get::<McpRequestContext>().is_some() {
            return Ok(());
        }
        let metadata = adapt_metadata(context)?;
        let canonical = self
            .context_resolver
            .resolve(&metadata, context)
            .map_err(|_| invalid_request_context())?;
        let request_context = McpRequestContext::new(metadata, &self.extension_catalog, canonical);
        context.extensions.insert(request_context);
        Ok(())
    }

    fn prepare_operation(
        &self,
        context: &mut RequestContext<RoleServer>,
        operation: McpOperation,
    ) -> Result<McpRequestContext, ErrorData> {
        self.prepare_context(context)?;
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let request = context
            .extensions
            .get::<McpRequestContext>()
            .cloned()
            .ok_or_else(invalid_request_context)?;
        if !contributions.tenant_guard.authorize(&request)
            || !contributions.operation_guard.authorize(&request, operation)
        {
            return Err(invalid_request_context());
        }
        Ok(request)
    }

    fn prepare_subscription(
        &self,
        context: &SubscriptionContext,
    ) -> Result<McpRequestContext, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let request = context
            .request_context()
            .extensions
            .get::<McpRequestContext>()
            .cloned()
            .ok_or_else(invalid_request_context)?;
        if !contributions.tenant_guard.authorize(&request)
            || !contributions
                .operation_guard
                .authorize(&request, McpOperation::Listen)
        {
            return Err(invalid_request_context());
        }
        Ok(request)
    }
}

fn selected_extension_catalog(
    contributions: &McpApplicationContributions,
    declared: McpExtensionCatalog,
) -> McpExtensionCatalog {
    let selected = declared.into_extensions().into_iter().filter(|extension| {
        extension.id().as_str() != TASKS_EXTENSION_ID || contributions.tasks.is_some()
    });
    match McpExtensionCatalog::new(selected) {
        Ok(catalog) => catalog,
        Err(_) => McpExtensionCatalog::empty(),
    }
}
impl ServerHandler for StatelessHandlerAdapter {
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> {
        std::future::ready(Err(ErrorData::method_not_found::<InitializeResultMethod>()))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        debug_assert_eq!(self.kernel.protocol_revision(), MCP_PROTOCOL_REVISION);
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn discover(
        &self,
        mut context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> {
        let result = self.prepare_context(&mut context).map(|()| {
            DiscoverResult::from_server_info(
                ServerHandler::supported_protocol_versions(self).into_owned(),
                ServerHandler::get_info(self),
            )
        });
        std::future::ready(result)
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .prompts
            .as_ref()
            .ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::ListPrompts)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Prompt)
            .documents()
            .is_empty()
        {
            return Ok(ListPromptsResult::default());
        }
        adapter.list_prompts(request, prepared).await
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .prompts
            .as_ref()
            .ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::GetPrompt)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Prompt)
            .documents()
            .is_empty()
        {
            return Err(invalid_request_context());
        }
        let result = adapter.get_prompt(request, prepared).await?;
        Ok(GetPromptResponse::Complete(result))
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .resources
            .as_ref()
            .ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::ListResources)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Resource)
            .documents()
            .is_empty()
        {
            return Ok(ListResourcesResult::default());
        }
        adapter.list_resources(request, prepared).await
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .resources
            .as_ref()
            .ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::ListResourceTemplates)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Resource)
            .documents()
            .is_empty()
        {
            return Ok(ListResourceTemplatesResult::default());
        }
        adapter.list_resource_templates(request, prepared).await
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .resources
            .as_ref()
            .ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::ReadResource)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Resource)
            .documents()
            .is_empty()
        {
            return Err(invalid_request_context());
        }
        let result = adapter.read_resource(request, prepared).await?;
        Ok(ReadResourceResponse::Complete(result))
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions.tools.as_ref().ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::ListTools)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Tool)
            .documents()
            .is_empty()
        {
            return Ok(ListToolsResult::default());
        }
        adapter.list_tools(request, prepared).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions.tools.as_ref().ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::CallTool)?;
        if contributions
            .exposure_filter
            .authorized(&prepared, McpPrimitive::Tool)
            .documents()
            .is_empty()
        {
            return Err(invalid_request_context());
        }
        adapter.call_tool(request, prepared).await
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        self.contributions
            .as_ref()
            .and_then(|contributions| contributions.subscriptions.as_ref())
            .and_then(|adapter| adapter.accepted_subscription_filter(requested))
    }

    async fn listen(&self, context: SubscriptionContext) -> Result<(), ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions
            .subscriptions
            .as_ref()
            .ok_or_else(method_not_found)?;
        self.prepare_subscription(&context)?;
        adapter.listen(context).await
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions.tasks.as_ref().ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::GetTask)?;
        adapter.get_task(request, prepared).await
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions.tasks.as_ref().ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::UpdateTask)?;
        adapter.update_task(request, prepared).await?;
        Ok(())
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        mut context: RequestContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        let contributions = self.contributions.as_deref().ok_or_else(method_not_found)?;
        let adapter = contributions.tasks.as_ref().ok_or_else(method_not_found)?;
        let prepared = self.prepare_operation(&mut context, McpOperation::CancelTask)?;
        adapter.cancel_task(request, prepared).await?;
        Ok(())
    }

    fn get_info(&self) -> ServerInfo {
        let mut capabilities = ServerCapabilities::default();
        if let Some(contributions) = &self.contributions {
            if contributions.tools.is_some() {
                capabilities.tools = Some(ToolsCapability::default());
            }
            if contributions.resources.is_some() {
                let mut resources = ResourcesCapability::default();
                if contributions.subscriptions.is_some() {
                    resources.subscribe = Some(true);
                }
                capabilities.resources = Some(resources);
            }
            if contributions.prompts.is_some() {
                capabilities.prompts = Some(PromptsCapability::default());
            }
        }
        if !self.extension_catalog.extensions().is_empty() {
            capabilities.extensions = Some(
                self.extension_catalog
                    .extensions()
                    .iter()
                    .map(|extension| {
                        let mut metadata = JsonObject::new();
                        metadata.insert(
                            MCP_EXTENSION_REVISION_KEY.to_owned(),
                            extension.revision().as_str().into(),
                        );
                        (extension.id().as_str().to_owned(), metadata)
                    })
                    .collect(),
            );
        }
        ServerInfo::new(capabilities)
            .with_protocol_version(ProtocolVersion::V_2026_07_28)
            .with_server_info(Implementation::new(
                "omnius-mcp-server",
                env!("CARGO_PKG_VERSION"),
            ))
    }
}

impl Service<RoleServer> for ServerAdapter {
    async fn handle_request(
        &self,
        request: ClientRequest,
        mut context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        if is_deprecated_request(&request) {
            return Err(method_not_found());
        }
        if matches!(&request, ClientRequest::InitializeRequest(_)) {
            return Service::<RoleServer>::handle_request(&self.handler, request, context).await;
        }

        self.handler.prepare_context(&mut context)?;
        Service::<RoleServer>::handle_request(&self.handler, request, context).await
    }

    async fn handle_notification(
        &self,
        notification: ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> Result<(), ErrorData> {
        if is_deprecated_notification(&notification) {
            return Err(method_not_found());
        }
        Service::<RoleServer>::handle_notification(&self.handler, notification, context).await
    }

    fn get_info(&self) -> ServerInfo {
        Service::<RoleServer>::get_info(&self.handler)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Service::<RoleServer>::supported_protocol_versions(&self.handler)
    }
}

fn adapt_metadata(context: &RequestContext<RoleServer>) -> Result<McpRequestMetadata, ErrorData> {
    let missing = missing_metadata(context);
    if !missing.is_empty() {
        return Err(ErrorData::invalid_params(
            format!(
                "request _meta is missing or has malformed required fields: {}",
                missing.join(", ")
            ),
            None,
        ));
    }

    let protocol = context
        .meta
        .protocol_version()
        .ok_or_else(invalid_request_context)?;
    if protocol != ProtocolVersion::V_2026_07_28 {
        return Err(ErrorData::unsupported_protocol_version(
            protocol,
            SUPPORTED_PROTOCOL_VERSIONS,
        ));
    }
    let client = context
        .meta
        .client_info()
        .ok_or_else(invalid_request_context)?;
    let capabilities = context
        .meta
        .client_capabilities()
        .ok_or_else(invalid_request_context)?;
    let (client_capabilities, requested_extensions) = adapt_client_capabilities(&capabilities)?;

    McpRequestMetadata::new(
        protocol.as_str(),
        McpClientIdentity::new(client.name, client.version)
            .map_err(|_| invalid_request_context())?,
        client_capabilities,
        requested_extensions,
        None,
    )
    .map_err(|_| invalid_request_context())
}

fn missing_metadata(context: &RequestContext<RoleServer>) -> Vec<&'static str> {
    let mut missing = context
        .meta
        .missing_required_keys(&ProtocolVersion::V_2026_07_28);
    if context.meta.client_info().is_none() {
        missing.push("io.modelcontextprotocol/clientInfo");
    }
    missing
}

fn adapt_client_capabilities(
    capabilities: &ClientCapabilities,
) -> Result<(Vec<String>, Vec<McpExtension>), ErrorData> {
    let mut core = Vec::with_capacity(2);
    if capabilities.experimental.is_some() {
        core.push(CLIENT_CAPABILITY_EXPERIMENTAL.to_owned());
    }
    if capabilities.elicitation.is_some() {
        core.push(CLIENT_CAPABILITY_ELICITATION.to_owned());
    }
    let extensions = capabilities
        .extensions
        .as_ref()
        .map(|extensions| {
            extensions
                .iter()
                .map(|(id, metadata)| {
                    let revision = metadata
                        .get(MCP_EXTENSION_REVISION_KEY)
                        .and_then(|value| value.as_str())
                        .ok_or_else(invalid_request_context)?;
                    Ok(McpExtension::new(
                        McpExtensionId::new(id.clone()).map_err(|_| invalid_request_context())?,
                        McpExtensionRevision::new(revision.to_owned())
                            .map_err(|_| invalid_request_context())?,
                    ))
                })
                .collect::<Result<Vec<_>, ErrorData>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok((core, extensions))
}

fn is_deprecated_request(request: &ClientRequest) -> bool {
    matches!(request, ClientRequest::SetLevelRequest(_))
        || matches!(
            request.method(),
            "roots/list" | "sampling/createMessage" | "logging/setLevel"
        )
}

fn is_deprecated_notification(notification: &ClientNotification) -> bool {
    matches!(
        notification,
        ClientNotification::InitializedNotification(_)
            | ClientNotification::RootsListChangedNotification(_)
    ) || matches!(
        notification,
        ClientNotification::CustomNotification(custom)
            if matches!(
                custom.method.as_str(),
                "notifications/initialized" | "notifications/roots/list_changed"
            )
    )
}

fn method_not_found() -> ErrorData {
    ErrorData::new(ErrorCode::METHOD_NOT_FOUND, "method not found", None)
}

fn invalid_request_context() -> ErrorData {
    ErrorData::invalid_params("MCP request context is invalid", None)
}
