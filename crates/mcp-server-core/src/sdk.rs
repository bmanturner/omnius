//! RMCP integration reserved for Omnius-owned MCP projection and transport crates.
//!
//! Application and composition code must use the SDK-free crate-root contracts.

use std::{borrow::Cow, sync::Arc};

use omnius_agent_capability_registry::InvocationResult;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        ClientCapabilities, ClientNotification, ClientRequest, ErrorCode, Implementation,
        InitializeRequestParams, InitializeResult, InitializeResultMethod, JsonObject,
        ProtocolVersion, ServerCapabilities, ServerInfo, ServerResult,
    },
    service::{NotificationContext, RequestContext, Service},
};
use thiserror::Error;

use crate::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpDispatchError,
    McpDispatchRequest, McpExtensionCatalog, McpKernel, McpRequestContext, McpRequestMetadata,
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
    handler: HandlerAdapter,
    context_resolver: Arc<dyn CanonicalContextResolver>,
}

impl ServerAdapter {
    /// Wraps a kernel with no identity resolver and therefore rejects application requests.
    ///
    /// Transport composition should use [`Self::with_context_resolver`]. This fail-closed
    /// constructor remains useful while wiring dependencies in strict order.
    #[must_use]
    pub fn new(kernel: McpKernel) -> Self {
        Self::with_context_resolver(
            kernel,
            McpExtensionCatalog::empty(),
            Arc::new(RejectingContextResolver),
        )
    }

    /// Wraps a stateless kernel with explicit extension support and canonical context resolution.
    #[must_use]
    pub fn with_context_resolver(
        kernel: McpKernel,
        extension_catalog: McpExtensionCatalog,
        context_resolver: Arc<dyn CanonicalContextResolver>,
    ) -> Self {
        Self {
            handler: HandlerAdapter {
                kernel,
                extension_catalog,
            },
            context_resolver,
        }
    }

    /// Invokes one canonical registry request for a later RMCP primitive projection.
    ///
    /// RMCP values must be converted into the request's validated, owned metadata and canonical
    /// invocation context before this method is called.
    ///
    /// # Errors
    ///
    /// Returns only the kernel's fixed redacted error categories.
    pub async fn dispatch(
        &self,
        request: McpDispatchRequest,
    ) -> Result<InvocationResult, McpDispatchError> {
        self.handler.kernel.invoke(request).await
    }
}

#[derive(Clone)]
struct HandlerAdapter {
    kernel: McpKernel,
    extension_catalog: McpExtensionCatalog,
}

impl ServerHandler for HandlerAdapter {
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<InitializeResult, ErrorData>> {
        std::future::ready(Err(ErrorData::method_not_found::<InitializeResultMethod>()))
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        debug_assert_eq!(self.kernel.protocol_revision(), MCP_PROTOCOL_REVISION);
        Cow::Borrowed(SUPPORTED_PROTOCOL_VERSIONS)
    }

    fn get_info(&self) -> ServerInfo {
        let mut capabilities = ServerCapabilities::default();
        if !self.extension_catalog.extensions().is_empty() {
            capabilities.extensions = Some(
                self.extension_catalog
                    .extensions()
                    .iter()
                    .map(|extension| (extension.as_str().to_owned(), JsonObject::new()))
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

        let metadata = adapt_metadata(&context)?;
        let canonical = self
            .context_resolver
            .resolve(&metadata, &context)
            .map_err(|_| invalid_request_context())?;
        let request_context =
            McpRequestContext::new(metadata, &self.handler.extension_catalog, canonical);
        context.extensions.insert(request_context);
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
    let (client_capabilities, requested_extensions) = adapt_client_capabilities(&capabilities);

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

fn adapt_client_capabilities(capabilities: &ClientCapabilities) -> (Vec<String>, Vec<String>) {
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
        .map(|extensions| extensions.keys().cloned().collect())
        .unwrap_or_default();
    (core, extensions)
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
