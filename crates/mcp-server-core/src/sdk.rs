//! RMCP integration reserved for Omnius-owned MCP projection and transport crates.
//!
//! Application and composition code must use the SDK-free crate-root contracts.

use std::borrow::Cow;

use omnius_agent_capability_registry::InvocationResult;
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        ClientNotification, ClientRequest, Implementation, InitializeRequestParams,
        InitializeResult, InitializeResultMethod, ProtocolVersion, ServerCapabilities, ServerInfo,
        ServerResult,
    },
    service::{NotificationContext, RequestContext, Service},
};

use crate::{MCP_PROTOCOL_REVISION, McpDispatchError, McpDispatchRequest, McpKernel};

const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[ProtocolVersion::V_2026_07_28];

/// RMCP-facing adapter around the stateless SDK-free kernel.
///
/// This type is an implementation detail for Omnius-owned transports. It stores no
/// peer, initialization, or session state and advertises no primitive capabilities
/// until registry projection is added by the owning follow-on tasks.
#[derive(Clone)]
pub struct ServerAdapter {
    handler: HandlerAdapter,
}

impl ServerAdapter {
    /// Wraps a stateless kernel for RMCP dispatch.
    #[must_use]
    pub fn new(kernel: McpKernel) -> Self {
        Self {
            handler: HandlerAdapter { kernel },
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
        ServerInfo::new(ServerCapabilities::default())
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
        context: RequestContext<RoleServer>,
    ) -> Result<ServerResult, ErrorData> {
        if !matches!(&request, ClientRequest::InitializeRequest(_)) {
            let mut missing = context
                .meta
                .missing_required_keys(&ProtocolVersion::V_2026_07_28);
            if context.meta.client_info().is_none() {
                missing.push("io.modelcontextprotocol/clientInfo");
            }
            if !missing.is_empty() {
                return Err(ErrorData::invalid_params(
                    format!(
                        "request _meta is missing or has malformed required fields: {}",
                        missing.join(", ")
                    ),
                    None,
                ));
            }
        }
        Service::<RoleServer>::handle_request(&self.handler, request, context).await
    }

    fn handle_notification(
        &self,
        notification: ClientNotification,
        context: NotificationContext<RoleServer>,
    ) -> impl std::future::Future<Output = Result<(), ErrorData>> {
        Service::<RoleServer>::handle_notification(&self.handler, notification, context)
    }

    fn get_info(&self) -> ServerInfo {
        Service::<RoleServer>::get_info(&self.handler)
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Service::<RoleServer>::supported_protocol_versions(&self.handler)
    }
}
