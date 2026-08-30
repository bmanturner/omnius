//! RMCP-boundary contracts for the current stateless MCP lifecycle.

use std::{error::Error, sync::Arc};

use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityRegistryBuilder, InvocationContext, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId as CoreRequestId;
use omnius_mcp_server_core::{
    MCP_EXTENSION_REVISION_KEY, MCP_PROTOCOL_REVISION, McpCanonicalContext, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpKernel, McpRequestMetadata,
    sdk::{CanonicalContextResolver, ContextResolutionError, ServerAdapter},
};
use rmcp::{
    RoleServer, ServiceExt,
    model::{
        ClientCapabilities, ClientJsonRpcMessage, ClientRequest, DiscoverRequest,
        DiscoverRequestParams, ErrorCode, Implementation, InitializeRequest,
        InitializeRequestParams, JsonObject, ListToolsRequest, ProtocolVersion, RequestId,
        RequestMetaObject, ServerJsonRpcMessage, ServerResult,
    },
    service::{Service, serve_directly},
};
use time::OffsetDateTime;
use tokio::io::{
    AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, ReadHalf, WriteHalf,
};

struct ProtocolClient {
    lines: Lines<BufReader<ReadHalf<DuplexStream>>>,
    writer: WriteHalf<DuplexStream>,
}

impl ProtocolClient {
    fn new(stream: DuplexStream) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            lines: BufReader::new(reader).lines(),
            writer,
        }
    }

    async fn send(&mut self, message: ClientJsonRpcMessage) -> Result<(), Box<dyn Error>> {
        let mut encoded = serde_json::to_vec(&message)?;
        encoded.push(b'\n');
        self.writer.write_all(&encoded).await?;
        self.writer.flush().await?;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Option<ServerJsonRpcMessage>, Box<dyn Error>> {
        let Some(line) = self.lines.next_line().await? else {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&line)?))
    }
}

#[tokio::test]
async fn discovery_advertises_exactly_the_current_protocol_and_no_deprecated_surfaces()
-> Result<(), Box<dyn Error>> {
    let extension = McpExtension::new(
        McpExtensionId::new("io.modelcontextprotocol/tasks")?,
        McpExtensionRevision::new("2026-07-28")?,
    );
    let adapter = adapter_with_extensions(McpExtensionCatalog::new([extension])?);
    let supported = Service::<RoleServer>::supported_protocol_versions(&adapter);
    let info = Service::<RoleServer>::get_info(&adapter);

    assert_eq!(MCP_PROTOCOL_REVISION, "2026-07-28");
    assert_eq!(supported.as_ref(), &[ProtocolVersion::V_2026_07_28]);
    assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
    assert!(info.capabilities.logging.is_none());
    assert!(info.capabilities.prompts.is_none());
    assert!(info.capabilities.resources.is_none());
    assert!(info.capabilities.tools.is_none());
    assert_eq!(
        info.capabilities
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("io.modelcontextprotocol/tasks"))
            .and_then(|metadata| metadata.get(MCP_EXTENSION_REVISION_KEY))
            .and_then(serde_json::Value::as_str),
        Some("2026-07-28")
    );

    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server_task = tokio::spawn(async move { adapter.serve(server_transport).await });
    let mut client = ProtocolClient::new(client_transport);
    client.send(discover_request(1)).await?;
    let Some(ServerJsonRpcMessage::Response(response)) = client.receive().await? else {
        panic!("expected discovery response");
    };
    let ServerResult::DiscoverResult(discovery) = response.result else {
        panic!("expected discovery result");
    };
    let serialized_capabilities = serde_json::to_value(&discovery.capabilities)?;

    assert_eq!(
        discovery.supported_versions,
        [ProtocolVersion::V_2026_07_28]
    );
    assert!(serialized_capabilities.get("logging").is_none());
    assert!(
        serialized_capabilities
            .get("extensions")
            .and_then(|extensions| extensions.get("io.modelcontextprotocol/tasks"))
            .is_some()
    );
    assert!(serialized_capabilities.get("roots").is_none());
    assert!(serialized_capabilities.get("sampling").is_none());
    assert!(serialized_capabilities.get("session").is_none());

    server_task.await??.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn legacy_initialize_cannot_open_a_metadata_optional_session() -> Result<(), Box<dyn Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server_task = tokio::spawn(async move { adapter().serve(server_transport).await });
    let mut client = ProtocolClient::new(client_transport);

    let request = InitializeRequest::new(
        InitializeRequestParams::new(
            ClientCapabilities::default(),
            Implementation::new("legacy-client", "1.0.0"),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28),
    );
    client
        .send(ClientJsonRpcMessage::request(
            ClientRequest::InitializeRequest(request),
            RequestId::Number(1),
        ))
        .await?;

    let Some(ServerJsonRpcMessage::Error(error)) = client.receive().await? else {
        panic!("expected legacy initialize rejection");
    };
    assert_eq!(error.id, Some(RequestId::Number(1)));
    assert_eq!(error.error.code, ErrorCode::METHOD_NOT_FOUND);

    assert!(client.receive().await?.is_none());
    assert!(
        server_task.await?.is_err(),
        "legacy initialization must terminate the connection"
    );
    Ok(())
}

#[tokio::test]
async fn direct_stateless_transport_rejects_metadata_free_requests() -> Result<(), Box<dyn Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server = serve_directly::<RoleServer, _, _, _, _>(adapter(), server_transport, None);
    let mut client = ProtocolClient::new(client_transport);

    client.send(list_tools_request(None, 1)).await?;
    assert_invalid_params(client.receive().await?, 1, None);

    let missing_client: RequestMetaObject = serde_json::from_value(serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {}
    }))?;
    client
        .send(list_tools_request(Some(missing_client), 2))
        .await?;
    assert_invalid_params(client.receive().await?, 2, None);

    server.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn missing_identity_resolver_has_no_fallback_principal() -> Result<(), Box<dyn Error>> {
    let registry = Arc::new(CapabilityRegistryBuilder::new().build());
    let unresolved = ServerAdapter::new(McpKernel::new(registry));
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server = serve_directly::<RoleServer, _, _, _, _>(unresolved, server_transport, None);
    let mut client = ProtocolClient::new(client_transport);

    client
        .send(list_tools_request(
            Some(complete_meta("unresolved-client")),
            1,
        ))
        .await?;
    let Some(ServerJsonRpcMessage::Error(error)) = client.receive().await? else {
        panic!("expected canonical context rejection");
    };
    assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);
    assert_eq!(error.error.message, "MCP request context is invalid");

    server.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn every_request_requires_fresh_complete_current_metadata() -> Result<(), Box<dyn Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(8_192);
    let server_task = tokio::spawn(async move { adapter().serve(server_transport).await });
    let mut client = ProtocolClient::new(client_transport);

    client.send(discover_request(1)).await?;
    assert!(matches!(
        client.receive().await?,
        Some(ServerJsonRpcMessage::Response(_))
    ));

    client
        .send(list_tools_request(Some(complete_meta("first-client")), 2))
        .await?;
    assert!(matches!(
        client.receive().await?,
        Some(ServerJsonRpcMessage::Response(_))
    ));

    client.send(list_tools_request(None, 3)).await?;
    assert_invalid_params(client.receive().await?, 3, None);

    let sensitive_metadata = "private-client-credential";
    let malformed: RequestMetaObject = serde_json::from_value(serde_json::json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": sensitive_metadata,
        "io.modelcontextprotocol/clientCapabilities": null
    }))?;
    client.send(list_tools_request(Some(malformed), 4)).await?;
    assert_invalid_params(client.receive().await?, 4, Some(sensitive_metadata));

    server_task.await??.cancel().await?;
    Ok(())
}

#[tokio::test]
#[expect(
    deprecated,
    reason = "contract test verifies deprecated Logging is rejected by the new profile"
)]
async fn deprecated_logging_request_is_not_implemented() -> Result<(), Box<dyn Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server = serve_directly::<RoleServer, _, _, _, _>(adapter(), server_transport, None);
    let mut client = ProtocolClient::new(client_transport);
    let mut request = rmcp::model::SetLevelRequest::new(rmcp::model::SetLevelRequestParams::new(
        rmcp::model::LoggingLevel::Debug,
    ));
    request.extensions.insert(complete_meta("logging-client"));

    client
        .send(ClientJsonRpcMessage::request(
            ClientRequest::SetLevelRequest(request),
            RequestId::Number(1),
        ))
        .await?;
    let Some(ServerJsonRpcMessage::Error(error)) = client.receive().await? else {
        panic!("expected deprecated logging rejection");
    };
    assert_eq!(error.error.code, ErrorCode::METHOD_NOT_FOUND);
    assert_eq!(error.error.message, "method not found");

    server.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn request_selecting_an_older_revision_is_rejected() -> Result<(), Box<dyn Error>> {
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server_task = tokio::spawn(async move { adapter().serve(server_transport).await });
    let mut client = ProtocolClient::new(client_transport);

    client.send(discover_request(1)).await?;
    assert!(matches!(
        client.receive().await?,
        Some(ServerJsonRpcMessage::Response(_))
    ));

    let mut old_meta = complete_meta("old-client");
    old_meta.set_protocol_version(ProtocolVersion::V_2025_11_25);
    client.send(list_tools_request(Some(old_meta), 2)).await?;
    let Some(ServerJsonRpcMessage::Error(error)) = client.receive().await? else {
        panic!("expected unsupported-version error");
    };
    assert_eq!(error.id, Some(RequestId::Number(2)));
    assert_eq!(error.error.code, ErrorCode::UNSUPPORTED_PROTOCOL_VERSION);

    server_task.await??.cancel().await?;
    Ok(())
}

#[tokio::test]
async fn extension_without_an_exact_revision_is_rejected() -> Result<(), Box<dyn Error>> {
    let extension = McpExtension::new(
        McpExtensionId::new("io.modelcontextprotocol/tasks")?,
        McpExtensionRevision::new("2026-07-28")?,
    );
    let adapter = adapter_with_extensions(McpExtensionCatalog::new([extension])?);
    let (server_transport, client_transport) = tokio::io::duplex(4_096);
    let server_task = tokio::spawn(async move { adapter.serve(server_transport).await });
    let mut client = ProtocolClient::new(client_transport);

    let mut capabilities = ClientCapabilities::default();
    capabilities.extensions = Some(
        [(
            "io.modelcontextprotocol/tasks".to_owned(),
            JsonObject::new(),
        )]
        .into_iter()
        .collect(),
    );
    let mut meta = complete_meta("missing-extension-revision");
    meta.set_client_capabilities(capabilities);
    client.send(list_tools_request(Some(meta), 1)).await?;
    let Some(ServerJsonRpcMessage::Error(error)) = client.receive().await? else {
        panic!("expected invalid-params error");
    };
    assert_eq!(error.id, Some(RequestId::Number(1)));
    assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);
    assert_eq!(error.error.message, "MCP request context is invalid");
    assert!(!format!("{:?}", error.error).contains("missing-extension-revision"));

    server_task.await??.cancel().await?;
    Ok(())
}

#[derive(Debug)]
struct TestContextResolver;

impl CanonicalContextResolver for TestContextResolver {
    fn resolve(
        &self,
        _metadata: &McpRequestMetadata,
        request: &rmcp::service::RequestContext<RoleServer>,
    ) -> Result<McpCanonicalContext, ContextResolutionError> {
        let principal = Principal::new(
            SubjectId::new(),
            PrincipalKind::ServiceAccount,
            None,
            AuthMethod::ApiKey,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal1,
            Vec::new(),
        )
        .map_err(|_| ContextResolutionError)?;
        let invocation = InvocationContext::new(
            CoreRequestId::new(),
            TraceContext::new(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                    .parse()
                    .map_err(|_| ContextResolutionError)?,
                None,
            ),
            principal,
            None,
            Decision::Allow,
            "policy.mcp-protocol"
                .parse()
                .map_err(|_| ContextResolutionError)?,
            BudgetBounds::new(4_096, 4_096, 100).map_err(|_| ContextResolutionError)?,
            OffsetDateTime::now_utc() + time::Duration::seconds(10),
            request.ct.clone(),
        )
        .map_err(|_| ContextResolutionError)?;
        McpCanonicalContext::new(invocation, TenantMode::Global).map_err(|_| ContextResolutionError)
    }
}

fn adapter() -> ServerAdapter {
    adapter_with_extensions(McpExtensionCatalog::empty())
}

fn adapter_with_extensions(extension_catalog: McpExtensionCatalog) -> ServerAdapter {
    let registry = Arc::new(CapabilityRegistryBuilder::new().build());
    ServerAdapter::with_context_resolver(
        McpKernel::new(registry),
        extension_catalog,
        Arc::new(TestContextResolver),
    )
}

fn complete_meta(client_name: &str) -> RequestMetaObject {
    let mut meta = RequestMetaObject::new();
    meta.set_protocol_version(ProtocolVersion::V_2026_07_28);
    meta.set_client_info(Implementation::new(client_name, "1.0.0"));
    meta.set_client_capabilities(ClientCapabilities::default());
    meta
}

fn discover_request(id: i64) -> ClientJsonRpcMessage {
    let mut request = DiscoverRequest::new(DiscoverRequestParams {});
    request.extensions.insert(complete_meta("contract-client"));
    ClientJsonRpcMessage::request(
        ClientRequest::DiscoverRequest(request),
        RequestId::Number(id),
    )
}

fn list_tools_request(meta: Option<RequestMetaObject>, id: i64) -> ClientJsonRpcMessage {
    let mut request = ListToolsRequest::default();
    if let Some(meta) = meta {
        request.extensions.insert(meta);
    }
    ClientJsonRpcMessage::request(
        ClientRequest::ListToolsRequest(request),
        RequestId::Number(id),
    )
}

fn assert_invalid_params(
    message: Option<ServerJsonRpcMessage>,
    id: i64,
    sensitive_value: Option<&str>,
) {
    let Some(ServerJsonRpcMessage::Error(error)) = message else {
        panic!("expected invalid-params error");
    };
    let rendered = format!("{:?}", error.error);
    assert_eq!(error.id, Some(RequestId::Number(id)));
    assert_eq!(error.error.code, ErrorCode::INVALID_PARAMS);
    assert!(
        error
            .error
            .message
            .contains("request _meta is missing or has malformed required fields")
    );
    if let Some(sensitive_value) = sensitive_value {
        assert!(!rendered.contains(sensitive_value));
    }
}
