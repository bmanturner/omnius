//! Observable AC-AI-065 through AC-AI-068 contracts for the HTTP transport.

use std::{
    borrow::Cow,
    error::Error,
    future::{Future, ready},
    sync::Arc,
};

use axum::{
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
};
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityRegistryBuilder, InvocationContext, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId as CoreRequestId;
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpExtensionCatalog, McpKernel, McpRequestMetadata,
    sdk::{CanonicalContextResolver, ContextResolutionError, StatelessHandlerAdapter},
};
use omnius_mcp_transport_http::{
    MCP_HTTP_PATH, McpDrainOutcome, McpDrainSignal, McpHttpConfig, McpHttpServer,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    model::{
        CacheScope, Implementation, ListToolsResult, MetaObject, PaginatedRequestParams,
        ProtocolVersion, ServerCapabilities, ServerInfo, SubscriptionFilter,
    },
    service::{RequestContext, SubscriptionContext},
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const ALPHA_ETAG: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BETA_ETAG: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[tokio::test]
async fn discover_is_current_self_contained_and_core_backed() -> Result<(), Box<dyn Error>> {
    let registry = Arc::new(CapabilityRegistryBuilder::new().build());
    let handler = StatelessHandlerAdapter::with_context_resolver(
        McpKernel::new(registry),
        McpExtensionCatalog::empty(),
        Arc::new(CoreContextResolver),
    );
    let server = McpHttpServer::new(handler, McpHttpConfig::default())?;

    let response = server
        .router()
        .oneshot(mcp_request("server/discover", 1, true, None)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let document = response_json(response).await?;
    assert_eq!(
        document["result"]["supportedVersions"],
        json!([MCP_PROTOCOL_REVISION])
    );
    assert_eq!(
        document["result"]["_meta"]["io.modelcontextprotocol/serverInfo"]["name"],
        "omnius-mcp-server"
    );

    let missing_fresh_metadata = server
        .router()
        .oneshot(mcp_request("tools/list", 2, false, None)?)
        .await?;
    assert_eq!(missing_fresh_metadata.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn strict_post_headers_and_current_version_reject_legacy_surfaces()
-> Result<(), Box<dyn Error>> {
    let server = contract_server(McpHttpConfig::default())?;

    let get = Request::builder()
        .method(Method::GET)
        .uri(MCP_HTTP_PATH)
        .body(Body::empty())?;
    assert_eq!(
        server.router().oneshot(get).await?.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );

    let mut missing_accept = mcp_request("server/discover", 1, true, None)?;
    missing_accept.headers_mut().remove(header::ACCEPT);
    let missing_accept = server.router().oneshot(missing_accept).await?;
    assert_eq!(missing_accept.status(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(
        missing_accept.headers().get(header::CONTENT_TYPE),
        Some(&"application/json".parse()?)
    );
    let missing_accept = response_json(missing_accept).await?;
    assert_eq!(missing_accept["error"]["code"], -32600);
    assert!(missing_accept.get("type").is_none());

    let mut wrong_content_type = mcp_request("server/discover", 2, true, None)?;
    wrong_content_type
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json-patch+json".parse()?);
    assert_eq!(
        server.router().oneshot(wrong_content_type).await?.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    let mut stale = mcp_request("server/discover", 3, true, None)?;
    stale
        .headers_mut()
        .insert("mcp-protocol-version", "2025-11-25".parse()?);
    assert_eq!(
        server.router().oneshot(stale).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let mut mismatched = mcp_request("server/discover", 4, true, None)?;
    mismatched
        .headers_mut()
        .insert("mcp-method", "tools/list".parse()?);
    assert_eq!(
        server.router().oneshot(mismatched).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let mut stale_meta = request_meta();
    stale_meta["io.modelcontextprotocol/protocolVersion"] = json!("2025-11-25");
    let stale_body = request_with_params("tools/list", 5, &json!({"_meta": stale_meta}), None)?;
    assert_eq!(
        server.router().oneshot(stale_body).await?.status(),
        StatusCode::BAD_REQUEST
    );

    let mut malformed_identity = request_meta();
    malformed_identity["io.modelcontextprotocol/clientInfo"] = json!({"name": "client"});
    let malformed_identity =
        request_with_params("tools/list", 6, &json!({"_meta": malformed_identity}), None)?;
    assert_eq!(
        server.router().oneshot(malformed_identity).await?.status(),
        StatusCode::BAD_REQUEST
    );

    for forbidden in ["mcp-session-id", "last-event-id"] {
        let mut request = mcp_request("server/discover", 7, true, None)?;
        request.headers_mut().insert(forbidden, "opaque".parse()?);
        assert_eq!(
            server.router().oneshot(request).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }

    let initialize = request_with_params(
        "initialize",
        8,
        &json!({
            "protocolVersion": MCP_PROTOCOL_REVISION,
            "capabilities": {},
            "clientInfo": {"name": "legacy", "version": "1"}
        }),
        None,
    )?;
    assert_eq!(
        server.router().oneshot(initialize).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn bounded_body_and_host_origin_policy_fail_closed_without_reflection()
-> Result<(), Box<dyn Error>> {
    let mut config = McpHttpConfig::default();
    config.http.max_body_bytes = 512;
    config.allowed_hosts = vec!["api.example.test".to_owned()];
    config.http.trusted_origins = vec!["https://app.example.test".to_owned()];
    let server = contract_server(config)?;

    let mut oversized = mcp_request("server/discover", 1, true, None)?;
    oversized
        .headers_mut()
        .insert(header::HOST, "api.example.test".parse()?);
    *oversized.body_mut() = Body::from("x".repeat(513));
    oversized
        .headers_mut()
        .insert(header::CONTENT_LENGTH, "513".parse()?);
    let oversized = server.router().oneshot(oversized).await?;
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        oversized.headers()[header::CONTENT_TYPE],
        "application/json"
    );
    let oversized = response_json(oversized).await?;
    assert_eq!(oversized["error"]["code"], -32600);
    assert!(oversized.get("type").is_none());

    let mut wrong_host = mcp_request("server/discover", 2, true, None)?;
    wrong_host
        .headers_mut()
        .insert(header::HOST, "attacker.invalid".parse()?);
    let response = server.router().oneshot(wrong_host).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let rendered = String::from_utf8(to_bytes(response.into_body(), 4_096).await?.to_vec())?;
    assert!(!rendered.contains("attacker.invalid"));

    let mut wrong_origin = mcp_request("server/discover", 3, true, None)?;
    wrong_origin
        .headers_mut()
        .insert(header::HOST, "api.example.test".parse()?);
    wrong_origin
        .headers_mut()
        .insert(header::ORIGIN, "https://evil.example".parse()?);
    let response = server.router().oneshot(wrong_origin).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let rendered = String::from_utf8(to_bytes(response.into_body(), 4_096).await?.to_vec())?;
    assert!(!rendered.contains("evil.example"));
    Ok(())
}

#[tokio::test]
async fn bounded_response_failure_remains_a_json_rpc_error() -> Result<(), Box<dyn Error>> {
    let config = McpHttpConfig {
        max_json_response_bytes: 256,
        ..McpHttpConfig::default()
    };
    let server = contract_server(config)?;

    let response = server
        .router()
        .oneshot(mcp_request("tools/list", 9, true, Some("Bearer alpha"))?)
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let document = response_json(response).await?;
    assert_eq!(document["error"]["code"], -32603);
    assert!(document.get("type").is_none());
    Ok(())
}

#[tokio::test]
async fn private_list_cache_headers_preserve_authorized_variation() -> Result<(), Box<dyn Error>> {
    let server = contract_server(McpHttpConfig::default())?;

    let alpha = server
        .router()
        .oneshot(mcp_request("tools/list", 1, true, Some("Bearer alpha"))?)
        .await?;
    assert_eq!(alpha.status(), StatusCode::OK);
    assert_eq!(
        alpha.headers()[header::ETAG].to_str()?,
        format!("\"{ALPHA_ETAG}\"")
    );
    assert_eq!(
        alpha.headers()[header::CACHE_CONTROL],
        "private, max-age=60"
    );
    assert_eq!(alpha.headers()[header::VARY], "Authorization");

    let alpha_again = server
        .router()
        .oneshot(mcp_request("tools/list", 2, true, Some("Bearer alpha"))?)
        .await?;
    assert_eq!(
        alpha_again.headers()[header::ETAG].to_str()?,
        format!("\"{ALPHA_ETAG}\"")
    );

    let beta = server
        .router()
        .oneshot(mcp_request("tools/list", 3, true, Some("Bearer beta"))?)
        .await?;
    assert_eq!(
        beta.headers()[header::ETAG].to_str()?,
        format!("\"{BETA_ETAG}\"")
    );
    assert_ne!(alpha.headers()[header::ETAG], beta.headers()[header::ETAG]);
    Ok(())
}

#[tokio::test]
async fn subscription_stream_isolated_and_drain_is_bounded_and_graceful()
-> Result<(), Box<dyn Error>> {
    let server = contract_server(McpHttpConfig::default())?;
    let drain = server.drain_handle().clone();
    let router = server.router();
    let listen = request_with_params(
        "subscriptions/listen",
        41,
        &json!({
            "_meta": request_meta(),
            "notifications": {"toolsListChanged": true}
        }),
        None,
    )?;
    let response = router.clone().oneshot(listen).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(drain.in_flight(), 1);

    drain.begin_drain();
    assert!(!drain.is_ready());
    let rejected = router
        .clone()
        .oneshot(mcp_request("server/discover", 42, true, None)?)
        .await?;
    assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);

    let drain_task = tokio::spawn({
        let drain = drain.clone();
        async move { drain.drain().await }
    });
    let stream = String::from_utf8(to_bytes(response.into_body(), 64 * 1024).await?.to_vec())?;
    assert_eq!(drain_task.await?, McpDrainOutcome::Complete);
    assert_eq!(drain.in_flight(), 0);

    let Some(acknowledgment) = stream.find("notifications/subscriptions/acknowledged") else {
        return Err(std::io::Error::other("subscription acknowledgment missing").into());
    };
    let Some(graceful_close) = stream.rfind("io.modelcontextprotocol/subscriptionId") else {
        return Err(std::io::Error::other("graceful close metadata missing").into());
    };
    assert!(acknowledgment < graceful_close);
    assert!(stream.contains("\"io.modelcontextprotocol/subscriptionId\":41"));
    assert!(!stream.contains("notifications/progress"));
    assert!(!stream.contains("\nid:"));
    Ok(())
}

#[tokio::test]
async fn streamed_protocol_failures_are_redacted() -> Result<(), Box<dyn Error>> {
    let server = contract_server(McpHttpConfig::default())?;
    let listen = request_with_params(
        "subscriptions/listen",
        51,
        &json!({
            "_meta": request_meta(),
            "notifications": {"toolsListChanged": true}
        }),
        Some("Bearer stream-error"),
    )?;
    let response = server.router().oneshot(listen).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let stream = String::from_utf8(to_bytes(response.into_body(), 64 * 1024).await?.to_vec())?;
    assert!(stream.contains("MCP request failed"));
    assert!(!stream.contains("private-provider-diagnostic"));
    assert!(!stream.contains("private-response-data"));
    Ok(())
}

#[derive(Debug)]
struct CoreContextResolver;

impl CanonicalContextResolver for CoreContextResolver {
    fn resolve(
        &self,
        _metadata: &McpRequestMetadata,
        request: &RequestContext<RoleServer>,
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
            "policy.mcp-http"
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

#[derive(Clone)]
struct ContractHandler;

impl ServerHandler for ContractHandler {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(&[ProtocolVersion::V_2026_07_28])
    }

    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_tool_list_changed()
                .build(),
        )
        .with_protocol_version(ProtocolVersion::V_2026_07_28)
        .with_server_info(Implementation::new("contract-server", "0.1.0"))
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        let authorization = context
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.headers.get(header::AUTHORIZATION))
            .and_then(|value| value.to_str().ok());
        let etag = if authorization == Some("Bearer beta") {
            BETA_ETAG
        } else {
            ALPHA_ETAG
        };
        let mut meta = MetaObject::new();
        meta.insert(
            "io.omnius.mcp/catalogRevision".to_owned(),
            Value::String("catalog-7".to_owned()),
        );
        meta.insert(
            "io.omnius.mcp/catalogEtag".to_owned(),
            Value::String(format!("\"{etag}\"")),
        );
        meta.insert(
            "io.omnius.mcp/cacheControl".to_owned(),
            Value::String("private, max-age=60".to_owned()),
        );
        meta.insert("io.omnius.mcp/ttlMs".to_owned(), Value::from(60_000_u64));
        meta.insert(
            "io.omnius.mcp/cacheScope".to_owned(),
            Value::String("private".to_owned()),
        );
        let mut result = ListToolsResult::with_all_items(Vec::new())
            .with_ttl_ms(60_000)
            .with_cache_scope(CacheScope::Private);
        result.meta = Some(meta);
        ready(Ok(result))
    }

    fn accepted_subscription_filter(
        &self,
        requested: &SubscriptionFilter,
    ) -> Option<SubscriptionFilter> {
        Some(requested.clone())
    }

    fn listen(
        &self,
        context: SubscriptionContext,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        let fail_with_private_diagnostic = context
            .request_context()
            .extensions
            .get::<http::request::Parts>()
            .and_then(|parts| parts.headers.get(header::AUTHORIZATION))
            .and_then(|value| value.to_str().ok())
            == Some("Bearer stream-error");
        async move {
            let signal = McpDrainSignal::from_request_context(context.request_context())
                .cloned()
                .ok_or_else(|| ErrorData::internal_error("missing transport drain signal", None))?;
            if fail_with_private_diagnostic {
                return Err(ErrorData::internal_error(
                    "private-provider-diagnostic",
                    Some(json!({"detail": "private-response-data"})),
                ));
            }
            tokio::select! {
                () = signal.cancelled() => Ok(()),
                () = context.cancelled() => Ok(()),
            }
        }
    }
}

fn contract_server(config: McpHttpConfig) -> Result<McpHttpServer, Box<dyn Error>> {
    Ok(McpHttpServer::new(ContractHandler, config)?)
}

fn request_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_REVISION,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
            "name": "contract-client",
            "version": "1.0.0"
        }
    })
}

fn mcp_request(
    method: &str,
    id: i64,
    include_meta: bool,
    authorization: Option<&str>,
) -> Result<Request<Body>, Box<dyn Error>> {
    let params = if include_meta {
        json!({"_meta": request_meta()})
    } else {
        json!({})
    };
    request_with_params(method, id, &params, authorization)
}

fn request_with_params(
    method: &str,
    id: i64,
    params: &Value,
    authorization: Option<&str>,
) -> Result<Request<Body>, Box<dyn Error>> {
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(MCP_HTTP_PATH)
        .header(header::HOST, "localhost")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("mcp-protocol-version", MCP_PROTOCOL_REVISION)
        .header("mcp-method", method);
    if let Some(authorization) = authorization {
        builder = builder.header(header::AUTHORIZATION, authorization);
    }
    Ok(builder.body(Body::from(serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    }))?))?)
}

async fn response_json(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), 2 * 1024 * 1024).await?,
    )?)
}
