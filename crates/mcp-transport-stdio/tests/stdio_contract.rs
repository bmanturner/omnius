//! Behavioral contracts for bounded, stateless stdio MCP framing.

use std::{
    borrow::Cow,
    error::Error,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityRegistryBuilder, InvocationContext, TenantMode, TraceContext,
};
use omnius_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use omnius_authz_basic::Decision;
use omnius_core::RequestId as CoreRequestId;
use omnius_mcp_server_core::{
    McpCanonicalContext, McpExtensionCatalog, McpKernel, McpRequestMetadata,
    sdk::{CanonicalContextResolver, ContextResolutionError, ServerAdapter},
};
use omnius_mcp_transport_stdio::{
    LegacyCompatibilityAdapter, STDIO_TRANSPORT_PROFILE, StdioConfig, StdioDrainHandle,
    StdioFraming, StdioLifecycle, StdioTransport, TerminationReason, serve_stdio_handler_with_io,
    serve_stdio_with_io,
};
use rmcp::{
    ServerHandler,
    model::{
        ClientNotification, DiscoverResult, EmptyResult, ErrorData, GetMeta, JsonRpcMessage,
        NumberOrString, ProtocolVersion, ServerCapabilities, ServerResult,
    },
    service::{MaybeSendFuture, RequestContext, RoleServer},
    transport::Transport,
};
use time::OffsetDateTime;
use tokio::{
    io::{AsyncWrite, AsyncWriteExt, DuplexStream},
    sync::Notify,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Default)]
struct CaptureWriter(Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    fn bytes(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl AsyncWrite for CaptureWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buffer);
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PendingShutdownWriter;

impl AsyncWrite for PendingShutdownWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Pending
    }
}

#[derive(Clone)]
struct SlowDiscover {
    started: Arc<Notify>,
}

impl ServerHandler for SlowDiscover {
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Owned(vec![ProtocolVersion::V_2026_07_28])
    }

    fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<DiscoverResult, ErrorData>> + MaybeSendFuture + '_ {
        let started = self.started.clone();
        async move {
            started.notify_one();
            tokio::time::sleep(Duration::from_millis(50)).await;
            Ok(DiscoverResult::new(
                vec![ProtocolVersion::V_2026_07_28],
                ServerCapabilities::default(),
            ))
        }
    }
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
            "policy.mcp-stdio"
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

struct Harness {
    input: Option<DuplexStream>,
    transport: StdioTransport<DuplexStream, CaptureWriter>,
    observer: omnius_mcp_transport_stdio::StdioObserver,
    stdout: CaptureWriter,
    stderr: CaptureWriter,
    cancellation: CancellationToken,
}

impl Harness {
    fn new(config: StdioConfig) -> Self {
        let (input, transport_input) = tokio::io::duplex(4096);
        let stdout = CaptureWriter::default();
        let stderr = CaptureWriter::default();
        let cancellation = CancellationToken::new();
        let (transport, observer) = StdioTransport::new(
            transport_input,
            stdout.clone(),
            stderr.clone(),
            config,
            cancellation.clone(),
        );
        Self {
            input: Some(input),
            transport,
            observer,
            stdout,
            stderr,
            cancellation,
        }
    }

    async fn write(&mut self, bytes: &[u8]) {
        assert!(self.input.is_some(), "test input must remain open");
        if let Some(input) = self.input.as_mut() {
            assert!(
                input.write_all(bytes).await.is_ok(),
                "test input must accept frame"
            );
        }
    }

    fn close_input(&mut self) {
        self.input.take();
    }
}

fn current_request(id: i64, method: &str, additional_params: &str) -> Vec<u8> {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{{\"_meta\":{{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{{}},\"io.modelcontextprotocol/clientInfo\":{{\"name\":\"stdio-client\",\"version\":\"1\"}}}}{additional_params}}}}}\n"
    )
    .into_bytes()
}

fn cancellation(request_id: i64) -> Vec<u8> {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{{\"requestId\":{request_id}}}}}\n"
    )
    .into_bytes()
}

fn progress() -> &'static [u8] {
    b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progressToken\":\"shared\",\"progress\":1}}\n"
}

fn empty_response(id: NumberOrString) -> rmcp::model::ServerJsonRpcMessage {
    rmcp::model::ServerJsonRpcMessage::response(ServerResult::EmptyResult(EmptyResult {}), id)
}

#[tokio::test]
async fn ac_ai_069_stdout_contains_only_one_newline_delimited_protocol_frame() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(1, "server/discover", ""))
        .await;

    let received = harness.transport.receive().await;
    let internal_id = match received {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(internal_id.is_some());
    let Some(internal_id) = internal_id else {
        return;
    };
    assert!(
        harness
            .transport
            .send(empty_response(internal_id))
            .await
            .is_ok()
    );

    let stdout = harness.stdout.bytes();
    assert_eq!(
        stdout.iter().position(|byte| *byte == b'\n'),
        stdout.len().checked_sub(1)
    );
    assert!(serde_json::from_slice::<serde_json::Value>(&stdout).is_ok());
    let response = serde_json::from_slice::<serde_json::Value>(&stdout);
    assert!(response.is_ok());
    if let Ok(response) = response {
        assert_eq!(response["id"], 1);
    }
    assert!(harness.stderr.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_070_entrypoint_uses_explicit_core_context() -> Result<(), Box<dyn Error>> {
    let traces = CaptureWriter::default();
    let trace_writer = traces.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || trace_writer.clone())
        .finish();
    assert!(tracing::subscriber::set_global_default(subscriber).is_ok());
    tracing::info!("stdio-trace-capture-probe");
    let registry = Arc::new(CapabilityRegistryBuilder::new().build());
    let server = ServerAdapter::with_context_resolver(
        McpKernel::new(registry),
        McpExtensionCatalog::empty(),
        Arc::new(CoreContextResolver),
    );
    let (mut input, transport_input) = tokio::io::duplex(4_096);
    input
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{},\"io.modelcontextprotocol/clientInfo\":{\"name\":\"stdio-client\",\"version\":\"1\"}},\"secret\":\"sensitive-token\"}}\n",
        )
        .await?;
    drop(input);
    let stdout = CaptureWriter::default();
    let diagnostics = CaptureWriter::default();

    let report = serve_stdio_with_io(
        server,
        transport_input,
        stdout.clone(),
        diagnostics.clone(),
        StdioConfig::default(),
        CancellationToken::new(),
    )
    .await?;

    assert_eq!(report.termination, TerminationReason::Eof);
    let response = serde_json::from_slice::<serde_json::Value>(&stdout.bytes())?;
    assert_eq!(response["result"]["supportedVersions"][0], "2026-07-28");
    assert!(diagnostics.bytes().is_empty());
    let traces = String::from_utf8_lossy(&traces.bytes()).into_owned();
    assert!(traces.contains("stdio-trace-capture-probe"));
    assert!(!traces.contains("sensitive-token"));
    Ok(())
}

#[tokio::test]
async fn generic_entrypoint_drains_composed_handler_after_eof() -> Result<(), Box<dyn Error>> {
    let (mut input, transport_input) = tokio::io::duplex(4_096);
    input
        .write_all(&current_request(3, "server/discover", ""))
        .await?;
    drop(input);
    let stdout = CaptureWriter::default();
    let diagnostics = CaptureWriter::default();

    let report = serve_stdio_handler_with_io(
        SlowDiscover {
            started: Arc::new(Notify::new()),
        },
        transport_input,
        stdout.clone(),
        diagnostics.clone(),
        StdioConfig::default(),
        StdioDrainHandle::new(),
    )
    .await?;

    assert_eq!(report.termination, TerminationReason::Eof);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&stdout.bytes())?["id"],
        3
    );
    assert!(diagnostics.bytes().is_empty());
    Ok(())
}

#[tokio::test]
async fn ac_ai_069_malformed_frame_fails_closed_without_stdout_output() {
    let mut harness = Harness::new(StdioConfig::default());
    harness.write(b"not-json\n").await;

    assert!(harness.transport.receive().await.is_none());
    let snapshot = harness.observer.snapshot().await;
    assert_eq!(
        snapshot.termination,
        Some(TerminationReason::MalformedFrame)
    );
    assert!(harness.stdout.bytes().is_empty());
    assert!(!harness.stderr.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_070_current_request_requires_complete_client_identity() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(
            b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"server/discover\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}\n",
        )
        .await;

    assert!(harness.transport.receive().await.is_none());
    assert_eq!(
        harness.observer.snapshot().await.termination,
        Some(TerminationReason::InvalidRequestMetadata)
    );
    assert!(harness.stdout.bytes().is_empty());
}
#[tokio::test]
async fn ac_ai_069_oversize_frame_fails_closed_at_configured_bound() {
    let mut harness = Harness::new(StdioConfig::default().with_max_frame_bytes(32));
    harness.write(&[b'x'; 33]).await;

    assert!(harness.transport.receive().await.is_none());
    assert_eq!(
        harness.observer.snapshot().await.termination,
        Some(TerminationReason::InputFrameTooLarge)
    );
    assert!(harness.stdout.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_069_pending_work_saturation_fails_closed_without_exceeding_bound() {
    let mut harness = Harness::new(StdioConfig::default().with_max_pending_requests(1));
    harness
        .write(&current_request(3, "server/discover", ""))
        .await;
    harness
        .write(&current_request(4, "server/discover", ""))
        .await;

    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_none());
    let snapshot = harness.observer.snapshot().await;
    assert_eq!(
        snapshot.termination,
        Some(TerminationReason::PendingLimitReached)
    );
    assert_eq!(snapshot.max_observed_pending, 1);
    assert!(harness.stdout.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_069_unterminated_current_frame_fails_closed_on_eof() {
    let mut harness = Harness::new(StdioConfig::default());
    let mut frame = current_request(1, "server/discover", "");
    frame.pop();
    harness.write(&frame).await;
    harness.close_input();

    assert!(harness.transport.receive().await.is_none());
    assert_eq!(
        harness.observer.snapshot().await.termination,
        Some(TerminationReason::UnterminatedFrame)
    );
}

#[tokio::test]
async fn ac_ai_069_eof_allows_an_admitted_response_to_drain_before_close() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(7, "server/discover", ""))
        .await;
    let received = harness.transport.receive().await;
    let internal_id = match received {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(internal_id.is_some());
    let Some(internal_id) = internal_id else {
        return;
    };
    harness.close_input();
    assert!(harness.transport.receive().await.is_none());

    assert!(
        harness
            .transport
            .send(empty_response(internal_id))
            .await
            .is_ok()
    );
    let snapshot = harness.observer.snapshot().await;
    assert_eq!(snapshot.termination, Some(TerminationReason::Eof));
    assert_eq!(snapshot.pending_requests, 0);
    assert!(!harness.stdout.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_069_rmcp_service_drains_slow_response_after_stdin_eof() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(8, "server/discover", ""))
        .await;
    harness.close_input();
    let stdout = harness.stdout.clone();
    let observer = harness.observer.clone();
    let running = rmcp::service::serve_directly_with_ct(
        SlowDiscover {
            started: Arc::new(Notify::new()),
        },
        harness.transport,
        None,
        CancellationToken::new(),
    );

    let quit = running.waiting().await;
    assert!(quit.is_ok());
    let Ok(quit) = quit else {
        return;
    };
    assert!(matches!(quit, rmcp::service::QuitReason::Closed));
    let output = stdout.bytes();
    let response = serde_json::from_slice::<serde_json::Value>(&output);
    assert!(response.is_ok());
    let Ok(response) = response else {
        return;
    };
    assert_eq!(response["id"], 8);
    let snapshot = observer.snapshot().await;
    assert_eq!(snapshot.termination, Some(TerminationReason::Eof));
    assert_eq!(snapshot.pending_requests, 0);
}

#[tokio::test]
async fn ac_ai_069_process_cancellation_drops_in_flight_rmcp_response() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(81, "server/discover", ""))
        .await;
    let stdout = harness.stdout.clone();
    let observer = harness.observer.clone();
    let started = Arc::new(Notify::new());
    let cancellation = harness.cancellation.clone();
    let running = rmcp::service::serve_directly_with_ct(
        SlowDiscover {
            started: started.clone(),
        },
        harness.transport,
        None,
        cancellation.clone(),
    );
    started.notified().await;
    cancellation.cancel();

    let quit = running.waiting().await;
    assert!(quit.is_ok());
    let Ok(quit) = quit else {
        return;
    };
    assert!(matches!(
        quit,
        rmcp::service::QuitReason::Cancelled | rmcp::service::QuitReason::Closed
    ));
    assert!(stdout.bytes().is_empty());
    let snapshot = observer.snapshot().await;
    assert_eq!(snapshot.pending_requests, 0);
}

#[tokio::test]
async fn ac_ai_069_cancellation_releases_pending_work_without_protocol_noise() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(9, "server/discover", ""))
        .await;
    harness.write(&cancellation(9)).await;

    assert!(matches!(
        harness.transport.receive().await,
        Some(JsonRpcMessage::Request(_))
    ));
    assert!(matches!(
        harness.transport.receive().await,
        Some(JsonRpcMessage::Notification(_))
    ));
    assert_eq!(harness.observer.snapshot().await.pending_requests, 0);
    assert!(harness.stdout.bytes().is_empty());
}

#[tokio::test]
async fn ac_ai_069_cancelled_id_reuse_cannot_accept_a_stale_response() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(10, "server/discover", ""))
        .await;
    let first = harness.transport.receive().await;
    let first_id = match first {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(first_id.is_some());
    let Some(first_id) = first_id else {
        return;
    };
    harness.write(&cancellation(10)).await;
    assert!(harness.transport.receive().await.is_some());

    harness
        .write(&current_request(10, "server/discover", ""))
        .await;
    let second = harness.transport.receive().await;
    let second_id = match second {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(second_id.is_some());
    let Some(second_id) = second_id else {
        return;
    };
    assert_ne!(first_id, second_id);

    assert!(
        harness
            .transport
            .send(empty_response(first_id))
            .await
            .is_ok()
    );
    assert!(harness.stdout.bytes().is_empty());
    assert_eq!(harness.observer.snapshot().await.pending_requests, 1);
    assert!(
        harness
            .transport
            .send(empty_response(second_id))
            .await
            .is_ok()
    );
    let response = serde_json::from_slice::<serde_json::Value>(&harness.stdout.bytes());
    assert!(response.is_ok());
    if let Ok(response) = response {
        assert_eq!(response["id"], 10);
    }
    assert_eq!(harness.observer.snapshot().await.pending_requests, 0);
}

#[tokio::test(start_paused = true)]
async fn ac_ai_069_request_deadline_synthesizes_cancellation_and_releases_admission() {
    let mut harness =
        Harness::new(StdioConfig::default().with_request_deadline(Duration::from_millis(10)));
    harness
        .write(&current_request(11, "server/discover", ""))
        .await;
    let received = harness.transport.receive().await;
    let internal_id = match received {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(internal_id.is_some());
    let Some(internal_id) = internal_id else {
        return;
    };

    let deadline_message = harness.transport.receive().await;
    assert!(deadline_message.is_some());
    let Some(deadline_message) = deadline_message else {
        return;
    };
    let JsonRpcMessage::Notification(notification) = deadline_message else {
        panic!("deadline must produce a cancellation notification");
    };
    let ClientNotification::CancelledNotification(cancelled) = notification.notification else {
        panic!("deadline must use MCP cancellation");
    };
    assert_eq!(cancelled.params.request_id, Some(internal_id.clone()));
    assert_eq!(harness.observer.snapshot().await.pending_requests, 0);
    harness
        .write(&current_request(11, "server/discover", ""))
        .await;
    let second = harness.transport.receive().await;
    let second_id = match second {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(second_id.is_some());
    let Some(second_id) = second_id else {
        return;
    };
    assert_ne!(internal_id, second_id);
    assert!(
        harness
            .transport
            .send(empty_response(internal_id))
            .await
            .is_ok()
    );
    assert!(harness.stdout.bytes().is_empty());
    assert_eq!(harness.observer.snapshot().await.pending_requests, 1);
    assert!(
        harness
            .transport
            .send(empty_response(second_id))
            .await
            .is_ok()
    );
    let response = serde_json::from_slice::<serde_json::Value>(&harness.stdout.bytes());
    assert!(response.is_ok());
    if let Ok(response) = response {
        assert_eq!(response["id"], 11);
    }
    assert_eq!(harness.observer.snapshot().await.pending_requests, 0);
}

#[tokio::test]
async fn ac_ai_069_process_cancellation_closes_input_without_stdout_output() {
    let mut harness = Harness::new(StdioConfig::default());
    harness.cancellation.cancel();

    assert!(harness.transport.receive().await.is_none());
    assert_eq!(
        harness.observer.snapshot().await.termination,
        Some(TerminationReason::Cancelled)
    );
    assert!(harness.stdout.bytes().is_empty());
}

#[tokio::test(start_paused = true)]
async fn ac_ai_069_cancellation_shutdown_is_bounded_when_stdout_never_closes() {
    let (_input, transport_input) = tokio::io::duplex(64);
    let config = StdioConfig::default().with_output_write_deadline(Duration::from_millis(5));
    let (mut transport, observer) = StdioTransport::new(
        transport_input,
        PendingShutdownWriter,
        CaptureWriter::default(),
        config,
        CancellationToken::new(),
    );

    assert!(transport.close().await.is_err());
    assert_eq!(
        observer.snapshot().await.termination,
        Some(TerminationReason::OutputFailure)
    );
}

#[test]
fn ac_ai_070_stdio_profile_has_no_session_http_or_sse_assumptions() {
    assert_eq!(STDIO_TRANSPORT_PROFILE.protocol_revision, "2026-07-28");
    assert_eq!(
        STDIO_TRANSPORT_PROFILE.framing,
        StdioFraming::NewlineDelimitedJson
    );
    assert_eq!(STDIO_TRANSPORT_PROFILE.lifecycle, StdioLifecycle::Stateless);
}

#[tokio::test]
async fn ac_ai_071_subscription_admission_is_isolated_from_request_progress() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(
            21,
            "subscriptions/listen",
            ",\"notifications\":{}",
        ))
        .await;
    harness
        .write(&current_request(22, "server/discover", ""))
        .await;
    harness.write(progress()).await;

    assert!(harness.transport.receive().await.is_some());
    let ordinary = harness.transport.receive().await;
    let ordinary_id = match ordinary {
        Some(JsonRpcMessage::Request(request)) => Some(request.id),
        _ => None,
    };
    assert!(ordinary_id.is_some());
    let Some(ordinary_id) = ordinary_id else {
        return;
    };
    assert!(harness.transport.receive().await.is_some());
    let before_response = harness.observer.snapshot().await;
    assert_eq!(before_response.pending_subscriptions, 1);
    assert_eq!(before_response.pending_requests, 1);

    assert!(
        harness
            .transport
            .send(empty_response(ordinary_id))
            .await
            .is_ok()
    );
    let after_response = harness.observer.snapshot().await;
    assert_eq!(after_response.pending_subscriptions, 1);
    assert_eq!(after_response.pending_requests, 0);
}

#[tokio::test]
async fn ac_ai_071_subscription_cancellation_does_not_cancel_ordinary_request() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(&current_request(
            31,
            "subscriptions/listen",
            ",\"notifications\":{}",
        ))
        .await;
    harness
        .write(&current_request(32, "server/discover", ""))
        .await;
    harness.write(&cancellation(31)).await;

    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_some());
    let snapshot = harness.observer.snapshot().await;
    assert_eq!(snapshot.pending_subscriptions, 0);
    assert_eq!(snapshot.pending_requests, 1);
}

#[tokio::test]
async fn ac_ai_072_legacy_adapter_observably_translates_framing_metadata_and_lifecycle() {
    let config =
        StdioConfig::default().with_legacy_compatibility(LegacyCompatibilityAdapter::new());
    let mut harness = Harness::new(config);
    harness
        .write(
            b"\xEF\xBB\xBF{\"jsonrpc\":\"2.0\",\"id\":41,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{},\"clientInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}\r\n",
        )
        .await;

    let message = harness.transport.receive().await;
    assert!(message.is_some());
    let Some(message) = message else {
        return;
    };
    let JsonRpcMessage::Request(request) = message else {
        panic!("translated message must remain a request");
    };
    assert_eq!(request.request.method(), "server/discover");
    assert_eq!(
        request.request.get_meta().protocol_version(),
        Some(rmcp::model::ProtocolVersion::V_2026_07_28)
    );
    let compatibility = harness.observer.snapshot().await.compatibility;
    assert_eq!(compatibility.translated_frames, 1);
    assert_eq!(compatibility.translated_metadata, 1);
    assert_eq!(compatibility.translated_initializations, 1);
}

#[tokio::test]
async fn ac_ai_072_legacy_metadata_translation_preserves_application_parameters() {
    let config =
        StdioConfig::default().with_legacy_compatibility(LegacyCompatibilityAdapter::new());
    let mut harness = Harness::new(config);
    harness
        .write(
            b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"vendor/do\",\"params\":{\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"clientCapabilities\":{},\"clientInfo\":{\"name\":\"legacy\",\"version\":\"1\"}},\"capabilities\":{\"domain\":true}}}\n",
        )
        .await;

    let message = harness.transport.receive().await;
    assert!(message.is_some());
    let Some(message) = message else {
        return;
    };
    let serialized = serde_json::to_value(message);
    assert!(serialized.is_ok());
    let Ok(serialized) = serialized else {
        return;
    };
    assert_eq!(serialized["params"]["capabilities"]["domain"], true);
    assert_eq!(
        serialized["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
        "2026-07-28"
    );
    assert_eq!(
        serialized["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"],
        serde_json::json!({})
    );
    assert_eq!(
        harness
            .observer
            .snapshot()
            .await
            .compatibility
            .translated_metadata,
        1
    );
}

#[tokio::test]
async fn ac_ai_072_current_mode_rejects_legacy_initialization_without_session_state() {
    let mut harness = Harness::new(StdioConfig::default());
    harness
        .write(
            b"{\"jsonrpc\":\"2.0\",\"id\":51,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2026-07-28\",\"capabilities\":{},\"clientInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}\n",
        )
        .await;

    assert!(harness.transport.receive().await.is_none());
    assert_eq!(
        harness.observer.snapshot().await.termination,
        Some(TerminationReason::InitializationForbidden)
    );
    assert!(harness.stdout.bytes().is_empty());
}

#[tokio::test(start_paused = true)]
async fn ac_ai_069_diagnostics_are_bounded_and_never_echo_peer_data() {
    let config = StdioConfig::default()
        .with_request_deadline(Duration::from_millis(1))
        .with_diagnostic_limits(1, 64);
    let mut harness = Harness::new(config);
    harness
        .write(&current_request(
            61,
            "vendor/do",
            ",\"secret\":\"sensitive-token\"",
        ))
        .await;
    harness
        .write(&current_request(
            62,
            "vendor/do",
            ",\"secret\":\"sensitive-token\"",
        ))
        .await;
    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_some());
    assert!(harness.transport.receive().await.is_some());

    let stderr = harness.stderr.bytes();
    assert_eq!(
        stderr.iter().position(|byte| *byte == b'\n'),
        stderr.len().checked_sub(1)
    );
    assert!(!String::from_utf8_lossy(&stderr).contains("sensitive-token"));
    let diagnostics = harness.observer.snapshot().await.diagnostics;
    assert_eq!(diagnostics.emitted, 1);
    assert_eq!(diagnostics.dropped, 1);
}
