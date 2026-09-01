//! Bounded, stateless MCP JSON-RPC framing over process stdio.
//!
//! Stdout is owned exclusively by [`StdioTransport`] protocol frames. All
//! transport diagnostics are fixed, redacted codes written through a separately
//! supplied diagnostic writer (normally stderr).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};

use omnius_mcp_server_core::{MCP_PROTOCOL_REVISION, sdk::ServerAdapter};
use rmcp::{
    RoleServer, ServerHandler,
    model::{
        CancelledNotification, CancelledNotificationParam, ClientJsonRpcMessage,
        ClientNotification, GetMeta, JsonRpcMessage, ProtocolVersion, RequestId,
        ServerJsonRpcMessage,
    },
    service::{QuitReason, RxJsonRpcMessage, Service, TxJsonRpcMessage},
    transport::Transport,
};
use serde_json::{Map, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    sync::{Mutex, Notify},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";
const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";
const SUBSCRIPTIONS_LISTEN: &str = "subscriptions/listen";
const INITIALIZE: &str = "initialize";
const DISCOVER: &str = "server/discover";
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";
const MAX_CONFIGURED_DEADLINE: Duration = Duration::from_hours(24);

/// Wire framing used by the stdio transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioFraming {
    /// One complete JSON-RPC document per LF-terminated frame.
    NewlineDelimitedJson,
}

/// Lifecycle guarantees provided by the stdio transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioLifecycle {
    /// Per-request metadata with no initialization, sessions, HTTP endpoint, or SSE resumption.
    Stateless,
}

/// Static transport facts used by composition and conformance checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioTransportProfile {
    /// Protocol revision accepted on every current request.
    pub protocol_revision: &'static str,
    /// Process-stream wire framing.
    pub framing: StdioFraming,
    /// Request lifecycle and state model.
    pub lifecycle: StdioLifecycle,
}

/// The current stateless stdio transport profile.
pub const STDIO_TRANSPORT_PROFILE: StdioTransportProfile = StdioTransportProfile {
    protocol_revision: MCP_PROTOCOL_REVISION,
    framing: StdioFraming::NewlineDelimitedJson,
    lifecycle: StdioLifecycle::Stateless,
};

/// Explicit adapter for old stdio framing and request metadata locations.
///
/// Enabling this adapter accepts a UTF-8 BOM on the first frame, CRLF, and a
/// final EOF-terminated frame. It also moves legacy request metadata into the
/// current `_meta` namespace and maps `initialize` to stateless
/// `server/discover`. It does not enable old protocol revisions or session state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyCompatibilityAdapter;

impl Default for LegacyCompatibilityAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacyCompatibilityAdapter {
    /// Explicitly enables the legacy translation boundary.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn translate(value: &mut Value) -> Result<TranslationDelta, ()> {
        let object = value.as_object_mut().ok_or(())?;
        let is_request = object.get("id").is_some() && object.get("method").is_some();
        if !is_request {
            return Ok(TranslationDelta::default());
        }

        let initialization = object.get("method").and_then(Value::as_str) == Some(INITIALIZE);
        if initialization {
            object.insert("method".to_owned(), Value::String(DISCOVER.to_owned()));
        }

        let params = object
            .entry("params".to_owned())
            .or_insert_with(|| Value::Object(Map::new()))
            .as_object_mut()
            .ok_or(())?;
        let metadata_translated = if initialization {
            let protocol_version = params.remove("protocolVersion");
            let client_info = params.remove("clientInfo");
            let client_capabilities = take_legacy_capabilities(params)?;
            let translated = protocol_version.is_some()
                || client_info.is_some()
                || client_capabilities.is_some();
            if translated {
                let meta = params
                    .entry("_meta".to_owned())
                    .or_insert_with(|| Value::Object(Map::new()))
                    .as_object_mut()
                    .ok_or(())?;
                merge_legacy_metadata(meta, META_PROTOCOL_VERSION, protocol_version)?;
                merge_legacy_metadata(meta, META_CLIENT_INFO, client_info)?;
                merge_legacy_metadata(meta, META_CLIENT_CAPABILITIES, client_capabilities)?;
            }
            translated
        } else {
            let Some(meta) = params.get_mut("_meta").and_then(Value::as_object_mut) else {
                return Ok(TranslationDelta {
                    metadata: false,
                    initialization,
                });
            };
            let protocol_version = meta.remove("protocolVersion");
            let client_info = meta.remove("clientInfo");
            let client_capabilities = take_legacy_capabilities(meta)?;
            let translated = protocol_version.is_some()
                || client_info.is_some()
                || client_capabilities.is_some();
            if translated {
                merge_legacy_metadata(meta, META_PROTOCOL_VERSION, protocol_version)?;
                merge_legacy_metadata(meta, META_CLIENT_INFO, client_info)?;
                merge_legacy_metadata(meta, META_CLIENT_CAPABILITIES, client_capabilities)?;
            }
            translated
        };

        Ok(TranslationDelta {
            metadata: metadata_translated,
            initialization,
        })
    }
}

fn take_legacy_capabilities(params: &mut Map<String, Value>) -> Result<Option<Value>, ()> {
    match (
        params.remove("clientCapabilities"),
        params.remove("capabilities"),
    ) {
        (Some(left), Some(right)) if left != right => Err(()),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

fn merge_legacy_metadata(
    meta: &mut Map<String, Value>,
    current_key: &str,
    legacy_value: Option<Value>,
) -> Result<(), ()> {
    let Some(legacy_value) = legacy_value else {
        return Ok(());
    };
    if let Some(current_value) = meta.get(current_key) {
        if current_value != &legacy_value {
            return Err(());
        }
        return Ok(());
    }
    meta.insert(current_key.to_owned(), legacy_value);
    Ok(())
}

/// Resource bounds applied to one stdio service.
#[derive(Clone, Copy, Debug)]
pub struct StdioConfig {
    max_frame_bytes: usize,
    max_pending_requests: usize,
    max_pending_subscriptions: usize,
    request_deadline: Duration,
    shutdown_deadline: Duration,
    output_write_deadline: Duration,
    max_diagnostic_events: usize,
    max_diagnostic_bytes: usize,
    diagnostic_write_deadline: Duration,
    legacy: Option<LegacyCompatibilityAdapter>,
}

impl Default for StdioConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: 1024 * 1024,
            max_pending_requests: 64,
            max_pending_subscriptions: 16,
            request_deadline: Duration::from_secs(30),
            shutdown_deadline: Duration::from_secs(7),
            output_write_deadline: Duration::from_secs(5),
            max_diagnostic_events: 64,
            max_diagnostic_bytes: 128,
            diagnostic_write_deadline: Duration::from_millis(100),
            legacy: None,
        }
    }
}

impl StdioConfig {
    /// Sets the maximum JSON bytes in one input or output frame.
    #[must_use]
    pub fn with_max_frame_bytes(mut self, limit: usize) -> Self {
        self.max_frame_bytes = limit.max(1);
        self
    }

    /// Sets the maximum concurrently pending ordinary requests.
    #[must_use]
    pub fn with_max_pending_requests(mut self, limit: usize) -> Self {
        self.max_pending_requests = limit.max(1);
        self
    }

    /// Sets the independent maximum for long-lived subscription requests.
    #[must_use]
    pub fn with_max_pending_subscriptions(mut self, limit: usize) -> Self {
        self.max_pending_subscriptions = limit.max(1);
        self
    }

    /// Sets the deadline for ordinary requests. Subscriptions are not assigned a
    /// request-progress deadline and live until response, cancellation, or EOF.
    #[must_use]
    pub fn with_request_deadline(mut self, deadline: Duration) -> Self {
        self.request_deadline = bounded_deadline(deadline);
        self
    }

    /// Sets the upper bound for service drain and shutdown.
    #[must_use]
    pub fn with_shutdown_deadline(mut self, deadline: Duration) -> Self {
        self.shutdown_deadline = bounded_deadline(deadline);
        self
    }

    /// Sets the maximum time allowed to lock, write, and flush one stdout frame.
    #[must_use]
    pub fn with_output_write_deadline(mut self, deadline: Duration) -> Self {
        self.output_write_deadline = bounded_deadline(deadline);
        self
    }

    /// Sets the maximum number and byte length of redacted diagnostic lines.
    #[must_use]
    pub fn with_diagnostic_limits(mut self, events: usize, bytes_per_event: usize) -> Self {
        self.max_diagnostic_events = events.max(1);
        self.max_diagnostic_bytes = bytes_per_event.max(1);
        self
    }

    /// Sets the maximum time allowed to emit one bounded stderr diagnostic.
    #[must_use]
    pub fn with_diagnostic_write_deadline(mut self, deadline: Duration) -> Self {
        self.diagnostic_write_deadline = bounded_deadline(deadline);
        self
    }

    /// Enables the explicit legacy translation boundary.
    #[must_use]
    pub const fn with_legacy_compatibility(mut self, adapter: LegacyCompatibilityAdapter) -> Self {
        self.legacy = Some(adapter);
        self
    }
}

fn bounded_deadline(deadline: Duration) -> Duration {
    deadline.min(MAX_CONFIGURED_DEADLINE)
}

/// A fixed terminal transport category containing no peer-controlled detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TerminationReason {
    /// Stdin closed after its last newline-delimited frame.
    Eof,
    /// The process or caller cancellation token fired.
    Cancelled,
    /// A frame was not valid JSON-RPC.
    MalformedFrame,
    /// An input frame exceeded its configured bound.
    InputFrameTooLarge,
    /// EOF interrupted a current-protocol frame before its newline.
    UnterminatedFrame,
    /// Required current request metadata was missing or malformed.
    InvalidRequestMetadata,
    /// The request selected a protocol revision other than the baseline.
    UnsupportedProtocolVersion,
    /// Current-only mode received legacy initialization.
    InitializationForbidden,
    /// A request identifier was reused while still pending.
    DuplicateRequestId,
    /// An independent pending-work pool reached its bound.
    PendingLimitReached,
    /// Reading stdin failed.
    InputFailure,
    /// Serializing or writing a protocol response failed.
    OutputFailure,
    /// A protocol response exceeded the configured frame bound.
    OutputFrameTooLarge,
    /// Graceful drain exceeded its configured deadline.
    ShutdownDeadline,
    /// The RMCP service task failed.
    ServiceFailure,
}

impl TerminationReason {
    const fn code(self) -> u8 {
        match self {
            Self::Eof => 1,
            Self::Cancelled => 2,
            Self::MalformedFrame => 3,
            Self::InputFrameTooLarge => 4,
            Self::UnterminatedFrame => 5,
            Self::InvalidRequestMetadata => 6,
            Self::UnsupportedProtocolVersion => 7,
            Self::InitializationForbidden => 8,
            Self::DuplicateRequestId => 9,
            Self::PendingLimitReached => 10,
            Self::InputFailure => 11,
            Self::OutputFailure => 12,
            Self::OutputFrameTooLarge => 13,
            Self::ShutdownDeadline => 14,
            Self::ServiceFailure => 15,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Eof,
            2 => Self::Cancelled,
            3 => Self::MalformedFrame,
            4 => Self::InputFrameTooLarge,
            5 => Self::UnterminatedFrame,
            6 => Self::InvalidRequestMetadata,
            7 => Self::UnsupportedProtocolVersion,
            8 => Self::InitializationForbidden,
            9 => Self::DuplicateRequestId,
            10 => Self::PendingLimitReached,
            11 => Self::InputFailure,
            12 => Self::OutputFailure,
            13 => Self::OutputFrameTooLarge,
            14 => Self::ShutdownDeadline,
            15 => Self::ServiceFailure,
            _ => return None,
        })
    }

    const fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::Eof => b"mcp-stdio:eof",
            Self::Cancelled => b"mcp-stdio:cancelled",
            Self::MalformedFrame => b"mcp-stdio:malformed-frame",
            Self::InputFrameTooLarge => b"mcp-stdio:input-frame-too-large",
            Self::UnterminatedFrame => b"mcp-stdio:unterminated-frame",
            Self::InvalidRequestMetadata => b"mcp-stdio:invalid-request-metadata",
            Self::UnsupportedProtocolVersion => b"mcp-stdio:unsupported-protocol-version",
            Self::InitializationForbidden => b"mcp-stdio:initialization-forbidden",
            Self::DuplicateRequestId => b"mcp-stdio:duplicate-request-id",
            Self::PendingLimitReached => b"mcp-stdio:pending-limit-reached",
            Self::InputFailure => b"mcp-stdio:input-failure",
            Self::OutputFailure => b"mcp-stdio:output-failure",
            Self::OutputFrameTooLarge => b"mcp-stdio:output-frame-too-large",
            Self::ShutdownDeadline => b"mcp-stdio:shutdown-deadline",
            Self::ServiceFailure => b"mcp-stdio:service-failure",
        }
    }

    const fn cancels_service(self) -> bool {
        !matches!(self, Self::Eof)
    }
}

/// Observable counts produced only by the explicit legacy adapter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CompatibilitySnapshot {
    /// Frames whose BOM, CRLF, or missing final newline was normalized.
    pub translated_frames: usize,
    /// Requests whose legacy metadata keys were moved into current `_meta`.
    pub translated_metadata: usize,
    /// Legacy `initialize` requests translated to stateless discovery.
    pub translated_initializations: usize,
}

/// Bounded diagnostic emission counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DiagnosticSnapshot {
    /// Diagnostic lines actually written.
    pub emitted: usize,
    /// Diagnostic events discarded after the configured bound.
    pub dropped: usize,
}

/// A point-in-time view of transport state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportSnapshot {
    /// Terminal state, or `None` while input remains active.
    pub termination: Option<TerminationReason>,
    /// Pending ordinary requests.
    pub pending_requests: usize,
    /// Pending long-lived subscriptions.
    pub pending_subscriptions: usize,
    /// Largest combined pending-work count observed.
    pub max_observed_pending: usize,
    /// Explicit compatibility translations.
    pub compatibility: CompatibilitySnapshot,
    /// Bounded diagnostic counters.
    pub diagnostics: DiagnosticSnapshot,
}

/// Cloneable observation handle that cannot mutate transport state.
#[derive(Clone)]
pub struct StdioObserver {
    shared: Arc<SharedState>,
}

impl StdioObserver {
    /// Captures the current bounded transport state.
    pub async fn snapshot(&self) -> TransportSnapshot {
        let pending = self.shared.pending.lock().await;
        TransportSnapshot {
            termination: self.shared.termination(),
            pending_requests: pending.request_count,
            pending_subscriptions: pending.subscription_count,
            max_observed_pending: self.shared.max_observed_pending.load(Ordering::Acquire),
            compatibility: self.shared.compatibility.snapshot(),
            diagnostics: self.shared.diagnostics.snapshot(),
        }
    }
}
/// Cloneable admission signal for a bounded stdio drain.
///
/// Calling [`Self::begin_drain`] stops the transport from accepting another
/// frame. Requests admitted before the signal are allowed to finish until the
/// serving function's configured shutdown deadline.
#[derive(Clone, Debug)]
pub struct StdioDrainHandle {
    cancellation: CancellationToken,
}

impl StdioDrainHandle {
    /// Creates an independently owned drain signal.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancellation: CancellationToken::new(),
        }
    }

    /// Wraps an existing cancellation token for compatibility with existing
    /// process lifecycle wiring.
    #[must_use]
    pub fn from_cancellation_token(cancellation: CancellationToken) -> Self {
        Self { cancellation }
    }

    /// Stops admission. Already admitted work is drained by the serving task.
    pub fn begin_drain(&self) {
        self.cancellation.cancel();
    }

    /// Returns whether admission has been stopped.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.cancellation.is_cancelled()
    }

    /// Waits until admission is stopped.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    fn token(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

impl Default for StdioDrainHandle {
    fn default() -> Self {
        Self::new()
    }
}

/// Redacted transport failure used by the RMCP IO boundary.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StdioTransportError;

impl fmt::Debug for StdioTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StdioTransportError([redacted])")
    }
}

impl fmt::Display for StdioTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP stdio transport failed")
    }
}

impl std::error::Error for StdioTransportError {}

/// Redacted failure of the RMCP service task.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StdioRunError;

impl fmt::Debug for StdioRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StdioRunError([redacted])")
    }
}

impl fmt::Display for StdioRunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MCP stdio service failed")
    }
}

impl std::error::Error for StdioRunError {}

/// Final state returned after a bounded service shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioRunReport {
    /// The service's terminal category.
    pub termination: TerminationReason,
    /// Last transport state captured after shutdown.
    pub transport: TransportSnapshot,
}

#[derive(Clone, Copy, Debug, Default)]
struct TranslationDelta {
    metadata: bool,
    initialization: bool,
}

#[derive(Default)]
struct CompatibilityCounters {
    frames: AtomicUsize,
    metadata: AtomicUsize,
    initializations: AtomicUsize,
}

impl CompatibilityCounters {
    fn snapshot(&self) -> CompatibilitySnapshot {
        CompatibilitySnapshot {
            translated_frames: self.frames.load(Ordering::Acquire),
            translated_metadata: self.metadata.load(Ordering::Acquire),
            translated_initializations: self.initializations.load(Ordering::Acquire),
        }
    }
}

struct DiagnosticSink<W> {
    writer: Mutex<W>,
    max_events: usize,
    max_bytes: usize,
    write_deadline: Duration,
    attempted: AtomicUsize,
    emitted: AtomicUsize,
    dropped: AtomicUsize,
}

impl<W> DiagnosticSink<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    fn new(writer: W, max_events: usize, max_bytes: usize, write_deadline: Duration) -> Self {
        Self {
            writer: Mutex::new(writer),
            max_events,
            max_bytes,
            write_deadline,
            attempted: AtomicUsize::new(0),
            emitted: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    async fn emit(&self, message: &'static [u8]) {
        let index = self.attempted.fetch_add(1, Ordering::AcqRel);
        if index >= self.max_events {
            self.dropped.fetch_add(1, Ordering::AcqRel);
            return;
        }
        let content_limit = self.max_bytes.saturating_sub(1);
        let content = &message[..message.len().min(content_limit)];
        let wrote = tokio::time::timeout(self.write_deadline, async {
            let mut writer = self.writer.lock().await;
            writer.write_all(content).await.is_ok() && writer.write_all(b"\n").await.is_ok()
        })
        .await
        .unwrap_or(false);
        if wrote {
            self.emitted.fetch_add(1, Ordering::AcqRel);
        } else {
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn snapshot(&self) -> DiagnosticSnapshot {
        DiagnosticSnapshot {
            emitted: self.emitted.load(Ordering::Acquire),
            dropped: self.dropped.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingKind {
    Request,
    Subscription,
}

struct PendingWork {
    kind: PendingKind,
    deadline: Option<Instant>,
    external_id: RequestId,
    response_started: bool,
}

#[derive(Default)]
struct PendingState {
    entries: HashMap<RequestId, PendingWork>,
    active_external: HashMap<RequestId, RequestId>,
    next_internal_id: u64,
    request_count: usize,
    subscription_count: usize,
}

impl PendingState {
    fn reserve(
        &mut self,
        external_id: RequestId,
        kind: PendingKind,
        config: StdioConfig,
    ) -> Result<(usize, RequestId), TerminationReason> {
        if self.active_external.contains_key(&external_id) {
            return Err(TerminationReason::DuplicateRequestId);
        }
        match kind {
            PendingKind::Request if self.request_count >= config.max_pending_requests => {
                return Err(TerminationReason::PendingLimitReached);
            }
            PendingKind::Subscription
                if self.subscription_count >= config.max_pending_subscriptions =>
            {
                return Err(TerminationReason::PendingLimitReached);
            }
            PendingKind::Request | PendingKind::Subscription => {}
        }
        let Some(next_internal_id) = self.next_internal_id.checked_add(1) else {
            return Err(TerminationReason::PendingLimitReached);
        };
        self.next_internal_id = next_internal_id;
        let internal_id = RequestId::String(format!("omnius-stdio:{next_internal_id}").into());
        match kind {
            PendingKind::Request => self.request_count += 1,
            PendingKind::Subscription => self.subscription_count += 1,
        }
        let deadline = match kind {
            PendingKind::Request => Some(Instant::now() + config.request_deadline),
            PendingKind::Subscription => None,
        };
        self.entries.insert(
            internal_id.clone(),
            PendingWork {
                kind,
                deadline,
                external_id: external_id.clone(),
                response_started: false,
            },
        );
        self.active_external
            .insert(external_id, internal_id.clone());
        Ok((self.request_count + self.subscription_count, internal_id))
    }

    fn remove_internal(&mut self, internal_id: &RequestId) -> Option<PendingWork> {
        let work = self.entries.remove(internal_id)?;
        self.active_external.remove(&work.external_id);
        match work.kind {
            PendingKind::Request => self.request_count = self.request_count.saturating_sub(1),
            PendingKind::Subscription => {
                self.subscription_count = self.subscription_count.saturating_sub(1);
            }
        }
        Some(work)
    }

    fn cancel_external(&mut self, external_id: &RequestId) -> Option<RequestId> {
        let internal_id = self.active_external.get(external_id)?.clone();
        let response_started = self.entries.get(&internal_id)?.response_started;
        if !response_started {
            self.remove_internal(&internal_id)?;
        }
        Some(internal_id)
    }

    fn begin_response(&mut self, internal_id: &RequestId) -> Option<RequestId> {
        let work = self.entries.get_mut(internal_id)?;
        if work.response_started {
            return None;
        }
        work.response_started = true;
        work.deadline = None;
        Some(work.external_id.clone())
    }

    fn complete_response(&mut self, internal_id: &RequestId) {
        self.remove_internal(internal_id);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.active_external.clear();
        self.request_count = 0;
        self.subscription_count = 0;
    }

    fn next_deadline(&self) -> Option<(RequestId, Instant)> {
        self.entries
            .iter()
            .filter_map(|(id, work)| work.deadline.map(|deadline| (id.clone(), deadline)))
            .min_by_key(|(_, deadline)| *deadline)
    }
}

struct SharedState {
    termination: AtomicU8,
    pending: Mutex<PendingState>,
    max_observed_pending: AtomicUsize,
    compatibility: CompatibilityCounters,
    diagnostics: Arc<dyn DiagnosticEmitter>,
    cancellation: CancellationToken,
    terminated: Notify,
}

impl SharedState {
    fn termination(&self) -> Option<TerminationReason> {
        TerminationReason::from_code(self.termination.load(Ordering::Acquire))
    }

    fn mark_termination(&self, reason: TerminationReason) {
        let mut current = self.termination.load(Ordering::Acquire);
        loop {
            let may_replace_eof =
                current == TerminationReason::Eof.code() && reason != TerminationReason::Eof;
            if current != 0 && !may_replace_eof {
                return;
            }
            match self.termination.compare_exchange(
                current,
                reason.code(),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
        if reason.cancels_service() {
            self.cancellation.cancel();
        }
        self.terminated.notify_one();
    }

    fn replace_termination(&self, reason: TerminationReason) {
        self.termination.store(reason.code(), Ordering::Release);
        if reason.cancels_service() {
            self.cancellation.cancel();
        }
        self.terminated.notify_one();
    }

    async fn fail(&self, reason: TerminationReason) {
        self.diagnostics.emit(reason.diagnostic()).await;
        self.mark_termination(reason);
    }

    fn observe_pending(&self, pending: usize) {
        self.max_observed_pending
            .fetch_max(pending, Ordering::AcqRel);
    }
}

trait DiagnosticEmitter: Send + Sync {
    fn emit<'a>(&'a self, message: &'static [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
    fn snapshot(&self) -> DiagnosticSnapshot;
}

impl<W> DiagnosticEmitter for DiagnosticSink<W>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    fn emit<'a>(&'a self, message: &'static [u8]) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(DiagnosticSink::emit(self, message))
    }

    fn snapshot(&self) -> DiagnosticSnapshot {
        DiagnosticSink::snapshot(self)
    }
}

struct BoundedLineReader<R> {
    reader: BufReader<R>,
    bytes: Vec<u8>,
    max_bytes: usize,
}

struct InputFrame {
    bytes: Vec<u8>,
    newline_terminated: bool,
}

enum LineReadError {
    TooLarge,
    Io,
}

impl<R> BoundedLineReader<R>
where
    R: AsyncRead + Send + Unpin,
{
    fn new(reader: R, max_bytes: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            bytes: Vec::with_capacity(max_bytes.min(8192)),
            max_bytes,
        }
    }

    async fn next_frame(&mut self) -> Result<Option<InputFrame>, LineReadError> {
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| LineReadError::Io)?;
            if available.is_empty() {
                if self.bytes.is_empty() {
                    return Ok(None);
                }
                return Ok(Some(InputFrame {
                    bytes: std::mem::take(&mut self.bytes),
                    newline_terminated: false,
                }));
            }

            let remaining = self.max_bytes.saturating_sub(self.bytes.len());
            let newline = available.iter().position(|byte| *byte == b'\n');
            match newline {
                Some(index) if index <= remaining => {
                    self.bytes.extend_from_slice(&available[..index]);
                    self.reader.consume(index + 1);
                    return Ok(Some(InputFrame {
                        bytes: std::mem::take(&mut self.bytes),
                        newline_terminated: true,
                    }));
                }
                None if available.len() <= remaining => {
                    let length = available.len();
                    self.bytes.extend_from_slice(available);
                    self.reader.consume(length);
                }
                Some(_) | None => return Err(LineReadError::TooLarge),
            }
        }
    }
}

/// Strict RMCP server transport over separate protocol and diagnostic writers.
pub struct StdioTransport<R, W> {
    input: BoundedLineReader<R>,
    output: Arc<Mutex<Option<W>>>,
    config: StdioConfig,
    shared: Arc<SharedState>,
    first_frame: bool,
}

impl<R, W> StdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    /// Creates a transport and its read-only observer.
    ///
    /// `protocol_output` must be stdout (or its test double); `diagnostics` must
    /// be stderr (or its test double). The transport never crosses the streams.
    #[must_use]
    pub fn new<D>(
        input: R,
        protocol_output: W,
        diagnostics: D,
        config: StdioConfig,
        cancellation: CancellationToken,
    ) -> (Self, StdioObserver)
    where
        D: AsyncWrite + Send + Unpin + 'static,
    {
        Self::new_with_drain(
            input,
            protocol_output,
            diagnostics,
            config,
            &StdioDrainHandle::from_cancellation_token(cancellation),
        )
    }

    /// Creates a transport controlled by an explicitly owned drain handle.
    ///
    /// The caller should retain a clone of `drain` to stop admission. Protocol
    /// output and diagnostics remain different writer values and are never
    /// interchanged.
    #[must_use]
    pub fn new_with_drain<D>(
        input: R,
        protocol_output: W,
        diagnostics: D,
        config: StdioConfig,
        drain: &StdioDrainHandle,
    ) -> (Self, StdioObserver)
    where
        D: AsyncWrite + Send + Unpin + 'static,
    {
        let diagnostics: Arc<dyn DiagnosticEmitter> = Arc::new(DiagnosticSink::new(
            diagnostics,
            config.max_diagnostic_events,
            config.max_diagnostic_bytes,
            config.diagnostic_write_deadline,
        ));
        let shared = Arc::new(SharedState {
            termination: AtomicU8::new(0),
            pending: Mutex::new(PendingState::default()),
            max_observed_pending: AtomicUsize::new(0),
            compatibility: CompatibilityCounters::default(),
            diagnostics,
            cancellation: drain.token(),
            terminated: Notify::new(),
        });
        (
            Self {
                input: BoundedLineReader::new(input, config.max_frame_bytes),
                output: Arc::new(Mutex::new(Some(protocol_output))),
                config,
                shared: shared.clone(),
                first_frame: true,
            },
            StdioObserver { shared },
        )
    }

    async fn receive_next(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            if self.shared.cancellation.is_cancelled() {
                self.shared.mark_termination(TerminationReason::Cancelled);
                return None;
            }

            let next_deadline = self.shared.pending.lock().await.next_deadline();
            let input = if let Some((deadline_id, deadline)) = next_deadline {
                tokio::select! {
                    biased;
                    () = self.shared.cancellation.cancelled() => {
                        self.shared.mark_termination(TerminationReason::Cancelled);
                        return None;
                    }
                    () = tokio::time::sleep_until(deadline) => {
                        let removed = self
                            .shared
                            .pending
                            .lock()
                            .await
                            .remove_internal(&deadline_id)
                            .is_some();
                        if removed {
                            self.shared.diagnostics.emit(b"mcp-stdio:request-deadline").await;
                            return Some(deadline_notification(deadline_id));
                        }
                        continue;
                    }
                    frame = self.input.next_frame() => frame,
                }
            } else {
                tokio::select! {
                    biased;
                    () = self.shared.cancellation.cancelled() => {
                        self.shared.mark_termination(TerminationReason::Cancelled);
                        return None;
                    }
                    frame = self.input.next_frame() => frame,
                }
            };

            let frame = match input {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    self.shared.mark_termination(TerminationReason::Eof);
                    return None;
                }
                Err(LineReadError::TooLarge) => {
                    self.shared
                        .fail(TerminationReason::InputFrameTooLarge)
                        .await;
                    return None;
                }
                Err(LineReadError::Io) => {
                    self.shared.fail(TerminationReason::InputFailure).await;
                    return None;
                }
            };
            let mut message = self.decode_frame(frame).await?;
            let shared = Arc::clone(&self.shared);
            if !Self::admit_message(&shared, self.config, &mut message).await {
                return None;
            }
            return Some(message);
        }
    }

    async fn decode_frame(&mut self, mut frame: InputFrame) -> Option<ClientJsonRpcMessage> {
        let mut translated_framing = false;
        if !frame.newline_terminated {
            if self.config.legacy.is_none() {
                self.shared.fail(TerminationReason::UnterminatedFrame).await;
                return None;
            }
            translated_framing = true;
        }
        if frame.bytes.last() == Some(&b'\r') {
            if self.config.legacy.is_none() {
                self.shared.fail(TerminationReason::MalformedFrame).await;
                return None;
            }
            frame.bytes.pop();
            translated_framing = true;
        }
        if frame.bytes.starts_with(UTF8_BOM) {
            if self.config.legacy.is_none() || !self.first_frame {
                self.shared.fail(TerminationReason::MalformedFrame).await;
                return None;
            }
            frame.bytes.drain(..UTF8_BOM.len());
            translated_framing = true;
        }
        self.first_frame = false;
        if frame.bytes.is_empty() {
            self.shared.fail(TerminationReason::MalformedFrame).await;
            return None;
        }
        if translated_framing {
            self.shared
                .compatibility
                .frames
                .fetch_add(1, Ordering::AcqRel);
        }

        let Ok(mut value) = serde_json::from_slice::<Value>(&frame.bytes) else {
            self.shared.fail(TerminationReason::MalformedFrame).await;
            return None;
        };
        let initialization = value.get("method").and_then(Value::as_str) == Some(INITIALIZE);
        if initialization && self.config.legacy.is_none() {
            self.shared
                .fail(TerminationReason::InitializationForbidden)
                .await;
            return None;
        }
        if self.config.legacy.is_some() {
            let Ok(delta) = LegacyCompatibilityAdapter::translate(&mut value) else {
                self.shared
                    .fail(TerminationReason::InvalidRequestMetadata)
                    .await;
                return None;
            };
            if delta.metadata {
                self.shared
                    .compatibility
                    .metadata
                    .fetch_add(1, Ordering::AcqRel);
            }
            if delta.initialization {
                self.shared
                    .compatibility
                    .initializations
                    .fetch_add(1, Ordering::AcqRel);
            }
        }

        let Ok(message) = serde_json::from_value::<ClientJsonRpcMessage>(value) else {
            self.shared.fail(TerminationReason::MalformedFrame).await;
            return None;
        };
        Some(message)
    }

    async fn admit_message(
        shared: &SharedState,
        config: StdioConfig,
        message: &mut ClientJsonRpcMessage,
    ) -> bool {
        match message {
            JsonRpcMessage::Request(request) => {
                let meta = request.request.get_meta();
                let Some(protocol_version) = meta.protocol_version() else {
                    shared.fail(TerminationReason::InvalidRequestMetadata).await;
                    return false;
                };
                if protocol_version != ProtocolVersion::V_2026_07_28 {
                    shared
                        .fail(TerminationReason::UnsupportedProtocolVersion)
                        .await;
                    return false;
                }
                if meta.client_capabilities().is_none() || meta.client_info().is_none() {
                    shared.fail(TerminationReason::InvalidRequestMetadata).await;
                    return false;
                }
                let kind = if request.request.method() == SUBSCRIPTIONS_LISTEN {
                    PendingKind::Subscription
                } else {
                    PendingKind::Request
                };
                let reservation =
                    shared
                        .pending
                        .lock()
                        .await
                        .reserve(request.id.clone(), kind, config);
                match reservation {
                    Ok((pending, internal_id)) => {
                        request.id = internal_id;
                        shared.observe_pending(pending);
                        true
                    }
                    Err(reason) => {
                        shared.fail(reason).await;
                        false
                    }
                }
            }
            JsonRpcMessage::Notification(notification) => {
                if let ClientNotification::CancelledNotification(cancelled) =
                    &mut notification.notification
                {
                    let internal_id = match cancelled.params.request_id.as_ref() {
                        Some(external_id) => {
                            shared.pending.lock().await.cancel_external(external_id)
                        }
                        None => None,
                    };
                    cancelled.params.request_id = internal_id;
                }
                true
            }
            JsonRpcMessage::Response(_) | JsonRpcMessage::Error(_) => true,
        }
    }
}

fn deadline_notification(request_id: RequestId) -> ClientJsonRpcMessage {
    ClientJsonRpcMessage::notification(ClientNotification::CancelledNotification(
        CancelledNotification::new(CancelledNotificationParam::new(
            Some(request_id),
            Some("deadline exceeded".to_owned()),
        )),
    ))
}

impl<R, W> Transport<RoleServer> for StdioTransport<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Error = StdioTransportError;

    fn send(
        &mut self,
        mut item: TxJsonRpcMessage<RoleServer>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        let output = self.output.clone();
        let shared = self.shared.clone();
        let max_frame_bytes = self.config.max_frame_bytes;
        let output_write_deadline = self.config.output_write_deadline;
        async move {
            if shared.cancellation.is_cancelled()
                || shared
                    .termination()
                    .is_some_and(|reason| reason != TerminationReason::Eof)
            {
                return Err(StdioTransportError);
            }
            let internal_id = match &item {
                ServerJsonRpcMessage::Response(response) => Some(response.id.clone()),
                ServerJsonRpcMessage::Error(error) => error.id.clone(),
                ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_) => None,
            };
            if let Some(internal_id) = internal_id.as_ref() {
                let external_id = shared.pending.lock().await.begin_response(internal_id);
                let Some(external_id) = external_id else {
                    return Ok(());
                };
                match &mut item {
                    ServerJsonRpcMessage::Response(response) => response.id = external_id,
                    ServerJsonRpcMessage::Error(error) => error.id = Some(external_id),
                    ServerJsonRpcMessage::Request(_) | ServerJsonRpcMessage::Notification(_) => {}
                }
            }
            let Ok(encoded) = serde_json::to_vec(&item) else {
                shared.fail(TerminationReason::OutputFailure).await;
                return Err(StdioTransportError);
            };
            if encoded.len() > max_frame_bytes {
                shared.fail(TerminationReason::OutputFrameTooLarge).await;
                return Err(StdioTransportError);
            }
            let wrote = tokio::time::timeout(output_write_deadline, async {
                let mut output = output.lock().await;
                let Some(writer) = output.as_mut() else {
                    return false;
                };
                writer.write_all(&encoded).await.is_ok()
                    && writer.write_all(b"\n").await.is_ok()
                    && writer.flush().await.is_ok()
            })
            .await
            .unwrap_or(false);
            if !wrote {
                shared.fail(TerminationReason::OutputFailure).await;
                return Err(StdioTransportError);
            }
            if let Some(internal_id) = internal_id.as_ref() {
                shared.pending.lock().await.complete_response(internal_id);
            }
            Ok(())
        }
    }

    async fn receive(&mut self) -> Option<RxJsonRpcMessage<RoleServer>> {
        self.receive_next().await
    }

    fn close(&mut self) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let output = self.output.clone();
        let shared = self.shared.clone();
        let output_write_deadline = self.config.output_write_deadline;
        async move {
            shared.pending.lock().await.clear();
            let closed = tokio::time::timeout(output_write_deadline, async {
                let mut output = output.lock().await;
                match output.take() {
                    Some(mut writer) => writer.shutdown().await.is_ok(),
                    None => true,
                }
            })
            .await
            .unwrap_or(false);
            if !closed {
                shared.fail(TerminationReason::OutputFailure).await;
                return Err(StdioTransportError);
            }
            Ok(())
        }
    }
}

/// Serves a preconfigured canonical MCP adapter over supplied async IO.
///
/// This compatibility entrypoint retains the concrete [`ServerAdapter`] API.
/// New composition code can use [`serve_stdio_handler_with_io`] with any fully
/// assembled [`ServerHandler`].
///
/// # Errors
///
/// Returns a redacted error if the isolated executor cannot start or the RMCP task fails to join.
pub async fn serve_stdio_with_io<R, W, D>(
    server: ServerAdapter,
    input: R,
    protocol_output: W,
    diagnostics: D,
    config: StdioConfig,
    cancellation: CancellationToken,
) -> Result<StdioRunReport, StdioRunError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    D: AsyncWrite + Send + Unpin + 'static,
{
    serve_stdio_service_with_io(
        server,
        input,
        protocol_output,
        diagnostics,
        config,
        StdioDrainHandle::from_cancellation_token(cancellation),
    )
    .await
}

/// Serves a fully assembled RMCP server handler over separate protocol and
/// diagnostic writers.
///
/// The caller retains a clone of `drain` and calls
/// [`StdioDrainHandle::begin_drain`] to stop admission. EOF and an explicit
/// drain both allow admitted work to finish until `config.shutdown_deadline`.
/// The handler must already own every projection and resolver needed by its
/// profile; the transport adds neither identity nor dispatch behavior.
///
/// # Errors
///
/// Returns a redacted error if the isolated executor cannot start or the RMCP task fails to join.
pub async fn serve_stdio_handler_with_io<S, R, W, D>(
    handler: S,
    input: R,
    protocol_output: W,
    diagnostics: D,
    config: StdioConfig,
    drain: StdioDrainHandle,
) -> Result<StdioRunReport, StdioRunError>
where
    S: ServerHandler + 'static,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    D: AsyncWrite + Send + Unpin + 'static,
{
    serve_stdio_service_with_io(handler, input, protocol_output, diagnostics, config, drain).await
}
async fn serve_stdio_service_with_io<S, R, W, D>(
    service: S,
    input: R,
    protocol_output: W,
    diagnostics: D,
    config: StdioConfig,
    drain: StdioDrainHandle,
) -> Result<StdioRunReport, StdioRunError>
where
    S: Service<RoleServer> + 'static,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    D: AsyncWrite + Send + Unpin + 'static,
{
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| StdioRunError)?;
        let suppressed = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::new());
        let _dispatch_guard = tracing::dispatcher::set_default(&suppressed);
        runtime.block_on(run_stdio_with_io(
            service,
            input,
            protocol_output,
            diagnostics,
            config,
            drain,
        ))
    })
    .await
    .map_err(|_| StdioRunError)?
}

async fn run_stdio_with_io<S, R, W, D>(
    handler: S,
    input: R,
    protocol_output: W,
    diagnostics: D,
    config: StdioConfig,
    drain: StdioDrainHandle,
) -> Result<StdioRunReport, StdioRunError>
where
    S: Service<RoleServer> + 'static,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    D: AsyncWrite + Send + Unpin + 'static,
{
    let (transport, observer) =
        StdioTransport::new_with_drain(input, protocol_output, diagnostics, config, &drain);
    let running =
        rmcp::service::serve_directly_with_ct(handler, transport, None, CancellationToken::new());
    let service_cancellation = running.cancellation_token();
    let waiting = running.waiting();
    tokio::pin!(waiting);
    let joined = tokio::select! {
        result = &mut waiting => result,
        () = observer.shared.terminated.notified() => {
            let Ok(result) =
                tokio::time::timeout(config.shutdown_deadline, &mut waiting).await
            else {
                observer
                    .shared
                    .diagnostics
                    .emit(TerminationReason::ShutdownDeadline.diagnostic())
                    .await;
                observer
                    .shared
                    .replace_termination(TerminationReason::ShutdownDeadline);
                service_cancellation.cancel();
                let transport = observer.snapshot().await;
                return Ok(StdioRunReport {
                    termination: TerminationReason::ShutdownDeadline,
                    transport,
                });
            };
            result
        }
    };
    let Ok(quit) = joined else {
        observer
            .shared
            .fail(TerminationReason::ServiceFailure)
            .await;
        return Err(StdioRunError);
    };
    let fallback = match quit {
        QuitReason::Cancelled => TerminationReason::Cancelled,
        QuitReason::Closed => TerminationReason::Eof,
        _ => TerminationReason::ServiceFailure,
    };
    if observer.shared.termination().is_none() {
        observer.shared.mark_termination(fallback);
    }
    let transport = observer.snapshot().await;
    let termination = transport.termination.unwrap_or(fallback);
    if termination == TerminationReason::ServiceFailure {
        return Err(StdioRunError);
    }
    Ok(StdioRunReport {
        termination,
        transport,
    })
}

/// Serves a preconfigured canonical MCP adapter on process stdin/stdout/stderr
/// until EOF, cancellation, or Ctrl-C.
///
/// # Errors
///
/// Returns a redacted error only if the RMCP task fails to join.
pub async fn serve_stdio(
    server: ServerAdapter,
    config: StdioConfig,
    cancellation: CancellationToken,
) -> Result<StdioRunReport, StdioRunError> {
    let drain = StdioDrainHandle::from_cancellation_token(cancellation);
    let signal = drain.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.begin_drain();
        }
    });
    let result = serve_stdio_service_with_io(
        server,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
        config,
        drain,
    )
    .await;
    signal_task.abort();
    drop(signal_task.await);
    result
}

/// Serves a fully assembled RMCP handler on process stdin/stdout/stderr.
///
/// Ctrl-C begins the same bounded drain as an explicit call to
/// [`StdioDrainHandle::begin_drain`]. Stdout is reserved for protocol frames;
/// all fixed transport diagnostics are written to stderr.
///
/// # Errors
///
/// Returns a redacted error only if the RMCP task fails to join.
pub async fn serve_stdio_handler<S>(
    handler: S,
    config: StdioConfig,
    drain: StdioDrainHandle,
) -> Result<StdioRunReport, StdioRunError>
where
    S: ServerHandler + 'static,
{
    let signal = drain.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.begin_drain();
        }
    });
    let result = serve_stdio_handler_with_io(
        handler,
        tokio::io::stdin(),
        tokio::io::stdout(),
        tokio::io::stderr(),
        config,
        drain,
    )
    .await;
    signal_task.abort();
    drop(signal_task.await);
    result
}
