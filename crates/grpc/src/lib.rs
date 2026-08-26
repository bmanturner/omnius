//! Bounded `tonic` transport composition for canonical application services.
//!
//! The public route set contains the checked-in [`pb::foundation_server::Foundation`]
//! contract and the standard gRPC health service. Reflection exists only in the
//! separately returned protected route set, where the same authentication and
//! application authorization boundaries are enforced. Application logic is injected;
//! this crate owns only transport concerns.

mod generated;

/// Checked-in protobuf messages, client, and server for the minimal foundation contract.
pub mod pb {
    pub use crate::generated::*;
}

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    str::FromStr as _,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, HeaderValue, Request as HttpRequest, Response as HttpResponse};
use http_body::{Body as HttpBody, Frame, SizeHint};
use prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    MethodDescriptorProto, ServiceDescriptorProto,
    field_descriptor_proto::{Label, Type},
};
use rsk_auth_core::Principal;
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationService, Decision, Resource,
};
use rsk_core::{RequestId, ServiceError};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;
use tonic::{
    Code, Request, Response, Status,
    codec::CompressionEncoding,
    metadata::{Ascii, MetadataMap, MetadataValue},
    service::{Interceptor, Routes, interceptor::InterceptedService},
};
use tonic_health::server::HealthReporter;
use tonic_types::{ErrorDetails, StatusExt as _};
use tower::Service;
use tracing::{Instrument as _, Span};

use pb::{
    ExecuteRequest, ExecuteResponse, StreamRequest, StreamResponse,
    foundation_server::{Foundation, FoundationServer},
};

/// Metadata name used for the canonical request identifier.
pub const REQUEST_ID_METADATA: &str = "x-request-id";
/// Checked-in foundation service name.
pub const FOUNDATION_SERVICE_NAME: &str = pb::foundation_server::SERVICE_NAME;

const GRPC_TIMEOUT_METADATA: &str = "grpc-timeout";
const MAX_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
const MESSAGE_ENVELOPE_BYTES: usize = 16;
const MAX_STREAM_CAPACITY: usize = 1_024;
const MAX_CONCURRENT_STREAMS: usize = 4_096;
const MAX_DEADLINE: Duration = Duration::from_mins(5);
const MAX_SAFE_MESSAGE_BYTES: usize = 256;
type BoxServiceFuture<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send + 'static>>;
const ERROR_DOMAIN: &str = "rust-service-kit.grpc";

/// Explicit limits applied to every composed foundation service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrpcConfig {
    /// Required client deadline upper bound.
    pub max_deadline: Duration,
    /// Maximum protobuf response message size before transport compression.
    pub max_encoded_message_bytes: usize,
    /// Maximum decoded application payload accepted after protobuf decoding.
    pub max_decoded_payload_bytes: usize,
    /// Maximum request message size both before and after decompression.
    pub max_decompressed_message_bytes: usize,
    /// Number of response items a producer may buffer per stream.
    pub stream_capacity: usize,
    /// Maximum concurrent application response streams.
    pub max_concurrent_streams: usize,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            max_deadline: Duration::from_secs(30),
            max_encoded_message_bytes: 4 * 1024 * 1024,
            max_decoded_payload_bytes: 2 * 1024 * 1024,
            max_decompressed_message_bytes: 4 * 1024 * 1024,
            stream_capacity: 32,
            max_concurrent_streams: 128,
        }
    }
}

impl GrpcConfig {
    /// Validates hard safety ceilings and the relationship between decoded payload and envelope.
    ///
    /// # Errors
    ///
    /// Returns [`GrpcConfigError`] for zero, excessive, or internally inconsistent bounds.
    pub fn validate(self) -> Result<ValidatedGrpcConfig, GrpcConfigError> {
        if self.max_deadline.is_zero() || self.max_deadline > MAX_DEADLINE {
            return Err(GrpcConfigError::Deadline);
        }
        if !(MESSAGE_ENVELOPE_BYTES..=MAX_MESSAGE_BYTES).contains(&self.max_encoded_message_bytes)
            || !(MESSAGE_ENVELOPE_BYTES..=MAX_MESSAGE_BYTES)
                .contains(&self.max_decompressed_message_bytes)
            || self.max_decoded_payload_bytes == 0
            || self.max_decoded_payload_bytes > MAX_MESSAGE_BYTES
        {
            return Err(GrpcConfigError::Message);
        }
        if self
            .max_decoded_payload_bytes
            .saturating_add(MESSAGE_ENVELOPE_BYTES)
            > self.max_decompressed_message_bytes
        {
            return Err(GrpcConfigError::DecodedEnvelope);
        }
        if !(1..=MAX_STREAM_CAPACITY).contains(&self.stream_capacity)
            || !(1..=MAX_CONCURRENT_STREAMS).contains(&self.max_concurrent_streams)
        {
            return Err(GrpcConfigError::Streaming);
        }
        Ok(ValidatedGrpcConfig(self))
    }
}

/// A validated immutable gRPC limit set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedGrpcConfig(GrpcConfig);

impl ValidatedGrpcConfig {
    /// Returns the validated values.
    #[must_use]
    pub const fn get(self) -> GrpcConfig {
        self.0
    }
}

/// Invalid gRPC safety configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GrpcConfigError {
    /// Deadline was zero or exceeded five minutes.
    #[error("gRPC max deadline must be greater than zero and at most five minutes")]
    Deadline,
    /// A message bound was zero, below envelope overhead, or exceeded 64 MiB.
    #[error("gRPC message limit is outside the supported bounds")]
    Message,
    /// The decompression bound cannot contain the decoded payload and protobuf envelope.
    #[error("gRPC decompression limit is smaller than the decoded payload envelope")]
    DecodedEnvelope,
    /// A stream capacity or concurrency bound was zero or excessive.
    #[error("gRPC streaming limit is outside the supported bounds")]
    Streaming,
}

/// Authenticates transport metadata into the canonical [`Principal`].
pub trait Authenticator: Send + Sync + 'static {
    /// Authentication-specific failure. The transport never formats or exposes it.
    type Error;

    /// Authenticates request metadata without retaining credential values.
    ///
    /// # Errors
    ///
    /// Returns an implementation-specific error for missing or invalid credentials.
    fn authenticate(&self, metadata: &MetadataMap) -> Result<Principal, Self::Error>;
}

/// Canonical application authorization boundary used by the transport adapter.
pub trait ApplicationAuthorizer: Send + Sync + 'static {
    /// Evaluates canonical principal, action, resource, and authoritative context facts.
    fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        context: &AuthorizationContext,
    ) -> Decision;
}

impl<P> ApplicationAuthorizer for AuthorizationService<P>
where
    P: AuthorizationProvider + Send + Sync + 'static,
{
    fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        context: &AuthorizationContext,
    ) -> Decision {
        AuthorizationService::authorize(self, principal, action, resource, context)
    }
}

/// Canonical authorization facts assigned to one RPC method.
#[derive(Clone, Debug)]
pub struct MethodPolicy {
    action: Action,
    resource: Resource,
    context: AuthorizationContext,
}

impl MethodPolicy {
    /// Creates an RPC policy from canonical authorization types.
    #[must_use]
    pub const fn new(action: Action, resource: Resource, context: AuthorizationContext) -> Self {
        Self {
            action,
            resource,
            context,
        }
    }
}

/// Authorization policies for unary execution, streaming, and protected reflection.
#[derive(Clone, Debug)]
pub struct ServerPolicies {
    execute: MethodPolicy,
    stream: MethodPolicy,
    reflection: MethodPolicy,
}

impl ServerPolicies {
    /// Creates the complete fail-closed policy set.
    #[must_use]
    pub const fn new(
        execute: MethodPolicy,
        stream: MethodPolicy,
        reflection: MethodPolicy,
    ) -> Self {
        Self {
            execute,
            stream,
            reflection,
        }
    }
}

/// Canonical context established before a request reaches an application service.
#[derive(Clone, Debug)]
pub struct GrpcRequestContext {
    request_id: RequestId,
    principal: Option<Arc<Principal>>,
    expires_at: tokio::time::Instant,
    span: Span,
}

impl GrpcRequestContext {
    /// Returns the canonical request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the canonical authenticated principal, when this is not an operational health RPC.
    #[must_use]
    pub fn principal(&self) -> Option<&Principal> {
        self.principal.as_deref()
    }

    /// Returns the enforced absolute deadline.
    #[must_use]
    pub const fn expires_at(&self) -> tokio::time::Instant {
        self.expires_at
    }
}

/// Request-ID, tracing, authentication, and deadline interceptor for application RPCs.
pub struct CanonicalInterceptor<A> {
    config: ValidatedGrpcConfig,
    authenticator: Arc<A>,
    service: &'static str,
}

impl<A> CanonicalInterceptor<A> {
    /// Creates an authenticated interceptor for one named service.
    #[must_use]
    pub const fn new(
        config: ValidatedGrpcConfig,
        authenticator: Arc<A>,
        service: &'static str,
    ) -> Self {
        Self {
            config,
            authenticator,
            service,
        }
    }
}

impl<A> Clone for CanonicalInterceptor<A> {
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            authenticator: Arc::clone(&self.authenticator),
            service: self.service,
        }
    }
}

impl<A> Interceptor for CanonicalInterceptor<A>
where
    A: Authenticator,
{
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let request_id = request_id(request.metadata())?;
        let deadline = required_deadline(request.metadata(), self.config, request_id)?;
        let principal = self
            .authenticator
            .authenticate(request.metadata())
            .map(Arc::new)
            .map_err(|_| {
                boundary_status(
                    Code::Unauthenticated,
                    "authentication required",
                    "UNAUTHENTICATED",
                    request_id,
                )
            })?;
        insert_request_id(request.metadata_mut(), request_id);
        let span = request_span(self.service, request_id);
        request.extensions_mut().insert(GrpcRequestContext {
            request_id,
            principal: Some(principal),
            expires_at: tokio::time::Instant::now() + deadline,
            span,
        });
        Ok(request)
    }
}

#[derive(Clone)]
struct OperationalInterceptor {
    config: ValidatedGrpcConfig,
    service: &'static str,
}

impl Interceptor for OperationalInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let request_id = request_id(request.metadata())?;
        let deadline = required_deadline(request.metadata(), self.config, request_id)?;
        insert_request_id(request.metadata_mut(), request_id);
        let span = request_span(self.service, request_id);
        request.extensions_mut().insert(GrpcRequestContext {
            request_id,
            principal: None,
            expires_at: tokio::time::Instant::now() + deadline,
            span,
        });
        Ok(request)
    }
}

struct ReflectionInterceptor<A, Z> {
    boundary: CanonicalInterceptor<A>,
    authorizer: Arc<Z>,
    policy: MethodPolicy,
}

impl<A, Z> Clone for ReflectionInterceptor<A, Z> {
    fn clone(&self) -> Self {
        Self {
            boundary: self.boundary.clone(),
            authorizer: Arc::clone(&self.authorizer),
            policy: self.policy.clone(),
        }
    }
}

impl<A, Z> Interceptor for ReflectionInterceptor<A, Z>
where
    A: Authenticator,
    Z: ApplicationAuthorizer,
{
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        let request = self.boundary.call(request)?;
        let context = request
            .extensions()
            .get::<GrpcRequestContext>()
            .ok_or_else(|| Status::internal("request context unavailable"))?;
        let principal = context
            .principal()
            .ok_or_else(|| Status::internal("request context unavailable"))?;
        if self.authorizer.authorize(
            principal,
            &self.policy.action,
            &self.policy.resource,
            &self.policy.context,
        ) != Decision::Allow
        {
            return Err(boundary_status(
                Code::PermissionDenied,
                "permission denied",
                "PERMISSION_DENIED",
                context.request_id,
            ));
        }
        Ok(request)
    }
}

#[derive(Clone)]
struct RejectHealthWatch<S> {
    inner: S,
}

impl<S> RejectHealthWatch<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> tonic::server::NamedService for RejectHealthWatch<S>
where
    S: tonic::server::NamedService,
{
    const NAME: &'static str = S::NAME;
}

impl<S, B> Service<HttpRequest<B>> for RejectHealthWatch<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse<tonic::body::Body>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = HttpResponse<tonic::body::Body>;
    type Error = S::Error;
    type Future = BoxServiceFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        if request.uri().path() == "/grpc.health.v1.Health/Watch" {
            let request_id = request
                .extensions()
                .get::<GrpcRequestContext>()
                .map_or_else(RequestId::new, GrpcRequestContext::request_id);
            let status = boundary_status(
                Code::Unimplemented,
                "streaming health watch is not supported",
                "HEALTH_WATCH_UNSUPPORTED",
                request_id,
            );
            return Box::pin(async move { Ok(status.into_http()) });
        }
        let future = self.inner.call(request);
        Box::pin(future)
    }
}

#[derive(Clone)]
struct DeadlineBodyService<S> {
    inner: S,
}

impl<S> DeadlineBodyService<S> {
    const fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S> tonic::server::NamedService for DeadlineBodyService<S>
where
    S: tonic::server::NamedService,
{
    const NAME: &'static str = S::NAME;
}

impl<S, B, R> Service<HttpRequest<B>> for DeadlineBodyService<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse<R>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    R: HttpBody<Data = Bytes> + Send + 'static,
    R::Error: Send + 'static,
{
    type Response = HttpResponse<DeadlineBody<R>>;
    type Error = S::Error;
    type Future = BoxServiceFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        let context = request.extensions().get::<GrpcRequestContext>().cloned();
        let future = self.inner.call(request);
        Box::pin(async move {
            let response = future.await?;
            Ok(response.map(|body| DeadlineBody::new(body, context)))
        })
    }
}

struct DeadlineBody<B> {
    inner: Option<Pin<Box<B>>>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    request_id: Option<RequestId>,
    terminated: bool,
}

impl<B> DeadlineBody<B> {
    fn new(inner: B, context: Option<GrpcRequestContext>) -> Self {
        let (deadline, request_id) = context.map_or((None, None), |context| {
            (
                Some(Box::pin(tokio::time::sleep_until(context.expires_at))),
                Some(context.request_id),
            )
        });
        Self {
            inner: Some(Box::pin(inner)),
            deadline,
            request_id,
            terminated: false,
        }
    }
}

impl<B> HttpBody for DeadlineBody<B>
where
    B: HttpBody<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        if self
            .deadline
            .as_mut()
            .is_some_and(|deadline| deadline.as_mut().poll(context).is_ready())
        {
            self.inner = None;
            self.terminated = true;
            let request_id = self.request_id.unwrap_or_default();
            let status = deadline_status(request_id);
            let mut trailers = HeaderMap::with_capacity(4);
            if status.add_header(&mut trailers).is_err() {
                trailers.insert(Status::GRPC_STATUS, HeaderValue::from_static("4"));
            }
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        let Some(inner) = self.inner.as_mut() else {
            self.terminated = true;
            return Poll::Ready(None);
        };
        inner.as_mut().poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.terminated || self.inner.as_ref().is_none_or(HttpBody::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Opaque application call passed across the transport boundary.
#[derive(Clone, Debug)]
pub struct ApplicationCall {
    request_id: RequestId,
    principal: Arc<Principal>,
    payload: Bytes,
}

impl ApplicationCall {
    /// Returns the canonical request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the canonical authenticated principal.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the decoded opaque application payload.
    #[must_use]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Consumes the call and returns its payload without copying.
    #[must_use]
    pub fn into_payload(self) -> Bytes {
        self.payload
    }
}

/// Opaque application result encoded by the transport response message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationReply {
    payload: Bytes,
}

impl ApplicationReply {
    /// Creates an application reply without copying its payload.
    #[must_use]
    pub const fn new(payload: Bytes) -> Self {
        Self { payload }
    }

    /// Returns the reply payload.
    #[must_use]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// Injected application behavior. Implementations contain domain logic, not transport handlers.
#[tonic::async_trait]
pub trait ApplicationService: Send + Sync + 'static {
    /// Executes one unary application call.
    async fn execute(&self, call: ApplicationCall) -> Result<ApplicationReply, ServiceError>;

    /// Produces a stream through a bounded, cancellation-aware sender.
    async fn stream(&self, call: ApplicationCall, sender: StreamSender)
    -> Result<(), ServiceError>;
}

/// Bounded response-stream producer handle supplied to the application service.
#[derive(Clone, Debug)]
pub struct StreamSender {
    sender: mpsc::Sender<Result<StreamResponse, Status>>,
    cancellation: CancellationToken,
    max_payload_bytes: usize,
}

impl StreamSender {
    /// Waits for bounded channel capacity and sends one response payload.
    ///
    /// # Errors
    ///
    /// Returns [`StreamSendError`] when the payload is excessive or the consumer closed.
    pub async fn send(&self, payload: Bytes) -> Result<(), StreamSendError> {
        if payload.len().saturating_add(MESSAGE_ENVELOPE_BYTES) > self.max_payload_bytes {
            return Err(StreamSendError::PayloadTooLarge);
        }
        self.sender
            .send(Ok(StreamResponse { payload }))
            .await
            .map_err(|_| StreamSendError::Closed)
    }

    /// Attempts to send immediately without waiting for channel capacity.
    ///
    /// # Errors
    ///
    /// Returns [`StreamSendError::Full`] when backpressure is active.
    pub fn try_send(&self, payload: Bytes) -> Result<(), StreamSendError> {
        if payload.len().saturating_add(MESSAGE_ENVELOPE_BYTES) > self.max_payload_bytes {
            return Err(StreamSendError::PayloadTooLarge);
        }
        self.sender
            .try_send(Ok(StreamResponse { payload }))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => StreamSendError::Full,
                mpsc::error::TrySendError::Closed(_) => StreamSendError::Closed,
            })
    }

    /// Waits until the client drops the stream or the request deadline expires.
    pub async fn cancelled(&self) {
        self.cancellation.cancelled().await;
    }

    /// Reports whether cancellation was already requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancellation.is_cancelled()
    }
}

/// Failure to enqueue a bounded streaming response.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StreamSendError {
    /// The client closed or cancelled the stream.
    #[error("gRPC response stream is closed")]
    Closed,
    /// The bounded response channel is at capacity.
    #[error("gRPC response stream is applying backpressure")]
    Full,
    /// The encoded response would exceed the configured maximum.
    #[error("gRPC response payload exceeds the message limit")]
    PayloadTooLarge,
}

/// Cancellation-aware stream returned by the foundation transport.
pub struct ApplicationResponseStream {
    receiver: mpsc::Receiver<Result<StreamResponse, Status>>,
    cancellation: CancellationToken,
    deadline: Pin<Box<tokio::time::Sleep>>,
    request_id: RequestId,
    deadline_emitted: bool,
    terminated: bool,
    _permit: OwnedSemaphorePermit,
}

impl Stream for ApplicationResponseStream {
    type Item = Result<StreamResponse, Status>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminated {
            return Poll::Ready(None);
        }
        if self.deadline_emitted {
            self.terminated = true;
            return Poll::Ready(None);
        }
        if self.deadline.as_mut().poll(context).is_ready() {
            self.cancellation.cancel();
            self.receiver.close();
            self.deadline_emitted = true;
            return Poll::Ready(Some(Err(deadline_status(self.request_id))));
        }
        match self.receiver.poll_recv(context) {
            Poll::Ready(None) => {
                self.terminated = true;
                Poll::Ready(None)
            }
            result => result,
        }
    }
}

impl Drop for ApplicationResponseStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

struct FoundationAdapter<S, Z> {
    application: Arc<S>,
    authorizer: Arc<Z>,
    policies: ServerPolicies,
    config: ValidatedGrpcConfig,
    stream_slots: Arc<Semaphore>,
}

impl<S, Z> Clone for FoundationAdapter<S, Z> {
    fn clone(&self) -> Self {
        Self {
            application: Arc::clone(&self.application),
            authorizer: Arc::clone(&self.authorizer),
            policies: self.policies.clone(),
            config: self.config,
            stream_slots: Arc::clone(&self.stream_slots),
        }
    }
}

#[tonic::async_trait]
impl<S, Z> Foundation for FoundationAdapter<S, Z>
where
    S: ApplicationService,
    Z: ApplicationAuthorizer,
{
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let (context, call) = application_call(request, self.config)?;
        authorize(
            self.authorizer.as_ref(),
            call.principal(),
            &self.policies.execute,
            call.request_id(),
        )?;
        let request_id = call.request_id();
        let span = tracing::info_span!(
            target: "rsk_grpc",
            parent: &context.span,
            "grpc.method",
            rpc.method = "Execute"
        );
        let result = tokio::time::timeout_at(
            context.expires_at,
            self.application.execute(call).instrument(span),
        )
        .await
        .map_err(|_| deadline_status(request_id))?
        .map_err(|error| service_error_status(&error, request_id))?;
        if result.payload.len().saturating_add(MESSAGE_ENVELOPE_BYTES)
            > self.config.0.max_encoded_message_bytes
        {
            return Err(boundary_status(
                Code::ResourceExhausted,
                "response message exceeds configured limit",
                "MESSAGE_TOO_LARGE",
                request_id,
            ));
        }
        let mut response = Response::new(ExecuteResponse {
            payload: result.payload,
        });
        set_response_request_id(&mut response, request_id);
        Ok(response)
    }

    type StreamStream = ApplicationResponseStream;

    async fn stream(
        &self,
        request: Request<StreamRequest>,
    ) -> Result<Response<Self::StreamStream>, Status> {
        let (context, call) = application_call(request, self.config)?;
        authorize(
            self.authorizer.as_ref(),
            call.principal(),
            &self.policies.stream,
            call.request_id(),
        )?;
        let request_id = call.request_id();
        let permit = Arc::clone(&self.stream_slots)
            .try_acquire_owned()
            .map_err(|_| {
                boundary_status(
                    Code::ResourceExhausted,
                    "stream capacity exhausted",
                    "STREAM_CAPACITY_EXHAUSTED",
                    request_id,
                )
            })?;
        let (sender, receiver) = mpsc::channel(self.config.0.stream_capacity);
        let cancellation = CancellationToken::new();
        let application_sender = StreamSender {
            sender: sender.clone(),
            cancellation: cancellation.clone(),
            max_payload_bytes: self.config.0.max_encoded_message_bytes,
        };
        let application = Arc::clone(&self.application);
        let task_cancellation = cancellation.clone();
        let span = tracing::info_span!(
            target: "rsk_grpc",
            parent: &context.span,
            "grpc.method",
            rpc.method = "Stream"
        );
        let expires_at = context.expires_at;
        tokio::spawn(
            async move {
                let mut application = Box::pin(application.stream(call, application_sender));
                tokio::select! {
                    () = task_cancellation.cancelled() => {
                        // Give cooperative application cleanup one bounded poll window after
                        // exposing cancellation, then force-drop a producer that ignores it.
                        let _ = tokio::time::timeout(
                            Duration::from_millis(100),
                            &mut application,
                        )
                        .await;
                    }
                    result = tokio::time::timeout_at(expires_at, &mut application) => {
                        let status = match result {
                            Ok(Ok(())) => None,
                            Ok(Err(error)) => Some(service_error_status(&error, request_id)),
                            Err(_) => Some(deadline_status(request_id)),
                        };
                        if let Some(status) = status {
                            let _ = sender.send(Err(status)).await;
                        }
                    }
                }
                task_cancellation.cancel();
            }
            .instrument(span),
        );
        let mut response = Response::new(ApplicationResponseStream {
            receiver,
            cancellation,
            deadline: Box::pin(tokio::time::sleep_until(expires_at)),
            request_id,
            deadline_emitted: false,
            terminated: false,
            _permit: permit,
        });
        set_response_request_id(&mut response, request_id);
        Ok(response)
    }
}

/// Complete tonic route composition and health reporter.
#[derive(Clone)]
pub struct ServerComposition {
    public_routes: Routes,
    protected_routes: Routes,
    health_reporter: HealthReporter,
    config: ValidatedGrpcConfig,
}

impl ServerComposition {
    /// Builds public and separately protected route sets.
    ///
    /// Public routes contain only the foundation and standard health services.
    /// Protected routes additionally contain reflection behind authentication,
    /// required deadlines, and the supplied canonical reflection policy.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError`] for invalid limits or reflection descriptors.
    pub fn build<S, A, Z>(
        config: GrpcConfig,
        application: S,
        authenticator: A,
        authorizer: Z,
        policies: ServerPolicies,
    ) -> Result<Self, CompositionError>
    where
        S: ApplicationService,
        A: Authenticator,
        Z: ApplicationAuthorizer,
    {
        let config = config.validate()?;
        let application = Arc::new(application);
        let authenticator = Arc::new(authenticator);
        let authorizer = Arc::new(authorizer);
        let interceptor =
            CanonicalInterceptor::new(config, Arc::clone(&authenticator), FOUNDATION_SERVICE_NAME);
        let adapter = FoundationAdapter {
            application,
            authorizer: Arc::clone(&authorizer),
            policies: policies.clone(),
            config,
            stream_slots: Arc::new(Semaphore::new(config.0.max_concurrent_streams)),
        };
        // Tonic applies its send limit after compression. Keeping responses
        // uncompressed preserves one exact protobuf limit without gzip expansion gaps.
        let foundation = FoundationServer::new(adapter)
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(config.0.max_decompressed_message_bytes)
            .max_encoding_message_size(config.0.max_encoded_message_bytes);
        let foundation = InterceptedService::new(foundation, interceptor.clone());

        let (health_reporter, health) = tonic_health::server::health_reporter();
        let health = health
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(config.0.max_decompressed_message_bytes)
            .max_encoding_message_size(config.0.max_encoded_message_bytes);
        let health = RejectHealthWatch::new(health);
        let health = InterceptedService::new(
            health,
            OperationalInterceptor {
                config,
                service: tonic_health::pb::health_server::SERVICE_NAME,
            },
        );

        let reflection = tonic_reflection::server::Builder::configure()
            .register_file_descriptor_set(foundation_descriptor_set())
            .register_encoded_file_descriptor_set(tonic_health::pb::FILE_DESCRIPTOR_SET)
            .register_encoded_file_descriptor_set(tonic_types::pb::FILE_DESCRIPTOR_SET)
            .build_v1()?
            .accept_compressed(CompressionEncoding::Gzip)
            .max_decoding_message_size(config.0.max_decompressed_message_bytes)
            .max_encoding_message_size(config.0.max_encoded_message_bytes);
        let reflection = DeadlineBodyService::new(reflection);
        let reflection = InterceptedService::new(
            reflection,
            ReflectionInterceptor {
                boundary: CanonicalInterceptor::new(
                    config,
                    authenticator,
                    "grpc.reflection.v1.ServerReflection",
                ),
                authorizer,
                policy: policies.reflection,
            },
        );

        let public_routes = Routes::new(foundation.clone())
            .add_service(health.clone())
            .prepare();
        let protected_routes = Routes::new(foundation)
            .add_service(health)
            .add_service(reflection)
            .prepare();
        Ok(Self {
            public_routes,
            protected_routes,
            health_reporter,
            config,
        })
    }

    /// Returns public routes. Reflection is structurally absent from this route set.
    #[must_use]
    pub fn public_routes(&self) -> Routes {
        self.public_routes.clone()
    }

    /// Returns routes for a protected/internal listener, including guarded reflection.
    #[must_use]
    pub fn protected_routes(&self) -> Routes {
        self.protected_routes.clone()
    }

    /// Returns a reporter for the standard gRPC health service.
    #[must_use]
    pub fn health_reporter(&self) -> HealthReporter {
        self.health_reporter.clone()
    }

    /// Returns the validated limits used by the route sets.
    #[must_use]
    pub const fn config(&self) -> ValidatedGrpcConfig {
        self.config
    }
}

/// Failure to compose the bounded gRPC server surfaces.
#[derive(Debug, Error)]
pub enum CompositionError {
    /// The configured safety limits were invalid.
    #[error(transparent)]
    Config(#[from] GrpcConfigError),
    /// The checked-in reflection descriptor set was invalid.
    #[error("gRPC reflection descriptor composition failed")]
    Reflection(#[from] tonic_reflection::server::Error),
}

/// Maps a canonical [`ServiceError`] to a redacted richer-model tonic status.
///
/// Only the explicitly safe message is eligible for output. Internal source chains
/// are never inspected or serialized. `ErrorInfo` contains exactly a bounded reason,
/// a fixed domain, and the canonical request identifier.
#[must_use]
pub fn service_error_status(error: &ServiceError, request_id: RequestId) -> Status {
    let code = service_error_code(error.code().as_str());
    let message = bounded_safe_message(error.safe_message());
    let reason = bounded_reason(error.code().as_str());
    boundary_status(code, message, reason, request_id)
}

fn application_call<T>(
    request: Request<T>,
    config: ValidatedGrpcConfig,
) -> Result<(GrpcRequestContext, ApplicationCall), Status>
where
    T: IntoPayload,
{
    let context = request
        .extensions()
        .get::<GrpcRequestContext>()
        .cloned()
        .ok_or_else(|| Status::internal("request context unavailable"))?;
    let principal = context
        .principal
        .clone()
        .ok_or_else(|| Status::internal("request context unavailable"))?;
    let payload = request.into_inner().into_payload();
    if payload.len() > config.0.max_decoded_payload_bytes {
        return Err(boundary_status(
            Code::ResourceExhausted,
            "request payload exceeds configured limit",
            "MESSAGE_TOO_LARGE",
            context.request_id,
        ));
    }
    Ok((
        context.clone(),
        ApplicationCall {
            request_id: context.request_id,
            principal,
            payload,
        },
    ))
}

trait IntoPayload {
    fn into_payload(self) -> Bytes;
}

impl IntoPayload for ExecuteRequest {
    fn into_payload(self) -> Bytes {
        self.payload
    }
}

impl IntoPayload for StreamRequest {
    fn into_payload(self) -> Bytes {
        self.payload
    }
}

fn authorize<Z>(
    authorizer: &Z,
    principal: &Principal,
    policy: &MethodPolicy,
    request_id: RequestId,
) -> Result<(), Status>
where
    Z: ApplicationAuthorizer,
{
    if authorizer.authorize(principal, &policy.action, &policy.resource, &policy.context)
        == Decision::Allow
    {
        Ok(())
    } else {
        Err(boundary_status(
            Code::PermissionDenied,
            "permission denied",
            "PERMISSION_DENIED",
            request_id,
        ))
    }
}

fn request_id(metadata: &MetadataMap) -> Result<RequestId, Status> {
    let generated = RequestId::new();
    let Some(value) = single_metadata(metadata, REQUEST_ID_METADATA).map_err(|()| {
        boundary_status(
            Code::InvalidArgument,
            "invalid request identifier",
            "REQUEST_ID_INVALID",
            generated,
        )
    })?
    else {
        return Ok(generated);
    };
    if value.len() > 36 {
        return Err(boundary_status(
            Code::InvalidArgument,
            "invalid request identifier",
            "REQUEST_ID_INVALID",
            generated,
        ));
    }
    RequestId::from_str(value).map_err(|_| {
        boundary_status(
            Code::InvalidArgument,
            "invalid request identifier",
            "REQUEST_ID_INVALID",
            generated,
        )
    })
}

fn required_deadline(
    metadata: &MetadataMap,
    config: ValidatedGrpcConfig,
    request_id: RequestId,
) -> Result<Duration, Status> {
    let value = single_metadata(metadata, GRPC_TIMEOUT_METADATA)
        .map_err(|()| {
            boundary_status(
                Code::InvalidArgument,
                "invalid gRPC deadline",
                "DEADLINE_INVALID",
                request_id,
            )
        })?
        .ok_or_else(|| {
            boundary_status(
                Code::InvalidArgument,
                "gRPC deadline is required",
                "DEADLINE_REQUIRED",
                request_id,
            )
        })?;
    let duration = parse_grpc_timeout(value).ok_or_else(|| {
        boundary_status(
            Code::InvalidArgument,
            "invalid gRPC deadline",
            "DEADLINE_INVALID",
            request_id,
        )
    })?;
    if duration > config.0.max_deadline {
        return Err(boundary_status(
            Code::InvalidArgument,
            "gRPC deadline exceeds server maximum",
            "DEADLINE_TOO_LONG",
            request_id,
        ));
    }
    Ok(duration)
}

fn single_metadata<'a>(
    metadata: &'a MetadataMap,
    name: &'static str,
) -> Result<Option<&'a str>, ()> {
    let mut values = metadata.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    first.to_str().map(Some).map_err(|_| ())
}

fn parse_grpc_timeout(value: &str) -> Option<Duration> {
    if !(2..=9).contains(&value.len()) {
        return None;
    }
    let (digits, unit) = value.split_at(value.len() - 1);
    if digits.len() > 8 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let amount = digits.parse::<u64>().ok()?;
    match unit {
        "H" => Some(Duration::from_secs(amount.saturating_mul(60 * 60))),
        "M" => Some(Duration::from_secs(amount.saturating_mul(60))),
        "S" => Some(Duration::from_secs(amount)),
        "m" => Some(Duration::from_millis(amount)),
        "u" => Some(Duration::from_micros(amount)),
        "n" => Some(Duration::from_nanos(amount)),
        _ => None,
    }
}

fn insert_request_id(metadata: &mut MetadataMap, request_id: RequestId) {
    if let Ok(value) = MetadataValue::<Ascii>::try_from(request_id.to_string()) {
        metadata.insert(REQUEST_ID_METADATA, value);
    }
}

fn set_response_request_id<T>(response: &mut Response<T>, request_id: RequestId) {
    insert_request_id(response.metadata_mut(), request_id);
}

fn request_span(service: &'static str, request_id: RequestId) -> Span {
    tracing::info_span!(
        target: "rsk_grpc",
        "grpc.request",
        rpc.system = "grpc",
        rpc.service = service,
        request.id = %request_id,
        otel.kind = "server"
    )
}

fn deadline_status(request_id: RequestId) -> Status {
    boundary_status(
        Code::DeadlineExceeded,
        "gRPC deadline exceeded",
        "DEADLINE_EXCEEDED",
        request_id,
    )
}

fn boundary_status(
    code: Code,
    message: impl Into<String>,
    reason: &str,
    request_id: RequestId,
) -> Status {
    let mut metadata = HashMap::with_capacity(1);
    metadata.insert("request_id".to_owned(), request_id.to_string());
    let details = ErrorDetails::with_error_info(reason, ERROR_DOMAIN, metadata);
    let mut response_metadata = MetadataMap::with_capacity(1);
    if let Ok(value) = MetadataValue::<Ascii>::try_from(request_id.to_string()) {
        response_metadata.insert(REQUEST_ID_METADATA, value);
    }
    Status::with_error_details_and_metadata(code, message, details, response_metadata)
}

fn bounded_safe_message(message: &str) -> &str {
    if !message.is_empty()
        && message.len() <= MAX_SAFE_MESSAGE_BYTES
        && !message.chars().any(char::is_control)
    {
        message
    } else {
        "request failed"
    }
}

fn bounded_reason(code: &str) -> &str {
    if code.len() <= 63 {
        code
    } else {
        "SERVICE_ERROR"
    }
}

fn service_error_code(code: &str) -> Code {
    if code == "INVALID_ARGUMENT" || code == "VALIDATION_FAILED" || code.ends_with("_INVALID") {
        Code::InvalidArgument
    } else if code == "NOT_FOUND" || code.ends_with("_NOT_FOUND") {
        Code::NotFound
    } else if code == "ALREADY_EXISTS" || code.ends_with("_ALREADY_EXISTS") {
        Code::AlreadyExists
    } else if code == "CONFLICT" || code.ends_with("_CONFLICT") {
        Code::Aborted
    } else if code == "UNAUTHENTICATED" || code.ends_with("_UNAUTHENTICATED") {
        Code::Unauthenticated
    } else if code == "PERMISSION_DENIED" || code == "FORBIDDEN" {
        Code::PermissionDenied
    } else if code == "RATE_LIMITED" || code == "RESOURCE_EXHAUSTED" {
        Code::ResourceExhausted
    } else if code == "DEADLINE_EXCEEDED" {
        Code::DeadlineExceeded
    } else if code == "CANCELLED" {
        Code::Cancelled
    } else if code == "UNAVAILABLE" || code.ends_with("_UNAVAILABLE") {
        Code::Unavailable
    } else {
        Code::Internal
    }
}

fn foundation_descriptor_set() -> FileDescriptorSet {
    let message = |name: &str| DescriptorProto {
        name: Some(name.to_owned()),
        field: vec![FieldDescriptorProto {
            name: Some("payload".to_owned()),
            number: Some(1),
            label: Some(Label::Optional as i32),
            r#type: Some(Type::Bytes as i32),
            json_name: Some("payload".to_owned()),
            ..FieldDescriptorProto::default()
        }],
        ..DescriptorProto::default()
    };
    FileDescriptorSet {
        file: vec![FileDescriptorProto {
            name: Some("rsk/grpc/v1/foundation.proto".to_owned()),
            package: Some("rsk.grpc.v1".to_owned()),
            syntax: Some("proto3".to_owned()),
            message_type: vec![
                message("ExecuteRequest"),
                message("ExecuteResponse"),
                message("StreamRequest"),
                message("StreamResponse"),
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("Foundation".to_owned()),
                method: vec![
                    MethodDescriptorProto {
                        name: Some("Execute".to_owned()),
                        input_type: Some(".rsk.grpc.v1.ExecuteRequest".to_owned()),
                        output_type: Some(".rsk.grpc.v1.ExecuteResponse".to_owned()),
                        ..MethodDescriptorProto::default()
                    },
                    MethodDescriptorProto {
                        name: Some("Stream".to_owned()),
                        input_type: Some(".rsk.grpc.v1.StreamRequest".to_owned()),
                        output_type: Some(".rsk.grpc.v1.StreamResponse".to_owned()),
                        server_streaming: Some(true),
                        ..MethodDescriptorProto::default()
                    },
                ],
                ..ServiceDescriptorProto::default()
            }],
            ..FileDescriptorProto::default()
        }],
    }
}

#[cfg(test)]
mod tests {
    use futures::StreamExt as _;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[tokio::test]
    async fn queued_stream_item_is_discarded_when_consumed_after_deadline() -> TestResult {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slots
            .try_acquire_owned()
            .map_err(|_| "stream slot unavailable")?;
        let (sender, receiver) = mpsc::channel(1);
        if sender
            .send(Ok(StreamResponse {
                payload: Bytes::from_static(b"queued"),
            }))
            .await
            .is_err()
        {
            return Err("stream queue closed unexpectedly".into());
        }
        let cancellation = CancellationToken::new();
        let request_id = RequestId::new();
        let expires_at = tokio::time::Instant::now() + Duration::from_millis(20);
        let mut stream = ApplicationResponseStream {
            receiver,
            cancellation: cancellation.clone(),
            deadline: Box::pin(tokio::time::sleep_until(expires_at)),
            request_id,
            deadline_emitted: false,
            terminated: false,
            _permit: permit,
        };

        tokio::time::sleep(Duration::from_millis(30)).await;
        let first = stream.next().await.ok_or("deadline status missing")?;
        let Err(status) = first else {
            return Err("buffered item escaped after deadline".into());
        };
        assert_eq!(status.code(), Code::DeadlineExceeded);
        assert!(cancellation.is_cancelled());
        assert!(stream.next().await.is_none());
        Ok(())
    }
}
