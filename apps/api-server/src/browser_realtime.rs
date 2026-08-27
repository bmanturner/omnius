//! Browser realtime composition for the reference API profile.
//!
//! The selected local adapter is deliberately ephemeral: HTTP remains authoritative, reconnect
//! cursors are accepted as opaque subscription state, and no replay is claimed. Application
//! mutations publish only after their transaction commits.

use std::{convert::Infallible, future::Future, sync::Arc, time::Duration};

use axum::{
    Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header::ORIGIN},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use omnius_auth_core::{Principal, SubjectId, TenantId};
use omnius_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationService, BasicPolicy,
    ContextError, Decision, Grant, IdentifierError, PolicyError, PolicyMatrix, PolicyRule,
    Resource, ResourceKind,
};
use omnius_core::{ErrorCode, RequestId, ServiceError};
use omnius_http::ProblemDetails;
use omnius_realtime_core::{
    AuthorizationCommand, CanonicalFanoutEvent, CommandAuthorizationResolver,
    ConnectionDeliveryHub, ConnectionRegistry, DeliveryDrainOutcome, DeliveryQueueConfig,
    FanoutAuthorizer, FanoutRouteError, FanoutRouter, FanoutRouterConfig, MessageId, MessageType,
    ObjectPayload, PING_ACTION, PayloadError, PortableStringError, RealtimeService, RegistryConfig,
    ResolvedAuthorization, SUBSCRIBE_ACTION, SubscriptionSnapshot, Topic, UNSUBSCRIBE_ACTION,
};
use omnius_realtime_sse::{
    AuthenticatedSseIdentity, SseConfig, SseIdentityBinding, SseIdentityRevalidation,
    SseIdentityRevalidationFuture, SseState, sse_router,
};
use omnius_realtime_websocket::{
    AuthenticationFuture, IdentityRevalidation, RevalidationFuture, WebSocketAuthentication,
    WebSocketAuthenticationError, WebSocketConfig, WebSocketIdentity, WebSocketState,
    websocket_router,
};
use omnius_reference_domain::ReferenceRecordId;
use serde_json::{Map, Value};
use thiserror::Error;

use super::browser_auth::{
    BrowserAuthState, BrowserCookieAuthenticationError, BrowserCookieIdentity,
    BrowserSessionBinding, BrowserSessionRevalidation,
};

/// Tenant-scoped topic used by reference-record invalidation subscribers.
pub const REFERENCE_RECORDS_TOPIC: &str = "reference-records";
/// Stable module-owned browser event name for reference-record cache invalidation.
pub const REFERENCE_RECORD_INVALIDATED_EVENT: &str = "reference-record.invalidated.v1";

const REALTIME_SUBSCRIPTION_RESOURCE: &str = "realtime_subscription";
const REALTIME_CONNECTION_RESOURCE: &str = "realtime_connection";

/// Canonical opaque-cookie identity adapter used by both browser realtime transports.
///
/// Each WebSocket retains the exact auth-owned session binding that authenticated it. Sibling
/// sessions for the same principal therefore revalidate independently.
#[derive(Clone)]
pub struct BrowserSessionRealtimeIdentity {
    identity: BrowserCookieIdentity,
}

impl BrowserSessionRealtimeIdentity {
    /// Creates the transport adapter from the browser auth module's canonical provider boundary.
    #[must_use]
    pub fn new(state: &BrowserAuthState) -> Self {
        Self {
            identity: state.cookie_identity(),
        }
    }
}

impl WebSocketIdentity for BrowserSessionRealtimeIdentity {
    type Binding = BrowserSessionBinding;

    fn authenticate<'a>(
        &'a self,
        headers: &'a axum::http::HeaderMap,
    ) -> AuthenticationFuture<'a, Self::Binding> {
        Box::pin(async move {
            let (active, binding) = self
                .identity
                .authenticate_bound_headers(headers)
                .await
                .map_err(map_cookie_authentication_error)?;
            Ok(WebSocketAuthentication::new(active.principal, binding))
        })
    }

    fn revalidate<'a>(
        &'a self,
        principal: &'a Principal,
        binding: &'a Self::Binding,
    ) -> RevalidationFuture<'a> {
        Box::pin(async move {
            match self
                .identity
                .revalidate_bound_session(principal, binding)
                .await
            {
                BrowserSessionRevalidation::Active => IdentityRevalidation::Active,
                BrowserSessionRevalidation::Revoked => IdentityRevalidation::Revoked,
                BrowserSessionRevalidation::Unavailable => IdentityRevalidation::Unavailable,
            }
        })
    }
}

const fn map_cookie_authentication_error(
    error: BrowserCookieAuthenticationError,
) -> WebSocketAuthenticationError {
    match error {
        BrowserCookieAuthenticationError::Missing => WebSocketAuthenticationError::Missing,
        BrowserCookieAuthenticationError::Rejected => WebSocketAuthenticationError::Rejected,
        BrowserCookieAuthenticationError::Unavailable => WebSocketAuthenticationError::Unavailable,
    }
}

/// Validated limits and transport policy for the assembled browser realtime routes.
#[derive(Clone, Debug)]
pub struct BrowserRealtimeConfig {
    registry: RegistryConfig,
    delivery: DeliveryQueueConfig,
    fanout: FanoutRouterConfig,
    websocket: WebSocketConfig,
    sse: SseConfig,
}

impl BrowserRealtimeConfig {
    /// Creates composition policy from already-validated provider and transport settings.
    #[must_use]
    pub const fn new(
        registry: RegistryConfig,
        delivery: DeliveryQueueConfig,
        fanout: FanoutRouterConfig,
        websocket: WebSocketConfig,
        sse: SseConfig,
    ) -> Self {
        Self {
            registry,
            delivery,
            fanout,
            websocket,
            sse,
        }
    }
}

/// A realtime constant failed its bounded service-kit validation during composition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BrowserRealtimeBuildError {
    /// A declared authorization action or resource kind was invalid.
    #[error("browser realtime authorization constants are invalid")]
    Authorization(#[from] IdentifierError),
    /// A topic or event name was invalid.
    #[error("browser realtime protocol constants are invalid")]
    Protocol(#[from] PortableStringError),
    /// The built-in realtime permission matrix was invalid.
    #[error("browser realtime authorization policy is invalid")]
    Policy(#[from] PolicyError),
}

/// Authoritative command facts for the browser realtime connection and subscription resources.
#[derive(Clone)]
pub struct BrowserRealtimeAuthorizationResolver {
    subscribe_action: Action,
    unsubscribe_action: Action,
    ping_action: Action,
    subscription_kind: ResourceKind,
    connection_kind: ResourceKind,
}

impl BrowserRealtimeAuthorizationResolver {
    fn new() -> Result<Self, BrowserRealtimeBuildError> {
        Ok(Self {
            subscribe_action: Action::new(SUBSCRIBE_ACTION)?,
            unsubscribe_action: Action::new(UNSUBSCRIBE_ACTION)?,
            ping_action: Action::new(PING_ACTION)?,
            subscription_kind: ResourceKind::new(REALTIME_SUBSCRIPTION_RESOURCE)?,
            connection_kind: ResourceKind::new(REALTIME_CONNECTION_RESOURCE)?,
        })
    }

    fn context(principal: &Principal) -> Result<AuthorizationContext, ContextError> {
        AuthorizationContext::new(
            Vec::new(),
            principal.tenant_id.into_iter().collect(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn resource(kind: ResourceKind, owner_id: SubjectId, tenant_id: Option<TenantId>) -> Resource {
        let resource = Resource::new(kind).owned_by(owner_id);
        match tenant_id {
            Some(tenant_id) => resource.in_tenant(tenant_id),
            None => resource,
        }
    }

    fn subscription_authorization(
        &self,
        principal: &Principal,
        owner_id: SubjectId,
        tenant_id: Option<TenantId>,
    ) -> Result<ResolvedAuthorization, ContextError> {
        Ok(ResolvedAuthorization::new(
            self.subscribe_action.clone(),
            Self::resource(self.subscription_kind.clone(), owner_id, tenant_id),
            Self::context(principal)?,
        ))
    }
}

impl CommandAuthorizationResolver for BrowserRealtimeAuthorizationResolver {
    type Error = ContextError;

    fn resolve(
        &self,
        principal: &Principal,
        command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        let context = Self::context(principal)?;
        let resolved = match command {
            AuthorizationCommand::Subscribe(_) => ResolvedAuthorization::new(
                self.subscribe_action.clone(),
                Self::resource(
                    self.subscription_kind.clone(),
                    principal.subject_id,
                    principal.tenant_id,
                ),
                context,
            ),
            AuthorizationCommand::Unsubscribe { existing, .. } => {
                let (owner_id, tenant_id) = existing.map_or(
                    (principal.subject_id, principal.tenant_id),
                    |subscription| (subscription.subject_id(), Some(subscription.tenant_id())),
                );
                ResolvedAuthorization::new(
                    self.unsubscribe_action.clone(),
                    Self::resource(self.subscription_kind.clone(), owner_id, tenant_id),
                    context,
                )
            }
            AuthorizationCommand::Ping(_) => ResolvedAuthorization::new(
                self.ping_action.clone(),
                Self::resource(
                    self.connection_kind.clone(),
                    principal.subject_id,
                    principal.tenant_id,
                ),
                context,
            ),
        };
        Ok(resolved)
    }
}

struct BrowserFanoutAuthorizer<P> {
    registry: Arc<ConnectionRegistry>,
    authorization: AuthorizationService<P>,
    resolver: BrowserRealtimeAuthorizationResolver,
}

impl<P> FanoutAuthorizer for BrowserFanoutAuthorizer<P>
where
    P: AuthorizationProvider + Send + Sync,
{
    type Error = Infallible;

    fn authorize<'a>(
        &'a self,
        event: &'a CanonicalFanoutEvent,
        subscription: &'a SubscriptionSnapshot,
    ) -> impl Future<Output = Result<bool, Self::Error>> + Send + 'a {
        std::future::ready(Ok(self.authorize_now(event, subscription)))
    }
}

impl<P> BrowserFanoutAuthorizer<P>
where
    P: AuthorizationProvider,
{
    fn authorize_now(
        &self,
        event: &CanonicalFanoutEvent,
        subscription: &SubscriptionSnapshot,
    ) -> bool {
        if event.tenant_id() != subscription.tenant_id() || event.topic() != subscription.topic() {
            return false;
        }
        let Ok(Some(connection)) = self.registry.connection(subscription.connection_id()) else {
            return false;
        };
        let principal = connection.principal();
        if principal.subject_id != subscription.subject_id()
            || principal.tenant_id != Some(subscription.tenant_id())
        {
            return false;
        }
        let Ok(resolved) = self.resolver.subscription_authorization(
            principal,
            subscription.subject_id(),
            Some(subscription.tenant_id()),
        ) else {
            return false;
        };
        self.authorization.authorize(
            principal,
            resolved.action(),
            resolved.resource(),
            resolved.context(),
        ) == Decision::Allow
    }
}

/// Mutation class included in a reference-record invalidation event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRecordMutation {
    /// A record became visible.
    Created,
    /// A record representation changed.
    Updated,
    /// A record ceased to exist.
    Deleted,
}

impl ReferenceRecordMutation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Deleted => "deleted",
        }
    }
}

/// A reference-record event could not be admitted to bounded local delivery.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReferenceRecordPublicationError {
    /// The semantic payload exceeded protocol bounds.
    #[error("reference-record invalidation payload is invalid")]
    Payload(#[from] PayloadError),
    /// Fanout authorization or bounded delivery failed.
    #[error("reference-record invalidation delivery is unavailable")]
    Delivery(#[from] FanoutRouteError),
}

/// Cloneable post-commit publication port for reference-record mutations.
pub struct ReferenceRecordRealtimePublisher<P> {
    router: Arc<FanoutRouter<BrowserFanoutAuthorizer<P>>>,
    sink: omnius_realtime_core::ConnectionDeliverySink,
    topic: Topic,
    event_type: MessageType,
}

impl<P> Clone for ReferenceRecordRealtimePublisher<P> {
    fn clone(&self) -> Self {
        Self {
            router: Arc::clone(&self.router),
            sink: self.sink.clone(),
            topic: self.topic.clone(),
            event_type: self.event_type.clone(),
        }
    }
}

impl<P> ReferenceRecordRealtimePublisher<P>
where
    P: AuthorizationProvider + Send + Sync,
{
    /// Publishes one ephemeral, tenant-scoped invalidation after a committed mutation.
    ///
    /// `source_id` is supplied by the mutation boundary and must remain stable if an actual
    /// at-least-once provider redelivers the same event. Browser clients use it for bounded dedup.
    /// This selected in-process adapter intentionally emits no replay cursor.
    ///
    /// # Errors
    ///
    /// Returns a redacted error if the bounded payload, authorization refresh, or delivery
    /// admission fails.
    pub async fn publish_reference_record_invalidation(
        &self,
        source_id: MessageId,
        tenant_id: TenantId,
        record_id: ReferenceRecordId,
        mutation: ReferenceRecordMutation,
    ) -> Result<(), ReferenceRecordPublicationError> {
        let mut data = Map::new();
        data.insert("record_id".into(), Value::String(record_id.to_string()));
        data.insert("mutation".into(), Value::String(mutation.as_str().into()));
        let event = CanonicalFanoutEvent::new(
            source_id,
            tenant_id,
            self.topic.clone(),
            self.event_type.clone(),
            None,
            ObjectPayload::new(data)?,
        );
        self.router.route(&event, &self.sink).await?;
        Ok(())
    }
}

/// Fully assembled browser realtime routes and their shared lifecycle/publication handles.
pub struct BrowserRealtime<P> {
    router: Router,
    registry: Arc<ConnectionRegistry>,
    service: Arc<RealtimeService<P, BrowserRealtimeAuthorizationResolver>>,
    delivery_hub: ConnectionDeliveryHub,
    publisher: ReferenceRecordRealtimePublisher<P>,
}

impl<P> BrowserRealtime<P>
where
    P: AuthorizationProvider + Clone + Send + Sync + 'static,
{
    /// Assembles the canonical WebSocket and SSE paths over one registry and bounded local hub.
    ///
    /// The identity implementation is shared by both transports. It must use the browser auth
    /// module's opaque-cookie authentication and fail-closed revalidation implementation.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserRealtimeBuildError`] if a checked application constant is invalid.
    pub fn new<I>(
        provider: P,
        identity: Arc<I>,
        config: BrowserRealtimeConfig,
    ) -> Result<Self, BrowserRealtimeBuildError>
    where
        I: WebSocketIdentity,
    {
        let registry = Arc::new(ConnectionRegistry::new(config.registry));
        let resolver = BrowserRealtimeAuthorizationResolver::new()?;
        let authorization = AuthorizationService::new(provider);
        let service = Arc::new(RealtimeService::new(
            registry.as_ref().clone(),
            authorization.clone(),
            resolver.clone(),
        ));
        let delivery_hub = ConnectionDeliveryHub::new(Arc::clone(&registry), config.delivery);
        let fanout = Arc::new(FanoutRouter::new(
            Arc::clone(&registry),
            BrowserFanoutAuthorizer {
                registry: Arc::clone(&registry),
                authorization,
                resolver,
            },
            config.fanout,
        ));
        let publisher = ReferenceRecordRealtimePublisher {
            router: fanout,
            sink: delivery_hub.sink(),
            topic: Topic::new(REFERENCE_RECORDS_TOPIC)?,
            event_type: MessageType::new(REFERENCE_RECORD_INVALIDATED_EVENT)?,
        };

        let sse_identity = SseIdentityState {
            identity: Arc::clone(&identity),
            authentication_timeout: config.websocket.authentication_timeout(),
            trusted_origins: config.websocket.trusted_origins().into(),
        };
        let websocket = websocket_router(
            WebSocketState::new(Arc::clone(&service), identity, config.websocket)
                .with_delivery_hub(delivery_hub.clone()),
        );
        let sse = sse_router(SseState::from_delivery_hub(
            Arc::clone(&service),
            delivery_hub.clone(),
            config.sse,
        ))
        .layer(middleware::from_fn_with_state(
            sse_identity,
            authenticate_sse::<I>,
        ));

        Ok(Self {
            router: websocket.merge(sse),
            registry,
            service,
            delivery_hub,
            publisher,
        })
    }

    /// Returns a cloneable Axum router exposing exactly `/realtime/ws` and `/events`.
    #[must_use]
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Consumes the composition into its Axum router.
    #[must_use]
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Returns the single connection/subscription registry shared by both transports and fanout.
    #[must_use]
    pub const fn registry(&self) -> &Arc<ConnectionRegistry> {
        &self.registry
    }

    /// Returns the authorized transport-neutral command service.
    #[must_use]
    pub const fn service(&self) -> &Arc<RealtimeService<P, BrowserRealtimeAuthorizationResolver>> {
        &self.service
    }

    /// Returns the bounded delivery hub used by both transports.
    #[must_use]
    pub const fn delivery_hub(&self) -> &ConnectionDeliveryHub {
        &self.delivery_hub
    }

    /// Returns a cloneable post-commit reference-record publication port.
    #[must_use]
    pub fn publisher(&self) -> ReferenceRecordRealtimePublisher<P> {
        self.publisher.clone()
    }

    /// Synchronously rejects new upgrades, streams, and fanout intake.
    pub fn begin_drain(&self) {
        self.delivery_hub.begin_drain();
    }

    /// Drains admitted delivery and terminalizes every transport at the configured deadline.
    pub async fn drain(&self) -> DeliveryDrainOutcome {
        self.delivery_hub.drain().await
    }
}

impl BrowserRealtime<BasicPolicy> {
    /// Assembles the selected built-in owner-and-tenant realtime policy.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserRealtimeBuildError`] if checked policy or protocol constants are invalid.
    pub fn with_basic_policy<I>(
        identity: Arc<I>,
        config: BrowserRealtimeConfig,
    ) -> Result<Self, BrowserRealtimeBuildError>
    where
        I: WebSocketIdentity,
    {
        let subscription_kind = ResourceKind::new(REALTIME_SUBSCRIPTION_RESOURCE)?;
        let connection_kind = ResourceKind::new(REALTIME_CONNECTION_RESOURCE)?;
        let rules = vec![
            PolicyRule::new(
                Action::new(SUBSCRIBE_ACTION)?,
                subscription_kind.clone(),
                vec![Grant::Owner],
            )?
            .requiring_tenant_membership(),
            PolicyRule::new(
                Action::new(UNSUBSCRIBE_ACTION)?,
                subscription_kind,
                vec![Grant::Owner],
            )?
            .requiring_tenant_membership(),
            PolicyRule::new(
                Action::new(PING_ACTION)?,
                connection_kind,
                vec![Grant::Owner],
            )?
            .requiring_tenant_membership(),
        ];
        Self::new(
            BasicPolicy::new(PolicyMatrix::new(rules)?),
            identity,
            config,
        )
    }
}

struct SseIdentityState<I> {
    identity: Arc<I>,
    authentication_timeout: Duration,
    trusted_origins: Box<[HeaderValue]>,
}

impl<I> Clone for SseIdentityState<I> {
    fn clone(&self) -> Self {
        Self {
            identity: Arc::clone(&self.identity),
            authentication_timeout: self.authentication_timeout,
            trusted_origins: self.trusted_origins.clone(),
        }
    }
}

struct BrowserSseIdentityBinding<I>
where
    I: WebSocketIdentity,
{
    identity: Arc<I>,
    principal: Principal,
    binding: I::Binding,
}

impl<I> SseIdentityBinding for BrowserSseIdentityBinding<I>
where
    I: WebSocketIdentity,
{
    fn principal(&self) -> &Principal {
        &self.principal
    }

    fn revalidate(self: Arc<Self>) -> SseIdentityRevalidationFuture {
        Box::pin(async move {
            match self
                .identity
                .revalidate(&self.principal, &self.binding)
                .await
            {
                IdentityRevalidation::Active => SseIdentityRevalidation::Active,
                IdentityRevalidation::Revoked => SseIdentityRevalidation::Revoked,
                IdentityRevalidation::Unavailable => SseIdentityRevalidation::Unavailable,
            }
        })
    }
}

async fn authenticate_sse<I>(
    State(state): State<SseIdentityState<I>>,
    mut request: Request,
    next: Next,
) -> Response
where
    I: WebSocketIdentity,
{
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .copied()
        .unwrap_or_else(RequestId::new);
    request.extensions_mut().insert(request_id);

    let authentication = tokio::time::timeout(
        state.authentication_timeout,
        state.identity.authenticate(request.headers()),
    )
    .await;
    let (principal, binding) = match authentication {
        Ok(Ok(authentication)) => authentication.into_parts(),
        Ok(Err(WebSocketAuthenticationError::Missing | WebSocketAuthenticationError::Rejected)) => {
            return realtime_problem(
                StatusCode::UNAUTHORIZED,
                "SSE_AUTHENTICATION_REQUIRED",
                "authentication is required",
                request_id,
            );
        }
        Ok(Err(WebSocketAuthenticationError::Unavailable)) | Err(_) => {
            return realtime_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "SSE_AUTHENTICATION_UNAVAILABLE",
                "authentication is unavailable",
                request_id,
            );
        }
    };
    if principal.tenant_id.is_none() {
        return realtime_problem(
            StatusCode::FORBIDDEN,
            "SSE_TENANT_REQUIRED",
            "realtime access requires a tenant context",
            request_id,
        );
    }
    if !sse_origin_is_allowed(request.headers(), &state.trusted_origins) {
        return realtime_problem(
            StatusCode::FORBIDDEN,
            "SSE_ORIGIN_FORBIDDEN",
            "SSE Origin is not allowed",
            request_id,
        );
    }
    request
        .extensions_mut()
        .insert(AuthenticatedSseIdentity::new(BrowserSseIdentityBinding {
            identity: Arc::clone(&state.identity),
            principal,
            binding,
        }));
    next.run(request).await
}

fn sse_origin_is_allowed(headers: &axum::http::HeaderMap, trusted_origins: &[HeaderValue]) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    trusted_origins
        .iter()
        .any(|trusted| trusted.as_bytes() == origin.as_bytes())
}

fn realtime_problem(
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
    request_id: RequestId,
) -> Response {
    let Ok(code) = ErrorCode::try_new(code) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let error = ServiceError::new(code, detail);
    ProblemDetails::from_service_error(status, &error, request_id).map_or_else(
        |_| StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        IntoResponse::into_response,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        body::{Body, to_bytes},
        extract::ConnectInfo,
        http::{HeaderName, Request, StatusCode, header::ORIGIN},
    };
    use omnius_auth_core::{AssuranceLevel, AuthMethod, PrincipalKind};
    use omnius_authz_basic::BasicPolicy;
    use omnius_realtime_core::{
        AcceptedKind, InboundCommand, OpaqueCursor, OutboundMessage, PingCommand, RejectionCode,
        SubscribeCommand, SubscriptionId,
    };
    use time::OffsetDateTime;
    use tower::ServiceExt as _;
    use uuid::Uuid;

    use super::*;

    const SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
    const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
    const SUBSCRIPTION: &str = "01890f2a-0000-7000-8000-000000000021";
    const RECORD: &str = "01890f2a-0000-7000-8000-000000000031";

    #[derive(Clone, Copy)]
    enum IdentityMode {
        Active,
        Missing,
    }

    struct TestIdentity {
        mode: IdentityMode,
        calls: AtomicUsize,
    }

    impl TestIdentity {
        fn new(mode: IdentityMode) -> Self {
            Self {
                mode,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl WebSocketIdentity for TestIdentity {
        type Binding = ();

        fn authenticate<'a>(
            &'a self,
            _headers: &'a axum::http::HeaderMap,
        ) -> AuthenticationFuture<'a, Self::Binding> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async move {
                match self.mode {
                    IdentityMode::Active => principal()
                        .map(|principal| WebSocketAuthentication::new(principal, ()))
                        .map_err(|_| WebSocketAuthenticationError::Unavailable),
                    IdentityMode::Missing => Err(WebSocketAuthenticationError::Missing),
                }
            })
        }

        fn revalidate<'a>(
            &'a self,
            _principal: &'a Principal,
            _binding: &'a Self::Binding,
        ) -> RevalidationFuture<'a> {
            Box::pin(async { IdentityRevalidation::Active })
        }
    }

    fn principal() -> Result<Principal, Box<dyn Error>> {
        Ok(Principal::new(
            SubjectId::from_uuid(SUBJECT)?,
            PrincipalKind::User,
            Some(TenantId::from_uuid(TENANT)?),
            AuthMethod::Session,
            OffsetDateTime::UNIX_EPOCH,
            AssuranceLevel::Aal1,
            Vec::new(),
        )?)
    }

    fn composition(
        identity: Arc<TestIdentity>,
    ) -> Result<BrowserRealtime<BasicPolicy>, Box<dyn Error>> {
        let websocket = WebSocketConfig::new(["https://app.example"])?;
        Ok(BrowserRealtime::with_basic_policy(
            identity,
            BrowserRealtimeConfig::new(
                RegistryConfig::new(16, 32, 8)?,
                DeliveryQueueConfig::default(),
                FanoutRouterConfig::default(),
                websocket,
                SseConfig::default(),
            ),
        )?)
    }

    fn request_with_peer(uri: &str) -> Result<Request<Body>, Box<dyn Error>> {
        let mut request = Request::builder().uri(uri).body(Body::empty())?;
        request.extensions_mut().insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            42_000,
        )));
        Ok(request)
    }

    #[tokio::test]
    async fn websocket_authentication_precedes_origin_policy() -> Result<(), Box<dyn Error>> {
        let identity = Arc::new(TestIdentity::new(IdentityMode::Missing));
        let app = composition(Arc::clone(&identity))?;
        let mut request = request_with_peer("/realtime/ws")?;
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        let response = app.router().oneshot(request).await?;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(identity.calls.load(Ordering::Relaxed), 1);
        Ok(())
    }

    #[tokio::test]
    async fn authenticated_sse_rejects_untrusted_origin_and_last_event_id()
    -> Result<(), Box<dyn Error>> {
        let app = composition(Arc::new(TestIdentity::new(IdentityMode::Active)))?;
        let uri = format!("/events?subscription_id={SUBSCRIPTION}&topic={REFERENCE_RECORDS_TOPIC}");
        let mut untrusted = Request::builder().uri(&uri).body(Body::empty())?;
        untrusted
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_static("https://evil.example"));
        let untrusted_response = app.router().oneshot(untrusted).await?;
        assert_eq!(untrusted_response.status(), StatusCode::FORBIDDEN);

        let mut replay = Request::builder().uri(uri).body(Body::empty())?;
        replay.headers_mut().insert(
            HeaderName::from_static("last-event-id"),
            HeaderValue::from_static("ambiguous"),
        );
        let replay_response = app.router().oneshot(replay).await?;
        assert_eq!(replay_response.status(), StatusCode::CONFLICT);
        assert_eq!(app.registry().connection_count()?, 0);
        Ok(())
    }

    #[test]
    fn assembled_service_registers_one_subscription_generation() -> Result<(), Box<dyn Error>> {
        let app = composition(Arc::new(TestIdentity::new(IdentityMode::Active)))?;
        let connection = app.registry().register(principal()?)?;
        app.registry().activate(connection.id())?;
        let subscription_id = SUBSCRIPTION.parse::<SubscriptionId>()?;
        let command = || InboundCommand::Subscribe {
            id: MessageId::new(),
            correlation_id: None,
            command: SubscribeCommand::new(
                subscription_id,
                Topic::new(REFERENCE_RECORDS_TOPIC).expect("checked test topic"),
                None,
            ),
        };

        let first = app.service().handle(connection.id(), command());
        let second = app.service().handle(connection.id(), command());
        assert!(matches!(
            &first,
            OutboundMessage::Accepted(accepted)
                if matches!(accepted.kind(), AcceptedKind::SubscriptionCreated { .. })
        ));
        assert!(matches!(
            &second,
            OutboundMessage::Rejected(rejected)
                if rejected.code() == RejectionCode::Conflict
        ));
        assert_eq!(app.registry().subscription_count()?, 1);
        assert_eq!(
            app.registry()
                .subscription(subscription_id)?
                .ok_or("missing subscription")?
                .generation(),
            1,
        );
        Ok(())
    }

    #[tokio::test]
    async fn sse_cursor_duplicate_ids_named_events_and_drain_use_shared_hub()
    -> Result<(), Box<dyn Error>> {
        let app = composition(Arc::new(TestIdentity::new(IdentityMode::Active)))?;
        let uri = format!(
            "/events?subscription_id={SUBSCRIPTION}&topic={REFERENCE_RECORDS_TOPIC}&cursor=cursor-7"
        );
        let response = app
            .router()
            .oneshot(Request::builder().uri(uri).body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        let subscription_id = SUBSCRIPTION.parse::<SubscriptionId>()?;
        let subscription = app
            .registry()
            .subscription(subscription_id)?
            .ok_or("missing SSE subscription")?;
        assert_eq!(subscription.cursor(), Some(&OpaqueCursor::new("cursor-7")?),);

        let source_id = MessageId::new();
        let record_id = RECORD.parse::<ReferenceRecordId>()?;
        let publisher = app.publisher();
        publisher
            .publish_reference_record_invalidation(
                source_id,
                TenantId::from_uuid(TENANT)?,
                record_id,
                ReferenceRecordMutation::Updated,
            )
            .await?;
        publisher
            .publish_reference_record_invalidation(
                source_id,
                TenantId::from_uuid(TENANT)?,
                record_id,
                ReferenceRecordMutation::Updated,
            )
            .await?;

        let hub = app.delivery_hub().clone();
        let drain = tokio::spawn(async move { hub.drain().await });
        let body = to_bytes(response.into_body(), 64 * 1024).await?;
        let _outcome = drain.await?;
        let body = std::str::from_utf8(&body)?;
        assert_eq!(
            body.matches(&format!("event: {REFERENCE_RECORD_INVALIDATED_EVENT}"))
                .count(),
            2,
        );
        assert_eq!(body.matches(&source_id.to_string()).count(), 2);
        assert!(body.contains("event: reconnect"));
        assert!(body.contains("data: server-draining"));
        assert!(!app.delivery_hub().is_accepting());
        assert_eq!(app.registry().connection_count()?, 0);
        Ok(())
    }

    #[test]
    fn ping_authorization_uses_connection_facts_not_topic_text() -> Result<(), Box<dyn Error>> {
        let app = composition(Arc::new(TestIdentity::new(IdentityMode::Active)))?;
        let connection = app.registry().register(principal()?)?;
        app.registry().activate(connection.id())?;
        let output = app.service().handle(
            connection.id(),
            InboundCommand::Ping {
                id: MessageId::new(),
                correlation_id: None,
                command: PingCommand::new(),
            },
        );
        assert!(matches!(output, OutboundMessage::Control(_)));
        Ok(())
    }
}
