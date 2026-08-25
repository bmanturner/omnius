//! Bound-socket behavioral coverage for the public WebSocket adapter.

use std::{
    convert::Infallible,
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::Router;
use futures::{SinkExt as _, StreamExt as _};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationRequest,
    AuthorizationService, Decision, DenyReason, Resource, ResourceKind,
};
use rsk_realtime_core::{
    AuthorizationCommand, CommandAuthorizationResolver, ConnectionDeliveryHub, ConnectionRegistry,
    ControlOutput, DeliveryPriority, DeliveryQueueConfig, MAX_ENVELOPE_BYTES, MessageId,
    OutboundMessage, RealtimeService, RegistryConfig, ResolvedAuthorization, SubscriptionId,
};
use rsk_realtime_websocket::{
    AuthenticationFuture, ConnectionLimitConfig, ConnectionLimiter, IdentityRevalidation,
    RevalidationFuture, WEBSOCKET_PROTOCOL, WebSocketAuthenticationError, WebSocketConfig,
    WebSocketConfigError, WebSocketIdentity, WebSocketState, websocket_router,
};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async,
    tungstenite::{
        Error as WebSocketError, Message as ClientMessage,
        client::IntoClientRequest as _,
        http::{
            HeaderValue, Request as ClientRequest, StatusCode as ClientStatus,
            header::{AUTHORIZATION, COOKIE, ORIGIN, SEC_WEBSOCKET_PROTOCOL},
        },
        protocol::CloseFrame as ClientCloseFrame,
    },
};
use uuid::Uuid;

const SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const SECOND_SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0002);
const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const OTHER_TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);
const SUBSCRIPTION_ID: &str = "01890f2a-0000-7000-8000-000000000021";
const SUBSCRIBE_ID: &str = "01890f2a-0000-7000-8000-000000000031";
const UNSUBSCRIBE_ID: &str = "01890f2a-0000-7000-8000-000000000032";
const PING_ID: &str = "01890f2a-0000-7000-8000-000000000033";
const TRUSTED_ORIGIN: &str = "https://app.example.test";
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type ClientSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

fn principal(subject: Uuid, tenant: Uuid) -> TestResult<Principal> {
    Ok(Principal::new(
        SubjectId::from_uuid(subject)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(tenant)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

struct TestIdentity {
    primary: Principal,
    secondary: Principal,
    other_tenant: Principal,
    authenticate_calls: AtomicUsize,
    revalidation: AtomicU8,
}

impl TestIdentity {
    fn new() -> TestResult<Self> {
        Ok(Self {
            primary: principal(SUBJECT, TENANT)?,
            secondary: principal(SECOND_SUBJECT, TENANT)?,
            other_tenant: principal(SECOND_SUBJECT, OTHER_TENANT)?,
            authenticate_calls: AtomicUsize::new(0),
            revalidation: AtomicU8::new(0),
        })
    }

    fn authenticate_calls(&self) -> usize {
        self.authenticate_calls.load(Ordering::SeqCst)
    }

    fn set_revalidation(&self, revalidation: IdentityRevalidation) {
        let value = match revalidation {
            IdentityRevalidation::Active => 0,
            IdentityRevalidation::Revoked => 1,
            IdentityRevalidation::Unavailable => 2,
        };
        self.revalidation.store(value, Ordering::SeqCst);
    }

    fn set_revalidation_pending(&self) {
        self.revalidation.store(3, Ordering::SeqCst);
    }
}

impl WebSocketIdentity for TestIdentity {
    fn authenticate<'a>(&'a self, headers: &'a axum::http::HeaderMap) -> AuthenticationFuture<'a> {
        self.authenticate_calls.fetch_add(1, Ordering::SeqCst);
        let bearer = headers
            .get(AUTHORIZATION.as_str())
            .and_then(|value| value.to_str().ok());
        let cookie = headers
            .get(COOKIE.as_str())
            .and_then(|value| value.to_str().ok());
        if bearer == Some("Bearer stalled") {
            return Box::pin(std::future::pending());
        }
        let result = if let Some(bearer) = bearer {
            match bearer {
                "Bearer good" => Ok(self.primary.clone()),
                "Bearer secondary" => Ok(self.secondary.clone()),
                "Bearer other-tenant" => Ok(self.other_tenant.clone()),
                "Bearer unavailable" => Err(WebSocketAuthenticationError::Unavailable),
                _ => Err(WebSocketAuthenticationError::Rejected),
            }
        } else if cookie == Some("session=good") {
            Ok(self.primary.clone())
        } else if cookie.is_some() {
            Err(WebSocketAuthenticationError::Rejected)
        } else {
            Err(WebSocketAuthenticationError::Missing)
        };
        Box::pin(async move { result })
    }

    fn revalidate<'a>(&'a self, _principal: &'a Principal) -> RevalidationFuture<'a> {
        let mode = self.revalidation.load(Ordering::SeqCst);
        Box::pin(async move {
            match mode {
                0 => IdentityRevalidation::Active,
                1 => IdentityRevalidation::Revoked,
                2 => IdentityRevalidation::Unavailable,
                _ => std::future::pending::<IdentityRevalidation>().await,
            }
        })
    }
}

#[derive(Clone)]
struct TestProvider {
    allow: Arc<AtomicBool>,
    calls: Arc<AtomicUsize>,
}

impl TestProvider {
    fn new(allow: bool) -> Self {
        Self {
            allow: Arc::new(AtomicBool::new(allow)),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AuthorizationProvider for TestProvider {
    type Error = Infallible;

    fn evaluate(&self, _request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(if self.allow.load(Ordering::SeqCst) {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::NotEntitled)
        })
    }
}

#[derive(Clone)]
struct TestResolver {
    resource_kind: ResourceKind,
    resource_tenant: TenantId,
    context: AuthorizationContext,
}

impl TestResolver {
    fn new(resource_tenant: Uuid) -> TestResult<Self> {
        let resource_tenant = TenantId::from_uuid(resource_tenant)?;
        Ok(Self {
            resource_kind: ResourceKind::new("realtime_subscription")?,
            resource_tenant,
            context: AuthorizationContext::new(
                Vec::new(),
                vec![resource_tenant],
                Vec::new(),
                Vec::new(),
            )?,
        })
    }
}

impl CommandAuthorizationResolver for TestResolver {
    type Error = &'static str;

    fn resolve(
        &self,
        principal: &Principal,
        command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        let action = Action::new(command.declared_action()).map_err(|_| "invalid action")?;
        Ok(ResolvedAuthorization::new(
            action,
            Resource::new(self.resource_kind.clone())
                .owned_by(principal.subject_id)
                .in_tenant(self.resource_tenant),
            self.context.clone(),
        ))
    }
}

struct Fixture {
    addr: SocketAddr,
    server: JoinHandle<()>,
    registry: ConnectionRegistry,
    provider: TestProvider,
    identity: Arc<TestIdentity>,
    limiter: ConnectionLimiter,
    primary: Principal,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn fixture(
    config: WebSocketConfig,
    allow: bool,
    resource_tenant: Uuid,
) -> TestResult<Fixture> {
    let registry = ConnectionRegistry::new(RegistryConfig::default());
    let provider = TestProvider::new(allow);
    let identity = Arc::new(TestIdentity::new()?);
    let primary = identity.primary.clone();
    let service = Arc::new(RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(resource_tenant)?,
    ));
    let state = WebSocketState::new(service, Arc::clone(&identity), config);
    let limiter = state.limiter().clone();
    let app: Router = websocket_router(state);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok(Fixture {
        addr,
        server,
        registry,
        provider,
        identity,
        limiter,
        primary,
    })
}

async fn hub_fixture(max_messages: usize) -> TestResult<(Fixture, ConnectionDeliveryHub)> {
    let registry_config = RegistryConfig::default();
    let registry = ConnectionRegistry::new(registry_config);
    let provider = TestProvider::new(true);
    let identity = Arc::new(TestIdentity::new()?);
    let primary = identity.primary.clone();
    let service = Arc::new(RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(TENANT)?,
    ));
    let bytes_per_connection = max_messages * MAX_ENVELOPE_BYTES;
    let delivery_hub = ConnectionDeliveryHub::new(
        Arc::new(registry.clone()),
        DeliveryQueueConfig::new(
            max_messages,
            bytes_per_connection,
            registry_config.max_connections() * bytes_per_connection,
            Duration::from_secs(1),
        )?,
    )?;
    let state = WebSocketState::new(service, Arc::clone(&identity), default_config()?)
        .with_delivery_hub(delivery_hub.clone());
    let limiter = state.limiter().clone();
    let app: Router = websocket_router(state);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Ok((
        Fixture {
            addr,
            server,
            registry,
            provider,
            identity,
            limiter,
            primary,
        },
        delivery_hub,
    ))
}

fn default_config() -> TestResult<WebSocketConfig> {
    Ok(WebSocketConfig::new([TRUSTED_ORIGIN])?)
}

fn client_request(
    fixture: &Fixture,
    authorization: Option<&str>,
    cookie: Option<&str>,
    origin: Option<&str>,
    protocol: Option<&str>,
) -> TestResult<ClientRequest<()>> {
    let url = format!("ws://{}/realtime/ws", fixture.addr);
    let mut request = url.as_str().into_client_request()?;
    if let Some(authorization) = authorization {
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_str(authorization)?);
    }
    if let Some(cookie) = cookie {
        request
            .headers_mut()
            .insert(COOKIE, HeaderValue::from_str(cookie)?);
    }
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert(ORIGIN, HeaderValue::from_str(origin)?);
    }
    if let Some(protocol) = protocol {
        request
            .headers_mut()
            .insert(SEC_WEBSOCKET_PROTOCOL, HeaderValue::from_str(protocol)?);
    }
    Ok(request)
}

fn valid_request(fixture: &Fixture, authorization: &str) -> TestResult<ClientRequest<()>> {
    client_request(
        fixture,
        Some(authorization),
        None,
        Some(TRUSTED_ORIGIN),
        Some(WEBSOCKET_PROTOCOL),
    )
}

async fn connect(request: ClientRequest<()>) -> TestResult<ClientSocket> {
    let (socket, response) = connect_async(request).await?;
    assert_eq!(
        response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok()),
        Some(WEBSOCKET_PROTOCOL)
    );
    Ok(socket)
}

async fn rejected(request: ClientRequest<()>) -> TestResult<(ClientStatus, Value)> {
    match connect_async(request).await {
        Err(WebSocketError::Http(response)) => {
            let status = response.status();
            let body = response
                .body()
                .as_deref()
                .ok_or_else(|| io::Error::other("problem response body was missing"))?;
            Ok((status, serde_json::from_slice(body)?))
        }
        Ok(_) => Err(io::Error::other("WebSocket request unexpectedly upgraded").into()),
        Err(error) => Err(error.into()),
    }
}

fn assert_problem(status: ClientStatus, body: &Value, expected: ClientStatus, code: &str) {
    assert_eq!(status, expected);
    assert_eq!(body["status"], u64::from(expected.as_u16()));
    assert_eq!(body["code"], code);
    assert!(body.get("request_id").is_some());
    assert!(body.get("type").is_some());
}

async fn assert_rejected_request(
    request: ClientRequest<()>,
    expected: ClientStatus,
    code: &str,
) -> TestResult {
    let (status, body) = rejected(request).await?;
    assert_problem(status, &body, expected, code);
    Ok(())
}

fn subscribe_command() -> String {
    json!({
        "v": 1,
        "id": SUBSCRIBE_ID,
        "type": "subscription.create",
        "correlation_id": null,
        "payload": {
            "subscription_id": SUBSCRIPTION_ID,
            "topic": "orders/private"
        }
    })
    .to_string()
}

fn unsubscribe_command() -> String {
    json!({
        "v": 1,
        "id": UNSUBSCRIBE_ID,
        "type": "subscription.delete",
        "correlation_id": null,
        "payload": { "subscription_id": SUBSCRIPTION_ID }
    })
    .to_string()
}

fn ping_command() -> String {
    json!({
        "v": 1,
        "id": PING_ID,
        "type": "ping",
        "correlation_id": null,
        "payload": {}
    })
    .to_string()
}

async fn send_json(socket: &mut ClientSocket, message: String) -> TestResult<Value> {
    socket.send(ClientMessage::Text(message.into())).await?;
    loop {
        let message = tokio::time::timeout(CLIENT_TIMEOUT, socket.next())
            .await
            .map_err(|_| io::Error::other("timed out waiting for WebSocket message"))?
            .ok_or_else(|| io::Error::other("WebSocket ended before a reply"))??;
        match message {
            ClientMessage::Text(text) => return Ok(serde_json::from_str(text.as_str())?),
            ClientMessage::Ping(payload) => {
                socket.send(ClientMessage::Pong(payload)).await?;
            }
            ClientMessage::Close(_) => {
                return Err(io::Error::other("WebSocket closed before a reply").into());
            }
            ClientMessage::Binary(_) | ClientMessage::Pong(_) | ClientMessage::Frame(_) => {}
        }
    }
}

async fn next_close(socket: &mut ClientSocket) -> TestResult<ClientCloseFrame> {
    loop {
        let message = tokio::time::timeout(CLIENT_TIMEOUT, socket.next())
            .await
            .map_err(|_| io::Error::other("timed out waiting for WebSocket close"))?
            .ok_or_else(|| io::Error::other("WebSocket ended without a close frame"))??;
        match message {
            ClientMessage::Close(Some(close)) => return Ok(close),
            ClientMessage::Close(None) => {
                return Err(io::Error::other("WebSocket close omitted its status").into());
            }
            ClientMessage::Ping(payload) => {
                let _ = socket.send(ClientMessage::Pong(payload)).await;
            }
            ClientMessage::Text(_)
            | ClientMessage::Binary(_)
            | ClientMessage::Pong(_)
            | ClientMessage::Frame(_) => {}
        }
    }
}

fn assert_close(close: &ClientCloseFrame, code: u16, reason: &str) {
    assert_eq!(u16::from(close.code), code);
    assert_eq!(close.reason, reason);
}

async fn wait_for_cleanup(fixture: &Fixture) -> TestResult {
    tokio::time::timeout(CLIENT_TIMEOUT, async {
        loop {
            let usage = fixture
                .limiter
                .usage(IpAddr::V4(Ipv4Addr::LOCALHOST), &fixture.primary)?;
            let pending = fixture
                .limiter
                .pending_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
            if fixture.registry.connection_count()? == 0
                && fixture.registry.subscription_count()? == 0
                && usage.peer_ip == 0
                && usage.principal == 0
                && usage.tenant == 0
                && pending == 0
            {
                return Ok::<(), Box<dyn Error>>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| io::Error::other("WebSocket cleanup did not complete"))??;
    Ok(())
}

#[test]
fn configuration_and_limiter_are_strict_and_atomic() -> TestResult {
    assert_eq!(
        WebSocketConfig::new(Vec::<String>::new()),
        Err(WebSocketConfigError::EmptyTrustedOrigins)
    );
    assert_eq!(
        WebSocketConfig::new(["https://app.example.test/"]),
        Err(WebSocketConfigError::InvalidTrustedOrigin)
    );
    assert_eq!(
        WebSocketConfig::new([TRUSTED_ORIGIN, TRUSTED_ORIGIN]),
        Err(WebSocketConfigError::InvalidTrustedOrigin)
    );
    assert_eq!(
        default_config()?.with_max_message_bytes(0),
        Err(WebSocketConfigError::InvalidMessageLimit)
    );
    assert_eq!(
        default_config()?.with_header_limits(0, 1),
        Err(WebSocketConfigError::InvalidHeaderLimits)
    );
    assert_eq!(
        default_config()?.with_authentication_timeout(Duration::ZERO),
        Err(WebSocketConfigError::InvalidAuthenticationTimeout)
    );
    assert_eq!(
        default_config()?.with_liveness(
            Duration::from_millis(20),
            Duration::from_millis(30),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(WebSocketConfigError::InvalidPongDeadline)
    );
    assert_eq!(
        ConnectionLimitConfig::new(0, 1, 1),
        Err(WebSocketConfigError::InvalidConnectionLimits)
    );

    let limiter = ConnectionLimiter::new(ConnectionLimitConfig::new(1, 2, 2)?);
    let pending = limiter.acquire_pending(IpAddr::V4(Ipv4Addr::LOCALHOST))?;
    assert_eq!(
        limiter
            .acquire_pending(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .err(),
        Some(rsk_realtime_websocket::ConnectionLimitError::Capacity)
    );
    drop(pending);
    assert_eq!(limiter.pending_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))?, 0);
    let primary = principal(SUBJECT, TENANT)?;
    let secondary = principal(SECOND_SUBJECT, TENANT)?;
    let lease = limiter.acquire(IpAddr::V4(Ipv4Addr::LOCALHOST), &primary)?;
    assert_eq!(
        limiter
            .acquire(IpAddr::V4(Ipv4Addr::LOCALHOST), &secondary)
            .err(),
        Some(rsk_realtime_websocket::ConnectionLimitError::Capacity)
    );
    let secondary_usage = limiter.usage(IpAddr::V4(Ipv4Addr::LOCALHOST), &secondary)?;
    assert_eq!(secondary_usage.peer_ip, 1);
    assert_eq!(secondary_usage.principal, 0);
    assert_eq!(secondary_usage.tenant, 1);
    drop(lease);
    assert_eq!(
        limiter.usage(IpAddr::V4(Ipv4Addr::LOCALHOST), &primary)?,
        rsk_realtime_websocket::ConnectionLimitUsage {
            peer_ip: 0,
            principal: 0,
            tenant: 0,
        }
    );
    Ok(())
}

#[tokio::test]
async fn upgrade_checks_headers_then_auth_then_origin_and_subprotocol() -> TestResult {
    let fixture = fixture(default_config()?, true, TENANT).await?;

    assert_rejected_request(
        client_request(&fixture, Some("Bearer rejected"), None, None, None)?,
        ClientStatus::UNAUTHORIZED,
        "WEBSOCKET_AUTHENTICATION_REJECTED",
    )
    .await?;
    assert_eq!(fixture.identity.authenticate_calls(), 1);

    assert_rejected_request(
        client_request(
            &fixture,
            Some("Bearer good"),
            None,
            None,
            Some(WEBSOCKET_PROTOCOL),
        )?,
        ClientStatus::FORBIDDEN,
        "WEBSOCKET_ORIGIN_FORBIDDEN",
    )
    .await?;
    assert_rejected_request(
        client_request(
            &fixture,
            Some("Bearer good"),
            None,
            Some("https://APP.example.test"),
            Some(WEBSOCKET_PROTOCOL),
        )?,
        ClientStatus::FORBIDDEN,
        "WEBSOCKET_ORIGIN_FORBIDDEN",
    )
    .await?;
    assert_rejected_request(
        client_request(
            &fixture,
            Some("Bearer good"),
            None,
            Some(TRUSTED_ORIGIN),
            None,
        )?,
        ClientStatus::BAD_REQUEST,
        "WEBSOCKET_SUBPROTOCOL_REQUIRED",
    )
    .await?;
    assert_rejected_request(
        client_request(
            &fixture,
            Some("Bearer good"),
            None,
            Some(TRUSTED_ORIGIN),
            Some("rsk.realtime.v2"),
        )?,
        ClientStatus::BAD_REQUEST,
        "WEBSOCKET_SUBPROTOCOL_REQUIRED",
    )
    .await?;

    let mut bearer = connect(valid_request(&fixture, "Bearer good")?).await?;
    bearer.close(None).await?;
    wait_for_cleanup(&fixture).await?;

    let mut session = connect(client_request(
        &fixture,
        None,
        Some("session=good"),
        Some(TRUSTED_ORIGIN),
        Some(WEBSOCKET_PROTOCOL),
    )?)
    .await?;
    session.close(None).await?;
    wait_for_cleanup(&fixture).await?;

    assert_rejected_request(
        client_request(
            &fixture,
            Some("Bearer rejected"),
            Some("session=good"),
            None,
            None,
        )?,
        ClientStatus::UNAUTHORIZED,
        "WEBSOCKET_AUTHENTICATION_REJECTED",
    )
    .await?;
    assert_eq!(fixture.registry.connection_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn header_count_and_byte_limits_precede_identity() -> TestResult {
    for config in [
        default_config()?.with_header_limits(1, 64 * 1024)?,
        default_config()?.with_header_limits(100, 1)?,
    ] {
        let fixture = fixture(config, true, TENANT).await?;
        let (status, body) = rejected(valid_request(&fixture, "Bearer good")?).await?;
        assert_problem(
            status,
            &body,
            ClientStatus::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "WEBSOCKET_REQUEST_HEADERS_TOO_LARGE",
        );
        assert_eq!(fixture.identity.authenticate_calls(), 0);
        assert_eq!(fixture.registry.connection_count()?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn stalled_authentication_times_out_and_releases_pending_slot() -> TestResult {
    let limits = ConnectionLimitConfig::new(8, 8, 8)?.with_max_pending_per_ip(1)?;
    let config = default_config()?
        .with_authentication_timeout(Duration::from_millis(20))?
        .with_connection_limits(limits);
    let fixture = fixture(config, true, TENANT).await?;
    let request = client_request(&fixture, Some("Bearer stalled"), None, None, None)?;
    tokio::time::timeout(
        Duration::from_millis(250),
        assert_rejected_request(
            request,
            ClientStatus::SERVICE_UNAVAILABLE,
            "WEBSOCKET_UNAVAILABLE",
        ),
    )
    .await
    .map_err(|_| io::Error::other("initial authentication exceeded its deadline"))??;
    assert_eq!(fixture.identity.authenticate_calls(), 1);
    assert_eq!(
        fixture
            .limiter
            .pending_for_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))?,
        0
    );
    assert_eq!(fixture.registry.connection_count()?, 0);
    Ok(())
}

#[tokio::test]
async fn network_connection_limits_are_per_scope_and_release_on_close() -> TestResult {
    let cases = [
        (ConnectionLimitConfig::new(1, 8, 8)?, "Bearer secondary"),
        (ConnectionLimitConfig::new(8, 1, 8)?, "Bearer good"),
        (ConnectionLimitConfig::new(8, 8, 1)?, "Bearer secondary"),
    ];
    for (limits, second_credential) in cases {
        let config = default_config()?.with_connection_limits(limits);
        let fixture = fixture(config, true, TENANT).await?;
        let mut first = connect(valid_request(&fixture, "Bearer good")?).await?;

        let mut second_request = valid_request(&fixture, second_credential)?;
        second_request
            .headers_mut()
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.99"));
        let (status, body) = rejected(second_request).await?;
        assert_problem(
            status,
            &body,
            ClientStatus::TOO_MANY_REQUESTS,
            "WEBSOCKET_CONNECTION_LIMIT_REACHED",
        );
        assert_eq!(fixture.registry.connection_count()?, 1);

        first.close(None).await?;
        wait_for_cleanup(&fixture).await?;
        let mut after_release = connect(valid_request(&fixture, second_credential)?).await?;
        after_release.close(None).await?;
        wait_for_cleanup(&fixture).await?;
    }
    Ok(())
}

#[tokio::test]
async fn valid_commands_are_correlated_authorized_once_and_mutate_registry() -> TestResult {
    let fixture = fixture(default_config()?, true, TENANT).await?;
    let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;

    let subscribed = send_json(&mut socket, subscribe_command()).await?;
    assert_eq!(subscribed["type"], "subscription.created");
    assert_eq!(subscribed["correlation_id"], SUBSCRIBE_ID);
    assert_eq!(subscribed["payload"]["subscription_id"], SUBSCRIPTION_ID);
    assert_eq!(fixture.registry.subscription_count()?, 1);

    let unsubscribed = send_json(&mut socket, unsubscribe_command()).await?;
    assert_eq!(unsubscribed["type"], "subscription.deleted");
    assert_eq!(unsubscribed["correlation_id"], UNSUBSCRIBE_ID);
    assert_eq!(fixture.registry.subscription_count()?, 0);

    let pong = send_json(&mut socket, ping_command()).await?;
    assert_eq!(pong["type"], "pong");
    assert_eq!(pong["correlation_id"], PING_ID);
    assert_eq!(fixture.provider.calls(), 3);

    socket.close(None).await?;
    wait_for_cleanup(&fixture).await?;
    Ok(())
}

#[tokio::test]
async fn hub_serializes_command_replies_and_bounded_outbound_events() -> TestResult {
    let (fixture, hub) = hub_fixture(2).await?;
    let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
    let subscribed = send_json(&mut socket, subscribe_command()).await?;
    assert_eq!(subscribed["type"], "subscription.created");
    let subscription_id: SubscriptionId = SUBSCRIPTION_ID.parse()?;
    let connection_id = fixture
        .registry
        .subscription(subscription_id)?
        .ok_or_else(|| io::Error::other("WebSocket subscription missing"))?
        .connection_id();
    let correlation_id = MessageId::new();
    hub.enqueue(
        connection_id,
        DeliveryPriority::Normal,
        OutboundMessage::Control(ControlOutput::pong(correlation_id)),
    )?;

    let event = tokio::time::timeout(CLIENT_TIMEOUT, socket.next())
        .await?
        .ok_or_else(|| io::Error::other("WebSocket ended before hub delivery"))??;
    let ClientMessage::Text(event) = event else {
        return Err(io::Error::other("hub delivery was not a text frame").into());
    };
    let event: Value = serde_json::from_str(event.as_str())?;
    assert_eq!(event["correlation_id"], correlation_id.to_string());
    socket.close(None).await?;
    wait_for_cleanup(&fixture).await?;
    Ok(())
}

#[tokio::test]
async fn hub_slow_consumer_closes_with_1008_and_fixed_reason() -> TestResult {
    let (fixture, hub) = hub_fixture(1).await?;
    let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
    let _ = send_json(&mut socket, subscribe_command()).await?;
    let subscription_id: SubscriptionId = SUBSCRIPTION_ID.parse()?;
    let connection_id = fixture
        .registry
        .subscription(subscription_id)?
        .ok_or_else(|| io::Error::other("WebSocket subscription missing"))?
        .connection_id();
    hub.enqueue(
        connection_id,
        DeliveryPriority::Normal,
        OutboundMessage::Control(ControlOutput::pong(MessageId::new())),
    )?;
    assert!(
        hub.enqueue(
            connection_id,
            DeliveryPriority::Normal,
            OutboundMessage::Control(ControlOutput::pong(MessageId::new())),
        )
        .is_err()
    );

    let close = next_close(&mut socket).await?;
    assert_close(&close, 1008, "slow consumer");
    wait_for_cleanup(&fixture).await?;
    assert_eq!(hub.metrics().slow_consumer_disconnects, 1);
    Ok(())
}

#[tokio::test]
async fn hub_drain_rejects_new_upgrades_and_closes_existing_socket_with_1001() -> TestResult {
    let (fixture, hub) = hub_fixture(2).await?;
    let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
    let _ = send_json(&mut socket, subscribe_command()).await?;
    let _ = hub.force_close();

    let close = next_close(&mut socket).await?;
    assert_close(&close, 1001, "server draining");
    wait_for_cleanup(&fixture).await?;
    assert_rejected_request(
        valid_request(&fixture, "Bearer good")?,
        ClientStatus::SERVICE_UNAVAILABLE,
        "WEBSOCKET_UNAVAILABLE",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn authorization_denial_and_cross_tenant_resolution_never_mutate() -> TestResult {
    for (allow, resource_tenant) in [(false, TENANT), (true, OTHER_TENANT)] {
        let fixture = fixture(default_config()?, allow, resource_tenant).await?;
        let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
        let rejected = send_json(&mut socket, subscribe_command()).await?;
        assert_eq!(rejected["type"], "command.rejected");
        assert_eq!(rejected["correlation_id"], SUBSCRIBE_ID);
        assert_eq!(rejected["payload"]["code"], "unauthorized");
        assert_eq!(fixture.registry.subscription_count()?, 0);
        socket.close(None).await?;
        wait_for_cleanup(&fixture).await?;
    }
    Ok(())
}

#[tokio::test]
async fn binary_oversize_and_malformed_messages_close_with_fixed_codes() -> TestResult {
    let config = default_config()?.with_max_message_bytes(512)?;
    let fixture = fixture(config, true, TENANT).await?;

    let mut binary = connect(valid_request(&fixture, "Bearer good")?).await?;
    binary
        .send(ClientMessage::Binary(vec![0_u8; 4].into()))
        .await?;
    assert_close(
        &next_close(&mut binary).await?,
        1003,
        "binary messages unsupported",
    );
    wait_for_cleanup(&fixture).await?;

    let mut oversized = connect(valid_request(&fixture, "Bearer good")?).await?;
    oversized
        .send(ClientMessage::Text("x".repeat(513).into()))
        .await?;
    assert_close(
        &next_close(&mut oversized).await?,
        1009,
        "message too large",
    );
    wait_for_cleanup(&fixture).await?;

    let mut malformed = connect(valid_request(&fixture, "Bearer good")?).await?;
    malformed.send(ClientMessage::Text("{".into())).await?;
    assert_close(
        &next_close(&mut malformed).await?,
        1002,
        "invalid protocol message",
    );
    wait_for_cleanup(&fixture).await?;
    assert_eq!(fixture.provider.calls(), 0);
    Ok(())
}

#[tokio::test]
async fn websocket_ping_requires_matching_pong_and_does_not_replace_core_ping() -> TestResult {
    let timeout_config = default_config()?.with_liveness(
        Duration::from_millis(40),
        Duration::from_millis(20),
        Duration::from_millis(200),
        Duration::from_secs(1),
    )?;
    let timeout_fixture = fixture(timeout_config, true, TENANT).await?;
    let mut timed_out = connect(valid_request(&timeout_fixture, "Bearer good")?).await?;
    let ping = tokio::time::timeout(CLIENT_TIMEOUT, timed_out.next())
        .await
        .map_err(|_| io::Error::other("WebSocket Ping was not received"))?
        .ok_or_else(|| io::Error::other("WebSocket ended before Ping"))??;
    let ClientMessage::Ping(payload) = ping else {
        return Err(io::Error::other("expected WebSocket Ping frame").into());
    };
    tokio::time::sleep(Duration::from_millis(25)).await;
    let _ = timed_out.send(ClientMessage::Pong(payload)).await;
    assert_close(
        &next_close(&mut timed_out).await?,
        1001,
        "heartbeat timeout",
    );
    wait_for_cleanup(&timeout_fixture).await?;

    let success_config = default_config()?.with_liveness(
        Duration::from_millis(100),
        Duration::from_millis(50),
        Duration::from_millis(500),
        Duration::from_secs(2),
    )?;
    let success_fixture = fixture(success_config, true, TENANT).await?;
    let mut alive = connect(valid_request(&success_fixture, "Bearer good")?).await?;
    let ping = tokio::time::timeout(CLIENT_TIMEOUT, alive.next())
        .await
        .map_err(|_| io::Error::other("WebSocket Ping was not received"))?
        .ok_or_else(|| io::Error::other("WebSocket ended before Ping"))??;
    let ClientMessage::Ping(payload) = ping else {
        return Err(io::Error::other("expected WebSocket Ping frame").into());
    };
    alive.send(ClientMessage::Pong(payload)).await?;
    let protocol_pong = send_json(&mut alive, ping_command()).await?;
    assert_eq!(protocol_pong["type"], "pong");
    assert_eq!(success_fixture.provider.calls(), 1);
    alive.close(None).await?;
    wait_for_cleanup(&success_fixture).await?;
    Ok(())
}

#[tokio::test]
async fn revoked_unavailable_and_maximum_lifetime_close_and_cleanup() -> TestResult {
    for (status, expected_code, reason) in [
        (
            IdentityRevalidation::Revoked,
            1008,
            "identity no longer active",
        ),
        (
            IdentityRevalidation::Unavailable,
            1011,
            "identity unavailable",
        ),
    ] {
        let config = default_config()?.with_liveness(
            Duration::from_millis(200),
            Duration::from_millis(50),
            Duration::from_millis(20),
            Duration::from_secs(1),
        )?;
        let fixture = fixture(config, true, TENANT).await?;
        let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
        fixture.identity.set_revalidation(status);
        assert_close(&next_close(&mut socket).await?, expected_code, reason);
        wait_for_cleanup(&fixture).await?;
    }

    let lifetime_config = default_config()?.with_liveness(
        Duration::from_millis(200),
        Duration::from_millis(50),
        Duration::from_millis(200),
        Duration::from_millis(40),
    )?;
    let lifetime_fixture = fixture(lifetime_config, true, TENANT).await?;
    lifetime_fixture.identity.set_revalidation_pending();
    let mut lifetime = connect(valid_request(&lifetime_fixture, "Bearer good")?).await?;
    lifetime
        .send(ClientMessage::Text(ping_command().into()))
        .await?;
    assert_close(
        &next_close(&mut lifetime).await?,
        1001,
        "connection lifetime reached",
    );
    assert_eq!(lifetime_fixture.provider.calls(), 0);
    wait_for_cleanup(&lifetime_fixture).await?;
    Ok(())
}

#[tokio::test]
async fn peer_close_is_echoed_before_cleanup_completes() -> TestResult {
    let fixture = fixture(default_config()?, true, TENANT).await?;
    let mut socket = connect(valid_request(&fixture, "Bearer good")?).await?;
    let subscribed = send_json(&mut socket, subscribe_command()).await?;
    assert_eq!(subscribed["type"], "subscription.created");
    assert_eq!(fixture.registry.connection_count()?, 1);
    assert_eq!(fixture.registry.subscription_count()?, 1);
    let requested = ClientCloseFrame {
        code: 4001_u16.into(),
        reason: "client complete".into(),
    };
    socket
        .send(ClientMessage::Close(Some(requested.clone())))
        .await?;
    let echoed = next_close(&mut socket).await?;
    assert_eq!(echoed, requested);
    wait_for_cleanup(&fixture).await?;
    Ok(())
}

#[tokio::test]
async fn abrupt_peer_disconnect_releases_connection_and_lease() -> TestResult {
    let fixture = fixture(default_config()?, true, TENANT).await?;
    let socket = connect(valid_request(&fixture, "Bearer good")?).await?;
    drop(socket);
    wait_for_cleanup(&fixture).await?;
    Ok(())
}
