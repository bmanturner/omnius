//! Real Axum response-body tests for the authenticated SSE transport contract.

use std::{
    convert::Infallible,
    error::Error,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use futures::{StreamExt as _, stream};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationRequest,
    AuthorizationService, Decision, DenyReason, Resource, ResourceKind,
};
use rsk_realtime_core::{
    AuthorizationCommand, CommandAuthorizationResolver, ConnectionRegistry, EventOutput,
    MessageType, ObjectPayload, OutboundMessage, RealtimeService, RegistryConfig,
    ResolvedAuthorization, SUBSCRIBE_ACTION, SubscriptionId, Topic,
};
use rsk_realtime_sse::{
    SseConfig, SseConfigError, SseEventSource, SseMessageStream, SseOpenFuture, SseSourceError,
    SseState, SseSubscription, sse_router,
};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

const SUBJECT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0001);
const TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0011);
const OTHER_TENANT: Uuid = Uuid::from_u128(0x0189_0f2a_0000_7000_8000_0000_0000_0012);
const BODY_LIMIT: usize = 64 * 1024;
const EVENTS_URI: &str =
    "/events?subscription_id=01890f2a-0000-7000-8000-000000000021&topic=orders%2Fprivate";
const EVENTS_CURSOR_URI: &str = "/events?subscription_id=01890f2a-0000-7000-8000-000000000021&topic=orders%2Fprivate&cursor=opaque-123";

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type SourceItems = Vec<Result<OutboundMessage, SseSourceError>>;

fn principal(tenant: Uuid) -> TestResult<Principal> {
    Ok(Principal::new(
        SubjectId::from_uuid(SUBJECT)?,
        PrincipalKind::User,
        Some(TenantId::from_uuid(tenant)?),
        AuthMethod::Session,
        OffsetDateTime::UNIX_EPOCH,
        AssuranceLevel::Aal1,
        Vec::new(),
    )?)
}

#[derive(Clone, Copy)]
enum ProviderMode {
    Allow,
    Deny,
}

#[derive(Clone)]
struct TestProvider {
    mode: ProviderMode,
    calls: Arc<AtomicUsize>,
}

impl TestProvider {
    fn new(mode: ProviderMode) -> Self {
        Self {
            mode,
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
        Ok(match self.mode {
            ProviderMode::Allow => Decision::Allow,
            ProviderMode::Deny => Decision::Deny(DenyReason::NotEntitled),
        })
    }
}

#[derive(Clone)]
struct TestResolver {
    action: Action,
    resource_kind: ResourceKind,
    resource_tenant: TenantId,
    context: AuthorizationContext,
}

impl TestResolver {
    fn new(resource_tenant: TenantId) -> TestResult<Self> {
        Ok(Self {
            action: Action::new(SUBSCRIBE_ACTION)?,
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
    type Error = Infallible;

    fn resolve(
        &self,
        principal: &Principal,
        _command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        Ok(ResolvedAuthorization::new(
            self.action.clone(),
            Resource::new(self.resource_kind.clone())
                .owned_by(principal.subject_id)
                .in_tenant(self.resource_tenant),
            self.context.clone(),
        ))
    }
}

enum SourcePlan {
    Finite(Mutex<Option<SourceItems>>),
    Pending,
    OpenFailure,
}

struct TestSource {
    plan: SourcePlan,
    authorization_calls: Arc<AtomicUsize>,
    opens: AtomicUsize,
    opened_after_authorization: AtomicUsize,
    subscriptions: Mutex<Vec<SseSubscription>>,
}

impl TestSource {
    fn finite(messages: SourceItems, provider: &TestProvider) -> Self {
        Self {
            plan: SourcePlan::Finite(Mutex::new(Some(messages))),
            authorization_calls: Arc::clone(&provider.calls),
            opens: AtomicUsize::new(0),
            opened_after_authorization: AtomicUsize::new(0),
            subscriptions: Mutex::new(Vec::new()),
        }
    }

    fn pending(provider: &TestProvider) -> Self {
        Self {
            plan: SourcePlan::Pending,
            authorization_calls: Arc::clone(&provider.calls),
            opens: AtomicUsize::new(0),
            opened_after_authorization: AtomicUsize::new(0),
            subscriptions: Mutex::new(Vec::new()),
        }
    }

    fn failing(provider: &TestProvider) -> Self {
        Self {
            plan: SourcePlan::OpenFailure,
            authorization_calls: Arc::clone(&provider.calls),
            opens: AtomicUsize::new(0),
            opened_after_authorization: AtomicUsize::new(0),
            subscriptions: Mutex::new(Vec::new()),
        }
    }

    fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }

    fn opened_after_authorization(&self) -> bool {
        self.opened_after_authorization.load(Ordering::SeqCst) == 1
    }

    fn subscriptions(&self) -> Vec<SseSubscription> {
        self.subscriptions
            .lock()
            .map_or_else(|_| Vec::new(), |subscriptions| subscriptions.clone())
    }
}

impl SseEventSource for TestSource {
    fn open(&self, subscription: SseSubscription) -> SseOpenFuture<'_> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        if self.authorization_calls.load(Ordering::SeqCst) > 0 {
            self.opened_after_authorization
                .fetch_add(1, Ordering::SeqCst);
        }
        let recorded = self
            .subscriptions
            .lock()
            .map(|mut subscriptions| subscriptions.push(subscription));
        let result = if recorded.is_err() {
            Err(SseSourceError::Unavailable)
        } else {
            match &self.plan {
                SourcePlan::Finite(messages) => messages
                    .lock()
                    .ok()
                    .and_then(|mut messages| messages.take())
                    .map(|messages| Box::pin(stream::iter(messages)) as SseMessageStream)
                    .ok_or(SseSourceError::Unavailable),
                SourcePlan::Pending => Ok(Box::pin(stream::pending()) as SseMessageStream),
                SourcePlan::OpenFailure => Err(SseSourceError::Unavailable),
            }
        };
        Box::pin(async move { result })
    }
}

struct Fixture {
    app: Router,
    registry: ConnectionRegistry,
    provider: TestProvider,
    source: Arc<TestSource>,
}

fn fixture(
    provider_mode: ProviderMode,
    resource_tenant: Uuid,
    registry_config: RegistryConfig,
    config: SseConfig,
    source: impl FnOnce(&TestProvider) -> TestSource,
) -> TestResult<Fixture> {
    let registry = ConnectionRegistry::new(registry_config);
    let provider = TestProvider::new(provider_mode);
    let source = Arc::new(source(&provider));
    let service = Arc::new(RealtimeService::new(
        registry.clone(),
        AuthorizationService::new(provider.clone()),
        TestResolver::new(TenantId::from_uuid(resource_tenant)?)?,
    ));
    let app = sse_router(SseState::new(service, Arc::clone(&source), config));
    Ok(Fixture {
        app,
        registry,
        provider,
        source,
    })
}

fn request(uri: &str, authenticated: bool) -> TestResult<Request<Body>> {
    let mut request = Request::builder().uri(uri).body(Body::empty())?;
    if authenticated {
        request.extensions_mut().insert(principal(TENANT)?);
    }
    Ok(request)
}

fn event_message() -> TestResult<OutboundMessage> {
    let mut data = Map::new();
    data.insert("status".into(), Value::String("paid".into()));
    Ok(OutboundMessage::Event(EventOutput::new(
        MessageType::new("order.updated")?,
        None,
        SubscriptionId::new(),
        Topic::new("orders/private")?,
        None,
        ObjectPayload::new(data)?,
    )))
}

fn expected_frame(message: OutboundMessage) -> TestResult<String> {
    let envelope = message.into_envelope()?;
    let encoded = String::from_utf8(envelope.encode()?)?;
    Ok(format!(
        "event: {}\ndata: {encoded}\n\n",
        envelope.message_type().as_str()
    ))
}

async fn problem_code(response: axum::response::Response) -> TestResult<(StatusCode, String)> {
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if content_type != "application/problem+json" {
        return Err(format!("unexpected problem content type: {content_type}").into());
    }
    let body: Value = serde_json::from_slice(&to_bytes(response.into_body(), BODY_LIMIT).await?)?;
    let code = body
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok((status, code))
}

#[test]
fn config_rejects_zero_heartbeat_interval() {
    assert_eq!(
        SseConfig::new(Duration::ZERO, None),
        Err(SseConfigError::InvalidHeartbeatInterval)
    );
}

#[test]
fn config_rejects_excessively_frequent_retry_interval() {
    assert_eq!(
        SseConfig::new(Duration::from_secs(15), Some(Duration::from_millis(1))),
        Err(SseConfigError::InvalidRetryInterval)
    );
}

#[tokio::test]
async fn response_has_exact_headers_named_data_frame_and_no_replay_id() -> TestResult {
    let message = event_message()?;
    let expected = expected_frame(message.clone())?;
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        |provider| TestSource::finite(vec![Ok(message)], provider),
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = String::from_utf8(to_bytes(response.into_body(), BODY_LIMIT).await?.to_vec())?;
    let has_event_id = body.lines().any(|line| line.starts_with("id:"));
    assert_eq!(
        (
            status,
            headers
                .get(CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            headers
                .get("x-accel-buffering")
                .and_then(|value| value.to_str().ok()),
            headers.contains_key("connection"),
            body,
            has_event_id,
        ),
        (
            StatusCode::OK,
            Some("text/event-stream"),
            Some("no-store, no-transform"),
            Some("no"),
            false,
            expected,
            false,
        )
    );
    Ok(())
}

#[tokio::test]
async fn retry_directive_is_framed_without_claiming_an_event_id() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::new(Duration::from_secs(15), Some(Duration::from_millis(2_500)))?,
        |provider| TestSource::finite(Vec::new(), provider),
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;
    let body = to_bytes(response.into_body(), BODY_LIMIT).await?;

    assert_eq!(body.as_ref(), b"retry: 2500\n\n");
    Ok(())
}

#[tokio::test]
async fn pending_source_emits_heartbeat_comment_and_disconnect_cleans_registry() -> TestResult {
    let config = SseConfig::new(Duration::from_secs(1), None)?;
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        config,
        TestSource::pending,
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;
    let mut body = response.into_body().into_data_stream();
    let chunk = tokio::time::timeout(Duration::from_secs(2), body.next())
        .await?
        .ok_or("heartbeat stream ended")??;
    assert_eq!(chunk.as_ref(), b": heartbeat\n\n");
    drop(body);
    assert_eq!(
        (
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn last_event_id_is_rejected_without_opening_or_registering() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        TestSource::pending,
    )?;
    let mut replay_request = request(EVENTS_URI, true)?;
    replay_request
        .headers_mut()
        .insert("last-event-id", "resume-me".parse()?);
    let response = fixture.app.clone().oneshot(replay_request).await?;

    assert_eq!(
        (
            problem_code(response).await?,
            fixture.source.opens(),
            fixture.provider.calls(),
            fixture.registry.connection_count()?,
        ),
        (
            (StatusCode::CONFLICT, "SSE_REPLAY_UNAVAILABLE".into()),
            0,
            0,
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn authentication_precedes_replay_header_validation() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        TestSource::pending,
    )?;
    let mut unauthenticated_replay = request(EVENTS_URI, false)?;
    unauthenticated_replay
        .headers_mut()
        .insert("last-event-id", "resume-me".parse()?);
    let response = fixture.app.clone().oneshot(unauthenticated_replay).await?;

    assert_eq!(
        (problem_code(response).await?, fixture.source.opens()),
        (
            (
                StatusCode::UNAUTHORIZED,
                "SSE_AUTHENTICATION_REQUIRED".into(),
            ),
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn authorization_denial_never_opens_source_or_retains_state() -> TestResult {
    let fixture = fixture(
        ProviderMode::Deny,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        TestSource::pending,
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;

    assert_eq!(
        (
            problem_code(response).await?,
            fixture.provider.calls(),
            fixture.source.opens(),
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (
            (StatusCode::FORBIDDEN, "SSE_SUBSCRIPTION_FORBIDDEN".into(),),
            1,
            0,
            0,
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn source_opens_only_after_authorization_and_stream_end_cleans_state() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        |provider| TestSource::finite(Vec::new(), provider),
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_CURSOR_URI, true)?)
        .await?;
    let status = response.status();
    let _ = to_bytes(response.into_body(), BODY_LIMIT).await?;
    let subscriptions = fixture.source.subscriptions();
    let subscription_id = subscriptions
        .first()
        .map(|subscription| subscription.subscription().id().to_string());
    let cursor = subscriptions
        .first()
        .and_then(|subscription| subscription.subscription().cursor())
        .map(|cursor| cursor.as_str().to_owned());

    assert_eq!(
        (
            status,
            fixture.provider.calls(),
            fixture.source.opens(),
            fixture.source.opened_after_authorization(),
            cursor,
            subscription_id,
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (
            StatusCode::OK,
            1,
            1,
            true,
            Some("opaque-123".into()),
            Some("01890f2a-0000-7000-8000-000000000021".into()),
            0,
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn source_open_failure_is_redacted_problem_and_cleans_state() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        TestSource::failing,
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;

    assert_eq!(
        (
            problem_code(response).await?,
            fixture.source.opens(),
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (
            (StatusCode::SERVICE_UNAVAILABLE, "SSE_UNAVAILABLE".into()),
            1,
            0,
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn source_stream_failure_terminates_without_detail_and_cleans_state() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        |provider| TestSource::finite(vec![Err(SseSourceError::Unavailable)], provider),
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;
    let status = response.status();
    let body_result = to_bytes(response.into_body(), BODY_LIMIT).await;

    assert_eq!(
        (
            status,
            body_result.is_err(),
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (StatusCode::OK, true, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn connection_capacity_failure_is_problem_and_never_opens_source() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        TENANT,
        RegistryConfig::new(1, 2, 1)?,
        SseConfig::default(),
        TestSource::pending,
    )?;
    let _occupied = fixture.registry.register(principal(TENANT)?)?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;

    assert_eq!(
        (
            problem_code(response).await?,
            fixture.source.opens(),
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (
            (StatusCode::SERVICE_UNAVAILABLE, "SSE_UNAVAILABLE".into()),
            0,
            1,
            0,
        )
    );
    Ok(())
}

#[tokio::test]
async fn cross_tenant_subscription_is_denied_without_source_or_subscription() -> TestResult {
    let fixture = fixture(
        ProviderMode::Allow,
        OTHER_TENANT,
        RegistryConfig::new(4, 8, 2)?,
        SseConfig::default(),
        TestSource::pending,
    )?;
    let response = fixture
        .app
        .clone()
        .oneshot(request(EVENTS_URI, true)?)
        .await?;

    assert_eq!(
        (
            problem_code(response).await?,
            fixture.provider.calls(),
            fixture.source.opens(),
            fixture.registry.connection_count()?,
            fixture.registry.subscription_count()?,
        ),
        (
            (StatusCode::FORBIDDEN, "SSE_SUBSCRIPTION_FORBIDDEN".into(),),
            1,
            0,
            0,
            0,
        )
    );
    Ok(())
}
