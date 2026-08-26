//! Executable transport-boundary tests for the checked-in gRPC foundation contract.

use std::{
    error::Error as StdError,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures::{StreamExt as _, stream};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId};
use rsk_authz_basic::{Action, AuthorizationContext, Decision, Resource, ResourceKind};
use rsk_core::{ErrorCode, RequestId, ServiceError};
use rsk_grpc::{
    ApplicationAuthorizer, ApplicationCall, ApplicationReply, ApplicationService, Authenticator,
    FOUNDATION_SERVICE_NAME, GrpcConfig, MethodPolicy, REQUEST_ID_METADATA, ServerComposition,
    ServerPolicies, StreamSendError, StreamSender,
    pb::{ExecuteRequest, StreamRequest, foundation_client::FoundationClient},
    service_error_status,
};
use time::OffsetDateTime;
use tokio::sync::Notify;
use tonic::{Code, Request, codec::CompressionEncoding, metadata::MetadataMap};
use tonic_health::pb::{
    HealthCheckRequest, health_check_response::ServingStatus, health_client::HealthClient,
};
use tonic_reflection::pb::v1::{
    ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
    server_reflection_request::MessageRequest,
};
use tonic_types::StatusExt as _;
use tower::ServiceExt as _;

const AUTHORIZATION: &str = "authorization";
const VALID_BEARER: &str = "Bearer test-credential";

type TestResult = Result<(), Box<dyn StdError>>;

#[derive(Clone)]
struct TokenAuthenticator {
    principal: Principal,
}

impl Authenticator for TokenAuthenticator {
    type Error = ();

    fn authenticate(&self, metadata: &MetadataMap) -> Result<Principal, Self::Error> {
        let value = metadata
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if value == Some(VALID_BEARER) {
            Ok(self.principal.clone())
        } else {
            Err(())
        }
    }
}

#[derive(Clone, Copy)]
struct AllowAuthorizer;

impl ApplicationAuthorizer for AllowAuthorizer {
    fn authorize(
        &self,
        _principal: &Principal,
        _action: &Action,
        _resource: &Resource,
        _context: &AuthorizationContext,
    ) -> Decision {
        Decision::Allow
    }
}

#[derive(Clone, Copy)]
struct DenyAuthorizer;

impl ApplicationAuthorizer for DenyAuthorizer {
    fn authorize(
        &self,
        _principal: &Principal,
        _action: &Action,
        _resource: &Resource,
        _context: &AuthorizationContext,
    ) -> Decision {
        Decision::Deny(rsk_authz_basic::DenyReason::NotEntitled)
    }
}

struct EchoApplication;

#[tonic::async_trait]
impl ApplicationService for EchoApplication {
    async fn execute(&self, call: ApplicationCall) -> Result<ApplicationReply, ServiceError> {
        Ok(ApplicationReply::new(call.into_payload()))
    }

    async fn stream(
        &self,
        call: ApplicationCall,
        sender: StreamSender,
    ) -> Result<(), ServiceError> {
        let _ = sender.send(call.into_payload()).await;
        Ok(())
    }
}

fn principal() -> Result<Principal, rsk_auth_core::PrincipalError> {
    Principal::new(
        SubjectId::new(),
        PrincipalKind::User,
        None,
        AuthMethod::ApiKey,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal1,
        Vec::new(),
    )
}

fn policies() -> Result<ServerPolicies, rsk_authz_basic::IdentifierError> {
    let resource = Resource::new(ResourceKind::new("grpc.foundation")?);
    let execute = MethodPolicy::new(
        Action::new("grpc.execute")?,
        resource.clone(),
        AuthorizationContext::default(),
    );
    let stream = MethodPolicy::new(
        Action::new("grpc.stream")?,
        resource.clone(),
        AuthorizationContext::default(),
    );
    let reflection = MethodPolicy::new(
        Action::new("grpc.reflect")?,
        resource,
        AuthorizationContext::default(),
    );
    Ok(ServerPolicies::new(execute, stream, reflection))
}

fn composition<S, Z>(
    config: GrpcConfig,
    application: S,
    authorizer: Z,
) -> Result<ServerComposition, Box<dyn StdError>>
where
    S: ApplicationService,
    Z: ApplicationAuthorizer,
{
    Ok(ServerComposition::build(
        config,
        application,
        TokenAuthenticator {
            principal: principal()?,
        },
        authorizer,
        policies()?,
    )?)
}

fn authorized<T>(message: T) -> Result<Request<T>, tonic::metadata::errors::InvalidMetadataValue> {
    let mut request = Request::new(message);
    request
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    request.set_timeout(Duration::from_secs(1));
    Ok(request)
}

#[tokio::test]
async fn deadlines_are_required_and_cannot_exceed_the_server_maximum() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, AllowAuthorizer)?;
    let mut client = FoundationClient::new(composition.public_routes());

    let mut missing = Request::new(ExecuteRequest {
        payload: Bytes::new(),
    });
    missing
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    let missing = client.execute(missing).await;
    let Err(missing) = missing else {
        return Err("request without deadline was accepted".into());
    };
    assert_eq!(missing.code(), Code::InvalidArgument);
    assert_eq!(missing.message(), "gRPC deadline is required");

    let mut overlong = Request::new(ExecuteRequest {
        payload: Bytes::new(),
    });
    overlong
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    overlong.set_timeout(Duration::from_secs(31));
    let overlong = client.execute(overlong).await;
    let Err(overlong) = overlong else {
        return Err("overlong deadline was accepted".into());
    };
    assert_eq!(overlong.code(), Code::InvalidArgument);
    assert_eq!(overlong.message(), "gRPC deadline exceeds server maximum");
    Ok(())
}

#[tokio::test]
async fn authentication_and_application_authorization_fail_closed() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, DenyAuthorizer)?;
    let mut client = FoundationClient::new(composition.public_routes());

    let mut unauthenticated = Request::new(ExecuteRequest {
        payload: Bytes::new(),
    });
    unauthenticated.set_timeout(Duration::from_secs(1));
    let unauthenticated = client.execute(unauthenticated).await;
    let Err(unauthenticated) = unauthenticated else {
        return Err("unauthenticated request was accepted".into());
    };
    assert_eq!(unauthenticated.code(), Code::Unauthenticated);

    let denied = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::new(),
        })?)
        .await;
    let Err(denied) = denied else {
        return Err("authorization denial was ignored".into());
    };
    assert_eq!(denied.code(), Code::PermissionDenied);
    Ok(())
}

#[tokio::test]
async fn request_ids_are_generated_or_propagated_on_responses() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, AllowAuthorizer)?;
    let mut client = FoundationClient::new(composition.public_routes());

    let generated = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::new(),
        })?)
        .await?;
    let generated = generated
        .metadata()
        .get(REQUEST_ID_METADATA)
        .ok_or("missing generated request ID")?
        .to_str()?
        .parse::<RequestId>()?;
    assert!(generated.is_v7());

    let inbound = RequestId::new();
    let mut request = authorized(ExecuteRequest {
        payload: Bytes::new(),
    })?;
    request
        .metadata_mut()
        .insert(REQUEST_ID_METADATA, inbound.to_string().parse()?);
    let propagated = client.execute(request).await?;
    assert_eq!(
        propagated
            .metadata()
            .get(REQUEST_ID_METADATA)
            .ok_or("missing propagated request ID")?
            .to_str()?,
        inbound.to_string()
    );
    Ok(())
}

#[tokio::test]
async fn standard_health_service_is_composed_on_the_public_surface() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, AllowAuthorizer)?;
    let mut health = HealthClient::new(composition.public_routes());
    let mut request = Request::new(HealthCheckRequest {
        service: String::new(),
    });
    request.set_timeout(Duration::from_secs(1));
    let response = health.check(request).await?.into_inner();
    assert_eq!(response.status, ServingStatus::Serving as i32);

    let mut watch_request = Request::new(HealthCheckRequest {
        service: String::new(),
    });
    watch_request.set_timeout(Duration::from_secs(1));
    let watch = health.watch(watch_request).await;
    let Err(watch) = watch else {
        return Err("unbounded health Watch was exposed".into());
    };
    assert_eq!(watch.code(), Code::Unimplemented);
    Ok(())
}

#[tokio::test]
async fn decoded_encoded_and_decompressed_message_limits_are_enforced() -> TestResult {
    let config = GrpcConfig {
        max_encoded_message_bytes: 32,
        max_decoded_payload_bytes: 64,
        max_decompressed_message_bytes: 80,
        ..GrpcConfig::default()
    };
    let composition = composition(config, EchoApplication, AllowAuthorizer)?;
    let mut client = FoundationClient::new(composition.public_routes());

    let decoded = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::from(vec![0; 65]),
        })?)
        .await;
    let Err(decoded) = decoded else {
        return Err("oversized decoded payload was accepted".into());
    };
    assert_eq!(decoded.code(), Code::ResourceExhausted);

    let encoded = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::from(vec![0; 20]),
        })?)
        .await;
    let Err(encoded) = encoded else {
        return Err("oversized encoded response was accepted".into());
    };
    assert_eq!(encoded.code(), Code::ResourceExhausted);

    let mut compressed_client = FoundationClient::new(composition.public_routes())
        .send_compressed(CompressionEncoding::Gzip);
    let decompressed = compressed_client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::from(vec![0; 128]),
        })?)
        .await;
    let Err(decompressed) = decompressed else {
        return Err("decompression limit was not enforced".into());
    };
    assert!(matches!(
        decompressed.code(),
        Code::ResourceExhausted | Code::OutOfRange
    ));
    Ok(())
}

#[tokio::test]
async fn incompressible_response_at_the_uncompressed_boundary_succeeds() -> TestResult {
    let config = GrpcConfig {
        max_encoded_message_bytes: 1_024,
        max_decoded_payload_bytes: 1_008,
        max_decompressed_message_bytes: 1_024,
        ..GrpcConfig::default()
    };
    let composition = composition(config, EchoApplication, AllowAuthorizer)?;
    let mut state = 0x9E37_79B9_u32;
    let payload = (0..1_008)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect::<Vec<_>>();
    let mut client = FoundationClient::new(composition.public_routes())
        .accept_compressed(CompressionEncoding::Gzip);
    let response = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::from(payload.clone()),
        })?)
        .await?
        .into_inner();
    assert_eq!(response.payload, Bytes::from(payload));
    Ok(())
}

#[derive(Debug)]
struct SensitiveCause;

impl fmt::Display for SensitiveCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("database password=transport-secret")
    }
}

impl StdError for SensitiveCause {}

struct FailingApplication;

#[tonic::async_trait]
impl ApplicationService for FailingApplication {
    async fn execute(&self, _call: ApplicationCall) -> Result<ApplicationReply, ServiceError> {
        let Ok(code) = ErrorCode::try_new("DATABASE_FAILURE") else {
            unreachable!("static test error code is valid");
        };
        Err(ServiceError::new(code, "service unavailable").with_source(SensitiveCause))
    }

    async fn stream(
        &self,
        _call: ApplicationCall,
        _sender: StreamSender,
    ) -> Result<(), ServiceError> {
        Ok(())
    }
}

#[tokio::test]
async fn status_mapping_exposes_only_bounded_safe_error_info() -> TestResult {
    let composition = composition(GrpcConfig::default(), FailingApplication, AllowAuthorizer)?;
    let mut client = FoundationClient::new(composition.public_routes());
    let failure = client
        .execute(authorized(ExecuteRequest {
            payload: Bytes::new(),
        })?)
        .await;
    let Err(failure) = failure else {
        return Err("failing application returned success".into());
    };

    assert_eq!(failure.code(), Code::Internal);
    assert_eq!(failure.message(), "service unavailable");
    assert!(!format!("{failure:?}").contains("transport-secret"));
    let info = failure
        .get_details_error_info()
        .ok_or("missing ErrorInfo detail")?;
    assert_eq!(info.reason, "DATABASE_FAILURE");
    assert_eq!(info.domain, "rust-service-kit.grpc");
    assert_eq!(info.metadata.len(), 1);
    assert!(info.metadata.contains_key("request_id"));

    let code = ErrorCode::try_new("DATABASE_FAILURE")?;
    let oversized = ServiceError::new(code, "x".repeat(257));
    let bounded = service_error_status(&oversized, RequestId::new());
    assert_eq!(bounded.message(), "request failed");
    assert!(bounded.details().len() <= 512);
    Ok(())
}

#[derive(Default)]
struct StreamState {
    outcomes: Mutex<Option<Vec<Result<(), StreamSendError>>>>,
    sent: Notify,
    cancelled: Notify,
    cancellation_observed: AtomicBool,
}

struct CapacityApplication {
    state: Arc<StreamState>,
}

#[tonic::async_trait]
impl ApplicationService for CapacityApplication {
    async fn execute(&self, call: ApplicationCall) -> Result<ApplicationReply, ServiceError> {
        Ok(ApplicationReply::new(call.into_payload()))
    }

    async fn stream(
        &self,
        _call: ApplicationCall,
        sender: StreamSender,
    ) -> Result<(), ServiceError> {
        let outcomes = vec![
            sender.try_send(Bytes::from_static(b"one")),
            sender.try_send(Bytes::from_static(b"two")),
            sender.try_send(Bytes::from_static(b"three")),
        ];
        match self.state.outcomes.lock() {
            Ok(mut slot) => *slot = Some(outcomes),
            Err(poisoned) => *poisoned.into_inner() = Some(outcomes),
        }
        self.state.sent.notify_one();
        sender.cancelled().await;
        self.state
            .cancellation_observed
            .store(true, Ordering::Release);
        self.state.cancelled.notify_one();
        Ok(())
    }
}

#[tokio::test]
async fn streaming_applies_channel_and_concurrency_backpressure_and_cancellation() -> TestResult {
    let state = Arc::new(StreamState::default());
    let config = GrpcConfig {
        stream_capacity: 2,
        max_concurrent_streams: 1,
        ..GrpcConfig::default()
    };
    let composition = composition(
        config,
        CapacityApplication {
            state: Arc::clone(&state),
        },
        AllowAuthorizer,
    )?;
    let mut first_client = FoundationClient::new(composition.public_routes());
    let first = first_client
        .stream(authorized(StreamRequest {
            payload: Bytes::new(),
        })?)
        .await?
        .into_inner();
    tokio::time::timeout(Duration::from_secs(1), state.sent.notified()).await?;
    let outcomes = match state.outcomes.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    }
    .ok_or("stream producer did not record channel outcomes")?;
    assert_eq!(outcomes, vec![Ok(()), Ok(()), Err(StreamSendError::Full)]);

    let mut second_client = FoundationClient::new(composition.public_routes());
    let second = second_client
        .stream(authorized(StreamRequest {
            payload: Bytes::new(),
        })?)
        .await;
    let Err(second) = second else {
        return Err("concurrent stream capacity was not enforced".into());
    };
    assert_eq!(second.code(), Code::ResourceExhausted);

    drop(first);
    tokio::time::timeout(Duration::from_secs(1), state.cancelled.notified()).await?;
    assert!(state.cancellation_observed.load(Ordering::Acquire));

    let third = second_client
        .stream(authorized(StreamRequest {
            payload: Bytes::new(),
        })?)
        .await?;
    drop(third);
    Ok(())
}

#[tokio::test]
async fn reflection_is_absent_publicly_and_authorized_on_the_protected_surface() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, DenyAuthorizer)?;
    let request = tonic::codegen::http::Request::builder()
        .uri("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo")
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::empty())?;
    let response = composition.public_routes().oneshot(request).await?;
    assert_eq!(
        response.headers().get(tonic::Status::GRPC_STATUS),
        Some(&tonic::codegen::http::HeaderValue::from_static("12"))
    );

    let mut reflection = ServerReflectionClient::new(composition.protected_routes());
    let messages = stream::iter([ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    }]);
    let mut request = Request::new(messages);
    request
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    request.set_timeout(Duration::from_secs(1));
    let denied = reflection.server_reflection_info(request).await;
    let Err(denied) = denied else {
        return Err("reflection authorization denial was ignored".into());
    };
    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(FOUNDATION_SERVICE_NAME, "rsk.grpc.v1.Foundation");
    Ok(())
}

#[tokio::test]
async fn protected_reflection_stream_terminates_at_the_absolute_deadline() -> TestResult {
    let composition = composition(GrpcConfig::default(), EchoApplication, AllowAuthorizer)?;
    let mut reflection = ServerReflectionClient::new(composition.protected_routes());
    let message = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let messages =
        stream::once(async move { message }).chain(stream::pending::<ServerReflectionRequest>());
    let mut request = Request::new(messages);
    request
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    request.set_timeout(Duration::from_millis(100));
    let mut response = reflection
        .server_reflection_info(request)
        .await?
        .into_inner();
    let first = response.message().await?;
    assert!(first.is_some());
    tokio::time::sleep(Duration::from_millis(120)).await;
    let expired = response.message().await;
    let Err(expired) = expired else {
        return Err("reflection stream outlived its absolute deadline".into());
    };
    assert_eq!(expired.code(), Code::DeadlineExceeded);
    Ok(())
}
