//! Integration contracts for the bounded `GraphQL` HTTP transport.

use std::{
    collections::HashMap,
    convert::Infallible,
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_graphql::{
    Context, EmptyMutation, ErrorExtensions as _, Object, Request as GraphqlRequest, SimpleObject,
    dataloader::DataLoader,
};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header::CONTENT_TYPE},
};
use rsk_auth_core::{AssuranceLevel, AuthMethod, Principal, PrincipalKind, SubjectId, TenantId};
use rsk_authz_basic::{
    Action, AuthorizationContext, AuthorizationProvider, AuthorizationRequest,
    AuthorizationService, Decision, DenyReason, Resource, ResourceKind,
};
use rsk_core::RequestId;
use rsk_graphql::{
    ApplicationQueryService, AuthorizedBatchLoader, BoundedList, GraphqlBuildError, GraphqlConfig,
    GraphqlRequestContext, IntrospectionPolicy, PersistedOperationPolicy, QueryObject,
    RuntimeEnvironment, graphql_router, operation_hash,
};
use serde_json::{Value as JsonValue, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

#[derive(Clone, Debug, SimpleObject)]
struct TestObject {
    id: String,
    label: String,
}

#[derive(Clone)]
struct TestService {
    rows: Arc<HashMap<String, QueryObject<TestObject>>>,
    calls: Arc<AtomicUsize>,
}

impl ApplicationQueryService<String> for TestService {
    type Value = TestObject;
    type Error = Infallible;

    async fn load(
        &self,
        _context: &GraphqlRequestContext,
        keys: &[String],
    ) -> Result<HashMap<String, QueryObject<Self::Value>>, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let matching_rows = keys
            .iter()
            .filter_map(|key| {
                self.rows
                    .get(key)
                    .cloned()
                    .map(|value| (key.clone(), value))
            })
            .collect();
        std::future::ready(Ok(matching_rows)).await
    }
}

#[derive(Clone)]
struct ObjectPolicy;

impl AuthorizationProvider for ObjectPolicy {
    type Error = Infallible;

    fn evaluate(&self, request: AuthorizationRequest<'_>) -> Result<Decision, Self::Error> {
        let same_owner = request.resource.owner_id == Some(request.principal.subject_id);
        let same_tenant = request.resource.tenant_id == request.principal.tenant_id;
        let active_membership = request
            .resource
            .tenant_id
            .is_some_and(|tenant_id| request.context.tenant_memberships().contains(&tenant_id));
        Ok(if same_owner && same_tenant && active_membership {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::NotEntitled)
        })
    }
}

struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn health(&self) -> bool {
        true
    }

    async fn branch(&self) -> Branch {
        Branch
    }

    async fn objects(
        &self,
        context: &Context<'_>,
        ids: Vec<String>,
    ) -> async_graphql::Result<BoundedList<TestObject>> {
        let request_context = context.data::<Arc<GraphqlRequestContext>>()?;
        let object_loader =
            context.data::<DataLoader<AuthorizedBatchLoader<TestService, ObjectPolicy>>>()?;
        let authorized_objects = object_loader
            .load_many(ids.clone())
            .await
            .map_err(|error| async_graphql::Error::new(error.to_string()))?;
        BoundedList::try_collect(
            ids.into_iter()
                .filter_map(|id| authorized_objects.get(&id).cloned()),
            request_context.batch_item_limit(),
        )
        .map_err(|error| error.extend())
    }

    async fn oversized(&self, context: &Context<'_>) -> async_graphql::Result<BoundedList<i32>> {
        let request_context = context.data::<Arc<GraphqlRequestContext>>()?;
        let bounded = BoundedList::try_collect(1..=3, request_context.batch_item_limit())
            .map_err(|error| error.extend());
        std::future::ready(bounded).await
    }

    async fn payload(&self, bytes: i32) -> async_graphql::Result<String> {
        let bytes = usize::try_from(bytes)
            .map_err(|_| async_graphql::Error::new("invalid payload size"))?;
        if bytes > rsk_graphql::MAX_RESPONSE_BYTES {
            return Err(async_graphql::Error::new("invalid payload size"));
        }
        std::future::ready(Ok("x".repeat(bytes))).await
    }

    async fn internal_failure(&self) -> async_graphql::Result<bool> {
        std::future::ready(Err(async_graphql::Error::new(
            "database password secret must never cross the transport",
        )))
        .await
    }

    async fn wait_for_deadline(&self, context: &Context<'_>) -> async_graphql::Result<bool> {
        let request_context = context.data::<Arc<GraphqlRequestContext>>()?;
        request_context.cancellation_token().cancelled().await;
        Ok(true)
    }
}

struct Branch;

#[Object]
impl Branch {
    async fn child(&self) -> Leaf {
        Leaf
    }
}

struct Leaf;

#[Object]
impl Leaf {
    async fn value(&self) -> i32 {
        7
    }
}

struct Fixture {
    router: Router,
    principal: Principal,
    authorization_context: AuthorizationContext,
    request_id: RequestId,
    calls: Arc<AtomicUsize>,
}

fn fixture(config: GraphqlConfig) -> Result<Fixture, Box<dyn Error + Send + Sync>> {
    let subject_id = SubjectId::new();
    let other_subject_id = SubjectId::new();
    let tenant_id = TenantId::new();
    let principal = Principal::new(
        subject_id,
        PrincipalKind::User,
        Some(tenant_id),
        AuthMethod::Session,
        OffsetDateTime::now_utc(),
        AssuranceLevel::Aal1,
        Vec::new(),
    )?;
    let authorization_context =
        AuthorizationContext::new(Vec::new(), vec![tenant_id], Vec::new(), Vec::new())?;
    let resource_kind = ResourceKind::new("test_object")?;
    let rows = HashMap::from([
        (
            "owned".to_owned(),
            QueryObject::new(
                Resource::new(resource_kind.clone())
                    .owned_by(subject_id)
                    .in_tenant(tenant_id),
                TestObject {
                    id: "owned".to_owned(),
                    label: "visible".to_owned(),
                },
            ),
        ),
        (
            "other".to_owned(),
            QueryObject::new(
                Resource::new(resource_kind)
                    .owned_by(other_subject_id)
                    .in_tenant(tenant_id),
                TestObject {
                    id: "other".to_owned(),
                    label: "must-not-leak".to_owned(),
                },
            ),
        ),
    ]);
    let calls = Arc::new(AtomicUsize::new(0));
    let service = Arc::new(TestService {
        rows: Arc::new(rows),
        calls: Arc::clone(&calls),
    });
    let authorizer = Arc::new(AuthorizationService::new(ObjectPolicy));
    let action = Action::new("objects.read")?;
    let router = graphql_router(
        QueryRoot,
        EmptyMutation,
        config,
        move |request: GraphqlRequest, request_context: Arc<GraphqlRequestContext>| {
            let batch_item_limit = request_context.batch_item_limit();
            let loader = AuthorizedBatchLoader::new(
                Arc::clone(&service),
                Arc::clone(&authorizer),
                action.clone(),
                request_context,
                batch_item_limit,
            )
            .into_data_loader();
            request.data(loader)
        },
    )?;
    Ok(Fixture {
        router,
        principal,
        authorization_context,
        request_id: RequestId::new(),
        calls,
    })
}

async fn post(
    fixture: &Fixture,
    body: JsonValue,
) -> Result<(StatusCode, JsonValue), Box<dyn Error + Send + Sync>> {
    post_bytes(fixture, serde_json::to_vec(&body)?).await
}

async fn post_bytes(
    fixture: &Fixture,
    body: Vec<u8>,
) -> Result<(StatusCode, JsonValue), Box<dyn Error + Send + Sync>> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/graphql")
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;
    request.extensions_mut().insert(fixture.principal.clone());
    request
        .extensions_mut()
        .insert(fixture.authorization_context.clone());
    request.extensions_mut().insert(fixture.request_id);
    let response = fixture.router.clone().oneshot(request).await?;
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await?;
    let body = serde_json::from_slice(&bytes)?;
    Ok((status, body))
}

fn error_code(body: &JsonValue) -> Option<&str> {
    body.pointer("/errors/0/extensions/code")
        .and_then(JsonValue::as_str)
}

#[tokio::test]
async fn depth_limit_rejects_nested_operation() -> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig {
        max_depth: 2,
        ..GraphqlConfig::default()
    })?;
    let (status, body) = post(&fixture, json!({"query": "{ branch { child { value } } }"})).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(error_code(&body), Some("GRAPHQL_REQUEST_FAILED"));
    Ok(())
}

#[tokio::test]
async fn complexity_limit_rejects_repeated_fields() -> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig {
        max_complexity: 1,
        ..GraphqlConfig::default()
    })?;
    let (status, body) = post(
        &fixture,
        json!({"query": "{ first: health second: health }"}),
    )
    .await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(error_code(&body), Some("GRAPHQL_REQUEST_FAILED"));
    Ok(())
}

#[tokio::test]
async fn list_limit_rejects_inline_inputs_and_oversized_outputs()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig {
        max_list_items: 2,
        ..GraphqlConfig::default()
    })?;
    let (_, input_body) = post(
        &fixture,
        json!({"query": "{ objects(ids: [\"owned\", \"other\", \"third\"]) { id } }"}),
    )
    .await?;
    assert_eq!(error_code(&input_body), Some("LIST_LIMIT_EXCEEDED"));

    let (_, output_body) = post(&fixture, json!({"query": "{ oversized }"})).await?;
    assert_eq!(error_code(&output_body), Some("LIST_LIMIT_EXCEEDED"));
    Ok(())
}

#[tokio::test]
async fn response_limit_rejects_huge_scalar_without_partial_output()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig {
        max_response_bytes: 512,
        ..GraphqlConfig::default()
    })?;
    let (_, body) = post(&fixture, json!({"query": "{ payload(bytes: 4096) }"})).await?;
    assert_eq!(error_code(&body), Some("GRAPHQL_RESPONSE_TOO_LARGE"));
    let serialized = body.to_string();
    let partial_payload = "x".repeat(64);
    assert!(!serialized.contains(partial_payload.as_str()));
    Ok(())
}

#[tokio::test]
async fn response_limit_accepts_exact_boundary_and_rejects_aggregate()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let payload = "x".repeat(300);
    let boundary_size = serde_json::to_vec(&json!({"data": {"payload": payload}}))?.len();
    let boundary_fixture = fixture(GraphqlConfig {
        max_response_bytes: boundary_size,
        ..GraphqlConfig::default()
    })?;
    let (_, boundary_body) = post(
        &boundary_fixture,
        json!({"query": "{ payload(bytes: 300) }"}),
    )
    .await?;
    assert_eq!(
        boundary_body
            .pointer("/data/payload")
            .and_then(JsonValue::as_str),
        Some(payload.as_str())
    );

    let aggregate_fixture = fixture(GraphqlConfig {
        max_response_bytes: 256,
        ..GraphqlConfig::default()
    })?;
    let (_, aggregate_body) = post(
        &aggregate_fixture,
        json!({"query": "{ first: payload(bytes: 120) second: payload(bytes: 120) }"}),
    )
    .await?;
    assert_eq!(
        error_code(&aggregate_body),
        Some("GRAPHQL_RESPONSE_TOO_LARGE")
    );
    Ok(())
}

#[tokio::test]
async fn response_finalization_fails_closed_after_deadline()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig {
        max_response_bytes: 3 * 1024 * 1024,
        execution_timeout: Duration::from_nanos(1),
        ..GraphqlConfig::default()
    })?;
    let (_, body) = post(&fixture, json!({"query": "{ payload(bytes: 2000000) }"})).await?;
    assert_eq!(error_code(&body), Some("REQUEST_TIMEOUT"));
    Ok(())
}

#[tokio::test]
async fn persisted_allowlist_requires_and_resolves_known_hash()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let operation = "query Health { health }";
    let fixture = fixture(GraphqlConfig {
        persisted_operations: PersistedOperationPolicy::allowlist([operation])?,
        ..GraphqlConfig::default()
    })?;
    let (_, rejected) = post(&fixture, json!({"query": "{ health }"})).await?;
    assert_eq!(error_code(&rejected), Some("PERSISTED_OPERATION_REQUIRED"));
    let (_, unknown) = post(
        &fixture,
        json!({
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": "0".repeat(64)}
            }
        }),
    )
    .await?;
    assert_eq!(
        error_code(&unknown),
        Some("PERSISTED_OPERATION_NOT_ALLOWED")
    );

    let hash = operation_hash(operation);
    let (_, accepted) = post(
        &fixture,
        json!({
            "operationName": "Health",
            "variables": {},
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": hash}
            }
        }),
    )
    .await?;
    assert_eq!(
        accepted.pointer("/data/health"),
        Some(&JsonValue::Bool(true))
    );
    Ok(())
}

#[tokio::test]
async fn introspection_is_denied_and_cannot_be_enabled_in_production()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig::default())?;
    let (_, body) = post(
        &fixture,
        json!({"query": "{ __schema { queryType { name } } }"}),
    )
    .await?;
    assert_eq!(error_code(&body), Some("GRAPHQL_REQUEST_FAILED"));

    let result = rsk_graphql::GraphqlTransport::new(
        QueryRoot,
        EmptyMutation,
        GraphqlConfig {
            environment: RuntimeEnvironment::Production,
            introspection: IntrospectionPolicy::Enabled,
            ..GraphqlConfig::default()
        },
        |request: GraphqlRequest, _: Arc<GraphqlRequestContext>| request,
    );
    assert!(matches!(
        result,
        Err(GraphqlBuildError::ProductionIntrospection)
    ));
    let recursion_result = rsk_graphql::GraphqlTransport::new(
        QueryRoot,
        EmptyMutation,
        GraphqlConfig {
            max_recursive_depth: 65,
            ..GraphqlConfig::default()
        },
        |request: GraphqlRequest, _: Arc<GraphqlRequestContext>| request,
    );
    assert!(matches!(
        recursion_result,
        Err(GraphqlBuildError::LimitTooLarge("max_recursive_depth"))
    ));
    Ok(())
}

#[tokio::test]
async fn dataloader_authorizes_every_returned_object() -> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig::default())?;
    let (_, body) = post(
        &fixture,
        json!({"query": "{ objects(ids: [\"owned\", \"other\"]) { id label } }"}),
    )
    .await?;
    assert_eq!(
        body.pointer("/data/objects"),
        Some(&json!([{"id": "owned", "label": "visible"}]))
    );
    assert_eq!(fixture.calls.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test]
async fn body_and_execution_deadline_limits_are_enforced()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let body_fixture = fixture(GraphqlConfig {
        max_body_bytes: 256,
        ..GraphqlConfig::default()
    })?;
    let oversized_body = format!("{{\"query\":\"{{ health }}{}\"}}", " ".repeat(512));
    let (status, body) = post_bytes(&body_fixture, oversized_body.into_bytes()).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(error_code(&body), Some("REQUEST_BODY_TOO_LARGE"));

    let deadline_fixture = fixture(GraphqlConfig {
        execution_timeout: Duration::from_millis(5),
        ..GraphqlConfig::default()
    })?;
    let (_, body) = post(&deadline_fixture, json!({"query": "{ waitForDeadline }"})).await?;
    assert_eq!(error_code(&body), Some("REQUEST_TIMEOUT"));
    Ok(())
}

#[tokio::test]
async fn subscription_is_rejected_with_realtime_handoff() -> Result<(), Box<dyn Error + Send + Sync>>
{
    let fixture = fixture(GraphqlConfig::default())?;
    let (_, body) = post(&fixture, json!({"query": "subscription { health }"})).await?;
    assert_eq!(error_code(&body), Some("SUBSCRIPTION_NOT_SUPPORTED"));
    assert_eq!(
        body.pointer("/errors/0/message")
            .and_then(JsonValue::as_str),
        Some("Subscriptions use the realtime transport")
    );
    Ok(())
}

#[tokio::test]
async fn error_mapping_adds_request_id_and_redacts_internal_detail()
-> Result<(), Box<dyn Error + Send + Sync>> {
    let fixture = fixture(GraphqlConfig::default())?;
    let (_, body) = post(&fixture, json!({"query": "{ internalFailure }"})).await?;
    assert_eq!(
        body.pointer("/errors/0/message")
            .and_then(JsonValue::as_str),
        Some("GraphQL request failed")
    );
    let expected_request_id = fixture.request_id.to_string();
    assert_eq!(
        body.pointer("/errors/0/extensions/requestId")
            .and_then(JsonValue::as_str),
        Some(expected_request_id.as_str())
    );
    assert!(!body.to_string().contains("database password"));
    Ok(())
}
