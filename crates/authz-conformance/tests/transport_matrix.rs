//! One executable authorization matrix across every supported transport class.

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
    Context, EmptyMutation, ErrorExtensions as _, Object, Request as GraphqlRequest,
    dataloader::DataLoader,
};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::State,
    http::{Request, StatusCode, header::CONTENT_TYPE},
    response::IntoResponse,
    routing::post,
};
use bytes::Bytes;
use futures::future::BoxFuture;
use omnius_admin::{
    AdminAuthorityResolver, AdminConfig, AdminError, AdminLineage, AdminOperationHandler,
    AdminPermission, AdminService, AuthorityResolvedImpersonationTarget, AuthorizedImpersonation,
    ImpersonationTarget, admin_policy_rules,
};
use omnius_audit::{AuditReasonCode, PostgresAuditSink};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::{
    Action, AuthorizationContext, AuthorizationService, BasicAuthorizer, BasicPolicy, Decision,
    DenyReason, Grant, PolicyMatrix, PolicyRule, Resource, ResourceKind,
};
use omnius_config::{DeploymentEnvironment, SecretString};
use omnius_core::{Clock, CorrelationId, RequestId, ServiceError};
use omnius_graphql::{
    ApplicationQueryService, AuthorizedBatchLoader, BoundedList, GraphqlConfig,
    GraphqlRequestContext, QueryObject, graphql_router,
};
use omnius_grpc::{
    ApplicationCall, ApplicationReply, ApplicationService, Authenticator, GrpcConfig, MethodPolicy,
    ServerComposition, ServerPolicies, StreamSender,
    pb::{ExecuteRequest, foundation_client::FoundationClient},
};
use omnius_http::{HttpShell, HttpShellConfig};
use omnius_jobs_core::{
    CompatibilityPolicy, DeadLetterPolicy, DeliveryContext, FailureCode, HandlerFailure,
    HandlerOutcome, IdempotencyRequirement, Jitter, Job, JobEnvelope, JobEnvelopeOptions,
    JobHandler, JobPolicy, TenantId as JobTenantId, TypedJobHandler, TypedJobHandlerAdapter,
};
use omnius_migrations::{MIGRATOR, MigrationConfig, MigrationRunner, SchemaVersionRange};
use omnius_postgres::{
    PostgresConfig, PostgresPool, PostgresTlsMode, TransactionIsolation, TransactionRetryConfig,
};
use omnius_realtime_core::{
    AuthorizationCommand, CommandAuthorizationResolver, ConnectionRegistry, InboundCommand,
    MessageId, OutboundMessage, RealtimeService, RegistryConfig, RejectionCode,
    ResolvedAuthorization, SUBSCRIBE_ACTION, SubscribeCommand, SubscriptionId, Topic,
};
use omnius_test_support::PostgresFixture;
use serde::{Deserialize, Serialize};
use serde_json::{Value as JsonValue, json};
use sqlx::PgConnection;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;
use tonic::{Code, Request as GrpcRequest, metadata::MetadataMap};
use tower::ServiceExt as _;
use uuid::Uuid;

const AUTHORIZATION: &str = "authorization";
const VALID_BEARER: &str = "Bearer conformance-credential";
const AUDIT_SCHEMA_HEAD: i64 = 2_026_082_320;
const NOW_UNIX: i64 = 1_800_000_000;

const JOB_POLICY: JobPolicy = match JobPolicy::new(
    IdempotencyRequirement::Optional,
    3,
    10,
    1_000,
    2,
    Jitter::Full,
    30,
    4,
    None,
    "authorization",
    5,
    86_400,
    DeadLetterPolicy::Retain,
    CompatibilityPolicy::Exact,
    1_024,
) {
    Ok(policy) => policy,
    Err(_) => panic!("authorization conformance job policy must be valid"),
};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum MatrixCase {
    Allowed,
    Denied,
    CrossTenant,
    MissingAuthority,
}

impl MatrixCase {
    const ALL: [Self; 4] = [
        Self::Allowed,
        Self::Denied,
        Self::CrossTenant,
        Self::MissingAuthority,
    ];
}

#[derive(Clone)]
struct AuthorizationInput {
    principal: Principal,
    resource: Resource,
    context: AuthorizationContext,
}

struct CanonicalFixtures {
    policy: BasicPolicy,
    authorizer: BasicAuthorizer,
    action: Action,
    kind: ResourceKind,
    subject: SubjectId,
    other_subject: SubjectId,
    tenant: TenantId,
    other_tenant: TenantId,
    now: OffsetDateTime,
}

impl CanonicalFixtures {
    fn new() -> Result<Self, Box<dyn Error>> {
        let action = Action::new("records.execute")?;
        let kind = ResourceKind::new("protected_record")?;
        let mut rules = vec![
            PolicyRule::new(action.clone(), kind.clone(), vec![Grant::Owner])?
                .with_minimum_assurance(AssuranceLevel::Aal2)
                .requiring_tenant_membership(),
            PolicyRule::new(
                Action::new(SUBSCRIBE_ACTION)?,
                ResourceKind::new("realtime_subscription")?,
                vec![Grant::Owner],
            )?
            .with_minimum_assurance(AssuranceLevel::Aal2)
            .requiring_tenant_membership(),
        ];
        rules.extend(admin_policy_rules()?);
        let policy = BasicPolicy::new(PolicyMatrix::new(rules)?);
        let authorizer = AuthorizationService::new(policy.clone());
        Ok(Self {
            policy,
            authorizer,
            action,
            kind,
            subject: SubjectId::new(),
            other_subject: SubjectId::new(),
            tenant: TenantId::new(),
            other_tenant: TenantId::new(),
            now: OffsetDateTime::from_unix_timestamp(NOW_UNIX)?,
        })
    }

    fn principal(
        subject: SubjectId,
        tenant: Option<TenantId>,
        authenticated_at: OffsetDateTime,
    ) -> Result<Principal, omnius_auth_core::PrincipalError> {
        Principal::new(
            subject,
            PrincipalKind::User,
            tenant,
            AuthMethod::WebAuthn,
            authenticated_at,
            AssuranceLevel::Aal2,
            Vec::<Scope>::new(),
        )
    }

    fn input(&self, case: MatrixCase) -> Result<AuthorizationInput, Box<dyn Error>> {
        let (subject, resource_tenant, memberships) = match case {
            MatrixCase::Allowed => (self.subject, self.tenant, vec![self.tenant]),
            MatrixCase::Denied => (self.other_subject, self.tenant, vec![self.tenant]),
            MatrixCase::CrossTenant => (self.subject, self.other_tenant, vec![self.other_tenant]),
            MatrixCase::MissingAuthority => (self.subject, self.tenant, Vec::new()),
        };
        Ok(AuthorizationInput {
            principal: Self::principal(subject, Some(self.tenant), self.now)?,
            resource: Resource::new(self.kind.clone())
                .owned_by(self.subject)
                .in_tenant(resource_tenant),
            context: AuthorizationContext::new(Vec::new(), memberships, Vec::new(), Vec::new())?,
        })
    }
}

#[derive(Clone)]
struct ProtectedOperation {
    authorizer: BasicAuthorizer,
    action: Action,
    calls: Arc<AtomicUsize>,
}

impl ProtectedOperation {
    fn execute(&self, input: &AuthorizationInput) -> Result<(), DenyReason> {
        match self.authorizer.authorize(
            &input.principal,
            &self.action,
            &input.resource,
            &input.context,
        ) {
            Decision::Allow => {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Decision::Deny(reason) => Err(reason),
        }
    }
}

#[derive(Clone)]
struct HttpState {
    operation: ProtectedOperation,
    resource: Resource,
}

async fn protected_http_handler(
    State(state): State<HttpState>,
    Extension(principal): Extension<Principal>,
    Extension(context): Extension<AuthorizationContext>,
) -> impl IntoResponse {
    let input = AuthorizationInput {
        principal,
        resource: state.resource,
        context,
    };
    let status = match state.operation.execute(&input) {
        Ok(()) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::FORBIDDEN,
    };
    std::future::ready(status).await
}

async fn exercise_http(fixtures: &CanonicalFixtures) -> Result<(), Box<dyn Error>> {
    for case in MatrixCase::ALL {
        let input = fixtures.input(case)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let state = HttpState {
            operation: ProtectedOperation {
                authorizer: fixtures.authorizer.clone(),
                action: fixtures.action.clone(),
                calls: Arc::clone(&calls),
            },
            resource: input.resource.clone(),
        };
        let routes = Router::new()
            .route("/protected", post(protected_http_handler))
            .with_state(state);
        let app = HttpShell::new(HttpShellConfig::default())?.apply_machine_callbacks(routes);
        let mut request = Request::builder()
            .method("POST")
            .uri("/protected")
            .body(Body::empty())?;
        request.extensions_mut().insert(input.principal);
        request.extensions_mut().insert(input.context);
        let response = app.oneshot(request).await?;
        let expected_status = if case == MatrixCase::Allowed {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::FORBIDDEN
        };
        assert_eq!(response.status(), expected_status, "HTTP {case:?}");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(case == MatrixCase::Allowed),
            "HTTP protected operation {case:?}"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ConformanceJob {
    case: MatrixCase,
}

impl Job for ConformanceJob {
    const NAME: &'static str = "authorization.conformance";
    const VERSION: u16 = 1;
    const POLICY: JobPolicy = JOB_POLICY;
    const METRICS_PREFIX: &'static str = "omnius_job_authorization_conformance";
    const RUNBOOK: &'static str = "runbooks/authorization-conformance";
}

#[derive(Clone)]
struct ProtectedJobHandler {
    fixtures: Arc<CanonicalFixtures>,
    operation: ProtectedOperation,
    denied: HandlerFailure,
}

impl TypedJobHandler<ConformanceJob> for ProtectedJobHandler {
    fn handle(
        &self,
        job: ConformanceJob,
        context: DeliveryContext,
    ) -> BoxFuture<'_, HandlerOutcome> {
        let input = self.fixtures.input(job.case).ok();
        let delivery_tenant = context
            .tenant_id()
            .and_then(|tenant| Uuid::parse_str(tenant.as_str()).ok());
        let operation = self.operation.clone();
        let denied = self.denied.clone();
        Box::pin(async move {
            let Some(input) = input else {
                return HandlerOutcome::Permanent(denied);
            };
            if input.principal.tenant_id.map(TenantId::as_uuid) != delivery_tenant {
                return HandlerOutcome::Permanent(denied);
            }
            match operation.execute(&input) {
                Ok(()) => HandlerOutcome::Succeeded,
                Err(_) => HandlerOutcome::Permanent(denied),
            }
        })
    }
}

async fn exercise_jobs(fixtures: Arc<CanonicalFixtures>) -> Result<(), Box<dyn Error>> {
    for case in MatrixCase::ALL {
        let input = fixtures.input(case)?;
        let tenant = input
            .principal
            .tenant_id
            .ok_or("job conformance principal must carry a tenant")?;
        let options = JobEnvelopeOptions::new(Uuid::now_v7())?
            .with_tenant(JobTenantId::try_from(tenant.to_string())?);
        let calls = Arc::new(AtomicUsize::new(0));
        let handler = TypedJobHandlerAdapter::new(ProtectedJobHandler {
            fixtures: Arc::clone(&fixtures),
            operation: ProtectedOperation {
                authorizer: fixtures.authorizer.clone(),
                action: fixtures.action.clone(),
                calls: Arc::clone(&calls),
            },
            denied: HandlerFailure::new(FailureCode::try_from("authorization_denied")?),
        });
        let envelope = JobEnvelope::new(ConformanceJob { case }, options)?.encode()?;
        let context = DeliveryContext::from_envelope(
            &envelope,
            1,
            CancellationToken::new(),
            OffsetDateTime::now_utc() + time::Duration::seconds(30),
        )?;
        let outcome = handler.handle(envelope, context).await;
        match (case, outcome) {
            (MatrixCase::Allowed, HandlerOutcome::Succeeded) => {}
            (_, HandlerOutcome::Permanent(failure))
                if failure.code().as_str() == "authorization_denied" => {}
            (_, other) => panic!("job {case:?} returned unexpected outcome {other:?}"),
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(case == MatrixCase::Allowed),
            "job protected operation {case:?}"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct GraphqlRecord {
    calls: Arc<AtomicUsize>,
}

#[Object]
impl GraphqlRecord {
    async fn execute(&self) -> bool {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::ready(true).await
    }
}

#[derive(Clone)]
struct GraphqlRecordService {
    object: QueryObject<GraphqlRecord>,
}

impl ApplicationQueryService<String> for GraphqlRecordService {
    type Value = GraphqlRecord;
    type Error = Infallible;

    async fn load(
        &self,
        _context: &GraphqlRequestContext,
        keys: &[String],
    ) -> Result<HashMap<String, QueryObject<Self::Value>>, Self::Error> {
        let rows = keys
            .iter()
            .filter(|key| key.as_str() == "record")
            .map(|key| (key.clone(), self.object.clone()))
            .collect();
        std::future::ready(Ok(rows)).await
    }
}

struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn records(
        &self,
        context: &Context<'_>,
        ids: Vec<String>,
    ) -> async_graphql::Result<BoundedList<GraphqlRecord>> {
        let request_context = context.data::<Arc<GraphqlRequestContext>>()?;
        let loader = context
            .data::<DataLoader<AuthorizedBatchLoader<GraphqlRecordService, BasicPolicy>>>()?;
        let records = loader
            .load_many(ids.clone())
            .await
            .map_err(|error| async_graphql::Error::new(error.to_string()))?;
        BoundedList::try_collect(
            ids.into_iter().filter_map(|id| records.get(&id).cloned()),
            request_context.batch_item_limit(),
        )
        .map_err(|error| error.extend())
    }
}

async fn exercise_graphql(fixtures: &CanonicalFixtures) -> Result<(), Box<dyn Error>> {
    for case in MatrixCase::ALL {
        let input = fixtures.input(case)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let service = Arc::new(GraphqlRecordService {
            object: QueryObject::new(
                input.resource.clone(),
                GraphqlRecord {
                    calls: Arc::clone(&calls),
                },
            ),
        });
        let authorizer = Arc::new(fixtures.authorizer.clone());
        let action = fixtures.action.clone();
        let router = graphql_router(
            QueryRoot,
            EmptyMutation,
            GraphqlConfig::default(),
            move |request: GraphqlRequest, context: Arc<GraphqlRequestContext>| {
                let limit = context.batch_item_limit();
                request.data(
                    AuthorizedBatchLoader::new(
                        Arc::clone(&service),
                        Arc::clone(&authorizer),
                        action.clone(),
                        context,
                        limit,
                    )
                    .into_data_loader(),
                )
            },
        )?;
        let mut request = Request::builder()
            .method("POST")
            .uri("/graphql")
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&json!({
                "query": "{ records(ids: [\"record\"]) { execute } }"
            }))?))?;
        request.extensions_mut().insert(input.principal);
        request.extensions_mut().insert(input.context);
        request.extensions_mut().insert(RequestId::new());
        let response = router.oneshot(request).await?;
        assert_eq!(response.status(), StatusCode::OK, "GraphQL {case:?}");
        let body: JsonValue =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await?)?;
        let expected = if case == MatrixCase::Allowed {
            json!({"data": {"records": [{"execute": true}]}})
        } else {
            json!({"data": {"records": []}})
        };
        assert_eq!(body, expected, "GraphQL native result {case:?}");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(case == MatrixCase::Allowed),
            "GraphQL protected field {case:?}"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct TokenAuthenticator {
    principal: Principal,
}

impl Authenticator for TokenAuthenticator {
    type Error = ();

    fn authenticate(&self, metadata: &MetadataMap) -> Result<Principal, Self::Error> {
        let credential = metadata
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        if credential == Some(VALID_BEARER) {
            Ok(self.principal.clone())
        } else {
            Err(())
        }
    }
}

#[derive(Clone)]
struct CountingGrpcApplication {
    calls: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl ApplicationService for CountingGrpcApplication {
    async fn execute(&self, call: ApplicationCall) -> Result<ApplicationReply, ServiceError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Ok(ApplicationReply::new(call.into_payload()))).await
    }

    async fn stream(
        &self,
        _call: ApplicationCall,
        _sender: StreamSender,
    ) -> Result<(), ServiceError> {
        std::future::ready(Ok(())).await
    }
}

fn grpc_request() -> Result<GrpcRequest<ExecuteRequest>, Box<dyn Error>> {
    let mut request = GrpcRequest::new(ExecuteRequest {
        payload: Bytes::from_static(b"protected"),
    });
    request
        .metadata_mut()
        .insert(AUTHORIZATION, VALID_BEARER.parse()?);
    request.set_timeout(Duration::from_secs(1));
    Ok(request)
}

async fn exercise_grpc(fixtures: &CanonicalFixtures) -> Result<(), Box<dyn Error>> {
    for case in MatrixCase::ALL {
        let input = fixtures.input(case)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let policy = MethodPolicy::new(fixtures.action.clone(), input.resource, input.context);
        let policies = ServerPolicies::new(policy.clone(), policy.clone(), policy);
        let composition = ServerComposition::build(
            GrpcConfig::default(),
            CountingGrpcApplication {
                calls: Arc::clone(&calls),
            },
            TokenAuthenticator {
                principal: input.principal,
            },
            fixtures.authorizer.clone(),
            policies,
        )?;
        let result = FoundationClient::new(composition.public_routes())
            .execute(grpc_request()?)
            .await;
        if case == MatrixCase::Allowed {
            let response = result?;
            assert_eq!(
                response.into_inner().payload,
                Bytes::from_static(b"protected")
            );
        } else {
            let Err(status) = result else {
                return Err(format!("denied gRPC case {case:?} was accepted").into());
            };
            assert_eq!(status.code(), Code::PermissionDenied, "gRPC {case:?}");
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(case == MatrixCase::Allowed),
            "gRPC protected application {case:?}"
        );
    }
    Ok(())
}

#[derive(Clone)]
struct RealtimeResolver {
    action: Action,
    input: AuthorizationInput,
}

impl CommandAuthorizationResolver for RealtimeResolver {
    type Error = Infallible;

    fn resolve(
        &self,
        _principal: &Principal,
        _command: AuthorizationCommand<'_>,
    ) -> Result<ResolvedAuthorization, Self::Error> {
        Ok(ResolvedAuthorization::new(
            self.action.clone(),
            self.input.resource.clone(),
            self.input.context.clone(),
        ))
    }
}

fn subscribe_command() -> Result<InboundCommand, Box<dyn Error>> {
    Ok(InboundCommand::Subscribe {
        id: MessageId::new(),
        correlation_id: None,
        command: SubscribeCommand::new(
            SubscriptionId::new(),
            Topic::new("records/protected")?,
            None,
        ),
    })
}

fn exercise_realtime(fixtures: &CanonicalFixtures) -> Result<(), Box<dyn Error>> {
    for case in MatrixCase::ALL {
        let mut input = fixtures.input(case)?;
        input.resource = Resource::new(ResourceKind::new("realtime_subscription")?)
            .owned_by(fixtures.subject)
            .in_tenant(input.resource.tenant_id.ok_or("missing fixture tenant")?);
        let registry = ConnectionRegistry::new(RegistryConfig::new(1, 2, 1)?);
        let connection = registry.register(input.principal.clone())?;
        registry.activate(connection.id())?;
        let service = RealtimeService::new(
            registry.clone(),
            fixtures.authorizer.clone(),
            RealtimeResolver {
                action: Action::new(SUBSCRIBE_ACTION)?,
                input,
            },
        );
        let output = service.handle(connection.id(), subscribe_command()?);
        if case == MatrixCase::Allowed {
            assert!(
                matches!(&output, OutboundMessage::Accepted(_)),
                "realtime {case:?}"
            );
        } else {
            assert!(
                matches!(
                    &output,
                    OutboundMessage::Rejected(rejected)
                        if rejected.code() == RejectionCode::Unauthorized
                ),
                "realtime {case:?}"
            );
        }
        assert_eq!(
            registry.subscription_count()?,
            usize::from(case == MatrixCase::Allowed),
            "realtime protected mutation {case:?}"
        );
    }
    Ok(())
}

struct TestDatabase {
    pool: PostgresPool,
    _fixture: PostgresFixture,
}

fn postgres_config(url: SecretString) -> PostgresConfig {
    PostgresConfig {
        url,
        tls_mode: PostgresTlsMode::Disable,
        min_connections: 1,
        max_connections: 3,
        connect_timeout: Duration::from_secs(5),
        acquire_timeout: Duration::from_secs(1),
        idle_timeout: Duration::from_secs(30),
        max_lifetime: Duration::from_secs(60),
        max_lifetime_jitter: Duration::from_secs(10),
        application_name: "omnius-authz-conformance".to_owned(),
        initialization_sql: Vec::new(),
        statement_timeout: Duration::from_secs(5),
        lock_timeout: Duration::from_secs(1),
        health_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_secs(3),
        transaction_retry: TransactionRetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(5),
            max_delay: Duration::from_millis(50),
            max_jitter: Duration::from_millis(5),
            isolation: TransactionIsolation::Serializable,
        },
    }
}

async fn test_database() -> Result<TestDatabase, Box<dyn Error>> {
    let fixture = PostgresFixture::start().await?;
    let pool = PostgresPool::connect(
        &postgres_config(fixture.database_url().clone()),
        DeploymentEnvironment::Test,
    )
    .await?;
    MigrationRunner::new(
        pool.clone(),
        &MIGRATOR,
        SchemaVersionRange::new(AUDIT_SCHEMA_HEAD, omnius_migrations::CURRENT_SCHEMA_VERSION)?,
        MigrationConfig {
            run_on_startup: false,
            operation_timeout: Duration::from_secs(10),
        },
        DeploymentEnvironment::Test,
    )?
    .run()
    .await?;
    Ok(TestDatabase {
        pool,
        _fixture: fixture,
    })
}

#[derive(Clone)]
struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now_utc(&self) -> OffsetDateTime {
        self.0
    }
}

#[derive(Clone)]
struct AdminAuthority {
    context: Option<AuthorizationContext>,
    target: Principal,
}

impl AdminAuthorityResolver for AdminAuthority {
    fn resolve(&self, _principal: &Principal) -> Option<AuthorizationContext> {
        self.context.clone()
    }

    fn resolve_target(
        &self,
        target: ImpersonationTarget,
    ) -> Option<AuthorityResolvedImpersonationTarget> {
        (target.subject_id() == self.target.subject_id && target.tenant_id().is_none())
            .then(|| AuthorityResolvedImpersonationTarget::Global(self.target.clone()))
    }
}

#[derive(Clone)]
struct CountingAdminOperations {
    calls: Arc<AtomicUsize>,
}

impl CountingAdminOperations {
    async fn execute(
        &self,
        _connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<SubjectId, Infallible> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        std::future::ready(Ok(authority.subject_id())).await
    }
}

impl AdminOperationHandler for CountingAdminOperations {
    type Output = SubjectId;
    type RepairRequest = ();
    type FeatureOverrideRequest = ();
    type Error = Infallible;

    async fn lookup_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }

    async fn lookup_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }

    async fn suspend_user(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }

    async fn suspend_tenant(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }

    async fn execute_safe_repair(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        (): Self::RepairRequest,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }

    async fn apply_feature_override(
        &self,
        connection: &mut PgConnection,
        authority: &AuthorizedImpersonation<'_>,
        (): Self::FeatureOverrideRequest,
    ) -> Result<Self::Output, Self::Error> {
        self.execute(connection, authority).await
    }
}

#[derive(Clone, Copy, Debug)]
enum AdminExpectation {
    Allowed,
    Denied(DenyReason),
    MissingAuthority,
    StaleAuthority,
}

#[expect(
    clippy::too_many_lines,
    reason = "one table keeps every native administration outcome beside its zero-effect assertion"
)]
async fn exercise_admin(
    fixtures: &CanonicalFixtures,
    database: &TestDatabase,
) -> Result<(), Box<dyn Error>> {
    let target_principal =
        CanonicalFixtures::principal(fixtures.other_subject, None, fixtures.now)?;
    let capability_context = AuthorizationContext::new(
        Vec::new(),
        Vec::new(),
        vec![
            AdminPermission::StartImpersonation.capability()?,
            AdminPermission::UserLookup.capability()?,
        ],
        Vec::new(),
    )?;
    let fresh = CanonicalFixtures::principal(fixtures.subject, None, fixtures.now)?;
    let stale = CanonicalFixtures::principal(
        fixtures.subject,
        None,
        fixtures.now - time::Duration::hours(2),
    )?;
    let cases = [
        (
            "allowed",
            fresh.clone(),
            Some(capability_context.clone()),
            AdminExpectation::Allowed,
        ),
        (
            "denied",
            fresh.clone(),
            Some(AuthorizationContext::default()),
            AdminExpectation::Denied(DenyReason::NotEntitled),
        ),
        (
            "missing authority",
            fresh,
            None,
            AdminExpectation::MissingAuthority,
        ),
        (
            "stale authority",
            stale,
            Some(capability_context),
            AdminExpectation::StaleAuthority,
        ),
    ];

    for (name, administrator, context, expectation) in cases {
        let calls = Arc::new(AtomicUsize::new(0));
        let service = AdminService::new(
            fixtures.policy.clone(),
            AdminAuthority {
                context,
                target: target_principal.clone(),
            },
            CountingAdminOperations {
                calls: Arc::clone(&calls),
            },
            Arc::new(FixedClock(fixtures.now)),
            PostgresAuditSink::default(),
            AdminConfig::default(),
        )?;
        let started = service
            .start_impersonation(
                &database.pool,
                &administrator,
                ImpersonationTarget::global(target_principal.subject_id),
                AuditReasonCode::new("authorization.conformance")?,
                Duration::from_mins(15),
                AdminLineage {
                    request_id: RequestId::new(),
                    correlation_id: CorrelationId::new(),
                    causation_id: None,
                },
            )
            .await;
        match expectation {
            AdminExpectation::Allowed => {
                let impersonation = started?;
                let output = service
                    .lookup_user(
                        &database.pool,
                        &administrator,
                        &impersonation,
                        AuditReasonCode::new("authorization.conformance")?,
                        AdminLineage {
                            request_id: RequestId::new(),
                            correlation_id: CorrelationId::new(),
                            causation_id: None,
                        },
                    )
                    .await?;
                assert_eq!(output, target_principal.subject_id, "admin {name}");
            }
            AdminExpectation::Denied(reason) => assert!(
                matches!(&started, Err(AdminError::AuthorizationDenied(actual)) if *actual == reason),
                "admin {name}: {started:?}"
            ),
            AdminExpectation::MissingAuthority => assert!(
                matches!(&started, Err(AdminError::AuthorityUnavailable)),
                "admin {name}: {started:?}"
            ),
            AdminExpectation::StaleAuthority => assert!(
                matches!(&started, Err(AdminError::StaleAuthentication)),
                "admin {name}: {started:?}"
            ),
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            usize::from(matches!(expectation, AdminExpectation::Allowed)),
            "admin protected operation {name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn authorization_is_conformant_across_all_transport_boundaries() -> Result<(), Box<dyn Error>>
{
    let fixtures = Arc::new(CanonicalFixtures::new()?);
    exercise_http(&fixtures).await?;
    exercise_jobs(Arc::clone(&fixtures)).await?;
    exercise_graphql(&fixtures).await?;
    exercise_grpc(&fixtures).await?;
    exercise_realtime(&fixtures)?;
    let database = test_database().await?;
    exercise_admin(&fixtures, &database).await?;
    Ok(())
}
