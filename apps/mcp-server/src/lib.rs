//! Dedicated OAuth-authenticated reference MCP application assembly.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse as _, Response},
    routing::get,
};
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDescription, CapabilityDocument, CapabilityHandler, CapabilityId,
    CapabilityKey, CapabilityKind, CapabilityRegistryBuilder, CapabilityTitle, CapabilityVersion,
    ConfirmationPolicy, DataPolicyRef, Exposure, HandlerError, HandlerErrorCode, HandlerInvocation,
    IdempotencyPolicy, InvocationContext, ObjectSchema, Permission, RuntimeAvailability,
    SideEffect, TenantMode, TraceContext, TraceParent, TraceState,
};
use omnius_auth_core::{AuthMethod, Scope};
use omnius_auth_oauth_server::{
    PostgresAccessTokenStateStore, SystemClock, ValidatedAuthorizationServerConfig,
};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_http::{HttpShell, HttpShellError};
use omnius_mcp_auth_oauth::{
    BearerAuthenticationError, BearerCredential, BearerTokenAuthenticator,
    McpAuthenticatedIdentity, McpProtectedResource, McpResourceIdentity,
    OAuthAccessTokenAuthenticator, OperationRequirements, ProtectedResourceError,
    TokenDecisionInput, authenticate_bearer_request,
};
use omnius_mcp_server_core::{
    McpDispatch, McpExposureAuthorizer, McpExposureFilter, McpExtensionCatalog, McpKernel,
    McpPrimitive, McpRequestContext,
    sdk::{
        CanonicalContextResolver, ContextResolutionError, McpApplicationContributionsBuilder,
        McpApplicationContributionsError, McpOperation, McpOperationGuard, McpTenantGuard,
        StatelessHandlerAdapter,
    },
};
use omnius_mcp_tools::{
    CatalogCacheControl, CatalogRevision, CompatibilityState, JsonSchemaDocument, RmcpToolAdapter,
    SchemaRevision, ToolAuthorizationDecision, ToolAuthorizationRequest, ToolAuthorizer,
    ToolDeclaration, ToolDescription, ToolName, ToolProjection, ToolTitle,
};
use omnius_mcp_transport_http::{
    McpHttpBuildError, McpHttpConfig, McpHttpDrainHandle, McpHttpServer,
};
use omnius_pagination::CursorCodec;
use omnius_postgres::PostgresPool;
use omnius_reference_api::oauth_provider::{
    OAuthAccessTokenVerifier, OAuthResourceVerifierBuildError, OAuthResourceVerifierInput,
    REFERENCE_RECORDS_READ_SCOPE, ReferenceOAuthResource, build_oauth_resource_verifier,
    mcp_resource_uri,
};
use omnius_reference_api::{
    ReferenceRecordListError, ReferenceRecordListRequest, ReferenceRecordService,
};
use rmcp::{RoleServer, service::RequestContext};
use serde_json::{Value, json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Exact RFC 9728 metadata path for the separately hosted MCP resource.
pub const MCP_PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
/// Sole tool exposed by the checked-in reference MCP application.
pub const REFERENCE_RECORDS_LIST_TOOL: &str = "reference_records.list.v1";

const REFERENCE_RECORDS_LIST_CAPABILITY: &str = "reference-records.list";
const REFERENCE_RECORDS_LIST_VERSION: &str = "1.0.0";
const REFERENCE_RECORDS_LIST_SCHEMA_REVISION: &str = "1";
const REFERENCE_RECORDS_LIST_CATALOG_REVISION: &str = "reference-records-v1";
const DATA_POLICY: &str = "policy.reference-records.read.v1";
const TRACEPARENT: &str = "traceparent";
const TRACESTATE: &str = "tracestate";

/// Complete independently constructible inputs for the reference MCP HTTP application.
pub struct ReferenceMcpApplicationInput {
    /// Validated authorization-server snapshot shared by configuration, not process memory.
    pub authorization_server: Arc<ValidatedAuthorizationServerConfig>,
    /// Independently connected PostgreSQL pool used by token live-state and reference queries.
    pub pool: PostgresPool,
    /// Exact local identity-provider namespace used by the PostgreSQL OAuth state adapter.
    pub local_identity_provider: String,
    /// Authenticated cursor codec built from the MCP process's own strict configuration.
    pub cursor_codec: CursorCodec,
    /// Strict stateless HTTP transport policy.
    pub http: McpHttpConfig,
}

/// Assembled reference MCP routes and their independent bounded drain handle.
pub struct ReferenceMcpApplication {
    router: Router,
    drain: McpHttpDrainHandle,
}

impl ReferenceMcpApplication {
    /// Clones the complete route set: authenticated `POST /mcp` plus public RFC 9728 metadata.
    pub fn router(&self) -> Router {
        self.router.clone()
    }

    /// Borrows the MCP-specific readiness and bounded-drain handle.
    #[must_use]
    pub const fn drain_handle(&self) -> &McpHttpDrainHandle {
        &self.drain
    }

    /// Consumes the application into its route set and owned drain handle.
    pub fn into_parts(self) -> (Router, McpHttpDrainHandle) {
        (self.router, self.drain)
    }
}

/// Stable, redacted construction failures for the dedicated MCP composition root.
#[derive(Debug, Error)]
pub enum ReferenceMcpBuildError {
    /// The shared exact OAuth resource declaration or PostgreSQL verifier was invalid.
    #[error("MCP OAuth verifier composition failed: {0}")]
    OAuthVerifier(#[from] OAuthResourceVerifierBuildError),
    /// The RFC 8707 resource or RFC 9728 metadata contract was invalid.
    #[error("MCP protected-resource composition failed: {0}")]
    ProtectedResource(#[from] ProtectedResourceError),
    /// The checked-in capability, schema, catalog, or policy contract was invalid.
    #[error("reference MCP capability contract is invalid")]
    CapabilityContract,
    /// A required MCP kernel or policy contribution was absent.
    #[error("reference MCP application contribution is invalid: {0}")]
    Contributions(#[from] McpApplicationContributionsError),
    /// MCP Streamable HTTP transport policy was invalid.
    #[error("reference MCP HTTP transport composition failed: {0}")]
    Transport(#[from] McpHttpBuildError),
    /// The shared HTTP shell rejected metadata-route policy.
    #[error("reference MCP metadata HTTP composition failed: {0}")]
    Http(#[from] HttpShellError),
}

/// Builds the real tools-only reference MCP application and independent OAuth verifier.
///
/// # Errors
///
/// Returns [`ReferenceMcpBuildError`] unless resource, verifier, capability registry, policy,
/// projection, metadata, and HTTP transport contracts all compose exactly.
pub fn build_reference_mcp_application(
    input: ReferenceMcpApplicationInput,
) -> Result<ReferenceMcpApplication, ReferenceMcpBuildError> {
    let ReferenceMcpApplicationInput {
        authorization_server,
        pool,
        local_identity_provider,
        cursor_codec,
        http,
    } = input;
    let resource = mcp_resource_uri(&authorization_server)?;
    let resource_identity =
        McpResourceIdentity::new(resource, authorization_server.issuer().clone())?;
    let read_scope = Scope::new(REFERENCE_RECORDS_READ_SCOPE.to_owned())
        .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
    let profile = Arc::new(McpProtectedResource::new(
        resource_identity,
        vec![read_scope.clone()],
    )?);
    let requirements = Arc::new(
        profile
            .operation_requirements(vec![read_scope])
            .map_err(ReferenceMcpBuildError::from)?,
    );
    let verifier: OAuthAccessTokenVerifier =
        build_oauth_resource_verifier(OAuthResourceVerifierInput {
            config: Arc::clone(&authorization_server),
            resource: ReferenceOAuthResource::Mcp,
            pool: pool.clone(),
            local_identity_provider,
            clock: Arc::new(SystemClock),
        })?;
    let authenticator = Arc::new(GlobalOAuthAuthenticator {
        inner: Arc::new(OAuthAccessTokenAuthenticator::from_verifier(
            Arc::clone(&profile),
            verifier,
        )),
    });

    let reference_records = ReferenceRecordService::new(pool, cursor_codec);
    let handler = build_tools_handler(
        reference_records,
        Arc::clone(&profile),
        http.http.handler_timeout,
        http.http.max_body_bytes,
        http.max_json_response_bytes,
    )?;
    let metadata_state = ProtectedResourceMetadataState {
        body: Bytes::copy_from_slice(profile.metadata_json()),
    };
    let metadata_routes = Router::new()
        .route(
            MCP_PROTECTED_RESOURCE_METADATA_PATH,
            get(protected_resource_metadata),
        )
        .with_state(metadata_state);
    let metadata_routes = HttpShell::new(http.http.clone())?.apply(metadata_routes)?;

    let server = McpHttpServer::new(handler, http)?;
    let (mcp_routes, drain) = server.into_parts();
    let auth_state = BearerMiddlewareState {
        profile,
        requirements,
        authenticator,
    };
    let mcp_routes = mcp_routes.route_layer(middleware::from_fn_with_state(
        auth_state,
        authenticate_mcp_request,
    ));
    Ok(ReferenceMcpApplication {
        router: metadata_routes.merge(mcp_routes),
        drain,
    })
}

type ReferenceOAuthAuthenticator =
    OAuthAccessTokenAuthenticator<PostgresAccessTokenStateStore<SystemClock>, SystemClock>;

#[derive(Clone)]
struct GlobalOAuthAuthenticator {
    inner: Arc<ReferenceOAuthAuthenticator>,
}

impl BearerTokenAuthenticator for GlobalOAuthAuthenticator {
    async fn authenticate<'a>(
        &'a self,
        credential: BearerCredential<'a>,
        decision: TokenDecisionInput<'a>,
    ) -> Result<McpAuthenticatedIdentity, BearerAuthenticationError> {
        let identity = self.inner.authenticate(credential, decision).await?;
        if identity.principal().tenant_id.is_some() {
            return Err(BearerAuthenticationError);
        }
        Ok(identity)
    }
}

#[derive(Clone)]
struct BearerMiddlewareState {
    profile: Arc<McpProtectedResource>,
    requirements: Arc<OperationRequirements>,
    authenticator: Arc<GlobalOAuthAuthenticator>,
}

async fn authenticate_mcp_request(
    State(state): State<BearerMiddlewareState>,
    mut request: Request,
    next: Next,
) -> Response {
    match authenticate_bearer_request(
        &state.profile,
        &state.requirements,
        state.authenticator.as_ref(),
        request.headers(),
        request.uri().query(),
    )
    .await
    {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(rejection) => bearer_rejection_response(&rejection),
    }
}

fn bearer_rejection_response(rejection: &omnius_mcp_auth_oauth::McpAuthRejection) -> Response {
    let Ok(challenge) = HeaderValue::from_str(rejection.www_authenticate().as_str()) else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    let mut response = rejection.status().into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, challenge);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Clone)]
struct ProtectedResourceMetadataState {
    body: Bytes,
}

async fn protected_resource_metadata(
    State(state): State<ProtectedResourceMetadataState>,
) -> Response {
    let mut response = Response::new(Body::from(state.body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(omnius_mcp_auth_oauth::PROTECTED_RESOURCE_METADATA_CONTENT_TYPE),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(omnius_mcp_auth_oauth::PROTECTED_RESOURCE_METADATA_CACHE_CONTROL),
    );
    response
}

fn build_tools_handler(
    service: ReferenceRecordService,
    profile: Arc<McpProtectedResource>,
    handler_timeout: std::time::Duration,
    max_input_bytes: usize,
    max_output_bytes: usize,
) -> Result<StatelessHandlerAdapter, ReferenceMcpBuildError> {
    let capability = reference_records_capability()?;
    let capability_key = capability.key();
    let (input_schema, output_schema) = reference_record_schemas();
    let mut registry = CapabilityRegistryBuilder::new();
    registry
        .register(
            capability,
            RuntimeAvailability::Available,
            ReferenceRecordListHandler { service },
        )
        .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
    let kernel = Arc::new(McpKernel::new(Arc::new(registry.build())));
    let dispatch: Arc<dyn McpDispatch> = kernel.clone();
    let policy = Arc::new(ReferenceMcpPolicy {
        capability: capability_key.clone(),
    });
    let projection = ToolProjection::with_dispatch(
        Arc::clone(&kernel),
        Arc::clone(&dispatch),
        CatalogRevision::new(REFERENCE_RECORDS_LIST_CATALOG_REVISION)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        CatalogCacheControl::private(1_000)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        [ToolDeclaration::new(
            ToolName::new(REFERENCE_RECORDS_LIST_TOOL)
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            capability_key,
            ToolTitle::new("List reference records")
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            Some(
                ToolDescription::new(
                    "Lists one bounded page of globally scoped reference records.",
                )
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            ),
            JsonSchemaDocument::compile(input_schema)
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            JsonSchemaDocument::compile(output_schema)
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            SchemaRevision::new(REFERENCE_RECORDS_LIST_SCHEMA_REVISION)
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
            CompatibilityState::Active,
            [],
        )
        .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?],
        policy.clone(),
    )
    .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
    let resolver = Arc::new(ReferenceContextResolver::new(
        profile,
        handler_timeout,
        max_input_bytes,
        max_output_bytes,
    )?);
    let contributions = McpApplicationContributionsBuilder::new()
        .kernel(kernel.as_ref().clone())
        .dispatch(dispatch)
        .exposure_filter(McpExposureFilter::new(
            kernel.as_ref().clone(),
            policy.clone(),
        ))
        .bearer_authenticator(resolver)
        .tenant_guard(policy.clone())
        .operation_guard(policy)
        .tools(Arc::new(RmcpToolAdapter::new(Arc::new(projection))))
        .finish()?;
    Ok(StatelessHandlerAdapter::with_application_contributions(
        contributions,
        McpExtensionCatalog::empty(),
    ))
}

fn reference_records_capability() -> Result<CapabilityDocument, ReferenceMcpBuildError> {
    let (input_schema, output_schema) = reference_record_schemas();
    Ok(CapabilityDocument {
        id: CapabilityId::new(REFERENCE_RECORDS_LIST_CAPABILITY.to_owned())
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        version: CapabilityVersion::new(REFERENCE_RECORDS_LIST_VERSION.to_owned())
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        title: CapabilityTitle::new("List reference records".to_owned())
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        kind: CapabilityKind::Query,
        description: Some(
            CapabilityDescription::new(
                "Lists one bounded page from the PostgreSQL reference-record repository."
                    .to_owned(),
            )
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        ),
        input_schema: ObjectSchema::try_from(input_schema)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        output_schema: ObjectSchema::try_from(output_schema)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        permissions: vec![
            Permission::new(REFERENCE_RECORDS_READ_SCOPE.to_owned())
                .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?,
        ],
        side_effect: SideEffect::None,
        confirmation: ConfirmationPolicy::Never,
        idempotency: IdempotencyPolicy::NotApplicable,
        tenant_modes: vec![TenantMode::Global],
        exposures: vec![Exposure::McpTool],
        deprecated: false,
    })
}

fn reference_record_schemas() -> (Value, Value) {
    let input = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            "cursor": {"type": "string", "minLength": 1, "maxLength": 256},
            "name": {"type": "string", "minLength": 1, "maxLength": 100}
        }
    });
    let output = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": false,
        "required": ["items", "next_cursor"],
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["id", "name", "created_at", "updated_at", "version"],
                    "properties": {
                        "id": {"type": "string", "format": "uuid"},
                        "name": {"type": "string"},
                        "created_at": {"type": "string", "format": "date-time"},
                        "updated_at": {"type": "string", "format": "date-time"},
                        "version": {"type": "integer", "minimum": 1}
                    }
                }
            },
            "next_cursor": {"type": ["string", "null"]}
        }
    });
    (input, output)
}

#[derive(Clone)]
struct ReferenceRecordListHandler {
    service: ReferenceRecordService,
}

#[async_trait]
impl CapabilityHandler for ReferenceRecordListHandler {
    async fn invoke(&self, invocation: HandlerInvocation) -> Result<Value, HandlerError> {
        if invocation.tenant_mode() != TenantMode::Global
            || invocation.context().tenant_id().is_some()
        {
            return Err(HandlerError::new(HandlerErrorCode::Rejected));
        }
        let input = invocation
            .input()
            .as_object()
            .ok_or_else(|| HandlerError::new(HandlerErrorCode::InvalidInput))?;
        let limit = input
            .get("limit")
            .map(|value| {
                value
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok())
                    .ok_or_else(|| HandlerError::new(HandlerErrorCode::InvalidInput))
            })
            .transpose()?;
        let cursor = optional_string(input.get("cursor"))?;
        let name = optional_string(input.get("name"))?;
        let page = self
            .service
            .list(ReferenceRecordListRequest {
                limit,
                cursor,
                name,
            })
            .await
            .map_err(map_reference_list_error)?;
        let items = page
            .items
            .into_iter()
            .map(|record| {
                let created_at = record
                    .created_at()
                    .format(&Rfc3339)
                    .map_err(|_| HandlerError::new(HandlerErrorCode::Internal))?;
                let updated_at = record
                    .updated_at()
                    .format(&Rfc3339)
                    .map_err(|_| HandlerError::new(HandlerErrorCode::Internal))?;
                Ok(json!({
                    "id": record.id(),
                    "name": record.name(),
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "version": record.version().get(),
                }))
            })
            .collect::<Result<Vec<_>, HandlerError>>()?;
        Ok(json!({
            "items": items,
            "next_cursor": page.next_cursor,
        }))
    }
}

fn optional_string(value: Option<&Value>) -> Result<Option<String>, HandlerError> {
    value
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| HandlerError::new(HandlerErrorCode::InvalidInput))
        })
        .transpose()
}

const fn map_reference_list_error(error: ReferenceRecordListError) -> HandlerError {
    match error {
        ReferenceRecordListError::InvalidPagination | ReferenceRecordListError::Pagination(_) => {
            HandlerError::new(HandlerErrorCode::InvalidInput)
        }
        ReferenceRecordListError::Store(_) => {
            HandlerError::new(HandlerErrorCode::DependencyUnavailable)
        }
    }
}

#[derive(Debug)]
struct ReferenceMcpPolicy {
    capability: CapabilityKey,
}

impl McpExposureAuthorizer for ReferenceMcpPolicy {
    fn is_authorized(
        &self,
        request: &McpRequestContext,
        document: &CapabilityDocument,
        primitive: McpPrimitive,
    ) -> bool {
        primitive == McpPrimitive::Tool
            && &document.id == self.capability.id()
            && &document.version == self.capability.version()
            && is_global_reference_reader(request)
    }
}

impl McpTenantGuard for ReferenceMcpPolicy {
    fn authorize(&self, context: &McpRequestContext) -> bool {
        context.canonical().tenant_mode() == TenantMode::Global
            && context.canonical().invocation().tenant_id().is_none()
            && is_global_reference_reader(context)
    }
}

impl McpOperationGuard for ReferenceMcpPolicy {
    fn authorize(&self, context: &McpRequestContext, operation: McpOperation) -> bool {
        matches!(operation, McpOperation::ListTools | McpOperation::CallTool)
            && is_global_reference_reader(context)
    }
}

#[async_trait]
impl ToolAuthorizer for ReferenceMcpPolicy {
    async fn authorize(&self, request: ToolAuthorizationRequest<'_>) -> ToolAuthorizationDecision {
        if request.declaration().capability() == &self.capability
            && request.tenant_mode() == TenantMode::Global
            && is_global_reference_reader(request.request_context())
        {
            ToolAuthorizationDecision::Allow
        } else {
            ToolAuthorizationDecision::Deny
        }
    }
}

fn is_global_reference_reader(context: &McpRequestContext) -> bool {
    let invocation = context.canonical().invocation();
    let principal = invocation.principal();
    invocation.authorization() == Decision::Allow
        && invocation.tenant_id().is_none()
        && principal.tenant_id.is_none()
        && principal.auth_method == AuthMethod::Jwt
        && principal.scopes.len() == 1
        && principal.scopes[0].as_str() == REFERENCE_RECORDS_READ_SCOPE
}

#[derive(Debug)]
struct ReferenceContextResolver {
    profile: Arc<McpProtectedResource>,
    deadline: time::Duration,
    budget: BudgetBounds,
    data_policy: DataPolicyRef,
}

impl ReferenceContextResolver {
    fn new(
        profile: Arc<McpProtectedResource>,
        handler_timeout: std::time::Duration,
        max_input_bytes: usize,
        max_output_bytes: usize,
    ) -> Result<Self, ReferenceMcpBuildError> {
        let deadline = time::Duration::try_from(handler_timeout)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
        let max_input_bytes = u64::try_from(max_input_bytes)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
        let max_output_bytes = u64::try_from(max_output_bytes)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
        let budget = BudgetBounds::new(max_input_bytes, max_output_bytes, 10_000)
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
        let data_policy = DataPolicyRef::new(DATA_POLICY.to_owned())
            .map_err(|_| ReferenceMcpBuildError::CapabilityContract)?;
        Ok(Self {
            profile,
            deadline,
            budget,
            data_policy,
        })
    }
}

impl CanonicalContextResolver for ReferenceContextResolver {
    fn resolve(
        &self,
        _metadata: &omnius_mcp_server_core::McpRequestMetadata,
        request: &RequestContext<RoleServer>,
    ) -> Result<omnius_mcp_server_core::McpCanonicalContext, ContextResolutionError> {
        let parts = request
            .extensions
            .get::<http::request::Parts>()
            .ok_or(ContextResolutionError)?;
        let identity = parts
            .extensions
            .get::<McpAuthenticatedIdentity>()
            .ok_or(ContextResolutionError)?;
        if identity.issuer() != self.profile.issuer()
            || identity.audience() != self.profile.resource()
            || identity.resource() != self.profile.resource()
            || identity.principal().tenant_id.is_some()
            || identity.scopes().len() != 1
            || identity.scopes()[0].as_str() != REFERENCE_RECORDS_READ_SCOPE
        {
            return Err(ContextResolutionError);
        }
        let request_id = parts
            .extensions
            .get::<RequestId>()
            .copied()
            .ok_or(ContextResolutionError)?;
        let trace_context = resolve_trace_context(parts, request_id)?;
        let invocation = InvocationContext::new(
            request_id,
            trace_context,
            identity.principal().clone(),
            None,
            Decision::Allow,
            self.data_policy.clone(),
            self.budget,
            OffsetDateTime::now_utc() + self.deadline,
            request.ct.clone(),
        )
        .map_err(|_| ContextResolutionError)?;
        omnius_mcp_server_core::McpCanonicalContext::new(invocation, TenantMode::Global)
            .map_err(|_| ContextResolutionError)
    }
}

fn resolve_trace_context(
    parts: &http::request::Parts,
    request_id: RequestId,
) -> Result<TraceContext, ContextResolutionError> {
    let mut traceparents = parts.headers.get_all(TRACEPARENT).iter();
    let traceparent = match (traceparents.next(), traceparents.next()) {
        (Some(value), None) => value
            .to_str()
            .map_err(|_| ContextResolutionError)?
            .parse::<TraceParent>()
            .map_err(|_| ContextResolutionError)?,
        (None, None) => generated_traceparent(request_id)?,
        _ => return Err(ContextResolutionError),
    };
    let mut tracestates = parts.headers.get_all(TRACESTATE).iter();
    let tracestate = match (tracestates.next(), tracestates.next()) {
        (Some(value), None) => Some(
            value
                .to_str()
                .map_err(|_| ContextResolutionError)?
                .parse::<TraceState>()
                .map_err(|_| ContextResolutionError)?,
        ),
        (None, None) => None,
        _ => return Err(ContextResolutionError),
    };
    Ok(TraceContext::new(traceparent, tracestate))
}

fn generated_traceparent(request_id: RequestId) -> Result<TraceParent, ContextResolutionError> {
    let trace_id = request_id.as_uuid().as_u128();
    let low = u64::try_from(trace_id & u128::from(u64::MAX)).map_err(|_| ContextResolutionError)?;
    let high = u64::try_from(trace_id >> u64::BITS).map_err(|_| ContextResolutionError)?;
    let mut span_id = low ^ high;
    if span_id == 0 {
        span_id = 1;
    }
    format!("00-{trace_id:032x}-{span_id:016x}-01")
        .parse()
        .map_err(|_| ContextResolutionError)
}
