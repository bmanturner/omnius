//! Security contracts for enterprise-managed authorization.

use std::{
    error::Error,
    future::ready,
    str::FromStr,
    sync::{Arc, Mutex},
};

use futures::executor::block_on;
use omnius_agent_capability_registry::{
    BudgetBounds, CapabilityDocument, CapabilityKind, ConfirmationPolicy, Exposure,
    IdempotencyPolicy, InvocationContext, ObjectSchema, SideEffect, TenantMode, TraceContext,
};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_auth_oauth_server::{
    ClientId, GrantId, IssuerUri, JwtId, ResourceUri, VerifiedAccessToken, store::PublicSubject,
};
use omnius_authz_basic::{Decision, DenyReason};
use omnius_core::RequestId;
use omnius_mcp_auth_client_credentials::{
    OAuthClientAuthenticationMethod, ResourceAuthorizationPolicy, ResourceBoundaryError,
    ResourceIssuerPort,
};
use omnius_mcp_auth_enterprise::*;
use omnius_mcp_auth_oauth::{
    CapabilityVisibility, McpAuthenticatedIdentity, McpOperation, McpOperationAuthorizer,
    McpProtectedResource, McpResourceIdentity, OperationAuthorizationRequest,
};
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

const NOW_UNIX: i64 = 1_800_000_000;
const LOCAL_SUBJECT: &str = "01890f2a-0000-7000-8000-000000000011";
const TENANT: &str = "01890f2a-0000-7000-8000-000000000021";
const PUBLIC_SUBJECT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone)]
struct StaticVerifier(Result<SignatureVerifiedIdJag, IdJagVerificationError>);

impl IdJagSignatureVerifier for StaticVerifier {
    fn verify_signature(
        &self,
        _token: &CompactIdJag,
        _trusted_issuers: &[IssuerUri],
    ) -> impl Future<Output = Result<SignatureVerifiedIdJag, IdJagVerificationError>> + Send {
        ready(self.0.clone())
    }
}

#[derive(Clone)]
struct StaticResourcePort(ResourceAuthorizationPolicy);

impl ResourceIssuerPort for StaticResourcePort {
    fn resolve_resource(
        &self,
        _resource: &ResourceUri,
    ) -> impl Future<Output = Result<ResourceAuthorizationPolicy, ResourceBoundaryError>> + Send
    {
        ready(Ok(self.0.clone()))
    }
}

#[derive(Clone)]
struct StaticLinkPort(EnterpriseIdentityLink);

impl EnterpriseIdentityLinkPort for StaticLinkPort {
    fn load_live_link(
        &self,
        _issuer: &IssuerUri,
        _external_subject: &ExternalSubjectId,
    ) -> impl Future<Output = Result<EnterpriseIdentityLink, IdentityLinkStoreError>> + Send {
        ready(Ok(self.0.clone()))
    }
}

#[derive(Clone)]
struct StaticTenantPort(TenantEntitlement);

impl TenantEntitlementPort for StaticTenantPort {
    fn load_live_entitlement(
        &self,
        _local_subject: SubjectId,
        _tenant_id: TenantId,
    ) -> impl Future<Output = Result<TenantEntitlement, TenantEntitlementStoreError>> + Send {
        ready(Ok(self.0.clone()))
    }
}

#[derive(Clone)]
struct RecordingReplayPort {
    decision: ReplayDecision,
    retain_until: Arc<Mutex<Option<OffsetDateTime>>>,
}

impl IdJagReplayPort for RecordingReplayPort {
    fn consume_once(
        &self,
        _issuer: &IssuerUri,
        _jwt_id: &AssertionJwtId,
        retain_until: OffsetDateTime,
    ) -> impl Future<Output = Result<ReplayDecision, ReplayStoreError>> + Send {
        let result = self
            .retain_until
            .lock()
            .map_err(|_| ReplayStoreError)
            .map(|mut deadline| {
                *deadline = Some(retain_until);
                self.decision
            });
        ready(result)
    }
}

#[derive(Clone)]
struct StaticClientPort(EnterpriseOAuthClientState);

impl EnterpriseOAuthClientPort for StaticClientPort {
    type Authentication = ();

    fn authenticate_client(
        &self,
        _authentication: &Self::Authentication,
        _resource: &ResourceUri,
    ) -> impl Future<Output = Result<EnterpriseOAuthClientState, EnterpriseOAuthClientError>> + Send
    {
        ready(Ok(self.0.clone()))
    }
}

struct Fixture {
    idp_issuer: IssuerUri,
    resource_issuer: IssuerUri,
    resource: ResourceUri,
    client_id: ClientId,
    assertion_id: AssertionJwtId,
    local_token_id: JwtId,
    grant_id: GrantId,
    public_subject: PublicSubject,
    subject: SubjectId,
    tenant: TenantId,
    read: Scope,
    write: Scope,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            idp_issuer: IssuerUri::parse("https://enterprise-idp.example", true)?,
            resource_issuer: IssuerUri::parse("https://resource-as.example", true)?,
            resource: ResourceUri::parse("https://mcp.example/tenant/tools", true)?,
            client_id: ClientId::parse("enterprise-mcp-client")?,
            assertion_id: AssertionJwtId::new("enterprise-assertion-7")?,
            local_token_id: JwtId::new(),
            grant_id: GrantId::new(),
            public_subject: PublicSubject::parse(PUBLIC_SUBJECT)?,
            subject: SubjectId::from_str(LOCAL_SUBJECT)?,
            tenant: TenantId::from_str(TENANT)?,
            read: Scope::new("tools.read")?,
            write: Scope::new("tools.write")?,
        })
    }

    fn protected_resource(&self) -> Result<McpProtectedResource, Box<dyn Error>> {
        Ok(McpProtectedResource::new(
            McpResourceIdentity::new(self.resource.clone(), self.resource_issuer.clone())?,
            vec![self.read.clone(), self.write.clone()],
        )?)
    }

    fn policy(&self) -> Result<ResourceAuthorizationPolicy, Box<dyn Error>> {
        Ok(ResourceAuthorizationPolicy::from(
            &self.protected_resource()?,
        ))
    }

    fn header() -> Result<IdJagProtectedHeader, Box<dyn Error>> {
        Ok(IdJagProtectedHeader {
            token_type: Some(ID_JAG_JOSE_TYPE.to_owned()),
            algorithm: Some(SignatureAlgorithm::Es256),
            key_id: Some(KeyId::new("enterprise-key-1")?),
        })
    }

    fn payload(&self, not_before: Option<OffsetDateTime>) -> Result<IdJagPayload, Box<dyn Error>> {
        let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
        Ok(IdJagPayload {
            issuer: Some(self.idp_issuer.clone()),
            subject: Some(ExternalSubjectId::new("employee-stable-subject")?),
            audiences: Some(vec![self.resource_issuer.clone()]),
            resource: Some(self.resource.clone()),
            client_id: Some(self.client_id.clone()),
            jwt_id: Some(self.assertion_id.clone()),
            issued_at: Some(now - Duration::seconds(5)),
            not_before,
            expires_at: Some(now + Duration::minutes(5)),
            scopes: Some(vec![self.read.clone(), self.write.clone()]),
        })
    }

    fn link(&self) -> Result<EnterpriseIdentityLink, EnterpriseAuthorizationError> {
        EnterpriseIdentityLink::new(EnterpriseIdentityLinkInput {
            link_id: IdentityLinkId::new("enterprise-link-1")
                .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
            issuer: self.idp_issuer.clone(),
            external_subject: ExternalSubjectId::new("employee-stable-subject")
                .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
            local_subject: self.subject,
            tenant_id: self.tenant,
            grant_id: self.grant_id,
            public_subject: self.public_subject.clone(),
            active: true,
            permitted_clients: vec![self.client_id.clone()],
            permitted_resources: vec![self.resource.clone()],
            allowed_scopes: vec![self.read.clone(), self.write.clone()],
            link_version: 3,
            revocation_version: 7,
            policy_version: 11,
        })
    }

    fn tenant_entitlement(&self) -> Result<TenantEntitlement, EnterpriseAuthorizationError> {
        TenantEntitlement::new(TenantEntitlementInput {
            local_subject: self.subject,
            tenant_id: self.tenant,
            active: true,
            allowed_scopes: vec![self.read.clone(), self.write.clone()],
            authorization_revision: 13,
        })
    }

    fn client_state(&self) -> EnterpriseOAuthClientState {
        EnterpriseOAuthClientState {
            issuer: self.resource_issuer.clone(),
            client_id: self.client_id.clone(),
            resource: self.resource.clone(),
            allowed_scopes: vec![self.read.clone(), self.write.clone()],
            authorization_revision: 17,
            authentication_method: OAuthClientAuthenticationMethod::PrivateKeyJwt,
            active: true,
        }
    }
}

fn extension(revision: &str) -> Result<McpExtension, Box<dyn Error>> {
    Ok(McpExtension::new(
        McpExtensionId::new(ENTERPRISE_AUTHORIZATION_EXTENSION_ID)?,
        McpExtensionRevision::new(revision)?,
    ))
}

fn request_context(
    requested_revision: Option<&str>,
    principal: Principal,
    tenant_id: Option<TenantId>,
    tenant_mode: TenantMode,
) -> Result<McpRequestContext, Box<dyn Error>> {
    let requested = requested_revision
        .map(extension)
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("enterprise-contract", "1.0.0")?,
        std::iter::empty(),
        requested,
        None,
    )?;
    let catalog = McpExtensionCatalog::new(vec![extension(
        ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION,
    )?])?;
    let invocation = InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        tenant_id,
        Decision::Allow,
        "policy.enterprise-mcp".parse()?,
        BudgetBounds::new(8_192, 8_192, 100)?,
        OffsetDateTime::now_utc() + Duration::seconds(30),
        CancellationToken::new(),
    )?;
    Ok(McpRequestContext::new(
        metadata,
        &catalog,
        McpCanonicalContext::new(invocation, tenant_mode)?,
    ))
}

fn exchange_context(revision: Option<&str>) -> Result<McpRequestContext, Box<dyn Error>> {
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
    let principal = Principal::new(
        SubjectId::new(),
        PrincipalKind::ServiceAccount,
        None,
        AuthMethod::Jwt,
        now,
        AssuranceLevel::Aal1,
        vec![Scope::new("mcp.enterprise.exchange")?],
    )?;
    request_context(revision, principal, None, TenantMode::Global)
}

fn exchange_with(
    fixture: &Fixture,
    context: McpRequestContext,
    payload: IdJagPayload,
    client: EnterpriseOAuthClientState,
    replay: RecordingReplayPort,
) -> Result<EnterpriseExchange, EnterpriseAuthorizationError> {
    let service = EnterpriseExchangeService::new(
        EnterpriseAuthorizationConfig::new(
            vec![fixture.idp_issuer.clone()],
            vec![SignatureAlgorithm::Es256],
            Duration::minutes(10),
            Duration::seconds(30),
            Duration::minutes(5),
        )
        .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
        StaticVerifier(Ok(SignatureVerifiedIdJag::new(
            Fixture::header()
                .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
            payload,
        ))),
        StaticResourcePort(
            fixture
                .policy()
                .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
        ),
        StaticLinkPort(fixture.link()?),
        StaticTenantPort(fixture.tenant_entitlement()?),
        replay,
        StaticClientPort(client),
    );
    block_on(
        service.exchange(
            &EnterpriseExchangeRequest {
                request_context: context,
                grant: IdJagJwtBearerGrant::new(JWT_BEARER_GRANT_TYPE)?,
                assertion: CompactIdJag::new("header.payload.signature")
                    .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
                resource: fixture.resource.clone(),
                requested_scopes: vec![fixture.read.clone()],
            },
            &(),
            OffsetDateTime::from_unix_timestamp(NOW_UNIX)
                .map_err(|_| EnterpriseAuthorizationError::InvalidLifetime)?,
            fixture.local_token_id,
        ),
    )
}

fn valid_exchange(fixture: &Fixture) -> Result<EnterpriseExchange, EnterpriseAuthorizationError> {
    exchange_with(
        fixture,
        exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))
            .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
        fixture
            .payload(None)
            .map_err(|_| EnterpriseAuthorizationError::InvalidAuthoritativeState)?,
        fixture.client_state(),
        RecordingReplayPort {
            decision: ReplayDecision::Fresh,
            retain_until: Arc::new(Mutex::new(None)),
        },
    )
}

#[test]
fn exchange_requires_exact_request_scoped_revision() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    for revision in [None, Some("2026-07-29")] {
        assert_eq!(
            exchange_with(
                &fixture,
                exchange_context(revision)?,
                fixture.payload(None)?,
                fixture.client_state(),
                RecordingReplayPort {
                    decision: ReplayDecision::Fresh,
                    retain_until: Arc::new(Mutex::new(None)),
                },
            ),
            Err(EnterpriseAuthorizationError::ExtensionNotNegotiated)
        );
    }
    Ok(())
}

#[test]
fn optional_nbf_replay_horizon_and_opaque_claims_are_canonical() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let replay = RecordingReplayPort {
        decision: ReplayDecision::Fresh,
        retain_until: Arc::new(Mutex::new(None)),
    };
    let expected_expiration = fixture
        .payload(None)?
        .expires_at
        .ok_or("missing fixture expiration")?;
    let exchange = exchange_with(
        &fixture,
        exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))?,
        fixture.payload(None)?,
        fixture.client_state(),
        replay.clone(),
    )?;

    assert_eq!(
        *replay.retain_until.lock().map_err(|_| "replay lock")?,
        Some(expected_expiration + Duration::seconds(30))
    );
    assert_eq!(exchange.principal.kind, PrincipalKind::User);
    assert_eq!(exchange.principal.subject_id, fixture.subject);
    assert_eq!(exchange.principal.tenant_id, Some(fixture.tenant));
    assert_eq!(exchange.access_token_claims.subject(), PUBLIC_SUBJECT);
    assert_ne!(exchange.access_token_claims.subject(), LOCAL_SUBJECT);
    assert!(!format!("{:?}", exchange.access_token_claims).contains(TENANT));
    assert_eq!(
        exchange.access_token_claims.grant_id(),
        fixture.grant_id.as_uuid()
    );
    assert_eq!(
        exchange.access_token_claims.jwt_id(),
        fixture.local_token_id.as_uuid()
    );
    assert_eq!(exchange.access_token_claims.scope(), fixture.read.as_str());
    assert!(!exchange.refresh_token_issued());
    Ok(())
}

#[test]
fn live_client_revocation_and_scope_ceiling_fail_closed() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let replay = || RecordingReplayPort {
        decision: ReplayDecision::Fresh,
        retain_until: Arc::new(Mutex::new(None)),
    };
    let mut inactive = fixture.client_state();
    inactive.active = false;
    assert_eq!(
        exchange_with(
            &fixture,
            exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))?,
            fixture.payload(None)?,
            inactive,
            replay(),
        ),
        Err(EnterpriseAuthorizationError::OAuthClientUnavailable)
    );

    let mut restricted = fixture.client_state();
    restricted.allowed_scopes = vec![fixture.write.clone()];
    assert_eq!(
        exchange_with(
            &fixture,
            exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))?,
            fixture.payload(None)?,
            restricted,
            replay(),
        ),
        Err(EnterpriseAuthorizationError::InvalidScope)
    );
    Ok(())
}

#[test]
fn replay_and_registered_claim_failures_are_redacted() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    assert_eq!(
        exchange_with(
            &fixture,
            exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))?,
            fixture.payload(None)?,
            fixture.client_state(),
            RecordingReplayPort {
                decision: ReplayDecision::Replayed,
                retain_until: Arc::new(Mutex::new(None)),
            },
        ),
        Err(EnterpriseAuthorizationError::Replayed)
    );
    let mut missing_exp = fixture.payload(None)?;
    missing_exp.expires_at = None;
    assert_eq!(
        exchange_with(
            &fixture,
            exchange_context(Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION))?,
            missing_exp,
            fixture.client_state(),
            RecordingReplayPort {
                decision: ReplayDecision::Fresh,
                retain_until: Arc::new(Mutex::new(None)),
            },
        ),
        Err(EnterpriseAuthorizationError::MissingExpiration)
    );
    let rendered = format!("{:?}", CompactIdJag::new("email@example.com.secret-token")?);
    assert!(!rendered.contains("email@example.com"));
    assert!(!rendered.contains("secret-token"));
    Ok(())
}

#[derive(Clone, Copy)]
struct StaticLivePort(EnterpriseLiveState);

impl EnterpriseLiveStatePort for StaticLivePort {
    fn check_live_state(
        &self,
        _query: &EnterpriseLiveStateQuery,
    ) -> impl Future<Output = Result<EnterpriseLiveState, EnterpriseLiveStateError>> + Send {
        ready(Ok(self.0))
    }
}

#[derive(Clone)]
struct StaticRegistry(EnterpriseCapabilitySnapshot);

impl EnterpriseCapabilityRegistryPort for StaticRegistry {
    fn resolve_catalog(
        &self,
        request_context: &McpRequestContext,
        exposure: Exposure,
    ) -> impl Future<Output = Result<EnterpriseCatalogSnapshot, EnterpriseRegistryError>> + Send
    {
        ready(EnterpriseCatalogSnapshot::new(
            request_context,
            exposure,
            vec![self.0.document().key()],
        ))
    }

    fn resolve_capability(
        &self,
        _request_context: &McpRequestContext,
        _key: &omnius_agent_capability_registry::CapabilityKey,
    ) -> impl Future<Output = Result<EnterpriseCapabilitySnapshot, EnterpriseRegistryError>> + Send
    {
        ready(Ok(self.0.clone()))
    }
}
#[derive(Clone)]
struct StaleCatalogRegistry {
    capability: EnterpriseCapabilitySnapshot,
    catalog: EnterpriseCatalogSnapshot,
}

impl EnterpriseCapabilityRegistryPort for StaleCatalogRegistry {
    fn resolve_catalog(
        &self,
        _request_context: &McpRequestContext,
        _exposure: Exposure,
    ) -> impl Future<Output = Result<EnterpriseCatalogSnapshot, EnterpriseRegistryError>> + Send
    {
        ready(Ok(self.catalog.clone()))
    }

    fn resolve_capability(
        &self,
        _request_context: &McpRequestContext,
        _key: &omnius_agent_capability_registry::CapabilityKey,
    ) -> impl Future<Output = Result<EnterpriseCapabilitySnapshot, EnterpriseRegistryError>> + Send
    {
        ready(Ok(self.capability.clone()))
    }
}

#[derive(Clone, Copy)]
struct StaticAuthorizer(Decision);

impl McpOperationAuthorizer<EnterpriseAuthorizationTarget> for StaticAuthorizer {
    fn authorize(
        &self,
        request: OperationAuthorizationRequest<'_, EnterpriseAuthorizationTarget>,
    ) -> Decision {
        if self.0 != Decision::Allow {
            return self.0;
        }
        let target = request.target();
        let registry_shape_is_valid = match request.operation() {
            McpOperation::ListResources | McpOperation::ListPrompts | McpOperation::ListTools => {
                target
                    .catalog()
                    .is_some_and(|catalog| !catalog.visible_capabilities().is_empty())
            }
            McpOperation::ReadResource | McpOperation::GetPrompt | McpOperation::CallTool => {
                target.capability().is_some()
            }
        };
        if registry_shape_is_valid {
            Decision::Allow
        } else {
            Decision::Deny(DenyReason::MissingPolicy)
        }
    }
}

#[derive(Clone)]
struct StaticConsent(ConsentDecision);

impl EnterpriseConsentPort for StaticConsent {
    fn resolve_consent(
        &self,
        _query: &ConsentQuery,
    ) -> impl Future<Output = Result<ConsentDecision, ConsentStoreError>> + Send {
        ready(Ok(self.0.clone()))
    }
}

#[derive(Default)]
struct RecordingExecution {
    events: Vec<EnterpriseAuditEvent>,
    executed: bool,
    fail_atomic: bool,
}

impl EnterpriseAuditedExecution for RecordingExecution {
    type Output = &'static str;

    fn record_denial(
        &mut self,
        event: EnterpriseAuditEvent,
    ) -> impl Future<Output = Result<(), EnterpriseExecutionError>> + Send {
        self.events.push(event);
        ready(Ok(()))
    }

    fn execute_authorized(
        &mut self,
        _action: EnterpriseAuthorizedAction,
        event: EnterpriseAuditEvent,
    ) -> impl Future<Output = Result<Self::Output, EnterpriseExecutionError>> + Send {
        if self.fail_atomic {
            return ready(Err(EnterpriseExecutionError));
        }
        self.executed = true;
        self.events.push(event);
        ready(Ok("executed"))
    }
}

fn live_state(active: bool) -> EnterpriseLiveState {
    EnterpriseLiveState {
        access_token_active: active,
        identity_link_active: active,
        tenant_entitlement_active: active,
        policy_version: 11,
        tenant_authorization_revision: 13,
    }
}

fn capability(exposure: Exposure) -> Result<CapabilityDocument, Box<dyn Error>> {
    let document = CapabilityDocument {
        id: "enterprise.action".parse()?,
        version: "1.2.3".parse()?,
        title: "Enterprise action".parse()?,
        kind: CapabilityKind::Command,
        description: None,
        input_schema: ObjectSchema::try_from(json!({"type": "object"}))?,
        output_schema: ObjectSchema::try_from(json!({"type": "object"}))?,
        permissions: Vec::new(),
        side_effect: SideEffect::Mutating,
        confirmation: ConfirmationPolicy::Always,
        idempotency: IdempotencyPolicy::Required,
        tenant_modes: vec![TenantMode::Tenant],
        exposures: vec![exposure],
        deprecated: false,
    };
    document.validate()?;
    Ok(document)
}

fn authenticated_identity(
    fixture: &Fixture,
    exchange: &EnterpriseExchange,
) -> Result<McpAuthenticatedIdentity, Box<dyn Error>> {
    let verified = VerifiedAccessToken {
        principal: exchange.principal.clone(),
        public_subject: exchange.access_token_claims.subject().to_owned(),
        verified_email: None,
        client_id: fixture.client_id.clone(),
        grant_id: fixture.grant_id,
        jwt_id: fixture.local_token_id,
        audience: fixture.resource.clone(),
        scopes: vec![fixture.read.clone()],
    };
    Ok(McpAuthenticatedIdentity::from_verified_access_token(
        fixture.resource_issuer.clone(),
        verified,
    )?)
}

fn invocation_context(
    fixture: &Fixture,
    identity: &McpAuthenticatedIdentity,
) -> Result<McpRequestContext, Box<dyn Error>> {
    request_context(
        Some(ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION),
        identity.principal().clone(),
        Some(fixture.tenant),
        TenantMode::Tenant,
    )
}

#[test]
fn registry_metadata_requires_consent_and_atomic_execution_audit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let document = capability(Exposure::McpTool)?;
    let key = document.key();
    let authorizer = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(true)),
        StaticRegistry(EnterpriseCapabilitySnapshot::new(
            document,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?),
        StaticAuthorizer(Decision::Allow),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: key.clone(),
        }),
    );
    let mut execution = RecordingExecution::default();
    let result = block_on(authorizer.authorize_and_execute(
        &invocation_context(&fixture, &identity)?,
        &identity,
        &EnterpriseInvocationRequest {
            operation: McpOperation::CallTool,
            target: EnterpriseInvocationTarget::Capability(key.clone()),
            argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"count=1")?,
        },
        &mut execution,
    ))?;
    assert_eq!(result, "executed");
    assert!(execution.executed);
    assert_eq!(execution.events.len(), 1);
    let event = &execution.events[0];
    assert_eq!(event.decision, EnterpriseAuditDecision::Allow);
    assert_eq!(event.target, EnterpriseInvocationTarget::Capability(key));
    assert_eq!(
        event.extension_revision,
        ENTERPRISE_AUTHORIZATION_EXTENSION_REVISION
    );
    let rendered = format!("{event:?}");
    assert!(!rendered.contains("header.payload.signature"));
    assert!(!rendered.contains("employee-stable-subject"));
    assert!(!rendered.contains("count=1"));
    Ok(())
}

#[test]
fn ordinary_policy_denial_precedes_consent_and_execution() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let document = capability(Exposure::McpTool)?;
    let key = document.key();
    let authorizer = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(true)),
        StaticRegistry(EnterpriseCapabilitySnapshot::new(
            document,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?),
        StaticAuthorizer(Decision::Deny(DenyReason::NotEntitled)),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: key.clone(),
        }),
    );
    let mut execution = RecordingExecution::default();
    assert_eq!(
        block_on(authorizer.authorize_and_execute(
            &invocation_context(&fixture, &identity)?,
            &identity,
            &EnterpriseInvocationRequest {
                operation: McpOperation::CallTool,
                target: EnterpriseInvocationTarget::Capability(key),
                argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"redacted")?,
            },
            &mut execution,
        )),
        Err(EnterpriseInvocationError::AuthorizationDenied)
    );
    assert!(!execution.executed);
    assert_eq!(execution.events.len(), 1);
    assert_eq!(
        execution.events[0].result,
        EnterpriseAuditResult::PolicyDenied
    );
    Ok(())
}

#[test]
fn stale_consent_key_and_revocation_are_denied_and_audited() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let document = capability(Exposure::McpTool)?;
    let key = document.key();
    let wrong_key = omnius_agent_capability_registry::CapabilityKey::new(
        "enterprise.action".parse()?,
        "1.2.4".parse()?,
    );
    let authorizer = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(true)),
        StaticRegistry(EnterpriseCapabilitySnapshot::new(
            document,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?),
        StaticAuthorizer(Decision::Allow),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: wrong_key,
        }),
    );
    let request = EnterpriseInvocationRequest {
        operation: McpOperation::CallTool,
        target: EnterpriseInvocationTarget::Capability(key),
        argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"redacted")?,
    };
    let context = invocation_context(&fixture, &identity)?;
    let mut execution = RecordingExecution::default();
    assert_eq!(
        block_on(authorizer.authorize_and_execute(&context, &identity, &request, &mut execution,)),
        Err(EnterpriseInvocationError::ConsentDenied)
    );
    assert_eq!(
        execution.events[0].result,
        EnterpriseAuditResult::ConsentDenied
    );

    let revoked = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(false)),
        StaticRegistry(EnterpriseCapabilitySnapshot::new(
            capability(Exposure::McpTool)?,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?),
        StaticAuthorizer(Decision::Allow),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: match &request.target {
                EnterpriseInvocationTarget::Capability(key) => key.clone(),
                EnterpriseInvocationTarget::Catalog(_) => return Err("unexpected catalog".into()),
            },
        }),
    );
    let mut revoked_execution = RecordingExecution::default();
    assert_eq!(
        block_on(revoked.authorize_and_execute(
            &context,
            &identity,
            &request,
            &mut revoked_execution,
        )),
        Err(EnterpriseInvocationError::Revoked)
    );
    assert_eq!(
        revoked_execution.events[0].result,
        EnterpriseAuditResult::Revoked
    );
    Ok(())
}

#[test]
fn all_six_operations_use_canonical_guard_and_target_shape() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let context = invocation_context(&fixture, &identity)?;
    for (operation, exposure, listed) in [
        (McpOperation::ListResources, Exposure::McpResource, true),
        (McpOperation::ReadResource, Exposure::McpResource, false),
        (McpOperation::ListPrompts, Exposure::McpPrompt, true),
        (McpOperation::GetPrompt, Exposure::McpPrompt, false),
        (McpOperation::ListTools, Exposure::McpTool, true),
        (McpOperation::CallTool, Exposure::McpTool, false),
    ] {
        let document = capability(exposure)?;
        let key = document.key();
        let authorizer = EnterpriseInvocationAuthorizer::new(
            StaticLivePort(live_state(true)),
            StaticRegistry(EnterpriseCapabilitySnapshot::new(
                document,
                CapabilityVisibility::TenantPrivate(fixture.tenant),
            )?),
            StaticAuthorizer(Decision::Allow),
            StaticConsent(ConsentDecision {
                granted: true,
                source: ConsentSource::UserInteractive,
                capability: key.clone(),
            }),
        );
        let target = if listed {
            EnterpriseInvocationTarget::Catalog(exposure)
        } else {
            EnterpriseInvocationTarget::Capability(key)
        };
        let mut execution = RecordingExecution::default();
        assert_eq!(
            block_on(authorizer.authorize_and_execute(
                &context,
                &identity,
                &EnterpriseInvocationRequest {
                    operation,
                    target,
                    argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"")?,
                },
                &mut execution,
            ))?,
            "executed"
        );
    }
    Ok(())
}

#[test]
fn atomic_execution_failure_never_returns_a_detached_permit() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let document = capability(Exposure::McpTool)?;
    let key = document.key();
    let authorizer = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(true)),
        StaticRegistry(EnterpriseCapabilitySnapshot::new(
            document,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?),
        StaticAuthorizer(Decision::Allow),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: key.clone(),
        }),
    );
    let mut execution = RecordingExecution {
        fail_atomic: true,
        ..RecordingExecution::default()
    };
    assert_eq!(
        block_on(authorizer.authorize_and_execute(
            &invocation_context(&fixture, &identity)?,
            &identity,
            &EnterpriseInvocationRequest {
                operation: McpOperation::CallTool,
                target: EnterpriseInvocationTarget::Capability(key),
                argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"redacted")?,
            },
            &mut execution,
        )),
        Err(EnterpriseInvocationError::ExecutionFailed)
    );
    assert!(!execution.executed);
    assert!(execution.events.is_empty());
    Ok(())
}

#[test]
fn catalog_snapshots_cannot_cross_request_or_principal_boundaries() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let exchange = valid_exchange(&fixture)?;
    let identity = authenticated_identity(&fixture, &exchange)?;
    let first_context = invocation_context(&fixture, &identity)?;
    let second_context = invocation_context(&fixture, &identity)?;
    let document = capability(Exposure::McpTool)?;
    let key = document.key();
    let registry = StaleCatalogRegistry {
        capability: EnterpriseCapabilitySnapshot::new(
            document,
            CapabilityVisibility::TenantPrivate(fixture.tenant),
        )?,
        catalog: EnterpriseCatalogSnapshot::new(
            &first_context,
            Exposure::McpTool,
            vec![key.clone()],
        )?,
    };
    let authorizer = EnterpriseInvocationAuthorizer::new(
        StaticLivePort(live_state(true)),
        registry,
        StaticAuthorizer(Decision::Allow),
        StaticConsent(ConsentDecision {
            granted: true,
            source: ConsentSource::UserInteractive,
            capability: key,
        }),
    );
    let mut execution = RecordingExecution::default();
    assert_eq!(
        block_on(authorizer.authorize_and_execute(
            &second_context,
            &identity,
            &EnterpriseInvocationRequest {
                operation: McpOperation::ListTools,
                target: EnterpriseInvocationTarget::Catalog(Exposure::McpTool),
                argument_summary: ArgumentSummaryDigest::from_redacted_canonical(b"")?,
            },
            &mut execution,
        )),
        Err(EnterpriseInvocationError::AuthorizationDenied)
    );
    assert!(!execution.executed);
    Ok(())
}
