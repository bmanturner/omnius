//! Contracts for issuer-bound, resource-scoped client-credentials grants.

use std::{
    error::Error,
    future::ready,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use futures::executor::block_on;
use omnius_agent_capability_registry::{BudgetBounds, InvocationContext, TenantMode, TraceContext};
use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_authz_basic::Decision;
use omnius_core::RequestId;
use omnius_mcp_auth_client_credentials::{
    AccessTokenIdentity, AccessTokenLiveCheck, AccessTokenStateStore,
    AuthenticatedOAuthClientInput, CLIENT_CREDENTIALS_EXTENSION_ID,
    CLIENT_CREDENTIALS_EXTENSION_REVISION, ClientCredentialsAccessTokenStateStore,
    ClientCredentialsConfigError, ClientCredentialsError, ClientCredentialsGrant,
    ClientCredentialsGrantRequest, ClientCredentialsGrantService, ClientCredentialsStateError,
    ClientCredentialsStatePort, ClientId, GrantId, IssuerUri, JwtId, LiveClientCredentialsState,
    LiveClientCredentialsStateInput, McpProtectedResource, McpResourceIdentity,
    OAuthClientAuthenticationError, OAuthClientAuthenticationMethod, OAuthClientAuthenticationPort,
    OAuthStoreError, PublicSubject, ResourceAuthorizationPolicy, ResourceBoundaryError,
    ResourceIssuerPort, ResourceUri, ServiceAccountAccessTokenState,
};
use omnius_mcp_server_core::{
    MCP_PROTOCOL_REVISION, McpCanonicalContext, McpClientIdentity, McpExtension,
    McpExtensionCatalog, McpExtensionId, McpExtensionRevision, McpRequestContext,
    McpRequestMetadata,
};
use time::{Duration, OffsetDateTime};
use tokio_util::sync::CancellationToken;

const NOW_UNIX: i64 = 1_800_000_000;
const SUBJECT: &str = "01890f2a-0000-7000-8000-000000000001";
const TENANT: &str = "01890f2a-0000-7000-8000-000000000002";
const PUBLIC_SUBJECT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[derive(Clone)]
struct ResourcePort {
    policy: ResourceAuthorizationPolicy,
}

impl ResourceIssuerPort for ResourcePort {
    fn resolve_resource(
        &self,
        _resource: &ResourceUri,
    ) -> impl Future<Output = Result<ResourceAuthorizationPolicy, ResourceBoundaryError>> + Send
    {
        ready(Ok(self.policy.clone()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PresentedAuthentication {
    accepted_by_port: bool,
}

#[derive(Clone)]
struct StaticAuthenticationPort {
    output: Option<AuthenticatedOAuthClientInput>,
    calls: Arc<AtomicUsize>,
}

impl StaticAuthenticationPort {
    fn allowing(output: AuthenticatedOAuthClientInput) -> Self {
        Self {
            output: Some(output),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn denying() -> Self {
        Self {
            output: None,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl OAuthClientAuthenticationPort for StaticAuthenticationPort {
    type AuthenticationRequest = PresentedAuthentication;

    fn authenticate_client(
        &self,
        request: &Self::AuthenticationRequest,
        _resource: &ResourceUri,
    ) -> impl Future<Output = Result<AuthenticatedOAuthClientInput, OAuthClientAuthenticationError>> + Send
    {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ready(
            request
                .accepted_by_port
                .then(|| self.output.clone())
                .flatten()
                .ok_or(OAuthClientAuthenticationError),
        )
    }
}

#[derive(Clone)]
struct StatePort {
    state: Arc<LiveClientCredentialsState>,
    access_token_state: ServiceAccountAccessTokenState,
}

impl StatePort {
    fn new(
        input: LiveClientCredentialsStateInput,
        access_token_state: ServiceAccountAccessTokenState,
    ) -> Result<Self, ClientCredentialsError> {
        Ok(Self {
            state: Arc::new(LiveClientCredentialsState::new(input)?),
            access_token_state,
        })
    }
}

impl ClientCredentialsStatePort for StatePort {
    fn load_live_state(
        &self,
        _issuer: &IssuerUri,
        _client_id: &ClientId,
        _resource: &ResourceUri,
    ) -> impl Future<Output = Result<LiveClientCredentialsState, ClientCredentialsStateError>> + Send
    {
        ready(Ok(self.state.as_ref().clone()))
    }

    fn authorize_service_account_access_token(
        &self,
        _check: AccessTokenLiveCheck,
    ) -> impl Future<Output = Result<ServiceAccountAccessTokenState, ClientCredentialsStateError>> + Send
    {
        ready(Ok(self.access_token_state.clone()))
    }
}

#[derive(Clone)]
struct UserStateStore {
    identity: Option<AccessTokenIdentity>,
    calls: Arc<AtomicUsize>,
}

impl UserStateStore {
    fn new(identity: Option<AccessTokenIdentity>) -> Self {
        Self {
            identity,
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AccessTokenStateStore for UserStateStore {
    fn authorize_access_token(
        &self,
        _check: AccessTokenLiveCheck,
    ) -> impl Future<Output = Result<Option<AccessTokenIdentity>, OAuthStoreError>> + Send {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ready(Ok(self.identity.clone()))
    }
}

type GrantRequest = ClientCredentialsGrantRequest<PresentedAuthentication>;

struct Fixture {
    issuer: IssuerUri,
    resource: ResourceUri,
    client_id: ClientId,
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
            issuer: IssuerUri::parse("https://auth.example", true)?,
            resource: ResourceUri::parse("https://mcp.example/tenant/tools", true)?,
            client_id: ClientId::parse("issuer-local-client")?,
            grant_id: GrantId::new(),
            public_subject: PublicSubject::parse(PUBLIC_SUBJECT)?,
            subject: SubjectId::from_str(SUBJECT)?,
            tenant: TenantId::from_str(TENANT)?,
            read: Scope::new("tools.read")?,
            write: Scope::new("tools.write")?,
        })
    }

    fn profile(&self) -> Result<McpProtectedResource, Box<dyn Error>> {
        Ok(McpProtectedResource::new(
            McpResourceIdentity::new(self.resource.clone(), self.issuer.clone())?,
            vec![self.read.clone(), self.write.clone()],
        )?)
    }

    fn policy(&self) -> Result<ResourceAuthorizationPolicy, Box<dyn Error>> {
        Ok(ResourceAuthorizationPolicy::from(&self.profile()?))
    }

    fn state_input(&self) -> LiveClientCredentialsStateInput {
        LiveClientCredentialsStateInput {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            client_enabled: true,
            resource: self.resource.clone(),
            resource_enabled: true,
            client_scopes: vec![self.read.clone(), self.write.clone()],
            authorization_revision: 41,
            authentication_method: OAuthClientAuthenticationMethod::PrivateKeyJwt,
            grant_id: self.grant_id,
            grant_enabled: true,
            public_subject: self.public_subject.clone(),
            service_account_subject: self.subject,
            service_account_enabled: true,
            service_account_scopes: vec![self.read.clone()],
            tenant_id: self.tenant,
            tenant_binding_enabled: true,
        }
    }

    fn authenticated_input(&self) -> AuthenticatedOAuthClientInput {
        AuthenticatedOAuthClientInput {
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            resource: self.resource.clone(),
            allowed_scopes: vec![self.read.clone(), self.write.clone()],
            authorization_revision: 41,
            method: OAuthClientAuthenticationMethod::PrivateKeyJwt,
        }
    }

    fn request(&self, requested_scopes: Vec<Scope>) -> GrantRequest {
        ClientCredentialsGrantRequest {
            authentication: PresentedAuthentication {
                accepted_by_port: true,
            },
            resource: self.resource.clone(),
            requested_scopes,
        }
    }

    fn service_identity(&self, authenticated_at: OffsetDateTime) -> AccessTokenIdentity {
        AccessTokenIdentity {
            subject_id: self.subject,
            kind: PrincipalKind::ServiceAccount,
            tenant_id: Some(self.tenant),
            authenticated_at,
            assurance: AssuranceLevel::Aal1,
            public_subject: self.public_subject.as_str().to_owned(),
            verified_email: None,
        }
    }

    fn user_identity(&self, authenticated_at: OffsetDateTime) -> AccessTokenIdentity {
        AccessTokenIdentity {
            subject_id: SubjectId::new(),
            kind: PrincipalKind::User,
            tenant_id: Some(self.tenant),
            authenticated_at,
            assurance: AssuranceLevel::Aal1,
            public_subject: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_owned(),
            verified_email: Some("user@example.com".to_owned()),
        }
    }
}

fn authorize_at(
    context: &McpRequestContext,
    policy: ResourceAuthorizationPolicy,
    authentication_port: StaticAuthenticationPort,
    state_port: StatePort,
    request: &GrantRequest,
    access_token_lifetime: Duration,
    now: OffsetDateTime,
) -> Result<ClientCredentialsGrant, ClientCredentialsError> {
    let service = ClientCredentialsGrantService::new(
        ResourcePort { policy },
        authentication_port,
        state_port,
        access_token_lifetime,
    )
    .map_err(|_| ClientCredentialsError::InvalidAuthoritativeState)?;
    block_on(service.authorize(context, request, now))
}

fn authorize(
    context: &McpRequestContext,
    fixture: &Fixture,
    authenticated_input: AuthenticatedOAuthClientInput,
    state_input: LiveClientCredentialsStateInput,
    request: &GrantRequest,
) -> Result<ClientCredentialsGrant, ClientCredentialsError> {
    let state_port = StatePort::new(state_input, ServiceAccountAccessTokenState::NotManaged)?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)
        .map_err(|_| ClientCredentialsError::InvalidAuthoritativeState)?;
    authorize_at(
        context,
        fixture
            .policy()
            .map_err(|_| ClientCredentialsError::InvalidAuthoritativeState)?,
        StaticAuthenticationPort::allowing(authenticated_input),
        state_port,
        request,
        Duration::minutes(5),
        now,
    )
}

fn live_check(grant: &ClientCredentialsGrant) -> Result<AccessTokenLiveCheck, Box<dyn Error>> {
    Ok(AccessTokenLiveCheck {
        public_subject: grant.access_token_claims.subject().to_owned(),
        client_id: ClientId::parse(grant.access_token_claims.client_id())?,
        grant_id: GrantId::from_uuid(grant.access_token_claims.grant_id())?,
        audience: ResourceUri::parse(grant.access_token_claims.audience(), true)?,
        jwt_id: JwtId::from_uuid(grant.access_token_claims.jwt_id())?,
        scopes: grant
            .access_token_claims
            .scope()
            .split_ascii_whitespace()
            .map(Scope::new)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn extension(revision: &str) -> Result<McpExtension, Box<dyn Error>> {
    Ok(McpExtension::new(
        McpExtensionId::new(CLIENT_CREDENTIALS_EXTENSION_ID)?,
        McpExtensionRevision::new(revision)?,
    ))
}

fn request_context(
    requested_revision: Option<&str>,
    supported_revision: Option<&str>,
) -> Result<McpRequestContext, Box<dyn Error>> {
    let requested = requested_revision
        .map(extension)
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let supported = supported_revision
        .map(extension)
        .transpose()?
        .into_iter()
        .collect::<Vec<_>>();
    let metadata = McpRequestMetadata::new(
        MCP_PROTOCOL_REVISION,
        McpClientIdentity::new("client-credentials-contract", "1.0.0")?,
        std::iter::empty(),
        requested,
        None,
    )?;
    let catalog = McpExtensionCatalog::new(supported)?;
    let principal = Principal::new(
        SubjectId::new(),
        PrincipalKind::ServiceAccount,
        None,
        AuthMethod::Jwt,
        OffsetDateTime::from_unix_timestamp(NOW_UNIX)?,
        AssuranceLevel::Aal1,
        vec![Scope::new("mcp.grants.issue")?],
    )?;
    let invocation = InvocationContext::new(
        RequestId::new(),
        TraceContext::new(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01".parse()?,
            None,
        ),
        principal,
        None,
        Decision::Allow,
        "policy.mcp-client-credentials".parse()?,
        BudgetBounds::new(4_096, 4_096, 100)?,
        OffsetDateTime::now_utc() + Duration::seconds(10),
        CancellationToken::new(),
    )?;
    let canonical = McpCanonicalContext::new(invocation, TenantMode::Global)?;
    Ok(McpRequestContext::new(metadata, &catalog, canonical))
}

fn exact_context() -> Result<McpRequestContext, Box<dyn Error>> {
    request_context(
        Some(CLIENT_CREDENTIALS_EXTENSION_REVISION),
        Some(CLIENT_CREDENTIALS_EXTENSION_REVISION),
    )
}

#[test]
fn negotiation_is_request_scoped_and_requires_exact_client_and_server_revision()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let request = fixture.request(vec![fixture.read.clone()]);
    let grant = authorize(
        &exact_context()?,
        &fixture,
        fixture.authenticated_input(),
        fixture.state_input(),
        &request,
    )?;
    assert_eq!(
        grant.access_token_claims.audience(),
        fixture.resource.as_str()
    );

    for context in [
        request_context(None, Some(CLIENT_CREDENTIALS_EXTENSION_REVISION))?,
        request_context(
            Some("2026-07-27"),
            Some(CLIENT_CREDENTIALS_EXTENSION_REVISION),
        )?,
        request_context(Some(CLIENT_CREDENTIALS_EXTENSION_REVISION), None)?,
    ] {
        assert_eq!(
            authorize(
                &context,
                &fixture,
                fixture.authenticated_input(),
                fixture.state_input(),
                &request,
            ),
            Err(ClientCredentialsError::ExtensionNotNegotiated)
        );
    }
    Ok(())
}

#[test]
fn configured_authentication_port_is_mandatory_and_validates_its_output()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let request = fixture.request(vec![fixture.read.clone()]);
    let state_port = StatePort::new(
        fixture.state_input(),
        ServiceAccountAccessTokenState::NotManaged,
    )?;
    let denying_port = StaticAuthenticationPort::denying();
    assert_eq!(
        authorize_at(
            &exact_context()?,
            fixture.policy()?,
            denying_port.clone(),
            state_port.clone(),
            &request,
            Duration::minutes(5),
            OffsetDateTime::from_unix_timestamp(NOW_UNIX)?,
        ),
        Err(ClientCredentialsError::ClientAuthenticationFailed)
    );
    assert_eq!(denying_port.calls(), 1);

    let mut malformed = fixture.authenticated_input();
    malformed.allowed_scopes.clear();
    assert_eq!(
        authorize_at(
            &exact_context()?,
            fixture.policy()?,
            StaticAuthenticationPort::allowing(malformed),
            state_port,
            &request,
            Duration::minutes(5),
            OffsetDateTime::from_unix_timestamp(NOW_UNIX)?,
        ),
        Err(ClientCredentialsError::InvalidAuthenticatedClientEvidence)
    );
    Ok(())
}

#[test]
fn resource_policy_can_only_snapshot_the_canonical_mcp_profile() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let profile = fixture.profile()?;
    let policy = ResourceAuthorizationPolicy::from(&profile);
    assert_eq!(policy.resource(), &fixture.resource);
    assert_eq!(policy.authorization_server_issuer(), &fixture.issuer);
    assert_eq!(
        policy.allowed_scopes(),
        &[fixture.read.clone(), fixture.write.clone()]
    );

    let query_resource = ResourceUri::parse("https://mcp.example/tools?tenant=leak", true)?;
    assert!(McpResourceIdentity::new(query_resource, fixture.issuer.clone()).is_err());

    let identity = McpResourceIdentity::new(fixture.resource.clone(), fixture.issuer.clone())?;
    assert!(McpProtectedResource::new(identity, vec![Scope::new("offline_access")?]).is_err());
    Ok(())
}

#[test]
fn access_token_lifetime_is_whole_second_bounded_and_fractional_now_is_deterministic()
-> Result<(), Box<dyn Error>> {
    assert!(matches!(
        ClientCredentialsGrantService::new((), (), (), Duration::milliseconds(999)),
        Err(ClientCredentialsConfigError::InvalidAccessTokenLifetime)
    ));
    assert!(matches!(
        ClientCredentialsGrantService::new(
            (),
            (),
            (),
            Duration::minutes(15) + Duration::NANOSECOND
        ),
        Err(ClientCredentialsConfigError::InvalidAccessTokenLifetime)
    ));

    let fixture = Fixture::new()?;
    let state_port = StatePort::new(
        fixture.state_input(),
        ServiceAccountAccessTokenState::NotManaged,
    )?;
    let fractional_now =
        OffsetDateTime::from_unix_timestamp(NOW_UNIX)?.replace_nanosecond(999_999_999)?;
    let grant = authorize_at(
        &exact_context()?,
        fixture.policy()?,
        StaticAuthenticationPort::allowing(fixture.authenticated_input()),
        state_port,
        &fixture.request(vec![fixture.read.clone()]),
        Duration::SECOND,
        fractional_now,
    )?;
    assert_eq!(grant.access_token_claims.subject(), PUBLIC_SUBJECT);
    Ok(())
}

#[test]
fn issuer_resource_client_scope_revision_and_method_must_match_live_state()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let context = exact_context()?;
    let request = fixture.request(vec![fixture.read.clone()]);

    let mut wrong_issuer = fixture.authenticated_input();
    wrong_issuer.issuer = IssuerUri::parse("https://other-auth.example", true)?;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            wrong_issuer,
            fixture.state_input(),
            &request
        ),
        Err(ClientCredentialsError::IssuerMismatch)
    );

    let mut wrong_resource = fixture.authenticated_input();
    wrong_resource.resource = ResourceUri::parse("https://other-mcp.example/tools", true)?;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            wrong_resource,
            fixture.state_input(),
            &request
        ),
        Err(ClientCredentialsError::ResourceNotAllowed)
    );

    let mut wrong_client = fixture.state_input();
    wrong_client.client_id = ClientId::parse("different-client")?;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            wrong_client,
            &request,
        ),
        Err(ClientCredentialsError::ClientMismatch)
    );

    let mut wrong_scopes = fixture.state_input();
    wrong_scopes.client_scopes = vec![fixture.read.clone()];
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            wrong_scopes,
            &request,
        ),
        Err(ClientCredentialsError::ClientMismatch)
    );

    let mut wrong_revision = fixture.state_input();
    wrong_revision.authorization_revision = 42;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            wrong_revision,
            &request,
        ),
        Err(ClientCredentialsError::ClientMismatch)
    );

    let mut wrong_method = fixture.state_input();
    wrong_method.authentication_method = OAuthClientAuthenticationMethod::MutualTls;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            wrong_method,
            &request,
        ),
        Err(ClientCredentialsError::ClientMismatch)
    );
    Ok(())
}

#[test]
fn exact_scope_intersection_and_raw_duplicate_bound_are_enforced() -> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let context = exact_context()?;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            fixture.state_input(),
            &fixture.request(vec![fixture.read.clone(), fixture.write.clone()]),
        ),
        Err(ClientCredentialsError::InvalidScope)
    );

    let grant = authorize(
        &context,
        &fixture,
        fixture.authenticated_input(),
        fixture.state_input(),
        &fixture.request(vec![fixture.read.clone()]),
    )?;
    assert_eq!(grant.access_token_claims.scope(), fixture.read.as_str());

    let authentication_port = StaticAuthenticationPort::allowing(fixture.authenticated_input());
    let amplified = fixture.request(vec![fixture.read.clone(); 129]);
    assert_eq!(
        authorize_at(
            &context,
            fixture.policy()?,
            authentication_port.clone(),
            StatePort::new(
                fixture.state_input(),
                ServiceAccountAccessTokenState::NotManaged,
            )?,
            &amplified,
            Duration::minutes(5),
            OffsetDateTime::from_unix_timestamp(NOW_UNIX)?,
        ),
        Err(ClientCredentialsError::InvalidScope)
    );
    assert_eq!(authentication_port.calls(), 0);
    Ok(())
}

#[test]
fn client_grant_service_account_and_tenant_revocation_deny_issuance() -> Result<(), Box<dyn Error>>
{
    let fixture = Fixture::new()?;
    let context = exact_context()?;
    let request = fixture.request(vec![fixture.read.clone()]);

    let mut disabled_client = fixture.state_input();
    disabled_client.client_enabled = false;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            disabled_client,
            &request,
        ),
        Err(ClientCredentialsError::ClientDisabled)
    );

    let mut disabled_resource = fixture.state_input();
    disabled_resource.resource_enabled = false;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            disabled_resource,
            &request,
        ),
        Err(ClientCredentialsError::ResourceNotAllowed)
    );

    let mut revoked_grant = fixture.state_input();
    revoked_grant.grant_enabled = false;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            revoked_grant,
            &request,
        ),
        Err(ClientCredentialsError::GrantRevoked)
    );

    let mut disabled_account = fixture.state_input();
    disabled_account.service_account_enabled = false;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            disabled_account,
            &request,
        ),
        Err(ClientCredentialsError::ServiceAccountDisabled)
    );

    let mut disabled_tenant = fixture.state_input();
    disabled_tenant.tenant_binding_enabled = false;
    assert_eq!(
        authorize(
            &context,
            &fixture,
            fixture.authenticated_input(),
            disabled_tenant,
            &request,
        ),
        Err(ClientCredentialsError::TenantBindingInactive)
    );
    Ok(())
}

#[test]
fn issued_claims_flow_through_shared_service_account_state_and_reconstruct_principal()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
    let inactive_port = StatePort::new(
        fixture.state_input(),
        ServiceAccountAccessTokenState::NotManaged,
    )?;
    let grant = authorize_at(
        &exact_context()?,
        fixture.policy()?,
        StaticAuthenticationPort::allowing(fixture.authenticated_input()),
        inactive_port.clone(),
        &fixture.request(vec![fixture.read.clone()]),
        Duration::minutes(5),
        now,
    )?;
    let check = live_check(&grant)?;
    let service_identity = fixture.service_identity(now);
    let shared_state_port = StatePort {
        state: inactive_port.state,
        access_token_state: ServiceAccountAccessTokenState::Authorized(service_identity.clone()),
    };
    let user_store = UserStateStore::new(Some(fixture.user_identity(now)));
    let composite =
        ClientCredentialsAccessTokenStateStore::new(user_store.clone(), shared_state_port);
    let authorized = block_on(composite.authorize_access_token(check.clone()))?
        .ok_or("service-account token unexpectedly inactive")?;
    assert_eq!(authorized, service_identity);
    assert_eq!(user_store.calls(), 0);

    let reconstructed = Principal::new(
        authorized.subject_id,
        authorized.kind,
        authorized.tenant_id,
        AuthMethod::Jwt,
        authorized.authenticated_at,
        authorized.assurance,
        check.scopes,
    )?;
    assert_eq!(reconstructed, grant.principal);
    Ok(())
}

#[test]
fn managed_inactive_tokens_never_fall_through_but_unmanaged_user_tokens_do()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
    let grant = authorize(
        &exact_context()?,
        &fixture,
        fixture.authenticated_input(),
        fixture.state_input(),
        &fixture.request(vec![fixture.read.clone()]),
    )?;
    let check = live_check(&grant)?;
    let user_identity = fixture.user_identity(now);

    let inactive_user_store = UserStateStore::new(Some(user_identity.clone()));
    let inactive_composite = ClientCredentialsAccessTokenStateStore::new(
        inactive_user_store.clone(),
        StatePort::new(
            fixture.state_input(),
            ServiceAccountAccessTokenState::Inactive,
        )?,
    );
    assert_eq!(
        block_on(inactive_composite.authorize_access_token(check.clone()))?,
        None
    );
    assert_eq!(inactive_user_store.calls(), 0);

    let unmanaged_user_store = UserStateStore::new(Some(user_identity.clone()));
    let unmanaged_composite = ClientCredentialsAccessTokenStateStore::new(
        unmanaged_user_store.clone(),
        StatePort::new(
            fixture.state_input(),
            ServiceAccountAccessTokenState::NotManaged,
        )?,
    );
    assert_eq!(
        block_on(unmanaged_composite.authorize_access_token(check))?,
        Some(user_identity)
    );
    assert_eq!(unmanaged_user_store.calls(), 1);
    Ok(())
}

#[test]
fn composite_rejects_noncanonical_service_account_identity_without_user_fallback()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_UNIX)?;
    let grant = authorize(
        &exact_context()?,
        &fixture,
        fixture.authenticated_input(),
        fixture.state_input(),
        &fixture.request(vec![fixture.read.clone()]),
    )?;
    let check = live_check(&grant)?;
    let user_store = UserStateStore::new(Some(fixture.user_identity(now)));

    let mut wrong_kind = fixture.service_identity(now);
    wrong_kind.kind = PrincipalKind::User;
    let mut wrong_subject = fixture.service_identity(now);
    wrong_subject.public_subject = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC".to_owned();
    let mut wrong_tenant = fixture.service_identity(now);
    wrong_tenant.tenant_id = None;
    let mut verified_email = fixture.service_identity(now);
    verified_email.verified_email = Some("service@example.com".to_owned());

    for invalid_identity in [wrong_kind, wrong_subject, wrong_tenant, verified_email] {
        let composite = ClientCredentialsAccessTokenStateStore::new(
            user_store.clone(),
            StatePort::new(
                fixture.state_input(),
                ServiceAccountAccessTokenState::Authorized(invalid_identity),
            )?,
        );
        assert_eq!(
            block_on(composite.authorize_access_token(check.clone()))?,
            None
        );
    }
    assert_eq!(user_store.calls(), 0);
    Ok(())
}

#[test]
fn canonical_claims_are_opaque_refreshless_and_evidence_debug_is_redacted()
-> Result<(), Box<dyn Error>> {
    let fixture = Fixture::new()?;
    let grant = authorize(
        &exact_context()?,
        &fixture,
        fixture.authenticated_input(),
        fixture.state_input(),
        &fixture.request(vec![fixture.read.clone()]),
    )?;
    let check = live_check(&grant)?;

    assert_eq!(grant.principal.kind, PrincipalKind::ServiceAccount);
    assert_eq!(grant.principal.subject_id, fixture.subject);
    assert_eq!(grant.principal.tenant_id, Some(fixture.tenant));
    assert_eq!(grant.access_token_claims.subject(), PUBLIC_SUBJECT);
    assert!(!grant.access_token_claims.subject().contains(SUBJECT));
    assert!(!grant.access_token_claims.subject().contains(TENANT));
    assert_eq!(check.grant_id, fixture.grant_id);
    assert_eq!(check.jwt_id.as_uuid().get_version_num(), 7);
    assert_eq!(check.public_subject, fixture.public_subject.as_str());
    assert_eq!(check.client_id, fixture.client_id);
    assert_eq!(check.audience, fixture.resource);
    assert!(!grant.refresh_token_issued());
    assert_eq!(grant.evidence.authorization_revision(), 41);
    assert_eq!(
        grant.evidence.authentication_method(),
        OAuthClientAuthenticationMethod::PrivateKeyJwt
    );

    let rendered = format!("{:?}", grant.evidence);
    assert!(!rendered.contains(SUBJECT));
    assert!(!rendered.contains(TENANT));
    assert!(!rendered.contains("Bearer "));
    assert!(!rendered.contains("api_key"));
    assert!(
        !ClientCredentialsError::ClientAuthenticationFailed
            .to_string()
            .contains(SUBJECT)
    );
    Ok(())
}
