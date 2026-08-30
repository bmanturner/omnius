//! Stateless policy boundary for the opt-in MCP OAuth client credentials extension.
//!
//! OAuth client authentication remains the authorization server's responsibility. This
//! crate invokes a configured authentication port, reloads authoritative live state, and emits
//! canonical unsigned access-token claims. Signing, persistence, and
//! bearer-token transport remain outside this crate.

use std::{fmt, future::Future};

use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use omnius_mcp_server_core::McpRequestContext;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

pub use omnius_auth_oauth_server::{
    AccessTokenClaims, AccessTokenClaimsInput, AccessTokenIdentity, AccessTokenLiveCheck,
    AccessTokenStateStore, ClientId, GrantId, IssuerUri, JwtId, OAuthStoreError, ResourceUri,
    store::PublicSubject,
};
pub use omnius_mcp_auth_oauth::{McpProtectedResource, McpResourceIdentity};

/// Exact capability identifier for the client credentials extension.
pub const CLIENT_CREDENTIALS_EXTENSION_ID: &str =
    "io.modelcontextprotocol/oauth-client-credentials";
/// Exact revision implemented by this client credentials extension.
pub const CLIENT_CREDENTIALS_EXTENSION_REVISION: &str = "2026-07-28";

const MAX_SCOPES: usize = 128;
const MAX_ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(15);

/// Confidential-client authentication mechanisms accepted at the OAuth AS boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthClientAuthenticationMethod {
    /// HTTP Basic client-secret authentication.
    ClientSecretBasic,
    /// Form-body client-secret authentication.
    ClientSecretPost,
    /// A signed private-key JWT assertion.
    PrivateKeyJwt,
    /// Mutual TLS client authentication.
    MutualTls,
}

impl OAuthClientAuthenticationMethod {
    fn amr(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::MutualTls => "tls_client_auth",
        }
    }
}

/// Bounded issuer-local data returned by a trusted OAuth client authentication port.
///
/// This remains distinct from the service-account [`Principal`]. It contains no credential,
/// assertion, bearer, or API key. The grant service validates every field before constructing
/// authenticated-client evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOAuthClientInput {
    /// Authorization server that authenticated the confidential client.
    pub issuer: IssuerUri,
    /// Issuer-local client identifier.
    pub client_id: ClientId,
    /// Exact resource authorized during client authentication.
    pub resource: ResourceUri,
    /// Scope ceiling loaded while authenticating the client.
    pub allowed_scopes: Vec<Scope>,
    /// Nonzero revision of the authenticated authorization record.
    pub authorization_revision: u64,
    /// Confidential-client authentication mechanism that succeeded.
    pub method: OAuthClientAuthenticationMethod,
}

/// Validated issuer-local authorization evidence for an authenticated OAuth client.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedOAuthClient {
    issuer: IssuerUri,
    client_id: ClientId,
    resource: ResourceUri,
    allowed_scopes: Vec<Scope>,
    authorization_revision: u64,
    method: OAuthClientAuthenticationMethod,
}

impl AuthenticatedOAuthClient {
    fn new(input: AuthenticatedOAuthClientInput) -> Result<Self, ClientCredentialsError> {
        let allowed_scopes = canonical_scopes(input.allowed_scopes)
            .map_err(|_| ClientCredentialsError::InvalidAuthenticatedClientEvidence)?;
        if allowed_scopes.is_empty() || input.authorization_revision == 0 {
            return Err(ClientCredentialsError::InvalidAuthenticatedClientEvidence);
        }
        Ok(Self {
            issuer: input.issuer,
            client_id: input.client_id,
            resource: input.resource,
            allowed_scopes,
            authorization_revision: input.authorization_revision,
            method: input.method,
        })
    }

    /// Returns the authorization server that authenticated the client.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        &self.issuer
    }

    /// Returns the issuer-local client identifier.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the exact resource authorized during client authentication.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns the canonical authenticated-client scope ceiling.
    #[must_use]
    pub fn allowed_scopes(&self) -> &[Scope] {
        &self.allowed_scopes
    }

    /// Returns the nonzero issuer-local authorization revision.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }

    /// Returns the confidential-client authentication mechanism.
    #[must_use]
    pub const fn method(&self) -> OAuthClientAuthenticationMethod {
        self.method
    }
}

/// Value-free failure from the trusted client-authentication boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OAuth client authentication failed")]
pub struct OAuthClientAuthenticationError;

/// Authenticates one confidential-client request and returns issuer-local authorization data.
pub trait OAuthClientAuthenticationPort: Send + Sync {
    /// Transport- or mechanism-specific authentication request accepted by this port.
    type AuthenticationRequest: Send + Sync;

    /// Authenticates the request for the exact requested resource.
    fn authenticate_client(
        &self,
        request: &Self::AuthenticationRequest,
        resource: &ResourceUri,
    ) -> impl Future<Output = Result<AuthenticatedOAuthClientInput, OAuthClientAuthenticationError>> + Send;
}

/// Immutable resource authorization snapshot derived from the canonical MCP resource profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceAuthorizationPolicy {
    resource: ResourceUri,
    authorization_server_issuer: IssuerUri,
    allowed_scopes: Vec<Scope>,
}

impl From<&McpProtectedResource> for ResourceAuthorizationPolicy {
    fn from(profile: &McpProtectedResource) -> Self {
        Self {
            resource: profile.resource().clone(),
            authorization_server_issuer: profile.issuer().clone(),
            allowed_scopes: profile.supported_scopes().to_vec(),
        }
    }
}

impl ResourceAuthorizationPolicy {
    /// Returns the exact protected resource identifier.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns the sole issuer trusted for the protected resource.
    #[must_use]
    pub const fn authorization_server_issuer(&self) -> &IssuerUri {
        &self.authorization_server_issuer
    }

    /// Returns the resource's canonical scope ceiling.
    #[must_use]
    pub fn allowed_scopes(&self) -> &[Scope] {
        &self.allowed_scopes
    }
}

/// Failure at an external issuer/resource boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("resource authorization metadata is unavailable")]
pub struct ResourceBoundaryError;

/// Resolves one exact protected resource to its authoritative OAuth issuer and scope policy.
pub trait ResourceIssuerPort: Send + Sync {
    /// Loads policy for `resource` without accepting an issuer selected by the client.
    fn resolve_resource(
        &self,
        resource: &ResourceUri,
    ) -> impl Future<Output = Result<ResourceAuthorizationPolicy, ResourceBoundaryError>> + Send;
}

/// One atomic live client, grant, service-account, and tenant authorization snapshot.
#[expect(
    clippy::struct_excessive_bools,
    reason = "one atomic snapshot preserves independent revocation dimensions without lossy state folding"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveClientCredentialsState {
    issuer: IssuerUri,
    client_id: ClientId,
    client_enabled: bool,
    resource: ResourceUri,
    resource_enabled: bool,
    client_scopes: Vec<Scope>,
    authorization_revision: u64,
    authentication_method: OAuthClientAuthenticationMethod,
    grant_id: GrantId,
    grant_enabled: bool,
    public_subject: PublicSubject,
    service_account_subject: SubjectId,
    service_account_enabled: bool,
    service_account_scopes: Vec<Scope>,
    tenant_id: TenantId,
    tenant_binding_enabled: bool,
}

/// Constructor parameters for a live client-credentials snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the persistence-port input names each independently revocable authorization fact"
)]
pub struct LiveClientCredentialsStateInput {
    /// Issuer that owns the client registration.
    pub issuer: IssuerUri,
    /// Issuer-local client identifier.
    pub client_id: ClientId,
    /// Whether the OAuth client remains enabled.
    pub client_enabled: bool,
    /// Exact protected resource registration.
    pub resource: ResourceUri,
    /// Whether the client remains enabled for that resource.
    pub resource_enabled: bool,
    /// Client registration scope ceiling.
    pub client_scopes: Vec<Scope>,
    /// Nonzero authorization-state revision.
    pub authorization_revision: u64,
    /// Confidential-client authentication mechanism authorized by live state.
    pub authentication_method: OAuthClientAuthenticationMethod,
    /// Durable grant installed in canonical live access-token state.
    pub grant_id: GrantId,
    /// Whether the durable grant remains live.
    pub grant_enabled: bool,
    /// Bounded issuer-public subject installed in canonical live access-token state.
    pub public_subject: PublicSubject,
    /// Internal canonical service-account subject, never copied into token claims.
    pub service_account_subject: SubjectId,
    /// Whether the service account remains enabled.
    pub service_account_enabled: bool,
    /// Service-account policy scope ceiling.
    pub service_account_scopes: Vec<Scope>,
    /// Internal authoritative tenant binding, never copied into token claims.
    pub tenant_id: TenantId,
    /// Whether the service-account tenant binding remains live.
    pub tenant_binding_enabled: bool,
}

impl LiveClientCredentialsState {
    /// Creates an authoritative state snapshot returned by [`ClientCredentialsStatePort`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientCredentialsError::InvalidAuthoritativeState`] for empty or
    /// oversized scope sets, or a zero authorization revision.
    pub fn new(input: LiveClientCredentialsStateInput) -> Result<Self, ClientCredentialsError> {
        let client_scopes = canonical_scopes(input.client_scopes)?;
        let service_account_scopes = canonical_scopes(input.service_account_scopes)?;
        if client_scopes.is_empty()
            || service_account_scopes.is_empty()
            || input.authorization_revision == 0
        {
            return Err(ClientCredentialsError::InvalidAuthoritativeState);
        }
        Ok(Self {
            issuer: input.issuer,
            client_id: input.client_id,
            client_enabled: input.client_enabled,
            resource: input.resource,
            resource_enabled: input.resource_enabled,
            client_scopes,
            authorization_revision: input.authorization_revision,
            authentication_method: input.authentication_method,
            grant_id: input.grant_id,
            grant_enabled: input.grant_enabled,
            public_subject: input.public_subject,
            service_account_subject: input.service_account_subject,
            service_account_enabled: input.service_account_enabled,
            service_account_scopes,
            tenant_id: input.tenant_id,
            tenant_binding_enabled: input.tenant_binding_enabled,
        })
    }
}

/// Value-free failure from authoritative client-credentials storage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("client credentials authorization state is unavailable")]
pub struct ClientCredentialsStateError;

/// Explicit live-state decision for a canonical service-account access-token check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceAccountAccessTokenState {
    /// The grant is not owned by the client-credentials state implementation.
    NotManaged,
    /// The grant is managed here but is inactive, revoked, or does not match the check.
    Inactive,
    /// Every live check succeeded and reconstructed this canonical identity.
    Authorized(AccessTokenIdentity),
}

/// Loads issuance state and authorizes service-account access tokens from one implementation.
pub trait ClientCredentialsStatePort: Send + Sync {
    /// Loads the issuer-local state for an authenticated client and exact resource.
    fn load_live_state(
        &self,
        issuer: &IssuerUri,
        client_id: &ClientId,
        resource: &ResourceUri,
    ) -> impl Future<Output = Result<LiveClientCredentialsState, ClientCredentialsStateError>> + Send;

    /// Atomically decides whether a canonical access-token check belongs to an active
    /// service-account grant.
    ///
    /// A managed grant must return [`ServiceAccountAccessTokenState::Inactive`] for every
    /// revocation or mismatch. Only an unknown, non-client-credentials grant returns
    /// [`ServiceAccountAccessTokenState::NotManaged`].
    fn authorize_service_account_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> impl Future<Output = Result<ServiceAccountAccessTokenState, ClientCredentialsStateError>> + Send;
}

/// Canonical verifier store combining service-account grants with an ordinary user-token store.
pub struct ClientCredentialsAccessTokenStateStore<U, S> {
    user_store: U,
    client_credentials_store: S,
}

impl<U, S> ClientCredentialsAccessTokenStateStore<U, S> {
    /// Creates a typed composite using the same client-credentials state implementation as
    /// issuance composition.
    #[must_use]
    pub const fn new(user_store: U, client_credentials_store: S) -> Self {
        Self {
            user_store,
            client_credentials_store,
        }
    }
}

impl<U, S> AccessTokenStateStore for ClientCredentialsAccessTokenStateStore<U, S>
where
    U: AccessTokenStateStore,
    S: ClientCredentialsStatePort,
{
    async fn authorize_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> Result<Option<AccessTokenIdentity>, OAuthStoreError> {
        let service_account_state = self
            .client_credentials_store
            .authorize_service_account_access_token(check.clone())
            .await
            .map_err(|_| OAuthStoreError)?;
        match service_account_state {
            ServiceAccountAccessTokenState::NotManaged => {
                self.user_store.authorize_access_token(check).await
            }
            ServiceAccountAccessTokenState::Inactive => Ok(None),
            ServiceAccountAccessTokenState::Authorized(identity) => {
                let is_valid = identity.kind == PrincipalKind::ServiceAccount
                    && identity.tenant_id.is_some()
                    && identity.verified_email.is_none()
                    && identity.public_subject == check.public_subject;
                Ok(is_valid.then_some(identity))
            }
        }
    }
}

/// Input to the issuer-local client credentials grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCredentialsGrantRequest<A> {
    /// Authentication material interpreted only by the configured authentication port.
    pub authentication: A,
    /// Exact RFC 9728 resource indicator.
    pub resource: ResourceUri,
    /// Requested scopes; empty selects the exact authoritative intersection.
    pub requested_scopes: Vec<Scope>,
}

/// Safe, bounded evidence for audit and downstream identity-evidence ports.
#[derive(Clone, Eq, PartialEq)]
pub struct ClientCredentialsEvidence {
    issuer: IssuerUri,
    resource: ResourceUri,
    client_id: ClientId,
    grant_id: GrantId,
    service_account_subject: SubjectId,
    tenant_id: TenantId,
    authentication_method: OAuthClientAuthenticationMethod,
    authorization_revision: u64,
}

impl ClientCredentialsEvidence {
    /// Returns the issuer-local authorization server.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        &self.issuer
    }

    /// Returns the exact MCP resource.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.resource
    }

    /// Returns the authenticated OAuth client identifier.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the durable canonical grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> GrantId {
        self.grant_id
    }

    /// Returns the internal canonical service-account subject for audit correlation.
    #[must_use]
    pub const fn service_account_subject(&self) -> SubjectId {
        self.service_account_subject
    }

    /// Returns the internal authoritative tenant binding for audit correlation.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the confidential-client authentication mechanism.
    #[must_use]
    pub const fn authentication_method(&self) -> OAuthClientAuthenticationMethod {
        self.authentication_method
    }

    /// Returns the live authorization-state revision.
    #[must_use]
    pub const fn authorization_revision(&self) -> u64 {
        self.authorization_revision
    }
}

impl fmt::Debug for ClientCredentialsEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCredentialsEvidence")
            .field("issuer", &self.issuer)
            .field("resource", &self.resource)
            .field("client_id", &self.client_id)
            .field("grant_id", &self.grant_id)
            .field("service_account_subject", &"[REDACTED]")
            .field("tenant_id", &"[REDACTED]")
            .field("authentication_method", &self.authentication_method)
            .field("authorization_revision", &self.authorization_revision)
            .finish()
    }
}

/// Successful service-account grant result.
///
/// It contains canonical unsigned claims, never a bearer token or refresh token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCredentialsGrant {
    /// Canonical internal service-account principal for issuance-time authorization.
    pub principal: Principal,
    /// Canonical claims to sign into the short-lived resource access token.
    pub access_token_claims: AccessTokenClaims,
    /// Separate safe audit and identity evidence.
    pub evidence: ClientCredentialsEvidence,
}

impl ClientCredentialsGrant {
    /// Client-credentials grants never issue refresh tokens.
    #[must_use]
    pub const fn refresh_token_issued(&self) -> bool {
        false
    }
}

/// Client-credentials policy/configuration error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClientCredentialsConfigError {
    /// Access-token lifetime was below one second or exceeded 15 minutes.
    #[error("client credentials access-token lifetime is invalid")]
    InvalidAccessTokenLifetime,
}

/// Complete, fixed, redacted grant denial.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ClientCredentialsError {
    /// The default-disabled exact extension revision was not negotiated for this request.
    #[error("MCP client credentials extension is not negotiated")]
    ExtensionNotNegotiated,
    /// The configured trusted client-authentication port denied the request.
    #[error("OAuth client authentication failed")]
    ClientAuthenticationFailed,
    /// Authenticated-client authorization evidence was malformed or unbounded.
    #[error("authenticated OAuth client authorization evidence is invalid")]
    InvalidAuthenticatedClientEvidence,
    /// Protected-resource metadata could not be resolved.
    #[error("protected resource authorization policy is unavailable")]
    ResourcePolicyUnavailable,
    /// Authoritative client/service-account state could not be loaded.
    #[error("client credentials state is unavailable")]
    StateUnavailable,
    /// The authenticated client's issuer is not the resource issuer.
    #[error("OAuth issuer does not match protected resource")]
    IssuerMismatch,
    /// The loaded registration or its authorization evidence does not match the client.
    #[error("OAuth client binding does not match")]
    ClientMismatch,
    /// The OAuth client is disabled.
    #[error("OAuth client is disabled")]
    ClientDisabled,
    /// The client is not enabled for the exact protected resource.
    #[error("OAuth client is not enabled for protected resource")]
    ResourceNotAllowed,
    /// The canonical durable grant is revoked.
    #[error("OAuth grant is revoked")]
    GrantRevoked,
    /// The canonical service account is disabled.
    #[error("service account is disabled")]
    ServiceAccountDisabled,
    /// The service-account tenant binding is no longer active.
    #[error("service account tenant binding is inactive")]
    TenantBindingInactive,
    /// Requested scopes are empty after intersection or exceed an authoritative ceiling.
    #[error("requested scope is not authorized")]
    InvalidScope,
    /// An authoritative adapter returned malformed or unbounded state.
    #[error("authoritative client credentials state is invalid")]
    InvalidAuthoritativeState,
    /// Canonical principal construction failed.
    #[error("canonical service principal could not be constructed")]
    PrincipalConstructionFailed,
}

/// Authorizes resource-bound client-credentials grants.
pub struct ClientCredentialsGrantService<R, A, S> {
    resource_port: R,
    authentication_port: A,
    state_port: S,
    access_token_lifetime: Duration,
}

impl<R, A, S> ClientCredentialsGrantService<R, A, S> {
    /// Builds the grant service with a short access-token lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`ClientCredentialsConfigError::InvalidAccessTokenLifetime`] unless the
    /// lifetime is at least one second and at most 15 minutes.
    pub fn new(
        resource_port: R,
        authentication_port: A,
        state_port: S,
        access_token_lifetime: Duration,
    ) -> Result<Self, ClientCredentialsConfigError> {
        if access_token_lifetime < Duration::SECOND
            || access_token_lifetime > MAX_ACCESS_TOKEN_LIFETIME
        {
            return Err(ClientCredentialsConfigError::InvalidAccessTokenLifetime);
        }
        Ok(Self {
            resource_port,
            authentication_port,
            state_port,
            access_token_lifetime,
        })
    }
}

impl<R, A, S> ClientCredentialsGrantService<R, A, S>
where
    R: ResourceIssuerPort,
    A: OAuthClientAuthenticationPort,
    S: ClientCredentialsStatePort,
{
    /// Performs request-scoped negotiation and issuer/resource/client/live-state checks.
    ///
    /// The requested scope is accepted only when it equals the exact intersection of
    /// requested, resource, authenticated-client, live-client, and service-account ceilings.
    /// Omitting scope selects the full authoritative intersection.
    ///
    /// # Errors
    ///
    /// Returns a value-free [`ClientCredentialsError`] on every denial.
    #[expect(
        clippy::too_many_lines,
        reason = "the grant flow keeps negotiation, authentication, live-state, scope, principal, and claim checks ordered"
    )]
    pub async fn authorize(
        &self,
        request_context: &McpRequestContext,
        request: &ClientCredentialsGrantRequest<A::AuthenticationRequest>,
        now: OffsetDateTime,
    ) -> Result<ClientCredentialsGrant, ClientCredentialsError> {
        if !request_context
            .negotiated_extensions()
            .extensions()
            .iter()
            .any(|extension| {
                extension.id().as_str() == CLIENT_CREDENTIALS_EXTENSION_ID
                    && extension.revision().as_str() == CLIENT_CREDENTIALS_EXTENSION_REVISION
            })
        {
            return Err(ClientCredentialsError::ExtensionNotNegotiated);
        }
        if request.requested_scopes.len() > MAX_SCOPES {
            return Err(ClientCredentialsError::InvalidScope);
        }

        let authenticated_client = self
            .authentication_port
            .authenticate_client(&request.authentication, &request.resource)
            .await
            .map_err(|_| ClientCredentialsError::ClientAuthenticationFailed)
            .and_then(AuthenticatedOAuthClient::new)?;
        if authenticated_client.resource() != &request.resource {
            return Err(ClientCredentialsError::ResourceNotAllowed);
        }

        let resource_policy = self
            .resource_port
            .resolve_resource(&request.resource)
            .await
            .map_err(|_| ClientCredentialsError::ResourcePolicyUnavailable)?;
        if resource_policy.resource() != &request.resource {
            return Err(ClientCredentialsError::InvalidAuthoritativeState);
        }
        if resource_policy.authorization_server_issuer() != authenticated_client.issuer() {
            return Err(ClientCredentialsError::IssuerMismatch);
        }

        let state = self
            .state_port
            .load_live_state(
                authenticated_client.issuer(),
                authenticated_client.client_id(),
                &request.resource,
            )
            .await
            .map_err(|_| ClientCredentialsError::StateUnavailable)?;

        if state.issuer != *authenticated_client.issuer() {
            return Err(ClientCredentialsError::IssuerMismatch);
        }
        if state.client_id != *authenticated_client.client_id()
            || state.client_scopes.as_slice() != authenticated_client.allowed_scopes()
            || state.authorization_revision != authenticated_client.authorization_revision()
            || state.authentication_method != authenticated_client.method()
        {
            return Err(ClientCredentialsError::ClientMismatch);
        }
        if !state.client_enabled {
            return Err(ClientCredentialsError::ClientDisabled);
        }
        if state.resource != request.resource || !state.resource_enabled {
            return Err(ClientCredentialsError::ResourceNotAllowed);
        }
        if !state.grant_enabled {
            return Err(ClientCredentialsError::GrantRevoked);
        }
        if !state.service_account_enabled {
            return Err(ClientCredentialsError::ServiceAccountDisabled);
        }
        if !state.tenant_binding_enabled {
            return Err(ClientCredentialsError::TenantBindingInactive);
        }

        let requested = canonical_scopes(request.requested_scopes.clone())
            .map_err(|_| ClientCredentialsError::InvalidScope)?;
        let ceilings = [
            resource_policy.allowed_scopes(),
            authenticated_client.allowed_scopes(),
            state.client_scopes.as_slice(),
            state.service_account_scopes.as_slice(),
        ];
        let authoritative = intersect_scopes(&ceilings);
        let granted_scopes = if requested.is_empty() {
            authoritative
        } else {
            let with_request = [requested.as_slice(), authoritative.as_slice()];
            let granted = intersect_scopes(&with_request);
            if granted != requested {
                return Err(ClientCredentialsError::InvalidScope);
            }
            granted
        };
        if granted_scopes.is_empty() {
            return Err(ClientCredentialsError::InvalidScope);
        }

        let principal = Principal::new(
            state.service_account_subject,
            PrincipalKind::ServiceAccount,
            Some(state.tenant_id),
            AuthMethod::Jwt,
            now,
            AssuranceLevel::Aal1,
            granted_scopes.clone(),
        )
        .map_err(|_| ClientCredentialsError::PrincipalConstructionFailed)?;
        let expires_at = now
            .checked_add(self.access_token_lifetime)
            .ok_or(ClientCredentialsError::InvalidAuthoritativeState)?;
        let access_token_claims = AccessTokenClaims::new(AccessTokenClaimsInput {
            issuer: state.issuer.clone(),
            subject: state.public_subject.as_str().to_owned(),
            audience: request.resource.clone(),
            expires_at,
            not_before: now,
            issued_at: now,
            jwt_id: JwtId::new(),
            client_id: state.client_id.clone(),
            grant_id: state.grant_id,
            scopes: granted_scopes,
            auth_time: now,
            acr: "aal1".to_owned(),
            amr: vec![authenticated_client.method().amr().to_owned()],
        })
        .map_err(|_| ClientCredentialsError::InvalidAuthoritativeState)?;
        let evidence = ClientCredentialsEvidence {
            issuer: state.issuer,
            resource: state.resource,
            client_id: state.client_id,
            grant_id: state.grant_id,
            service_account_subject: state.service_account_subject,
            tenant_id: state.tenant_id,
            authentication_method: authenticated_client.method(),
            authorization_revision: state.authorization_revision,
        };
        Ok(ClientCredentialsGrant {
            principal,
            access_token_claims,
            evidence,
        })
    }
}

fn canonical_scopes(mut scopes: Vec<Scope>) -> Result<Vec<Scope>, ClientCredentialsError> {
    if scopes.len() > MAX_SCOPES {
        return Err(ClientCredentialsError::InvalidAuthoritativeState);
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

fn intersect_scopes(scope_sets: &[&[Scope]]) -> Vec<Scope> {
    let Some((first, rest)) = scope_sets.split_first() else {
        return Vec::new();
    };
    let mut intersection = first.to_vec();
    intersection.retain(|scope| rest.iter().all(|set| set.binary_search(scope).is_ok()));
    intersection
}
