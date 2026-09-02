use std::{fmt, future::Future, sync::Arc};

use http::{HeaderMap, header::AUTHORIZATION};
use omnius_auth_core::{AuthMethod, Principal, Scope};
use omnius_auth_oauth_server::{
    AccessTokenStateStore, AccessTokenVerificationError, AccessTokenVerifier, ClientId, Clock,
    GrantId, IssuerUri, JwtId, MAX_JWT_BYTES, ResourceUri, SigningKeyRing, VerifiedAccessToken,
};
use thiserror::Error;
use url::form_urlencoded;

use crate::{
    BearerAuthenticationError, McpAuthRejection, McpProtectedResource, OperationRequirements,
};

/// A Bearer presentation was absent or violated the Authorization-header-only contract.
///
/// Variants never contain the rejected header, query value, or bearer credential.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BearerPresentationError {
    /// No Authorization header was present.
    #[error("bearer credential is missing")]
    Missing,
    /// More than one Authorization field value was present.
    #[error("authorization header is duplicated")]
    Duplicate,
    /// The sole Authorization field was not one well-formed Bearer credential.
    #[error("authorization header is malformed")]
    Malformed,
    /// An OAuth access token was supplied through the query string.
    #[error("query bearer credentials are forbidden")]
    QueryToken,
}

/// One borrowed, bounded Bearer credential visible only to the authenticator port.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BearerCredential<'a>(&'a str);

impl<'a> BearerCredential<'a> {
    /// Exposes the credential to a token verifier implementation.
    ///
    /// Callers must not retain, log, audit, or project this value into an
    /// outbound request. The standard request boundary drops it immediately
    /// after [`BearerTokenAuthenticator::authenticate`] completes.
    #[must_use]
    pub const fn expose_secret(self) -> &'a str {
        self.0
    }

    pub(crate) const fn as_str(self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for BearerCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerCredential([REDACTED])")
    }
}
/// An authenticated MCP identity retaining canonical principal and verified OAuth evidence.
///
/// Fields are private and debug output is fully redacted. Ordinary policy can
/// inspect the bounded typed values through read-only accessors without
/// reconstructing client or token evidence from request metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct McpAuthenticatedIdentity {
    principal: Principal,
    issuer: IssuerUri,
    audience: ResourceUri,
    client_id: ClientId,
    grant_id: GrantId,
    jwt_id: JwtId,
    public_subject: String,
    verified_email: Option<String>,
    scopes: Vec<Scope>,
}

impl McpAuthenticatedIdentity {
    /// Retains the complete result of an independently verified access token.
    ///
    /// This construction path is intended for [`BearerTokenAuthenticator`]
    /// implementations after signature, claims, lifetime, resource, and live
    /// authorization-state verification. The request boundary independently
    /// requires the supplied issuer and returned audience to match its profile.
    ///
    /// # Errors
    ///
    /// Returns a value-free error unless the verified aggregate contains a JWT
    /// principal whose canonical scopes exactly equal the token scopes.
    pub fn from_verified_access_token(
        issuer: IssuerUri,
        verified: VerifiedAccessToken,
    ) -> Result<Self, BearerAuthenticationError> {
        if verified.principal.auth_method != AuthMethod::Jwt
            || verified.principal.scopes != verified.scopes
        {
            return Err(BearerAuthenticationError);
        }
        Ok(Self {
            principal: verified.principal,
            issuer,
            audience: verified.audience,
            client_id: verified.client_id,
            grant_id: verified.grant_id,
            jwt_id: verified.jwt_id,
            public_subject: verified.public_subject,
            verified_email: verified.verified_email,
            scopes: verified.scopes,
        })
    }

    /// Returns the canonical application principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the independently verified token issuer.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        &self.issuer
    }

    /// Returns the exact verified token audience.
    #[must_use]
    pub const fn audience(&self) -> &ResourceUri {
        &self.audience
    }

    /// Returns the RFC 8707 resource represented by the exact token audience.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        &self.audience
    }

    /// Returns the verified OAuth client bound to the token.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Returns the verified durable OAuth grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> &GrantId {
        &self.grant_id
    }

    /// Returns the verified JWT identifier.
    #[must_use]
    pub const fn jwt_id(&self) -> &JwtId {
        &self.jwt_id
    }

    /// Returns the bounded issuer-public subject.
    #[must_use]
    pub fn public_subject(&self) -> &str {
        &self.public_subject
    }

    /// Returns the current verified email, when one was retained by live state.
    #[must_use]
    pub fn verified_email(&self) -> Option<&str> {
        self.verified_email.as_deref()
    }

    /// Returns the exact sorted scopes carried by the verified access token.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }
}

impl fmt::Debug for McpAuthenticatedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("McpAuthenticatedIdentity([REDACTED])")
    }
}

/// Requires the verifier to perform its live authorization-state read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveStateRequirement {
    /// Cryptographic success is insufficient without current issuer-side state.
    Required,
}

/// Complete exact input to one MCP bearer authentication decision.
///
/// `audience` and `resource` deliberately name the same canonical RFC 8707
/// resource. Keeping both explicit prevents adapters from validating a generic
/// audience while authorizing a different MCP resource.
#[derive(Clone, Copy, Debug)]
pub struct TokenDecisionInput<'a> {
    issuer: &'a IssuerUri,
    audience: &'a ResourceUri,
    resource: &'a ResourceUri,
    required_scopes: &'a [Scope],
    live_state: LiveStateRequirement,
}

impl TokenDecisionInput<'_> {
    /// Returns the exact trusted token issuer.
    #[must_use]
    pub const fn issuer(&self) -> &IssuerUri {
        self.issuer
    }

    /// Returns the exact access-token audience.
    #[must_use]
    pub const fn audience(&self) -> &ResourceUri {
        self.audience
    }

    /// Returns the exact RFC 8707 resource indicator.
    #[must_use]
    pub const fn resource(&self) -> &ResourceUri {
        self.resource
    }

    /// Returns the complete sorted scope set needed for this operation.
    #[must_use]
    pub const fn required_scopes(&self) -> &[Scope] {
        self.required_scopes
    }

    /// Returns the mandatory live-state verification policy.
    #[must_use]
    pub const fn live_state(&self) -> LiveStateRequirement {
        self.live_state
    }
}

/// Bearer-only authentication port producing typed verified MCP identity evidence.
///
/// Implementations must validate the exact issuer, audience/resource, token
/// lifetime and signature, and perform the requested live-state decision. They
/// must not fall back to sessions, API keys, model identity, or tool claims.
pub trait BearerTokenAuthenticator: Send + Sync {
    /// Authenticates one credential against the complete exact decision input.
    fn authenticate<'a>(
        &'a self,
        credential: BearerCredential<'a>,
        decision: TokenDecisionInput<'a>,
    ) -> impl Future<Output = Result<McpAuthenticatedIdentity, BearerAuthenticationError>> + Send + 'a;
}

/// Extracts exactly one Authorization-header Bearer credential.
///
/// The OAuth `access_token` query parameter is rejected even when a valid header
/// is also present. Scheme matching is case-insensitive and the scheme is followed
/// by one or more ASCII spaces, never tabs or surrounding whitespace. The
/// credential must use the RFC 6750 `b64token` grammar and cannot exceed the
/// OAuth verifier's bound.
///
/// # Errors
///
/// Returns a value-free [`BearerPresentationError`] for every invalid presentation.
pub fn extract_bearer_credential<'a>(
    headers: &'a HeaderMap,
    query: Option<&str>,
) -> Result<BearerCredential<'a>, BearerPresentationError> {
    if query.is_some_and(contains_query_access_token) {
        return Err(BearerPresentationError::QueryToken);
    }

    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(BearerPresentationError::Missing)?;
    if values.next().is_some() {
        return Err(BearerPresentationError::Duplicate);
    }
    let value = value
        .to_str()
        .map_err(|_| BearerPresentationError::Malformed)?;
    let (scheme, remainder) = value
        .split_once(' ')
        .ok_or(BearerPresentationError::Malformed)?;
    let token = remainder.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("Bearer") || !valid_b64token(token) {
        return Err(BearerPresentationError::Malformed);
    }
    Ok(BearerCredential(token))
}

fn contains_query_access_token(query: &str) -> bool {
    let query = query.strip_prefix('?').unwrap_or(query);
    form_urlencoded::parse(query.as_bytes()).any(|(name, _)| name == "access_token")
}

fn valid_b64token(token: &str) -> bool {
    if token.is_empty() || token.len() > MAX_JWT_BYTES {
        return false;
    }
    let core = token.trim_end_matches('=');
    !core.is_empty()
        && core.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && token[core.len()..].bytes().all(|byte| byte == b'=')
}

/// Authenticates one request and enforces the complete required scope set.
///
/// The returned [`McpAuthenticatedIdentity`] owns only verified evidence. The
/// borrowed bearer credential is dropped before the function returns and cannot
/// enter an MCP operation or outbound-header projection.
///
/// # Errors
///
/// Returns a deterministic 400 challenge for malformed presentations, a
/// deterministic 401 challenge for missing or invalid tokens, and a deterministic
/// 403 `insufficient_scope` challenge when verified token scopes are insufficient.
pub async fn authenticate_bearer_request<A>(
    profile: &McpProtectedResource,
    requirements: &OperationRequirements,
    authenticator: &A,
    headers: &HeaderMap,
    query: Option<&str>,
) -> Result<McpAuthenticatedIdentity, McpAuthRejection>
where
    A: BearerTokenAuthenticator + ?Sized,
{
    if requirements.resource() != profile.resource() {
        return Err(McpAuthRejection::invalid_request(profile, requirements));
    }

    let credential = extract_bearer_credential(headers, query).map_err(|error| match error {
        BearerPresentationError::Missing => McpAuthRejection::missing(profile, requirements),
        BearerPresentationError::Duplicate
        | BearerPresentationError::Malformed
        | BearerPresentationError::QueryToken => {
            McpAuthRejection::invalid_request(profile, requirements)
        }
    })?;
    let decision = TokenDecisionInput {
        issuer: profile.issuer(),
        audience: profile.resource(),
        resource: profile.resource(),
        required_scopes: requirements.required_scopes(),
        live_state: LiveStateRequirement::Required,
    };
    let identity = authenticator
        .authenticate(credential, decision)
        .await
        .map_err(|_| McpAuthRejection::invalid_token(profile, requirements))?;

    if identity.issuer() != decision.issuer()
        || identity.audience() != decision.audience()
        || identity.resource() != decision.resource()
        || identity.principal().auth_method != AuthMethod::Jwt
    {
        return Err(McpAuthRejection::invalid_token(profile, requirements));
    }
    if requirements
        .required_scopes()
        .iter()
        .any(|required| identity.scopes().binary_search(required).is_err())
    {
        return Err(McpAuthRejection::insufficient_scope(profile, requirements));
    }
    Ok(identity)
}

/// Direct adapter from the first-party issuer's `AccessTokenVerifier` to MCP authentication.
///
/// Construction configures the verifier from the same immutable MCP profile used
/// for metadata and challenges, so issuer, audience, resource scopes, and live
/// state cannot drift independently.
#[derive(Clone)]
pub struct OAuthAccessTokenAuthenticator<S, C> {
    profile: Arc<McpProtectedResource>,
    verifier: AccessTokenVerifier<S, C>,
}

impl<S, C> OAuthAccessTokenAuthenticator<S, C>
where
    S: AccessTokenStateStore,
    C: Clock,
{
    /// Builds an exact-resource verifier using the profile's issuer, audience, and scopes.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenVerificationError`] if the OAuth verifier rejects the
    /// profile's scope policy.
    pub fn new(
        profile: Arc<McpProtectedResource>,
        keys: Arc<SigningKeyRing>,
        store: Arc<S>,
        clock: Arc<C>,
    ) -> Result<Self, AccessTokenVerificationError> {
        let verifier = AccessTokenVerifier::new(
            keys,
            profile.issuer().clone(),
            profile.resource().clone(),
            profile.supported_scopes().to_vec(),
            store,
            clock,
        )?;
        Ok(Self { profile, verifier })
    }

    /// Adapts an independently constructed verifier to the immutable MCP profile used for
    /// metadata, challenges, and request-time decisions.
    ///
    /// The verifier is consumed rather than unpacked or rebuilt. Every authentication still checks
    /// the decision issuer, audience, resource, scopes, live-state policy, and verified audience
    /// against `profile`.
    #[must_use]
    pub fn from_verifier(
        profile: Arc<McpProtectedResource>,
        verifier: AccessTokenVerifier<S, C>,
    ) -> Self {
        Self { profile, verifier }
    }
}

impl<S, C> BearerTokenAuthenticator for OAuthAccessTokenAuthenticator<S, C>
where
    S: AccessTokenStateStore,
    C: Clock,
{
    async fn authenticate<'a>(
        &'a self,
        credential: BearerCredential<'a>,
        decision: TokenDecisionInput<'a>,
    ) -> Result<McpAuthenticatedIdentity, BearerAuthenticationError> {
        if decision.issuer() != self.profile.issuer()
            || decision.audience() != self.profile.resource()
            || decision.resource() != self.profile.resource()
            || decision.live_state() != LiveStateRequirement::Required
            || decision.required_scopes().iter().any(|scope| {
                self.profile
                    .supported_scopes()
                    .binary_search(scope)
                    .is_err()
            })
        {
            return Err(BearerAuthenticationError);
        }

        let verified = self
            .verifier
            .verify(credential.as_str())
            .await
            .map_err(map_access_token_error)?;
        if &verified.audience != decision.audience() {
            return Err(BearerAuthenticationError);
        }
        McpAuthenticatedIdentity::from_verified_access_token(
            self.profile.issuer().clone(),
            verified,
        )
    }
}

fn map_access_token_error(_: AccessTokenVerificationError) -> BearerAuthenticationError {
    BearerAuthenticationError
}

impl<S, C> fmt::Debug for OAuthAccessTokenAuthenticator<S, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthAccessTokenAuthenticator")
            .field("resource", &self.profile.resource())
            .field("issuer", &self.profile.issuer())
            .field("verifier", &"[redacted]")
            .finish()
    }
}
