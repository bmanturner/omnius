//! Transport-neutral OAuth Authorization Server and `OpenID` Provider state machine.

use std::{future::Future, sync::Arc, time::Duration as StdDuration};

use omnius_auth_core::{AssuranceLevel, Principal, Scope, SubjectId};
use serde::Serialize;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    Clock,
    config::{ResourceDeclaration, ValidatedAuthorizationServerConfig},
    crypto::{
        AccessTokenClaims, AccessTokenClaimsInput, BearerDigest, BearerDigestDomain, IdTokenClaims,
        IdTokenClaimsInput, JwksDocument, digest_bearer, issue_bearer,
    },
    metadata::{
        AuthorizationServerMetadata, MetadataSnapshots, OpenIdProviderMetadata,
        ProtectedResourceMetadata,
    },
    types::{
        AuthorizationRequestInput, ClientId, EntropySource, GrantId, GrantType, IssuerUri, JwtId,
        MAX_JWT_BYTES, MAX_SCOPES, MAX_URI_BYTES, OpaqueBearer, PkceChallenge, PkceVerifier,
        Prompt, RedirectUri, ResourceUri, TokenEndpointAuthMethod,
    },
    verifier::{
        AccessTokenStateStore, AccessTokenVerificationError, AccessTokenVerifier, OAuthStoreError,
    },
};

const MAX_STATE_BYTES: usize = 1_024;
const MAX_ASSERTION_ID_BYTES: usize = 128;
const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 300;
const MAX_SECRET_BYTES: usize = 1_024;
const MAX_DISPLAY_TEXT_BYTES: usize = 1_024;
const USERINFO_PATH: &str = "/oauth/userinfo";
const TOKEN_PATH: &str = "/oauth/token";
const REDACTED: &str = "[REDACTED]";

/// OAuth/OIDC error codes emitted by the transport-neutral engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// A required parameter is absent, malformed, duplicated, or unsupported.
    InvalidRequest,
    /// The client identifier or client authentication is invalid.
    InvalidClient,
    /// The client is not permitted to use the requested endpoint or grant.
    UnauthorizedClient,
    /// The resource owner denied authorization.
    AccessDenied,
    /// The authorization response type is unsupported.
    UnsupportedResponseType,
    /// The requested scope set is invalid.
    InvalidScope,
    /// The requested resource indicator is invalid.
    InvalidTarget,
    /// The authorization code or refresh token is invalid.
    InvalidGrant,
    /// A bearer token presented to a protected endpoint is invalid.
    InvalidToken,
    /// Silent authorization requires authentication.
    LoginRequired,
    /// Silent authorization requires consent.
    ConsentRequired,
    /// A revocation token-type hint is unsupported.
    UnsupportedTokenType,
    /// The provider could not safely complete the request.
    ServerError,
}

/// A redirectable OAuth error after client and redirect validation succeeded.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationErrorRedirect {
    /// Exact registered redirect supplied by the validated request.
    pub redirect_uri: RedirectUri,
    /// Client state echoed byte-for-byte when supplied.
    pub state: Option<String>,
    /// Exact issuer added under RFC 9207.
    pub issuer: IssuerUri,
}

impl std::fmt::Debug for AuthorizationErrorRedirect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationErrorRedirect")
            .field("redirect_uri", &REDACTED)
            .field("state", &self.state.as_ref().map(|_| REDACTED))
            .field("issuer", &REDACTED)
            .finish()
    }
}

/// Stable protocol rejection with value-free diagnostics.
#[derive(Clone, Eq, Error, PartialEq)]
#[error("OAuth protocol request was rejected")]
pub struct ProtocolError {
    code: OAuthErrorCode,
    redirect: Option<AuthorizationErrorRedirect>,
}

impl ProtocolError {
    /// Returns the standard error code.
    #[must_use]
    pub const fn code(&self) -> OAuthErrorCode {
        self.code
    }

    /// Returns redirect data only after the redirect-safety gate passed.
    #[must_use]
    pub const fn redirect(&self) -> Option<&AuthorizationErrorRedirect> {
        self.redirect.as_ref()
    }

    fn endpoint(code: OAuthErrorCode) -> Self {
        Self {
            code,
            redirect: None,
        }
    }

    fn authorization(
        code: OAuthErrorCode,
        request: &AuthorizationRequestInput,
        issuer: &IssuerUri,
    ) -> Self {
        Self::authorization_redirect(
            code,
            request.redirect_uri().clone(),
            request.state().map(str::to_owned),
            issuer.clone(),
        )
    }

    fn authorization_redirect(
        code: OAuthErrorCode,
        redirect_uri: RedirectUri,
        state: Option<String>,
        issuer: IssuerUri,
    ) -> Self {
        Self {
            code,
            redirect: Some(AuthorizationErrorRedirect {
                redirect_uri,
                state,
                issuer,
            }),
        }
    }
}

impl std::fmt::Debug for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtocolError")
            .field("code", &self.code)
            .field("redirectable", &self.redirect.is_some())
            .finish()
    }
}

/// Explicit response sensitivity classification for transport adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseSensitivity {
    /// The response is safe for ordinary cache policy.
    Public,
    /// The response requires `Cache-Control: no-store` and `Pragma: no-cache`.
    NoStore,
}

/// Trusted, active client record resolved from pre-registration, DCR, or CIMD.
#[derive(Clone, Debug)]
pub struct ResolvedClient {
    /// Exact client identifier.
    pub client_id: ClientId,
    /// Safe bounded display name.
    pub display_name: String,
    /// Safe bounded display origin.
    pub display_origin: String,
    /// Exact registered authorization redirect URIs.
    pub redirect_uris: Vec<RedirectUri>,
    /// Exact registered post-logout redirect URIs.
    pub post_logout_redirect_uris: Vec<RedirectUri>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Registered grant types.
    pub grant_types: Vec<GrantType>,
    /// Maximum client-authorized scopes.
    pub scopes: Vec<Scope>,
    /// Maximum client-authorized resources.
    pub resources: Vec<ResourceUri>,
}

impl ResolvedClient {
    fn is_well_formed(&self) -> bool {
        !self.display_name.is_empty()
            && self.display_name.len() <= MAX_DISPLAY_TEXT_BYTES
            && !self.display_origin.is_empty()
            && self.display_origin.len() <= MAX_URI_BYTES
            && !self.redirect_uris.is_empty()
            && self.scopes.len() <= MAX_SCOPES
            && strictly_sorted(&self.scopes)
            && strictly_sorted(&self.resources)
    }

    fn matches_redirect(&self, requested: &RedirectUri) -> bool {
        self.redirect_uris
            .iter()
            .any(|registered| registered.matches_registered(requested))
    }
}

/// Minimal browser-session identity that must be revalidated by the store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionCandidate {
    /// Canonical internal user identifier.
    pub subject_id: SubjectId,
    /// Authentication time recorded by the browser session.
    pub authenticated_at: OffsetDateTime,
}

/// Live authorization subject returned by one store revalidation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSubject {
    /// Canonical internal principal.
    pub principal: Principal,
    /// Stable issuer-public subject.
    pub public_subject: String,
    /// Verified local email, when present.
    pub verified_email: Option<String>,
    /// Authentication context class reference.
    pub acr: String,
    /// Authentication method references.
    pub amr: Vec<String>,
}

/// Existing live grant potentially covering an authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExistingGrant {
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// Exact granted resource.
    pub resource: ResourceUri,
    /// Sorted granted scopes.
    pub scopes: Vec<Scope>,
    /// Whether offline access was explicitly consented.
    pub offline_access_consented: bool,
}

/// Query for a covering, currently live consent grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoveringGrantQuery {
    /// Canonical subject.
    pub subject_id: SubjectId,
    /// Tenant context resolved by the current browser session, when present.
    pub tenant_id: Option<omnius_auth_core::TenantId>,
    /// Exact client.
    pub client_id: ClientId,
    /// Exact effective resource.
    pub resource: ResourceUri,
    /// Requested scopes.
    pub scopes: Vec<Scope>,
}

/// Why the browser interaction cannot be completed silently.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum InteractionRequirement {
    /// Authentication or fresh reauthentication is required.
    Login,
    /// Explicit consent is required.
    Consent,
    /// A covering grant can be reused without displaying consent.
    Ready,
}

/// One safe scope description displayed by the consent UI.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InteractionScope {
    /// Exact scope token.
    pub name: Scope,
    /// Safe provider-authored description.
    pub description: String,
    /// Whether this scope is newly requested beyond an existing grant.
    pub newly_requested: bool,
}

/// Safe display data retained with an opaque authorization interaction.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationInteraction {
    /// Safe client name.
    pub client_name: String,
    /// Safe client origin.
    pub client_origin: String,
    /// Host of the already validated exact redirect URI.
    pub redirect_host: String,
    /// Exact target resource.
    pub resource: ResourceUri,
    /// Safe target resource name.
    pub resource_name: String,
    /// Safe target resource description.
    pub resource_description: String,
    /// Minimum resource assurance.
    pub minimum_assurance: AssuranceLevel,
    /// Requested scopes and existing-grant delta.
    pub scopes: Vec<InteractionScope>,
    /// Current interaction requirement.
    pub requirement: InteractionRequirement,
}

/// Durable authorization transaction content addressed only by a digest.
#[derive(Clone, Debug)]
pub struct StoredAuthorization {
    /// Validated protocol request.
    pub request: AuthorizationRequestInput,
    /// Resolved client snapshot.
    pub client: ResolvedClient,
    /// Effective resource, including the OIDC `UserInfo` audience default.
    pub resource: ResourceUri,
    /// Safe interaction display data.
    pub interaction: AuthorizationInteraction,
    /// Authentication time observed before a required reauthentication.
    pub authentication_time_before_login: Option<OffsetDateTime>,
    /// Expiry instant.
    pub expires_at: OffsetDateTime,
}

/// Atomic authorization transaction insertion.
#[derive(Clone, Debug)]
pub struct CreateAuthorization {
    /// HMAC digest of the opaque browser handle.
    pub handle_digest: BearerDigest,
    /// Durable transaction content.
    pub authorization: StoredAuthorization,
}

/// Opaque browser handle returned after persistence.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationHandle(String);

impl AuthorizationHandle {
    /// Borrows the exact canonical handle for an immediate response boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthorizationHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("AuthorizationHandle")
            .field(&REDACTED)
            .finish()
    }
}

/// Successful start of a persisted authorization interaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BegunAuthorization {
    /// Opaque handle whose digest alone is stored.
    pub handle: AuthorizationHandle,
    /// Requirement used by the browser application to select login or consent.
    pub requirement: InteractionRequirement,
    /// Interaction handles are sensitive and must not be cached.
    pub sensitivity: ResponseSensitivity,
}

/// Result of beginning authorization: either a browser interaction or direct grant reuse.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeginAuthorizationResult {
    /// Login or explicit consent must be completed using the opaque handle.
    Interaction(BegunAuthorization),
    /// A covering live grant was reused without displaying user interface.
    Redirect(AuthorizationRedirect),
}

/// User decision received from a same-origin, CSRF-protected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentDecision {
    /// Approve exactly the validated requested scope set.
    Approve,
    /// Deny the authorization request.
    Deny,
}

/// Atomic terminal authorization decision.
#[derive(Clone, Debug)]
pub struct CommitAuthorizationDecision {
    /// Authorization-request handle digest.
    pub handle_digest: BearerDigest,
    /// Live authorizing subject.
    pub subject: AuthorizationSubject,
    /// Approval or denial.
    pub decision: ConsentDecision,
    /// Generated authorization-code digest for approvals only.
    pub code_digest: Option<BearerDigest>,
    /// Authorization-code expiry for approvals only.
    pub code_expires_at: Option<OffsetDateTime>,
    /// Whether offline access was explicitly displayed and approved.
    pub explicit_offline_consent: bool,
    /// Whether approval is valid only while a covering grant remains live.
    pub require_existing_grant: bool,
}

/// Result of the atomic decision operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitDecisionOutcome {
    /// The request became terminal and its approval code was stored.
    Approved,
    /// The request became terminal as denied.
    Denied,
    /// The handle was missing, expired, or already terminal.
    Unavailable,
}

/// Server-owned authorization redirect response.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthorizationRedirect {
    /// Exact already validated redirect URI.
    pub redirect_uri: RedirectUri,
    /// Client state echoed byte-for-byte when supplied.
    pub state: Option<String>,
    /// Exact RFC 9207 issuer value.
    pub issuer: IssuerUri,
    /// Authorization code only on approval.
    pub code: Option<String>,
    /// Standard error only on denial.
    pub error: Option<OAuthErrorCode>,
}

impl std::fmt::Debug for AuthorizationRedirect {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationRedirect")
            .field("redirect_uri", &REDACTED)
            .field("state", &self.state.as_ref().map(|_| REDACTED))
            .field("issuer", &REDACTED)
            .field("has_code", &self.code.is_some())
            .field("error", &self.error)
            .finish()
    }
}

/// Bounded client secret presentation.
#[derive(Clone)]
pub struct ClientSecret(Zeroizing<String>);

impl ClientSecret {
    /// Validates and owns a client-secret presentation.
    ///
    /// # Errors
    ///
    /// Returns `invalid_client` when the secret is empty, exceeds the bounded
    /// presentation size, or contains control characters.
    pub fn parse(mut value: String) -> Result<Self, ProtocolError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES || value.chars().any(char::is_control)
        {
            value.zeroize();
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidClient));
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Borrows the secret only for the authentication store boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ClientSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("ClientSecret")
            .field(&REDACTED)
            .finish()
    }
}

/// Semantically decoded private-key JWT assertion plus its signed presentation.
#[derive(Clone)]
pub struct PrivateKeyJwtAssertion {
    token: Zeroizing<String>,
    /// Assertion issuer.
    pub issuer: ClientId,
    /// Assertion subject.
    pub subject: ClientId,
    /// Exact assertion audience.
    pub audience: String,
    /// One-use assertion identifier.
    pub jwt_id: String,
    /// Assertion issuance time.
    pub issued_at: OffsetDateTime,
    /// Assertion expiry.
    pub expires_at: OffsetDateTime,
}

impl PrivateKeyJwtAssertion {
    /// Constructs a bounded assertion model. Signature verification remains a store contract.
    ///
    /// # Errors
    ///
    /// Returns `invalid_client` when the signed presentation, audience, or JWT ID
    /// is empty, oversized, or contains characters prohibited by its field.
    pub fn new(
        mut token: String,
        issuer: ClientId,
        subject: ClientId,
        audience: String,
        jwt_id: String,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
    ) -> Result<Self, ProtocolError> {
        if token.is_empty()
            || token.len() > MAX_JWT_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
            || audience.is_empty()
            || audience.len() > MAX_URI_BYTES
            || jwt_id.is_empty()
            || jwt_id.len() > MAX_ASSERTION_ID_BYTES
            || jwt_id.chars().any(char::is_control)
        {
            token.zeroize();
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidClient));
        }
        Ok(Self {
            token: Zeroizing::new(token),
            issuer,
            subject,
            audience,
            jwt_id,
            issued_at,
            expires_at,
        })
    }

    /// Borrows the signed assertion only for registered-key verification.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for PrivateKeyJwtAssertion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateKeyJwtAssertion")
            .field("token", &REDACTED)
            .field("claims", &REDACTED)
            .finish()
    }
}

/// Mutually exclusive token-endpoint client authentication.
#[derive(Clone, Debug)]
pub enum ClientAuthentication {
    /// Public client authentication by client ID only.
    None {
        /// Exact public client identifier.
        client_id: ClientId,
    },
    /// Confidential HTTP Basic authentication.
    ClientSecretBasic {
        /// Exact confidential client identifier.
        client_id: ClientId,
        /// Bounded client-secret presentation.
        secret: ClientSecret,
    },
    /// Registered-key JWT authentication.
    PrivateKeyJwt {
        /// Exact registered-key client identifier.
        client_id: ClientId,
        /// Parsed assertion and its signed presentation.
        assertion: PrivateKeyJwtAssertion,
    },
}

impl ClientAuthentication {
    /// Exact client identifier selected by the sole authentication method.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        match self {
            Self::None { client_id }
            | Self::ClientSecretBasic { client_id, .. }
            | Self::PrivateKeyJwt { client_id, .. } => client_id,
        }
    }
}

/// Raw authentication slots used to reject duplicate or mixed client credentials.
#[derive(Clone, Debug)]
pub struct ClientAuthenticationParts {
    /// Public body client ID, mutually exclusive with confidential credentials.
    pub public_client_id: Option<ClientId>,
    /// HTTP Basic client ID and secret.
    pub basic: Option<(ClientId, ClientSecret)>,
    /// Private-key assertion client ID and assertion.
    pub private_key_jwt: Option<(ClientId, PrivateKeyJwtAssertion)>,
}

impl TryFrom<ClientAuthenticationParts> for ClientAuthentication {
    type Error = ProtocolError;

    fn try_from(parts: ClientAuthenticationParts) -> Result<Self, Self::Error> {
        match (parts.public_client_id, parts.basic, parts.private_key_jwt) {
            (Some(client_id), None, None) => Ok(Self::None { client_id }),
            (None, Some((client_id, secret)), None) => {
                Ok(Self::ClientSecretBasic { client_id, secret })
            }
            (None, None, Some((client_id, assertion))) => Ok(Self::PrivateKeyJwt {
                client_id,
                assertion,
            }),
            _ => Err(ProtocolError::endpoint(OAuthErrorCode::InvalidClient)),
        }
    }
}

/// Authorization-code token request.
#[derive(Clone)]
pub struct AuthorizationCodeTokenRequest {
    /// Sole client authentication.
    pub client_authentication: ClientAuthentication,
    /// Opaque authorization code presentation.
    pub code: String,
    /// Exact redirect URI used at authorization.
    pub redirect_uri: RedirectUri,
    /// S256 verifier.
    pub code_verifier: PkceVerifier,
    /// Exact resource used at authorization, or omitted for an OIDC-only `UserInfo` grant.
    pub resource: Option<ResourceUri>,
}

impl std::fmt::Debug for AuthorizationCodeTokenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationCodeTokenRequest")
            .field("client_authentication", &REDACTED)
            .field("code", &REDACTED)
            .field("redirect_uri", &REDACTED)
            .field("code_verifier", &REDACTED)
            .field("resource", &self.resource.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Refresh-token request with optional narrowing.
#[derive(Clone)]
pub struct RefreshTokenRequest {
    /// Sole client authentication.
    pub client_authentication: ClientAuthentication,
    /// Opaque refresh token presentation.
    pub refresh_token: String,
    /// Optional scope subset; absence retains the original set.
    pub scopes: Option<Vec<Scope>>,
    /// Optional identical resource; absence retains the original resource.
    pub resource: Option<ResourceUri>,
}

impl std::fmt::Debug for RefreshTokenRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshTokenRequest")
            .field("client_authentication", &REDACTED)
            .field("refresh_token", &REDACTED)
            .field("scope_count", &self.scopes.as_ref().map(Vec::len))
            .field("resource", &self.resource.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Token endpoint request variants implemented by the provider.
#[derive(Clone, Debug)]
pub enum TokenRequest {
    /// Authorization-code exchange.
    AuthorizationCode(AuthorizationCodeTokenRequest),
    /// Refresh rotation.
    RefreshToken(RefreshTokenRequest),
}

/// A recognized authorization code consumed atomically before binding checks.
#[derive(Clone, Debug)]
pub struct ConsumedAuthorizationCode {
    /// Bound client.
    pub client_id: ClientId,
    /// Exact authorization redirect.
    pub redirect_uri: RedirectUri,
    /// Exact effective resource.
    pub resource: ResourceUri,
    /// Stored S256 challenge.
    pub pkce_challenge: PkceChallenge,
    /// Token issuance context.
    pub context: TokenGrantContext,
}

/// Atomic code-consumption request.
#[derive(Clone, Debug)]
pub struct ConsumeAuthorizationCode {
    /// Authorization-code digest.
    pub code_digest: BearerDigest,
    /// Authenticated client binding.
    pub client_id: ClientId,
    /// Exact redirect binding.
    pub redirect_uri: RedirectUri,
    /// Exact resource binding.
    pub resource: ResourceUri,
    /// S256 verifier checked before the recognized code transaction commits.
    pub pkce_verifier: PkceVerifier,
    /// Replacement refresh digest, persisted only when offline access was consented.
    pub refresh_digest: BearerDigest,
    /// Replacement refresh expiry.
    pub refresh_expires_at: OffsetDateTime,
    /// Exchange time.
    pub now: OffsetDateTime,
}

/// Atomic code-consumption result.
#[derive(Clone, Debug)]
pub enum ConsumeCodeOutcome {
    /// A recognized code was consumed and its bindings returned for mandatory checks.
    Consumed(Box<ConsumedAuthorizationCode>),
    /// The code was unknown, expired, or already consumed.
    Unavailable,
}

/// Immutable context used to mint access and ID tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenGrantContext {
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// Exact client.
    pub client_id: ClientId,
    /// Stable issuer-public subject.
    pub public_subject: String,
    /// Exact resource audience.
    pub resource: ResourceUri,
    /// Sorted granted scopes.
    pub scopes: Vec<Scope>,
    /// Authentication time.
    pub auth_time: OffsetDateTime,
    /// Authentication context class reference.
    pub acr: String,
    /// Authentication method references.
    pub amr: Vec<String>,
    /// Authorization nonce.
    pub nonce: Option<String>,
    /// Verified local email, when present.
    pub verified_email: Option<String>,
    /// Whether a refresh family was explicitly consented and activated.
    pub refresh_allowed: bool,
}

/// Atomic refresh rotation input.
#[derive(Clone, Debug)]
pub struct RotateRefreshToken {
    /// Presented refresh digest.
    pub presented_digest: BearerDigest,
    /// Authenticated client.
    pub client_id: ClientId,
    /// Requested scope subset, or `None` to retain the original set.
    pub scopes: Option<Vec<Scope>>,
    /// Requested resource, or `None` to retain the original resource.
    pub resource: Option<ResourceUri>,
    /// Replacement digest.
    pub replacement_digest: BearerDigest,
    /// Replacement expiry.
    pub replacement_expires_at: OffsetDateTime,
    /// Rotation time.
    pub now: OffsetDateTime,
}

/// Atomic refresh rotation result.
#[derive(Clone, Debug)]
pub enum RotateRefreshOutcome {
    /// Rotation succeeded and the old member is permanently consumed.
    Rotated(Box<TokenGrantContext>),
    /// A consumed family member was reused; the store revoked its family and grant.
    ReuseDetected,
    /// The token was unknown, expired, revoked, or bound to another client.
    Unavailable,
}

/// OAuth token response. Diagnostics never reveal credential values.
#[derive(Clone, Eq, PartialEq, Serialize)]
pub struct TokenResponse {
    /// Signed `at+jwt` access token.
    pub access_token: String,
    /// Bearer token type.
    pub token_type: String,
    /// Access-token lifetime in seconds.
    pub expires_in: u64,
    /// Sorted granted scopes.
    pub scopes: Vec<Scope>,
    /// Rotating refresh token only for explicitly consented offline access.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// ID Token only when `openid` is granted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Required transport cache policy.
    #[serde(skip)]
    pub sensitivity: ResponseSensitivity,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("access_token", &REDACTED)
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope_count", &self.scopes.len())
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_id_token", &self.id_token.is_some())
            .field("sensitivity", &self.sensitivity)
            .finish()
    }
}

/// Supported RFC 7009 token-type hints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenTypeHint {
    /// JWT access token.
    AccessToken,
    /// Opaque refresh token.
    RefreshToken,
    /// An unsupported hint.
    Unsupported,
}

/// Bounded revocation request.
#[derive(Clone)]
pub struct RevocationRequest {
    /// Sole client authentication.
    pub client_authentication: ClientAuthentication,
    /// Credential presentation. Debug output is redacted by the request implementation.
    pub token: String,
    /// Optional token-type hint.
    pub token_type_hint: Option<TokenTypeHint>,
    /// Exact audience needed to validate a JWT access token.
    pub audience: Option<ResourceUri>,
}

impl std::fmt::Debug for RevocationRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RevocationRequest")
            .field("client_authentication", &REDACTED)
            .field("token", &REDACTED)
            .field("token_type_hint", &self.token_type_hint)
            .field("audience", &self.audience.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Store-owned revocation target.
#[derive(Clone, Debug)]
pub enum RevocationTarget {
    /// Valid access token owned by the authenticated client.
    AccessToken {
        /// Access-token JWT identifier.
        jwt_id: JwtId,
        /// Grant bound to the access token.
        grant_id: GrantId,
    },
    /// Opaque refresh token digest.
    RefreshToken(BearerDigest),
}

/// RFC 7009 success response, including unknown-token submissions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationResponse {
    /// Revocation responses are sensitive even though their body is empty.
    pub sensitivity: ResponseSensitivity,
}

/// Safe connected-grant list item.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConnectedGrant {
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// Safe client display name.
    pub client_name: String,
    /// Exact resource.
    pub resource: ResourceUri,
    /// Sorted granted scopes.
    pub scopes: Vec<Scope>,
    /// Consent time.
    pub consented_at: OffsetDateTime,
}

/// OIDC `UserInfo` response for implemented scopes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct UserInfoResponse {
    /// Stable issuer-public subject, identical to the ID Token subject.
    pub sub: String,
    /// Verified email only under the `email` scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Present and true exactly when email is released.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    /// `UserInfo` is a bearer-protected response.
    #[serde(skip)]
    pub sensitivity: ResponseSensitivity,
}

/// Bounded ID Token hint used by RP-Initiated Logout.
#[derive(Clone)]
pub struct IdTokenHint {
    token: Zeroizing<String>,
    /// Untrusted client audience used only to select the full verifier.
    pub client_id: ClientId,
    /// Untrusted nonce passed to full signed-claim validation.
    pub nonce: Option<String>,
}

impl IdTokenHint {
    /// Owns a bounded encoded ID Token hint.
    ///
    /// # Errors
    ///
    /// Returns `invalid_request` when the hint is empty, exceeds the JWT size
    /// bound, contains whitespace, or carries an invalid nonce.
    pub fn new(
        mut token: String,
        client_id: ClientId,
        nonce: Option<String>,
    ) -> Result<Self, ProtocolError> {
        if token.is_empty()
            || token.len() > MAX_JWT_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
            || nonce
                .as_ref()
                .is_some_and(|value| !bounded_text(value, MAX_STATE_BYTES))
        {
            token.zeroize();
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        Ok(Self {
            token: Zeroizing::new(token),
            client_id,
            nonce,
        })
    }

    fn token(&self) -> &str {
        &self.token
    }
}

impl std::fmt::Debug for IdTokenHint {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("IdTokenHint")
            .field(&REDACTED)
            .finish()
    }
}

/// RP-Initiated Logout request associated with the current browser session.
#[derive(Clone, Debug)]
pub struct LogoutRequest {
    /// Current canonical browser-session subject.
    pub subject_id: SubjectId,
    /// Recommended ID Token hint.
    pub id_token_hint: Option<IdTokenHint>,
    /// Optional exact registered post-logout redirect.
    pub post_logout_redirect_uri: Option<RedirectUri>,
    /// State returned only with a validated redirect.
    pub state: Option<String>,
}

/// Browser-session logout binding that the application session authority must validate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutSession {
    /// Current canonical browser-session subject.
    pub subject_id: SubjectId,
    /// Signed public subject from the hint, when supplied.
    pub public_subject: Option<String>,
}

/// Validated logout result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogoutResponse {
    /// Exact registered redirect, only after hint and registration validation.
    pub redirect_uri: Option<RedirectUri>,
    /// State returned only alongside a valid redirect.
    pub state: Option<String>,
    /// Logout responses must not be cached.
    pub sensitivity: ResponseSensitivity,
}

/// Complete durable protocol contract required by the state machine.
///
/// Mutating methods must write their matching audit event in the same transaction.
/// `consume_authorization_code` must consume every recognized code even when the
/// caller later rejects a binding. `rotate_refresh_token` must revoke the family,
/// grant, and emit the refresh-reuse security event atomically on reuse.
pub trait AuthorizationStore: AccessTokenStateStore {
    /// Resolves only active pre-registered, dynamic, or validated CIMD clients.
    fn resolve_client(
        &self,
        client_id: &ClientId,
    ) -> impl Future<Output = Result<Option<ResolvedClient>, OAuthStoreError>> + Send;

    /// Rechecks active user, authentication version, and tenant membership.
    fn authorize_session(
        &self,
        candidate: SessionCandidate,
    ) -> impl Future<Output = Result<Option<AuthorizationSubject>, OAuthStoreError>> + Send;

    /// Finds one covering, unrevoked consent grant.
    fn find_covering_grant(
        &self,
        query: CoveringGrantQuery,
    ) -> impl Future<Output = Result<Option<ExistingGrant>, OAuthStoreError>> + Send;

    /// Atomically persists a new authorization request and matching audit record.
    fn create_authorization(
        &self,
        command: CreateAuthorization,
    ) -> impl Future<Output = Result<(), OAuthStoreError>> + Send;

    /// Loads one unexpired, non-terminal authorization by its handle digest.
    fn load_authorization(
        &self,
        handle_digest: BearerDigest,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<Option<StoredAuthorization>, OAuthStoreError>> + Send;

    /// Atomically makes an authorization request terminal and audits approve or deny.
    fn commit_authorization_decision(
        &self,
        command: CommitAuthorizationDecision,
    ) -> impl Future<Output = Result<CommitDecisionOutcome, OAuthStoreError>> + Send;

    /// Constant-time confidential client-secret authentication.
    fn authenticate_client_secret(
        &self,
        client_id: &ClientId,
        secret: &str,
    ) -> impl Future<Output = Result<bool, OAuthStoreError>> + Send;

    /// Verifies a registered public-key signature and atomically inserts the JTI replay row.
    fn accept_private_key_assertion(
        &self,
        client_id: &ClientId,
        assertion: &PrivateKeyJwtAssertion,
    ) -> impl Future<Output = Result<bool, OAuthStoreError>> + Send;

    /// Atomically consumes a recognized code, including failed-binding attempts.
    fn consume_authorization_code(
        &self,
        command: ConsumeAuthorizationCode,
    ) -> impl Future<Output = Result<ConsumeCodeOutcome, OAuthStoreError>> + Send;

    /// Atomically rotates a refresh member or revokes its family and grant on reuse.
    fn rotate_refresh_token(
        &self,
        command: RotateRefreshToken,
    ) -> impl Future<Output = Result<RotateRefreshOutcome, OAuthStoreError>> + Send;

    /// Atomically revokes the target and matching grant/family state when applicable.
    fn revoke_token(
        &self,
        client_id: &ClientId,
        target: RevocationTarget,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<(), OAuthStoreError>> + Send;

    /// Lists safe connected-grant metadata after current subject authorization.
    fn list_connected_grants(
        &self,
        subject_id: SubjectId,
    ) -> impl Future<Output = Result<Vec<ConnectedGrant>, OAuthStoreError>> + Send;

    /// Atomically revokes a subject-owned grant, refresh family, and matching audit state.
    fn revoke_connected_grant(
        &self,
        subject_id: SubjectId,
        grant_id: GrantId,
    ) -> impl Future<Output = Result<bool, OAuthStoreError>> + Send;

    /// Validates the stable public-subject and current browser-session binding.
    ///
    /// Cookie clearing and provider-session mutation remain transport/application actions.
    fn logout_session(
        &self,
        command: LogoutSession,
    ) -> impl Future<Output = Result<bool, OAuthStoreError>> + Send;
}

/// Transport-neutral OAuth Authorization Server and `OpenID` Provider orchestration.
pub struct AuthorizationServer<S, C, E> {
    config: Arc<ValidatedAuthorizationServerConfig>,
    metadata: MetadataSnapshots,
    store: Arc<S>,
    clock: Arc<C>,
    entropy: Arc<E>,
}

struct AuthorizationPreparation {
    now: OffsetDateTime,
    client: ResolvedClient,
    subject: Option<AuthorizationSubject>,
    resource: ResourceUri,
    existing_grant: Option<ExistingGrant>,
    requirement: InteractionRequirement,
    requires_login: bool,
}

impl<S, C, E> Clone for AuthorizationServer<S, C, E> {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            metadata: self.metadata.clone(),
            store: Arc::clone(&self.store),
            clock: Arc::clone(&self.clock),
            entropy: Arc::clone(&self.entropy),
        }
    }
}

impl<S, C, E> std::fmt::Debug for AuthorizationServer<S, C, E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationServer")
            .field("issuer", &self.config.issuer())
            .finish_non_exhaustive()
    }
}

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
    /// Constructs the state machine from validated immutable dependencies.
    #[must_use]
    pub fn new(
        config: Arc<ValidatedAuthorizationServerConfig>,
        store: Arc<S>,
        clock: Arc<C>,
        entropy: Arc<E>,
    ) -> Self {
        let metadata = MetadataSnapshots::new(&config);
        Self {
            config,
            metadata,
            store,
            clock,
            entropy,
        }
    }

    /// Builds a redirect-bound protocol error only after resolving the client and
    /// exact registered redirect URI.
    pub async fn authorization_request_error(
        &self,
        client_id: &ClientId,
        redirect_uri: &RedirectUri,
        state: Option<&str>,
        code: OAuthErrorCode,
    ) -> ProtocolError {
        let client = match self.store.resolve_client(client_id).await {
            Ok(Some(client)) if client.is_well_formed() => client,
            Ok(None | Some(_)) => {
                return ProtocolError::endpoint(OAuthErrorCode::InvalidClient);
            }
            Err(_) => return ProtocolError::endpoint(OAuthErrorCode::ServerError),
        };
        if !client.matches_redirect(redirect_uri) {
            return ProtocolError::endpoint(OAuthErrorCode::InvalidRequest);
        }
        let state = state
            .filter(|value| bounded_text(value, MAX_STATE_BYTES))
            .map(str::to_owned);
        ProtocolError::authorization_redirect(
            code,
            redirect_uri.clone(),
            state,
            self.config.issuer().clone(),
        )
    }

    /// Validates redirect safety first and persists an opaque authorization interaction.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the client, redirect, issuer, scopes, resource,
    /// prompt, or session cannot be accepted, or when secure issuance or persistence fails.
    pub async fn begin_authorization(
        &self,
        request: AuthorizationRequestInput,
        session: Option<SessionCandidate>,
    ) -> Result<BeginAuthorizationResult, ProtocolError> {
        let AuthorizationPreparation {
            now,
            client,
            subject,
            resource,
            existing_grant,
            requirement,
            requires_login,
        } = self.prepare_authorization(&request, session).await?;
        let interaction = self.interaction_display(
            &request,
            &client,
            &resource,
            existing_grant.as_ref(),
            requirement,
        )?;
        let issued = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::AuthorizationRequest,
        )
        .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
        let expires_at = add_std(now, self.config.authorization_request_ttl())
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
        let handle_digest = issued.digest;
        self.store
            .create_authorization(CreateAuthorization {
                handle_digest: handle_digest.clone(),
                authorization: StoredAuthorization {
                    request: request.clone(),
                    client,
                    resource,
                    interaction,
                    authentication_time_before_login: if requires_login {
                        subject
                            .as_ref()
                            .map(|value| value.principal.authenticated_at)
                    } else {
                        None
                    },
                    expires_at,
                },
            })
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        if requirement == InteractionRequirement::Ready {
            let subject = subject
                .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, &request))?;
            return self
                .complete_ready_authorization(&request, subject, handle_digest, now)
                .await;
        }
        Ok(BeginAuthorizationResult::Interaction(BegunAuthorization {
            handle: AuthorizationHandle(issued.presentation.expose_once()),
            requirement,
            sensitivity: ResponseSensitivity::NoStore,
        }))
    }

    async fn prepare_authorization(
        &self,
        request: &AuthorizationRequestInput,
        session: Option<SessionCandidate>,
    ) -> Result<AuthorizationPreparation, ProtocolError> {
        let client = self
            .store
            .resolve_client(request.client_id())
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .filter(ResolvedClient::is_well_formed)
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidClient))?;
        if !client.matches_redirect(request.redirect_uri()) {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        if request
            .expected_issuer()
            .is_some_and(|issuer| issuer != self.config.issuer())
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidRequest, request));
        }
        self.validate_authorization_request(request, &client)?;
        let now = self.clock.now_utc();
        let subject = match session {
            Some(candidate) => self
                .store
                .authorize_session(candidate)
                .await
                .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?,
            None => None,
        };
        let resource = self.effective_resource(request)?;
        let minimum_assurance = self.minimum_assurance(&resource);
        let requires_login = subject.as_ref().is_none_or(|subject| {
            request.prompt() == Some(Prompt::Login)
                || subject.principal.assurance < minimum_assurance
                || request.max_age_seconds().is_some_and(|max_age| {
                    max_age == 0
                        || now - subject.principal.authenticated_at > duration_seconds(max_age)
                })
        });
        let existing_grant = if requires_login {
            None
        } else {
            let subject_id = subject
                .as_ref()
                .map(|value| value.principal.subject_id)
                .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
            self.store
                .find_covering_grant(CoveringGrantQuery {
                    subject_id,
                    tenant_id: subject.as_ref().and_then(|value| value.principal.tenant_id),
                    client_id: client.client_id.clone(),
                    resource: resource.clone(),
                    scopes: request.scopes().to_vec(),
                })
                .await
                .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?
        };
        let explicit_consent = request.prompt() == Some(Prompt::Consent)
            || has_scope(request.scopes(), "offline_access");
        let requirement = if requires_login {
            InteractionRequirement::Login
        } else if explicit_consent || existing_grant.is_none() {
            InteractionRequirement::Consent
        } else {
            InteractionRequirement::Ready
        };
        if request.prompt() == Some(Prompt::None) && requirement != InteractionRequirement::Ready {
            let code = if requirement == InteractionRequirement::Login {
                OAuthErrorCode::LoginRequired
            } else {
                OAuthErrorCode::ConsentRequired
            };
            return Err(self.authorization_error(code, request));
        }
        Ok(AuthorizationPreparation {
            now,
            client,
            subject,
            resource,
            existing_grant,
            requirement,
            requires_login,
        })
    }

    async fn complete_ready_authorization(
        &self,
        request: &AuthorizationRequestInput,
        subject: AuthorizationSubject,
        handle_digest: BearerDigest,
        now: OffsetDateTime,
    ) -> Result<BeginAuthorizationResult, ProtocolError> {
        let code = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::AuthorizationCode,
        )
        .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let code_expires_at = add_std(now, self.config.authorization_code_ttl())
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let outcome = self
            .store
            .commit_authorization_decision(CommitAuthorizationDecision {
                handle_digest,
                subject,
                decision: ConsentDecision::Approve,
                code_digest: Some(code.digest),
                code_expires_at: Some(code_expires_at),
                explicit_offline_consent: false,
                require_existing_grant: true,
            })
            .await
            .map_err(|_| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        if outcome != CommitDecisionOutcome::Approved {
            return Err(self.authorization_error(OAuthErrorCode::ServerError, request));
        }
        Ok(BeginAuthorizationResult::Redirect(AuthorizationRedirect {
            redirect_uri: request.redirect_uri().clone(),
            state: request.state().map(str::to_owned),
            issuer: self.config.issuer().clone(),
            code: Some(code.presentation.expose_once()),
            error: None,
        }))
    }

    /// Returns only provider-validated display data for an opaque interaction handle.
    ///
    /// # Errors
    ///
    /// Returns `invalid_request` for a malformed, unknown, expired, or terminal handle,
    /// and `server_error` when digesting or loading the interaction fails.
    pub async fn interaction(
        &self,
        handle: &str,
    ) -> Result<AuthorizationInteraction, ProtocolError> {
        let (_, digest) = self.parse_bearer(handle, BearerDigestDomain::AuthorizationRequest)?;
        self.store
            .load_authorization(digest, self.clock.now_utc())
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .map(|authorization| authorization.interaction)
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))
    }

    /// Revalidates the session and atomically approves or denies one interaction.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when the handle is invalid or unavailable, the session
    /// cannot satisfy the interaction, issuance fails, or the decision cannot be committed.
    pub async fn decide(
        &self,
        handle: &str,
        session: SessionCandidate,
        decision: ConsentDecision,
    ) -> Result<AuthorizationRedirect, ProtocolError> {
        let (_, handle_digest) =
            self.parse_bearer(handle, BearerDigestDomain::AuthorizationRequest)?;
        let now = self.clock.now_utc();
        let authorization = self
            .store
            .load_authorization(handle_digest.clone(), now)
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
        let subject = self
            .store
            .authorize_session(session)
            .await
            .map_err(|_| {
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            })?
            .ok_or_else(|| {
                self.authorization_error(OAuthErrorCode::LoginRequired, &authorization.request)
            })?;
        let stale_login = authorization
            .authentication_time_before_login
            .is_some_and(|before| subject.principal.authenticated_at <= before);
        let stale_max_age = authorization
            .request
            .max_age_seconds()
            .is_some_and(|max_age| {
                max_age != 0 && now - subject.principal.authenticated_at > duration_seconds(max_age)
            });
        if stale_login
            || stale_max_age
            || subject.principal.assurance < self.minimum_assurance(&authorization.resource)
        {
            return Err(
                self.authorization_error(OAuthErrorCode::LoginRequired, &authorization.request)
            );
        }
        let code = if decision == ConsentDecision::Approve {
            Some(
                issue_bearer(
                    self.entropy.as_ref(),
                    self.config.token_pepper(),
                    BearerDigestDomain::AuthorizationCode,
                )
                .map_err(|_| {
                    self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
                })?,
            )
        } else {
            None
        };
        let command = CommitAuthorizationDecision {
            handle_digest,
            subject,
            decision,
            code_digest: code.as_ref().map(|issued| issued.digest.clone()),
            code_expires_at: if code.is_some() {
                add_std(now, self.config.authorization_code_ttl())
            } else {
                None
            },
            explicit_offline_consent: decision == ConsentDecision::Approve
                && has_scope(authorization.request.scopes(), "offline_access")
                && authorization.request.prompt() == Some(Prompt::Consent),
            require_existing_grant: false,
        };
        if code.is_some() && command.code_expires_at.is_none() {
            return Err(
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            );
        }
        let outcome = self
            .store
            .commit_authorization_decision(command)
            .await
            .map_err(|_| {
                self.authorization_error(OAuthErrorCode::ServerError, &authorization.request)
            })?;
        let (code, error) = match (decision, outcome, code) {
            (ConsentDecision::Approve, CommitDecisionOutcome::Approved, Some(code)) => {
                (Some(code.presentation.expose_once()), None)
            }
            (ConsentDecision::Deny, CommitDecisionOutcome::Denied, None) => {
                (None, Some(OAuthErrorCode::AccessDenied))
            }
            _ => return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest)),
        };
        Ok(AuthorizationRedirect {
            redirect_uri: authorization.request.redirect_uri().clone(),
            state: authorization.request.state().map(str::to_owned),
            issuer: self.config.issuer().clone(),
            code,
            error,
        })
    }

    /// Exchanges a code or rotates a refresh token without broadening any binding.
    ///
    /// # Errors
    ///
    /// Returns a protocol error when client authentication fails, the grant presentation
    /// or binding is invalid, refresh reuse is detected, or secure issuance or storage fails.
    pub async fn token(&self, request: TokenRequest) -> Result<TokenResponse, ProtocolError> {
        match request {
            TokenRequest::AuthorizationCode(request) => self.exchange_code(request).await,
            TokenRequest::RefreshToken(request) => self.refresh(request).await,
        }
    }

    /// Revokes access or refresh state while preserving RFC 7009 unknown-token success.
    ///
    /// # Errors
    ///
    /// Returns `unsupported_token_type` for an unsupported hint, `invalid_client` when
    /// client authentication fails, or `server_error` when authentication or revocation
    /// storage is unavailable.
    pub async fn revoke(
        &self,
        request: RevocationRequest,
    ) -> Result<RevocationResponse, ProtocolError> {
        if request.token_type_hint == Some(TokenTypeHint::Unsupported) {
            return Err(ProtocolError::endpoint(
                OAuthErrorCode::UnsupportedTokenType,
            ));
        }
        if request.token.is_empty() || request.token.len() > MAX_JWT_BYTES {
            return Ok(RevocationResponse {
                sensitivity: ResponseSensitivity::NoStore,
            });
        }
        let client = self
            .authenticate_client(&request.client_authentication)
            .await?;
        let target = match request.token_type_hint {
            Some(TokenTypeHint::RefreshToken) => self.refresh_revocation_target(&request.token),
            Some(TokenTypeHint::AccessToken) => self
                .access_revocation_target(&request.token, request.audience.as_ref(), &client)
                .ok(),
            None => self.refresh_revocation_target(&request.token).or_else(|| {
                self.access_revocation_target(&request.token, request.audience.as_ref(), &client)
                    .ok()
            }),
            Some(TokenTypeHint::Unsupported) => None,
        };
        if let Some(target) = target {
            self.store
                .revoke_token(&client.client_id, target, self.clock.now_utc())
                .await
                .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        }
        Ok(RevocationResponse {
            sensitivity: ResponseSensitivity::NoStore,
        })
    }

    /// Lists currently connected grants for the canonical subject.
    ///
    /// # Errors
    ///
    /// Returns `server_error` when connected-grant storage is unavailable.
    pub async fn connected_grants(
        &self,
        subject_id: SubjectId,
    ) -> Result<Vec<ConnectedGrant>, ProtocolError> {
        self.store
            .list_connected_grants(subject_id)
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
    }

    /// Revokes one subject-owned connected grant and all derived refresh/access authority.
    ///
    /// # Errors
    ///
    /// Returns `server_error` when connected-grant storage is unavailable.
    pub async fn revoke_connected_grant(
        &self,
        subject_id: SubjectId,
        grant_id: GrantId,
    ) -> Result<bool, ProtocolError> {
        self.store
            .revoke_connected_grant(subject_id, grant_id)
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
    }

    /// Verifies a `UserInfo`-audience token and releases only scope-covered claims.
    ///
    /// # Errors
    ///
    /// Returns `invalid_token` when the token is invalid, inactive, or lacks `openid`,
    /// and `server_error` when verifier configuration or live-state storage fails.
    pub async fn userinfo(&self, access_token: &str) -> Result<UserInfoResponse, ProtocolError> {
        let audience = self.userinfo_audience()?;
        let access_token_verifier = AccessTokenVerifier::new(
            Arc::new(self.config.signing_keys().clone()),
            self.config.issuer().clone(),
            audience,
            vec![scope("email")?, scope("offline_access")?, scope("openid")?],
            Arc::clone(&self.store),
            Arc::clone(&self.clock),
        )
        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let verified_token = access_token_verifier
            .verify(access_token)
            .await
            .map_err(|error| match error {
                AccessTokenVerificationError::StoreUnavailable => {
                    ProtocolError::endpoint(OAuthErrorCode::ServerError)
                }
                AccessTokenVerificationError::InvalidToken
                | AccessTokenVerificationError::Inactive => {
                    ProtocolError::endpoint(OAuthErrorCode::InvalidToken)
                }
            })?;
        if !has_scope(&verified_token.scopes, "openid") {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidToken));
        }
        let email = has_scope(&verified_token.scopes, "email")
            .then_some(verified_token.verified_email)
            .flatten();
        Ok(UserInfoResponse {
            sub: verified_token.public_subject,
            email_verified: email.as_ref().map(|_| true),
            email,
            sensitivity: ResponseSensitivity::NoStore,
        })
    }

    /// Validates an optional ID Token hint and exact post-logout redirect before logout.
    ///
    /// # Errors
    ///
    /// Returns `invalid_request` when the state, hint, client, redirect, signed claims,
    /// or session binding is invalid, and `server_error` when session storage fails.
    pub async fn logout(&self, request: LogoutRequest) -> Result<LogoutResponse, ProtocolError> {
        if request
            .state
            .as_ref()
            .is_some_and(|state| !bounded_text(state, MAX_STATE_BYTES))
        {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        if request.post_logout_redirect_uri.is_some() && request.id_token_hint.is_none() {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        let (public_subject, redirect_uri) = if let Some(hint) = request.id_token_hint.as_ref() {
            let client = self
                .store
                .resolve_client(&hint.client_id)
                .await
                .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
                .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
            let claims = self
                .config
                .signing_keys()
                .verify_id_token(
                    hint.token(),
                    self.config.issuer(),
                    &hint.client_id,
                    hint.nonce.as_deref(),
                    self.clock.now_utc(),
                )
                .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
            let redirect = match request.post_logout_redirect_uri.as_ref() {
                Some(requested)
                    if client
                        .post_logout_redirect_uris
                        .iter()
                        .any(|registered| registered == requested) =>
                {
                    Some(requested.clone())
                }
                Some(_) => return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest)),
                None => None,
            };
            (Some(claims.subject().to_owned()), redirect)
        } else {
            (None, None)
        };
        let logged_out = self
            .store
            .logout_session(LogoutSession {
                subject_id: request.subject_id,
                public_subject,
            })
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        if !logged_out {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        Ok(LogoutResponse {
            state: redirect_uri.as_ref().and(request.state),
            redirect_uri,
            sensitivity: ResponseSensitivity::NoStore,
        })
    }

    /// Immutable RFC 8414 metadata snapshot.
    #[must_use]
    pub fn authorization_server_metadata(&self) -> &AuthorizationServerMetadata {
        self.metadata.authorization_server()
    }

    /// Immutable `OpenID` Provider discovery snapshot.
    #[must_use]
    pub fn openid_provider_metadata(&self) -> &OpenIdProviderMetadata {
        self.metadata.openid_provider()
    }

    /// Immutable protected-resource metadata for one exact audience.
    #[must_use]
    pub fn protected_resource_metadata(
        &self,
        resource: &str,
    ) -> Option<&ProtectedResourceMetadata> {
        self.metadata.protected_resource(resource)
    }

    /// Public JWKS with expired retiring keys removed at request time.
    #[must_use]
    pub fn jwks(&self) -> JwksDocument {
        self.config.signing_keys().jwks(self.clock.now_utc())
    }

    async fn exchange_code(
        &self,
        request: AuthorizationCodeTokenRequest,
    ) -> Result<TokenResponse, ProtocolError> {
        let client = self
            .authenticate_client(&request.client_authentication)
            .await?;
        let resource = request
            .resource
            .clone()
            .map_or_else(|| self.userinfo_audience(), Ok)?;
        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        }
        let (_, code_digest) = self
            .parse_bearer(&request.code, BearerDigestDomain::AuthorizationCode)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidGrant))?;
        let replacement = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::RefreshToken,
        )
        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let now = self.clock.now_utc();
        let refresh_expires_at = add_std(now, self.config.refresh_token_ttl())
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let consumed = self
            .store
            .consume_authorization_code(ConsumeAuthorizationCode {
                code_digest,
                client_id: client.client_id.clone(),
                redirect_uri: request.redirect_uri.clone(),
                resource: resource.clone(),
                pkce_verifier: request.code_verifier.clone(),
                refresh_digest: replacement.digest,
                refresh_expires_at,
                now,
            })
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let ConsumeCodeOutcome::Consumed(consumed) = consumed else {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        };
        let consumed = *consumed;
        if consumed.client_id != client.client_id
            || consumed.redirect_uri != request.redirect_uri
            || consumed.resource != resource
            || consumed.pkce_challenge != request.code_verifier.challenge()
            || consumed.context.client_id != client.client_id
            || consumed.context.resource != resource
        {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        }
        let refresh_token = consumed
            .context
            .refresh_allowed
            .then(|| replacement.presentation.expose_once());
        self.issue_tokens(consumed.context, refresh_token)
    }

    async fn refresh(&self, request: RefreshTokenRequest) -> Result<TokenResponse, ProtocolError> {
        let client = self
            .authenticate_client(&request.client_authentication)
            .await?;
        if !client.grant_types.contains(&GrantType::RefreshToken) {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        }
        let scopes = validate_optional_scope_subset(request.scopes)?;
        let (_, presented_digest) = self
            .parse_bearer(&request.refresh_token, BearerDigestDomain::RefreshToken)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidGrant))?;
        let replacement = issue_bearer(
            self.entropy.as_ref(),
            self.config.token_pepper(),
            BearerDigestDomain::RefreshToken,
        )
        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let now = self.clock.now_utc();
        let replacement_expires_at = add_std(now, self.config.refresh_token_ttl())
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let outcome = self
            .store
            .rotate_refresh_token(RotateRefreshToken {
                presented_digest,
                client_id: client.client_id.clone(),
                scopes: scopes.clone(),
                resource: request.resource.clone(),
                replacement_digest: replacement.digest,
                replacement_expires_at,
                now,
            })
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let RotateRefreshOutcome::Rotated(context) = outcome else {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        };
        let context = *context;
        if context.client_id != client.client_id
            || request
                .resource
                .as_ref()
                .is_some_and(|resource| resource != &context.resource)
            || scopes
                .as_ref()
                .is_some_and(|requested| !scope_sets_equal(requested, &context.scopes))
            || !context.refresh_allowed
        {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidGrant));
        }
        self.issue_tokens(context, Some(replacement.presentation.expose_once()))
    }

    async fn authenticate_client(
        &self,
        authentication: &ClientAuthentication,
    ) -> Result<ResolvedClient, ProtocolError> {
        let client = self
            .store
            .resolve_client(authentication.client_id())
            .await
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .filter(ResolvedClient::is_well_formed)
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::InvalidClient))?;
        let authenticated = match authentication {
            ClientAuthentication::None { .. } => {
                client.token_endpoint_auth_method == TokenEndpointAuthMethod::None
            }
            ClientAuthentication::ClientSecretBasic { secret, .. } => {
                client.token_endpoint_auth_method == TokenEndpointAuthMethod::ClientSecretBasic
                    && self
                        .store
                        .authenticate_client_secret(&client.client_id, secret.expose())
                        .await
                        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            }
            ClientAuthentication::PrivateKeyJwt { assertion, .. } => {
                client.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
                    && self.private_assertion_semantics(&client.client_id, assertion)
                    && self
                        .store
                        .accept_private_key_assertion(&client.client_id, assertion)
                        .await
                        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            }
        };
        if !authenticated {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidClient));
        }
        Ok(client)
    }

    fn private_assertion_semantics(
        &self,
        client_id: &ClientId,
        assertion: &PrivateKeyJwtAssertion,
    ) -> bool {
        let now = self.clock.now_utc();
        &assertion.issuer == client_id
            && &assertion.subject == client_id
            && assertion.audience == self.config.issuer().endpoint(TOKEN_PATH)
            && assertion.issued_at <= now
            && assertion.expires_at > now
            && assertion.expires_at - assertion.issued_at
                <= Duration::seconds(MAX_ASSERTION_LIFETIME_SECONDS)
    }

    fn issue_tokens(
        &self,
        context: TokenGrantContext,
        refresh_token: Option<String>,
    ) -> Result<TokenResponse, ProtocolError> {
        if context.scopes.is_empty()
            || context.scopes.len() > MAX_SCOPES
            || !strictly_sorted(&context.scopes)
            || refresh_token.is_some() != context.refresh_allowed
            || context.refresh_allowed && !has_scope(&context.scopes, "offline_access")
        {
            return Err(ProtocolError::endpoint(OAuthErrorCode::ServerError));
        }
        let now = self.clock.now_utc();
        let expires_at = add_std(now, self.config.access_token_ttl())
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let claims = AccessTokenClaims::new(AccessTokenClaimsInput {
            issuer: self.config.issuer().clone(),
            subject: context.public_subject.clone(),
            audience: context.resource.clone(),
            expires_at,
            not_before: now,
            issued_at: now,
            jwt_id: self.next_jwt_id()?,
            client_id: context.client_id.clone(),
            grant_id: context.grant_id,
            scopes: context.scopes.clone(),
            auth_time: context.auth_time,
            acr: context.acr.clone(),
            amr: context.amr.clone(),
        })
        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let access_token = self
            .config
            .signing_keys()
            .sign_access_token(&claims)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
            .expose_once();
        let id_token = if has_scope(&context.scopes, "openid") {
            let email = has_scope(&context.scopes, "email")
                .then_some(context.verified_email.clone())
                .flatten();
            let id_expires_at = add_std(now, self.config.id_token_ttl())
                .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
            let claims = IdTokenClaims::new(IdTokenClaimsInput {
                issuer: self.config.issuer().clone(),
                subject: context.public_subject,
                audience: context.client_id,
                expires_at: id_expires_at,
                issued_at: now,
                auth_time: context.auth_time,
                acr: context.acr,
                amr: context.amr,
                nonce: context.nonce,
                authorized_party: None,
                email_verified: email.as_ref().map(|_| true),
                email,
            })
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
            Some(
                self.config
                    .signing_keys()
                    .sign_id_token(&claims)
                    .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?
                    .expose_once(),
            )
        } else {
            None
        };
        Ok(TokenResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: self.config.access_token_ttl().as_secs(),
            scopes: context.scopes,
            refresh_token,
            id_token,
            sensitivity: ResponseSensitivity::NoStore,
        })
    }

    fn validate_authorization_request(
        &self,
        request: &AuthorizationRequestInput,
        client: &ResolvedClient,
    ) -> Result<(), ProtocolError> {
        if request.client_id() != &client.client_id
            || !client.grant_types.contains(&GrantType::AuthorizationCode)
        {
            return Err(self.authorization_error(OAuthErrorCode::UnauthorizedClient, request));
        }
        if !client.scopes.is_empty()
            && request
                .scopes()
                .iter()
                .any(|scope| client.scopes.binary_search(scope).is_err())
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
        }
        if (has_scope(request.scopes(), "email") && !has_scope(request.scopes(), "openid"))
            || (has_scope(request.scopes(), "offline_access")
                && (!has_scope(request.scopes(), "openid")
                    || request.prompt() != Some(Prompt::Consent)))
        {
            return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
        }
        let resource = self.effective_resource(request)?;
        if !client.resources.is_empty() && client.resources.binary_search(&resource).is_err() {
            return Err(self.authorization_error(OAuthErrorCode::InvalidTarget, request));
        }
        Ok(())
    }

    fn effective_resource(
        &self,
        request: &AuthorizationRequestInput,
    ) -> Result<ResourceUri, ProtocolError> {
        match request.resources() {
            [resource] => {
                let declaration = self.resource(resource).ok_or_else(|| {
                    self.authorization_error(OAuthErrorCode::InvalidTarget, request)
                })?;
                if request.scopes().iter().any(|scope| {
                    !is_reserved_scope(scope)
                        && declaration
                            .scopes()
                            .iter()
                            .all(|described| described.name() != scope)
                }) {
                    return Err(self.authorization_error(OAuthErrorCode::InvalidScope, request));
                }
                Ok(resource.clone())
            }
            [] if has_scope(request.scopes(), "openid")
                && request.scopes().iter().all(is_reserved_scope) =>
            {
                self.userinfo_audience()
            }
            _ => Err(self.authorization_error(OAuthErrorCode::InvalidTarget, request)),
        }
    }

    fn interaction_display(
        &self,
        request: &AuthorizationRequestInput,
        client: &ResolvedClient,
        resource: &ResourceUri,
        existing: Option<&ExistingGrant>,
        requirement: InteractionRequirement,
    ) -> Result<AuthorizationInteraction, ProtocolError> {
        let (resource_name, resource_description, minimum_assurance) =
            if let Some(declaration) = self.resource(resource) {
                (
                    declaration.name().to_owned(),
                    declaration.description().to_owned(),
                    declaration.minimum_assurance(),
                )
            } else {
                (
                    "OpenID UserInfo".to_owned(),
                    "Claims approved for this OpenID Connect client.".to_owned(),
                    AssuranceLevel::Aal1,
                )
            };
        let redirect_host = url::Url::parse(request.redirect_uri().as_str())
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned))
            .ok_or_else(|| self.authorization_error(OAuthErrorCode::ServerError, request))?;
        let scopes = request
            .scopes()
            .iter()
            .map(|requested| InteractionScope {
                name: requested.clone(),
                description: self.scope_description(resource, requested),
                newly_requested: existing
                    .is_none_or(|grant| grant.scopes.binary_search(requested).is_err()),
            })
            .collect();
        Ok(AuthorizationInteraction {
            client_name: client.display_name.clone(),
            client_origin: client.display_origin.clone(),
            redirect_host,
            resource: resource.clone(),
            resource_name,
            resource_description,
            minimum_assurance,
            scopes,
            requirement,
        })
    }

    fn scope_description(&self, resource: &ResourceUri, requested: &Scope) -> String {
        match requested.as_str() {
            "openid" => "Sign in and identify your account.".to_owned(),
            "email" => "Read your verified email address.".to_owned(),
            "offline_access" => "Keep access after this browser session ends.".to_owned(),
            _ => self
                .resource(resource)
                .and_then(|declaration| {
                    declaration
                        .scopes()
                        .iter()
                        .find(|scope| scope.name() == requested)
                })
                .map_or_else(String::new, |scope| scope.description().to_owned()),
        }
    }

    fn resource(&self, resource: &ResourceUri) -> Option<&ResourceDeclaration> {
        self.config
            .resources()
            .iter()
            .find(|candidate| candidate.uri() == resource)
    }

    fn minimum_assurance(&self, resource: &ResourceUri) -> AssuranceLevel {
        self.resource(resource)
            .map_or(AssuranceLevel::Aal1, ResourceDeclaration::minimum_assurance)
    }

    fn userinfo_audience(&self) -> Result<ResourceUri, ProtocolError> {
        ResourceUri::parse(self.config.issuer().endpoint(USERINFO_PATH), false)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
    }

    fn parse_bearer(
        &self,
        value: &str,
        domain: BearerDigestDomain,
    ) -> Result<(OpaqueBearer, BearerDigest), ProtocolError> {
        let bearer = OpaqueBearer::parse(value)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
        let digest = digest_bearer(&bearer, self.config.token_pepper(), domain)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        Ok((bearer, digest))
    }

    fn refresh_revocation_target(&self, value: &str) -> Option<RevocationTarget> {
        self.parse_bearer(value, BearerDigestDomain::RefreshToken)
            .ok()
            .map(|(_, digest)| RevocationTarget::RefreshToken(digest))
    }

    fn access_revocation_target(
        &self,
        token: &str,
        audience: Option<&ResourceUri>,
        client: &ResolvedClient,
    ) -> Result<RevocationTarget, ProtocolError> {
        let claims = if let Some(audience) = audience {
            self.config.signing_keys().verify_access_token(
                token,
                self.config.issuer(),
                audience,
                self.clock.now_utc(),
            )
        } else {
            self.config.signing_keys().verify_access_token_for_issuer(
                token,
                self.config.issuer(),
                self.clock.now_utc(),
            )
        }
        .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
        let token_audience = ResourceUri::parse(claims.audience().to_owned(), false)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?;
        let userinfo_audience = self.userinfo_audience()?;
        if token_audience != userinfo_audience
            && !self
                .config
                .resources()
                .iter()
                .any(|resource| resource.uri() == &token_audience)
        {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        if claims.client_id() != client.client_id.as_str() {
            return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidRequest));
        }
        Ok(RevocationTarget::AccessToken {
            jwt_id: JwtId::from_uuid(claims.jwt_id())
                .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?,
            grant_id: GrantId::from_uuid(claims.grant_id())
                .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::InvalidRequest))?,
        })
    }

    fn next_jwt_id(&self) -> Result<JwtId, ProtocolError> {
        let now = self.clock.now_utc();
        let millis = now.unix_timestamp_nanos() / 1_000_000;
        let millis = u64::try_from(millis)
            .ok()
            .filter(|value| *value < (1_u64 << 48))
            .ok_or_else(|| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let mut bytes = [0_u8; 16];
        self.entropy
            .try_fill(&mut bytes)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))?;
        let timestamp = millis.to_be_bytes();
        bytes[..6].copy_from_slice(&timestamp[2..]);
        bytes[6] = (bytes[6] & 0x0f) | 0x70;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        JwtId::from_uuid(Uuid::from_bytes(bytes))
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
    }

    fn authorization_error(
        &self,
        code: OAuthErrorCode,
        request: &AuthorizationRequestInput,
    ) -> ProtocolError {
        ProtocolError::authorization(code, request, self.config.issuer())
    }
}

fn validate_optional_scope_subset(
    scopes: Option<Vec<Scope>>,
) -> Result<Option<Vec<Scope>>, ProtocolError> {
    let Some(mut scopes) = scopes else {
        return Ok(None);
    };
    scopes.sort_unstable();
    if scopes.is_empty()
        || scopes.len() > MAX_SCOPES
        || scopes.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(ProtocolError::endpoint(OAuthErrorCode::InvalidScope));
    }
    Ok(Some(scopes))
}

fn scope(value: &str) -> Result<Scope, ProtocolError> {
    Scope::new(value.to_owned()).map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
}

fn has_scope(scopes: &[Scope], expected: &str) -> bool {
    scopes.iter().any(|scope| scope.as_str() == expected)
}

fn is_reserved_scope(scope: &Scope) -> bool {
    matches!(scope.as_str(), "openid" | "email" | "offline_access")
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn scope_sets_equal(left: &[Scope], right: &[Scope]) -> bool {
    left == right
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn duration_seconds(seconds: u64) -> Duration {
    i64::try_from(seconds).map_or(Duration::MAX, Duration::seconds)
}

fn add_std(now: OffsetDateTime, duration: StdDuration) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(duration.as_secs()).ok()?;
    now.checked_add(Duration::seconds(seconds))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashSet, VecDeque},
        error::Error,
        future::{Future, Ready, ready},
        sync::{
            Arc, Mutex,
            atomic::{AtomicU8, Ordering},
        },
        task::{Context, Poll, Waker},
        thread,
    };

    use omnius_auth_core::{AuthMethod, PrincipalKind, SubjectId};
    use omnius_config::{DeploymentEnvironment, SecretString};

    use super::*;
    use crate::{
        config::{
            AuthorizationServerConfig, KeyAlgorithm, KeyState, ResourceConfig, ResourceScopeConfig,
            SigningKeyConfig,
        },
        crypto::{RsaPublicJwk, TEST_RSA_E, TEST_RSA_N, TEST_RSA_PRIVATE_KEY, TokenPepper},
        error::OAuthCryptoError,
        types::{AuthorizationRequestParts, ResponseMode, ResponseType},
        verifier::{AccessTokenIdentity, AccessTokenLiveCheck},
    };

    const NOW_SECONDS: i64 = 1_800_000_000;
    const OPAQUE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const VERIFIER: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    #[derive(Debug)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now_utc(&self) -> OffsetDateTime {
            self.0
        }
    }

    #[derive(Debug, Default)]
    struct FixedEntropy(AtomicU8);

    impl EntropySource for FixedEntropy {
        fn try_fill(&self, output: &mut [u8]) -> Result<(), OAuthCryptoError> {
            let start = self.0.fetch_add(1, Ordering::Relaxed);
            for (offset, byte) in output.iter_mut().enumerate() {
                *byte = start.wrapping_add(u8::try_from(offset).unwrap_or(0));
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeState {
        session: Option<AuthorizationSubject>,
        covering_grant: Option<ExistingGrant>,
        authorization: Option<StoredAuthorization>,
        consumed_code: Option<ConsumedAuthorizationCode>,
        refresh_outcomes: VecDeque<RotateRefreshOutcome>,
        assertion_ids: HashSet<String>,
        live_access: bool,
        access_store_unavailable: bool,
        revocations: usize,
        decisions: usize,
        logout_allowed: bool,
    }

    #[derive(Debug)]
    struct FakeStore {
        client: ResolvedClient,
        state: Mutex<FakeState>,
    }

    impl FakeStore {
        fn new(client: ResolvedClient, session: AuthorizationSubject) -> Self {
            Self {
                client,
                state: Mutex::new(FakeState {
                    session: Some(session),
                    covering_grant: None,
                    authorization: None,
                    consumed_code: None,
                    refresh_outcomes: VecDeque::new(),
                    assertion_ids: HashSet::new(),
                    live_access: true,
                    access_store_unavailable: false,
                    revocations: 0,
                    decisions: 0,
                    logout_allowed: true,
                }),
            }
        }

        fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    #[allow(refining_impl_trait)]
    impl AccessTokenStateStore for FakeStore {
        fn authorize_access_token(
            &self,
            check: AccessTokenLiveCheck,
        ) -> Ready<Result<Option<AccessTokenIdentity>, OAuthStoreError>> {
            let state = self.state();
            if state.access_store_unavailable {
                return ready(Err(OAuthStoreError));
            }
            let identity = state
                .live_access
                .then(|| state.session.as_ref())
                .flatten()
                .filter(|subject| subject.public_subject == check.public_subject)
                .map(|subject| AccessTokenIdentity {
                    subject_id: subject.principal.subject_id,
                    kind: subject.principal.kind,
                    tenant_id: subject.principal.tenant_id,
                    authenticated_at: subject.principal.authenticated_at,
                    assurance: subject.principal.assurance,
                    public_subject: subject.public_subject.clone(),
                    verified_email: subject.verified_email.clone(),
                });
            ready(Ok(identity))
        }
    }

    #[allow(refining_impl_trait)]
    impl AuthorizationStore for FakeStore {
        fn resolve_client(
            &self,
            client_id: &ClientId,
        ) -> Ready<Result<Option<ResolvedClient>, OAuthStoreError>> {
            ready(Ok(
                (client_id == &self.client.client_id).then(|| self.client.clone())
            ))
        }

        fn authorize_session(
            &self,
            candidate: SessionCandidate,
        ) -> Ready<Result<Option<AuthorizationSubject>, OAuthStoreError>> {
            let state = self.state();
            ready(Ok(state
                .session
                .as_ref()
                .filter(|subject| {
                    state.live_access && subject.principal.subject_id == candidate.subject_id
                })
                .cloned()))
        }

        fn find_covering_grant(
            &self,
            _query: CoveringGrantQuery,
        ) -> Ready<Result<Option<ExistingGrant>, OAuthStoreError>> {
            ready(Ok(self.state().covering_grant.clone()))
        }

        fn create_authorization(
            &self,
            command: CreateAuthorization,
        ) -> Ready<Result<(), OAuthStoreError>> {
            self.state().authorization = Some(command.authorization);
            ready(Ok(()))
        }

        fn load_authorization(
            &self,
            _handle_digest: BearerDigest,
            now: OffsetDateTime,
        ) -> Ready<Result<Option<StoredAuthorization>, OAuthStoreError>> {
            ready(Ok(self
                .state()
                .authorization
                .as_ref()
                .filter(|authorization| authorization.expires_at > now)
                .cloned()))
        }

        fn commit_authorization_decision(
            &self,
            command: CommitAuthorizationDecision,
        ) -> Ready<Result<CommitDecisionOutcome, OAuthStoreError>> {
            let mut state = self.state();
            if state.authorization.take().is_none() {
                return ready(Ok(CommitDecisionOutcome::Unavailable));
            }
            state.decisions += 1;
            ready(Ok(match command.decision {
                ConsentDecision::Approve
                    if command.code_digest.is_some() && command.code_expires_at.is_some() =>
                {
                    CommitDecisionOutcome::Approved
                }
                ConsentDecision::Deny if command.code_digest.is_none() => {
                    CommitDecisionOutcome::Denied
                }
                ConsentDecision::Approve | ConsentDecision::Deny => {
                    CommitDecisionOutcome::Unavailable
                }
            }))
        }

        fn authenticate_client_secret(
            &self,
            _client_id: &ClientId,
            secret: &str,
        ) -> Ready<Result<bool, OAuthStoreError>> {
            ready(Ok(secret == "correct-secret"))
        }

        fn accept_private_key_assertion(
            &self,
            _client_id: &ClientId,
            assertion: &PrivateKeyJwtAssertion,
        ) -> Ready<Result<bool, OAuthStoreError>> {
            let accepted = assertion.token() == "signed"
                && self.state().assertion_ids.insert(assertion.jwt_id.clone());
            ready(Ok(accepted))
        }

        fn consume_authorization_code(
            &self,
            _command: ConsumeAuthorizationCode,
        ) -> Ready<Result<ConsumeCodeOutcome, OAuthStoreError>> {
            ready(Ok(self
                .state()
                .consumed_code
                .take()
                .map_or(ConsumeCodeOutcome::Unavailable, |code| {
                    ConsumeCodeOutcome::Consumed(Box::new(code))
                })))
        }

        fn rotate_refresh_token(
            &self,
            _command: RotateRefreshToken,
        ) -> Ready<Result<RotateRefreshOutcome, OAuthStoreError>> {
            ready(Ok(self
                .state()
                .refresh_outcomes
                .pop_front()
                .unwrap_or(RotateRefreshOutcome::Unavailable)))
        }

        fn revoke_token(
            &self,
            _client_id: &ClientId,
            _target: RevocationTarget,
            _now: OffsetDateTime,
        ) -> Ready<Result<(), OAuthStoreError>> {
            let mut state = self.state();
            state.live_access = false;
            state.revocations += 1;
            ready(Ok(()))
        }

        fn list_connected_grants(
            &self,
            _subject_id: SubjectId,
        ) -> Ready<Result<Vec<ConnectedGrant>, OAuthStoreError>> {
            ready(Ok(vec![ConnectedGrant {
                grant_id: grant_id(),
                client_name: self.client.display_name.clone(),
                resource: root_resource(),
                scopes: vec![test_scope("records:read")],
                consented_at: fixed_now(),
            }]))
        }

        fn revoke_connected_grant(
            &self,
            _subject_id: SubjectId,
            _grant_id: GrantId,
        ) -> Ready<Result<bool, OAuthStoreError>> {
            let mut state = self.state();
            state.live_access = false;
            ready(Ok(true))
        }

        fn logout_session(&self, command: LogoutSession) -> Ready<Result<bool, OAuthStoreError>> {
            let state = self.state();
            let matches = state.logout_allowed
                && state.session.as_ref().is_some_and(|subject| {
                    subject.principal.subject_id == command.subject_id
                        && command
                            .public_subject
                            .as_ref()
                            .is_none_or(|public| public == &subject.public_subject)
                });
            ready(Ok(matches))
        }
    }

    type TestServer = AuthorizationServer<FakeStore, FixedClock, FixedEntropy>;

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => thread::yield_now(),
            }
        }
    }

    fn fixed_now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(NOW_SECONDS)
            .unwrap_or_else(|_| unreachable!("fixed timestamp is valid"))
    }

    fn uuid_v7(last: u8) -> Uuid {
        let mut bytes = [0_u8; 16];
        bytes[..6].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        bytes[6] = 0x70;
        bytes[8] = 0x80;
        bytes[15] = last;
        Uuid::from_bytes(bytes)
    }

    fn subject_id() -> SubjectId {
        SubjectId::from_uuid(uuid_v7(1))
            .unwrap_or_else(|_| unreachable!("fixed subject UUID is v7"))
    }

    fn grant_id() -> GrantId {
        GrantId::from_uuid(uuid_v7(2)).unwrap_or_else(|_| unreachable!("fixed grant UUID is v7"))
    }

    fn test_scope(value: &str) -> Scope {
        Scope::new(value.to_owned()).unwrap_or_else(|_| unreachable!("test scope is valid"))
    }

    fn client_id() -> ClientId {
        ClientId::parse("client-1").unwrap_or_else(|_| unreachable!("test client is valid"))
    }

    fn root_resource() -> ResourceUri {
        ResourceUri::parse("https://issuer.example.test", true)
            .unwrap_or_else(|_| unreachable!("test resource is valid"))
    }

    fn userinfo_resource() -> ResourceUri {
        ResourceUri::parse("https://issuer.example.test/oauth/userinfo", true)
            .unwrap_or_else(|_| unreachable!("test resource is valid"))
    }

    fn redirect() -> RedirectUri {
        RedirectUri::parse("https://client.example.test/callback")
            .unwrap_or_else(|_| unreachable!("test redirect is valid"))
    }

    fn subject(email: Option<&str>, authenticated_at: OffsetDateTime) -> AuthorizationSubject {
        AuthorizationSubject {
            principal: Principal::new(
                subject_id(),
                PrincipalKind::User,
                None,
                AuthMethod::Session,
                authenticated_at,
                AssuranceLevel::Aal1,
                Vec::new(),
            )
            .unwrap_or_else(|_| unreachable!("test principal is valid")),
            public_subject: OPAQUE.to_owned(),
            verified_email: email.map(str::to_owned),
            acr: "urn:omnius:aal1".to_owned(),
            amr: vec!["pwd".to_owned()],
        }
    }

    fn resolved_client(method: TokenEndpointAuthMethod) -> ResolvedClient {
        let mut scopes = vec![
            test_scope("openid"),
            test_scope("email"),
            test_scope("offline_access"),
            test_scope("records:read"),
        ];
        scopes.sort_unstable();
        let mut resources = vec![root_resource(), userinfo_resource()];
        resources.sort_unstable();
        ResolvedClient {
            client_id: client_id(),
            display_name: "Example Client".to_owned(),
            display_origin: "https://client.example.test".to_owned(),
            redirect_uris: vec![
                redirect(),
                RedirectUri::parse("http://127.0.0.1:49152/callback?native=1")
                    .unwrap_or_else(|_| unreachable!("test loopback redirect is valid")),
            ],
            post_logout_redirect_uris: vec![
                RedirectUri::parse("https://client.example.test/logout-complete")
                    .unwrap_or_else(|_| unreachable!("test logout redirect is valid")),
            ],
            token_endpoint_auth_method: method,
            grant_types: vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            scopes,
            resources,
        }
    }

    fn validated_config() -> Result<Arc<ValidatedAuthorizationServerConfig>, Box<dyn Error>> {
        let config = AuthorizationServerConfig {
            enabled: true,
            issuer: "https://issuer.example.test".to_owned(),
            token_pepper: Some(TokenPepper::parse(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            )?),
            resources: vec![ResourceConfig {
                uri: root_resource().as_str().to_owned(),
                name: "Root API".to_owned(),
                description: "Root API resource".to_owned(),
                minimum_assurance: AssuranceLevel::Aal1,
                scopes: vec![ResourceScopeConfig {
                    name: test_scope("records:read"),
                    description: "Read records".to_owned(),
                }],
            }],
            signing_keys: vec![SigningKeyConfig {
                kid: "active-1".to_owned(),
                algorithm: KeyAlgorithm::RS256,
                state: KeyState::Active,
                public_jwk: RsaPublicJwk {
                    kty: "RSA".to_owned(),
                    public_key_use: "sig".to_owned(),
                    key_ops: vec!["verify".to_owned()],
                    alg: "RS256".to_owned(),
                    kid: "active-1".to_owned(),
                    n: TEST_RSA_N.to_owned(),
                    e: TEST_RSA_E.to_owned(),
                },
                private_key_pkcs8_pem: Some(SecretString::from(TEST_RSA_PRIVATE_KEY.to_owned())),
                verification_until: None,
            }],
            ..AuthorizationServerConfig::default()
        };
        let validated = config
            .build_for(DeploymentEnvironment::Production, fixed_now())?
            .ok_or_else(|| std::io::Error::other("enabled test config was not built"))?;
        Ok(Arc::new(validated))
    }

    fn server_with(
        method: TokenEndpointAuthMethod,
    ) -> Result<(TestServer, Arc<FakeStore>), Box<dyn Error>> {
        let store = Arc::new(FakeStore::new(
            resolved_client(method),
            subject(None, fixed_now() - Duration::seconds(60)),
        ));
        let server = AuthorizationServer::new(
            validated_config()?,
            Arc::clone(&store),
            Arc::new(FixedClock(fixed_now())),
            Arc::new(FixedEntropy::default()),
        );
        Ok((server, store))
    }

    fn authorization_request(
        redirect_uri: RedirectUri,
        scopes: Vec<Scope>,
        resources: Vec<ResourceUri>,
        prompt: Option<Prompt>,
        max_age_seconds: Option<u64>,
    ) -> Result<AuthorizationRequestInput, Box<dyn Error>> {
        let verifier = PkceVerifier::parse(VERIFIER.to_owned())?;
        Ok(AuthorizationRequestInput::new(AuthorizationRequestParts {
            client_id: client_id(),
            redirect_uri,
            response_type: ResponseType::Code,
            response_mode: ResponseMode::Query,
            state: Some("secret-state".to_owned()),
            scopes,
            resources,
            pkce_challenge: verifier.challenge(),
            pkce_method: "S256".to_owned(),
            nonce: Some("nonce-1".to_owned()),
            prompt,
            max_age_seconds,
            expected_issuer: Some(IssuerUri::parse("https://issuer.example.test", true)?),
        })?)
    }

    fn api_request(
        redirect_uri: RedirectUri,
        prompt: Option<Prompt>,
    ) -> Result<AuthorizationRequestInput, Box<dyn Error>> {
        authorization_request(
            redirect_uri,
            vec![test_scope("records:read")],
            vec![root_resource()],
            prompt,
            None,
        )
    }

    fn context(
        resource: ResourceUri,
        scopes: Vec<Scope>,
        email: Option<&str>,
        refresh_allowed: bool,
    ) -> TokenGrantContext {
        TokenGrantContext {
            grant_id: grant_id(),
            client_id: client_id(),
            public_subject: OPAQUE.to_owned(),
            resource,
            scopes,
            auth_time: fixed_now() - Duration::seconds(60),
            acr: "urn:omnius:aal1".to_owned(),
            amr: vec!["pwd".to_owned()],
            nonce: Some("nonce-1".to_owned()),
            verified_email: email.map(str::to_owned),
            refresh_allowed,
        }
    }

    fn consumed_code(context: TokenGrantContext) -> ConsumedAuthorizationCode {
        ConsumedAuthorizationCode {
            client_id: client_id(),
            redirect_uri: redirect(),
            resource: context.resource.clone(),
            pkce_challenge: PkceVerifier::parse(VERIFIER.to_owned())
                .unwrap_or_else(|_| unreachable!("test verifier is valid"))
                .challenge(),
            context,
        }
    }

    fn none_authentication() -> ClientAuthentication {
        ClientAuthentication::None {
            client_id: client_id(),
        }
    }

    fn code_request(resource: ResourceUri, verifier: &str) -> AuthorizationCodeTokenRequest {
        AuthorizationCodeTokenRequest {
            client_authentication: none_authentication(),
            code: OPAQUE.to_owned(),
            redirect_uri: redirect(),
            code_verifier: PkceVerifier::parse(verifier.to_owned())
                .unwrap_or_else(|_| unreachable!("test verifier is valid")),
            resource: Some(resource),
        }
    }

    #[test]
    fn authorization_errors_redirect_only_for_registered_redirects() -> Result<(), Box<dyn Error>> {
        let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
        let registered = block_on(server.authorization_request_error(
            &client_id(),
            &redirect(),
            Some("correlation-state"),
            OAuthErrorCode::UnsupportedResponseType,
        ));
        assert_eq!(registered.code(), OAuthErrorCode::UnsupportedResponseType);
        let redirect = registered
            .redirect()
            .ok_or_else(|| std::io::Error::other("registered redirect did not receive an error"))?;
        assert_eq!(redirect.redirect_uri, self::redirect());
        assert_eq!(redirect.state.as_deref(), Some("correlation-state"));
        assert_eq!(redirect.issuer.as_str(), "https://issuer.example.test");

        let unsafe_redirect = RedirectUri::parse("https://evil.example.test/callback")?;
        let unsafe_error = block_on(server.authorization_request_error(
            &client_id(),
            &unsafe_redirect,
            Some("must-not-echo"),
            OAuthErrorCode::InvalidRequest,
        ));
        assert_eq!(unsafe_error.code(), OAuthErrorCode::InvalidRequest);
        assert!(unsafe_error.redirect().is_none());
        Ok(())
    }

    #[test]
    fn expected_issuer_mismatch_is_rejected_before_persistence() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        let verifier = PkceVerifier::parse(VERIFIER.to_owned())?;
        let request = AuthorizationRequestInput::new(AuthorizationRequestParts {
            client_id: client_id(),
            redirect_uri: redirect(),
            response_type: ResponseType::Code,
            response_mode: ResponseMode::Query,
            state: Some("issuer-state".to_owned()),
            scopes: vec![test_scope("records:read")],
            resources: vec![root_resource()],
            pkce_challenge: verifier.challenge(),
            pkce_method: "S256".to_owned(),
            nonce: None,
            prompt: None,
            max_age_seconds: None,
            expected_issuer: Some(IssuerUri::parse(
                "https://different-issuer.example.test",
                true,
            )?),
        })?;
        let error = block_on(server.begin_authorization(request, None))
            .err()
            .ok_or_else(|| std::io::Error::other("mismatched issuer was accepted"))?;
        assert_eq!(error.code(), OAuthErrorCode::InvalidRequest);
        assert!(error.redirect().is_some());
        assert!(store.state().authorization.is_none());
        Ok(())
    }

    #[test]
    fn redirect_safety_and_loopback_exception_are_exact() -> Result<(), Box<dyn Error>> {
        let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
        let unsafe_request = api_request(
            RedirectUri::parse("https://evil.example.test/callback")?,
            None,
        )?;
        let error = block_on(server.begin_authorization(unsafe_request, None))
            .err()
            .ok_or_else(|| std::io::Error::other("unsafe redirect was accepted"))?;
        assert_eq!(error.redirect(), None);

        let registered = RedirectUri::parse("http://127.0.0.1:49152/callback?native=1")?;
        let substituted = RedirectUri::parse("http://127.0.0.1:61234/callback?native=1")?;
        assert!(registered.matches_registered(&substituted));
        let changed_query = RedirectUri::parse("http://127.0.0.1:61234/callback?native=2")?;
        assert!(!registered.matches_registered(&changed_query));
        assert!(RedirectUri::parse("http://localhost:61234/callback").is_err());
        Ok(())
    }

    #[test]
    fn prompt_none_returns_login_consent_or_direct_success() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store.state().session = None;
        let login_error = block_on(
            server.begin_authorization(api_request(redirect(), Some(Prompt::None))?, None),
        )
        .err()
        .ok_or_else(|| std::io::Error::other("prompt none displayed login"))?;
        assert_eq!(login_error.code(), OAuthErrorCode::LoginRequired);
        assert!(login_error.redirect().is_some());

        store.state().session = Some(subject(None, fixed_now()));
        let consent_error = block_on(server.begin_authorization(
            api_request(redirect(), Some(Prompt::None))?,
            Some(SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now(),
            }),
        ))
        .err()
        .ok_or_else(|| std::io::Error::other("prompt none displayed consent"))?;
        assert_eq!(consent_error.code(), OAuthErrorCode::ConsentRequired);

        store.state().covering_grant = Some(ExistingGrant {
            grant_id: grant_id(),
            resource: root_resource(),
            scopes: vec![test_scope("records:read")],
            offline_access_consented: false,
        });
        let success = block_on(server.begin_authorization(
            api_request(redirect(), Some(Prompt::None))?,
            Some(SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now(),
            }),
        ))?;
        let BeginAuthorizationResult::Redirect(success) = success else {
            return Err(std::io::Error::other("covering grant was not reused").into());
        };
        assert!(success.code.is_some());
        assert_eq!(success.issuer.as_str(), "https://issuer.example.test");
        Ok(())
    }

    #[test]
    fn offline_access_requires_explicit_consent_and_interaction_hides_state()
    -> Result<(), Box<dyn Error>> {
        let (server, _) = server_with(TokenEndpointAuthMethod::None)?;
        let scopes = vec![test_scope("offline_access"), test_scope("openid")];
        let error = block_on(server.begin_authorization(
            authorization_request(redirect(), scopes.clone(), Vec::new(), None, None)?,
            Some(SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now(),
            }),
        ))
        .err()
        .ok_or_else(|| std::io::Error::other("offline access skipped consent"))?;
        assert_eq!(error.code(), OAuthErrorCode::InvalidScope);

        let begun = block_on(server.begin_authorization(
            authorization_request(redirect(), scopes, Vec::new(), Some(Prompt::Consent), None)?,
            Some(SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now(),
            }),
        ))?;
        let BeginAuthorizationResult::Interaction(begun) = begun else {
            return Err(std::io::Error::other("offline access did not require interaction").into());
        };
        let interaction = block_on(server.interaction(begun.handle.expose()))?;
        let serialized = serde_json::to_string(&interaction)?;
        assert!(!serialized.contains("secret-state"));
        assert_eq!(interaction.requirement, InteractionRequirement::Consent);
        Ok(())
    }

    #[test]
    fn max_age_zero_requires_newer_authentication() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        let begun = block_on(server.begin_authorization(
            authorization_request(
                redirect(),
                vec![test_scope("records:read")],
                vec![root_resource()],
                None,
                Some(0),
            )?,
            Some(SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now() - Duration::seconds(60),
            }),
        ))?;
        let BeginAuthorizationResult::Interaction(begun) = begun else {
            return Err(std::io::Error::other("max_age zero did not require login").into());
        };
        let stale = block_on(server.decide(
            begun.handle.expose(),
            SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now() - Duration::seconds(60),
            },
            ConsentDecision::Approve,
        ))
        .err()
        .ok_or_else(|| std::io::Error::other("stale authentication was accepted"))?;
        assert_eq!(stale.code(), OAuthErrorCode::LoginRequired);

        store.state().session = Some(subject(None, fixed_now()));
        let approved = block_on(server.decide(
            begun.handle.expose(),
            SessionCandidate {
                subject_id: subject_id(),
                authenticated_at: fixed_now(),
            },
            ConsentDecision::Approve,
        ))?;
        assert!(approved.code.is_some());
        Ok(())
    }

    #[test]
    fn failed_pkce_consumes_recognized_code_once() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let wrong_verifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
        let first = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            root_resource(),
            wrong_verifier,
        ))))
        .err()
        .ok_or_else(|| std::io::Error::other("bad PKCE was accepted"))?;
        assert_eq!(first.code(), OAuthErrorCode::InvalidGrant);
        let second = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            root_resource(),
            VERIFIER,
        ))))
        .err()
        .ok_or_else(|| std::io::Error::other("consumed code was accepted"))?;
        assert_eq!(second.code(), OAuthErrorCode::InvalidGrant);
        Ok(())
    }

    #[test]
    fn concurrent_code_exchange_has_one_winner() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let first_server = server.clone();
        let second_server = server;
        let first = thread::spawn(move || {
            block_on(
                first_server.token(TokenRequest::AuthorizationCode(code_request(
                    root_resource(),
                    VERIFIER,
                ))),
            )
        });
        let second = thread::spawn(move || {
            block_on(
                second_server.token(TokenRequest::AuthorizationCode(code_request(
                    root_resource(),
                    VERIFIER,
                ))),
            )
        });
        let first = first
            .join()
            .unwrap_or_else(|_| panic!("first exchange panicked"));
        let second = second
            .join()
            .unwrap_or_else(|_| panic!("second exchange panicked"));
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        Ok(())
    }

    #[test]
    fn client_authentication_is_exclusive_and_assertion_jti_is_one_use()
    -> Result<(), Box<dyn Error>> {
        let mixed = ClientAuthentication::try_from(ClientAuthenticationParts {
            public_client_id: Some(client_id()),
            basic: Some((
                client_id(),
                ClientSecret::parse("correct-secret".to_owned())?,
            )),
            private_key_jwt: None,
        });
        assert_eq!(
            mixed.err().map(|error| error.code()),
            Some(OAuthErrorCode::InvalidClient)
        );

        let (server, store) = server_with(TokenEndpointAuthMethod::PrivateKeyJwt)?;
        assert!(
            server
                .issue_tokens(
                    context(
                        root_resource(),
                        vec![test_scope("records:read")],
                        None,
                        false,
                    ),
                    None,
                )
                .is_ok(),
            "private-key client token signing must use the common issuer path",
        );
        let assertion = PrivateKeyJwtAssertion::new(
            "signed".to_owned(),
            client_id(),
            client_id(),
            "https://issuer.example.test/oauth/token".to_owned(),
            "assertion-1".to_owned(),
            fixed_now() - Duration::seconds(1),
            fixed_now() + Duration::seconds(60),
        )?;
        let authentication = ClientAuthentication::PrivateKeyJwt {
            client_id: client_id(),
            assertion,
        };
        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let mut request = code_request(root_resource(), VERIFIER);
        request.client_authentication = authentication.clone();
        let first_exchange = block_on(server.token(TokenRequest::AuthorizationCode(request)));
        assert!(first_exchange.is_ok(), "{first_exchange:?}");

        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let mut replay = code_request(root_resource(), VERIFIER);
        replay.client_authentication = authentication;
        let error = block_on(server.token(TokenRequest::AuthorizationCode(replay)))
            .err()
            .ok_or_else(|| std::io::Error::other("assertion replay was accepted"))?;
        assert_eq!(error.code(), OAuthErrorCode::InvalidClient);
        Ok(())
    }

    #[test]
    fn refresh_rotation_narrows_and_reuse_is_rejected() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store
            .state()
            .refresh_outcomes
            .push_back(RotateRefreshOutcome::Rotated(Box::new(context(
                root_resource(),
                vec![test_scope("offline_access"), test_scope("records:read")],
                None,
                true,
            ))));
        store
            .state()
            .refresh_outcomes
            .push_back(RotateRefreshOutcome::ReuseDetected);
        let request = RefreshTokenRequest {
            client_authentication: none_authentication(),
            refresh_token: OPAQUE.to_owned(),
            scopes: Some(vec![
                test_scope("offline_access"),
                test_scope("records:read"),
            ]),
            resource: Some(root_resource()),
        };
        let response = block_on(server.token(TokenRequest::RefreshToken(request.clone())))?;
        assert!(response.refresh_token.is_some());
        assert_eq!(
            response.scopes,
            vec![test_scope("offline_access"), test_scope("records:read")]
        );
        let reuse = block_on(server.token(TokenRequest::RefreshToken(request)))
            .err()
            .ok_or_else(|| std::io::Error::other("refresh reuse was accepted"))?;
        assert_eq!(reuse.code(), OAuthErrorCode::InvalidGrant);
        Ok(())
    }

    #[test]
    fn unknown_revocation_succeeds_and_live_revocation_is_immediate() -> Result<(), Box<dyn Error>>
    {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        let unknown = block_on(server.revoke(RevocationRequest {
            client_authentication: none_authentication(),
            token: "not-a-token".to_owned(),
            token_type_hint: None,
            audience: None,
        }))?;
        assert_eq!(unknown.sensitivity, ResponseSensitivity::NoStore);
        assert_eq!(store.state().revocations, 0);

        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            root_resource(),
            VERIFIER,
        ))))?;
        let verifier = AccessTokenVerifier::new(
            Arc::new(validated_config()?.signing_keys().clone()),
            IssuerUri::parse("https://issuer.example.test", true)?,
            root_resource(),
            vec![test_scope("records:read")],
            Arc::clone(&store),
            Arc::new(FixedClock(fixed_now())),
        )?;
        assert!(block_on(verifier.verify(&response.access_token)).is_ok());
        block_on(server.revoke(RevocationRequest {
            client_authentication: none_authentication(),
            token: response.access_token.clone(),
            token_type_hint: Some(TokenTypeHint::AccessToken),
            audience: Some(root_resource()),
        }))?;
        assert_eq!(
            block_on(verifier.verify(&response.access_token)).err(),
            Some(AccessTokenVerificationError::Inactive)
        );
        Ok(())
    }

    #[test]
    fn userinfo_rejections_use_invalid_token() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        let malformed = block_on(server.userinfo("not-a-jwt"))
            .err()
            .ok_or_else(|| std::io::Error::other("malformed UserInfo token was accepted"))?;
        assert_eq!(malformed.code(), OAuthErrorCode::InvalidToken);

        store.state().consumed_code = Some(consumed_code(context(
            root_resource(),
            vec![test_scope("records:read")],
            None,
            false,
        )));
        let wrong_audience = block_on(server.token(TokenRequest::AuthorizationCode(
            code_request(root_resource(), VERIFIER),
        )))?;
        let rejected_audience = block_on(server.userinfo(&wrong_audience.access_token))
            .err()
            .ok_or_else(|| std::io::Error::other("wrong-audience UserInfo token was accepted"))?;
        assert_eq!(rejected_audience.code(), OAuthErrorCode::InvalidToken);

        store.state().consumed_code = Some(consumed_code(context(
            userinfo_resource(),
            vec![test_scope("email")],
            None,
            false,
        )));
        let insufficient_scope = block_on(server.token(TokenRequest::AuthorizationCode(
            code_request(userinfo_resource(), VERIFIER),
        )))?;
        let rejected_scope = block_on(server.userinfo(&insufficient_scope.access_token))
            .err()
            .ok_or_else(|| std::io::Error::other("UserInfo token without openid was accepted"))?;
        assert_eq!(rejected_scope.code(), OAuthErrorCode::InvalidToken);

        store.state().consumed_code = Some(consumed_code(context(
            userinfo_resource(),
            vec![test_scope("openid")],
            None,
            false,
        )));
        let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            userinfo_resource(),
            VERIFIER,
        ))))?;
        let expired_server = AuthorizationServer::new(
            validated_config()?,
            Arc::clone(&store),
            Arc::new(FixedClock(fixed_now() + Duration::hours(2))),
            Arc::new(FixedEntropy::default()),
        );
        let expired = block_on(expired_server.userinfo(&response.access_token))
            .err()
            .ok_or_else(|| std::io::Error::other("expired UserInfo token was accepted"))?;
        assert_eq!(expired.code(), OAuthErrorCode::InvalidToken);
        store.state().access_store_unavailable = true;
        let unavailable = block_on(server.userinfo(&response.access_token))
            .err()
            .ok_or_else(|| std::io::Error::other("unavailable UserInfo store was ignored"))?;
        assert_eq!(unavailable.code(), OAuthErrorCode::ServerError);
        store.state().access_store_unavailable = false;

        store.state().live_access = false;
        let revoked = block_on(server.userinfo(&response.access_token))
            .err()
            .ok_or_else(|| std::io::Error::other("revoked UserInfo token was accepted"))?;
        assert_eq!(revoked.code(), OAuthErrorCode::InvalidToken);
        Ok(())
    }

    #[test]
    fn id_token_and_userinfo_share_subject_without_unverified_email() -> Result<(), Box<dyn Error>>
    {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store.state().consumed_code = Some(consumed_code(context(
            userinfo_resource(),
            vec![test_scope("email"), test_scope("openid")],
            None,
            false,
        )));
        let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            userinfo_resource(),
            VERIFIER,
        ))))?;
        let id_token = response
            .id_token
            .as_deref()
            .ok_or_else(|| std::io::Error::other("OIDC exchange omitted ID Token"))?;
        let claims = validated_config()?.signing_keys().verify_id_token(
            id_token,
            &IssuerUri::parse("https://issuer.example.test", true)?,
            &client_id(),
            Some("nonce-1"),
            fixed_now(),
        )?;
        assert_eq!(claims.email(), None);
        let userinfo = block_on(server.userinfo(&response.access_token))?;
        assert_eq!(userinfo.sub, claims.subject());
        assert_eq!(userinfo.email, None);
        assert_eq!(userinfo.email_verified, None);
        Ok(())
    }

    #[test]
    fn logout_redirect_requires_valid_hint_and_exact_registration() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        store.state().consumed_code = Some(consumed_code(context(
            userinfo_resource(),
            vec![test_scope("openid")],
            None,
            false,
        )));
        let response = block_on(server.token(TokenRequest::AuthorizationCode(code_request(
            userinfo_resource(),
            VERIFIER,
        ))))?;
        let id_token = response
            .id_token
            .ok_or_else(|| std::io::Error::other("OIDC exchange omitted ID Token"))?;
        let registered = RedirectUri::parse("https://client.example.test/logout-complete")?;
        let result = block_on(server.logout(LogoutRequest {
            subject_id: subject_id(),
            id_token_hint: Some(IdTokenHint::new(
                id_token.clone(),
                client_id(),
                Some("nonce-1".to_owned()),
            )?),
            post_logout_redirect_uri: Some(registered.clone()),
            state: Some("logout-state".to_owned()),
        }))?;
        assert_eq!(result.redirect_uri, Some(registered));
        assert_eq!(result.state.as_deref(), Some("logout-state"));

        let rejected = block_on(server.logout(LogoutRequest {
            subject_id: subject_id(),
            id_token_hint: Some(IdTokenHint::new(
                id_token,
                client_id(),
                Some("nonce-1".to_owned()),
            )?),
            post_logout_redirect_uri: Some(RedirectUri::parse(
                "https://client.example.test/not-registered",
            )?),
            state: Some("must-not-return".to_owned()),
        }))
        .err()
        .ok_or_else(|| std::io::Error::other("unregistered logout redirect was accepted"))?;
        assert_eq!(rejected.code(), OAuthErrorCode::InvalidRequest);
        Ok(())
    }

    #[test]
    fn connected_grant_revocation_removes_live_authority() -> Result<(), Box<dyn Error>> {
        let (server, store) = server_with(TokenEndpointAuthMethod::None)?;
        let grants = block_on(server.connected_grants(subject_id()))?;
        assert_eq!(grants.len(), 1);
        assert!(block_on(
            server.revoke_connected_grant(subject_id(), grant_id())
        )?);
        assert!(!store.state().live_access);
        Ok(())
    }
}
