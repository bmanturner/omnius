//! Token endpoint client authentication, code exchange, and refresh flow.

use super::{
    AuthorizationServer, AuthorizationStore, OAuthErrorCode, ProtocolError, REDACTED,
    ResolvedClient, ResponseSensitivity, add_std, has_scope, strictly_sorted,
};
use crate::Clock;
use crate::crypto::{
    AccessTokenClaims, AccessTokenClaimsInput, BearerDigest, BearerDigestDomain, IdTokenClaims,
    IdTokenClaimsInput, issue_bearer,
};
use crate::types::{
    ClientId, EntropySource, GrantId, GrantType, MAX_JWT_BYTES, MAX_SCOPES, MAX_URI_BYTES,
    PkceChallenge, PkceVerifier, RedirectUri, ResourceUri, TokenEndpointAuthMethod,
};
use omnius_auth_core::Scope;
use serde::Serialize;
use time::{Duration, OffsetDateTime};
use zeroize::{Zeroize, Zeroizing};

const MAX_ASSERTION_ID_BYTES: usize = 128;

const MAX_ASSERTION_LIFETIME_SECONDS: i64 = 300;

const MAX_SECRET_BYTES: usize = 1_024;

const TOKEN_PATH: &str = "/oauth/token";

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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
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

    pub(super) async fn authenticate_client(
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

    pub(super) fn issue_tokens(
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

fn scope_sets_equal(left: &[Scope], right: &[Scope]) -> bool {
    left == right
}
