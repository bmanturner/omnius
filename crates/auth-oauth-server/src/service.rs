//! Transport-neutral OAuth Authorization Server and `OpenID` Provider state machine.

use crate::Clock;
use crate::config::{ResourceDeclaration, ValidatedAuthorizationServerConfig};
use crate::crypto::{BearerDigest, BearerDigestDomain, JwksDocument, digest_bearer};
use crate::metadata::{
    AuthorizationServerMetadata, MetadataSnapshots, OpenIdProviderMetadata,
    ProtectedResourceMetadata,
};
use crate::types::{
    AuthorizationRequestInput, ClientId, EntropySource, GrantId, GrantType, IssuerUri, JwtId,
    MAX_SCOPES, MAX_URI_BYTES, OpaqueBearer, RedirectUri, ResourceUri, TokenEndpointAuthMethod,
};
use crate::verifier::{AccessTokenStateStore, OAuthStoreError};
use omnius_auth_core::{AssuranceLevel, Scope, SubjectId};
use serde::Serialize;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

mod authorize;
mod logout;
mod revoke;
#[cfg(test)]
mod tests;
mod token;
mod userinfo;

pub use authorize::{
    AuthorizationErrorRedirect, AuthorizationHandle, AuthorizationInteraction,
    AuthorizationRedirect, AuthorizationSubject, BeginAuthorizationResult, BegunAuthorization,
    CommitAuthorizationDecision, CommitDecisionOutcome, ConsentDecision, CoveringGrantQuery,
    CreateAuthorization, ExistingGrant, InteractionRequirement, InteractionScope, SessionCandidate,
    StoredAuthorization,
};
pub use logout::{IdTokenHint, LogoutRequest, LogoutResponse, LogoutSession};
pub use revoke::{
    ConnectedGrant, RevocationRequest, RevocationResponse, RevocationTarget, TokenTypeHint,
};
pub use token::{
    AuthorizationCodeTokenRequest, ClientAuthentication, ClientAuthenticationParts, ClientSecret,
    ConsumeAuthorizationCode, ConsumeCodeOutcome, ConsumedAuthorizationCode,
    PrivateKeyJwtAssertion, RefreshTokenRequest, RotateRefreshOutcome, RotateRefreshToken,
    TokenGrantContext, TokenRequest, TokenResponse,
};
pub use userinfo::UserInfoResponse;

const MAX_STATE_BYTES: usize = 1_024;

const MAX_DISPLAY_TEXT_BYTES: usize = 1_024;

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
#[non_exhaustive]
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

    pub(super) fn resource(&self, resource: &ResourceUri) -> Option<&ResourceDeclaration> {
        self.config
            .resources()
            .iter()
            .find(|candidate| candidate.uri() == resource)
    }

    pub(super) fn minimum_assurance(&self, resource: &ResourceUri) -> AssuranceLevel {
        self.resource(resource)
            .map_or(AssuranceLevel::Aal1, ResourceDeclaration::minimum_assurance)
    }

    pub(super) fn parse_bearer(
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

    pub(super) fn next_jwt_id(&self) -> Result<JwtId, ProtocolError> {
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

    pub(super) fn authorization_error(
        &self,
        code: OAuthErrorCode,
        request: &AuthorizationRequestInput,
    ) -> ProtocolError {
        ProtocolError::authorization(code, request, self.config.issuer())
    }
}

fn scope(value: &str) -> Result<Scope, ProtocolError> {
    Scope::new(value.to_owned()).map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
}

fn has_scope(scopes: &[Scope], expected: &str) -> bool {
    scopes.iter().any(|scope| scope.as_str() == expected)
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn add_std(now: OffsetDateTime, duration: StdDuration) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(duration.as_secs()).ok()?;
    now.checked_add(Duration::seconds(seconds))
}
