//! Token revocation and connected-grant management flow.

use super::{
    AuthorizationServer, AuthorizationStore, ClientAuthentication, OAuthErrorCode, ProtocolError,
    REDACTED, ResolvedClient, ResponseSensitivity,
};
use crate::Clock;
use crate::crypto::{BearerDigest, BearerDigestDomain};
use crate::types::{EntropySource, GrantId, JwtId, MAX_JWT_BYTES, ResourceUri};
use omnius_auth_core::{Scope, SubjectId};
use serde::Serialize;
use time::OffsetDateTime;

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
#[non_exhaustive]
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

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
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
}
