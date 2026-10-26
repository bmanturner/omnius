//! RP-initiated logout flow.

use super::{
    AuthorizationServer, AuthorizationStore, MAX_STATE_BYTES, OAuthErrorCode, ProtocolError,
    REDACTED, ResponseSensitivity, bounded_text,
};
use crate::Clock;
use crate::types::{ClientId, EntropySource, MAX_JWT_BYTES, RedirectUri};
use omnius_auth_core::SubjectId;
use zeroize::{Zeroize, Zeroizing};

/// Bounded ID Token hint used by RP-Initiated Logout.
#[derive(Clone)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct LogoutSession {
    /// Current canonical browser-session subject.
    pub subject_id: SubjectId,
    /// Signed public subject from the hint, when supplied.
    pub public_subject: Option<String>,
}

/// Validated logout result.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct LogoutResponse {
    /// Exact registered redirect, only after hint and registration validation.
    pub redirect_uri: Option<RedirectUri>,
    /// State returned only alongside a valid redirect.
    pub state: Option<String>,
    /// Logout responses must not be cached.
    pub sensitivity: ResponseSensitivity,
}

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
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
}
