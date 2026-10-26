//! `UserInfo` endpoint flow.

use super::{
    AuthorizationServer, AuthorizationStore, OAuthErrorCode, ProtocolError, ResponseSensitivity,
    has_scope, scope,
};
use crate::Clock;
use crate::types::{EntropySource, ResourceUri};
use crate::verifier::{AccessTokenVerificationError, AccessTokenVerifier};
use serde::Serialize;
use std::sync::Arc;

const USERINFO_PATH: &str = "/oauth/userinfo";

/// OIDC `UserInfo` response for implemented scopes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[non_exhaustive]
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

impl<S, C, E> AuthorizationServer<S, C, E>
where
    S: AuthorizationStore,
    C: Clock,
    E: EntropySource,
{
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

    pub(super) fn userinfo_audience(&self) -> Result<ResourceUri, ProtocolError> {
        ResourceUri::parse(self.config.issuer().endpoint(USERINFO_PATH), false)
            .map_err(|_| ProtocolError::endpoint(OAuthErrorCode::ServerError))
    }
}
