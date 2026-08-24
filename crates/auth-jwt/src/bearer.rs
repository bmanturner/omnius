use std::ops::Deref;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{HeaderValue, StatusCode, header, request::Parts},
    response::{IntoResponse, Response},
};
use rsk_auth_core::Principal;
use thiserror::Error;

use crate::JwtVerifier;

/// Canonical principal extracted from one verified HTTP Bearer credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BearerPrincipal(pub Principal);

impl Deref for BearerPrincipal {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for BearerPrincipal
where
    S: Send + Sync,
    JwtVerifier: FromRef<S>,
{
    type Rejection = BearerRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let mut values = parts.headers.get_all(header::AUTHORIZATION).iter();
        let value = values.next().ok_or(BearerRejection::Missing)?;
        if values.next().is_some() {
            return Err(BearerRejection::Malformed);
        }
        let value = value.to_str().map_err(|_| BearerRejection::Malformed)?;
        let (scheme, token) = value.split_once(' ').ok_or(BearerRejection::Malformed)?;
        if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
            return Err(BearerRejection::Malformed);
        }
        let verifier = JwtVerifier::from_ref(state);
        verifier
            .verify(token)
            .await
            .map(Self)
            .map_err(|_| BearerRejection::Rejected)
    }
}

/// Value-free HTTP bearer rejection classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BearerRejection {
    /// No authorization header was provided.
    #[error("bearer credential is missing")]
    Missing,
    /// The authorization header was malformed or ambiguous.
    #[error("bearer credential is malformed")]
    Malformed,
    /// Cryptographic or claim verification rejected the token.
    #[error("bearer credential is rejected")]
    Rejected,
}

impl IntoResponse for BearerRejection {
    fn into_response(self) -> Response {
        let mut response = StatusCode::UNAUTHORIZED.into_response();
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        response
    }
}
