//! Issuer-local access-token verification with one live authorization decision.

use std::{future::Future, sync::Arc};

use omnius_auth_core::{
    AssuranceLevel, AuthMethod, Principal, PrincipalKind, Scope, SubjectId, TenantId,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    Clock,
    crypto::{AccessTokenClaims, SigningKeyRing},
    types::{ClientId, GrantId, IssuerUri, JwtId, MAX_JWT_BYTES, MAX_SCOPES, ResourceUri},
};

/// Value-free persistence failure exposed by protocol storage adapters.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("OAuth protocol storage operation failed")]
pub struct OAuthStoreError;

/// The complete live-state decision requested after cryptographic JWT validation.
///
/// A store implementation must evaluate the user status and authentication version,
/// client status, grant revocation/version, tenant membership, and access-token JTI
/// revocation in one consistent read. Returning an identity asserts every check passed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessTokenLiveCheck {
    /// Stable issuer-public subject carried by the token.
    pub public_subject: String,
    /// Exact client bound to the token and grant.
    pub client_id: ClientId,
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// Exact resource audience.
    pub audience: ResourceUri,
    /// JWT identifier checked against the revocation set.
    pub jwt_id: JwtId,
    /// Sorted, unique token scopes already checked against the audience policy.
    pub scopes: Vec<Scope>,
}

/// Canonical identity returned only after all live authorization checks succeed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessTokenIdentity {
    /// Internal canonical subject identifier. It is never copied into a JWT.
    pub subject_id: SubjectId,
    /// Canonical principal kind.
    pub kind: PrincipalKind,
    /// Revalidated tenant context, when the grant is tenant-scoped.
    pub tenant_id: Option<TenantId>,
    /// Authentication time retained by the live grant.
    pub authenticated_at: OffsetDateTime,
    /// Authentication assurance retained by the live grant.
    pub assurance: AssuranceLevel,
    /// Stable issuer-public subject, which must equal the checked JWT subject.
    pub public_subject: String,
    /// Verified local email, when one currently exists.
    pub verified_email: Option<String>,
}

/// Live authorization state required by the issuer-local verifier.
///
/// The single method is deliberately coarse: splitting these checks across calls
/// permits client-disable, grant-revoke, membership, and JTI-revoke races.
pub trait AccessTokenStateStore: Send + Sync {
    /// Atomically authorizes a cryptographically valid access token against live state.
    fn authorize_access_token(
        &self,
        check: AccessTokenLiveCheck,
    ) -> impl Future<Output = Result<Option<AccessTokenIdentity>, OAuthStoreError>> + Send;
}

/// Stable, value-free access-token rejection classes.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccessTokenVerificationError {
    /// The presentation, JOSE header, signature, registered claims, or scope policy is invalid.
    #[error("access token is invalid")]
    InvalidToken,
    /// Cryptography succeeded but current authorization state denies the token.
    #[error("access token is inactive")]
    Inactive,
    /// Live authorization state could not be read safely.
    #[error("access token authorization state is unavailable")]
    StoreUnavailable,
}

/// A verified access token and its sole canonical authentication result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAccessToken {
    /// Canonical principal safe for request authentication.
    pub principal: Principal,
    /// Stable public subject used by OIDC `UserInfo`.
    pub public_subject: String,
    /// Verified email currently attached to the subject, if any.
    pub verified_email: Option<String>,
    /// Exact OAuth client.
    pub client_id: ClientId,
    /// Durable grant identifier.
    pub grant_id: GrantId,
    /// JWT identifier.
    pub jwt_id: JwtId,
    /// Exact token audience.
    pub audience: ResourceUri,
    /// Sorted token scopes.
    pub scopes: Vec<Scope>,
}

/// Issuer-local verifier for one exact configured audience.
#[derive(Clone)]
pub struct AccessTokenVerifier<S, C> {
    keys: Arc<SigningKeyRing>,
    issuer: IssuerUri,
    audience: ResourceUri,
    allowed_scopes: Arc<[Scope]>,
    store: Arc<S>,
    clock: Arc<C>,
}

impl<S, C> std::fmt::Debug for AccessTokenVerifier<S, C> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessTokenVerifier")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("allowed_scope_count", &self.allowed_scopes.len())
            .finish_non_exhaustive()
    }
}

impl<S, C> AccessTokenVerifier<S, C>
where
    S: AccessTokenStateStore,
    C: Clock,
{
    /// Builds a verifier for one audience and its complete scope allow-list.
    ///
    /// Invalid or duplicate scope policy is rejected before any token is handled.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenVerificationError::InvalidToken`] when the scope
    /// allow-list is empty, exceeds the configured bound, or contains duplicates.
    pub fn new(
        keys: Arc<SigningKeyRing>,
        issuer: IssuerUri,
        audience: ResourceUri,
        mut allowed_scopes: Vec<Scope>,
        store: Arc<S>,
        clock: Arc<C>,
    ) -> Result<Self, AccessTokenVerificationError> {
        allowed_scopes.sort_unstable();
        if allowed_scopes.is_empty()
            || allowed_scopes.len() > MAX_SCOPES
            || allowed_scopes.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(AccessTokenVerificationError::InvalidToken);
        }
        Ok(Self {
            keys,
            issuer,
            audience,
            allowed_scopes: allowed_scopes.into(),
            store,
            clock,
        })
    }

    /// Verifies JOSE and claims, then performs exactly one live authorization read.
    ///
    /// # Errors
    ///
    /// Returns [`AccessTokenVerificationError::InvalidToken`] when the token,
    /// signature, claims, scope policy, or resulting principal is invalid;
    /// [`AccessTokenVerificationError::Inactive`] when live authorization denies
    /// it; or [`AccessTokenVerificationError::StoreUnavailable`] when live state
    /// cannot be read safely.
    pub async fn verify(
        &self,
        token: &str,
    ) -> Result<VerifiedAccessToken, AccessTokenVerificationError> {
        if token.is_empty()
            || token.len() > MAX_JWT_BYTES
            || token.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(AccessTokenVerificationError::InvalidToken);
        }
        let claims = self
            .keys
            .verify_access_token(token, &self.issuer, &self.audience, self.clock.now_utc())
            .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        let parsed = ParsedAccessClaims::try_from(claims)?;
        if parsed
            .scopes
            .iter()
            .any(|scope| self.allowed_scopes.binary_search(scope).is_err())
        {
            return Err(AccessTokenVerificationError::InvalidToken);
        }
        let identity = self
            .store
            .authorize_access_token(AccessTokenLiveCheck {
                public_subject: parsed.public_subject.clone(),
                client_id: parsed.client_id.clone(),
                grant_id: parsed.grant_id,
                audience: self.audience.clone(),
                jwt_id: parsed.jwt_id,
                scopes: parsed.scopes.clone(),
            })
            .await
            .map_err(|_| AccessTokenVerificationError::StoreUnavailable)?
            .ok_or(AccessTokenVerificationError::Inactive)?;
        if identity.public_subject != parsed.public_subject {
            return Err(AccessTokenVerificationError::Inactive);
        }
        let principal = Principal::new(
            identity.subject_id,
            identity.kind,
            identity.tenant_id,
            AuthMethod::Jwt,
            identity.authenticated_at,
            identity.assurance,
            parsed.scopes.clone(),
        )
        .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        Ok(VerifiedAccessToken {
            principal,
            public_subject: identity.public_subject,
            verified_email: identity.verified_email,
            client_id: parsed.client_id,
            grant_id: parsed.grant_id,
            jwt_id: parsed.jwt_id,
            audience: self.audience.clone(),
            scopes: parsed.scopes,
        })
    }
}

struct ParsedAccessClaims {
    public_subject: String,
    client_id: ClientId,
    grant_id: GrantId,
    jwt_id: JwtId,
    scopes: Vec<Scope>,
}

impl TryFrom<AccessTokenClaims> for ParsedAccessClaims {
    type Error = AccessTokenVerificationError;

    fn try_from(claims: AccessTokenClaims) -> Result<Self, Self::Error> {
        let client_id = ClientId::parse(claims.client_id().to_owned())
            .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        let grant_id = GrantId::from_uuid(claims.grant_id())
            .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        let jwt_id = JwtId::from_uuid(claims.jwt_id())
            .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        let scopes = claims
            .scope()
            .split(' ')
            .map(|value| Scope::new(value.to_owned()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccessTokenVerificationError::InvalidToken)?;
        if scopes.is_empty()
            || scopes.len() > MAX_SCOPES
            || scopes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(AccessTokenVerificationError::InvalidToken);
        }
        Ok(Self {
            public_subject: claims.subject().to_owned(),
            client_id,
            grant_id,
            jwt_id,
            scopes,
        })
    }
}
