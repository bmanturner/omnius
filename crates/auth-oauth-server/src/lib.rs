//! Transport-neutral first-party OAuth Authorization Server and `OpenID` Provider core.
//!
//! This crate owns strict configuration, bounded protocol values, opaque bearer
//! cryptography, RS256 signing/verification, immutable discovery metadata, and
//! security-policy-constrained client metadata resolution.

pub mod cleanup;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod metadata;
pub mod postgres_adapter;
pub mod service;
pub mod store;
pub mod types;
pub mod verifier;

pub use client::{
    ClientMetadataCacheValidators, ClientMetadataResolver, ClientMetadataResolverError,
    ResolvedClientMetadata,
};
pub use config::{
    AuthorizationServerConfig, DescribedScope, KeyAlgorithm, KeyState, ResourceConfig,
    ResourceDeclaration, ResourceScopeConfig, SigningKeyConfig, ValidatedAuthorizationServerConfig,
};
pub use crypto::{
    AccessTokenClaims, AccessTokenClaimsInput, BearerDigest, BearerDigestDomain, IdTokenClaims,
    IdTokenClaimsInput, IssuedBearer, JwksDocument, RsaPublicJwk, SignedJwt, SigningKeyRing,
    TokenPepper, digest_bearer, issue_bearer, verify_bearer_digest,
};
pub use error::{AuthorizationServerConfigError, OAuthCryptoError, OAuthInputError};
pub use metadata::{
    AuthorizationServerMetadata, MetadataSnapshots, OpenIdProviderMetadata,
    ProtectedResourceMetadata,
};
pub use omnius_core::{Clock, SystemClock};
pub use postgres_adapter::{
    AuthorizedBrowserSession, OAuthAuditError, OAuthAuditEvent, OAuthAuditSink,
    OAuthClientMetadataResolver, OAuthSessionAuthority, OnboardedClient,
    PostgresAdapterConfigError, PostgresOAuthAdapter, PostgresOAuthAdapterInput,
    PostgresRecordMappingError, SessionAuthorityError,
};
pub use service::*;
pub use types::{
    ApplicationType, AuthorizationRequestInput, AuthorizationRequestParts, ClientId,
    ClientMetadata, ClientMetadataInput, EntropySource, GrantId, GrantType, IssuerUri, JwtId,
    MAX_CLIENT_ID_BYTES, MAX_JWT_BYTES, MAX_POST_LOGOUT_REDIRECT_URIS, MAX_REDIRECT_URIS,
    MAX_REQUEST_RESOURCES, MAX_SCOPES, MAX_URI_BYTES, OPAQUE_BEARER_BYTES,
    OPAQUE_BEARER_ENCODED_BYTES, OpaqueBearer, OsEntropy, PkceChallenge, PkceVerifier, Prompt,
    RedirectUri, ResourceUri, ResponseMode, ResponseType, TokenEndpointAuthMethod,
};
pub use verifier::*;
