//! Stable, value-free failure classifications for the provider core.

use thiserror::Error;

/// Strict authorization-server configuration failure.
///
/// Variants deliberately contain no rejected configuration value or key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AuthorizationServerConfigError {
    /// An enabled server omitted or malformed its issuer.
    #[error("authorization-server issuer configuration is invalid")]
    InvalidIssuer,
    /// The opaque-token pepper was absent, non-canonical, or not exactly 32 bytes.
    #[error("authorization-server token pepper is invalid")]
    InvalidTokenPepper,
    /// One or more protocol lifetimes were outside their fixed bounds.
    #[error("authorization-server lifetime configuration is invalid")]
    InvalidLifetime,
    /// A request or metadata byte ceiling was outside its fixed bounds.
    #[error("authorization-server byte-limit configuration is invalid")]
    InvalidByteLimit,
    /// Resource declarations were empty, duplicated, malformed, or exceeded fixed bounds.
    #[error("authorization-server resource configuration is invalid")]
    InvalidResources,
    /// A resource scope was malformed, reserved, duplicated, or exceeded fixed bounds.
    #[error("authorization-server scope configuration is invalid")]
    InvalidScopes,
    /// Signing-key declarations were empty, duplicated, malformed, or exceeded fixed bounds.
    #[error("authorization-server signing-key configuration is invalid")]
    InvalidSigningKeys,
    /// The active key did not contain one valid PKCS#8 RSA private key.
    #[error("authorization-server active signing key is invalid")]
    InvalidPrivateKey,
    /// A public JWK was not a canonical RS256 RSA verification key.
    #[error("authorization-server public signing key is invalid")]
    InvalidPublicKey,
    /// The active private key did not correspond to its configured public JWK.
    #[error("authorization-server signing key pair is inconsistent")]
    SigningKeyMismatch,
    /// The startup RS256 sign/verify probe failed.
    #[error("authorization-server signing-key probe failed")]
    SigningKeyProbe,
}

/// Bounded OAuth or OIDC input failure.
///
/// The error never retains request text, redirect targets, credentials, or tokens.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OAuthInputError {
    /// A required bounded text value was empty, oversized, or contained control characters.
    #[error("OAuth text input is invalid")]
    InvalidText,
    /// A client identifier was empty, oversized, or malformed.
    #[error("OAuth client identifier is invalid")]
    InvalidClientId,
    /// A URI was malformed, non-canonical, credentialed, fragmented, or insecure.
    #[error("OAuth URI is invalid")]
    InvalidUri,
    /// A redirect URI was malformed or did not meet the HTTPS/loopback policy.
    #[error("OAuth redirect URI is invalid")]
    InvalidRedirectUri,
    /// A scope collection was malformed, duplicated, empty, or exceeded its bound.
    #[error("OAuth scope input is invalid")]
    InvalidScopes,
    /// A resource collection was malformed, duplicated, empty, or exceeded its bound.
    #[error("OAuth resource input is invalid")]
    InvalidResources,
    /// The response type or response mode is not supported.
    #[error("OAuth response selection is unsupported")]
    UnsupportedResponse,
    /// A prompt value or prompt combination is not supported.
    #[error("OpenID Connect prompt input is invalid")]
    InvalidPrompt,
    /// A PKCE challenge or verifier was malformed or used an unsupported method.
    #[error("OAuth PKCE input is invalid")]
    InvalidPkce,
    /// A one-time bearer presentation was malformed or non-canonical.
    #[error("OAuth bearer input is invalid")]
    InvalidBearer,
    /// Client metadata was malformed, internally inconsistent, or exceeded fixed bounds.
    #[error("OAuth client metadata is invalid")]
    InvalidClientMetadata,
    /// A UUID-backed protocol identifier was not an RFC-compatible `UUIDv7` value.
    #[error("OAuth protocol identifier is invalid")]
    InvalidIdentifier,
    /// JWT claims were missing, malformed, inconsistent, or outside their validity interval.
    #[error("OAuth token claims are invalid")]
    InvalidClaims,
}

/// Secret generation, digest, signing, or verification failure.
///
/// Variants are safe for logs and never contain a token, digest, pepper, claim, or key.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OAuthCryptoError {
    /// The operating-system entropy source failed.
    #[error("OAuth secure entropy is unavailable")]
    EntropyUnavailable,
    /// The token pepper was unavailable or invalid.
    #[error("OAuth token digest key is invalid")]
    InvalidPepper,
    /// The bearer presentation was malformed or non-canonical.
    #[error("OAuth bearer presentation is invalid")]
    InvalidBearer,
    /// The supplied digest did not authenticate the presentation for the selected domain.
    #[error("OAuth bearer digest does not match")]
    DigestMismatch,
    /// No configured key matched the required key identifier.
    #[error("OAuth signing key is unavailable")]
    KeyUnavailable,
    /// JWT creation failed.
    #[error("OAuth token signing failed")]
    SigningFailed,
    /// The encoded token or its JOSE header was malformed or outside fixed bounds.
    #[error("OAuth token header is invalid")]
    InvalidTokenHeader,
    /// JWT signature verification failed.
    #[error("OAuth token signature is invalid")]
    InvalidSignature,
    /// JWT claims failed exact issuer, audience, type, lifetime, or domain checks.
    #[error("OAuth token claims are invalid")]
    InvalidClaims,
}
