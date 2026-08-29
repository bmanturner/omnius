//! Opaque bearer derivation and pinned RS256 JOSE primitives.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac as _};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
    jwk::{AlgorithmParameters, Jwk},
};
use omnius_auth_core::Scope;
use omnius_config::ExposeSecret as _;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::Sha256;
use time::OffsetDateTime;
use uuid::{Uuid, Variant, Version};
use zeroize::{Zeroize as _, Zeroizing};

use crate::{
    config::{KeyState, SigningKeyConfig},
    error::{AuthorizationServerConfigError, OAuthCryptoError, OAuthInputError},
    types::{
        ClientId, EntropySource, GrantId, IssuerUri, JwtId, MAX_JWT_BYTES, MAX_SCOPES,
        OPAQUE_BEARER_BYTES, OpaqueBearer, ResourceUri,
    },
};

const PEPPER_BYTES: usize = 32;
const MAX_KID_BYTES: usize = 128;
const MAX_RSA_MODULUS_ENCODED_BYTES: usize = 1_024;
const MAX_RSA_EXPONENT_ENCODED_BYTES: usize = 16;
const MIN_RSA_MODULUS_BYTES: usize = 256;
const MAX_RSA_MODULUS_BYTES: usize = 512;
const MAX_ACR_BYTES: usize = 128;
const MAX_AMR_VALUES: usize = 16;
const MAX_AMR_BYTES: usize = 64;
const MAX_EMAIL_BYTES: usize = 320;
const MAX_NONCE_BYTES: usize = 1_024;
const MAX_PRIVATE_KEY_BYTES: usize = 16 * 1_024;
const REDACTED: &str = "[REDACTED]";
const PKCS8_BEGIN: &str = concat!("-----BEGIN ", "PRIVATE KEY-----\n");
const PKCS8_END: &str = "-----END PRIVATE KEY-----";
const DIGEST_PREFIX: &[u8] = b"omnius.oauth.opaque.v1\0";

type HmacSha256 = Hmac<Sha256>;

/// Canonical exact 32-byte token pepper decoded from unpadded base64url.
#[derive(Clone)]
pub struct TokenPepper(Zeroizing<[u8; PEPPER_BYTES]>);

impl TokenPepper {
    /// Parses canonical unpadded base64url into an exact 32-byte key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationServerConfigError::InvalidTokenPepper`] when
    /// `value` is not the canonical unpadded base64url encoding of exactly
    /// 32 bytes.
    pub fn parse(value: &str) -> Result<Self, AuthorizationServerConfigError> {
        if value.len() != 43
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(AuthorizationServerConfigError::InvalidTokenPepper);
        }
        let mut decoded = Zeroizing::new([0_u8; PEPPER_BYTES]);
        let Ok(decoded_len) = URL_SAFE_NO_PAD.decode_slice(value, decoded.as_mut_slice()) else {
            return Err(AuthorizationServerConfigError::InvalidTokenPepper);
        };
        let mut canonical = Zeroizing::new([0_u8; 43]);
        let Ok(encoded_len) =
            URL_SAFE_NO_PAD.encode_slice(decoded.as_slice(), canonical.as_mut_slice())
        else {
            return Err(AuthorizationServerConfigError::InvalidTokenPepper);
        };
        if decoded_len != PEPPER_BYTES || &canonical[..encoded_len] != value.as_bytes() {
            return Err(AuthorizationServerConfigError::InvalidTokenPepper);
        }
        Ok(Self(decoded))
    }

    pub(crate) fn key(&self) -> &[u8; PEPPER_BYTES] {
        &self.0
    }
}

impl fmt::Debug for TokenPepper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("TokenPepper")
            .field(&REDACTED)
            .finish()
    }
}

impl<'de> Deserialize<'de> for TokenPepper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = String::deserialize(deserializer)?;
        let result = Self::parse(&value).map_err(D::Error::custom);
        value.zeroize();
        result
    }
}

/// Domain separation labels for persisted opaque-bearer digests.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BearerDigestDomain {
    /// Browser authorization-request handle.
    AuthorizationRequest,
    /// Authorization code.
    AuthorizationCode,
    /// Refresh token.
    RefreshToken,
    /// Generated dynamic-client secret.
    ClientSecret,
}

impl BearerDigestDomain {
    const fn label(self) -> &'static [u8] {
        match self {
            Self::AuthorizationRequest => b"authorization-request",
            Self::AuthorizationCode => b"authorization-code",
            Self::RefreshToken => b"refresh-token",
            Self::ClientSecret => b"client-secret",
        }
    }
}

/// Exact HMAC-SHA-256 digest persisted instead of an opaque bearer presentation.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerDigest([u8; 32]);

impl BearerDigest {
    /// Restores one exact 32-byte digest from durable storage.
    #[must_use]
    pub const fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Borrows the exact bytes written to durable storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BearerDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BearerDigest")
            .field(&REDACTED)
            .finish()
    }
}

/// One generated presentation and its independently persistable digest.
pub struct IssuedBearer {
    /// Presentation revealed exactly once to its protocol boundary.
    pub presentation: OpaqueBearer,
    /// Domain-separated HMAC digest safe for persistence.
    pub digest: BearerDigest,
}

impl fmt::Debug for IssuedBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedBearer")
            .field("presentation", &REDACTED)
            .field("digest", &REDACTED)
            .finish()
    }
}

/// Generates and digests one exact 32-byte opaque bearer.
///
/// # Errors
///
/// Returns [`OAuthCryptoError::EntropyUnavailable`] when secure entropy
/// generation fails, or [`OAuthCryptoError::InvalidPepper`] when the digest
/// key cannot initialize the HMAC.
pub fn issue_bearer(
    entropy: &impl EntropySource,
    pepper: &TokenPepper,
    domain: BearerDigestDomain,
) -> Result<IssuedBearer, OAuthCryptoError> {
    let presentation = OpaqueBearer::generate(entropy)?;
    let digest = digest_bearer(&presentation, pepper, domain)?;
    Ok(IssuedBearer {
        presentation,
        digest,
    })
}

/// Computes a domain-separated HMAC-SHA-256 digest for one bearer.
///
/// # Errors
///
/// Returns [`OAuthCryptoError::InvalidPepper`] when the digest key cannot
/// initialize the HMAC.
pub fn digest_bearer(
    bearer: &OpaqueBearer,
    pepper: &TokenPepper,
    domain: BearerDigestDomain,
) -> Result<BearerDigest, OAuthCryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(pepper.key()).map_err(|_| OAuthCryptoError::InvalidPepper)?;
    update_digest_transcript(&mut mac, bearer, domain);
    Ok(BearerDigest(mac.finalize().into_bytes().into()))
}

/// Compares a presented bearer with a stored digest in constant time.
///
/// # Errors
///
/// Returns [`OAuthCryptoError::InvalidPepper`] when the digest key cannot
/// initialize the HMAC, or [`OAuthCryptoError::DigestMismatch`] when the
/// presentation does not authenticate against `expected` in `domain`.
pub fn verify_bearer_digest(
    bearer: &OpaqueBearer,
    expected: &BearerDigest,
    pepper: &TokenPepper,
    domain: BearerDigestDomain,
) -> Result<(), OAuthCryptoError> {
    let mut mac =
        HmacSha256::new_from_slice(pepper.key()).map_err(|_| OAuthCryptoError::InvalidPepper)?;
    update_digest_transcript(&mut mac, bearer, domain);
    mac.verify_slice(expected.as_bytes())
        .map_err(|_| OAuthCryptoError::DigestMismatch)
}

fn update_digest_transcript(
    mac: &mut HmacSha256,
    bearer: &OpaqueBearer,
    domain: BearerDigestDomain,
) {
    mac.update(DIGEST_PREFIX);
    mac.update(domain.label());
    mac.update(&[0]);
    mac.update(bearer.material());
}

/// Canonical public RSA JWK accepted for signing-key publication.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RsaPublicJwk {
    /// Key type, exactly `RSA`.
    pub kty: String,
    /// Intended use, exactly `sig`.
    #[serde(rename = "use")]
    pub public_key_use: String,
    /// Key operations, exactly `["verify"]`.
    pub key_ops: Vec<String>,
    /// JOSE algorithm, exactly `RS256`.
    pub alg: String,
    /// Unique bounded key identifier.
    pub kid: String,
    /// Canonical unpadded base64url RSA modulus.
    pub n: String,
    /// Canonical unpadded base64url RSA public exponent.
    pub e: String,
}

impl RsaPublicJwk {
    pub(crate) fn validate_for_kid(
        &self,
        expected_kid: &str,
    ) -> Result<(), AuthorizationServerConfigError> {
        if self.kty != "RSA"
            || self.public_key_use != "sig"
            || self.key_ops.len() != 1
            || self.key_ops[0] != "verify"
            || self.alg != "RS256"
            || self.kid != expected_kid
            || !valid_kid(&self.kid)
        {
            return Err(AuthorizationServerConfigError::InvalidPublicKey);
        }
        let modulus = decode_canonical_component(
            &self.n,
            MAX_RSA_MODULUS_ENCODED_BYTES,
            MIN_RSA_MODULUS_BYTES,
            MAX_RSA_MODULUS_BYTES,
        )?;
        let exponent = decode_canonical_component(&self.e, MAX_RSA_EXPONENT_ENCODED_BYTES, 1, 8)?;
        if modulus.first() == Some(&0) || exponent.first() == Some(&0) {
            return Err(AuthorizationServerConfigError::InvalidPublicKey);
        }
        let exponent = exponent
            .iter()
            .fold(0_u64, |value, byte| value << 8 | u64::from(*byte));
        if exponent < 3 || exponent % 2 == 0 {
            return Err(AuthorizationServerConfigError::InvalidPublicKey);
        }
        DecodingKey::from_rsa_components(&self.n, &self.e)
            .map_err(|_| AuthorizationServerConfigError::InvalidPublicKey)?;
        Ok(())
    }

    fn decoding_key(&self) -> Result<DecodingKey, AuthorizationServerConfigError> {
        DecodingKey::from_rsa_components(&self.n, &self.e)
            .map_err(|_| AuthorizationServerConfigError::InvalidPublicKey)
    }
}

/// Deterministic JWKS representation containing public verification keys only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JwksDocument {
    /// Active and unexpired retiring keys, ordered by `kid`.
    pub keys: Vec<RsaPublicJwk>,
}

#[derive(Clone)]
struct ActiveSigningKey {
    kid: String,
    key: EncodingKey,
}

#[derive(Clone)]
struct VerificationKey {
    key: DecodingKey,
    public_jwk: RsaPublicJwk,
    verification_until: Option<OffsetDateTime>,
}

impl VerificationKey {
    fn is_available_at(&self, now: OffsetDateTime) -> bool {
        self.verification_until.is_none_or(|until| now < until)
    }
}

/// Immutable active signer and time-bounded verification keys.
#[derive(Clone)]
pub struct SigningKeyRing {
    active: ActiveSigningKey,
    verification: Arc<BTreeMap<String, VerificationKey>>,
}

impl fmt::Debug for SigningKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SigningKeyRing")
            .field("active_kid", &self.active.kid)
            .field("verification_key_count", &self.verification.len())
            .finish_non_exhaustive()
    }
}

impl SigningKeyRing {
    /// Validates configured key roles, RSA material, pair consistency, and a startup probe.
    ///
    /// # Errors
    ///
    /// Returns an [`AuthorizationServerConfigError`] when the key count, key
    /// identifiers, roles, public or private key material, key-pair
    /// consistency, or startup sign/verify probe violates the signing-key
    /// policy.
    pub fn from_config(
        configs: &[SigningKeyConfig],
        _now: OffsetDateTime,
    ) -> Result<Self, AuthorizationServerConfigError> {
        if configs.is_empty() || configs.len() > 8 {
            return Err(AuthorizationServerConfigError::InvalidSigningKeys);
        }
        let mut seen = HashSet::with_capacity(configs.len());
        let mut active = None;
        let mut verification = BTreeMap::new();

        for config in configs {
            if !valid_kid(&config.kid) || !seen.insert(config.kid.as_str()) {
                return Err(AuthorizationServerConfigError::InvalidSigningKeys);
            }
            config.public_jwk.validate_for_kid(&config.kid)?;
            match config.state {
                KeyState::Active => {
                    if active.is_some() || config.verification_until.is_some() {
                        return Err(AuthorizationServerConfigError::InvalidSigningKeys);
                    }
                    let secret = config
                        .private_key_pkcs8_pem
                        .as_ref()
                        .ok_or(AuthorizationServerConfigError::InvalidPrivateKey)?;
                    let pem = secret.expose_secret();
                    if pem.len() > MAX_PRIVATE_KEY_BYTES
                        || !pem.starts_with(PKCS8_BEGIN)
                        || !pem.trim_end().ends_with(PKCS8_END)
                    {
                        return Err(AuthorizationServerConfigError::InvalidPrivateKey);
                    }
                    let encoding = EncodingKey::from_rsa_pem(pem.as_bytes())
                        .map_err(|_| AuthorizationServerConfigError::InvalidPrivateKey)?;
                    ensure_key_pair(&encoding, &config.public_jwk)?;
                    let decoding = config.public_jwk.decoding_key()?;
                    sign_verify_probe(&config.kid, &encoding, &decoding)?;
                    verification.insert(
                        config.kid.clone(),
                        VerificationKey {
                            key: decoding,
                            public_jwk: config.public_jwk.clone(),
                            verification_until: None,
                        },
                    );
                    active = Some(ActiveSigningKey {
                        kid: config.kid.clone(),
                        key: encoding,
                    });
                }
                KeyState::Retiring => {
                    if config.private_key_pkcs8_pem.is_some() || config.verification_until.is_none()
                    {
                        return Err(AuthorizationServerConfigError::InvalidSigningKeys);
                    }
                    verification.insert(
                        config.kid.clone(),
                        VerificationKey {
                            key: config.public_jwk.decoding_key()?,
                            public_jwk: config.public_jwk.clone(),
                            verification_until: config.verification_until,
                        },
                    );
                }
            }
        }
        let active = active.ok_or(AuthorizationServerConfigError::InvalidSigningKeys)?;
        Ok(Self {
            active,
            verification: Arc::new(verification),
        })
    }

    /// Active signing-key identifier.
    #[must_use]
    pub fn active_kid(&self) -> &str {
        &self.active.kid
    }

    /// Active-plus-unexpired-retiring JWKS evaluated at the supplied time.
    #[must_use]
    pub fn jwks(&self, now: OffsetDateTime) -> JwksDocument {
        JwksDocument {
            keys: self
                .verification
                .values()
                .filter(|key| key.is_available_at(now))
                .map(|key| key.public_jwk.clone())
                .collect(),
        }
    }

    /// Signs one structurally valid issuer-local `at+jwt` access token.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthCryptoError::InvalidClaims`] when `claims` violates the
    /// access-token claim policy, or [`OAuthCryptoError::SigningFailed`] when
    /// signing fails or the encoded token exceeds its bound.
    pub fn sign_access_token(
        &self,
        claims: &AccessTokenClaims,
    ) -> Result<SignedJwt, OAuthCryptoError> {
        claims.validate(None, None, None)?;
        self.sign("at+jwt", claims)
    }

    /// Signs one structurally valid `OpenID Connect` ID Token.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthCryptoError::InvalidClaims`] when `claims` violates the
    /// ID Token claim policy, or [`OAuthCryptoError::SigningFailed`] when
    /// signing fails or the encoded token exceeds its bound.
    pub fn sign_id_token(&self, claims: &IdTokenClaims) -> Result<SignedJwt, OAuthCryptoError> {
        claims.validate(None, None, None)?;
        self.sign("JWT", claims)
    }

    /// Verifies signature, JOSE header, exact issuer/audience, temporal claims, IDs, and scopes.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthCryptoError`] when the JOSE header is invalid, its key
    /// is unavailable, signature verification fails, or the claims violate
    /// the exact issuer, audience, temporal, identifier, or scope policy.
    pub fn verify_access_token(
        &self,
        token: &str,
        expected_issuer: &IssuerUri,
        expected_audience: &ResourceUri,
        now: OffsetDateTime,
    ) -> Result<AccessTokenClaims, OAuthCryptoError> {
        let (kid, algorithm) = validated_header(token, "at+jwt")?;
        let key = self.verification_key(&kid, now)?;
        let mut validation = signature_validation(algorithm, true);
        validation.set_issuer(&[expected_issuer.as_str()]);
        validation.set_audience(&[expected_audience.as_str()]);
        let claims = decode::<AccessTokenClaims>(token, key, &validation)
            .map_err(|_| OAuthCryptoError::InvalidSignature)?
            .claims;
        claims.validate(Some(expected_issuer), Some(expected_audience), Some(now))?;
        Ok(claims)
    }
    /// Verifies an issuer-local access token without a caller-supplied audience.
    ///
    /// This is limited to endpoints such as RFC 7009 that receive the token
    /// itself but no standard audience parameter. Callers must authorize the
    /// returned audience before acting on the claims.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthCryptoError`] when the JOSE header is invalid, its key
    /// is unavailable, signature verification fails, or the claims violate
    /// the exact issuer, temporal, identifier, or scope policy.
    pub fn verify_access_token_for_issuer(
        &self,
        token: &str,
        expected_issuer: &IssuerUri,
        now: OffsetDateTime,
    ) -> Result<AccessTokenClaims, OAuthCryptoError> {
        let (kid, algorithm) = validated_header(token, "at+jwt")?;
        let key = self.verification_key(&kid, now)?;
        let mut validation = signature_validation(algorithm, true);
        validation.set_issuer(&[expected_issuer.as_str()]);
        validation.validate_aud = false;
        let claims = decode::<AccessTokenClaims>(token, key, &validation)
            .map_err(|_| OAuthCryptoError::InvalidSignature)?
            .claims;
        claims.validate(Some(expected_issuer), None, Some(now))?;
        Ok(claims)
    }

    /// Verifies signature, header, issuer, client audience, nonce, and OIDC claim consistency.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthCryptoError`] when the JOSE header is invalid, its key
    /// is unavailable, signature verification fails, or the claims violate
    /// the exact issuer, client audience, nonce, temporal, or OIDC claim
    /// policy.
    pub fn verify_id_token(
        &self,
        token: &str,
        expected_issuer: &IssuerUri,
        expected_client: &ClientId,
        expected_nonce: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<IdTokenClaims, OAuthCryptoError> {
        let (kid, algorithm) = validated_header(token, "JWT")?;
        let key = self.verification_key(&kid, now)?;
        let mut validation = signature_validation(algorithm, false);
        validation.set_issuer(&[expected_issuer.as_str()]);
        validation.set_audience(&[expected_client.as_str()]);
        let claims = decode::<IdTokenClaims>(token, key, &validation)
            .map_err(|_| OAuthCryptoError::InvalidSignature)?
            .claims;
        claims.validate(
            Some(expected_issuer),
            Some(expected_client),
            Some((expected_nonce, now)),
        )?;
        Ok(claims)
    }

    fn verification_key(
        &self,
        kid: &str,
        now: OffsetDateTime,
    ) -> Result<&DecodingKey, OAuthCryptoError> {
        let key = self
            .verification
            .get(kid)
            .filter(|key| key.is_available_at(now))
            .ok_or(OAuthCryptoError::KeyUnavailable)?;
        Ok(&key.key)
    }

    fn sign<T: Serialize>(
        &self,
        token_type: &str,
        claims: &T,
    ) -> Result<SignedJwt, OAuthCryptoError> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.active.kid.clone());
        header.typ = Some(token_type.to_owned());
        let token = encode(&header, claims, &self.active.key)
            .map_err(|_| OAuthCryptoError::SigningFailed)?;
        if token.len() > MAX_JWT_BYTES {
            return Err(OAuthCryptoError::SigningFailed);
        }
        Ok(SignedJwt(Zeroizing::new(token)))
    }
}

/// Signed JWT held in zeroizing storage and redacted from diagnostics.
pub struct SignedJwt(Zeroizing<String>);

impl SignedJwt {
    /// Borrows the token only for an immediate transport or verification boundary.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Consumes and reveals the token for a single protocol response.
    #[must_use]
    pub fn expose_once(self) -> String {
        self.0.as_str().to_owned()
    }
}

impl fmt::Debug for SignedJwt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("SignedJwt").field(&REDACTED).finish()
    }
}

/// Typed inputs for an issuer-local resource access token.
#[derive(Clone, Debug)]
pub struct AccessTokenClaimsInput {
    /// Exact configured issuer.
    pub issuer: IssuerUri,
    /// Stable issuer-public subject, never an internal user UUID.
    pub subject: String,
    /// Exact resource audience.
    pub audience: ResourceUri,
    /// Expiration instant.
    pub expires_at: OffsetDateTime,
    /// Not-before instant.
    pub not_before: OffsetDateTime,
    /// Issuance instant.
    pub issued_at: OffsetDateTime,
    /// `UUIDv7` token identifier.
    pub jwt_id: JwtId,
    /// OAuth client identifier.
    pub client_id: ClientId,
    /// `UUIDv7` grant identifier.
    pub grant_id: GrantId,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Authentication time.
    pub auth_time: OffsetDateTime,
    /// Authentication context class reference.
    pub acr: String,
    /// Authentication methods references.
    pub amr: Vec<String>,
}

/// Claims carried by an issuer-local `at+jwt` access token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    nbf: u64,
    iat: u64,
    jti: Uuid,
    client_id: String,
    grant_id: Uuid,
    scope: String,
    auth_time: u64,
    acr: String,
    amr: Vec<String>,
}

impl AccessTokenClaims {
    /// Constructs validated access-token claims from typed protocol values.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidScopes`] when scopes are empty,
    /// duplicated, or exceed their bound. Returns
    /// [`OAuthInputError::InvalidClaims`] when a timestamp cannot be encoded
    /// or any remaining claim violates the access-token claim policy.
    pub fn new(input: AccessTokenClaimsInput) -> Result<Self, OAuthInputError> {
        let mut scopes = input.scopes;
        scopes.sort_unstable();
        if scopes.is_empty()
            || scopes.len() > MAX_SCOPES
            || scopes.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(OAuthInputError::InvalidScopes);
        }
        let mut amr = input.amr;
        amr.sort_unstable();
        if amr.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OAuthInputError::InvalidClaims);
        }
        let claims = Self {
            iss: input.issuer.as_str().to_owned(),
            sub: input.subject,
            aud: input.audience.as_str().to_owned(),
            exp: unix_seconds(input.expires_at)?,
            nbf: unix_seconds(input.not_before)?,
            iat: unix_seconds(input.issued_at)?,
            jti: input.jwt_id.as_uuid(),
            client_id: input.client_id.as_str().to_owned(),
            grant_id: input.grant_id.as_uuid(),
            scope: scopes
                .iter()
                .map(Scope::as_str)
                .collect::<Vec<_>>()
                .join(" "),
            auth_time: unix_seconds(input.auth_time)?,
            acr: input.acr,
            amr,
        };
        claims
            .validate(None, None, None)
            .map_err(|_| OAuthInputError::InvalidClaims)?;
        Ok(claims)
    }

    /// Exact token issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// Stable issuer-public subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// Exact resource audience.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.aud
    }

    /// `UUIDv7` JWT identifier.
    #[must_use]
    pub const fn jwt_id(&self) -> Uuid {
        self.jti
    }

    /// OAuth client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// `UUIDv7` grant identifier.
    #[must_use]
    pub const fn grant_id(&self) -> Uuid {
        self.grant_id
    }

    /// Space-delimited sorted scope claim.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }

    fn validate(
        &self,
        expected_issuer: Option<&IssuerUri>,
        expected_audience: Option<&ResourceUri>,
        now: Option<OffsetDateTime>,
    ) -> Result<(), OAuthCryptoError> {
        let times_valid = self.exp > self.iat
            && self.exp - self.iat <= 3_600
            && self.nbf <= self.exp
            && self.auth_time <= self.iat
            && now.is_none_or(|now| {
                u64::try_from(now.unix_timestamp())
                    .is_ok_and(|now| self.iat <= now && self.nbf <= now && self.exp > now)
            });
        if !times_valid
            || IssuerUri::parse(self.iss.clone(), false).is_err()
            || ResourceUri::parse(self.aud.clone(), false).is_err()
            || !valid_public_subject(&self.sub)
            || ClientId::parse(self.client_id.clone()).is_err()
            || !uuid_v7(self.jti)
            || !uuid_v7(self.grant_id)
            || !valid_claim_scopes(&self.scope)
            || !valid_acr_amr(&self.acr, &self.amr)
            || expected_issuer.is_some_and(|issuer| issuer.as_str() != self.iss)
            || expected_audience.is_some_and(|audience| audience.as_str() != self.aud)
        {
            return Err(OAuthCryptoError::InvalidClaims);
        }
        Ok(())
    }
}

/// Typed inputs for one `OpenID Connect` ID Token.
#[derive(Clone, Debug)]
pub struct IdTokenClaimsInput {
    /// Exact configured issuer.
    pub issuer: IssuerUri,
    /// Stable issuer-public subject.
    pub subject: String,
    /// Client audience.
    pub audience: ClientId,
    /// Expiration instant.
    pub expires_at: OffsetDateTime,
    /// Issuance instant.
    pub issued_at: OffsetDateTime,
    /// Authentication time.
    pub auth_time: OffsetDateTime,
    /// Authentication context class reference.
    pub acr: String,
    /// Authentication methods references.
    pub amr: Vec<String>,
    /// Authorization nonce echoed exactly when supplied.
    pub nonce: Option<String>,
    /// Authorized party when OIDC audience rules require it.
    pub authorized_party: Option<ClientId>,
    /// Verified local email released only under the `email` scope.
    pub email: Option<String>,
    /// Must be true exactly when a verified email is present.
    pub email_verified: Option<bool>,
}

/// Claims carried by a signed `OpenID Connect` ID Token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdTokenClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: u64,
    iat: u64,
    auth_time: u64,
    acr: String,
    amr: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    azp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email_verified: Option<bool>,
}

impl IdTokenClaims {
    /// Constructs and validates one minimal, public-subject ID Token claim set.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidClaims`] when authentication methods
    /// are duplicated, a timestamp cannot be encoded, or any claim violates
    /// the ID Token claim policy.
    pub fn new(input: IdTokenClaimsInput) -> Result<Self, OAuthInputError> {
        let mut amr = input.amr;
        amr.sort_unstable();
        if amr.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OAuthInputError::InvalidClaims);
        }
        let claims = Self {
            iss: input.issuer.as_str().to_owned(),
            sub: input.subject,
            aud: input.audience.as_str().to_owned(),
            exp: unix_seconds(input.expires_at)?,
            iat: unix_seconds(input.issued_at)?,
            auth_time: unix_seconds(input.auth_time)?,
            acr: input.acr,
            amr,
            nonce: input.nonce,
            azp: input
                .authorized_party
                .map(|client| client.as_str().to_owned()),
            email: input.email,
            email_verified: input.email_verified,
        };
        claims
            .validate(None, None, None)
            .map_err(|_| OAuthInputError::InvalidClaims)?;
        Ok(claims)
    }

    /// Exact token issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// Stable issuer-public subject.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.sub
    }

    /// Client audience.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.aud
    }

    /// Nonce echoed from the authorization request.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Verified email claim, when consented.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    fn validate(
        &self,
        expected_issuer: Option<&IssuerUri>,
        expected_client: Option<&ClientId>,
        expected: Option<(Option<&str>, OffsetDateTime)>,
    ) -> Result<(), OAuthCryptoError> {
        let times_valid = self.exp > self.iat
            && self.exp - self.iat <= 900
            && self.auth_time <= self.iat
            && expected.is_none_or(|(_, now)| {
                u64::try_from(now.unix_timestamp())
                    .is_ok_and(|now| self.iat <= now && self.exp > now)
            });
        let nonce_valid = expected.is_none_or(|(expected_nonce, _)| match expected_nonce {
            Some(expected) => self.nonce.as_deref() == Some(expected),
            None => self.nonce.is_none(),
        });
        let email_valid = match (&self.email, self.email_verified) {
            (None, None) => true,
            (Some(email), Some(true)) => valid_email_claim(email),
            _ => false,
        };
        if !times_valid
            || !nonce_valid
            || !email_valid
            || IssuerUri::parse(self.iss.clone(), false).is_err()
            || !valid_public_subject(&self.sub)
            || ClientId::parse(self.aud.clone()).is_err()
            || self.azp.as_ref().is_some_and(|azp| azp != &self.aud)
            || !valid_acr_amr(&self.acr, &self.amr)
            || self
                .nonce
                .as_ref()
                .is_some_and(|nonce| !valid_claim_text(nonce, MAX_NONCE_BYTES))
            || expected_issuer.is_some_and(|issuer| issuer.as_str() != self.iss)
            || expected_client.is_some_and(|client| client.as_str() != self.aud)
        {
            return Err(OAuthCryptoError::InvalidClaims);
        }
        Ok(())
    }
}

fn ensure_key_pair(
    encoding: &EncodingKey,
    configured: &RsaPublicJwk,
) -> Result<(), AuthorizationServerConfigError> {
    let derived = Jwk::from_encoding_key(encoding, Algorithm::RS256)
        .map_err(|_| AuthorizationServerConfigError::InvalidPrivateKey)?;
    let AlgorithmParameters::RSA(parameters) = derived.algorithm else {
        return Err(AuthorizationServerConfigError::InvalidPrivateKey);
    };
    if parameters.n != configured.n || parameters.e != configured.e {
        return Err(AuthorizationServerConfigError::SigningKeyMismatch);
    }
    Ok(())
}

fn sign_verify_probe(
    kid: &str,
    encoding: &EncodingKey,
    decoding: &DecodingKey,
) -> Result<(), AuthorizationServerConfigError> {
    #[derive(Deserialize, Serialize)]
    struct ProbeClaims {
        probe: String,
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    header.typ = Some("JWT".to_owned());
    let token = encode(
        &header,
        &ProbeClaims {
            probe: "omnius".to_owned(),
        },
        encoding,
    )
    .map_err(|_| AuthorizationServerConfigError::SigningKeyProbe)?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let decoded = decode::<ProbeClaims>(&token, decoding, &validation)
        .map_err(|_| AuthorizationServerConfigError::SigningKeyProbe)?;
    if decoded.claims.probe != "omnius" {
        return Err(AuthorizationServerConfigError::SigningKeyProbe);
    }
    Ok(())
}

fn validated_header(
    token: &str,
    expected_type: &str,
) -> Result<(String, Algorithm), OAuthCryptoError> {
    if token.is_empty()
        || token.len() > MAX_JWT_BYTES
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(OAuthCryptoError::InvalidTokenHeader);
    }
    let header = decode_header(token).map_err(|_| OAuthCryptoError::InvalidTokenHeader)?;
    let kid = header
        .kid
        .as_ref()
        .filter(|kid| valid_kid(kid))
        .cloned()
        .ok_or(OAuthCryptoError::InvalidTokenHeader)?;
    if header.alg != Algorithm::RS256
        || header.typ.as_deref() != Some(expected_type)
        || header.cty.is_some()
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.x5t.is_some()
        || header.x5t_s256.is_some()
        || header.crit.is_some()
        || header.enc.is_some()
        || header.zip.is_some()
        || header.url.is_some()
        || header.nonce.is_some()
        || !header.extras.inner().is_empty()
    {
        return Err(OAuthCryptoError::InvalidTokenHeader);
    }
    Ok((kid, header.alg))
}

fn signature_validation(algorithm: Algorithm, require_nbf: bool) -> Validation {
    let mut validation = Validation::new(algorithm);
    validation.algorithms = vec![Algorithm::RS256];
    let required = if require_nbf {
        &["exp", "nbf", "iss", "aud", "sub"][..]
    } else {
        &["exp", "iss", "aud", "sub"][..]
    };
    validation.set_required_spec_claims(required);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation
}

fn valid_kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_KID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn decode_canonical_component(
    value: &str,
    max_encoded: usize,
    min_decoded: usize,
    max_decoded: usize,
) -> Result<Vec<u8>, AuthorizationServerConfigError> {
    if value.is_empty()
        || value.len() > max_encoded
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(AuthorizationServerConfigError::InvalidPublicKey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorizationServerConfigError::InvalidPublicKey)?;
    if !(min_decoded..=max_decoded).contains(&decoded.len())
        || URL_SAFE_NO_PAD.encode(&decoded) != value
    {
        return Err(AuthorizationServerConfigError::InvalidPublicKey);
    }
    Ok(decoded)
}

fn unix_seconds(value: OffsetDateTime) -> Result<u64, OAuthInputError> {
    u64::try_from(value.unix_timestamp()).map_err(|_| OAuthInputError::InvalidClaims)
}

fn uuid_v7(value: Uuid) -> bool {
    value.get_version() == Some(Version::SortRand) && value.get_variant() == Variant::RFC4122
}

fn valid_public_subject(value: &str) -> bool {
    if value.len() != 43
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    let mut decoded = [0_u8; OPAQUE_BEARER_BYTES];
    let Ok(decoded_len) = URL_SAFE_NO_PAD.decode_slice(value, &mut decoded) else {
        return false;
    };
    let mut canonical = [0_u8; 43];
    let Ok(encoded_len) = URL_SAFE_NO_PAD.encode_slice(decoded.as_slice(), &mut canonical) else {
        return false;
    };
    decoded_len == OPAQUE_BEARER_BYTES && &canonical[..encoded_len] == value.as_bytes()
}

fn valid_claim_scopes(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let mut previous = None;
    let mut count = 0_usize;
    for token in value.split(' ') {
        let Ok(_scope) = Scope::new(token) else {
            return false;
        };
        if previous.is_some_and(|prior: &str| prior >= token) {
            return false;
        }
        previous = Some(token);
        count += 1;
        if count > MAX_SCOPES {
            return false;
        }
    }
    count > 0
}

fn valid_acr_amr(acr: &str, amr: &[String]) -> bool {
    valid_claim_text(acr, MAX_ACR_BYTES)
        && !amr.is_empty()
        && amr.len() <= MAX_AMR_VALUES
        && amr
            .iter()
            .all(|method| valid_claim_text(method, MAX_AMR_BYTES))
        && amr.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_claim_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_email_claim(value: &str) -> bool {
    valid_claim_text(value, MAX_EMAIL_BYTES)
        && value
            .split_once('@')
            .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
}

#[cfg(test)]
pub(crate) const TEST_RSA_PRIVATE_KEY: &str = include_str!("../../auth-jwt/tests/test_rsa_key.pem");
#[cfg(test)]
pub(crate) const TEST_RSA_N: &str = "ibepHr39ICr8VUuIFq8Eo0YwJPK5ho4EGyMmhmycy365cohGDI2gvZxpfSeB7N00Xjbx1kC789yiO0_VM-uuWf_olDXzRtkJqW7ukGZ1ThRCqGfOsVDizeTYGkeGz4MU_8l4E1ehu5_CZBDsyBqfuNq5FtnDBjJU_o7PeTIHHtyNDwgMFFWo3aLNxW7j-kDTd_zHrxRc0XG9vIbZRLh35_mu9oiUcsjpeGifE4uhkjIT3I2co4m6Rk-_loFBrs6DAhmZpISKDiTrk0ain6nOoYTe3W3fTHpDDjiyxQAi7m51GHdWvkmiAf_nL7zmmGZIuuTTWNCh2T3Kcju-1T_6VQ";
#[cfg(test)]
pub(crate) const TEST_RSA_E: &str = "AQAB";

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use omnius_config::SecretString;

    use super::*;
    use crate::config::{KeyAlgorithm, KeyState, SigningKeyConfig};
    use crate::types::{OsEntropy, RedirectUri};

    fn public_jwk(kid: &str) -> RsaPublicJwk {
        RsaPublicJwk {
            kty: "RSA".to_owned(),
            public_key_use: "sig".to_owned(),
            key_ops: vec!["verify".to_owned()],
            alg: "RS256".to_owned(),
            kid: kid.to_owned(),
            n: TEST_RSA_N.to_owned(),
            e: TEST_RSA_E.to_owned(),
        }
    }

    fn active_key(kid: &str) -> SigningKeyConfig {
        SigningKeyConfig {
            kid: kid.to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Active,
            public_jwk: public_jwk(kid),
            private_key_pkcs8_pem: Some(SecretString::from(TEST_RSA_PRIVATE_KEY.to_owned())),
            verification_until: None,
        }
    }

    fn key_config() -> SigningKeyConfig {
        active_key("active-1")
    }
    fn retiring_key(kid: &str, verification_until: OffsetDateTime) -> SigningKeyConfig {
        SigningKeyConfig {
            kid: kid.to_owned(),
            algorithm: KeyAlgorithm::RS256,
            state: KeyState::Retiring,
            public_jwk: public_jwk(kid),
            private_key_pkcs8_pem: None,
            verification_until: Some(verification_until),
        }
    }

    fn public_subject() -> String {
        URL_SAFE_NO_PAD.encode([3_u8; OPAQUE_BEARER_BYTES])
    }

    #[test]
    fn bearer_digests_should_be_domain_separated_and_constant_time_verified()
    -> Result<(), Box<dyn std::error::Error>> {
        let pepper = TokenPepper::parse(&URL_SAFE_NO_PAD.encode([9_u8; PEPPER_BYTES]))?;
        let issued = issue_bearer(&OsEntropy, &pepper, BearerDigestDomain::AuthorizationCode)?;
        verify_bearer_digest(
            &issued.presentation,
            &issued.digest,
            &pepper,
            BearerDigestDomain::AuthorizationCode,
        )?;
        assert_eq!(
            verify_bearer_digest(
                &issued.presentation,
                &issued.digest,
                &pepper,
                BearerDigestDomain::RefreshToken,
            ),
            Err(OAuthCryptoError::DigestMismatch)
        );
        assert_eq!(
            format!("{:?}", issued.digest),
            "BearerDigest(\"[REDACTED]\")"
        );
        Ok(())
    }

    #[test]
    fn signing_ring_should_probe_and_publish_only_public_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let ring = SigningKeyRing::from_config(&[key_config()], now)?;
        assert_eq!(ring.active_kid(), "active-1");
        assert_eq!(ring.jwks(now).keys, vec![public_jwk("active-1")]);
        let encoded = serde_json::to_string(&ring.jwks(now))?;
        assert!(!encoded.contains("PRIVATE"));
        Ok(())
    }
    #[test]
    fn signing_ring_should_stop_publishing_retiring_keys_at_the_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let deadline = now + Duration::from_secs(60);
        let ring = SigningKeyRing::from_config(
            &[
                key_config(),
                retiring_key("retiring-current", deadline),
                retiring_key("retiring-expired", now),
            ],
            now,
        )?;

        let before_kids = ring
            .jwks(deadline - Duration::from_secs(1))
            .keys
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>();
        assert_eq!(
            before_kids,
            vec!["active-1".to_owned(), "retiring-current".to_owned()]
        );

        let at_kids = ring
            .jwks(deadline)
            .keys
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>();
        assert_eq!(at_kids, vec!["active-1".to_owned()]);

        let after_kids = ring
            .jwks(deadline + Duration::from_secs(1))
            .keys
            .into_iter()
            .map(|key| key.kid)
            .collect::<Vec<_>>();
        assert_eq!(after_kids, vec!["active-1".to_owned()]);
        Ok(())
    }

    #[test]
    fn access_token_should_reject_a_retiring_key_at_and_after_its_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let deadline = now + Duration::from_secs(60);
        let issuer = IssuerUri::parse("https://issuer.example.test", true)?;
        let audience = ResourceUri::parse("https://api.example.test", true)?;
        let claims = AccessTokenClaims::new(AccessTokenClaimsInput {
            issuer: issuer.clone(),
            subject: public_subject(),
            audience: audience.clone(),
            expires_at: now + Duration::from_secs(600),
            not_before: now,
            issued_at: now,
            jwt_id: JwtId::new(),
            client_id: ClientId::parse("client-1")?,
            grant_id: GrantId::new(),
            scopes: vec![Scope::new("openid")?],
            auth_time: now,
            acr: "aal2".to_owned(),
            amr: vec!["pwd".to_owned()],
        })?;
        let retired_signer = SigningKeyRing::from_config(&[active_key("retiring-1")], now)?;
        let token = retired_signer.sign_access_token(&claims)?;
        let ring = SigningKeyRing::from_config(
            &[key_config(), retiring_key("retiring-1", deadline)],
            now,
        )?;

        let before = deadline - Duration::from_secs(1);
        assert_eq!(
            ring.verify_access_token(token.expose(), &issuer, &audience, before)?,
            claims
        );
        assert_eq!(
            ring.verify_access_token_for_issuer(token.expose(), &issuer, before)?,
            claims
        );
        assert_eq!(
            ring.verify_access_token(token.expose(), &issuer, &audience, deadline),
            Err(OAuthCryptoError::KeyUnavailable)
        );
        assert_eq!(
            ring.verify_access_token_for_issuer(token.expose(), &issuer, deadline),
            Err(OAuthCryptoError::KeyUnavailable)
        );
        let after = deadline + Duration::from_secs(1);
        assert_eq!(
            ring.verify_access_token(token.expose(), &issuer, &audience, after),
            Err(OAuthCryptoError::KeyUnavailable)
        );
        assert_eq!(
            ring.verify_access_token_for_issuer(token.expose(), &issuer, after),
            Err(OAuthCryptoError::KeyUnavailable)
        );

        let active_token = ring.sign_access_token(&claims)?;
        assert_eq!(
            ring.verify_access_token(active_token.expose(), &issuer, &audience, after)?,
            claims
        );
        Ok(())
    }

    #[test]
    fn access_token_should_enforce_type_signature_and_exact_claims()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let issuer = IssuerUri::parse("https://issuer.example.test", true)?;
        let audience = ResourceUri::parse("https://api.example.test", true)?;
        let client = ClientId::parse("client-1")?;
        let ring = SigningKeyRing::from_config(&[key_config()], now)?;
        let claims = AccessTokenClaims::new(AccessTokenClaimsInput {
            issuer: issuer.clone(),
            subject: public_subject(),
            audience: audience.clone(),
            expires_at: now + Duration::from_secs(600),
            not_before: now,
            issued_at: now,
            jwt_id: JwtId::new(),
            client_id: client,
            grant_id: GrantId::new(),
            scopes: vec![Scope::new("openid")?, Scope::new("records:read")?],
            auth_time: now,
            acr: "aal2".to_owned(),
            amr: vec!["pwd".to_owned()],
        })?;
        let token = ring.sign_access_token(&claims)?;
        let verified = ring.verify_access_token(token.expose(), &issuer, &audience, now)?;
        assert_eq!(verified, claims);
        let wrong_audience = ResourceUri::parse("https://other.example.test", true)?;
        assert!(
            ring.verify_access_token(token.expose(), &issuer, &wrong_audience, now)
                .is_err()
        );
        let wrong_type = ring.sign("JWT", &claims)?;
        assert_eq!(
            ring.verify_access_token(wrong_type.expose(), &issuer, &audience, now),
            Err(OAuthCryptoError::InvalidTokenHeader)
        );
        let mut tampered = token.expose().to_owned();
        let last = tampered.pop().ok_or("signed token was empty")?;
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert!(
            ring.verify_access_token(&tampered, &issuer, &audience, now)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn id_token_should_require_exact_nonce_and_verified_email_pair()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let issuer = IssuerUri::parse("https://issuer.example.test", true)?;
        let client = ClientId::parse("client-1")?;
        let ring = SigningKeyRing::from_config(&[key_config()], now)?;
        let claims = IdTokenClaims::new(IdTokenClaimsInput {
            issuer: issuer.clone(),
            subject: public_subject(),
            audience: client.clone(),
            expires_at: now + Duration::from_secs(600),
            issued_at: now,
            auth_time: now,
            acr: "aal2".to_owned(),
            amr: vec!["pwd".to_owned()],
            nonce: Some("nonce-1".to_owned()),
            authorized_party: None,
            email: Some("verified@example.test".to_owned()),
            email_verified: Some(true),
        })?;
        let token = ring.sign_id_token(&claims)?;
        assert!(
            ring.verify_id_token(token.expose(), &issuer, &client, Some("nonce-1"), now)
                .is_ok()
        );
        assert_eq!(
            ring.verify_id_token(token.expose(), &issuer, &client, Some("other"), now),
            Err(OAuthCryptoError::InvalidClaims)
        );
        Ok(())
    }

    #[test]
    fn id_token_should_reject_a_retiring_key_at_and_after_its_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
        let deadline = now + Duration::from_secs(60);
        let issuer = IssuerUri::parse("https://issuer.example.test", true)?;
        let client = ClientId::parse("client-1")?;
        let claims = IdTokenClaims::new(IdTokenClaimsInput {
            issuer: issuer.clone(),
            subject: public_subject(),
            audience: client.clone(),
            expires_at: now + Duration::from_secs(600),
            issued_at: now,
            auth_time: now,
            acr: "aal2".to_owned(),
            amr: vec!["pwd".to_owned()],
            nonce: Some("nonce-1".to_owned()),
            authorized_party: None,
            email: None,
            email_verified: None,
        })?;
        let retired_signer = SigningKeyRing::from_config(&[active_key("retiring-1")], now)?;
        let token = retired_signer.sign_id_token(&claims)?;
        let ring = SigningKeyRing::from_config(
            &[key_config(), retiring_key("retiring-1", deadline)],
            now,
        )?;

        assert_eq!(
            ring.verify_id_token(
                token.expose(),
                &issuer,
                &client,
                Some("nonce-1"),
                deadline - Duration::from_secs(1),
            )?,
            claims
        );
        assert_eq!(
            ring.verify_id_token(token.expose(), &issuer, &client, Some("nonce-1"), deadline,),
            Err(OAuthCryptoError::KeyUnavailable)
        );
        let after = deadline + Duration::from_secs(1);
        assert_eq!(
            ring.verify_id_token(token.expose(), &issuer, &client, Some("nonce-1"), after),
            Err(OAuthCryptoError::KeyUnavailable)
        );

        let active_token = ring.sign_id_token(&claims)?;
        assert_eq!(
            ring.verify_id_token(
                active_token.expose(),
                &issuer,
                &client,
                Some("nonce-1"),
                after,
            )?,
            claims
        );
        Ok(())
    }

    #[test]
    fn malformed_public_key_should_fail_before_probe() {
        let mut key = key_config();
        key.public_jwk.e = "AAEAAQ".to_owned();
        assert!(matches!(
            SigningKeyRing::from_config(&[key], OffsetDateTime::UNIX_EPOCH),
            Err(AuthorizationServerConfigError::InvalidPublicKey)
        ));
    }
    #[test]
    fn mismatched_private_and_public_key_should_fail_before_probe() {
        let mut key = key_config();
        key.public_jwk.n.pop();
        key.public_jwk.n.push('A');
        assert!(matches!(
            SigningKeyRing::from_config(&[key], OffsetDateTime::UNIX_EPOCH),
            Err(AuthorizationServerConfigError::SigningKeyMismatch)
        ));
    }

    #[test]
    fn redirect_fixture_should_remain_transport_neutral() {
        assert!(RedirectUri::parse("https://client.example.test/callback").is_ok());
    }
}
