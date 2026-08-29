//! Bounded, transport-neutral OAuth and `OpenID Connect` domain values.

use std::{collections::HashSet, fmt, str::FromStr};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use omnius_auth_core::Scope;
use rand_core::{OsRng, RngCore as _};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::{Digest as _, Sha256};
use url::{Host, Url};
use uuid::{Uuid, Variant, Version};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::{OAuthCryptoError, OAuthInputError};

/// Exact byte length of every opaque bearer before encoding.
pub const OPAQUE_BEARER_BYTES: usize = 32;
/// Exact canonical unpadded base64url length of every opaque bearer.
pub const OPAQUE_BEARER_ENCODED_BYTES: usize = 43;
/// Maximum client identifier size accepted by protocol inputs.
pub const MAX_CLIENT_ID_BYTES: usize = 2_048;
/// Maximum URI size accepted by protocol inputs.
pub const MAX_URI_BYTES: usize = 2_048;
/// Maximum number of redirect URIs in one client metadata document.
pub const MAX_REDIRECT_URIS: usize = 32;
/// Maximum number of post-logout redirect URIs in one client metadata document.
pub const MAX_POST_LOGOUT_REDIRECT_URIS: usize = 16;
/// Maximum number of resources in one authorization request.
pub const MAX_REQUEST_RESOURCES: usize = 16;
/// Maximum number of distinct scopes in one authorization request or client.
pub const MAX_SCOPES: usize = 128;
/// Maximum encoded JWT accepted by the local verifier.
pub const MAX_JWT_BYTES: usize = 16 * 1_024;

const MAX_TEXT_BYTES: usize = 1_024;
const MAX_CLIENT_NAME_BYTES: usize = 256;
const MAX_JWKS_BYTES: usize = 256 * 1_024;
const MAX_CLIENT_JWKS_KEYS: usize = 8;
const REDACTED: &str = "[REDACTED]";

/// Root issuer URL accepted by the authorization-server core.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct IssuerUri(String);

impl IssuerUri {
    /// Validates a canonical root issuer URL.
    ///
    /// Production requires HTTPS. All deployments reject credentials, query,
    /// fragment, non-root paths, non-canonical spelling, and unsupported schemes.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidUri`] when the value exceeds the URI
    /// bound or is not a canonical root HTTP(S) origin permitted in the selected
    /// deployment mode.
    pub fn parse(value: impl Into<String>, production: bool) -> Result<Self, OAuthInputError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_URI_BYTES) {
            return Err(OAuthInputError::InvalidUri);
        }
        let url = Url::parse(&value).map_err(|_| OAuthInputError::InvalidUri)?;
        if !valid_http_origin(&url)
            || url.path() != "/"
            || url.query().is_some()
            || (production && url.scheme() != "https")
            || canonical_root(&url).as_deref() != Some(value.as_str())
        {
            return Err(OAuthInputError::InvalidUri);
        }
        Ok(Self(value))
    }

    /// Returns the exact issuer identifier used in tokens and metadata.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derives one fixed provider endpoint without accepting independent configuration.
    #[must_use]
    pub fn endpoint(&self, path: &str) -> String {
        debug_assert!(path.starts_with('/'));
        let mut endpoint = String::with_capacity(self.0.len() + path.len());
        endpoint.push_str(&self.0);
        endpoint.push_str(path);
        endpoint
    }
}

/// Exact absolute OAuth resource indicator.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceUri(String);

impl ResourceUri {
    /// Validates a canonical HTTP(S) resource URI without credentials or fragment.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidUri`] when the value exceeds the URI
    /// bound or is not a canonical HTTP(S) resource URI permitted in the selected
    /// deployment mode.
    pub fn parse(value: impl Into<String>, production: bool) -> Result<Self, OAuthInputError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_URI_BYTES) {
            return Err(OAuthInputError::InvalidUri);
        }
        let url = Url::parse(&value).map_err(|_| OAuthInputError::InvalidUri)?;
        if !valid_http_origin(&url)
            || (production && url.scheme() != "https")
            || canonical_absolute(&url).as_deref() != Some(value.as_str())
        {
            return Err(OAuthInputError::InvalidUri);
        }
        Ok(Self(value))
    }

    /// Returns the exact resource audience value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact registered OAuth redirect URI.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct RedirectUri(String);

impl RedirectUri {
    /// Validates an HTTPS redirect or an RFC 8252 IP-literal HTTP loopback redirect.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidRedirectUri`] when the value exceeds the
    /// URI bound or is not a canonical HTTPS or IP-literal HTTP loopback URI.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthInputError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_URI_BYTES) {
            return Err(OAuthInputError::InvalidRedirectUri);
        }
        let url = Url::parse(&value).map_err(|_| OAuthInputError::InvalidRedirectUri)?;
        let secure = url.scheme() == "https" || url.scheme() == "http" && loopback_host(&url);
        if !valid_http_origin(&url) || !secure || url.as_str() != value {
            return Err(OAuthInputError::InvalidRedirectUri);
        }
        Ok(Self(value))
    }

    /// Returns the registered spelling retained for exact comparisons and redirects.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Applies exact matching with only RFC 8252 loopback-port substitution.
    #[must_use]
    pub fn matches_registered(&self, requested: &Self) -> bool {
        if self == requested {
            return true;
        }
        let Ok(registered) = Url::parse(&self.0) else {
            return false;
        };
        let Ok(requested) = Url::parse(&requested.0) else {
            return false;
        };
        registered.scheme() == "http"
            && requested.scheme() == "http"
            && loopback_host(&registered)
            && loopback_host(&requested)
            && registered.host() == requested.host()
            && registered.path() == requested.path()
            && registered.query() == requested.query()
            && requested.port().is_some()
    }

    /// Whether this is an HTTP IP-literal native loopback redirect.
    #[must_use]
    pub fn is_loopback_http(&self) -> bool {
        Url::parse(&self.0).is_ok_and(|url| url.scheme() == "http" && loopback_host(&url))
    }
}

impl<'de> Deserialize<'de> for RedirectUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// One bounded OAuth client identifier.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ClientId(String);

impl ClientId {
    /// Validates and owns a client identifier.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidClientId`] when the identifier is empty,
    /// exceeds the client-ID bound, has surrounding or control characters, or
    /// contains ASCII whitespace.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthInputError> {
        let value = value.into();
        if !valid_bounded_text(&value, MAX_CLIENT_ID_BYTES)
            || value.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(OAuthInputError::InvalidClientId);
        }
        Ok(Self(value))
    }

    /// Returns the exact client identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ClientId {
    type Err = OAuthInputError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<'de> Deserialize<'de> for ClientId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(D::Error::custom)
    }
}

/// OAuth authorization response type supported by this provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ResponseType {
    /// Authorization code response.
    #[serde(rename = "code")]
    Code,
}

/// OAuth authorization response mode supported by this provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ResponseMode {
    /// Query-component response parameters.
    #[serde(rename = "query")]
    Query,
}

/// `OpenID Connect` prompt behavior implemented by this provider.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Prompt {
    /// Do not display authentication or consent UI.
    None,
    /// Require interactive reauthentication.
    Login,
    /// Require explicit consent.
    Consent,
}

/// Canonical PKCE S256 code challenge.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PkceChallenge(String);

impl PkceChallenge {
    /// Parses an exact 32-byte SHA-256 result encoded as unpadded base64url.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidPkce`] unless the value is the canonical
    /// unpadded base64url encoding of exactly 32 bytes.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthInputError> {
        let value = value.into();
        decode_exact_32(&value).map_err(|_| OAuthInputError::InvalidPkce)?;
        Ok(Self(value))
    }

    /// Returns the canonical encoded challenge.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Bounded RFC 7636 code verifier held in zeroizing storage.
#[derive(Clone)]
pub struct PkceVerifier(Zeroizing<String>);

impl PkceVerifier {
    /// Validates a 43–128 byte RFC 7636 unreserved verifier.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidPkce`] when the verifier is outside the
    /// RFC 7636 length bound or contains a character outside the unreserved set.
    pub fn parse(value: impl Into<String>) -> Result<Self, OAuthInputError> {
        let mut value = value.into();
        if !(43..=128).contains(&value.len())
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
            })
        {
            value.zeroize();
            return Err(OAuthInputError::InvalidPkce);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    /// Derives the S256 challenge for constant-size comparison with a stored challenge.
    #[must_use]
    pub fn challenge(&self) -> PkceChallenge {
        let digest = Sha256::digest(self.0.as_bytes());
        PkceChallenge(URL_SAFE_NO_PAD.encode(digest))
    }
}

impl fmt::Debug for PkceVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PkceVerifier")
            .field(&REDACTED)
            .finish()
    }
}

/// Fully validated authorization request independent of HTTP transport.
#[derive(Clone, Debug)]
pub struct AuthorizationRequestInput {
    client_id: ClientId,
    redirect_uri: RedirectUri,
    state: Option<String>,
    scopes: Vec<Scope>,
    resources: Vec<ResourceUri>,
    pkce_challenge: PkceChallenge,
    nonce: Option<String>,
    prompt: Option<Prompt>,
    max_age_seconds: Option<u64>,
    expected_issuer: Option<IssuerUri>,
}

/// Raw bounded fields used to construct an [`AuthorizationRequestInput`].
#[derive(Clone, Debug)]
pub struct AuthorizationRequestParts {
    /// Client identifier from the authorization request.
    pub client_id: ClientId,
    /// Requested exact redirect URI.
    pub redirect_uri: RedirectUri,
    /// Only `code` is accepted.
    pub response_type: ResponseType,
    /// Only `query` is accepted.
    pub response_mode: ResponseMode,
    /// Opaque client state echoed only after redirect validation.
    pub state: Option<String>,
    /// Requested OAuth/OIDC scopes.
    pub scopes: Vec<Scope>,
    /// Requested resource indicators.
    pub resources: Vec<ResourceUri>,
    /// Required S256 PKCE challenge.
    pub pkce_challenge: PkceChallenge,
    /// Required method spelling, which must be `S256`.
    pub pkce_method: String,
    /// Optional OIDC nonce.
    pub nonce: Option<String>,
    /// Optional supported prompt.
    pub prompt: Option<Prompt>,
    /// Optional maximum authentication age.
    pub max_age_seconds: Option<u64>,
    /// Optional RFC 9207 issuer expectation.
    pub expected_issuer: Option<IssuerUri>,
}

impl AuthorizationRequestInput {
    /// Validates collection uniqueness, optional fields, and PKCE method.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthInputError`] when the PKCE method or optional text is
    /// invalid, or when scopes or resource indicators violate their bounds or
    /// uniqueness requirements.
    pub fn new(parts: AuthorizationRequestParts) -> Result<Self, OAuthInputError> {
        let AuthorizationRequestParts {
            client_id,
            redirect_uri,
            response_type: ResponseType::Code,
            response_mode: ResponseMode::Query,
            state,
            mut scopes,
            mut resources,
            pkce_challenge,
            pkce_method,
            nonce,
            prompt,
            max_age_seconds,
            expected_issuer,
        } = parts;
        if pkce_method != "S256" {
            return Err(OAuthInputError::InvalidPkce);
        }
        validate_optional_text(state.as_deref(), MAX_TEXT_BYTES)?;
        validate_optional_text(nonce.as_deref(), MAX_TEXT_BYTES)?;
        if scopes.is_empty() || scopes.len() > MAX_SCOPES {
            return Err(OAuthInputError::InvalidScopes);
        }
        scopes.sort_unstable();
        if scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OAuthInputError::InvalidScopes);
        }
        if resources.len() > MAX_REQUEST_RESOURCES {
            return Err(OAuthInputError::InvalidResources);
        }
        resources.sort_unstable();
        if resources.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OAuthInputError::InvalidResources);
        }
        Ok(Self {
            client_id,
            redirect_uri,
            state,
            scopes,
            resources,
            pkce_challenge,
            nonce,
            prompt,
            max_age_seconds,
            expected_issuer,
        })
    }

    /// Client identifier bound to the transaction.
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// Exact redirect URI bound to the transaction.
    #[must_use]
    pub fn redirect_uri(&self) -> &RedirectUri {
        &self.redirect_uri
    }

    /// Opaque client state retained for the validated redirect only.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    /// Sorted unique scopes.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Sorted unique resource indicators.
    #[must_use]
    pub fn resources(&self) -> &[ResourceUri] {
        &self.resources
    }

    /// Required S256 challenge.
    #[must_use]
    pub const fn pkce_challenge(&self) -> &PkceChallenge {
        &self.pkce_challenge
    }

    /// OIDC nonce when supplied.
    #[must_use]
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Supported prompt when supplied.
    #[must_use]
    pub const fn prompt(&self) -> Option<Prompt> {
        self.prompt
    }

    /// Maximum authentication age when supplied.
    #[must_use]
    pub const fn max_age_seconds(&self) -> Option<u64> {
        self.max_age_seconds
    }

    /// Expected authorization issuer when supplied.
    #[must_use]
    pub const fn expected_issuer(&self) -> Option<&IssuerUri> {
        self.expected_issuer.as_ref()
    }
}

/// Client application class from RFC 7591/OpenID Connect registration.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationType {
    /// Browser-based confidential or public web application.
    #[default]
    Web,
    /// Installed native application.
    Native,
}

/// Implemented token endpoint client authentication methods.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum TokenEndpointAuthMethod {
    /// Public client without a client secret.
    #[default]
    #[serde(rename = "none")]
    None,
    /// HTTP Basic client-secret authentication.
    #[serde(rename = "client_secret_basic")]
    ClientSecretBasic,
    /// Signed JWT assertion using a registered public key.
    #[serde(rename = "private_key_jwt")]
    PrivateKeyJwt,
}

/// Implemented OAuth grant types.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum GrantType {
    /// Authorization code grant.
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    /// Refresh token grant.
    #[serde(rename = "refresh_token")]
    RefreshToken,
}

/// Strict deserialization model for pre-registration, CIMD, and optional DCR.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientMetadataInput {
    /// Required in a Client ID Metadata Document and absent for local pre-registration.
    #[serde(default)]
    pub client_id: Option<ClientId>,
    /// Human-readable client name.
    pub client_name: String,
    /// Registered authorization response redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Registered post-logout redirect URIs.
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    /// Web or native client class.
    #[serde(default)]
    pub application_type: ApplicationType,
    /// Token endpoint authentication method.
    #[serde(default)]
    pub token_endpoint_auth_method: TokenEndpointAuthMethod,
    /// Implemented grant types requested by the client.
    #[serde(default = "default_grant_types")]
    pub grant_types: Vec<GrantType>,
    /// Implemented response types requested by the client.
    #[serde(default = "default_response_types")]
    pub response_types: Vec<ResponseType>,
    /// Client scopes, bounded and canonicalized by the provider.
    #[serde(default)]
    pub scope: Vec<Scope>,
    /// Public client keys used only for assertion verification.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
}

/// Validated client metadata shared by every onboarding path.
#[derive(Clone, Debug)]
pub struct ClientMetadata {
    client_id: Option<ClientId>,
    client_name: String,
    redirect_uris: Vec<RedirectUri>,
    post_logout_redirect_uris: Vec<RedirectUri>,
    application_type: ApplicationType,
    token_endpoint_auth_method: TokenEndpointAuthMethod,
    grant_types: Vec<GrantType>,
    response_types: Vec<ResponseType>,
    scopes: Vec<Scope>,
    jwks: Option<serde_json::Value>,
}

impl ClientMetadata {
    /// Parses strict JSON only after enforcing the caller's validated byte ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidClientMetadata`] when the byte ceiling is
    /// invalid, the input is empty or exceeds it, strict JSON decoding fails, or
    /// the decoded metadata violates the shared client policy.
    pub fn from_json(
        input: &[u8],
        max_bytes: usize,
        expected_document_client_id: Option<&ClientId>,
    ) -> Result<Self, OAuthInputError> {
        if input.is_empty() || max_bytes > MAX_JWKS_BYTES || input.len() > max_bytes {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        let metadata = serde_json::from_slice::<ClientMetadataInput>(input)
            .map_err(|_| OAuthInputError::InvalidClientMetadata)?;
        Self::validate(metadata, expected_document_client_id)
    }

    /// Applies the same strict metadata policy to every client source.
    ///
    /// `expected_document_client_id` is required for CIMD and enforces exact
    /// document URL/client-ID equality. Pass `None` for local registration.
    ///
    /// # Errors
    ///
    /// Returns an [`OAuthInputError`] when metadata fields, redirect URIs, grants,
    /// response types, scopes, authentication method, or public keys violate the
    /// shared client policy, including a Client ID Metadata Document ID mismatch.
    pub fn validate(
        input: ClientMetadataInput,
        expected_document_client_id: Option<&ClientId>,
    ) -> Result<Self, OAuthInputError> {
        if !valid_bounded_text(&input.client_name, MAX_CLIENT_NAME_BYTES) {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        match (expected_document_client_id, input.client_id.as_ref()) {
            (Some(expected), Some(actual)) if expected == actual => {}
            (Some(_), _) | (None, Some(_)) => return Err(OAuthInputError::InvalidClientMetadata),
            (None, None) => {}
        }
        let redirect_uris = validate_redirects(input.redirect_uris, MAX_REDIRECT_URIS)?;
        let post_logout_redirect_uris = validate_redirects(
            input.post_logout_redirect_uris,
            MAX_POST_LOGOUT_REDIRECT_URIS,
        )?;
        if redirect_uris.is_empty() {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        let mut grant_types = input.grant_types;
        let grant_type_count = grant_types.len();
        grant_types.sort_unstable();
        grant_types.dedup();
        if grant_types.is_empty()
            || grant_types.len() != grant_type_count
            || grant_types.len() > 2
            || !grant_types.contains(&GrantType::AuthorizationCode)
        {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        if input.response_types != [ResponseType::Code] {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        let mut scopes = input.scope;
        scopes.sort_unstable();
        if scopes.len() > MAX_SCOPES || scopes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        if input.application_type == ApplicationType::Native
            && input.token_endpoint_auth_method != TokenEndpointAuthMethod::None
        {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        if input.token_endpoint_auth_method == TokenEndpointAuthMethod::PrivateKeyJwt
            && input.jwks.is_none()
        {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        if let Some(jwks) = input.jwks.as_ref() {
            validate_public_jwks(jwks)?;
        }
        Ok(Self {
            client_id: input.client_id,
            client_name: input.client_name,
            redirect_uris,
            post_logout_redirect_uris,
            application_type: input.application_type,
            token_endpoint_auth_method: input.token_endpoint_auth_method,
            grant_types,
            response_types: input.response_types,
            scopes,
            jwks: input.jwks,
        })
    }

    /// CIMD client identifier, when this metadata originated from a document.
    #[must_use]
    pub const fn client_id(&self) -> Option<&ClientId> {
        self.client_id.as_ref()
    }

    /// Safe display name.
    #[must_use]
    pub fn client_name(&self) -> &str {
        &self.client_name
    }

    /// Exact registered authorization redirects.
    #[must_use]
    pub fn redirect_uris(&self) -> &[RedirectUri] {
        &self.redirect_uris
    }

    /// Exact registered post-logout redirects.
    #[must_use]
    pub fn post_logout_redirect_uris(&self) -> &[RedirectUri] {
        &self.post_logout_redirect_uris
    }

    /// Client application class.
    #[must_use]
    pub const fn application_type(&self) -> ApplicationType {
        self.application_type
    }

    /// Token endpoint authentication method.
    #[must_use]
    pub const fn token_endpoint_auth_method(&self) -> TokenEndpointAuthMethod {
        self.token_endpoint_auth_method
    }

    /// Sorted implemented grant types.
    #[must_use]
    pub fn grant_types(&self) -> &[GrantType] {
        &self.grant_types
    }

    /// Implemented response types.
    #[must_use]
    pub fn response_types(&self) -> &[ResponseType] {
        &self.response_types
    }

    /// Sorted unique requested client scopes.
    #[must_use]
    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    /// Public client JWKS, when configured.
    #[must_use]
    pub const fn jwks(&self) -> Option<&serde_json::Value> {
        self.jwks.as_ref()
    }
}

/// A 32-byte opaque bearer held only as zeroizing binary material.
#[derive(Clone)]
pub struct OpaqueBearer(Zeroizing<[u8; OPAQUE_BEARER_BYTES]>);

impl OpaqueBearer {
    /// Parses a canonical, unpadded base64url presentation after exact length checks.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthInputError::InvalidBearer`] unless the presentation is the
    /// canonical unpadded base64url encoding of exactly 32 bytes.
    pub fn parse(value: &str) -> Result<Self, OAuthInputError> {
        let material = decode_exact_32(value).map_err(|_| OAuthInputError::InvalidBearer)?;
        Ok(Self(Zeroizing::new(material)))
    }

    /// Generates one bearer from exactly 32 bytes supplied by secure entropy.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthCryptoError::EntropyUnavailable`] when the entropy source
    /// cannot fill all 32 bytes.
    pub fn generate(entropy: &impl EntropySource) -> Result<Self, OAuthCryptoError> {
        let mut material = [0_u8; OPAQUE_BEARER_BYTES];
        if entropy.try_fill(&mut material).is_err() {
            material.zeroize();
            return Err(OAuthCryptoError::EntropyUnavailable);
        }
        Ok(Self(Zeroizing::new(material)))
    }

    /// Consumes and reveals the presentation for a single response boundary.
    #[must_use]
    pub fn expose_once(self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.as_slice())
    }

    pub(crate) fn material(&self) -> &[u8; OPAQUE_BEARER_BYTES] {
        &self.0
    }
}

impl fmt::Debug for OpaqueBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OpaqueBearer")
            .field(&REDACTED)
            .finish()
    }
}

/// Injectable cryptographically secure byte source.
pub trait EntropySource: Send + Sync {
    /// Fills the complete output or returns a value-free failure.
    ///
    /// # Errors
    ///
    /// Returns [`OAuthCryptoError`] when the source cannot securely fill the
    /// complete output buffer.
    fn try_fill(&self, output: &mut [u8]) -> Result<(), OAuthCryptoError>;
}

/// Operating-system cryptographic entropy source.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl EntropySource for OsEntropy {
    fn try_fill(&self, output: &mut [u8]) -> Result<(), OAuthCryptoError> {
        OsRng
            .try_fill_bytes(output)
            .map_err(|_| OAuthCryptoError::EntropyUnavailable)
    }
}

macro_rules! uuid_v7_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generates a new RFC-compatible `UUIDv7` value.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }

            /// Validates and wraps an existing `UUIDv7` value.
            ///
            /// # Errors
            ///
            /// Returns [`OAuthInputError::InvalidIdentifier`] unless `value` is
            /// an RFC 4122 variant, version 7 UUID.
            pub fn from_uuid(value: Uuid) -> Result<Self, OAuthInputError> {
                if value.get_version() == Some(Version::SortRand)
                    && value.get_variant() == Variant::RFC4122
                {
                    Ok(Self(value))
                } else {
                    Err(OAuthInputError::InvalidIdentifier)
                }
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = Uuid::deserialize(deserializer)?;
                Self::from_uuid(value).map_err(D::Error::custom)
            }
        }
    };
}

uuid_v7_id!(GrantId, "A durable OAuth grant identifier.");
uuid_v7_id!(JwtId, "A unique JWT `jti` identifier.");

fn valid_bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn validate_optional_text(value: Option<&str>, max_bytes: usize) -> Result<(), OAuthInputError> {
    if value.is_some_and(|text| !valid_bounded_text(text, max_bytes)) {
        Err(OAuthInputError::InvalidText)
    } else {
        Ok(())
    }
}

fn valid_http_origin(url: &Url) -> bool {
    matches!(url.scheme(), "http" | "https")
        && url.host().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    }
}

fn canonical_root(url: &Url) -> Option<String> {
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    url.as_str().strip_suffix('/').map(str::to_owned)
}

fn canonical_absolute(url: &Url) -> Option<String> {
    if url.path() == "/" && url.query().is_none() {
        canonical_root(url)
    } else {
        Some(url.as_str().to_owned())
    }
}

fn decode_exact_32(value: &str) -> Result<[u8; OPAQUE_BEARER_BYTES], OAuthInputError> {
    if value.len() != OPAQUE_BEARER_ENCODED_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(OAuthInputError::InvalidBearer);
    }
    let mut material = [0_u8; OPAQUE_BEARER_BYTES];
    let Ok(decoded) = URL_SAFE_NO_PAD.decode_slice(value, &mut material) else {
        material.zeroize();
        return Err(OAuthInputError::InvalidBearer);
    };
    let mut canonical = [0_u8; OPAQUE_BEARER_ENCODED_BYTES];
    let Ok(encoded) = URL_SAFE_NO_PAD.encode_slice(material.as_slice(), &mut canonical) else {
        material.zeroize();
        return Err(OAuthInputError::InvalidBearer);
    };
    if decoded != OPAQUE_BEARER_BYTES || &canonical[..encoded] != value.as_bytes() {
        material.zeroize();
        return Err(OAuthInputError::InvalidBearer);
    }
    Ok(material)
}

fn validate_redirects(
    values: Vec<String>,
    max_count: usize,
) -> Result<Vec<RedirectUri>, OAuthInputError> {
    if values.len() > max_count {
        return Err(OAuthInputError::InvalidClientMetadata);
    }
    let mut redirects = values
        .into_iter()
        .map(RedirectUri::parse)
        .collect::<Result<Vec<_>, _>>()?;
    redirects.sort_unstable();
    if redirects.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(OAuthInputError::InvalidClientMetadata);
    }
    Ok(redirects)
}

fn validate_public_jwks(value: &serde_json::Value) -> Result<(), OAuthInputError> {
    let encoded = serde_json::to_vec(value).map_err(|_| OAuthInputError::InvalidClientMetadata)?;
    if encoded.len() > MAX_JWKS_BYTES {
        return Err(OAuthInputError::InvalidClientMetadata);
    }
    let object = value
        .as_object()
        .ok_or(OAuthInputError::InvalidClientMetadata)?;
    if object.len() != 1 {
        return Err(OAuthInputError::InvalidClientMetadata);
    }
    let keys = object
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .filter(|keys| !keys.is_empty() && keys.len() <= MAX_CLIENT_JWKS_KEYS)
        .ok_or(OAuthInputError::InvalidClientMetadata)?;
    let mut kids = HashSet::with_capacity(keys.len());
    for key in keys {
        let key = key
            .as_object()
            .ok_or(OAuthInputError::InvalidClientMetadata)?;
        if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|private| key.contains_key(*private))
        {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
        let kid = key
            .get("kid")
            .and_then(serde_json::Value::as_str)
            .filter(|kid| valid_bounded_text(kid, 128))
            .ok_or(OAuthInputError::InvalidClientMetadata)?;
        let kty = key
            .get("kty")
            .and_then(serde_json::Value::as_str)
            .filter(|kty| matches!(*kty, "RSA" | "EC" | "OKP"))
            .ok_or(OAuthInputError::InvalidClientMetadata)?;
        if !kids.insert(kid) || kty == "RSA" && !(key.contains_key("n") && key.contains_key("e")) {
            return Err(OAuthInputError::InvalidClientMetadata);
        }
    }
    Ok(())
}

fn default_grant_types() -> Vec<GrantType> {
    vec![GrantType::AuthorizationCode]
}

fn default_response_types() -> Vec<ResponseType> {
    vec![ResponseType::Code]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedEntropy([u8; OPAQUE_BEARER_BYTES]);

    impl EntropySource for FixedEntropy {
        fn try_fill(&self, output: &mut [u8]) -> Result<(), OAuthCryptoError> {
            output.copy_from_slice(&self.0);
            Ok(())
        }
    }

    #[test]
    fn opaque_bearer_should_be_exact_canonical_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let bearer = OpaqueBearer::generate(&FixedEntropy([7_u8; OPAQUE_BEARER_BYTES]))?;
        assert_eq!(format!("{bearer:?}"), "OpaqueBearer(\"[REDACTED]\")");
        let presentation = bearer.expose_once();
        assert_eq!(presentation.len(), OPAQUE_BEARER_ENCODED_BYTES);
        assert!(presentation.bytes().all(|byte| byte != b'='));
        assert!(OpaqueBearer::parse(&presentation).is_ok());
        assert!(matches!(
            OpaqueBearer::parse(&format!("{presentation}=")),
            Err(OAuthInputError::InvalidBearer)
        ));
        Ok(())
    }
    #[test]
    fn pkce_values_should_enforce_bounds_and_redact_verifiers() -> Result<(), OAuthInputError> {
        let verifier = PkceVerifier::parse("A".repeat(43))?;
        assert_eq!(format!("{verifier:?}"), "PkceVerifier(\"[REDACTED]\")");
        assert_eq!(verifier.challenge().as_str().len(), 43);
        assert!(matches!(
            PkceVerifier::parse("short"),
            Err(OAuthInputError::InvalidPkce)
        ));
        Ok(())
    }

    #[test]
    fn issuer_should_require_canonical_root_https_in_production() {
        assert!(IssuerUri::parse("https://issuer.example.test", true).is_ok());
        assert_eq!(
            IssuerUri::parse("http://issuer.example.test", true),
            Err(OAuthInputError::InvalidUri)
        );
        assert_eq!(
            IssuerUri::parse("https://issuer.example.test/tenant", true),
            Err(OAuthInputError::InvalidUri)
        );
        assert_eq!(
            IssuerUri::parse("https://issuer.example.test/", true),
            Err(OAuthInputError::InvalidUri)
        );
    }

    #[test]
    fn redirect_should_allow_only_https_or_ip_loopback_http() {
        assert!(RedirectUri::parse("https://client.example.test/callback").is_ok());
        assert!(RedirectUri::parse("http://127.0.0.1:49152/callback").is_ok());
        assert!(RedirectUri::parse("http://[::1]:49152/callback").is_ok());
        assert_eq!(
            RedirectUri::parse("http://localhost/callback"),
            Err(OAuthInputError::InvalidRedirectUri)
        );
        assert_eq!(
            RedirectUri::parse("https://client.example.test/callback#secret"),
            Err(OAuthInputError::InvalidRedirectUri)
        );
    }

    #[test]
    fn redirect_matching_should_change_only_native_loopback_port() -> Result<(), OAuthInputError> {
        let registered = RedirectUri::parse("http://127.0.0.1:8000/cb?fixed=1")?;
        let requested = RedirectUri::parse("http://127.0.0.1:49152/cb?fixed=1")?;
        let changed_path = RedirectUri::parse("http://127.0.0.1:49152/other?fixed=1")?;
        assert!(registered.matches_registered(&requested));
        assert!(!registered.matches_registered(&changed_path));
        Ok(())
    }

    #[test]
    fn client_metadata_should_reject_private_jwk_material() -> Result<(), Box<dyn std::error::Error>>
    {
        let input = ClientMetadataInput {
            client_id: None,
            client_name: "Example".to_owned(),
            redirect_uris: vec!["https://client.example.test/callback".to_owned()],
            post_logout_redirect_uris: Vec::new(),
            application_type: ApplicationType::Web,
            token_endpoint_auth_method: TokenEndpointAuthMethod::PrivateKeyJwt,
            grant_types: default_grant_types(),
            response_types: default_response_types(),
            scope: vec![Scope::new("openid")?],
            jwks: Some(
                serde_json::json!({"keys":[{"kty":"RSA","kid":"one","n":"AQ","e":"AQAB","d":"secret"}]}),
            ),
        };
        assert!(matches!(
            ClientMetadata::validate(input, None),
            Err(OAuthInputError::InvalidClientMetadata)
        ));
        Ok(())
    }
    #[test]
    fn client_metadata_json_should_reject_bytes_before_deserialization() {
        assert!(matches!(
            ClientMetadata::from_json(b"{}", 1, None),
            Err(OAuthInputError::InvalidClientMetadata)
        ));
    }
}
